"""``CloudReporter`` — a non-blocking telemetry listener for ``Guard``.

Buffers verdict events in memory and flushes them to a Cordon Cloud
ingest endpoint from a single background thread. Every public method
is non-raising; every network call is bounded by a short timeout.

Usage
-----

::

    from cordon import Guard
    from cordon.cloud import CloudReporter

    reporter = CloudReporter(api_key="cdn_live_...")
    guard = Guard.strict()
    guard.add_listener(reporter)

    # ... your agent runs ...

    reporter.close()  # optional; idempotent; flushes pending events

Wire format
-----------

The ingest endpoint receives JSON of the form::

    POST /v1/ingest
    Authorization: Bearer cdn_live_...
    {
      "events": [
        {
          "ts": 1715000000.123,
          "action_id": "act_...",
          "kind": "shell",
          "command_preview": "pip install -r requirements.txt",
          "decision": "block",
          "blocked": true,
          "suspicion_score": 0.95,
          "top_probe": "typosquat",
          "top_severity": "critical",
          "top_evidence": "1 supply-chain indicator(s): ...",
          "probes_triggered": [
              {"probe": "typosquat", "severity": "critical",
               "confidence": 0.95, "evidence": "..."}
          ],
          "latency_ms": null,
          "sdk_version": "0.2.0",
          "guard_profile": "strict"
        },
        ...
      ]
    }

Server replies ``{"accepted": <int>}`` on success.
"""

from __future__ import annotations

import json
import os
import queue
import threading
import time
import warnings
from typing import TYPE_CHECKING, Any
from urllib import error as urlerror
from urllib import request as urlrequest

import cordon

if TYPE_CHECKING:
    from cordon.core.types import Action, Verdict


DEFAULT_ENDPOINT = "https://seyomi-cordon-cloud.hf.space"
"""Default Cordon Cloud ingest endpoint.

The hosted demo lives on a Hugging Face Space; production deployments
override this via ``CORDON_CLOUD_ENDPOINT`` or the ``endpoint=``
constructor argument. When ``cordon.ai`` ships, this default will move
to ``https://cloud.cordon.ai``.
"""

_COMMAND_PREVIEW_LIMIT = 512
_EVIDENCE_PREVIEW_LIMIT = 512
_PROBES_PER_EVENT_LIMIT = 16


class CloudReporter:
    """Listener that batches verdict events and ships them to Cordon Cloud.

    Args:
        api_key: Project API key. If omitted, falls back to the
            ``CORDON_API_KEY`` environment variable. If still empty
            after that, the reporter becomes a no-op (so importing
            the SDK never crashes a CI run that lacks credentials).
        endpoint: Base URL of the Cordon Cloud ingest server.
            Defaults to ``https://cloud.cordon.ai`` or, if set, the
            ``CORDON_CLOUD_ENDPOINT`` environment variable.
        batch_size: Flush a batch once this many events are buffered.
        flush_interval: Background thread flushes at least this often.
        max_queue_size: Hard cap on in-memory buffer to bound memory
            in the face of an unreachable server. Excess events are
            dropped (counted in ``self.dropped``).
        timeout: Per-request HTTP timeout in seconds.
        include_bodies: If ``True``, ship full file change bodies
            instead of byte counts. Defaults to ``False`` for safety.
        guard_profile: Optional human label (``"strict"`` /
            ``"default"`` / ``"permissive"``) attached to every event
            to make dashboard filtering easy.
    """

    def __init__(
        self,
        api_key: str | None = None,
        *,
        endpoint: str | None = None,
        batch_size: int = 50,
        flush_interval: float = 2.0,
        max_queue_size: int = 10_000,
        timeout: float = 5.0,
        include_bodies: bool = False,
        guard_profile: str | None = None,
        verify_credentials: bool = True,
    ) -> None:
        self.api_key = api_key or os.environ.get("CORDON_API_KEY", "")
        self.endpoint = (
            endpoint
            or os.environ.get("CORDON_CLOUD_ENDPOINT")
            or DEFAULT_ENDPOINT
        ).rstrip("/")
        self.batch_size = max(1, int(batch_size))
        self.flush_interval = max(0.1, float(flush_interval))
        self.timeout = max(0.5, float(timeout))
        self.include_bodies = bool(include_bodies)
        self.guard_profile = guard_profile

        self._queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=max_queue_size)
        self._stop = threading.Event()
        self.dropped = 0
        self.sent = 0
        self.failed_batches = 0
        self._lock = threading.Lock()

        # No API key → run as a no-op so unit tests / CI imports still work.
        # We still serialize events so users can spot-check ``self._queue``.
        self._enabled = bool(self.api_key)

        # Credential status: True (verified), False (rejected), None
        # (unknown — either not yet checked, transport error, or
        # verify_credentials=False). We surface this in stats() so a
        # bad key is visible even without scanning stderr.
        self.auth_ok: bool | None = None

        if self._enabled and verify_credentials:
            self._check_credentials()

        self._thread: threading.Thread | None = None
        if self._enabled:
            self._thread = threading.Thread(
                target=self._run,
                name="cordon-cloud-reporter",
                daemon=True,
            )
            self._thread.start()

    # ─── Credential health-check ──────────────────────────────────────────────

    def _check_credentials(self) -> None:
        """Synchronously verify the API key against the ingest endpoint.

        On 401/403, emit a *loud* warning so users notice immediately
        instead of staring at an empty dashboard wondering why. On
        transport error we stay quiet (the user might just be offline
        — the background thread will surface its own warnings later).

        The request is bounded by a short timeout so a flaky network
        doesn't block ``__init__`` for long. We POST an empty events
        batch, which is a valid no-op the server accepts.
        """
        try:
            self._send([])
        except RuntimeError as exc:
            msg = str(exc)
            if "HTTP 401" in msg or "HTTP 403" in msg:
                self.auth_ok = False
                warnings.warn(
                    f"CloudReporter: API key rejected by {self.endpoint} "
                    f"({msg}). Events will be dropped. Set CORDON_API_KEY "
                    f"to a valid ingest key (email founders@cordon.ai for one).",
                    RuntimeWarning,
                    stacklevel=3,
                )
            else:
                # Transport error — leave auth_ok=None and stay quiet.
                # The background thread will warn on every failed batch.
                self.auth_ok = None
        else:
            self.auth_ok = True

    # ─── Listener interface ───────────────────────────────────────────────────

    def __call__(self, action: "Action", verdict: "Verdict") -> None:
        """Implements ``Guard.Listener``: ``(Action, Verdict) -> None``."""
        try:
            event = self._serialize(action, verdict)
        except Exception as exc:  # noqa: BLE001 — never raise from a listener
            warnings.warn(
                f"CloudReporter: failed to serialize verdict ({exc!r})",
                RuntimeWarning,
                stacklevel=2,
            )
            return

        try:
            self._queue.put_nowait(event)
        except queue.Full:
            with self._lock:
                self.dropped += 1

    # ─── Lifecycle ────────────────────────────────────────────────────────────

    def flush(self, timeout: float = 5.0) -> None:
        """Block until the in-memory queue is drained or ``timeout`` elapses.

        Useful before process exit to avoid losing recent events.
        """
        if not self._enabled:
            return
        deadline = time.monotonic() + max(0.0, float(timeout))
        while time.monotonic() < deadline:
            if self._queue.empty():
                return
            time.sleep(0.05)

    def close(self, timeout: float = 5.0) -> None:
        """Stop the background thread; flush remaining events first.

        Idempotent. Safe to call from ``atexit`` handlers.
        """
        if not self._enabled:
            return
        self.flush(timeout=timeout)
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)

    # ─── Internals ────────────────────────────────────────────────────────────

    def _serialize(self, action: "Action", verdict: "Verdict") -> dict[str, Any]:
        cmd = action.command or ""
        if len(cmd) > _COMMAND_PREVIEW_LIMIT:
            cmd = cmd[:_COMMAND_PREVIEW_LIMIT] + "…"

        change_summary: dict[str, Any]
        if self.include_bodies and action.changes:
            change_summary = {"files": dict(action.changes)}
        else:
            change_summary = {
                "n_files": len(action.changes or {}),
                "total_bytes": sum(len(b) for b in (action.changes or {}).values()),
                "paths": list((action.changes or {}).keys())[:20],
            }

        triggered = list(verdict.probes_triggered)[:_PROBES_PER_EVENT_LIMIT]
        top = triggered[0] if triggered else None

        return {
            "ts": time.time(),
            "action_id": action.id,
            "kind": action.kind,
            "command_preview": cmd or None,
            "changes": change_summary,
            "decision": verdict.decision,
            "blocked": bool(verdict.blocked),
            "suspicion_score": round(float(verdict.suspicion_score), 4),
            "top_probe": top.probe if top else None,
            "top_severity": (
                str(getattr(top.severity, "value", top.severity)).lower()
                if top else None
            ),
            "top_evidence": (
                (top.evidence or "")[:_EVIDENCE_PREVIEW_LIMIT] if top else None
            ),
            "probes_triggered": [
                {
                    "probe": p.probe,
                    "severity": str(getattr(p.severity, "value", p.severity)).lower(),
                    "confidence": round(float(p.confidence), 4),
                    "evidence": (p.evidence or "")[:_EVIDENCE_PREVIEW_LIMIT],
                }
                for p in triggered
            ],
            "n_probes_total": len(verdict.all_probes),
            "sdk_version": cordon.__version__,
            "guard_profile": self.guard_profile,
        }

    def _run(self) -> None:
        """Background thread: drain queue in batches; never raise out."""
        while not self._stop.is_set():
            batch: list[dict[str, Any]] = []
            deadline = time.monotonic() + self.flush_interval

            while len(batch) < self.batch_size and time.monotonic() < deadline:
                remaining = deadline - time.monotonic()
                try:
                    event = self._queue.get(timeout=max(0.01, remaining))
                except queue.Empty:
                    break
                batch.append(event)

            if not batch:
                continue

            try:
                self._send(batch)
                with self._lock:
                    self.sent += len(batch)
            except Exception as exc:  # noqa: BLE001 — must never escape
                with self._lock:
                    self.failed_batches += 1
                warnings.warn(
                    f"CloudReporter: dropped batch of {len(batch)} ({exc!r})",
                    RuntimeWarning,
                    stacklevel=2,
                )

        # Drain on shutdown — best-effort, single attempt.
        leftover: list[dict[str, Any]] = []
        while True:
            try:
                leftover.append(self._queue.get_nowait())
            except queue.Empty:
                break
        if leftover:
            try:
                self._send(leftover)
                with self._lock:
                    self.sent += len(leftover)
            except Exception:  # noqa: BLE001
                with self._lock:
                    self.failed_batches += 1

    def _send(self, batch: list[dict[str, Any]]) -> None:
        """One HTTP POST. Raises on non-2xx or transport error."""
        url = f"{self.endpoint}/v1/ingest"
        body = json.dumps({"events": batch}).encode("utf-8")
        req = urlrequest.Request(
            url,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
                "User-Agent": f"cordon-cloud-sdk/{cordon.__version__}",
            },
        )
        try:
            with urlrequest.urlopen(req, timeout=self.timeout) as resp:
                if resp.status >= 300:
                    raise RuntimeError(f"ingest returned HTTP {resp.status}")
                resp.read(64)  # drain a few bytes; ignore body
        except urlerror.HTTPError as e:
            raise RuntimeError(f"ingest HTTP {e.code}: {e.reason}") from e
        except urlerror.URLError as e:
            raise RuntimeError(f"ingest transport error: {e.reason}") from e

    # ─── Diagnostics ──────────────────────────────────────────────────────────

    def stats(self) -> dict[str, Any]:
        """Snapshot of reporter health, suitable for logging.

        ``auth_ok`` is ``True`` if the credentials were verified at
        construction time, ``False`` if the server rejected them
        (401/403), and ``None`` if not checked or unreachable.
        """
        return {
            "enabled": self._enabled,
            "endpoint": self.endpoint,
            "auth_ok": self.auth_ok,
            "queued": self._queue.qsize(),
            "sent": self.sent,
            "dropped": self.dropped,
            "failed_batches": self.failed_batches,
        }
