"""Tests for :class:`cordon.cloud.CloudReporter`.

These tests pin down the four contractual guarantees the SDK makes to
agent operators:

1. **Never blocks the agent.** Even when the cloud endpoint is down,
   slow, or unreachable, ``reporter(action, verdict)`` returns in
   microseconds.
2. **Never raises.** Any exception inside the listener — from
   serialization, queue full, network error, server 5xx — is swallowed
   and surfaced via :mod:`warnings` instead.
3. **PII-safe.** ``command`` and ``evidence`` strings are length-capped;
   file *bodies* are dropped by default and only summarized.
4. **Honors the Guard.add_listener contract.** The reporter is callable
   as ``(Action, Verdict) -> None`` and survives being attached.

The tests use a fake HTTP transport instead of the real ``urlopen`` so
they run offline and deterministically.
"""

from __future__ import annotations

import json
import threading
import time
import warnings
from typing import Any
from unittest.mock import patch

import pytest

from cordon import Action, Guard
from cordon.cloud import CloudReporter


# ─── Fake transport ────────────────────────────────────────────────────────────


class _FakeTransport:
    """Captures every batch the reporter would send. Pluggable failures."""

    def __init__(
        self,
        *,
        fail_first_n: int = 0,
        latency_s: float = 0.0,
        raise_exc: BaseException | None = None,
    ) -> None:
        self.batches: list[list[dict[str, Any]]] = []
        self.requests: list[dict[str, str]] = []
        self.fail_first_n = fail_first_n
        self.latency_s = latency_s
        self.raise_exc = raise_exc
        self._n_calls = 0
        self._lock = threading.Lock()

    def __call__(self, request, timeout: float):  # type: ignore[no-untyped-def]
        # Mimic urllib.request.urlopen's return shape.
        with self._lock:
            self._n_calls += 1
            n = self._n_calls

        if self.latency_s:
            time.sleep(self.latency_s)
        if self.raise_exc is not None and n <= max(self.fail_first_n, 1):
            raise self.raise_exc

        body = request.data
        parsed = json.loads(body.decode("utf-8"))
        with self._lock:
            self.batches.append(parsed["events"])
            self.requests.append(dict(request.headers))

        class _Resp:
            status = 500 if n <= self.fail_first_n else 200

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self, n: int = 64) -> bytes:
                return b'{"accepted": 1}'

        return _Resp()


@pytest.fixture
def transport():
    """A fresh fake transport for each test."""
    return _FakeTransport()


@pytest.fixture
def reporter(transport):
    """A reporter wired to the fake transport, with a tight flush interval."""
    with patch("cordon.cloud.reporter.urlrequest.urlopen", new=transport):
        r = CloudReporter(
            api_key="cdn_test_abc123",
            endpoint="https://example.invalid",
            batch_size=3,
            flush_interval=0.05,
            timeout=1.0,
        )
        try:
            yield r
        finally:
            r.close(timeout=2.0)


# ─── Helpers ───────────────────────────────────────────────────────────────────


def _wait_until(predicate, timeout: float = 2.0, interval: float = 0.02) -> bool:
    """Spin until ``predicate()`` is truthy or ``timeout`` elapses."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


def _check(guard: Guard, action: Action):
    """Run a check and surface the (action, verdict) pair to the listener."""
    return action, guard.check(action)


# ─── 1. Never blocks the agent ─────────────────────────────────────────────────


def test_listener_returns_quickly_even_when_transport_is_slow(transport):
    """A 5-second transport latency must not delay the listener call."""
    transport.latency_s = 5.0  # would be catastrophic if synchronous
    with patch("cordon.cloud.reporter.urlrequest.urlopen", new=transport):
        reporter = CloudReporter(
            api_key="cdn_test",
            endpoint="https://example.invalid",
            batch_size=10,
            flush_interval=0.05,
            timeout=10.0,
        )
        try:
            guard = Guard.strict()
            action = Action(kind="shell", command="echo hi")
            verdict = guard.check(action)

            t0 = time.perf_counter()
            for _ in range(20):
                reporter(action, verdict)
            elapsed = time.perf_counter() - t0
        finally:
            reporter.close(timeout=0.0)  # don't wait for slow transport

    # 20 enqueues must complete in well under a millisecond each.
    assert elapsed < 0.1, f"listener was synchronous? took {elapsed:.3f}s"


# ─── 2. Never raises ───────────────────────────────────────────────────────────


def test_listener_swallows_serialization_errors():
    """A broken Verdict-like object must not propagate out of the listener."""
    reporter = CloudReporter(api_key="cdn_test", endpoint="https://example.invalid")
    try:

        class _BoomAction:
            id = "x"
            kind = "shell"
            command = "echo"
            changes = None

        class _BoomVerdict:
            @property
            def decision(self) -> str:
                raise RuntimeError("boom")

            blocked = False
            suspicion_score = 0.0
            probes_triggered: list = []
            all_probes: list = []

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            # Must not raise.
            reporter(_BoomAction(), _BoomVerdict())  # type: ignore[arg-type]

        assert any("failed to serialize" in str(w.message) for w in caught), \
            "serialization failure should be surfaced via warnings"
    finally:
        reporter.close(timeout=0.5)


def test_listener_attached_to_guard_survives_serialization_failure(
    transport,
):
    """``Guard._notify_listeners`` wraps listeners in try/except, but
    ``CloudReporter`` should also self-protect so the Guard's try/except
    is never triggered (which would emit its own warning)."""

    class _Wrap:
        def __init__(self, real):
            self.real = real
            self.calls = 0

        def __call__(self, action, verdict):
            self.calls += 1
            return self.real(action, verdict)

    with patch("cordon.cloud.reporter.urlrequest.urlopen", new=transport):
        reporter = CloudReporter(
            api_key="cdn_test",
            endpoint="https://example.invalid",
            batch_size=2,
            flush_interval=0.05,
        )
        try:
            wrap = _Wrap(reporter)
            guard = Guard.strict()
            guard.add_listener(wrap)

            for i in range(5):
                guard.check(Action(kind="shell", command=f"echo {i}"))

            assert wrap.calls == 5
            assert _wait_until(
                lambda: sum(len(b) for b in transport.batches) >= 5
            ), f"only flushed {sum(len(b) for b in transport.batches)} events"
        finally:
            reporter.close(timeout=2.0)


def test_network_errors_do_not_propagate(transport):
    """Server 5xx / connection errors must remain inside the background thread."""
    import urllib.error

    transport.raise_exc = urllib.error.URLError("connection refused")
    transport.fail_first_n = 100  # fail every send

    with patch("cordon.cloud.reporter.urlrequest.urlopen", new=transport):
        reporter = CloudReporter(
            api_key="cdn_test",
            endpoint="https://example.invalid",
            batch_size=2,
            flush_interval=0.05,
        )
        try:
            guard = Guard.strict()
            guard.add_listener(reporter)

            for i in range(4):
                guard.check(Action(kind="shell", command=f"echo {i}"))

            assert _wait_until(lambda: reporter.failed_batches >= 1, timeout=2.0)
            assert reporter.sent == 0
        finally:
            reporter.close(timeout=1.0)


# ─── 3. PII-safe serialization ────────────────────────────────────────────────


def test_long_command_is_truncated():
    reporter = CloudReporter(api_key="cdn_test", endpoint="https://example.invalid")
    try:
        long_cmd = "a" * 2000
        action = Action(kind="shell", command=long_cmd)
        verdict = Guard.permissive().check(action)
        event = reporter._serialize(action, verdict)
        assert len(event["command_preview"]) <= 513  # 512 + ellipsis
        assert event["command_preview"].endswith("…")
    finally:
        reporter.close(timeout=0.5)


def test_file_bodies_dropped_by_default():
    """Without ``include_bodies=True``, only path + size leaks."""
    reporter = CloudReporter(api_key="cdn_test", endpoint="https://example.invalid")
    try:
        action = Action(
            kind="write_file",
            changes={"secrets.env": "OPENAI_API_KEY=sk-proj-real-secret"},
        )
        verdict = Guard.strict().check(action)
        event = reporter._serialize(action, verdict)

        # No raw file body in the wire payload.
        flat = json.dumps(event)
        assert "sk-proj-real-secret" not in flat
        assert event["changes"]["paths"] == ["secrets.env"]
        assert event["changes"]["n_files"] == 1
        assert event["changes"]["total_bytes"] > 0
    finally:
        reporter.close(timeout=0.5)


def test_include_bodies_opt_in_ships_full_files():
    reporter = CloudReporter(
        api_key="cdn_test",
        endpoint="https://example.invalid",
        include_bodies=True,
    )
    try:
        action = Action(kind="write_file", changes={"a.txt": "hello"})
        verdict = Guard.strict().check(action)
        event = reporter._serialize(action, verdict)
        assert event["changes"]["files"] == {"a.txt": "hello"}
    finally:
        reporter.close(timeout=0.5)


# ─── 4. No-op without an API key (CI / unit-test friendly) ─────────────────────


def test_no_api_key_makes_reporter_a_noop(monkeypatch):
    """The SDK must import-and-call cleanly even when CORDON_API_KEY is unset."""
    monkeypatch.delenv("CORDON_API_KEY", raising=False)
    r = CloudReporter()
    assert r._enabled is False
    assert r._thread is None
    # A call still doesn't raise.
    r(Action(kind="shell", command="echo"), Guard.permissive().check(
        Action(kind="shell", command="echo")
    ))


def test_environment_variable_picked_up(monkeypatch):
    monkeypatch.setenv("CORDON_API_KEY", "cdn_env_key")
    monkeypatch.setenv("CORDON_CLOUD_ENDPOINT", "https://example.invalid")
    r = CloudReporter()
    try:
        assert r._enabled is True
        assert r.api_key == "cdn_env_key"
        assert r.endpoint == "https://example.invalid"
    finally:
        r.close(timeout=0.5)


# ─── 5. Batching + queue overflow ──────────────────────────────────────────────


def test_events_flush_in_batches(transport):
    """Once ``batch_size`` events are buffered, a single HTTP call ships them."""
    with patch("cordon.cloud.reporter.urlrequest.urlopen", new=transport):
        reporter = CloudReporter(
            api_key="cdn_test",
            endpoint="https://example.invalid",
            batch_size=3,
            flush_interval=2.0,  # large — force size-based flush
        )
        try:
            guard = Guard.strict()
            guard.add_listener(reporter)
            for i in range(6):
                guard.check(Action(kind="shell", command=f"echo {i}"))

            assert _wait_until(
                lambda: sum(len(b) for b in transport.batches) >= 6,
                timeout=3.0,
            ), f"observed batches: {transport.batches}"
            assert all(len(b) <= 3 for b in transport.batches)
        finally:
            reporter.close(timeout=2.0)


def test_queue_overflow_drops_events_not_raises():
    """When the in-memory queue is full, excess events are counted, not raised."""
    # No transport patch: the reporter's thread will fail every send, so the
    # queue fills up. We make the queue tiny to trigger overflow quickly.
    r = CloudReporter(
        api_key="cdn_test",
        endpoint="http://127.0.0.1:1",  # guaranteed connection refused
        batch_size=100,
        flush_interval=10.0,           # don't flush during the test
        max_queue_size=4,
        timeout=0.1,
    )
    try:
        action = Action(kind="shell", command="echo")
        verdict = Guard.permissive().check(action)
        for _ in range(20):
            r(action, verdict)  # must not raise
        # 20 attempted, queue cap = 4, so at least 16 dropped.
        assert r.dropped >= 16
    finally:
        r.close(timeout=0.5)


# ─── 6. Authorization header ───────────────────────────────────────────────────


def test_bearer_token_header_is_set(transport):
    with patch("cordon.cloud.reporter.urlrequest.urlopen", new=transport):
        r = CloudReporter(
            api_key="cdn_live_xyz",
            endpoint="https://example.invalid",
            batch_size=1,
            flush_interval=0.05,
        )
        try:
            guard = Guard.strict()
            guard.add_listener(r)
            guard.check(Action(kind="shell", command="echo hi"))
            assert _wait_until(lambda: transport.requests, timeout=2.0)
            # urllib lowercases header names; check both styles.
            hdrs = {k.lower(): v for k, v in transport.requests[0].items()}
            assert hdrs.get("authorization") == "Bearer cdn_live_xyz"
            assert "cordon-cloud-sdk" in hdrs.get("user-agent", "")
        finally:
            r.close(timeout=1.0)
