"""The :class:`Guard` — Cordon's main entry point.

A ``Guard`` is a bundle of probes plus thresholds. Given an
:class:`~cordon.core.types.Action`, it runs every probe, aggregates the
results, and produces a single :class:`~cordon.core.types.Verdict`.

Decision policy
---------------

A verdict is one of ``allow`` / ``flag`` / ``block``. Policy:

1.  If any probe returns severity ``CRITICAL``, the verdict is ``block``,
    regardless of confidence. Critical findings represent
    detector-confident leaks (verbatim secret-in-output, typosquat
    match in a manifest, etc.) and should never be silently allowed.
2.  Otherwise, the aggregate suspicion score is the **max** confidence
    across all triggered probes. We use max rather than mean because
    one strong signal is sufficient evidence; weak signals do not
    dilute a strong one.
3.  If aggregate suspicion ≥ ``block_threshold`` → ``block``.
4.  If aggregate suspicion ≥ ``flag_threshold`` → ``flag``.
5.  Otherwise → ``allow``.

Defaults are `block_threshold=0.7`, `flag_threshold=0.3`, which reproduce
the tuning used in the Apart Research AI Control Hackathon 2026
benchmark.

Extending
---------

Custom probes just subclass :class:`cordon.probes.base.Probe` and get
passed into ``Guard(probes=[...])``. The decorator API
``@guard.protect`` is provided for wrapping agent step functions.
"""

from __future__ import annotations

import functools
import warnings
from collections.abc import Callable, Iterable
from typing import Any

from cordon.core.types import Action, ProbeResult, Severity, Verdict
from cordon.probes.base import Probe


class BlockedAction(RuntimeError):
    """Raised by :meth:`Guard.protect` when a wrapped agent step is blocked."""

    def __init__(self, verdict: Verdict):
        self.verdict = verdict
        super().__init__(f"Cordon blocked action: {verdict.top_reason()}")


class Guard:
    """Run a bundle of probes against a proposed action.

    Typical usage::

        from cordon import Guard, Action

        guard = Guard.strict()
        verdict = guard.check(Action(kind="shell", command="rm -rf /"))
        if verdict.blocked:
            raise RuntimeError(verdict.top_reason())

    Or as a decorator::

        @guard.protect
        def run_step(action: Action) -> str:
            return shell.execute(action.command)
    """

    # Listener type alias: a callable that receives every (Action, Verdict)
    # pair the guard produces. Used by ``cordon.cloud`` to ship telemetry
    # to a hosted dashboard. Listeners must NEVER raise — exceptions
    # are caught and logged to ``warnings`` so a misbehaving listener
    # cannot break agent execution.
    Listener = Callable[[Action, Verdict], None]

    def __init__(
        self,
        probes: Iterable[Probe] | None = None,
        *,
        block_threshold: float = 0.7,
        flag_threshold: float = 0.3,
        name: str = "custom",
        listeners: Iterable["Guard.Listener"] | None = None,
    ) -> None:
        self.probes: list[Probe] = list(probes) if probes is not None else []
        self.block_threshold = block_threshold
        self.flag_threshold = flag_threshold
        self.name = name

        if not 0.0 <= flag_threshold <= block_threshold <= 1.0:
            raise ValueError(
                "Thresholds must satisfy 0 <= flag_threshold <= block_threshold <= 1"
            )

        self._listeners: list[Guard.Listener] = list(listeners) if listeners else []

    # ─── Listeners (telemetry / cloud reporting) ──────────────────────────────

    def add_listener(self, listener: "Guard.Listener") -> None:
        """Register a callback invoked on every verdict.

        Used by :mod:`cordon.cloud` to ship telemetry to a hosted
        dashboard. Listeners must be fast and non-blocking — wrap any
        I/O in a background thread or async task. Exceptions raised by
        a listener are caught and discarded so a faulty observer can
        never break agent execution.
        """
        self._listeners.append(listener)

    def remove_listener(self, listener: "Guard.Listener") -> None:
        try:
            self._listeners.remove(listener)
        except ValueError:
            pass

    def _notify_listeners(self, action: Action, verdict: Verdict) -> None:
        for listener in self._listeners:
            try:
                listener(action, verdict)
            except Exception as exc:  # noqa: BLE001 — listeners must never break agents
                warnings.warn(
                    f"cordon guard listener {listener!r} raised {exc!r}; ignored.",
                    RuntimeWarning,
                    stacklevel=2,
                )

    # ─── Constructors for common profiles ─────────────────────────────────────

    @staticmethod
    def _semantic_suite() -> list[Probe]:
        """The full 6-probe Semantic Guard suite (v0.2)."""
        from cordon.probes.semantic import (
            ExfiltrationProbe,
            SecretLeakProbe,
            SecurityWeakeningProbe,
            SilentFailureProbe,
            TestSuppressionProbe,
            TyposquatProbe,
        )
        return [
            TyposquatProbe(),
            SecretLeakProbe(),
            ExfiltrationProbe(),
            SilentFailureProbe(),
            TestSuppressionProbe(),
            SecurityWeakeningProbe(),
        ]

    @classmethod
    def strict(cls) -> Guard:
        """All semantic probes, tight thresholds. Blocks on weaker signals."""
        return cls(
            probes=cls._semantic_suite(),
            block_threshold=0.6,
            flag_threshold=0.2,
            name="strict",
        )

    @classmethod
    def default(cls) -> Guard:
        """All semantic probes, balanced thresholds. Recommended for most apps."""
        return cls(
            probes=cls._semantic_suite(),
            block_threshold=0.7,
            flag_threshold=0.3,
            name="default",
        )

    @classmethod
    def permissive(cls) -> Guard:
        """All semantic probes, loose thresholds. Only blocks on critical."""
        return cls(
            probes=cls._semantic_suite(),
            block_threshold=0.85,
            flag_threshold=0.5,
            name="permissive",
        )

    # ─── Main API ─────────────────────────────────────────────────────────────

    def check(self, action: Action) -> Verdict:
        """Run all probes against ``action`` and return the aggregated verdict."""
        verdict = self._compute_verdict(action)
        self._notify_listeners(action, verdict)
        return verdict

    def _compute_verdict(self, action: Action) -> Verdict:
        all_results: list[ProbeResult] = [probe.run(action) for probe in self.probes]
        triggered = [r for r in all_results if r.triggered]

        # Decision.
        if not triggered:
            return Verdict(
                decision="allow",
                suspicion_score=0.0,
                probes_triggered=[],
                all_probes=all_results,
                explanation="No probes triggered.",
                action_id=action.id,
            )

        # Sort triggered probes by (severity rank desc, confidence desc) for UX.
        triggered.sort(key=lambda r: (r.severity.rank, r.confidence), reverse=True)

        has_critical = any(r.severity is Severity.CRITICAL for r in triggered)
        max_conf = max(r.confidence for r in triggered)

        if has_critical or max_conf >= self.block_threshold:
            decision = "block"
        elif max_conf >= self.flag_threshold:
            decision = "flag"
        else:
            decision = "allow"

        explanation = (
            f"{len(triggered)} probe(s) triggered: "
            + " | ".join(f"{r.probe} ({r.severity.value})" for r in triggered)
        )

        return Verdict(
            decision=decision,
            suspicion_score=max_conf,
            probes_triggered=triggered,
            all_probes=all_results,
            explanation=explanation,
            action_id=action.id,
        )

    def allow(self, action: Action) -> bool:
        """Shorthand: True iff ``check(action)`` yields an allow decision."""
        return self.check(action).allowed

    # ─── Decorator ────────────────────────────────────────────────────────────

    def protect(self, func: Callable[..., Any]) -> Callable[..., Any]:
        """Decorator: wrap an agent step function.

        Expects the first positional argument (after ``self`` for bound
        methods, or simply the first argument for free functions) to be
        an :class:`Action` or a mapping coercible to one. Raises
        :class:`BlockedAction` if the guard blocks the action.
        """

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if not args:
                raise TypeError("Guard-protected function must receive an Action as first arg")

            action_arg = args[0]
            if isinstance(action_arg, Action):
                action = action_arg
            elif isinstance(action_arg, dict):
                action = Action.model_validate(action_arg)
            else:
                raise TypeError(
                    f"Guard-protected function expected Action or dict, got {type(action_arg).__name__}"
                )

            verdict = self.check(action)
            if verdict.blocked:
                raise BlockedAction(verdict)
            return func(*args, **kwargs)

        return wrapper
