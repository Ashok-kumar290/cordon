"""Abstract base class for all probes.

A probe is a pure function of an :class:`~cordon.core.types.Action` that
produces a :class:`~cordon.core.types.ProbeResult`. Probes must:

* Be deterministic (same `Action` → same `ProbeResult`). This is the
  research-grade property that makes Cordon auditable: you can replay
  any verdict and get the same answer.
* Never execute side effects. Probes may parse, match, diff, or
  statically analyze content, but must never run shell commands, open
  network connections, or write files.
* Be cheap. The design target is < 10 ms per probe per action on
  typical payloads. Heavy analysis belongs in a separate "deep" probe
  tier that is opt-in.

Subclasses implement :meth:`Probe.analyze`. The :meth:`Probe.run` method
wraps ``analyze`` with error handling so a broken probe never takes
down the whole ``Guard``.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod

from cordon.core.types import Action, ProbeResult, Severity

logger = logging.getLogger(__name__)


class Probe(ABC):
    """Abstract base for all Cordon probes."""

    #: Canonical probe name. Used in ProbeResult.probe and in CLI flags.
    name: str = "probe"

    #: Short human-readable description. Shown in ``cordon list-probes``.
    description: str = ""

    #: Tier: `"fast"` (< 10ms, always-on) or `"deep"` (opt-in, may be slow).
    tier: str = "fast"

    @abstractmethod
    def analyze(self, action: Action) -> ProbeResult:
        """Inspect an action and return a single :class:`ProbeResult`."""

    def run(self, action: Action) -> ProbeResult:
        """Run the probe, catching any exception and reporting it as SAFE.

        The philosophy: a probe that crashes should not crash the guard,
        but it also must not silently pretend the action is safe. We
        emit a probe result with severity SAFE (so it does not block)
        but include the error in ``details`` for audit visibility.
        """
        try:
            return self.analyze(action)
        except Exception as e:  # noqa: BLE001 — intentional broad catch
            logger.warning("Probe %s failed: %s", self.name, e)
            return ProbeResult(
                probe=self.name,
                severity=Severity.SAFE,
                confidence=0.0,
                evidence=f"Probe error (see details): {type(e).__name__}",
                details={"error": str(e), "error_type": type(e).__name__},
            )
