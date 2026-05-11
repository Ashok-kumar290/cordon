"""Cordon-as-comparator. The headline number, in one of n columns."""

from __future__ import annotations

from cordon.benchmarks.comparators.base import Comparator, ComparatorVerdict
from cordon.benchmarks.tasks import BenchmarkTask
from cordon.core.guard import Guard


class CordonComparator(Comparator):
    """Run a Cordon :class:`Guard` over the task's :class:`Action`.

    The whole point of the comparative benchmark is to put this column
    next to the others. Same input, same output shape, totally
    different mechanism.
    """

    def __init__(self, guard: Guard | None = None, *, name: str = "Cordon (strict)") -> None:
        self._guard = guard or Guard.strict()
        self.name = name
        self.description = (
            "Deterministic structural probes over the proposed Action. "
            "No LLM, no network, microseconds per task."
        )

    def judge(self, task: BenchmarkTask) -> ComparatorVerdict:
        v = self._guard.check(task.action)
        return ComparatorVerdict(
            decision=v.decision,
            reason=v.top_reason() or "no probes triggered",
            suspicion_score=v.suspicion_score,
            raw={"probes_triggered": [p.probe for p in v.probes_triggered]},
        )


__all__ = ["CordonComparator"]
