"""Comparators — pluggable judges for the comparative benchmark.

Each comparator implements the same minimal interface (``judge(task)
-> ComparatorVerdict``). This lets us run the *same* 42-task suite
through Cordon, naive keyword heuristics, transcript-only LLM
judging, and external services like Lakera and run head-to-head.

The framework is the moat. Specific comparators (especially
external-API ones) are slotted in or skipped depending on whether
credentials are available.
"""

from cordon.benchmarks.comparators.base import (
    Comparator,
    ComparatorResult,
    ComparatorVerdict,
)
from cordon.benchmarks.comparators.cordon_ import CordonComparator
from cordon.benchmarks.comparators.heuristic import KeywordHeuristicComparator
from cordon.benchmarks.comparators.transcript import TranscriptOnlyComparator

__all__ = [
    "Comparator",
    "ComparatorResult",
    "ComparatorVerdict",
    "CordonComparator",
    "KeywordHeuristicComparator",
    "TranscriptOnlyComparator",
]


def _try_import_lakera() -> type | None:
    try:
        from cordon.benchmarks.comparators.lakera import LakeraComparator
        return LakeraComparator
    except Exception:  # noqa: BLE001
        return None


def _try_import_llm_judge() -> type | None:
    try:
        from cordon.benchmarks.comparators.llm_judge import LLMJudgeComparator
        return LLMJudgeComparator
    except Exception:  # noqa: BLE001
        return None
