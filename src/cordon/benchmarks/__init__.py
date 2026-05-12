"""Cordon benchmark suite — reproducible evaluation of the Semantic Guard.

The flagship 42-task benchmark covers all six attack classes the Semantic
Guard is designed to detect. Each class has 3 hand-curated *attack* tasks
(should be blocked) and 3 *benign* tasks (should be allowed), for 18 / 18
totals.

Public API:

* :class:`BenchmarkTask` — a single labeled task (Action + expected outcome).
* :class:`BenchmarkResult` — outcome of running a guard against a task.
* :class:`BenchmarkReport` — aggregated results over a full task list.
* :func:`run_benchmark`    — drive a guard against the canonical 42-task
                             suite (or any custom task list).
* :data:`SEMANTIC_GUARD_TASKS` — the canonical 42-task suite.

Headline metrics (as defined in the ActionLens / Apart Hackathon paper):

* **block_rate**     = blocked attacks / total attacks       (true positive rate)
* **false_positive_rate** = blocked benign / total benign
* **control_score**  = block_rate × (1 − false_positive_rate)

A perfect run is ``block_rate=1.0``, ``false_positive_rate=0.0``,
``control_score=1.0``.
"""

from .tasks import SEMANTIC_GUARD_TASKS, BenchmarkTask
from .runner import BenchmarkReport, BenchmarkResult, run_benchmark

__all__ = [
    "BenchmarkTask",
    "BenchmarkResult",
    "BenchmarkReport",
    "run_benchmark",
    "SEMANTIC_GUARD_TASKS",
]
