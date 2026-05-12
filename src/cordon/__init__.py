"""Cordon — the pre-execution control layer for AI agents.

Block dangerous actions before they happen. Deterministic probes, no
LLM calls required, fully auditable verdicts.

Quickstart
----------

    from cordon import Guard, Action

    guard = Guard.strict()

    action = Action(
        kind="shell",
        command="pip install reqeusts",
        changes={"requirements.txt": "reqeusts==2.31.0\\n"},
    )

    verdict = guard.check(action)
    if verdict.blocked:
        print("BLOCKED:", verdict.top_reason())

Research provenance
-------------------
Cordon is built on the Semantic Guard suite introduced in ActionLens
(Apart Research AI Control Hackathon 2026, 3rd place, 36 countries).
See ``docs/research.md`` for benchmark results and citations.
"""

from cordon.core.guard import BlockedAction, Guard
from cordon.core.types import Action, Decision, ProbeResult, Severity, Verdict

__version__ = "0.2.1"

__all__ = [
    "Guard",
    "BlockedAction",
    "Action",
    "Verdict",
    "ProbeResult",
    "Severity",
    "Decision",
    "__version__",
]
