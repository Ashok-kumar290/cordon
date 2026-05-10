"""Core types for Cordon.

All probes and guards speak in terms of these types. The design goals:

1.  **`Action`** is a narrow description of what the agent proposes to do,
    plus structured side-effect metadata (file changes, shell commands,
    network calls). Probes inspect this structure — they never execute
    the action.

2.  **`ProbeResult`** is what a single probe returns. Every probe reports
    a severity, a confidence, and human-readable evidence. Probes never
    make the final allow/flag/block decision — the `Guard` aggregates.

3.  **`Verdict`** is what the `Guard` returns to the caller. It carries
    the final decision plus a complete audit trail of every probe that
    triggered.

Types are Pydantic models so they serialize cleanly to JSON for traces,
audit logs, and the hosted dashboard.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


# ─── Severity and Decision ────────────────────────────────────────────────────


class Severity(str, Enum):
    """Probe-level severity. Ordered from least to most severe."""

    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    DANGEROUS = "dangerous"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {
            Severity.SAFE: 0,
            Severity.SUSPICIOUS: 1,
            Severity.DANGEROUS: 2,
            Severity.CRITICAL: 3,
        }[self]


Decision = Literal["allow", "flag", "block"]


# ─── Action (what the agent wants to do) ──────────────────────────────────────


class Action(BaseModel):
    """A proposed agent action, in structured form.

    Probes inspect this object. Cordon never executes actions itself —
    execution happens downstream in the caller's infrastructure only
    after `Guard.check()` returns `allow`.

    Attributes:
        id: Optional identifier (e.g., step UUID). Used for trace joins.
        kind: The type of action. Free-form for future probes, but core
            probes understand `"shell"`, `"file"`, `"network"`, and
            `"tool"` out of the box.
        intent: A one-line natural-language description of what the
            agent is trying to achieve. Not used for blocking; kept for
            audit logs and future LLM-assisted probes.
        command: For shell actions — the literal command that would run.
        changes: Map of `{filepath: new_content}` describing file writes
            the action would perform. Used by static semantic probes.
        deletions: List of filepaths the action would delete.
        reads: List of filepaths the action would read.
        network: List of outbound URLs/hostnames the action would
            contact.
        workspace_files: Optional snapshot of current-state file
            contents keyed by path. Allows probes to diff `changes`
            against the existing workspace.
        metadata: Open dict for probe-specific extensions (e.g., the
            tool name for `tool` actions, the model that proposed the
            action, conversation turn index).
    """

    id: str | None = None
    kind: str = Field(default="shell")
    intent: str | None = None

    command: str | None = None
    changes: dict[str, str] = Field(default_factory=dict)
    deletions: list[str] = Field(default_factory=list)
    reads: list[str] = Field(default_factory=list)
    network: list[str] = Field(default_factory=list)
    workspace_files: dict[str, str] = Field(default_factory=dict)

    metadata: dict[str, Any] = Field(default_factory=dict)

    def has_file_changes(self) -> bool:
        return bool(self.changes or self.deletions)

    def has_network(self) -> bool:
        return bool(self.network)


# ─── Probe output ─────────────────────────────────────────────────────────────


class ProbeResult(BaseModel):
    """Output of a single probe invocation.

    Attributes:
        probe: Canonical probe name (e.g., ``"typosquat"``).
        severity: One of `Severity.SAFE / SUSPICIOUS / DANGEROUS / CRITICAL`.
        confidence: How confident the probe is that the flagged pattern
            is truly malicious. 0.0 = no signal, 1.0 = certain.
            `SAFE` severity always has confidence 0.0.
        evidence: Short human-readable string suitable for an audit log
            or a `cordon check --explain` CLI output.
        details: Optional structured details (matched patterns, offsets,
            package names, etc.). Useful for dashboards.
    """

    probe: str
    severity: Severity = Severity.SAFE
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    evidence: str = ""
    details: dict[str, Any] = Field(default_factory=dict)

    @property
    def triggered(self) -> bool:
        """True if this probe flagged anything above SAFE."""
        return self.severity is not Severity.SAFE


# ─── Final verdict ────────────────────────────────────────────────────────────


class Verdict(BaseModel):
    """Aggregated decision from all probes run against an action.

    Attributes:
        decision: One of ``"allow"``, ``"flag"``, or ``"block"``.
        suspicion_score: Aggregated suspicion (max of triggered probe
            confidences). 0.0 when nothing fired.
        probes_triggered: All probe results that returned a non-SAFE
            severity, in descending severity/confidence order.
        all_probes: Every probe that ran (including SAFE), for audit
            completeness.
        explanation: One-paragraph human-readable summary.
        action_id: Mirrors ``Action.id`` when provided, so verdicts
            can be joined back to actions in trace logs.
    """

    decision: Decision
    suspicion_score: float = Field(default=0.0, ge=0.0, le=1.0)
    probes_triggered: list[ProbeResult] = Field(default_factory=list)
    all_probes: list[ProbeResult] = Field(default_factory=list)
    explanation: str = ""
    action_id: str | None = None

    # Convenience accessors used in agent code: `if verdict.blocked: raise ...`
    @property
    def blocked(self) -> bool:
        return self.decision == "block"

    @property
    def flagged(self) -> bool:
        return self.decision == "flag"

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"

    def top_reason(self) -> str:
        """Return the evidence string of the highest-confidence triggered probe."""
        if not self.probes_triggered:
            return "No probes triggered."
        return self.probes_triggered[0].evidence
