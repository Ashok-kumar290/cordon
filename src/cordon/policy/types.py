"""Policy DSL data model.

A :class:`Policy` is a base profile name plus a list of :class:`Rule`
objects. Each rule has an *action* and a list of *predicates*; the
rule fires when **all** predicates match (logical AND). Predicates
themselves are simple ``(field, op, value)`` triples — no nesting,
no OR — because customer-facing DSLs over-engineer in two days flat
and the resulting grammar nobody can debug.

The types here are plain dataclasses (rather than Pydantic models)
because:

* They're internal to the parser ⇄ runtime boundary.
* They go through trivial JSON conversion in
  :class:`cloud_server.storage.PolicyStore`, where we always
  re-serialise from the source text rather than from the object
  graph. Round-trip stability is therefore the parser's job, not
  the dataclass's.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from cordon.core.types import Decision

# ─── Vocabulary ──────────────────────────────────────────────────────────────

#: What a rule does to the verdict when it matches. ``allow``/``flag``/
#: ``block`` map directly to :data:`cordon.Decision` values; the rule
#: simply overrides the decision (and lets the suspicion score and
#: probe trail stand as-is, so the dashboard still shows *why* the
#: rule chose to intervene).
RuleAction = Literal["allow", "flag", "block"]

#: Predicate left-hand sides. Kept deliberately small and concrete —
#: every entry must be cheap to evaluate against an :class:`Action`
#: + :class:`Verdict` pair, with no regex back-ends.
PREDICATE_FIELDS: tuple[str, ...] = (
    "command_starts_with",
    "command_contains",
    "path_starts_with",
    "path_contains",
    "probe",
    "kind",
)

#: The three base profiles a policy can extend.
PROFILES: tuple[str, ...] = ("strict", "default", "permissive")


# ─── Predicate ───────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Predicate:
    """One ``field: value`` clause inside a rule.

    Attributes:
        field: One of :data:`PREDICATE_FIELDS`.
        value: The literal string to compare against. Comparison
            semantics depend on ``field`` (see
            :func:`cordon.policy.runtime.predicate_matches`).
    """

    field: str
    value: str

    def __post_init__(self) -> None:
        if self.field not in PREDICATE_FIELDS:
            raise ValueError(
                f"unknown predicate field {self.field!r}; expected one of "
                f"{', '.join(PREDICATE_FIELDS)}"
            )
        if not isinstance(self.value, str):
            raise ValueError(
                f"predicate value must be a string, got {type(self.value).__name__}"
            )


# ─── Rule ────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Rule:
    """One override rule: ``<action> when <predicates joined by AND>``.

    Attributes:
        action: What to do when this rule matches (``allow``,
            ``flag``, or ``block``).
        predicates: All predicates that must match. Empty tuple means
            *match every action* — useful for sweeping overrides like
            ``allow when`` (no predicates) which downgrades everything
            to allow. The parser warns on the empty form to prevent
            footguns.
        line: 1-indexed source line, for error messages and dashboard
            highlighting. Zero when constructed programmatically.
    """

    action: RuleAction
    predicates: tuple[Predicate, ...]
    line: int = 0

    def __post_init__(self) -> None:
        if self.action not in ("allow", "flag", "block"):
            raise ValueError(
                f"rule action must be 'allow' | 'flag' | 'block', got {self.action!r}"
            )


# ─── Policy ──────────────────────────────────────────────────────────────────


@dataclass
class Policy:
    """A parsed Cordon policy document.

    Attributes:
        profile: Base profile (``strict`` / ``default`` /
            ``permissive``). Always present — the parser requires it
            as the first non-comment line of the document.
        rules: Override rules in document order. Apply top-to-bottom;
            the first matching rule mutates the verdict.
        source: The original text the policy was parsed from. Stored
            verbatim so the dashboard can show the user's exact
            formatting (comments, whitespace, blank lines).
    """

    profile: str
    rules: list[Rule] = field(default_factory=list)
    source: str = ""

    def __post_init__(self) -> None:
        if self.profile not in PROFILES:
            raise ValueError(
                f"unknown profile {self.profile!r}; expected one of "
                f"{', '.join(PROFILES)}"
            )

    # Convenience: a stable Decision result-type for the runtime to
    # narrow against without re-importing the literal everywhere.
    Decision = Decision  # noqa: F811  (re-export for module-internal use)
