"""Apply a parsed :class:`Policy` to a base Guard's verdict.

The runtime is a single function — :func:`apply_policy` — that:

1. Inspects the current ``Action`` + ``Verdict`` pair.
2. Walks the policy's rules top-to-bottom.
3. Returns a new ``Verdict`` whose ``decision`` is mutated by the
   first matching rule (or the original verdict if no rule matches).

The probe trail (``probes_triggered``, ``all_probes``) is *not*
mutated — operators looking at the dashboard need to see *why* the
base profile fired, even when a policy rule overrode the decision.
The explanation string gets a trailing ``"; policy: line N <action>
<predicates>"`` annotation so it's obvious at a glance where the
final decision came from.
"""

from __future__ import annotations

from cordon.core.types import Action, Verdict
from cordon.policy.types import Policy, Predicate, Rule


# ─── Predicate evaluation ────────────────────────────────────────────────────


def predicate_matches(p: Predicate, action: Action, verdict: Verdict) -> bool:
    """True if ``p`` matches the action/verdict pair.

    Field semantics:

    * ``command_starts_with`` / ``command_contains``: tested against
      ``action.command`` (empty string when None — so a policy rule
      keyed on a command never matches a write-only file action).
    * ``path_starts_with`` / ``path_contains``: tested against every
      key in ``action.changes`` — *any* file path matching counts
      as a match. The intent is "this rule applies to actions that
      touch a path that looks like X", not "every path matches".
    * ``probe``: matches when a probe with that name appears in
      ``verdict.probes_triggered``. Empty / unfired verdicts never
      match.
    * ``kind``: exact-match on ``action.kind`` (case-insensitive
      via lowercased comparison, because hand-written policies
      commonly write ``Shell`` or ``FILE``).
    """
    if p.field == "command_starts_with":
        return (action.command or "").startswith(p.value)
    if p.field == "command_contains":
        return p.value in (action.command or "")
    if p.field == "path_starts_with":
        return any(path.startswith(p.value) for path in (action.changes or {}))
    if p.field == "path_contains":
        return any(p.value in path for path in (action.changes or {}))
    if p.field == "probe":
        return any(pr.probe == p.value for pr in verdict.probes_triggered)
    if p.field == "kind":
        return (action.kind or "").lower() == p.value.lower()
    # Should be unreachable — Predicate.__post_init__ guards the field set.
    return False


def rule_matches(r: Rule, action: Action, verdict: Verdict) -> bool:
    """True if every predicate in ``r`` matches (logical AND).

    A rule with zero predicates is a sweep — it matches every action.
    That's the foot-gun behavior the parser warns about; the runtime
    honors it because there are legitimate "force everything to flag"
    use cases (e.g., dry-run mode for a new policy).
    """
    return all(predicate_matches(p, action, verdict) for p in r.predicates)


# ─── Verdict mutation ────────────────────────────────────────────────────────


def apply_policy(policy: Policy, action: Action, verdict: Verdict) -> Verdict:
    """Apply ``policy`` to ``verdict`` and return the (possibly mutated) result.

    Rules are tried in document order; the first match wins. The
    returned object is a new :class:`Verdict` (via
    ``model_copy(update=...)``) when a rule fires, or the original
    verdict otherwise — so callers can use ``is``-identity to detect
    whether the policy intervened.

    Args:
        policy: A parsed policy (see :func:`cordon.policy.parse`).
        action: The action whose verdict is being evaluated.
        verdict: The verdict produced by the base profile's probes.

    Returns:
        A :class:`Verdict` with the policy's decision applied. The
        probe trail is preserved verbatim; only ``decision`` and
        ``explanation`` may change.
    """
    for rule in policy.rules:
        if not rule_matches(rule, action, verdict):
            continue
        return verdict.model_copy(update={
            "decision": rule.action,
            "explanation": _annotate(verdict.explanation, rule, action, verdict),
        })
    return verdict


def _annotate(explanation: str, rule: Rule, action: Action, verdict: Verdict) -> str:
    """Append a `; policy: line N <action> when ...` trailer to the explanation.

    The trailer is what makes audits sensible: when a security
    engineer looks at the dashboard and sees a ``BLOCK`` they don't
    recognise, they immediately know whether it came from a probe
    (no trailer) or a policy rule (trailer with line number).
    """
    preds = ", ".join(f"{p.field}: {p.value!r}" for p in rule.predicates) or "(no predicates)"
    note = f"policy line {rule.line} → {rule.action} when {preds}"
    if not explanation:
        return note
    sep = "; " if not explanation.rstrip().endswith(";") else " "
    return f"{explanation.rstrip()}{sep}{note}"
