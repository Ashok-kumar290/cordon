"""Runtime tests: what does the policy actually *do* to verdicts.

The parser tests pin grammar; these tests pin semantics. We construct
Action/Verdict pairs directly (rather than running probes against
real attacks) so the tests stay fast and don't drift if the probe
behaviour evolves.
"""

from __future__ import annotations

import pytest

from cordon.core.types import Action, ProbeResult, Severity, Verdict
from cordon.policy import apply_policy, parse
from cordon.policy.runtime import predicate_matches, rule_matches
from cordon.policy.types import Predicate, Rule


# ─── Helpers ────────────────────────────────────────────────────────────────


def _verdict(
    decision: str = "block",
    triggered: list[ProbeResult] | None = None,
    explanation: str = "",
) -> Verdict:
    triggered = triggered or []
    return Verdict(
        decision=decision,  # type: ignore[arg-type]
        suspicion_score=max((r.confidence for r in triggered), default=0.0),
        probes_triggered=triggered,
        all_probes=triggered,
        explanation=explanation or "probes triggered",
    )


def _probe_result(probe: str, severity: Severity = Severity.CRITICAL, conf: float = 0.95) -> ProbeResult:
    return ProbeResult(
        probe=probe, severity=severity, confidence=conf,
        evidence=f"{probe} fired", triggered=True,
    )


# ─── predicate_matches ──────────────────────────────────────────────────────


class TestPredicateMatches:
    def test_command_starts_with_positive(self):
        action = Action(kind="shell", command="rm -rf node_modules")
        assert predicate_matches(
            Predicate("command_starts_with", "rm -rf node_modules"),
            action, _verdict(),
        ) is True

    def test_command_starts_with_negative(self):
        action = Action(kind="shell", command="ls -la")
        assert predicate_matches(
            Predicate("command_starts_with", "rm "),
            action, _verdict(),
        ) is False

    def test_command_contains(self):
        action = Action(kind="shell", command="sudo chmod 777 /etc")
        assert predicate_matches(Predicate("command_contains", "chmod"), action, _verdict()) is True
        assert predicate_matches(Predicate("command_contains", "ssh"),   action, _verdict()) is False

    def test_command_predicates_dont_match_file_only_action(self):
        """Write-only actions have command=None and must not match command-keyed rules."""
        action = Action(kind="file", changes={"a.py": "print(1)"})
        assert predicate_matches(
            Predicate("command_starts_with", "rm"), action, _verdict(),
        ) is False

    def test_path_starts_with_any_changed_file_matches(self):
        action = Action(kind="file", changes={
            "src/a.py":   "x = 1",
            "/etc/hosts": "127.0.0.1 evil",
        })
        assert predicate_matches(Predicate("path_starts_with", "/etc/"), action, _verdict()) is True

    def test_path_starts_with_none_match(self):
        action = Action(kind="file", changes={"src/a.py": "x = 1"})
        assert predicate_matches(Predicate("path_starts_with", "/etc/"), action, _verdict()) is False

    def test_path_contains(self):
        action = Action(kind="file", changes={"src/secrets/aws.txt": ""})
        assert predicate_matches(Predicate("path_contains", "secrets"), action, _verdict()) is True
        assert predicate_matches(Predicate("path_contains", "vendor"),  action, _verdict()) is False

    def test_probe_matches_triggered_probe(self):
        v = _verdict(triggered=[_probe_result("typosquat")])
        assert predicate_matches(Predicate("probe", "typosquat"), Action(kind="shell"), v) is True

    def test_probe_no_match_on_empty_verdict(self):
        assert predicate_matches(
            Predicate("probe", "typosquat"), Action(kind="shell"), _verdict(triggered=[]),
        ) is False

    def test_kind_matches_case_insensitive(self):
        action = Action(kind="shell", command="ls")
        assert predicate_matches(Predicate("kind", "shell"), action, _verdict()) is True
        assert predicate_matches(Predicate("kind", "Shell"), action, _verdict()) is True
        assert predicate_matches(Predicate("kind", "file"),  action, _verdict()) is False


# ─── rule_matches (AND semantics) ───────────────────────────────────────────


def test_rule_with_all_predicates_matching():
    action = Action(kind="shell", command="chmod 777 /etc/shadow")
    rule = Rule(action="block", predicates=(
        Predicate("command_contains", "chmod"),
        Predicate("command_contains", "/etc"),
    ))
    assert rule_matches(rule, action, _verdict()) is True


def test_rule_with_one_predicate_failing():
    action = Action(kind="shell", command="chmod 777 /home/x")
    rule = Rule(action="block", predicates=(
        Predicate("command_contains", "chmod"),
        Predicate("command_contains", "/etc"),
    ))
    assert rule_matches(rule, action, _verdict()) is False


def test_empty_rule_is_sweep_match():
    """No predicates → matches every action (foot-gun the parser warns about)."""
    rule = Rule(action="flag", predicates=())
    for cmd in ["ls", "rm -rf /", "echo hi"]:
        assert rule_matches(rule, Action(kind="shell", command=cmd), _verdict()) is True


# ─── apply_policy: end-to-end mutation ──────────────────────────────────────


class TestApplyPolicy:
    def test_no_rules_preserves_verdict_identity(self):
        policy = parse("profile: strict")
        original = _verdict(decision="block")
        out = apply_policy(policy, Action(kind="shell", command="rm -rf /"), original)
        assert out is original   # identity, not equality

    def test_first_matching_rule_wins(self):
        """Two carve-outs that both match; the first one in document order wins."""
        policy = parse("""
profile: strict
allow when command_starts_with: "rm -rf node_modules"
flag  when command_starts_with: "rm -rf"
""")
        original = _verdict(decision="block")
        out = apply_policy(
            policy, Action(kind="shell", command="rm -rf node_modules"), original,
        )
        assert out.decision == "allow"

    def test_carveout_downgrades_block_to_allow(self):
        policy = parse('profile: strict\nallow when command_starts_with: "rm -rf node_modules"')
        original = _verdict(decision="block", triggered=[_probe_result("destructive_shell")])
        out = apply_policy(policy, Action(kind="shell", command="rm -rf node_modules"), original)
        assert out.decision == "allow"
        # Probe trail preserved verbatim — operators must still see *why*
        # the base profile fired.
        assert out.probes_triggered == original.probes_triggered

    def test_promote_allow_to_block(self):
        policy = parse('profile: default\nblock when path_starts_with: "/etc/"')
        original = _verdict(decision="allow", triggered=[])
        action = Action(kind="file", changes={"/etc/hosts": "..."})
        out = apply_policy(policy, action, original)
        assert out.decision == "block"

    def test_no_matching_rule_returns_original(self):
        policy = parse('profile: strict\nallow when command_starts_with: "ls"')
        original = _verdict(decision="block")
        out = apply_policy(policy, Action(kind="shell", command="rm -rf /"), original)
        assert out is original

    def test_explanation_annotated_with_line_and_rule(self):
        policy = parse("""
profile: strict
allow when command_starts_with: "rm -rf node_modules"
""")
        original = _verdict(
            decision="block",
            triggered=[_probe_result("destructive_shell")],
            explanation="destructive_shell critical",
        )
        out = apply_policy(
            policy, Action(kind="shell", command="rm -rf node_modules"), original,
        )
        assert out.decision == "allow"
        assert "policy line 3" in out.explanation
        assert "destructive_shell" in out.explanation   # base reason preserved


# ─── Guard.from_policy integration ──────────────────────────────────────────


class TestGuardFromPolicy:
    def test_basic_carveout_against_real_probes(self):
        from cordon import Action, Guard

        guard = Guard.from_policy("""
profile: strict
allow when command_starts_with: "rm -rf node_modules"
""")
        # The destructive_shell probe normally blocks `rm -rf node_modules` only
        # if its pattern matches; let's verify the carve-out works against real
        # probes by using a definitely-blocked attack and a known carve-out.
        blocked = guard.check(Action(kind="shell", command="rm -rf --no-preserve-root /"))
        assert blocked.decision == "block"

        allowed = guard.check(Action(kind="shell", command="rm -rf node_modules"))
        # Whether the probe fires or not, the carve-out forces allow.
        assert allowed.decision == "allow"

    def test_promote_chmod_etc_to_block(self):
        from cordon import Action, Guard
        guard = Guard.from_policy("""
profile: default
block when command_contains: "chmod" and command_contains: "/etc"
""")
        v = guard.check(Action(kind="shell", command="chmod 644 /etc/shadow"))
        assert v.decision == "block"
        # And the policy annotation must reach the explanation.
        assert "policy line" in v.explanation

    def test_guard_name_reflects_policy(self):
        from cordon import Guard
        guard = Guard.from_policy("profile: permissive")
        assert guard.name == "permissive+policy"

    def test_invalid_policy_raises_parse_error(self):
        from cordon import Guard
        from cordon.policy import PolicyParseError

        with pytest.raises(PolicyParseError):
            Guard.from_policy("profile: paranoid")
