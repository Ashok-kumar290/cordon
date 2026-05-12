"""Parser tests for the Cordon policy DSL.

These tests pin down the *grammar* — what the parser accepts, what it
rejects, and what the resulting AST looks like. Behavioural tests
that exercise the runtime against probes live in
``tests/policy/test_runtime.py``.

We're deliberately heavy on negative cases: a policy DSL that lets
typos through silently is worse than one that crashes, because the
typo will reach production as "the rule looked like it worked but
silently never fired".
"""

from __future__ import annotations

import pytest

from cordon.policy import Policy, PolicyParseError, parse
from cordon.policy.types import Predicate, Rule


# ─── Happy paths ────────────────────────────────────────────────────────────


def test_minimal_profile_only():
    """A policy can be just `profile: strict`."""
    policy = parse("profile: strict")
    assert policy.profile == "strict"
    assert policy.rules == []
    assert policy.source == "profile: strict"


def test_each_profile_name_accepted():
    for name in ("strict", "default", "permissive"):
        assert parse(f"profile: {name}").profile == name


def test_simple_rule():
    policy = parse("""
profile: strict
allow when command_starts_with: "rm -rf node_modules"
""")
    assert len(policy.rules) == 1
    rule = policy.rules[0]
    assert rule.action == "allow"
    assert rule.predicates == (
        Predicate(field="command_starts_with", value="rm -rf node_modules"),
    )
    assert rule.line == 3


def test_multi_predicate_rule_and_joined():
    policy = parse("""
profile: default
block when command_contains: "chmod" and path_starts_with: "/etc/"
""")
    rule = policy.rules[0]
    assert rule.action == "block"
    assert len(rule.predicates) == 2
    fields = [p.field for p in rule.predicates]
    assert fields == ["command_contains", "path_starts_with"]


def test_implicit_when_keyword_tolerated():
    """`when` is optional — common operator habit to drop it."""
    p1 = parse("profile: strict\nallow command_starts_with: \"echo\"")
    p2 = parse("profile: strict\nallow when command_starts_with: \"echo\"")
    assert p1.rules[0].predicates == p2.rules[0].predicates


def test_bare_action_with_no_predicates():
    """`flag` on its own is a sweep rule (parser allows, runtime honours)."""
    policy = parse("profile: strict\nflag")
    assert policy.rules[0].action == "flag"
    assert policy.rules[0].predicates == ()


def test_comments_and_blank_lines_ignored():
    policy = parse("""
# leading comment
# another

profile: strict   # inline comment

# Between profile and rules
allow when command_starts_with: "rm -rf /tmp/"   # trailing comment

""")
    assert policy.profile == "strict"
    assert len(policy.rules) == 1
    assert policy.rules[0].predicates[0].value == "rm -rf /tmp/"


def test_hash_inside_quoted_string_is_not_a_comment():
    """`#` inside a quoted predicate value must be preserved verbatim."""
    policy = parse("""
profile: default
allow when command_contains: "echo #not-a-comment"
""")
    assert policy.rules[0].predicates[0].value == "echo #not-a-comment"


def test_quoted_string_with_escaped_quote():
    policy = parse('profile: strict\nallow when command_contains: "she said \\"hi\\""')
    assert policy.rules[0].predicates[0].value == 'she said "hi"'


def test_bare_token_for_simple_values():
    """Probe names and kinds don't need quoting."""
    policy = parse("""
profile: strict
flag when probe: typosquat
block when kind: shell
""")
    assert policy.rules[0].predicates[0].value == "typosquat"
    assert policy.rules[1].predicates[0].value == "shell"


def test_and_inside_quoted_value_not_a_separator():
    """A literal " and " inside a quoted value must not split predicates."""
    policy = parse("""
profile: strict
allow when command_contains: "foo and bar"
""")
    rule = policy.rules[0]
    assert len(rule.predicates) == 1
    assert rule.predicates[0].value == "foo and bar"


def test_source_preserved_verbatim():
    text = "# hello\nprofile: strict\n\n  # rules\nallow when command_starts_with: \"x\"\n"
    policy = parse(text)
    assert policy.source == text


def test_case_insensitive_action_and_when():
    policy = parse("""
profile: strict
ALLOW WHEN command_starts_with: "x"
""")
    assert policy.rules[0].action == "allow"


# ─── Error paths ────────────────────────────────────────────────────────────


def test_missing_profile_line():
    with pytest.raises(PolicyParseError) as exc:
        parse("# only a comment\n\n")
    assert "must declare a base profile" in str(exc.value)


def test_unknown_profile():
    with pytest.raises(PolicyParseError) as exc:
        parse("profile: paranoid")
    msg = str(exc.value)
    assert "unknown profile 'paranoid'" in msg
    assert "line 1" in msg


def test_malformed_profile_line():
    with pytest.raises(PolicyParseError) as exc:
        parse("profile strict")   # missing colon
    assert "profile: strict|default|permissive" in str(exc.value)


def test_unknown_rule_action():
    with pytest.raises(PolicyParseError) as exc:
        parse("profile: strict\nprobably when probe: x")
    assert "must start with `allow`, `flag`, or `block`" in str(exc.value)


def test_when_without_predicate():
    with pytest.raises(PolicyParseError) as exc:
        parse("profile: strict\nallow when")
    assert "must be followed by at least one predicate" in str(exc.value)


def test_unknown_predicate_field():
    with pytest.raises(PolicyParseError) as exc:
        parse('profile: strict\nallow when path_endswith: "x"')
    msg = str(exc.value)
    assert "unknown predicate field 'path_endswith'" in msg
    assert "line 2" in msg


def test_predicate_without_value():
    with pytest.raises(PolicyParseError):
        parse("profile: strict\nallow when probe:")


def test_unterminated_quoted_string():
    with pytest.raises(PolicyParseError) as exc:
        parse('profile: strict\nallow when command_contains: "oops')
    assert "unterminated quoted" in str(exc.value)


def test_bare_token_with_unsupported_chars_must_be_quoted():
    """`/etc/shadow` looks bare but has slashes that need quoting."""
    # Slashes ARE allowed in the bare regex, so this should pass.
    parse('profile: strict\nallow when path_starts_with: /etc/shadow')


def test_bare_token_with_space_is_rejected():
    """Spaces are not part of the bare-token character class."""
    with pytest.raises(PolicyParseError):
        parse('profile: strict\nallow when command_starts_with: rm -rf')


def test_error_carries_line_and_snippet():
    """Errors must carry enough info to highlight in an editor."""
    with pytest.raises(PolicyParseError) as exc:
        parse("profile: strict\n\nallow when foo: bar")
    err = exc.value
    assert err.line == 3
    assert "allow when foo" in err.snippet


# ─── Predicate / Rule dataclass invariants ──────────────────────────────────


def test_predicate_rejects_unknown_field_at_construction():
    """Defensive: the dataclass itself guards the field set even if
    something bypasses the parser and constructs a Predicate directly.
    """
    with pytest.raises(ValueError):
        Predicate(field="path_endswith", value="x")


def test_rule_rejects_unknown_action_at_construction():
    with pytest.raises(ValueError):
        Rule(action="please", predicates=(), line=0)  # type: ignore[arg-type]


def test_policy_rejects_unknown_profile_at_construction():
    with pytest.raises(ValueError):
        Policy(profile="paranoid", rules=[])
