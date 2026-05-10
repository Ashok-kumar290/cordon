"""End-to-end tests for the Guard."""

from __future__ import annotations

import pytest

from cordon import Action, Guard
from cordon.core.guard import BlockedAction


def test_allow_on_clean_action() -> None:
    guard = Guard.default()
    verdict = guard.check(Action(kind="shell", command="echo hello"))
    assert verdict.allowed
    assert verdict.suspicion_score == 0.0


def test_block_on_critical_typosquat() -> None:
    guard = Guard.default()
    verdict = guard.check(
        Action(kind="shell", changes={"requirements.txt": "reqeusts==2.31.0\n"})
    )
    assert verdict.blocked
    assert any(p.probe == "typosquat" for p in verdict.probes_triggered)


def test_strict_profile_lower_thresholds_still_blocks_critical() -> None:
    guard = Guard.strict()
    verdict = guard.check(
        Action(kind="shell", changes={"requirements.txt": "reqeusts==2.31.0\n"})
    )
    assert verdict.blocked


def test_permissive_profile_allows_suspicious_but_not_critical() -> None:
    # Non-standard source is SUSPICIOUS, confidence 0.6 — below permissive's
    # block_threshold of 0.85, so should flag or allow.
    guard = Guard.permissive()
    verdict = guard.check(
        Action(
            kind="shell",
            network=["http://attacker.example.com/pip/install/whatever"],
        )
    )
    assert not verdict.blocked


def test_verdict_preserves_action_id() -> None:
    guard = Guard.default()
    verdict = guard.check(Action(id="step-42", kind="shell", command="echo ok"))
    assert verdict.action_id == "step-42"


def test_protect_decorator_raises_on_block() -> None:
    guard = Guard.default()

    @guard.protect
    def step(action: Action) -> str:
        return f"ran {action.command}"

    ok = step(Action(kind="shell", command="echo ok"))
    assert ok == "ran echo ok"

    with pytest.raises(BlockedAction) as exc_info:
        step(Action(kind="shell", changes={"requirements.txt": "reqeusts==2.31.0\n"}))
    assert exc_info.value.verdict.blocked


def test_custom_probes_and_thresholds() -> None:
    from cordon.probes.semantic import TyposquatProbe

    guard = Guard(
        probes=[TyposquatProbe()],
        block_threshold=0.99,   # effectively only block on critical
        flag_threshold=0.01,    # flag on anything
    )
    verdict = guard.check(
        Action(
            kind="shell",
            network=["http://attacker.example.com/pip/install/x"],
        )
    )
    # Non-standard source fires at confidence 0.6 → flag under these thresholds.
    assert verdict.flagged


def test_threshold_validation() -> None:
    with pytest.raises(ValueError):
        Guard(block_threshold=0.3, flag_threshold=0.5)
