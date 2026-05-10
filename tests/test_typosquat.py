"""Tests for TyposquatProbe."""

from __future__ import annotations

from cordon import Action, Severity
from cordon.probes.semantic import TyposquatProbe


def test_safe_when_all_legitimate_packages() -> None:
    probe = TyposquatProbe()
    action = Action(
        kind="shell",
        changes={"requirements.txt": "requests==2.31.0\nnumpy==1.26.0\nflask==3.0.0\n"},
    )
    result = probe.analyze(action)
    assert result.severity is Severity.SAFE
    assert not result.triggered


def test_flags_classic_typosquat_reqeusts() -> None:
    probe = TyposquatProbe()
    action = Action(
        kind="shell",
        changes={"requirements.txt": "reqeusts==2.31.0\n"},
    )
    result = probe.analyze(action)
    assert result.triggered
    assert result.severity is Severity.CRITICAL
    assert result.confidence >= 0.9
    suspects = result.details["suspects"]
    assert any(s["type"] == "typosquat" and s["similar_to"] == "requests" for s in suspects)


def test_flags_edit_distance_two() -> None:
    probe = TyposquatProbe()
    action = Action(
        kind="shell",
        changes={"requirements.txt": "numpyy==1.26.0\n"},
    )
    result = probe.analyze(action)
    assert result.triggered
    assert result.severity is Severity.CRITICAL


def test_ignores_legitimate_extensions() -> None:
    # `rich-click` is not in our reference list but looks nothing like a typosquat.
    # Distance from `rich` is 7, from `click` is 5 — well above threshold.
    probe = TyposquatProbe()
    action = Action(
        kind="shell",
        changes={"requirements.txt": "rich-click==1.7.0\n"},
    )
    result = probe.analyze(action)
    assert not result.triggered


def test_non_standard_package_source() -> None:
    probe = TyposquatProbe()
    action = Action(
        kind="shell",
        network=["http://attacker.example.com/pip/install/requests"],
    )
    result = probe.analyze(action)
    assert result.triggered
    assert result.severity is Severity.SUSPICIOUS


def test_pyproject_toml_dependency_parsing() -> None:
    probe = TyposquatProbe()
    pyproject = """
[project]
dependencies = [
    "reqeusts>=2.0",
    "numpy==1.26.0",
]
"""
    action = Action(kind="file", changes={"pyproject.toml": pyproject})
    result = probe.analyze(action)
    assert result.triggered
    assert any(
        s["package"] == "reqeusts"
        for s in result.details["suspects"]
        if s["type"] == "typosquat"
    )
