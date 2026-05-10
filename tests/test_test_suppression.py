"""Tests for TestSuppressionProbe."""

from __future__ import annotations

from cordon import Action
from cordon.core.types import Severity
from cordon.probes.semantic import TestSuppressionProbe


probe = TestSuppressionProbe()


# ─── Test deletions ───────────────────────────────────────────────────────────


def test_test_file_deletion_dangerous() -> None:
    result = probe.analyze(Action(
        kind="file",
        deletions=["tests/test_auth.py"],
    ))
    assert result.severity is Severity.DANGEROUS


def test_non_test_deletion_safe() -> None:
    result = probe.analyze(Action(kind="file", deletions=["src/utils.py"]))
    assert result.severity is Severity.SAFE


# ─── Skip marker injection ────────────────────────────────────────────────────


def test_pytest_skip_marker_added() -> None:
    old = (
        "def test_login():\n"
        "    assert auth(user, pw)\n"
    )
    new = (
        "import pytest\n"
        "@pytest.mark.skip\n"
        "def test_login():\n"
        "    assert auth(user, pw)\n"
    )
    result = probe.analyze(Action(
        kind="file",
        changes={"tests/test_auth.py": new},
        workspace_files={"tests/test_auth.py": old},
    ))
    assert result.severity is Severity.SUSPICIOUS
    kinds = {f["kind"] for f in result.details["findings"]}
    assert "skip_marker_added" in kinds


def test_jest_xit_added_flagged() -> None:
    old = "it('logs in', () => { expect(auth()).toBe(true); });"
    new = "xit('logs in', () => { expect(auth()).toBe(true); });"
    result = probe.analyze(Action(
        kind="file",
        changes={"src/auth.test.ts": new},
        workspace_files={"src/auth.test.ts": old},
    ))
    assert result.severity is not Severity.SAFE


# ─── Assertion deletion ───────────────────────────────────────────────────────


def test_assertion_deletion_dangerous() -> None:
    old = (
        "def test_pipeline():\n"
        "    assert step_a() == 1\n"
        "    assert step_b() == 2\n"
        "    assert step_c() == 3\n"
    )
    new = (
        "def test_pipeline():\n"
        "    step_a(); step_b(); step_c()\n"
    )
    result = probe.analyze(Action(
        kind="file",
        changes={"tests/test_pipeline.py": new},
        workspace_files={"tests/test_pipeline.py": old},
    ))
    assert result.severity is Severity.DANGEROUS


# ─── Test config weakening ───────────────────────────────────────────────────


def test_skip_tests_true_in_config() -> None:
    old = "{}\n"
    new = '{"skipTests": true}\n'
    result = probe.analyze(Action(
        kind="file",
        changes={"jest.config.json": new},
        workspace_files={"jest.config.json": old},
    ))
    assert result.severity is not Severity.SAFE


def test_ci_test_step_commented() -> None:
    old = "steps:\n  - run: pytest\n"
    new = "steps:\n  # - run: pytest\n"
    result = probe.analyze(Action(
        kind="file",
        changes={".github/workflows/ci.yml": new},
        workspace_files={".github/workflows/ci.yml": old},
    ))
    assert result.severity is not Severity.SAFE


# ─── Negatives ────────────────────────────────────────────────────────────────


def test_adding_new_test_safe() -> None:
    result = probe.analyze(Action(
        kind="file",
        changes={"tests/test_new.py": "def test_x():\n    assert True\n"},
    ))
    assert result.severity is Severity.SAFE


def test_unrelated_change_safe() -> None:
    result = probe.analyze(Action(
        kind="file",
        changes={"src/utils.py": "def f(): return 1\n"},
    ))
    assert result.severity is Severity.SAFE
