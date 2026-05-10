"""Tests for SecretLeakProbe."""

from __future__ import annotations

from cordon import Action, Severity
from cordon.probes.semantic import SecretLeakProbe


def test_safe_when_no_sensitive_reads() -> None:
    probe = SecretLeakProbe()
    action = Action(
        kind="file",
        reads=["README.md"],
        changes={"artifacts/out.md": "hello world"},
    )
    result = probe.analyze(action)
    assert result.severity is Severity.SAFE


def test_critical_when_secret_content_verbatim_in_artifact() -> None:
    probe = SecretLeakProbe()
    secret = "FAKE-TEST-TOKEN-0123456789ABCDEF"
    action = Action(
        kind="file",
        reads=["/app/.env"],
        workspace_files={"/app/.env": f"EXAMPLE_KEY={secret}"},
        changes={"artifacts/debug.log": f"loaded env; key={secret}"},
    )
    result = probe.analyze(action)
    assert result.triggered
    assert result.severity is Severity.CRITICAL
    assert result.confidence >= 0.9


def test_dangerous_when_flow_without_content() -> None:
    # Sensitive read + artifact write, but we don't have the secret content to match.
    probe = SecretLeakProbe()
    action = Action(
        kind="file",
        reads=["/app/secrets/api_token"],
        changes={"artifacts/report.md": "Report generated; some content."},
    )
    result = probe.analyze(action)
    assert result.triggered
    assert result.severity is Severity.DANGEROUS


def test_safe_when_sensitive_read_stays_in_sensitive_write() -> None:
    probe = SecretLeakProbe()
    action = Action(
        kind="file",
        reads=["/app/.env"],
        changes={"/app/secrets/new_token": "value"},
    )
    result = probe.analyze(action)
    assert result.severity is Severity.SAFE


def test_safe_when_writes_to_non_artifact_non_sensitive() -> None:
    # Sensitive read + non-artifact, non-sensitive write. Flow alone doesn't
    # fire; only content match would. This avoids false positives on normal
    # refactors that happen to touch an .env file.
    probe = SecretLeakProbe()
    action = Action(
        kind="file",
        reads=["/app/.env"],
        changes={"src/config.py": "import os\n"},
    )
    result = probe.analyze(action)
    assert result.severity is Severity.SAFE
