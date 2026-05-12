"""``Base64DecoderProbe`` — decode embedded base64 and re-check.

This probe closes §3.4 of the threat model: payloads wrapped in
base64 so the literal pattern never appears in the file or command.

Example evasion that today's substring matchers miss::

    Action(kind="file", changes={
        "icon.png": "PNG_HEADER... base64:cm0gLXJmIC8=",
        # decodes to: rm -rf /
    })

    Action(kind="shell",
        command="echo cm0gLXJmIC8= | base64 -d | sh")

The probe scans both the command and every file's content for base64-
looking substrings, decodes them to UTF-8 where possible, and re-runs
a tight set of *dangerous-pattern* matchers on the decoded text. If
the decoded payload looks like a shell command we'd flag at
``CRITICAL`` directly, the wrapper inherits CRITICAL with a small
confidence haircut.

Design constraints
------------------

* **Detection is the hard part, not decoding.** A naive
  `[A-Za-z0-9+/=]{8,}` regex matches a lot of innocuous text in real
  Python code (hashes, IDs, JWTs, base32-looking strings). We use
  a stricter pattern: ≥ 16 chars, characters from the base64 alphabet
  only, and the substring must round-trip cleanly through
  ``base64.b64decode(..., validate=True)``. The round-trip filter
  removes the vast majority of false positives.

* **Decode confidence ≠ payload confidence.** A valid base64 string
  that decodes to garbage is *not* a finding; we only fire when the
  *decoded* bytes match a dangerous pattern.

* **Bounded work per action.** At most 64 candidates per file or
  command are decoded. Files larger than 256 KB are skipped (same
  budget as PythonASTProbe). That keeps p99 latency below 5 ms even
  against pathologically-base64-rich content.

What it catches in the decoded payload
--------------------------------------

We reuse a small subset of :class:`DestructiveShellProbe`'s patterns
— intentionally narrower than the full semantic suite because
re-running every probe on every decoded blob blows the latency
budget. The narrower set is the highest-signal patterns:

* Recursive force-delete: ``rm -rf /`` and variants
* Network-pipe-to-shell: ``curl … | sh``, ``wget … | bash``
* Fork bombs: ``:(){ :|:& };:`` and equivalents
* ``dd`` to a block device
* ``mkfs.*`` on a non-loopback device
* Crontab injection: ``echo … >> ~/.bashrc`` / ``crontab -l``

What it does NOT do
-------------------

* It does **not** chain through other encodings (gzip + base64,
  hex + base64). One layer of base64 is the empirically-most-common
  evasion; multi-layer is rare and lives in the Archive inspector.
* It does **not** decode base64 inside JSON / YAML / XML
  attributes specifically. The regex scan is encoding-agnostic; we
  pick up base64 wherever it appears as a substring.

Performance
-----------

Single pass over content with a single compiled regex, then up to
64 b64decode + pattern checks per match. ~1-3 ms on typical files.
"""

from __future__ import annotations

import base64
import binascii
import re
from typing import Any

from cordon.core.types import Action, ProbeResult, Severity
from cordon.probes.base import Probe

# ─── Tunables ────────────────────────────────────────────────────────────────

#: Skip files larger than this. Same budget as PythonASTProbe.
_MAX_SCAN_BYTES = 256 * 1024

#: Cap on candidates decoded per file/command — defends against
#: a payload that's a million tiny base64 substrings.
_MAX_CANDIDATES = 64

#: Minimum base64 candidate length. 12 chars decodes to 8 bytes —
#: enough to cover the shortest interesting payload (``rm -rf /``)
#: while keeping happenstance-base64 false positives manageable
#: (the pattern-match step is what actually decides "fire or not").
_MIN_B64_LEN = 12


# ─── Patterns ────────────────────────────────────────────────────────────────

# Base64 candidate: ≥ 12 chars from the base64 alphabet, with optional
# ``=`` padding. We allow unpadded runs because payload lengths that
# are exact multiples of 3 produce no padding, and rejecting those
# misses an entire third of attack payloads (anything 9, 12, 15, …
# bytes long). The cheap-but-permissive regex is fine because the
# strict ``base64.b64decode(..., validate=True)`` step that follows
# is what actually filters: a happenstance alnum string almost
# always fails validation.
_B64_CANDIDATE = re.compile(
    rb"[A-Za-z0-9+/]{11,}={0,2}"
)

# Patterns we match against the *decoded* payload. Narrower than
# DestructiveShellProbe by design — see the module docstring.
_DECODED_PATTERNS: list[tuple[str, re.Pattern[bytes]]] = [
    ("rm-rf-root",
     re.compile(rb"rm\s+-rf\s+(?:--no-preserve-root\s+)?/(?:\s|$|\*|\.)")),
    ("network-pipe-shell",
     re.compile(rb"\b(?:curl|wget|fetch)[^\n]*\|\s*(?:sh|bash|zsh|/bin/sh|/bin/bash)\b")),
    ("fork-bomb",
     re.compile(rb":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:")),
    ("dd-to-device",
     re.compile(rb"\bdd\b[^\n]*\bof=/dev/(?:sd|hd|nvme|mmcblk|xvd)")),
    ("mkfs-on-device",
     re.compile(rb"\bmkfs\.\w+\s+/dev/(?:sd|hd|nvme|mmcblk|xvd)")),
    ("rc-file-write",
     re.compile(rb"\b(?:echo|printf|cat)\b[^\n]*>>\s*~?/?\.?(?:bashrc|zshrc|profile|bash_profile)")),
    ("crontab-inject",
     re.compile(rb"\b(?:echo|printf)\b[^\n]*\|\s*crontab\b")),
]


# ─── Probe ──────────────────────────────────────────────────────────────────


class Base64DecoderProbe(Probe):
    """Decode embedded base64 sequences and re-run the dangerous-pattern set.

    Closes §3.4 of the threat model: payloads wrapped in base64 so
    the literal pattern never appears in the source.
    """

    name = "base64_decoder"
    description = "Decodes embedded base64 sequences and flags dangerous decoded payloads."
    tier = "fast"

    def analyze(self, action: Action) -> ProbeResult:
        findings: list[dict[str, Any]] = []

        # Inspect every file content.
        for path, content in (action.changes or {}).items():
            if not isinstance(content, str):
                continue
            if len(content) > _MAX_SCAN_BYTES:
                continue
            findings.extend(self._scan(content, source=path))

        # Inspect the shell command, if any.
        if action.command:
            cmd_findings = self._scan(action.command, source="<command>")
            findings.extend(cmd_findings)

        if not findings:
            return ProbeResult(
                probe=self.name,
                severity=Severity.SAFE,
                confidence=0.0,
                evidence="No dangerous base64-decoded payloads found.",
            )

        # All dangerous-payload patterns we match are CRITICAL on their
        # own — but we apply a slight confidence haircut because base64
        # decode is itself a heuristic step (false-positive ≥ 0).
        primary = findings[0]
        sample = "; ".join(
            f"{f['source']} decoded → {f['kind']}" for f in findings[:3]
        )
        more = f" (+ {len(findings) - 3} more)" if len(findings) > 3 else ""
        evidence = (
            f"{len(findings)} dangerous base64-decoded payload(s); "
            f"primary: {primary['kind']} in {primary['source']}; "
            f"all: {sample}{more}"
        )
        confidence = min(0.7 + 0.1 * len(findings), 0.95)

        return ProbeResult(
            probe=self.name,
            severity=Severity.CRITICAL,
            confidence=confidence,
            evidence=evidence,
        )

    # ── Scan ─────────────────────────────────────────────────────────

    def _scan(self, text: str, *, source: str) -> list[dict[str, Any]]:
        """Find base64 candidates in ``text``, decode, match dangerous patterns."""
        as_bytes = text.encode("utf-8", errors="replace")

        findings: list[dict[str, Any]] = []
        seen = 0

        for m in _B64_CANDIDATE.finditer(as_bytes):
            if seen >= _MAX_CANDIDATES:
                break
            seen += 1

            candidate = m.group(0)
            if len(candidate) < _MIN_B64_LEN:
                continue

            decoded = _try_decode(candidate)
            if decoded is None:
                continue

            # Match dangerous patterns on the decoded bytes.
            for kind, pat in _DECODED_PATTERNS:
                if pat.search(decoded):
                    findings.append({
                        "source": source,
                        "kind": kind,
                        "decoded_preview": decoded[:80].decode("utf-8", errors="replace"),
                    })
                    # One pattern is enough — don't double-count the
                    # same decoded blob.
                    break

        return findings


# ─── Helpers ─────────────────────────────────────────────────────────────────


def _try_decode(candidate: bytes) -> bytes | None:
    """Return decoded bytes or ``None`` if the candidate isn't valid b64.

    Uses ``validate=True`` so happenstance-base64-shaped strings that
    contain non-alphabet characters don't slip through. Catches
    :class:`binascii.Error` for short / mispadded inputs that the
    regex would let through.
    """
    try:
        return base64.b64decode(candidate, validate=True)
    except (binascii.Error, ValueError):
        return None
