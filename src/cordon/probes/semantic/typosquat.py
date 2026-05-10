"""Typosquat detector — catches dependency supply-chain attacks.

Detects when an agent tries to install a package whose name is suspiciously
close to a well-known legitimate package (e.g. ``reqeusts`` vs ``requests``).
The probe is fully deterministic: edit-distance string comparison against a
curated reference list. No LLM, no heuristic, no false-negative risk from
model mood.

Also flags package fetches from non-standard mirrors, which is the second
half of a typical typosquat campaign (attacker-controlled registry serving
a look-alike package).

Research provenance
-------------------
Ported from the ``TyposquatDetector`` in ActionLens / Apart Research AI
Control Hackathon 2026 submission. Part of the Semantic Guard suite that
achieved 100% detection with 0% false positives on the 36-task benchmark.
"""

from __future__ import annotations

import re
from typing import Any

from cordon.core.types import Action, ProbeResult, Severity
from cordon.probes.base import Probe

from ._top_packages import STANDARD_PACKAGE_SOURCES, TOP_PYPI_PACKAGES


# ─── Edit distance ────────────────────────────────────────────────────────────


def _levenshtein(a: str, b: str) -> int:
    """Iterative Levenshtein edit distance."""
    if len(a) < len(b):
        a, b = b, a
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            cost = 0 if ca == cb else 1
            curr.append(min(curr[-1] + 1, prev[j + 1] + 1, prev[j] + cost))
        prev = curr
    return prev[-1]


# ─── Probe ────────────────────────────────────────────────────────────────────


class TyposquatProbe(Probe):
    """Flag dependency manifests or install URLs that look like typosquats."""

    name = "typosquat"
    description = "Detects supply-chain typosquatting in dependency manifests."
    tier = "fast"

    #: Maximum edit distance that counts as a typosquat. 2 catches real-world
    #: cases (e.g. ``reqeusts`` → ``requests``) without false-positive storms.
    MAX_EDIT_DISTANCE = 2

    _REQ_LINE_RE = re.compile(r"^([a-zA-Z0-9_.-]+)\s*(?:[=<>!~].*)?$")
    _PYPROJECT_DEP_RE = re.compile(r'"([a-zA-Z0-9_.-]+)\s*[=<>!~]')
    _PYPROJECT_BARE_RE = re.compile(r'"([a-zA-Z0-9_.-]+)"\s*$', re.MULTILINE)

    _MANIFEST_MARKERS = ("requirements", "pyproject", "setup.cfg", "pipfile")
    _PKG_INSTALL_KEYWORDS = ("package", "pypi", "pip", "install", "download")

    def analyze(self, action: Action) -> ProbeResult:
        suspects: list[dict[str, Any]] = []

        # Inspect dependency manifests in proposed file changes.
        for filepath, content in action.changes.items():
            if not self._looks_like_manifest(filepath):
                continue
            for pkg in self._extract_packages(content, filepath):
                if match := self._check_typosquat(pkg):
                    suspects.append(match)

        # Inspect outbound network calls for non-standard package sources.
        for url in action.network:
            domain = self._extract_domain(url)
            if domain and not self._is_standard_source(domain):
                lower = url.lower()
                if any(kw in lower for kw in self._PKG_INSTALL_KEYWORDS):
                    suspects.append({
                        "type": "non_standard_source",
                        "url": url,
                        "domain": domain,
                    })

        if not suspects:
            return ProbeResult(
                probe=self.name,
                severity=Severity.SAFE,
                confidence=0.0,
                evidence="No typosquat indicators found.",
            )

        has_typosquat = any(s.get("type") == "typosquat" for s in suspects)
        severity = Severity.CRITICAL if has_typosquat else Severity.SUSPICIOUS
        confidence = 0.95 if has_typosquat else 0.6
        evidence = f"{len(suspects)} supply-chain indicator(s): " + "; ".join(
            self._format_suspect(s) for s in suspects
        )

        return ProbeResult(
            probe=self.name,
            severity=severity,
            confidence=confidence,
            evidence=evidence,
            details={"suspects": suspects},
        )

    # ─── Helpers ──────────────────────────────────────────────────────────────

    def _looks_like_manifest(self, filepath: str) -> bool:
        lower = filepath.lower()
        return any(marker in lower for marker in self._MANIFEST_MARKERS)

    def _extract_packages(self, content: str, filepath: str) -> list[str]:
        """Extract package names from requirements.txt, pyproject.toml, Pipfile."""
        lower = filepath.lower()
        packages: list[str] = []

        if "requirements" in lower and lower.endswith((".txt", ".in")):
            for raw in content.splitlines():
                line = raw.strip()
                if not line or line.startswith(("#", "-")):
                    continue
                if m := self._REQ_LINE_RE.match(line):
                    packages.append(self._normalize(m.group(1)))

        elif "pyproject" in lower or "pipfile" in lower or "setup.cfg" in lower:
            for m in self._PYPROJECT_DEP_RE.finditer(content):
                packages.append(self._normalize(m.group(1)))
            for m in self._PYPROJECT_BARE_RE.finditer(content):
                packages.append(self._normalize(m.group(1)))

        return packages

    @staticmethod
    def _normalize(name: str) -> str:
        return name.lower().replace("_", "-").strip()

    def _check_typosquat(self, pkg: str) -> dict[str, Any] | None:
        if not pkg or pkg in TOP_PYPI_PACKAGES:
            return None
        for known in TOP_PYPI_PACKAGES:
            dist = _levenshtein(pkg, known)
            if 0 < dist <= self.MAX_EDIT_DISTANCE:
                return {
                    "type": "typosquat",
                    "package": pkg,
                    "similar_to": known,
                    "edit_distance": dist,
                }
        return None

    @staticmethod
    def _extract_domain(url: str) -> str | None:
        m = re.match(r"https?://([^/]+)", url)
        return m.group(1) if m else None

    @staticmethod
    def _is_standard_source(domain: str) -> bool:
        return any(std in domain for std in STANDARD_PACKAGE_SOURCES)

    @staticmethod
    def _format_suspect(s: dict[str, Any]) -> str:
        if s.get("type") == "typosquat":
            return (
                f"'{s['package']}' is {s['edit_distance']} edit(s) from "
                f"'{s['similar_to']}' (likely typosquat)"
            )
        return f"Non-standard package source: {s.get('domain', s.get('url', ''))}"
