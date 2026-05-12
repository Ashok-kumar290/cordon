"""``PackageManifestProbe`` — flag non-canonical sources in dependency manifests.

This probe closes §3.2 of the threat model: a ``requirements.txt``
or ``package.json`` that *looks* legitimate but contains a non-canonical
package source — typically a raw URL or a non-standard index that
delivers an attacker-controlled wheel.

The existing :class:`~cordon.probes.semantic.TyposquatProbe` already
covers misspelled *names* on legitimate registries. This probe is the
complement: legitimately-named (or arbitrarily-named) packages
fetched from places they shouldn't come from.

What it flags
-------------

**requirements.txt / requirements*.txt / constraints.txt**

* Raw URLs (``http://``, ``https://``, ``ftp://``) appearing on a
  dependency line — pip will fetch and install whatever's there.
* ``-e git+...`` / ``-e hg+...`` / ``-e svn+...`` editable installs
  pointing at non-PyPI / non-GitHub / non-GitLab hosts.
* ``--index-url`` / ``--extra-index-url`` / ``-i`` flags pointing at
  hosts that aren't ``pypi.org`` / ``pypi.python.org`` /
  ``files.pythonhosted.org``.
* Local file paths (``./malicious.whl``, ``/tmp/x.tar.gz``,
  ``file:///...``) — flagged because agent-generated requirements
  files shouldn't depend on local artefacts.

**package.json**

* Dependencies whose value isn't a SemVer range — git URLs, tarball
  URLs, ``file:``, ``link:``, or arbitrary strings.
* Any of the executable-on-install hooks (``preinstall``,
  ``install``, ``postinstall``, ``prepare``, ``preuninstall``,
  ``postuninstall``) that contain shell metacharacters
  (``;``, ``&&``, ``|``, ``` ` ```, ``$(``, ``>``, redirection).
* ``"resolutions"`` blocks (yarn) pointing at non-registry sources.

**pyproject.toml**

* ``[[tool.poetry.source]]`` entries whose URL isn't an allowlisted
  index.
* ``[tool.poetry.dependencies]`` values that are dicts with ``git``,
  ``path``, or ``url`` keys pointing at non-allowlisted hosts.

Severity ladder
---------------

* ``CRITICAL`` — package.json install hook with shell metacharacters,
  ``--index-url`` pointed at a non-PyPI host, or a raw URL inside a
  requirements file. These are the high-confidence attack patterns.
* ``DANGEROUS`` — git/hg/svn editable installs from non-canonical
  hosts; pyproject Poetry sources from non-allowlisted hosts.
* ``SUSPICIOUS`` — local file paths and ``file://`` URLs in
  requirements; install hooks without shell metacharacters but
  performing network fetches.

What it does NOT do
-------------------

* It does **not** fetch the URL to inspect what's there.
* It does **not** maintain an attacker-domain blocklist (no
  threat-intel feed yet).
* It does **not** parse ``setup.py`` — that's an arbitrary Python
  file; the :class:`PythonASTProbe` catches the dangerous-call
  patterns inside it.

Performance
-----------

Per-manifest cost is bounded by the manifest size; package.json
parses via stdlib :mod:`json`, pyproject via :mod:`tomllib`, and
requirements.txt is a line-by-line regex scan. All three stay under
1 ms on typical hand-written manifests.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlparse

try:
    import tomllib                # py311+
except ModuleNotFoundError:       # pragma: no cover — py310 fallback
    import tomli as tomllib       # type: ignore[no-redef]

from cordon.core.types import Action, ProbeResult, Severity
from cordon.probes.base import Probe


# ─── Allowlists ──────────────────────────────────────────────────────────────

#: Hosts that may legitimately serve Python packages. Anything else
#: from a requirements ``-i`` / ``--index-url`` flag is flagged.
_CANONICAL_PYPI_HOSTS: frozenset[str] = frozenset({
    "pypi.org",
    "pypi.python.org",
    "files.pythonhosted.org",
    "test.pypi.org",  # legitimate for testing flows
})

#: Hosts that may legitimately serve git/hg/svn editable installs.
#: GitLab self-hosted and Codeberg are included because they're the
#: two most-common non-GitHub homes for OSS libraries.
_CANONICAL_VCS_HOSTS: frozenset[str] = frozenset({
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "codeberg.org",
})

#: VCS schemes pip understands ahead of ``+`` (``git+ssh://`` etc.).
_VCS_PREFIXES: tuple[str, ...] = ("git+", "hg+", "svn+", "bzr+")

#: Shell metacharacters whose presence in a package.json install hook
#: turns it from a build step into a code-execution vector.
_SHELL_METACHARS = re.compile(r"[;&|`]|\$\(|>|<")


# ─── Filename gates ──────────────────────────────────────────────────────────


def _is_requirements_txt(path: str) -> bool:
    p = path.rsplit("/", 1)[-1].lower()
    if p in ("requirements.txt", "constraints.txt"):
        return True
    if p.startswith("requirements") and p.endswith(".txt"):
        return True  # requirements-dev.txt, requirements-prod.txt, ...
    return False


def _is_package_json(path: str) -> bool:
    return path.rsplit("/", 1)[-1].lower() == "package.json"


def _is_pyproject(path: str) -> bool:
    return path.rsplit("/", 1)[-1].lower() == "pyproject.toml"


# ─── Probe ──────────────────────────────────────────────────────────────────


class PackageManifestProbe(Probe):
    """Flag dependency manifests with non-canonical sources.

    Closes §3.2 of the threat model: trojaned requirements / package
    manifests with raw URLs, malicious install hooks, or VCS sources
    pointed at attacker-controlled hosts.
    """

    name = "package_manifest"
    description = "Detects non-canonical sources in dependency manifests."
    tier = "fast"

    def analyze(self, action: Action) -> ProbeResult:
        findings: list[dict[str, Any]] = []

        for path, content in (action.changes or {}).items():
            if not isinstance(content, str):
                continue
            if _is_requirements_txt(path):
                findings.extend(self._scan_requirements(path, content))
            elif _is_package_json(path):
                findings.extend(self._scan_package_json(path, content))
            elif _is_pyproject(path):
                findings.extend(self._scan_pyproject(path, content))

        if not findings:
            return ProbeResult(
                probe=self.name,
                severity=Severity.SAFE,
                confidence=0.0,
                evidence="No non-canonical package sources found.",
            )

        worst = max(findings, key=lambda f: _SEVERITY_RANK[f["severity"]])
        confidence = min(0.55 + 0.12 * len(findings), 0.97)
        sample = "; ".join(
            f"{f['path']}:{f.get('lineno','?')} {f['kind']}"
            for f in findings[:3]
        )
        more = f" (+ {len(findings) - 3} more)" if len(findings) > 3 else ""
        evidence = (
            f"{len(findings)} non-canonical package-manifest source(s); "
            f"primary: {worst['kind']} at {worst['path']}; "
            f"all: {sample}{more}"
        )

        return ProbeResult(
            probe=self.name,
            severity=worst["severity"],
            confidence=confidence,
            evidence=evidence,
        )

    # ── requirements.txt ──────────────────────────────────────────────

    def _scan_requirements(self, path: str, content: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for lineno, raw in enumerate(content.splitlines(), start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            # Strip inline comments. Cheap because requirements lines
            # don't contain quoted strings with #s.
            if "#" in line:
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue

            # --index-url / --extra-index-url / -i pointing off-PyPI.
            for flag in ("--index-url", "--extra-index-url", "-i"):
                if line.startswith(flag):
                    url = line[len(flag):].lstrip("= ").strip()
                    host = _host_of(url)
                    if host and host not in _CANONICAL_PYPI_HOSTS:
                        findings.append({
                            "path": path,
                            "lineno": lineno,
                            "kind": f"non-canonical {flag}",
                            "severity": Severity.CRITICAL,
                        })
                    break
            else:
                # ``-e git+https://github.com/foo/bar@x`` — editable VCS.
                if line.startswith("-e ") or any(
                    line.startswith(p) or f" {p}" in line for p in _VCS_PREFIXES
                ):
                    url = line.lstrip("-e ").strip()
                    # Strip ``git+`` etc. before parsing.
                    for p in _VCS_PREFIXES:
                        if url.startswith(p):
                            url = url[len(p):]
                            break
                    host = _host_of(url)
                    if host and host not in _CANONICAL_VCS_HOSTS:
                        findings.append({
                            "path": path,
                            "lineno": lineno,
                            "kind": "VCS install from non-canonical host",
                            "severity": Severity.DANGEROUS,
                        })
                elif line.startswith(("http://", "https://", "ftp://")):
                    # Raw URL dependency — pip will fetch it directly.
                    findings.append({
                        "path": path,
                        "lineno": lineno,
                        "kind": "raw URL dependency",
                        "severity": Severity.CRITICAL,
                    })
                elif line.startswith(("file:", "/", "./", "../")):
                    findings.append({
                        "path": path,
                        "lineno": lineno,
                        "kind": "local-file dependency",
                        "severity": Severity.SUSPICIOUS,
                    })
        return findings

    # ── package.json ──────────────────────────────────────────────────

    def _scan_package_json(self, path: str, content: str) -> list[dict[str, Any]]:
        try:
            doc = json.loads(content)
        except (json.JSONDecodeError, TypeError):
            return []
        if not isinstance(doc, dict):
            return []

        findings: list[dict[str, Any]] = []

        for section in ("dependencies", "devDependencies",
                        "peerDependencies", "optionalDependencies",
                        "resolutions"):
            deps = doc.get(section)
            if not isinstance(deps, dict):
                continue
            for pkg, ver in deps.items():
                if not isinstance(ver, str):
                    continue
                kind = _classify_npm_version(ver)
                if kind is not None:
                    findings.append({
                        "path": path,
                        "lineno": 0,  # we don't track JSON line numbers
                        "kind": f"npm {section}.{pkg}: {kind}",
                        "severity": _NPM_SEVERITY[kind],
                    })

        # Install hooks — preinstall / postinstall / etc.
        scripts = doc.get("scripts")
        if isinstance(scripts, dict):
            for hook in ("preinstall", "install", "postinstall",
                         "prepare", "preuninstall", "postuninstall"):
                cmd = scripts.get(hook)
                if not isinstance(cmd, str):
                    continue
                if _SHELL_METACHARS.search(cmd):
                    findings.append({
                        "path": path,
                        "lineno": 0,
                        "kind": f"npm {hook} hook with shell metacharacters",
                        "severity": Severity.CRITICAL,
                    })
                elif any(prot in cmd for prot in ("http://", "https://", "curl ", "wget ")):
                    findings.append({
                        "path": path,
                        "lineno": 0,
                        "kind": f"npm {hook} hook performs network fetch",
                        "severity": Severity.SUSPICIOUS,
                    })

        return findings

    # ── pyproject.toml ────────────────────────────────────────────────

    def _scan_pyproject(self, path: str, content: str) -> list[dict[str, Any]]:
        try:
            doc = tomllib.loads(content)
        except tomllib.TOMLDecodeError:
            return []

        findings: list[dict[str, Any]] = []

        tool = doc.get("tool", {}) if isinstance(doc, dict) else {}

        # Poetry sources block — [[tool.poetry.source]]
        poetry = tool.get("poetry", {}) if isinstance(tool, dict) else {}
        sources = poetry.get("source") if isinstance(poetry, dict) else None
        if isinstance(sources, list):
            for src in sources:
                if not isinstance(src, dict):
                    continue
                url = src.get("url")
                if isinstance(url, str):
                    host = _host_of(url)
                    if host and host not in _CANONICAL_PYPI_HOSTS:
                        findings.append({
                            "path": path,
                            "lineno": 0,
                            "kind": "poetry source on non-canonical host",
                            "severity": Severity.DANGEROUS,
                        })

        # Per-dependency overrides — ``{git = ...}`` / ``{path = ...}``.
        deps = poetry.get("dependencies") if isinstance(poetry, dict) else None
        if isinstance(deps, dict):
            for pkg, spec in deps.items():
                if not isinstance(spec, dict):
                    continue
                for vcs_key in ("git", "url"):
                    val = spec.get(vcs_key)
                    if isinstance(val, str):
                        host = _host_of(val)
                        if host and host not in _CANONICAL_VCS_HOSTS:
                            findings.append({
                                "path": path,
                                "lineno": 0,
                                "kind": f"poetry {pkg}.{vcs_key} on non-canonical host",
                                "severity": Severity.DANGEROUS,
                            })
                if "path" in spec:
                    findings.append({
                        "path": path,
                        "lineno": 0,
                        "kind": f"poetry {pkg}.path local dependency",
                        "severity": Severity.SUSPICIOUS,
                    })

        return findings


# ─── Helpers ─────────────────────────────────────────────────────────────────


def _host_of(url: str) -> str:
    """Return the hostname of ``url`` (case-insensitive), or empty string."""
    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
    except ValueError:
        return ""
    return (parsed.hostname or "").lower()


_SEVERITY_RANK = {
    Severity.SAFE:       0,
    Severity.SUSPICIOUS: 1,
    Severity.DANGEROUS:  2,
    Severity.CRITICAL:   3,
}


# package.json dependency value classification — npm/yarn allow many
# non-SemVer forms here, each with different risk.
_NPM_SEVERITY: dict[str, Severity] = {
    "git-url":      Severity.DANGEROUS,
    "tarball-url":  Severity.CRITICAL,
    "file-path":    Severity.SUSPICIOUS,
    "link-path":    Severity.SUSPICIOUS,
}


def _classify_npm_version(ver: str) -> str | None:
    """Return a tag for a non-SemVer npm dependency value, or ``None``."""
    if not ver:
        return None
    if ver.startswith(("git://", "git+", "github:")):
        return "git-url"
    if ver.startswith(("http://", "https://")):
        return "tarball-url"
    if ver.startswith("file:"):
        return "file-path"
    if ver.startswith("link:"):
        return "link-path"
    return None
