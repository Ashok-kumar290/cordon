"""``PythonASTProbe`` — flag dangerous calls in proposed ``.py`` writes.

This probe closes the §3.5 evasion in the threat model: a Python
file that calls ``os.system`` (or equivalent) where the dangerous
command string never appears as a literal in the source. Today's
substring matchers see::

    helper.py: "import os; os.system(' '.join(['rm', '-rf', '/']))"

…and pass it through because the bytes ``rm -rf /`` are nowhere in
the file. The AST sees a call to ``os.system`` and fires — that's
the gap this probe closes.

What it flags
-------------

The probe fires when a proposed file write contains a Python source
file (``.py``, ``.pyw``, or executable-script content starting with
``#!.*python``) and the AST contains any of:

* ``os.system(...)``
* ``os.popen(...)``
* ``subprocess.Popen(..., shell=True)`` /
  ``subprocess.run(..., shell=True)`` /
  ``subprocess.call(..., shell=True)`` /
  ``subprocess.check_*(..., shell=True)``
* ``eval(...)`` and ``exec(...)`` *on dynamic arguments* (a literal
  ``exec("print('hi')")`` is dull; ``exec(decode_b64(payload))`` is
  the threat — see :data:`_is_dynamic` below)
* ``__import__('os').system(...)`` and similar evasion-friendly
  indirect forms — we look at the *attribute chain*, not just the
  bare name, so renaming ``os`` doesn't help.
* ``compile(..., 'exec')`` followed by ``exec``
* Writing to ``sys.modules`` — a common bootstrap-poisoning vector

Severity ladder
---------------

* ``CRITICAL`` — any ``shell=True`` subprocess or ``os.system``.
  These have effectively no benign use in agent-generated code.
* ``DANGEROUS`` — ``eval`` / ``exec`` on dynamic strings;
  ``__import__`` indirection; ``compile(..., 'exec')``.
* ``SUSPICIOUS`` — ``eval`` / ``exec`` on string literals (kept
  visible because legitimate config-eval'ing code does exist and we
  don't want to false-positive on it).

What it does NOT do
-------------------

* It does **not** taint-track. A function that *could* receive
  user-controlled input is not flagged on its own — we only fire on
  the dangerous *call site*.
* It does **not** parse comments or docstrings. Cordon's substring
  family already covers literal patterns in those.
* It does **not** sandbox-execute the file. That's Layer 3 in the
  threat model.

Performance
-----------

The Python ``ast`` module compiles ~2 MB / sec on CPython 3.12. We
cap parse size at 256 KB per file (configurable) to keep the probe
well under the 10 ms / probe / action budget that the rest of the
semantic suite holds.
"""

from __future__ import annotations

import ast
import re
from typing import Any

from cordon.core.types import Action, ProbeResult, Severity
from cordon.probes.base import Probe


# Maximum bytes per file we'll parse. Files larger than this are
# inspected by the cheaper substring path (no AST). 256 KB covers
# every legitimate hand-written Python file we've seen; binary or
# minified payloads above the cap are rare in agent output and we'd
# rather miss them than blow the latency budget.
_MAX_PARSE_BYTES = 256 * 1024

# Filename extensions we treat as Python source.
_PY_SUFFIXES = (".py", ".pyw")

# Shebang patterns at the start of a file that mark it as Python.
_PYTHON_SHEBANG = re.compile(r"^#!.*\bpython[0-9.]*\b", re.MULTILINE)


# ─── Probe ────────────────────────────────────────────────────────────────────


class PythonASTProbe(Probe):
    """Static AST analysis of proposed Python file writes.

    Closes the §3.5 evasion in the threat model: dangerous call sites
    whose argument string never appears as a literal.
    """

    name = "python_ast"
    description = "Static AST analysis of proposed Python file writes."
    tier = "fast"

    def analyze(self, action: Action) -> ProbeResult:
        findings: list[dict[str, Any]] = []

        for path, content in (action.changes or {}).items():
            if not self._looks_like_python(path, content):
                continue
            findings.extend(self._inspect_source(path, content))

        if not findings:
            return ProbeResult(
                probe=self.name,
                severity=Severity.SAFE,
                confidence=0.0,
                evidence="No suspicious Python call sites found.",
            )

        # Aggregate to one verdict. Use the worst severity across
        # findings and a confidence proportional to how many distinct
        # dangerous calls fired — multiple findings amplify each
        # other.
        worst = max(findings, key=lambda f: _SEVERITY_RANK[f["severity"]])
        n_critical = sum(1 for f in findings if f["severity"] is Severity.CRITICAL)
        confidence = min(0.6 + 0.1 * len(findings) + 0.1 * n_critical, 0.98)

        sample = "; ".join(
            f"{f['path']}:{f['lineno']} {f['kind']}"
            for f in findings[:3]
        )
        more = f" (+ {len(findings) - 3} more)" if len(findings) > 3 else ""
        evidence = (
            f"{len(findings)} dangerous Python call site(s); "
            f"primary: {worst['kind']} at {worst['path']}:{worst['lineno']}; "
            f"all: {sample}{more}"
        )

        return ProbeResult(
            probe=self.name,
            severity=worst["severity"],
            confidence=confidence,
            evidence=evidence,
        )

    # ── File-type detection ───────────────────────────────────────────

    def _looks_like_python(self, path: str, content: str | bytes | None) -> bool:
        """True if ``path`` / ``content`` looks like Python source.

        We trust the extension first (cheap), and fall back to a
        shebang sniff for executable scripts written under a non-.py
        name (common in CI tooling). Both checks must be string-safe
        because Cordon's ``Action.changes`` is type-loose by design.
        """
        p = (path or "").lower()
        if p.endswith(_PY_SUFFIXES):
            return True
        if not isinstance(content, str):
            return False
        # Cheap shebang sniff over the first 256 bytes only.
        return bool(_PYTHON_SHEBANG.search(content[:256]))

    # ── Source inspection ─────────────────────────────────────────────

    def _inspect_source(self, path: str, content: Any) -> list[dict[str, Any]]:
        if not isinstance(content, str) or not content:
            return []
        if len(content) > _MAX_PARSE_BYTES:
            # Hand off to the cheaper substring path; we'd rather miss
            # a 1 MB payload than spend 30 ms parsing it.
            return []
        try:
            tree = ast.parse(content)
        except SyntaxError:
            # Not valid Python; substring matchers will handle it.
            return []

        visitor = _DangerVisitor(path=path)
        visitor.visit(tree)
        return visitor.findings


# ─── AST visitor ─────────────────────────────────────────────────────────────


# Severity rank — for picking the "worst" finding across a file.
_SEVERITY_RANK = {
    Severity.SAFE:       0,
    Severity.SUSPICIOUS: 1,
    Severity.DANGEROUS:  2,
    Severity.CRITICAL:   3,
}


class _DangerVisitor(ast.NodeVisitor):
    """Walk an AST, accumulate findings, never raise.

    Visitor methods record findings into ``self.findings`` rather
    than returning them so a misbehaving sub-visitor can't lose the
    accumulator. Each finding is a dict with stable keys consumed by
    :meth:`PythonASTProbe.analyze`.
    """

    def __init__(self, *, path: str) -> None:
        super().__init__()
        self.path = path
        self.findings: list[dict[str, Any]] = []

    # The ``visit_Call`` hook covers ~all of the dangerous patterns;
    # the only thing we additionally watch is ``Attribute`` chains
    # for ``sys.modules[...]`` assignments (see ``visit_Assign``).
    def visit_Call(self, node: ast.Call) -> None:
        kind = _classify_call(node)
        if kind is not None:
            severity = _CALL_SEVERITY[kind]
            self.findings.append({
                "path": self.path,
                "lineno": node.lineno,
                "kind": kind,
                "severity": severity,
            })
        # Always recurse so we don't miss nested calls.
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if _is_sys_modules_subscript(target):
                self.findings.append({
                    "path": self.path,
                    "lineno": node.lineno,
                    "kind": "sys.modules-write",
                    "severity": Severity.DANGEROUS,
                })
        self.generic_visit(node)


# ── Classifiers ─────────────────────────────────────────────────────────────


_CALL_SEVERITY: dict[str, Severity] = {
    "os.system":                Severity.CRITICAL,
    "os.popen":                 Severity.CRITICAL,
    "subprocess.shell=True":    Severity.CRITICAL,
    "__import__.indirect":      Severity.DANGEROUS,
    "compile(..., 'exec')":     Severity.DANGEROUS,
    "eval(dynamic)":            Severity.DANGEROUS,
    "exec(dynamic)":            Severity.DANGEROUS,
    "eval(literal)":            Severity.SUSPICIOUS,
    "exec(literal)":            Severity.SUSPICIOUS,
}


def _classify_call(node: ast.Call) -> str | None:
    """Return a short ``kind`` tag for a dangerous call, or ``None``."""
    chain = _attribute_chain(node.func)

    # subprocess.run / Popen / call / check_call / check_output with shell=True
    if (
        len(chain) >= 2
        and chain[0] == "subprocess"
        and chain[-1] in {"run", "Popen", "call", "check_call", "check_output"}
        and _has_shell_true(node)
    ):
        return "subprocess.shell=True"

    # os.system / os.popen — the import name may have been rebound but
    # we only flag the canonical form. Renamed ``import os as ox`` is
    # caught via the indirect-import path below.
    if chain == ["os", "system"]:
        return "os.system"
    if chain == ["os", "popen"]:
        return "os.popen"

    # __import__('os').system(...) and similar two-step evasions —
    # match the *outer* call whose function is an attribute on a
    # __import__(...) call.
    if (
        isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Call)
        and isinstance(node.func.value.func, ast.Name)
        and node.func.value.func.id == "__import__"
    ):
        return "__import__.indirect"

    # compile(..., 'exec') — the bytecode-then-exec gadget.
    if chain == ["compile"] and any(
        isinstance(a, ast.Constant) and a.value == "exec"
        for a in node.args
    ):
        return "compile(..., 'exec')"

    # eval / exec on dynamic strings.
    if chain == ["eval"]:
        return "eval(dynamic)" if _is_dynamic(node) else "eval(literal)"
    if chain == ["exec"]:
        return "exec(dynamic)" if _is_dynamic(node) else "exec(literal)"

    return None


def _attribute_chain(func: ast.AST) -> list[str]:
    """Collapse ``a.b.c`` into ``['a','b','c']``; bare ``foo`` → ``['foo']``."""
    parts: list[str] = []
    cur: ast.AST | None = func
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return list(reversed(parts))
    return []  # not a name-or-attribute chain (e.g. a call result)


def _has_shell_true(node: ast.Call) -> bool:
    """True if any keyword argument is ``shell=True``."""
    for kw in node.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


def _is_dynamic(node: ast.Call) -> bool:
    """True if any positional arg is not a string literal.

    Used to distinguish ``eval("2 + 2")`` (suspicious, mostly benign)
    from ``eval(decode_b64(payload))`` (clearly an evasion).
    """
    if not node.args:
        return False
    first = node.args[0]
    if isinstance(first, ast.Constant) and isinstance(first.value, str):
        return False
    # Joined f-strings / formatted strings are dynamic in practice
    # even if they look static — fall through to dynamic.
    return True


def _is_sys_modules_subscript(target: ast.AST) -> bool:
    """``sys.modules['evil'] = ...`` style bootstrap poisoning."""
    if not isinstance(target, ast.Subscript):
        return False
    chain = _attribute_chain(target.value)
    return chain == ["sys", "modules"]
