"""Tests for :class:`cordon.probes.content.PythonASTProbe`.

The probe's job is closing §3.5 of the threat model — Python files
whose dangerous calls compose their arguments at runtime so no
substring matcher can see them. These tests pin both the *positive*
catches (each dangerous pattern must fire at the right severity)
and the *negative* baseline (benign code must stay SAFE).
"""
from __future__ import annotations

import pytest

from cordon.core.types import Action, Severity
from cordon.probes.content import PythonASTProbe


@pytest.fixture()
def probe() -> PythonASTProbe:
    return PythonASTProbe()


def _check(probe: PythonASTProbe, src: str, *, path: str = "x.py"):
    return probe.analyze(Action(kind="file", changes={path: src}))


# ─── The threat-model §3.5 evasion ──────────────────────────────────────────


def test_os_system_with_dynamic_argument_fires(probe):
    """The exact §3.5 evasion: the literal pattern never appears."""
    src = "import os\nos.system(' '.join(['rm', '-rf', '/']))"
    res = _check(probe, src)
    assert res.severity is Severity.CRITICAL
    assert "os.system" in res.evidence


def test_os_popen_fires_critical(probe):
    res = _check(probe, "import os\nos.popen('whoami')")
    assert res.severity is Severity.CRITICAL


# ─── subprocess.run / Popen / call / check_* with shell=True ────────────────


@pytest.mark.parametrize("fn", ["run", "Popen", "call", "check_call", "check_output"])
def test_subprocess_shell_true_fires_critical(probe, fn):
    src = f"import subprocess\nsubprocess.{fn}(cmd, shell=True)"
    res = _check(probe, src)
    assert res.severity is Severity.CRITICAL
    assert "subprocess.shell=True" in res.evidence


def test_subprocess_shell_false_does_not_fire(probe):
    """shell=False is the safe form. Must NOT fire."""
    res = _check(probe, "import subprocess\nsubprocess.run(['ls'], shell=False)")
    assert res.severity is Severity.SAFE


def test_subprocess_without_shell_kw_does_not_fire(probe):
    """Default shell=False — same case."""
    res = _check(probe, "import subprocess\nsubprocess.run(['ls'])")
    assert res.severity is Severity.SAFE


# ─── __import__ indirection ─────────────────────────────────────────────────


def test_indirect_import_chain_fires(probe):
    res = _check(probe, "__import__('os').system('rm -rf /')")
    assert res.severity is Severity.DANGEROUS
    assert "__import__.indirect" in res.evidence


# ─── eval / exec ─────────────────────────────────────────────────────────────


def test_eval_on_literal_is_suspicious_not_dangerous(probe):
    """A literal eval is real (config systems do this) — keep visible but light."""
    res = _check(probe, "x = eval('2 + 2')")
    assert res.severity is Severity.SUSPICIOUS


def test_eval_on_dynamic_is_dangerous(probe):
    res = _check(probe, "import base64\neval(base64.b64decode(payload))")
    assert res.severity is Severity.DANGEROUS
    assert "eval(dynamic)" in res.evidence


def test_exec_on_literal_is_suspicious(probe):
    res = _check(probe, "exec('print(1)')")
    assert res.severity is Severity.SUSPICIOUS


def test_exec_on_dynamic_is_dangerous(probe):
    res = _check(probe, "exec(payload)")
    assert res.severity is Severity.DANGEROUS


def test_compile_then_exec_fires(probe):
    res = _check(probe, "exec(compile(src, '<x>', 'exec'))")
    # Two findings: compile and exec(dynamic). The aggregator picks the worst.
    assert res.severity is Severity.DANGEROUS


# ─── sys.modules bootstrap poisoning ─────────────────────────────────────────


def test_sys_modules_assignment_fires(probe):
    res = _check(probe, "import sys\nsys.modules['os'] = FakeOs()")
    assert res.severity is Severity.DANGEROUS
    assert "sys.modules-write" in res.evidence


# ─── Benign baselines (the false-positive defenders) ────────────────────────


@pytest.mark.parametrize("src", [
    "def add(a, b):\n    return a + b\nprint(add(2,3))",
    "import json\nprint(json.dumps({'ok': True}))",
    "class Foo:\n    def bar(self):\n        return self.x + 1",
    "import os\nprint(os.environ.get('HOME'))",     # os usage that isn't os.system
    "import subprocess\np = subprocess.run(['ls'])",  # safe subprocess
    "# eval and exec mentioned in a comment, not called",
    "doc = 'this docstring talks about os.system but never calls it'",
])
def test_benign_python_does_not_fire(probe, src):
    res = _check(probe, src)
    assert res.severity is Severity.SAFE, f"false positive on: {src!r}"


# ─── File-type detection ────────────────────────────────────────────────────


def test_non_python_extension_is_skipped(probe):
    """A .txt file with dangerous-looking content must NOT be parsed."""
    res = _check(probe, "import os\nos.system('rm -rf /')", path="notes.txt")
    assert res.severity is Severity.SAFE


def test_shebang_python_script_without_py_extension_is_parsed(probe):
    """Executable scripts named ``deploy`` are still Python."""
    src = "#!/usr/bin/env python3\nimport os\nos.system('rm -rf /')"
    res = _check(probe, src, path="deploy")
    assert res.severity is Severity.CRITICAL


def test_pyw_extension_is_parsed(probe):
    res = _check(probe, "import os\nos.system('x')", path="gui.pyw")
    assert res.severity is Severity.CRITICAL


# ─── Robustness ──────────────────────────────────────────────────────────────


def test_syntax_error_is_skipped_silently(probe):
    """Broken Python must NOT crash the probe."""
    res = _check(probe, "def broken( syntax error here")
    assert res.severity is Severity.SAFE


def test_oversized_file_skipped(probe):
    """Files > 256KB skip the parse path to stay under the latency budget."""
    src = "import os\nos.system('rm -rf /')\n" + ("# pad\n" * 60_000)
    assert len(src) > 256 * 1024
    res = _check(probe, src)
    assert res.severity is Severity.SAFE


def test_empty_content_is_safe(probe):
    res = _check(probe, "", path="x.py")
    assert res.severity is Severity.SAFE


# ─── Aggregation behaviour ──────────────────────────────────────────────────


def test_multiple_findings_amplify_confidence(probe):
    src = (
        "import os\n"
        "os.system('a')\n"
        "os.system('b')\n"
        "os.system('c')\n"
        "exec(payload)\n"
    )
    res = _check(probe, src)
    assert res.severity is Severity.CRITICAL
    # More findings → higher confidence (capped at ~0.98).
    assert res.confidence >= 0.9
    # Evidence summary mentions count + primary + samples
    assert "4 dangerous Python call site(s)" in res.evidence


def test_worst_severity_wins(probe):
    """If a file has eval(literal) + os.system, the aggregate is CRITICAL."""
    src = "x = eval('1+1')\nimport os\nos.system('rm -rf /')"
    res = _check(probe, src)
    assert res.severity is Severity.CRITICAL


# ─── End-to-end via Guard ────────────────────────────────────────────────────


def test_probe_is_wired_into_strict_guard():
    """The §3.5 evasion must be BLOCKED end-to-end by Guard.strict()."""
    from cordon import Guard
    guard = Guard.strict()
    verdict = guard.check(Action(kind="file", changes={
        "helper.py": "import os\nos.system(' '.join(['rm', '-rf', '/']))",
    }))
    assert verdict.decision == "block"
    assert any(p.probe == "python_ast" for p in verdict.probes_triggered)
