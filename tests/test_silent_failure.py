"""Tests for SilentFailureProbe."""

from __future__ import annotations

from cordon import Action
from cordon.core.types import Severity
from cordon.probes.semantic import SilentFailureProbe


probe = SilentFailureProbe()


# ─── Python: bare except / except: pass ───────────────────────────────────────


def test_bare_except_pass_flagged() -> None:
    code = (
        "def fetch():\n"
        "    try:\n"
        "        do_thing()\n"
        "    except:\n"
        "        pass\n"
    )
    result = probe.analyze(Action(kind="file", changes={"app.py": code}))
    assert result.severity is Severity.DANGEROUS
    assert any(f["kind"] == "bare_except_pass" for f in result.details["findings"])


def test_except_exception_pass_flagged() -> None:
    code = (
        "try:\n"
        "    work()\n"
        "except Exception:\n"
        "    pass\n"
    )
    result = probe.analyze(Action(kind="file", changes={"x.py": code}))
    assert result.severity is Severity.DANGEROUS


def test_except_as_pass_flagged() -> None:
    code = (
        "try:\n"
        "    work()\n"
        "except ValueError as err:\n"
        "    pass\n"
    )
    result = probe.analyze(Action(kind="file", changes={"x.py": code}))
    assert result.severity is Severity.DANGEROUS


def test_legitimate_handler_not_flagged() -> None:
    code = (
        "try:\n"
        "    work()\n"
        "except ValueError as err:\n"
        "    log.warning(\"work failed: %s\", err)\n"
        "    raise\n"
    )
    result = probe.analyze(Action(kind="file", changes={"x.py": code}))
    assert result.severity is Severity.SAFE


def test_narrow_import_error_not_flagged_when_logged() -> None:
    code = (
        "try:\n"
        "    import optional_dep\n"
        "except ImportError as e:\n"
        "    logger.info('optional dep missing: %s', e)\n"
        "    optional_dep = None\n"
    )
    result = probe.analyze(Action(kind="file", changes={"x.py": code}))
    assert result.severity is Severity.SAFE


# ─── JS / TS ──────────────────────────────────────────────────────────────────


def test_empty_catch_block_flagged() -> None:
    code = "try { riskyOp(); } catch (e) {}"
    result = probe.analyze(Action(kind="file", changes={"app.ts": code}))
    assert result.severity is Severity.DANGEROUS


def test_empty_promise_catch_flagged() -> None:
    code = "fetch('/x').then(handle).catch(() => {});"
    result = probe.analyze(Action(kind="file", changes={"app.js": code}))
    assert result.severity is Severity.DANGEROUS


# ─── Shell mufflers ───────────────────────────────────────────────────────────


def test_shell_redirect_stderr_null() -> None:
    result = probe.analyze(Action(kind="shell", command="run-tests 2>/dev/null"))
    assert result.severity is Severity.SUSPICIOUS


def test_shell_or_true() -> None:
    result = probe.analyze(Action(kind="shell", command="pytest || true"))
    assert result.severity is Severity.SUSPICIOUS


def test_shell_skip_tests_flag() -> None:
    result = probe.analyze(Action(kind="shell", command="mvn install -DskipTests"))
    assert result.severity is Severity.SUSPICIOUS


def test_safe_shell_unflagged() -> None:
    result = probe.analyze(Action(kind="shell", command="ls -la"))
    assert result.severity is Severity.SAFE
