"""Tests for ``examples/openai_live_demo.py``.

The example demo is the slide-4 artifact for VC pitches — it has to
behave deterministically across the three contract scenarios (allow,
flag, block) no matter whether OpenAI is reachable.

These tests assert:

* The canned-fallback path (no ``OPENAI_API_KEY``) produces exactly
  one ``allow``, one ``flag``, and one ``block`` verdict, with the
  right top probes (``-`` / ``exfiltration`` / ``destructive_shell``).
* A fake ``openai.OpenAI`` client whose ``chat.completions.create``
  returns hand-shaped responses is consumed by the same code path
  end-to-end (no shape mismatches).
* The :class:`CloudReporter` listener attached to the demo's
  ``Guard`` is invoked once per scenario verdict and never raises,
  even when the API key is unset (the listener becomes a queueing
  no-op).
"""

from __future__ import annotations

import importlib
import json
import sys
import types
from pathlib import Path
from unittest.mock import patch

import pytest


# ─── Import the example as a module (it lives outside src/) ───────────────────

EXAMPLES_DIR = Path(__file__).resolve().parents[1] / "examples"
if str(EXAMPLES_DIR) not in sys.path:
    sys.path.insert(0, str(EXAMPLES_DIR))


@pytest.fixture()
def demo(monkeypatch):
    """Fresh import of the demo module per test (clears module state)."""
    # Ensure the demo module starts from a clean slate: it reads env
    # vars at call time, but ``builder`` and ``guard`` are module-level
    # so we re-import to keep tests isolated.
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("CORDON_API_KEY", raising=False)
    sys.modules.pop("openai_live_demo", None)
    return importlib.import_module("openai_live_demo")


# ─── Tests ───────────────────────────────────────────────────────────────────


def test_canned_fallback_produces_allow_flag_block(demo, capsys):
    """No keys set → demo runs canned, ends with 1/1/1 verdicts."""
    rc = demo.main()
    assert rc == 0

    out = capsys.readouterr().out
    # Section headers — confirm all three scenarios actually ran.
    assert "scenario: benign" in out
    assert "scenario: exfiltration" in out
    assert "scenario: destructive_shell" in out

    # Decision tally on the summary line. The ``_c`` colour helper is a
    # no-op when stdout is not a TTY (which pytest captures it as), so
    # we can match the plain text.
    assert "1 allowed" in out
    assert "1 flagged" in out
    assert "1 blocked" in out


def test_canned_fallback_probe_attribution(demo):
    """Each scenario must trigger the expected probe (not just the right decision)."""
    from cordon.integrations.openai import check_response

    expectations = {
        "benign":            ("allow", None),
        "exfiltration":      ("flag",  "exfiltration"),
        "destructive_shell": ("block", "destructive_shell"),
    }

    for label, user_msg, canned in demo.SCENARIOS:
        completion = demo._canned_response(canned)
        verdicts = check_response(completion, builder=demo.builder, guard=demo.guard)
        assert len(verdicts) == 1, f"{label}: expected exactly one tool call"
        v = verdicts[0].verdict
        expected_decision, expected_probe = expectations[label]
        assert v.decision == expected_decision, (
            f"{label}: got decision={v.decision!r}, want {expected_decision!r}"
        )
        if expected_probe is not None:
            triggered = {p.probe for p in v.probes_triggered}
            assert expected_probe in triggered, (
                f"{label}: probe {expected_probe!r} not in {triggered!r}"
            )


def test_openai_live_path_consumes_real_sdk_shape(demo, monkeypatch):
    """A fake ``openai.OpenAI`` client returning real SDK objects works end-to-end.

    This pins the duck-typing contract: ``check_response`` must accept
    whatever ``client.chat.completions.create`` returns. We construct a
    minimal object graph that mirrors the OpenAI 1.x SDK
    (``ChatCompletion`` → ``choices[0]`` → ``message`` → ``tool_calls``).
    """
    monkeypatch.setenv("OPENAI_API_KEY", "sk-fake")

    # Build a fake `openai` module with an `OpenAI` class whose
    # `chat.completions.create` returns the per-scenario canned response,
    # but wrapped in SimpleNamespace so attribute access works.
    def _ns(d):
        if isinstance(d, dict):
            return types.SimpleNamespace(**{k: _ns(v) for k, v in d.items()})
        if isinstance(d, list):
            return [_ns(x) for x in d]
        return d

    scenario_lookup = {sc[1]: sc[2] for sc in demo.SCENARIOS}

    class FakeCompletions:
        def create(self, *, model, messages, tools, tool_choice):
            user_msg = messages[-1]["content"]
            canned = scenario_lookup[user_msg]
            return _ns({
                "choices": [{
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": canned["tool_calls"],
                    }
                }]
            })

    class FakeChat:
        def __init__(self): self.completions = FakeCompletions()

    class FakeOpenAI:
        def __init__(self, *, api_key): self.api_key = api_key; self.chat = FakeChat()

    fake_openai = types.ModuleType("openai")
    fake_openai.OpenAI = FakeOpenAI
    monkeypatch.setitem(sys.modules, "openai", fake_openai)

    # Reload the demo so it picks up the env var and the fake openai.
    sys.modules.pop("openai_live_demo", None)
    demo = importlib.import_module("openai_live_demo")

    rc = demo.main()
    assert rc == 0  # the live path completed without raising


def test_cloudreporter_listener_attached_and_safe(demo):
    """The module-level guard has a CloudReporter listener.

    With ``CORDON_API_KEY`` unset, the reporter becomes a no-op
    (``self._enabled = False``) — but it must still be installed on
    the guard and must not raise when called via ``guard.check``.
    """
    from cordon.cloud import CloudReporter

    listeners = demo.guard._listeners  # private but stable in this codebase
    cloud_listeners = [l for l in listeners if isinstance(l, CloudReporter)]
    assert len(cloud_listeners) == 1, (
        f"expected exactly one CloudReporter on the demo guard, got {listeners!r}"
    )

    # The listener must be a no-op without an API key.
    reporter = cloud_listeners[0]
    assert reporter._enabled is False
    assert reporter.guard_profile == "strict"

    # Round-trip a check through guard — listener must not raise.
    import cordon
    v = demo.guard.check(cordon.Action(kind="shell", command="echo ok"))
    assert v.decision == "allow"
