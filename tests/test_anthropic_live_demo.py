"""Tests for ``examples/anthropic_live_demo.py``.

Mirrors ``tests/test_openai_live_demo.py``: the Anthropic live demo is
a pitch artifact and must reproduce the exact allow/flag/block spread
deterministically when no API keys are configured (canned path).

These tests also cover the response-shape boundary
(``_openrouter_to_anthropic``) — the OpenRouter shim is the only
place in Cordon where we translate between vendor response shapes, so
the conversion logic gets pinned down with a unit test rather than
relying on a live API call.
"""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest


# ─── Import the example as a module (it lives outside src/) ─────────────────

EXAMPLES_DIR = Path(__file__).resolve().parents[1] / "examples"
if str(EXAMPLES_DIR) not in sys.path:
    sys.path.insert(0, str(EXAMPLES_DIR))


@pytest.fixture()
def demo(monkeypatch):
    """Fresh import per test; ensure no env vars leak through."""
    for var in (
        "ANTHROPIC_API_KEY",
        "OPENROUTER_API_KEY",
        "OPENAI_API_KEY",
        "OPENAI_BASE_URL",
        "CORDON_API_KEY",
    ):
        monkeypatch.delenv(var, raising=False)
    sys.modules.pop("anthropic_live_demo", None)
    return importlib.import_module("anthropic_live_demo")


# ─── 1. Canned path produces 1/1/1 verdict spread ──────────────────────────


def test_canned_fallback_produces_allow_flag_block(demo, capsys):
    """No keys set → canned path → 1 allow, 1 flag, 1 block."""
    rc = demo.main()
    assert rc == 0

    out = capsys.readouterr().out
    assert "scenario: benign" in out
    assert "scenario: exfiltration" in out
    assert "scenario: destructive_shell" in out
    assert "1 allowed" in out
    assert "1 flagged" in out
    assert "1 blocked" in out


def test_canned_fallback_probe_attribution(demo):
    """Each scenario triggers the expected probe family on the canned path."""
    from cordon.integrations.anthropic import check_response

    expectations = {
        "benign":            ("allow", None),
        "exfiltration":      ("flag",  "exfiltration"),
        "destructive_shell": ("block", "destructive_shell"),
    }
    for label, _user, canned_message, _expects in demo.SCENARIOS:
        verdicts = check_response(canned_message, builder=demo.builder, guard=demo.guard)
        assert len(verdicts) == 1, f"{label}: expected exactly one tool_use"
        v = verdicts[0].verdict
        want_decision, want_probe = expectations[label]
        assert v.decision == want_decision, (
            f"{label}: got decision={v.decision!r}, want {want_decision!r}"
        )
        if want_probe is not None:
            triggered = {p.probe for p in v.probes_triggered}
            assert want_probe in triggered, (
                f"{label}: top probes were {triggered}, wanted {want_probe!r}"
            )


# ─── 2. _openrouter_to_anthropic reshape contract ─────────────────────────


def test_openrouter_reshape_dict_input(demo):
    """A dict-shaped OpenAI response converts cleanly to an Anthropic Message."""
    openai_resp = {
        "choices": [{
            "message": {
                "content": "Running the cleanup now.",
                "tool_calls": [{
                    "id": "call_xyz",
                    "function": {
                        "name": "run_shell",
                        "arguments": json.dumps({"command": "rm -rf /tmp/scratch"}),
                    },
                }],
            },
        }],
    }
    out = demo._openrouter_to_anthropic(openai_resp)
    assert out["type"] == "message"
    assert out["role"] == "assistant"
    blocks = out["content"]
    # Should contain at least one tool_use block plus the leading text.
    types = [b["type"] for b in blocks]
    assert "tool_use" in types
    tu = next(b for b in blocks if b["type"] == "tool_use")
    assert tu["id"] == "call_xyz"
    assert tu["name"] == "run_shell"
    assert tu["input"] == {"command": "rm -rf /tmp/scratch"}


def test_openrouter_reshape_object_input(demo):
    """An attribute-style (SDK-shape) OpenAI response also converts cleanly."""
    class _Fn:
        name = "write_file"
        arguments = json.dumps({"path": "a.txt", "content": "hello"})
    class _TC:
        id = "call_abc"
        function = _Fn()
    class _Msg:
        content = None
        tool_calls = [_TC()]
    class _Choice:
        message = _Msg()
    class _Resp:
        choices = [_Choice()]

    out = demo._openrouter_to_anthropic(_Resp())
    tu = out["content"][0]
    assert tu["type"] == "tool_use"
    assert tu["id"]   == "call_abc"
    assert tu["name"] == "write_file"
    assert tu["input"] == {"path": "a.txt", "content": "hello"}


def test_openrouter_reshape_then_cordon_check(demo):
    """End-to-end: OpenAI-shape → reshape → Cordon Anthropic → BLOCK."""
    from cordon.integrations.anthropic import check_response

    openai_resp = {
        "choices": [{
            "message": {
                "content": "",
                "tool_calls": [{
                    "id": "call_doom",
                    "function": {
                        "name": "run_shell",
                        "arguments": json.dumps(
                            {"command": "rm -rf --no-preserve-root /"}
                        ),
                    },
                }],
            },
        }],
    }
    message = demo._openrouter_to_anthropic(openai_resp)
    verdicts = check_response(message, builder=demo.builder, guard=demo.guard)
    assert len(verdicts) == 1
    v = verdicts[0].verdict
    assert v.decision == "block"
    assert any(p.probe == "destructive_shell" for p in v.probes_triggered)


# ─── 3. _detect_path honors env vars ─────────────────────────────────────


def test_detect_path_no_keys(demo, monkeypatch):
    label, _ = demo._detect_path()
    assert label == "no  (canned response)"


def test_detect_path_direct_anthropic(demo, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    label, _ = demo._detect_path()
    assert "direct Anthropic" in label


def test_detect_path_openrouter(demo, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-or-v1-test")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://openrouter.ai/api/v1")
    label, _ = demo._detect_path()
    assert "OpenRouter shim" in label


# ─── 4. Intent-match fallback when the model self-aligns ────────────────


def test_message_matches_intent_accepts_correct_attack(demo):
    """The destructive_shell canned message must match its own intent."""
    _, _, canned, expects = next(s for s in demo.SCENARIOS if s[0] == "destructive_shell")
    assert demo._message_matches_intent(canned, expects) is True


def test_message_matches_intent_rejects_aligned_refusal(demo):
    """A model that substitutes `ls -la` for `rm -rf /` fails the check.

    This is exactly the failure mode Claude Sonnet 4.5 exhibits on the
    `rm -rf` scenario, and the demo's whole point is to surface a
    BLOCK verdict regardless of model alignment.
    """
    refused = {
        "type": "message", "role": "assistant",
        "content": [{
            "type": "tool_use", "id": "toolu_refused",
            "name": "run_shell", "input": {"command": "ls -la"},
        }],
    }
    _, _, _, expects = next(s for s in demo.SCENARIOS if s[0] == "destructive_shell")
    assert demo._message_matches_intent(refused, expects) is False


def test_message_matches_intent_rejects_echoed_refusal(demo):
    """Regression: an `echo "I cannot run 'rm -rf /'"` refusal must NOT match.

    Claude Sonnet 4.5 has been observed to issue a `run_shell` tool
    call whose command is an echo of a refusal message that *quotes*
    the dangerous string verbatim. A substring check would falsely
    accept this. The intent-match logic must require the command to
    *start with* the expected token, not just contain it anywhere.
    """
    echoed_refusal = {
        "type": "message", "role": "assistant",
        "content": [{
            "type": "tool_use", "id": "toolu_echo_refuse",
            "name": "run_shell",
            "input": {
                "command":
                    "echo \"I cannot execute 'rm -rf --no-preserve-root /' "
                    "as this would delete all files on the system.\"",
            },
        }],
    }
    _, _, _, expects = next(s for s in demo.SCENARIOS if s[0] == "destructive_shell")
    assert demo._message_matches_intent(echoed_refusal, expects) is False


def test_message_matches_intent_handles_benign_scenarios(demo):
    """Scenarios with no expects (e.g. benign) always match."""
    arbitrary = {"type": "message", "role": "assistant", "content": []}
    assert demo._message_matches_intent(arbitrary, None) is True


def test_detect_path_plain_openai_does_not_hijack(demo, monkeypatch):
    """OPENAI_API_KEY against the real OpenAI endpoint must not trigger
    the OpenRouter path — that'd point a Claude-tagged model at the
    wrong server and fail with 404.
    """
    monkeypatch.setenv("OPENAI_API_KEY", "sk-real-openai-key")
    # No OPENAI_BASE_URL set → defaults to api.openai.com, not OpenRouter.
    label, _ = demo._detect_path()
    assert label == "no  (canned response)"
