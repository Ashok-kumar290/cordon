"""Tests for the CordonGuardCallback complement to GuardedTool."""
from __future__ import annotations

import logging
import pytest

from cordon import Action, BlockedAction, Guard
from cordon.integrations.langchain import (
    ActionBuilder,
    CordonGuardCallback,
)


@pytest.fixture()
def builder() -> ActionBuilder:
    b = ActionBuilder()

    @b.tool("run_shell")
    def _(args):
        return Action(kind="shell", command=args["command"])

    @b.tool("write_file")
    def _(args):
        return Action(kind="file", changes={args["path"]: args["content"]})

    return b


@pytest.fixture()
def callback(builder) -> CordonGuardCallback:
    return CordonGuardCallback(Guard.strict(), builder=builder)


# ─── raise_error class attribute ────────────────────────────────────────────


def test_raise_error_attribute_is_true():
    """LangChain swallows callback exceptions unless this flag is True.

    Without raise_error=True the BlockedAction we raise would be logged
    and the tool would run anyway. This is the gate's single most
    important configuration bit.
    """
    assert CordonGuardCallback.raise_error is True


# ─── ALLOW path ─────────────────────────────────────────────────────────────


def test_allows_safe_tool_call(callback):
    callback.on_tool_start({"name": "run_shell"}, '{"command": "pytest -q"}')
    assert callback.last_verdict is not None
    assert callback.last_verdict.decision == "allow"


# ─── BLOCK path ─────────────────────────────────────────────────────────────


def test_blocks_destructive_shell_raises_BlockedAction(callback):
    with pytest.raises(BlockedAction) as exc:
        callback.on_tool_start(
            {"name": "run_shell"},
            '{"command": "rm -rf --no-preserve-root /"}',
        )
    assert exc.value.verdict.decision == "block"
    # The callback also records it on last_verdict for downstream observers.
    assert callback.last_verdict is exc.value.verdict


def test_return_error_mode_does_not_raise(builder, caplog):
    """on_block='return_error' must log + record but never raise."""
    cb = CordonGuardCallback(
        Guard.strict(), builder=builder, on_block="return_error",
    )
    with caplog.at_level(logging.WARNING, logger="cordon.integrations.langchain"):
        cb.on_tool_start(
            {"name": "run_shell"},
            '{"command": "rm -rf --no-preserve-root /"}',
        )
    assert cb.last_verdict.decision == "block"
    assert any("return_error" in r.getMessage() for r in caplog.records)


# ─── inputs vs input_str precedence ─────────────────────────────────────────


def test_inputs_dict_takes_precedence_over_input_str(callback):
    """Newer LangChain versions pass ``inputs=`` separately. Prefer it."""
    callback.on_tool_start(
        {"name": "run_shell"},
        "garbage that would fail json parse",
        inputs={"command": "pytest -q"},
    )
    assert callback.last_verdict.decision == "allow"


def test_input_str_json_decoded_when_inputs_missing(callback):
    callback.on_tool_start(
        {"name": "run_shell"},
        '{"command": "pytest -q"}',
    )
    assert callback.last_verdict.decision == "allow"


def test_input_str_non_json_wrapped_under_input_key(builder):
    """Single-input tools pass a raw string; we wrap it as {"input": ...}."""
    captured = {}

    @builder.tool("echo_single")
    def _(args):
        captured["arg"] = args
        return Action(kind="shell", command=f"echo {args.get('input', '')}")

    cb = CordonGuardCallback(Guard.strict(), builder=builder)
    cb.on_tool_start({"name": "echo_single"}, "hello world")
    assert captured["arg"] == {"input": "hello world"}
    assert cb.last_verdict.decision == "allow"


def test_empty_input_str_yields_empty_dict(builder):
    captured = {}

    @builder.tool("noop")
    def _(args):
        captured["arg"] = args
        return Action(kind="shell", command="true")

    cb = CordonGuardCallback(Guard.strict(), builder=builder)
    cb.on_tool_start({"name": "noop"}, "")
    assert captured["arg"] == {}


# ─── Unknown tool handling ──────────────────────────────────────────────────


def test_unknown_tool_uses_builder_default_policy(builder):
    """A tool with no builder factory follows builder.unknown_tool_policy."""
    # The fixture builder defaults to "flag".
    cb = CordonGuardCallback(Guard.strict(), builder=builder)
    cb.on_tool_start({"name": "mystery"}, "{}")
    assert cb.last_verdict.decision == "flag"


def test_unknown_tool_with_block_policy_raises(builder):
    builder.unknown_tool_policy = "block"
    cb = CordonGuardCallback(Guard.strict(), builder=builder)
    with pytest.raises(BlockedAction):
        cb.on_tool_start({"name": "mystery"}, "{}")


# ─── Lifecycle no-ops (must not raise / must remain hooks) ──────────────────


def test_on_tool_end_is_noop(callback):
    assert callback.on_tool_end("any output") is None


def test_on_tool_error_is_noop(callback):
    assert callback.on_tool_error(RuntimeError("anything")) is None


# ─── Async mirror ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_on_tool_start_async_mirrors_sync(callback):
    """Async hook must behave identically to the sync one for the gate."""
    with pytest.raises(BlockedAction):
        await callback.on_tool_start_async(
            {"name": "run_shell"},
            '{"command": "rm -rf --no-preserve-root /"}',
        )
    assert callback.last_verdict.decision == "block"
