"""Tests for the OpenAI integration.

We don't depend on the ``openai`` package — instead we build dict and
namespace fixtures that match the OpenAI 1.x ``ChatCompletion`` shape.
This both keeps the test suite light and verifies the duck-typing
contract the integration promises.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from cordon import Action, Guard
from cordon.core.guard import BlockedAction
from cordon.integrations.openai import (
    ActionBuilder,
    ToolCallVerdict,
    check_response,
    protect_tool,
)


# ─── Fixtures ─────────────────────────────────────────────────────────────────


def _make_response_dict(tool_calls: list[dict]) -> dict:
    """Build a minimal OpenAI-shaped response (dict variant)."""
    return {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": tool_calls,
                }
            }
        ]
    }


def _make_response_ns(tool_calls: list[SimpleNamespace]) -> SimpleNamespace:
    """Build a minimal OpenAI-shaped response (attrs/SimpleNamespace variant)."""
    return SimpleNamespace(
        choices=[
            SimpleNamespace(
                message=SimpleNamespace(
                    role="assistant",
                    content=None,
                    tool_calls=tool_calls,
                )
            )
        ]
    )


def _tool_call_dict(call_id: str, name: str, args: dict) -> dict:
    return {
        "id": call_id,
        "type": "function",
        "function": {"name": name, "arguments": json.dumps(args)},
    }


def _tool_call_ns(call_id: str, name: str, args: dict) -> SimpleNamespace:
    return SimpleNamespace(
        id=call_id,
        type="function",
        function=SimpleNamespace(name=name, arguments=json.dumps(args)),
    )


@pytest.fixture
def builder() -> ActionBuilder:
    b = ActionBuilder()

    @b.tool("run_shell")
    def _shell(args: dict) -> Action:
        return Action(
            kind="shell",
            command=args["command"],
            changes=args.get("changes", {}),
        )

    @b.tool("write_file")
    def _write(args: dict) -> Action:
        return Action(kind="file", changes={args["path"]: args["content"]})

    return b


# ─── ActionBuilder ────────────────────────────────────────────────────────────


def test_builder_decorator_registers() -> None:
    b = ActionBuilder()

    @b.tool("foo")
    def factory(args: dict) -> Action:
        return Action(kind="shell", command="echo " + args.get("msg", "hi"))

    assert b.has("foo")
    assert "foo" in b.names()


def test_builder_imperative_register() -> None:
    b = ActionBuilder()
    b.register("foo", lambda args: Action(kind="shell", command="x"))
    assert b.has("foo")


def test_builder_returns_none_for_unknown_tool() -> None:
    b = ActionBuilder()
    assert b.build("unknown", {}) is None


def test_builder_rejects_non_action_factory() -> None:
    b = ActionBuilder()
    b.register("bad", lambda args: "not an Action")  # type: ignore[arg-type, return-value]
    with pytest.raises(TypeError):
        b.build("bad", {})


def test_builder_unknown_tool_policy_validation() -> None:
    with pytest.raises(ValueError):
        ActionBuilder(unknown_tool_policy="invalid")


# ─── check_response — happy paths ─────────────────────────────────────────────


def test_check_response_dict_shape_allow(builder: ActionBuilder) -> None:
    response = _make_response_dict([
        _tool_call_dict("call_1", "run_shell", {"command": "echo hello"}),
    ])
    verdicts = check_response(response, builder=builder, guard=Guard.default())
    assert len(verdicts) == 1
    assert verdicts[0].tool_call_id == "call_1"
    assert verdicts[0].tool_name == "run_shell"
    assert verdicts[0].allowed
    assert isinstance(verdicts[0], ToolCallVerdict)


def test_check_response_namespace_shape_allow(builder: ActionBuilder) -> None:
    response = _make_response_ns([
        _tool_call_ns("call_1", "run_shell", {"command": "ls -la"}),
    ])
    verdicts = check_response(response, builder=builder)
    assert len(verdicts) == 1
    assert verdicts[0].allowed


def test_check_response_blocks_typosquat(builder: ActionBuilder) -> None:
    response = _make_response_dict([
        _tool_call_dict(
            "call_2",
            "run_shell",
            {
                "command": "pip install -r requirements.txt",
                "changes": {"requirements.txt": "reqeusts==2.31.0\n"},
            },
        ),
    ])
    verdicts = check_response(response, builder=builder, guard=Guard.strict())
    assert len(verdicts) == 1
    assert verdicts[0].blocked
    assert verdicts[0].verdict.suspicion_score >= 0.9


def test_check_response_multiple_tool_calls(builder: ActionBuilder) -> None:
    response = _make_response_dict([
        _tool_call_dict("call_a", "run_shell", {"command": "echo ok"}),
        _tool_call_dict(
            "call_b",
            "write_file",
            {"path": "requirements.txt", "content": "reqeusts==2.31.0\n"},
        ),
    ])
    verdicts = check_response(response, builder=builder, guard=Guard.default())
    assert len(verdicts) == 2
    assert verdicts[0].allowed
    assert verdicts[1].blocked
    # Order is preserved.
    assert verdicts[0].tool_call_id == "call_a"
    assert verdicts[1].tool_call_id == "call_b"


# ─── check_response — empty / edge cases ──────────────────────────────────────


def test_check_response_no_tool_calls() -> None:
    response = {"choices": [{"message": {"role": "assistant", "content": "Hello!"}}]}
    verdicts = check_response(response, builder=ActionBuilder())
    assert verdicts == []


def test_check_response_empty_response() -> None:
    assert check_response({}, builder=ActionBuilder()) == []
    assert check_response({"choices": []}, builder=ActionBuilder()) == []


def test_check_response_unknown_tool_default_flag(builder: ActionBuilder) -> None:
    response = _make_response_dict([
        _tool_call_dict("call_x", "totally_unknown_tool", {"foo": "bar"}),
    ])
    verdicts = check_response(response, builder=builder)
    assert len(verdicts) == 1
    assert verdicts[0].verdict.flagged
    assert "no ActionBuilder factory" in verdicts[0].verdict.explanation


def test_check_response_unknown_tool_block_policy() -> None:
    b = ActionBuilder(unknown_tool_policy="block")
    response = _make_response_dict([
        _tool_call_dict("call_x", "unknown_tool", {}),
    ])
    verdicts = check_response(response, builder=b)
    assert verdicts[0].blocked


def test_check_response_unknown_tool_allow_policy() -> None:
    b = ActionBuilder(unknown_tool_policy="allow")
    response = _make_response_dict([
        _tool_call_dict("call_x", "unknown_tool", {}),
    ])
    verdicts = check_response(response, builder=b)
    assert verdicts[0].allowed


def test_check_response_invalid_json_arguments(builder: ActionBuilder) -> None:
    response = _make_response_dict([
        {
            "id": "bad",
            "type": "function",
            "function": {"name": "run_shell", "arguments": "this is not json"},
        }
    ])
    with pytest.raises(ValueError, match="invalid JSON"):
        check_response(response, builder=builder)


def test_check_response_dict_arguments_passthrough(builder: ActionBuilder) -> None:
    # Some SDKs / wrappers pre-decode the arguments. Make sure we accept that.
    response = _make_response_dict([
        {
            "id": "call_predecoded",
            "type": "function",
            "function": {"name": "run_shell", "arguments": {"command": "echo ok"}},
        }
    ])
    verdicts = check_response(response, builder=builder)
    assert verdicts[0].allowed


def test_check_response_stamps_action_id_from_tool_call_id(builder: ActionBuilder) -> None:
    response = _make_response_dict([
        _tool_call_dict("call_id_propagation", "run_shell", {"command": "echo ok"}),
    ])
    verdicts = check_response(response, builder=builder)
    assert verdicts[0].action.id == "call_id_propagation"
    assert verdicts[0].verdict.action_id == "call_id_propagation"


# ─── protect_tool decorator ───────────────────────────────────────────────────


def test_protect_tool_allows_safe_call(builder: ActionBuilder) -> None:
    calls: list[str] = []

    @protect_tool(name="run_shell", builder=builder, guard=Guard.default())
    def run_shell(command: str) -> str:
        calls.append(command)
        return f"ran: {command}"

    result = run_shell(command="echo ok")
    assert result == "ran: echo ok"
    assert calls == ["echo ok"]


def test_protect_tool_raises_on_block(builder: ActionBuilder) -> None:
    calls: list[str] = []

    @protect_tool(name="run_shell", builder=builder, guard=Guard.default())
    def run_shell(command: str, changes: dict | None = None) -> str:
        calls.append(command)
        return "executed"

    with pytest.raises(BlockedAction) as exc_info:
        run_shell(command="pip install -r requirements.txt",
                  changes={"requirements.txt": "reqeusts==2.31.0\n"})
    assert exc_info.value.verdict.blocked
    # The tool body must not have been invoked.
    assert calls == []


def test_protect_tool_unknown_tool_block_policy() -> None:
    b = ActionBuilder(unknown_tool_policy="block")

    @protect_tool(name="undeclared", builder=b, guard=Guard.default())
    def fn(**kwargs):  # noqa: ANN003
        return "ran"

    with pytest.raises(BlockedAction):
        fn(foo="bar")


def test_protect_tool_unknown_tool_allow_falls_through() -> None:
    b = ActionBuilder(unknown_tool_policy="allow")

    @protect_tool(name="undeclared", builder=b, guard=Guard.default())
    def fn(**kwargs):  # noqa: ANN003
        return "ran"

    assert fn(foo="bar") == "ran"


def test_protect_tool_preserves_function_metadata(builder: ActionBuilder) -> None:
    @protect_tool(name="run_shell", builder=builder)
    def run_shell(command: str) -> str:
        """Run a shell command."""
        return command

    assert run_shell.__name__ == "run_shell"
    assert run_shell.__doc__ == "Run a shell command."
    assert hasattr(run_shell, "__wrapped__")
