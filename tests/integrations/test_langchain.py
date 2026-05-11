"""Tests for the LangChain integration.

We don't depend on the ``langchain`` package — we build small fakes
that match the LangChain ``BaseTool`` / Runnable surface (``name``,
``description``, ``invoke``, ``run``, ``_run``).
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from cordon import Action, Guard
from cordon.core.guard import BlockedAction
from cordon.integrations.langchain import (
    ActionBuilder,
    GuardedTool,
    guard_tool,
    guard_tools,
)


# ─── Fake BaseTool implementations ────────────────────────────────────────────


class _FakeTool:
    """A duck-typed stand-in for langchain_core.tools.BaseTool."""

    def __init__(
        self,
        name: str,
        description: str = "",
        impl: Any = None,
        *,
        async_impl: Any = None,
    ) -> None:
        self.name = name
        self.description = description
        self.args_schema = None
        self._impl = impl or (lambda **kwargs: f"ran {name} with {kwargs}")
        self._async_impl = async_impl

    # Modern Runnable API.
    def invoke(self, input: Any, config: Any = None, **kwargs: Any) -> Any:
        if isinstance(input, dict):
            return self._impl(**input)
        return self._impl(input)

    async def ainvoke(self, input: Any, config: Any = None, **kwargs: Any) -> Any:
        if self._async_impl is None:
            return self.invoke(input, config=config, **kwargs)
        if isinstance(input, dict):
            return await self._async_impl(**input)
        return await self._async_impl(input)

    # Legacy BaseTool API.
    def run(self, *args: Any, **kwargs: Any) -> Any:
        return self._run(*args, **kwargs)

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        if args and not kwargs and isinstance(args[0], dict):
            return self._impl(**args[0])
        return self._impl(*args, **kwargs)

    async def _arun(self, *args: Any, **kwargs: Any) -> Any:
        if self._async_impl is None:
            return self._run(*args, **kwargs)
        return await self._async_impl(*args, **kwargs)


# ─── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture
def builder() -> ActionBuilder:
    b = ActionBuilder()

    @b.tool("run_shell")
    def _shell(args: dict) -> Action:
        return Action(kind="shell", command=args["command"])

    @b.tool("write_file")
    def _write(args: dict) -> Action:
        return Action(kind="file", changes={args["path"]: args["content"]})

    return b


@pytest.fixture
def shell_tool() -> _FakeTool:
    return _FakeTool(name="run_shell", description="Run a shell command.")


@pytest.fixture
def write_tool() -> _FakeTool:
    return _FakeTool(name="write_file", description="Write content to a file.")


# ─── Surface forwarding ──────────────────────────────────────────────────────


def test_guarded_tool_forwards_name(shell_tool: _FakeTool, builder: ActionBuilder) -> None:
    g = guard_tool(shell_tool, builder=builder)
    assert g.name == "run_shell"
    assert g.description == "Run a shell command."


def test_guarded_tool_requires_name(builder: ActionBuilder) -> None:
    class _Nameless:
        description = "x"

    with pytest.raises(ValueError, match="no .name"):
        GuardedTool(_Nameless(), builder=builder)


def test_invalid_on_block_rejected(shell_tool: _FakeTool, builder: ActionBuilder) -> None:
    with pytest.raises(ValueError, match="on_block"):
        GuardedTool(shell_tool, builder=builder, on_block="ignore")  # type: ignore[arg-type]


# ─── Allow path ───────────────────────────────────────────────────────────────


def test_invoke_allows_benign_command(shell_tool: _FakeTool, builder: ActionBuilder) -> None:
    g = guard_tool(shell_tool, builder=builder, guard=Guard.default())
    result = g.invoke({"command": "ls -la"})
    assert "ran run_shell" in result
    assert g.last_verdict is not None and g.last_verdict.allowed


def test_run_allows_benign_command(shell_tool: _FakeTool, builder: ActionBuilder) -> None:
    g = guard_tool(shell_tool, builder=builder, guard=Guard.default())
    result = g.run(command="ls -la")
    assert "ran run_shell" in result


def test_call_dispatch_allows(shell_tool: _FakeTool, builder: ActionBuilder) -> None:
    g = guard_tool(shell_tool, builder=builder, guard=Guard.default())
    assert "ran" in g(command="ls -la")


# ─── Block path — raise mode ─────────────────────────────────────────────────


def test_invoke_blocks_typosquat_raises(shell_tool: _FakeTool, builder: ActionBuilder) -> None:
    g = guard_tool(shell_tool, builder=builder, guard=Guard.strict(), on_block="raise")

    # Typosquat in changes → should be blocked. We need a builder that
    # surfaces changes. Use the write_file tool path instead.
    write_tool = _FakeTool(name="install_pkg")
    # Register a richer builder for this test.
    b = ActionBuilder()

    @b.tool("install_pkg")
    def _(args: dict) -> Action:
        return Action(kind="shell",
                      command="pip install -r requirements.txt",
                      changes={"requirements.txt": f"{args['package']}\n"})

    g = guard_tool(write_tool, builder=b, guard=Guard.strict())

    with pytest.raises(BlockedAction):
        g.invoke({"package": "reqeusts==2.31.0"})


def test_run_blocks_chmod_777_raises(builder: ActionBuilder) -> None:
    tool = _FakeTool(name="run_shell")
    g = guard_tool(tool, builder=builder, guard=Guard.strict())
    with pytest.raises(BlockedAction):
        g.run(command="chmod -R 777 /app/data")


# ─── Block path — return_error mode ──────────────────────────────────────────


def test_invoke_blocks_returns_error_string(builder: ActionBuilder) -> None:
    tool = _FakeTool(name="run_shell")
    g = guard_tool(tool, builder=builder, guard=Guard.strict(), on_block="return_error")
    out = g.invoke({"command": "chmod -R 777 /app/data"})
    assert isinstance(out, str)
    assert "Cordon blocked" in out
    assert "run_shell" in out


def test_run_blocks_returns_error_string(builder: ActionBuilder) -> None:
    tool = _FakeTool(name="run_shell")
    g = guard_tool(tool, builder=builder, guard=Guard.strict(), on_block="return_error")
    out = g.run(command="chmod -R 777 /app/data")
    assert "Cordon blocked" in out


def test_underlying_tool_not_called_when_blocked(builder: ActionBuilder) -> None:
    """Critical safety guarantee: a blocked invocation must NOT call the wrapped tool."""
    calls: list[Any] = []

    def _impl(**kwargs: Any) -> str:
        calls.append(kwargs)
        return "ran"

    tool = _FakeTool(name="run_shell", impl=_impl)
    g = guard_tool(tool, builder=builder, guard=Guard.strict(), on_block="return_error")
    g.invoke({"command": "chmod -R 777 /app/data"})
    assert calls == [], f"Wrapped tool was called with {calls}"


# ─── Async path ──────────────────────────────────────────────────────────────


def test_ainvoke_allows() -> None:
    builder = ActionBuilder()

    @builder.tool("run_shell")
    def _(args: dict) -> Action:
        return Action(kind="shell", command=args["command"])

    async def _aimpl(**kwargs: Any) -> str:
        return f"async {kwargs}"

    tool = _FakeTool(name="run_shell", async_impl=_aimpl)
    g = guard_tool(tool, builder=builder, guard=Guard.default())
    result = asyncio.run(g.ainvoke({"command": "ls -la"}))
    assert "async" in result


def test_ainvoke_blocks_returns_error() -> None:
    builder = ActionBuilder()

    @builder.tool("run_shell")
    def _(args: dict) -> Action:
        return Action(kind="shell", command=args["command"])

    tool = _FakeTool(name="run_shell")
    g = guard_tool(tool, builder=builder, guard=Guard.strict(), on_block="return_error")
    out = asyncio.run(g.ainvoke({"command": "chmod -R 777 /app/data"}))
    assert "Cordon blocked" in out


# ─── Unknown tool policy ─────────────────────────────────────────────────────


def test_unknown_tool_default_flag_does_not_block() -> None:
    """Default unknown_tool_policy='flag' means the wrapped tool still runs."""
    tool = _FakeTool(name="mystery_tool")
    builder = ActionBuilder()  # nothing registered
    g = guard_tool(tool, builder=builder, guard=Guard.default())
    result = g.invoke({"x": 1})
    assert "ran" in result


def test_unknown_tool_block_policy_blocks() -> None:
    tool = _FakeTool(name="mystery_tool")
    builder = ActionBuilder(unknown_tool_policy="block")
    g = guard_tool(tool, builder=builder, guard=Guard.default(), on_block="return_error")
    out = g.invoke({"x": 1})
    assert "Cordon blocked" in out


# ─── guard_tools (batch) ─────────────────────────────────────────────────────


def test_guard_tools_wraps_each_tool(builder: ActionBuilder) -> None:
    a = _FakeTool(name="run_shell")
    b = _FakeTool(name="write_file")
    wrapped = guard_tools([a, b], builder=builder, guard=Guard.default())
    assert len(wrapped) == 2
    assert all(isinstance(w, GuardedTool) for w in wrapped)
    assert {w.name for w in wrapped} == {"run_shell", "write_file"}  # type: ignore[union-attr]


def test_guard_tools_skip_unregistered_leaves_bare(builder: ActionBuilder) -> None:
    known = _FakeTool(name="run_shell")
    unknown = _FakeTool(name="random_tool")
    wrapped = guard_tools([known, unknown], builder=builder,
                          guard=Guard.default(), skip_unregistered=True)
    assert len(wrapped) == 2
    assert isinstance(wrapped[0], GuardedTool)
    assert wrapped[1] is unknown  # left bare
