"""LangChain integration — guard tool calls before they execute.

Unlike the OpenAI and Anthropic integrations (which decode a model
response and report verdicts), LangChain dispatches tools itself
through ``BaseTool.invoke`` / ``_run`` / ``arun`` / ``_arun``. The
clean integration point, therefore, is a *wrapper* that duck-types
``BaseTool`` and gates execution on a guard.

This module gives you:

* :class:`GuardedTool` — a duck-typed BaseTool wrapper. Forwards
  ``name``, ``description``, and ``args_schema`` from the wrapped
  tool; runs Cordon on every ``invoke`` / ``_run`` and either
  delegates to the wrapped tool or blocks.
* :func:`guard_tool` — convenience wrapper that returns a
  :class:`GuardedTool` for a single tool.
* :func:`guard_tools` — wrap a list of tools at once. Skips tools
  that have no registered builder factory (logs a warning).

On-block behavior is configurable:

* ``"raise"``         — raise :class:`cordon.BlockedAction` (default).
* ``"return_error"``  — return a human-readable error string. This is
  often the right choice when feeding tool results back into a LangChain
  agent: the agent observes the error in its scratchpad and can recover
  (apologize, try a different approach, etc.) without crashing the run.

Design rules
------------

* **No runtime dependency on the ``langchain`` package.** We accept any
  object that exposes ``name`` and either an ``invoke``, ``run``, or
  ``_run`` method. Modern LCEL ``Runnable`` tools work; legacy
  ``BaseTool`` works; even plain functions wrapped in a tiny shim work.
* **Pure / side-effect free** apart from delegating to the wrapped tool.
* **Replayable.** The guard verdict is exposed on the wrapper for
  audit logs (``GuardedTool.last_verdict``).

Quickstart
----------

::

    import cordon
    from cordon.integrations.langchain import ActionBuilder, guard_tools

    from langchain_core.tools import tool

    @tool
    def run_shell(command: str) -> str:
        '''Execute a shell command.'''
        ...

    @tool
    def write_file(path: str, content: str) -> str:
        '''Write content to a file.'''
        ...

    builder = ActionBuilder()

    @builder.tool("run_shell")
    def _(args: dict) -> cordon.Action:
        return cordon.Action(kind="shell", command=args["command"])

    @builder.tool("write_file")
    def _(args: dict) -> cordon.Action:
        return cordon.Action(kind="file", changes={args["path"]: args["content"]})

    guarded = guard_tools(
        [run_shell, write_file],
        builder=builder,
        guard=cordon.Guard.strict(),
        on_block="return_error",
    )

    agent = create_react_agent(llm, guarded)
"""

from __future__ import annotations

import inspect
import logging
from collections.abc import Callable, Iterable
from typing import Any, Literal

from cordon.core.guard import BlockedAction, Guard
from cordon.core.types import Action, Verdict

from cordon.integrations._common import (
    ActionBuilder,
    ActionFactory,
    coerce_attr,
    verdict_for_unknown_tool,
)

logger = logging.getLogger(__name__)


OnBlock = Literal["raise", "return_error"]


# ─── Wrapped tool ────────────────────────────────────────────────────────────


class GuardedTool:
    """Duck-typed wrapper around a LangChain-like tool.

    Forwards ``name``, ``description``, and ``args_schema``. Wraps
    every invocation with a Cordon guard check.

    Attributes:
        wrapped: The underlying tool object.
        builder: An :class:`ActionBuilder` mapping tool names to Action
            factories.
        guard: The :class:`Guard` to run.
        on_block: ``"raise"`` (default) or ``"return_error"``.
        last_verdict: The most recent :class:`Verdict` produced for this
            tool, or ``None`` before the first call. Useful for tests
            and trace logs.
    """

    def __init__(
        self,
        wrapped: Any,
        *,
        builder: ActionBuilder,
        guard: Guard | None = None,
        on_block: OnBlock = "raise",
    ) -> None:
        if on_block not in ("raise", "return_error"):
            raise ValueError("on_block must be 'raise' or 'return_error'")

        self.wrapped = wrapped
        self.builder = builder
        self.guard = guard or Guard.default()
        self.on_block = on_block
        self.last_verdict: Verdict | None = None

        # Resolve the tool name once at wrap time. We require it to be
        # present because the builder lookup needs it.
        name = coerce_attr(wrapped, "name")
        if not isinstance(name, str) or not name:
            raise ValueError(
                f"GuardedTool: wrapped object {type(wrapped).__name__} has no .name; "
                "LangChain tools must expose a `name` attribute."
            )
        self._name = name

    # ── BaseTool-compat surface ───────────────────────────────────────────────

    @property
    def name(self) -> str:
        return self._name

    @property
    def description(self) -> str:
        return coerce_attr(self.wrapped, "description", "") or ""

    @property
    def args_schema(self) -> Any:
        return coerce_attr(self.wrapped, "args_schema")

    # ── Guard pipeline ────────────────────────────────────────────────────────

    def _guard_arguments(self, arguments: dict[str, Any]) -> tuple[Verdict, Action | None]:
        """Run the guard against the resolved arguments and stash the verdict.

        Returns ``(verdict, action_or_None)``. ``action`` is ``None`` when
        the tool has no registered builder factory.
        """
        action = self.builder.build(self._name, arguments)
        if action is None:
            verdict = verdict_for_unknown_tool(
                self._name, self.builder.unknown_tool_policy, action_id=None,
            )
            self.last_verdict = verdict
            return verdict, None

        verdict = self.guard.check(action)
        self.last_verdict = verdict
        return verdict, action

    def _handle_block(self, verdict: Verdict) -> str:
        """Apply the configured on-block policy. Returns a string when
        ``on_block="return_error"``; raises otherwise.
        """
        if self.on_block == "return_error":
            return (
                f"Cordon blocked tool '{self._name}': {verdict.top_reason()} "
                f"(suspicion={verdict.suspicion_score:.2f})"
            )
        raise BlockedAction(verdict)

    # ── Public invocation methods ─────────────────────────────────────────────

    def invoke(self, input: Any, config: Any = None, **kwargs: Any) -> Any:
        """Modern LangChain Runnable entry point."""
        arguments = _coerce_input_to_dict(input)
        verdict, _ = self._guard_arguments(arguments)
        if verdict.blocked:
            return self._handle_block(verdict)
        return _delegate_invoke(self.wrapped, input, config=config, **kwargs)

    async def ainvoke(self, input: Any, config: Any = None, **kwargs: Any) -> Any:
        """Async modern LangChain Runnable entry point."""
        arguments = _coerce_input_to_dict(input)
        verdict, _ = self._guard_arguments(arguments)
        if verdict.blocked:
            return self._handle_block(verdict)
        return await _delegate_ainvoke(self.wrapped, input, config=config, **kwargs)

    def run(self, *args: Any, **kwargs: Any) -> Any:
        """Legacy ``BaseTool.run`` entry point."""
        arguments = _coerce_run_args_to_dict(args, kwargs)
        verdict, _ = self._guard_arguments(arguments)
        if verdict.blocked:
            return self._handle_block(verdict)
        return _delegate_run(self.wrapped, *args, **kwargs)

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        """Legacy ``BaseTool._run`` entry point."""
        arguments = _coerce_run_args_to_dict(args, kwargs)
        verdict, _ = self._guard_arguments(arguments)
        if verdict.blocked:
            return self._handle_block(verdict)
        return _delegate__run(self.wrapped, *args, **kwargs)

    async def _arun(self, *args: Any, **kwargs: Any) -> Any:
        """Legacy async ``BaseTool._arun`` entry point."""
        arguments = _coerce_run_args_to_dict(args, kwargs)
        verdict, _ = self._guard_arguments(arguments)
        if verdict.blocked:
            return self._handle_block(verdict)
        return await _delegate__arun(self.wrapped, *args, **kwargs)

    # Calling the wrapper directly works, too.
    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        return self.run(*args, **kwargs)

    def __repr__(self) -> str:
        return f"GuardedTool(name={self._name!r}, on_block={self.on_block!r})"


# ─── Convenience wrappers ────────────────────────────────────────────────────


def guard_tool(
    tool: Any,
    *,
    builder: ActionBuilder,
    guard: Guard | None = None,
    on_block: OnBlock = "raise",
) -> GuardedTool:
    """Wrap a single LangChain-like tool with a Cordon guard."""
    return GuardedTool(tool, builder=builder, guard=guard, on_block=on_block)


def guard_tools(
    tools: Iterable[Any],
    *,
    builder: ActionBuilder,
    guard: Guard | None = None,
    on_block: OnBlock = "raise",
    skip_unregistered: bool = False,
) -> list[GuardedTool | Any]:
    """Wrap each tool in ``tools`` with a :class:`GuardedTool`.

    Args:
        tools: Iterable of LangChain-like tools.
        builder: Shared :class:`ActionBuilder`.
        guard: Shared :class:`Guard`.
        on_block: ``"raise"`` or ``"return_error"``.
        skip_unregistered: If ``True``, tools whose names have no
            registered builder factory are returned unwrapped (with a
            warning). If ``False`` (default), they're wrapped anyway —
            the wrapper will follow the builder's ``unknown_tool_policy``
            on each call.

    Returns:
        A list of wrappers (and possibly some bare tools, if
        ``skip_unregistered=True``).
    """
    out: list[GuardedTool | Any] = []
    for tool in tools:
        name = coerce_attr(tool, "name")
        if skip_unregistered and not builder.has(name or ""):
            logger.warning(
                "guard_tools: %r has no registered builder factory; "
                "leaving unwrapped per skip_unregistered=True.",
                name,
            )
            out.append(tool)
            continue
        out.append(GuardedTool(tool, builder=builder, guard=guard, on_block=on_block))
    return out


# ─── Internal helpers ────────────────────────────────────────────────────────


def _coerce_input_to_dict(input: Any) -> dict[str, Any]:
    """LangChain Runnable inputs may be a dict, a string, or a Pydantic model.

    Cordon builders take a dict, so we normalize:

    * dict → as-is.
    * Pydantic model (has ``model_dump``) → serialized.
    * other → ``{"input": value}``.

    This intentionally lossy mapping mirrors what LangChain's own
    `RunnableTool` does internally for single-arg tools.
    """
    if isinstance(input, dict):
        return input
    dump = getattr(input, "model_dump", None)
    if callable(dump):
        try:
            d = dump()
            if isinstance(d, dict):
                return d
        except Exception:  # noqa: BLE001
            pass
    return {"input": input}


def _coerce_run_args_to_dict(args: tuple[Any, ...], kwargs: dict[str, Any]) -> dict[str, Any]:
    """Normalize legacy ``_run(*args, **kwargs)`` into a single dict.

    The convention we've chosen — and that the OpenAI/Anthropic
    builders also use — is keyword-only. So:

    * If only kwargs are present: return them as-is.
    * If a single positional arg is a dict: use it directly.
    * Otherwise: bundle positional args under ``"args"``.
    """
    if kwargs and not args:
        return dict(kwargs)
    if not kwargs and len(args) == 1 and isinstance(args[0], dict):
        return dict(args[0])
    if not kwargs and not args:
        return {}
    bundle: dict[str, Any] = {}
    if args:
        bundle["args"] = args[0] if len(args) == 1 else list(args)
    bundle.update(kwargs)
    return bundle


def _delegate_invoke(tool: Any, input: Any, *, config: Any = None, **kwargs: Any) -> Any:
    """Call ``tool.invoke`` if available, else fall back to ``run`` / ``_run`` / call."""
    invoke = getattr(tool, "invoke", None)
    if callable(invoke):
        return invoke(input, config=config, **kwargs) if config is not None else invoke(input, **kwargs)
    return _delegate_run(tool, **(_coerce_input_to_dict(input)))


async def _delegate_ainvoke(tool: Any, input: Any, *, config: Any = None, **kwargs: Any) -> Any:
    ainvoke = getattr(tool, "ainvoke", None)
    if callable(ainvoke):
        result = ainvoke(input, config=config, **kwargs) if config is not None else ainvoke(input, **kwargs)
        if inspect.isawaitable(result):
            return await result
        return result
    # Fall back to sync invoke.
    return _delegate_invoke(tool, input, config=config, **kwargs)


def _delegate_run(tool: Any, *args: Any, **kwargs: Any) -> Any:
    run = getattr(tool, "run", None)
    if callable(run):
        return run(*args, **kwargs)
    return _delegate__run(tool, *args, **kwargs)


def _delegate__run(tool: Any, *args: Any, **kwargs: Any) -> Any:
    _run = getattr(tool, "_run", None)
    if callable(_run):
        return _run(*args, **kwargs)
    if callable(tool):
        return tool(*args, **kwargs)
    raise TypeError(
        f"GuardedTool: wrapped object {type(tool).__name__} is not callable and "
        "has no .run / ._run method"
    )


async def _delegate__arun(tool: Any, *args: Any, **kwargs: Any) -> Any:
    arun = getattr(tool, "_arun", None) or getattr(tool, "arun", None)
    if callable(arun):
        result = arun(*args, **kwargs)
        if inspect.isawaitable(result):
            return await result
        return result
    # Fall back to sync.
    return _delegate__run(tool, *args, **kwargs)


__all__ = [
    "ActionBuilder",
    "ActionFactory",
    "GuardedTool",
    "guard_tool",
    "guard_tools",
]
