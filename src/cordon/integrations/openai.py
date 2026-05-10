"""OpenAI integration — guard tool / function calls before they execute.

The OpenAI Python SDK does not call your tool functions for you. The
SDK returns a response with ``tool_calls``; your code dispatches them.
That's the seam where Cordon plugs in.

This module gives you three entry points, from most to least
opinionated:

1. :class:`ActionBuilder` — a small registry mapping tool names to
   functions that construct :class:`cordon.Action` objects from the
   tool's JSON arguments. You declare the mapping once, near where you
   declare the OpenAI tool schemas.

2. :func:`check_response` — given an OpenAI ``ChatCompletion``-shaped
   response and an :class:`ActionBuilder`, run the configured guard
   against every tool call in the assistant message and return a list
   of :class:`ToolCallVerdict` records.

3. :func:`protect_tool` — a decorator. Wraps a Python function that
   implements one of your tools. Calls to the wrapped function with
   blocked arguments raise :class:`cordon.BlockedAction` before the
   real implementation runs.

Design rules
------------

* **No runtime dependency on the ``openai`` package.** We duck-type the
  response shape: anything with ``.choices[0].message.tool_calls`` and
  the OpenAI 1.x ``ChatCompletionMessageToolCall`` shape works,
  including dicts, attrs classes, dataclasses, and the official
  Pydantic models.
* **Pure / side-effect free.** This module never executes tool calls,
  never calls the OpenAI API, and never mutates the response object.
* **Replayable.** Every verdict is a :class:`Verdict` that can be
  serialized, stored, and replayed offline against the same builder.

Quickstart
----------

::

    import cordon
    from cordon.integrations.openai import ActionBuilder, check_response

    builder = ActionBuilder()

    @builder.tool("run_shell")
    def _shell(args: dict) -> cordon.Action:
        return cordon.Action(kind="shell", command=args["command"])

    @builder.tool("write_file")
    def _write(args: dict) -> cordon.Action:
        return cordon.Action(
            kind="file",
            changes={args["path"]: args["content"]},
        )

    guard = cordon.Guard.strict()

    response = client.chat.completions.create(model="gpt-4o", messages=..., tools=...)
    verdicts = check_response(response, builder=builder, guard=guard)

    for tcv in verdicts:
        if tcv.verdict.blocked:
            send_refusal_to_model(tcv.tool_call_id, tcv.verdict.top_reason())
        else:
            dispatch_tool(tcv.tool_call_id, tcv.tool_name, tcv.arguments)
"""

from __future__ import annotations

import functools
import json
import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from cordon.core.guard import BlockedAction, Guard
from cordon.core.types import Action, Verdict

logger = logging.getLogger(__name__)


# ─── Public types ─────────────────────────────────────────────────────────────


#: Type alias: a function that takes a tool's arguments dict and returns
#: a :class:`cordon.Action` describing what the tool would do, for probe
#: consumption. Builders are pure functions; they should not call APIs
#: or read state.
ActionFactory = Callable[[dict[str, Any]], Action]


@dataclass(frozen=True)
class ToolCallVerdict:
    """The verdict for a single tool call in an OpenAI response.

    Attributes:
        tool_call_id: OpenAI's per-call identifier (e.g. ``"call_abc123"``).
            Round-trip this back when sending the tool result message.
        tool_name: The function name from the assistant's tool call.
        arguments: The decoded JSON argument dict.
        action: The :class:`Action` constructed by the builder.
        verdict: The :class:`Verdict` returned by the guard.
    """

    tool_call_id: str
    tool_name: str
    arguments: dict[str, Any]
    action: Action
    verdict: Verdict

    @property
    def blocked(self) -> bool:
        return self.verdict.blocked

    @property
    def flagged(self) -> bool:
        return self.verdict.flagged

    @property
    def allowed(self) -> bool:
        return self.verdict.allowed


# ─── ActionBuilder registry ───────────────────────────────────────────────────


class ActionBuilder:
    """Registry mapping tool names → :class:`Action` constructors.

    Use either the decorator API or the imperative :meth:`register` API.

    Decorator::

        builder = ActionBuilder()

        @builder.tool("run_shell")
        def _(args: dict) -> Action:
            return Action(kind="shell", command=args["command"])

    Imperative::

        builder = ActionBuilder()
        builder.register("run_shell", lambda args: Action(kind="shell", command=args["command"]))

    Tools that have no registered builder are reported as
    :class:`UnknownTool` results when checked. By default they're
    treated as ``unknown_tool_policy="flag"``; you can change this to
    ``"allow"`` for permissive setups or ``"block"`` for strict ones.
    """

    def __init__(self, *, unknown_tool_policy: str = "flag") -> None:
        if unknown_tool_policy not in {"allow", "flag", "block"}:
            raise ValueError(
                "unknown_tool_policy must be one of 'allow', 'flag', 'block'"
            )
        self._factories: dict[str, ActionFactory] = {}
        self.unknown_tool_policy = unknown_tool_policy

    # Decorator API.
    def tool(self, name: str) -> Callable[[ActionFactory], ActionFactory]:
        """Decorator to register an action factory for a tool name."""

        def decorator(factory: ActionFactory) -> ActionFactory:
            self.register(name, factory)
            return factory

        return decorator

    # Imperative API.
    def register(self, name: str, factory: ActionFactory) -> None:
        if name in self._factories:
            logger.warning("ActionBuilder: replacing factory for tool %r", name)
        self._factories[name] = factory

    def has(self, name: str) -> bool:
        return name in self._factories

    def names(self) -> list[str]:
        return list(self._factories)

    def build(self, tool_name: str, arguments: dict[str, Any]) -> Action | None:
        """Construct an :class:`Action` for a tool call, or ``None`` if unknown."""
        factory = self._factories.get(tool_name)
        if factory is None:
            return None
        action = factory(arguments)
        if not isinstance(action, Action):
            raise TypeError(
                f"ActionBuilder factory for {tool_name!r} returned "
                f"{type(action).__name__}, expected cordon.Action"
            )
        return action


# ─── Response inspection ──────────────────────────────────────────────────────


def _coerce_attr(obj: Any, key: str, default: Any = None) -> Any:
    """Get ``obj.key`` or ``obj[key]`` — works for dicts, dataclasses, Pydantic."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _extract_tool_calls(response: Any) -> list[Any]:
    """Pull the assistant message's ``tool_calls`` list off any OpenAI-shaped response.

    Handles the OpenAI 1.x SDK shape (``response.choices[0].message.tool_calls``)
    as well as plain dicts (``response["choices"][0]["message"]["tool_calls"]``).
    Returns an empty list when no tool calls are present.
    """
    choices = _coerce_attr(response, "choices", [])
    if not choices:
        return []
    message = _coerce_attr(choices[0], "message")
    if message is None:
        return []
    tool_calls = _coerce_attr(message, "tool_calls", [])
    return list(tool_calls or [])


def _decode_tool_call(tool_call: Any) -> tuple[str, str, dict[str, Any]]:
    """Decode a single OpenAI tool call into ``(call_id, name, arguments)``.

    Raises :class:`ValueError` if the tool call is malformed.
    """
    call_id = _coerce_attr(tool_call, "id") or ""
    function = _coerce_attr(tool_call, "function")
    if function is None:
        raise ValueError(f"Tool call {call_id!r} has no 'function' field")
    name = _coerce_attr(function, "name")
    if not isinstance(name, str) or not name:
        raise ValueError(f"Tool call {call_id!r} has no function name")
    raw_args = _coerce_attr(function, "arguments", "{}")
    if isinstance(raw_args, dict):
        arguments = raw_args
    elif isinstance(raw_args, str):
        try:
            arguments = json.loads(raw_args) if raw_args.strip() else {}
        except json.JSONDecodeError as e:
            raise ValueError(
                f"Tool call {call_id!r} ({name}) has invalid JSON arguments: {e}"
            ) from e
    else:
        raise ValueError(
            f"Tool call {call_id!r} ({name}) has unsupported arguments type "
            f"{type(raw_args).__name__}"
        )
    return call_id, name, arguments


def _verdict_for_unknown_tool(
    tool_name: str, policy: str, action_id: str | None
) -> Verdict:
    """Build a synthetic verdict when a tool is not registered with the builder."""
    decision = policy if policy in {"allow", "flag", "block"} else "flag"
    explanation = (
        f"Tool {tool_name!r} has no ActionBuilder factory registered "
        f"(policy: {policy})"
    )
    return Verdict(
        decision=decision,  # type: ignore[arg-type]
        suspicion_score=0.0 if decision == "allow" else 0.5,
        probes_triggered=[],
        all_probes=[],
        explanation=explanation,
        action_id=action_id,
    )


def check_response(
    response: Any,
    *,
    builder: ActionBuilder,
    guard: Guard | None = None,
) -> list[ToolCallVerdict]:
    """Run ``guard`` against every tool call in an OpenAI response.

    Args:
        response: An OpenAI ``ChatCompletion``-shaped object — anything
            with ``choices[0].message.tool_calls`` works, including
            dicts.
        builder: An :class:`ActionBuilder` mapping tool names to
            :class:`Action` constructors.
        guard: The :class:`Guard` to use. Defaults to
            :meth:`Guard.default`.

    Returns:
        A list of :class:`ToolCallVerdict` records, one per tool call,
        in the order they appeared. If the response has no tool calls,
        returns an empty list.
    """
    guard = guard or Guard.default()
    verdicts: list[ToolCallVerdict] = []

    for tool_call in _extract_tool_calls(response):
        call_id, tool_name, arguments = _decode_tool_call(tool_call)
        action = builder.build(tool_name, arguments)

        if action is None:
            placeholder = Action(id=call_id or None, kind="tool",
                                 metadata={"tool_name": tool_name, "arguments": arguments})
            verdict = _verdict_for_unknown_tool(
                tool_name, builder.unknown_tool_policy, action_id=call_id or None
            )
            verdicts.append(
                ToolCallVerdict(
                    tool_call_id=call_id,
                    tool_name=tool_name,
                    arguments=arguments,
                    action=placeholder,
                    verdict=verdict,
                )
            )
            continue

        # Stamp the action_id with the tool_call_id when not set, so traces line up.
        if action.id is None and call_id:
            action = action.model_copy(update={"id": call_id})

        verdict = guard.check(action)
        verdicts.append(
            ToolCallVerdict(
                tool_call_id=call_id,
                tool_name=tool_name,
                arguments=arguments,
                action=action,
                verdict=verdict,
            )
        )

    return verdicts


# ─── Decorator wrapper ────────────────────────────────────────────────────────


def protect_tool(
    *,
    name: str,
    builder: ActionBuilder,
    guard: Guard | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator: protect a Python function that implements an OpenAI tool.

    The wrapped function is expected to be called with keyword arguments
    matching the tool's JSON schema (the standard pattern in OpenAI tool
    dispatch loops). On call, Cordon constructs an :class:`Action` via
    the builder, runs the guard, and either calls the underlying
    function (allow / flag) or raises :class:`BlockedAction` (block).

    Example::

        builder = ActionBuilder()

        @builder.tool("run_shell")
        def _(args: dict) -> Action:
            return Action(kind="shell", command=args["command"])

        @protect_tool(name="run_shell", builder=builder, guard=Guard.strict())
        def run_shell(command: str) -> str:
            return subprocess.check_output(command, shell=True).decode()
    """
    guard = guard or Guard.default()

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            arguments = dict(kwargs)
            # If positional args are passed, we can't map them without knowing
            # the schema — fall back to a single "args" key so the builder
            # can decide how to interpret it.
            if args and not kwargs:
                arguments = {"args": args[0] if len(args) == 1 else list(args)}

            action = builder.build(name, arguments)
            if action is None:
                logger.warning(
                    "protect_tool: tool %r has no builder factory; "
                    "falling back to unknown_tool_policy=%r",
                    name, builder.unknown_tool_policy,
                )
                if builder.unknown_tool_policy == "block":
                    placeholder = Action(kind="tool",
                                         metadata={"tool_name": name, "arguments": arguments})
                    raise BlockedAction(_verdict_for_unknown_tool(
                        name, "block", action_id=None,
                    ))
                return func(*args, **kwargs)

            verdict = guard.check(action)
            if verdict.blocked:
                raise BlockedAction(verdict)
            return func(*args, **kwargs)

        # Expose the underlying function for testing / introspection.
        wrapper.__wrapped__ = func  # type: ignore[attr-defined]
        return wrapper

    return decorator


__all__ = [
    "ActionBuilder",
    "ActionFactory",
    "ToolCallVerdict",
    "check_response",
    "protect_tool",
]
