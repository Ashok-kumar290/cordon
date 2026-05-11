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

import json
from typing import Any

from cordon.core.guard import Guard
from cordon.core.types import Action

from cordon.integrations._common import (
    ActionBuilder,
    ActionFactory,
    ToolCallVerdict,
    coerce_attr,
    protect_tool,
    verdict_for_unknown_tool,
)


# ─── OpenAI-specific response inspection ──────────────────────────────────────


def _extract_tool_calls(response: Any) -> list[Any]:
    """Pull the assistant message's ``tool_calls`` list off any OpenAI-shaped response.

    Handles the OpenAI 1.x SDK shape (``response.choices[0].message.tool_calls``)
    as well as plain dicts. Returns an empty list when no tool calls are
    present.
    """
    choices = coerce_attr(response, "choices", [])
    if not choices:
        return []
    message = coerce_attr(choices[0], "message")
    if message is None:
        return []
    tool_calls = coerce_attr(message, "tool_calls", [])
    return list(tool_calls or [])


def _decode_tool_call(tool_call: Any) -> tuple[str, str, dict[str, Any]]:
    """Decode a single OpenAI tool call into ``(call_id, name, arguments)``."""
    call_id = coerce_attr(tool_call, "id") or ""
    function = coerce_attr(tool_call, "function")
    if function is None:
        raise ValueError(f"Tool call {call_id!r} has no 'function' field")
    name = coerce_attr(function, "name")
    if not isinstance(name, str) or not name:
        raise ValueError(f"Tool call {call_id!r} has no function name")
    raw_args = coerce_attr(function, "arguments", "{}")
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
        in the order they appeared.
    """
    guard = guard or Guard.default()
    verdicts: list[ToolCallVerdict] = []

    for tool_call in _extract_tool_calls(response):
        call_id, tool_name, arguments = _decode_tool_call(tool_call)
        action = builder.build(tool_name, arguments)

        if action is None:
            placeholder = Action(id=call_id or None, kind="tool",
                                 metadata={"tool_name": tool_name, "arguments": arguments})
            verdict = verdict_for_unknown_tool(
                tool_name, builder.unknown_tool_policy, action_id=call_id or None
            )
            verdicts.append(ToolCallVerdict(
                tool_call_id=call_id, tool_name=tool_name, arguments=arguments,
                action=placeholder, verdict=verdict,
            ))
            continue

        if action.id is None and call_id:
            action = action.model_copy(update={"id": call_id})

        verdict = guard.check(action)
        verdicts.append(ToolCallVerdict(
            tool_call_id=call_id, tool_name=tool_name, arguments=arguments,
            action=action, verdict=verdict,
        ))

    return verdicts


__all__ = [
    "ActionBuilder",
    "ActionFactory",
    "ToolCallVerdict",
    "check_response",
    "protect_tool",
]
