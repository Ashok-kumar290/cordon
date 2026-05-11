"""Anthropic integration — guard ``tool_use`` blocks before they execute.

The Anthropic Messages API returns a ``Message`` with a ``content``
list of typed blocks. When the model wants to call a tool, one of
those blocks has ``type="tool_use"`` and carries an ``id``, a
``name``, and an already-decoded ``input`` dict. Your application
dispatches the tool and replies with a ``tool_result`` block on the
next turn — that's the seam where Cordon plugs in.

Three entry points, mirroring the OpenAI integration:

1. :class:`ActionBuilder` — registry mapping tool names to
   :class:`Action` constructors. Same class as
   :mod:`cordon.integrations.openai`; you can share a single builder
   between vendors.

2. :func:`check_response` — given an Anthropic ``Message``-shaped
   response and a builder, run the configured guard against every
   ``tool_use`` block and return a list of :class:`ToolCallVerdict`
   records.

3. :func:`protect_tool` — decorator wrapping a Python tool implementation.

Design rules
------------

* **No runtime dependency on the ``anthropic`` package.** We duck-type
  the response shape: anything with ``.content`` (a list of objects /
  dicts each with ``type`` and either attribute or item access) works.
  This includes the official Pydantic ``Message`` model, dicts,
  dataclasses, and attrs classes.
* **Pure / side-effect free.** Never executes tool calls, never calls
  the Anthropic API, never mutates the response.
* **Replayable.** Verdicts serialize cleanly to JSON for traces.

Quickstart
----------

::

    import cordon
    from cordon.integrations.anthropic import ActionBuilder, check_response

    builder = ActionBuilder()

    @builder.tool("run_shell")
    def _shell(args: dict) -> cordon.Action:
        return cordon.Action(kind="shell", command=args["command"])

    guard = cordon.Guard.strict()

    message = client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=1024,
        tools=[...],
        messages=[...],
    )
    verdicts = check_response(message, builder=builder, guard=guard)

    for tcv in verdicts:
        if tcv.verdict.blocked:
            send_tool_result_error(tcv.tool_call_id, tcv.verdict.top_reason())
        else:
            dispatch_tool(tcv.tool_call_id, tcv.tool_name, tcv.arguments)
"""

from __future__ import annotations

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


# ─── Anthropic-specific response inspection ──────────────────────────────────


def _extract_tool_uses(response: Any) -> list[Any]:
    """Pull the ``tool_use`` content blocks off any Anthropic-shaped Message.

    Handles the ``anthropic`` SDK ``Message`` shape (``response.content``
    is a list of typed blocks) as well as plain dicts (``response["content"]``).
    Returns an empty list when no tool-use blocks are present.
    """
    content = coerce_attr(response, "content", [])
    if not content:
        return []
    blocks: list[Any] = []
    for block in content:
        block_type = coerce_attr(block, "type")
        if block_type == "tool_use":
            blocks.append(block)
    return blocks


def _decode_tool_use(block: Any) -> tuple[str, str, dict[str, Any]]:
    """Decode a single tool_use block into ``(call_id, name, arguments)``.

    Anthropic's ``input`` field is already a decoded JSON object — there
    is no string-encoded form to parse, unlike OpenAI. We still defend
    against weird shapes (None, list) for safety.

    Raises :class:`ValueError` if the block is malformed.
    """
    call_id = coerce_attr(block, "id") or ""
    name = coerce_attr(block, "name")
    if not isinstance(name, str) or not name:
        raise ValueError(f"tool_use block {call_id!r} has no name")

    raw_input = coerce_attr(block, "input", {})
    if raw_input is None:
        arguments: dict[str, Any] = {}
    elif isinstance(raw_input, dict):
        arguments = raw_input
    else:
        raise ValueError(
            f"tool_use block {call_id!r} ({name}) has unsupported input type "
            f"{type(raw_input).__name__}; expected dict"
        )

    return call_id, name, arguments


def check_response(
    response: Any,
    *,
    builder: ActionBuilder,
    guard: Guard | None = None,
) -> list[ToolCallVerdict]:
    """Run ``guard`` against every ``tool_use`` block in an Anthropic Message.

    Args:
        response: An Anthropic ``Message``-shaped object. Anything with
            a ``content`` list whose entries have ``type``, ``id``,
            ``name``, ``input`` works — official SDK Pydantic models,
            dicts, dataclasses.
        builder: An :class:`ActionBuilder` mapping tool names to
            :class:`Action` constructors.
        guard: The :class:`Guard` to use. Defaults to
            :meth:`Guard.default`.

    Returns:
        A list of :class:`ToolCallVerdict` records, one per ``tool_use``
        block in the response, in the order they appeared. If the
        message contains no ``tool_use`` blocks, returns ``[]``.
    """
    guard = guard or Guard.default()
    verdicts: list[ToolCallVerdict] = []

    for block in _extract_tool_uses(response):
        call_id, tool_name, arguments = _decode_tool_use(block)
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

        # Stamp the action_id with the block id when not set, so traces line up.
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
