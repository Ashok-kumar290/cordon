"""Shared types and helpers for vendor agent-framework integrations.

The pieces of an integration that are *not* SDK-specific live here:

* :class:`ActionBuilder` — registry mapping tool names → ``Action`` factories.
* :class:`ToolCallVerdict` — per-tool-call verdict record.
* :func:`protect_tool` — decorator wrapping a Python tool implementation.
* :func:`coerce_attr` — small helper for duck-typed attribute access.
* :func:`verdict_for_unknown_tool` — synthetic verdict used when a tool
  name has no registered builder factory.

The OpenAI and Anthropic integrations both consume these. The only
piece each vendor must implement is a small *extractor* + *decoder* pair
that converts the vendor's response shape into ``(call_id, tool_name,
arguments)`` tuples.
"""

from __future__ import annotations

import functools
import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from cordon.core.guard import BlockedAction, Guard
from cordon.core.types import Action, Verdict

logger = logging.getLogger(__name__)


# ─── Public types ─────────────────────────────────────────────────────────────


#: A function that takes a tool's arguments dict and returns an
#: :class:`Action`. Builders are pure: they don't call APIs or read state.
ActionFactory = Callable[[dict[str, Any]], Action]


@dataclass(frozen=True)
class ToolCallVerdict:
    """Verdict for a single tool / tool-use call from a model response.

    Attributes:
        tool_call_id: The vendor's per-call id (``call_…`` for OpenAI,
            ``toolu_…`` for Anthropic). Echo this back when sending the
            tool result message to keep the conversation in sync.
        tool_name: The function / tool name the model wants to invoke.
        arguments: The decoded argument dict.
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

    Decorator API::

        builder = ActionBuilder()

        @builder.tool("run_shell")
        def _(args: dict) -> Action:
            return Action(kind="shell", command=args["command"])

    Imperative API::

        builder = ActionBuilder()
        builder.register("run_shell", lambda a: Action(kind="shell", command=a["command"]))

    Tools without a registered builder are reported as :class:`Verdict`
    records with the configured ``unknown_tool_policy`` (default
    ``"flag"``).
    """

    def __init__(self, *, unknown_tool_policy: str = "flag") -> None:
        if unknown_tool_policy not in {"allow", "flag", "block"}:
            raise ValueError(
                "unknown_tool_policy must be one of 'allow', 'flag', 'block'"
            )
        self._factories: dict[str, ActionFactory] = {}
        self.unknown_tool_policy = unknown_tool_policy

    def tool(self, name: str) -> Callable[[ActionFactory], ActionFactory]:
        """Decorator to register a factory for a tool name."""

        def decorator(factory: ActionFactory) -> ActionFactory:
            self.register(name, factory)
            return factory

        return decorator

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


# ─── Helpers shared across vendor extractors ──────────────────────────────────


def coerce_attr(obj: Any, key: str, default: Any = None) -> Any:
    """Get ``obj.key`` or ``obj[key]`` — works for dicts, dataclasses, Pydantic models."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def verdict_for_unknown_tool(
    tool_name: str, policy: str, action_id: str | None
) -> Verdict:
    """Build a synthetic :class:`Verdict` when a tool is not registered."""
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


# ─── Decorator: protect a tool implementation function ────────────────────────


def protect_tool(
    *,
    name: str,
    builder: ActionBuilder,
    guard: Guard | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator: protect a Python function that implements a tool.

    On call, Cordon constructs an :class:`Action` via the builder, runs
    the guard, and either calls the underlying function (allow / flag)
    or raises :class:`BlockedAction` (block).

    The wrapped function is expected to be called with keyword arguments
    matching the tool's JSON schema (this is the standard tool-dispatch
    pattern for both OpenAI and Anthropic). Positional args are bundled
    into an ``"args"`` key, which the builder can decide how to interpret.

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
                    raise BlockedAction(verdict_for_unknown_tool(
                        name, "block", action_id=None,
                    ))
                return func(*args, **kwargs)

            verdict = guard.check(action)
            if verdict.blocked:
                raise BlockedAction(verdict)
            return func(*args, **kwargs)

        wrapper.__wrapped__ = func  # type: ignore[attr-defined]
        return wrapper

    return decorator


__all__ = [
    "ActionBuilder",
    "ActionFactory",
    "ToolCallVerdict",
    "coerce_attr",
    "verdict_for_unknown_tool",
    "protect_tool",
]
