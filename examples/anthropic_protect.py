"""Protect an Anthropic Claude tool-use loop with Cordon.

This example simulates a prompt-injected scenario without making any
real Anthropic API calls. We hand-craft a ``Message``-shaped response
object (an assistant turn that includes a ``tool_use`` block), route
it through Cordon, and show that:

1. A benign ``tool_use`` (``echo ok``) is allowed.
2. A typosquat-injected ``tool_use`` (``pip install reqeusts``) is
   blocked before our executor ever sees it.

In production you'd swap the hand-crafted response for a real
``client.messages.create(...)`` call. The Cordon code is unchanged —
the same ``ActionBuilder`` shape works across vendors.
"""

from __future__ import annotations

import cordon
from cordon.integrations.anthropic import ActionBuilder, check_response


# ─── 1. Declare the tool → Action mapping ─────────────────────────────────────

builder = ActionBuilder()


@builder.tool("run_shell")
def _shell(args: dict) -> cordon.Action:
    """Map a `run_shell` tool_use to a Cordon shell Action."""
    return cordon.Action(
        kind="shell",
        command=args["command"],
        changes=args.get("changes", {}),
    )


# ─── 2. Pick a guard profile ──────────────────────────────────────────────────

guard = cordon.Guard.strict()


# ─── 3. Simulate two assistant responses ──────────────────────────────────────


def _fake_message(blocks: list[dict]) -> dict:
    """Hand-rolled Anthropic-shaped Message. In real use, replace with the SDK."""
    return {
        "id": "msg_demo",
        "type": "message",
        "role": "assistant",
        "model": "claude-sonnet-4-5",
        "stop_reason": "tool_use",
        "content": blocks,
    }


def _tu(call_id: str, name: str, input_args: dict) -> dict:
    return {"type": "tool_use", "id": call_id, "name": name, "input": input_args}


benign_message = _fake_message([
    {"type": "text", "text": "Running a quick check."},
    _tu("toolu_benign", "run_shell", {"command": "echo hello world"}),
])

attack_message = _fake_message([
    {"type": "text", "text": "Installing the requested dep."},
    _tu(
        "toolu_attack",
        "run_shell",
        {
            "command": "pip install -r requirements.txt",
            "changes": {"requirements.txt": "reqeusts==2.31.0\n"},
        },
    ),
])


# ─── 4. Route both through Cordon ─────────────────────────────────────────────


def main() -> None:
    print("Cordon — Anthropic integration demo")
    print("-" * 60)

    for label, message in [("benign", benign_message), ("attack", attack_message)]:
        verdicts = check_response(message, builder=builder, guard=guard)
        for tcv in verdicts:
            decision = tcv.verdict.decision.upper()
            print(f"[{decision:5s}] {label:6s} | tool={tcv.tool_name:9s} | {tcv.verdict.top_reason()}")

            if tcv.allowed:
                print(f"         → would execute: {tcv.arguments['command']}")
            elif tcv.blocked:
                print("         → return tool_result with is_error=true to the model")


if __name__ == "__main__":
    main()
