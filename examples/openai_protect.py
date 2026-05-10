"""Protect an OpenAI-style coding agent with Cordon.

This example simulates a prompt-injected scenario without making any
real OpenAI API calls. We hand-craft a ``ChatCompletion``-shaped
response object, route it through Cordon, and show that:

1.  A benign tool call (``echo ok``) is allowed.
2.  A typosquat-injected tool call (``pip install reqeusts``) is
    blocked before our executor ever sees it.

In production you'd swap the hand-crafted response for the real
``client.chat.completions.create(...)`` call. The Cordon code is
unchanged.
"""

from __future__ import annotations

import json

import cordon
from cordon.integrations.openai import ActionBuilder, check_response


# ─── 1. Declare the tool → Action mapping ─────────────────────────────────────

builder = ActionBuilder()


@builder.tool("run_shell")
def _shell(args: dict) -> cordon.Action:
    """Map a `run_shell` call to a Cordon shell Action."""
    return cordon.Action(
        kind="shell",
        command=args["command"],
        changes=args.get("changes", {}),
    )


# ─── 2. Pick a guard profile ──────────────────────────────────────────────────

guard = cordon.Guard.strict()


# ─── 3. Simulate two assistant responses ──────────────────────────────────────


def _fake_response(tool_calls: list[dict]) -> dict:
    """Hand-rolled OpenAI-shaped response. In real use, replace with the SDK."""
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


def _tc(call_id: str, name: str, args: dict) -> dict:
    return {
        "id": call_id,
        "type": "function",
        "function": {"name": name, "arguments": json.dumps(args)},
    }


benign_response = _fake_response([
    _tc("call_benign", "run_shell", {"command": "echo hello world"}),
])

attack_response = _fake_response([
    _tc(
        "call_attack",
        "run_shell",
        {
            "command": "pip install -r requirements.txt",
            "changes": {"requirements.txt": "reqeusts==2.31.0\n"},
        },
    ),
])


# ─── 4. Route both through Cordon ─────────────────────────────────────────────


def main() -> None:
    print("Cordon — OpenAI integration demo")
    print("-" * 60)

    for label, response in [("benign", benign_response), ("attack", attack_response)]:
        verdicts = check_response(response, builder=builder, guard=guard)
        for tcv in verdicts:
            decision = tcv.verdict.decision.upper()
            print(f"[{decision:5s}] {label:6s} | tool={tcv.tool_name:9s} | {tcv.verdict.top_reason()}")

            # In production, this is where you'd dispatch the tool call.
            if tcv.allowed:
                print(f"         → would execute: {tcv.arguments['command']}")
            elif tcv.blocked:
                print("         → refuse and report back to the model")


if __name__ == "__main__":
    main()
