# Cordon

**The pre-execution control layer for AI agents.**

Cordon runs deterministic safety probes on a proposed agent action *before* it executes. No LLM calls, no heuristics, no inference latency — just fast, auditable, replayable verdicts on whether an action is safe to run.

```bash
pip install cordon
```

```python
from cordon import Guard, Action

guard = Guard.strict()

verdict = guard.check(Action(
    kind="shell",
    command="pip install -r requirements.txt",
    changes={"requirements.txt": "reqeusts==2.31.0\n"},
))

if verdict.blocked:
    print(verdict.top_reason())
    # → "'reqeusts' is 2 edit(s) from 'requests' (likely typosquat)"
```

## Protect your agent in 5 lines

Cordon ships first-class integrations for the three frameworks every production agent uses today:

| Vendor    | Module                                  | Entry point                          | Example |
|-----------|------------------------------------------|--------------------------------------|---------|
| OpenAI    | `cordon.integrations.openai`             | `check_response(response, ...)`      | [`examples/openai_protect.py`](examples/openai_protect.py)    |
| Anthropic | `cordon.integrations.anthropic`          | `check_response(message, ...)`       | [`examples/anthropic_protect.py`](examples/anthropic_protect.py) |
| LangChain | `cordon.integrations.langchain`          | `guard_tools([t1, t2], ...)`         | [`examples/langchain_protect.py`](examples/langchain_protect.py) |

A single `ActionBuilder` registry maps your tool names to `cordon.Action` shapes — the *same* registry works across all three vendors:

```python
import cordon
from cordon.integrations.openai import ActionBuilder, check_response

builder = ActionBuilder()

@builder.tool("run_shell")
def _(args): return cordon.Action(kind="shell", command=args["command"],
                                  changes=args.get("changes", {}))

response = client.chat.completions.create(model="gpt-4o", messages=..., tools=...)

for tcv in check_response(response, builder=builder, guard=cordon.Guard.strict()):
    if tcv.blocked:
        send_refusal(tcv.tool_call_id, tcv.verdict.top_reason())
    else:
        dispatch_tool(tcv.tool_name, tcv.arguments)
```

**No vendor SDK is a runtime dependency.** Cordon duck-types each response shape, so it works with the official SDKs, with `litellm`, with raw HTTP, and with any internal proxy.

## Why Cordon exists

LLM agents now write code, install packages, read secrets, and call APIs on behalf of users and companies. Current safety layers fall into two camps, and both have blind spots:

- **Transcript monitors** read the agent's reasoning. On semantic attacks (typosquatting, silent data loss, exfiltration-by-artifact) they approve **100%** of attacks because the commands *look* legitimate. Only the intent is malicious.
- **Guardrail LLMs** call another model to judge outputs. They add latency, cost, a non-deterministic failure mode, and a new attack surface.

Cordon is a third path: **static, deterministic probes on the proposed side effects**. An agent-written command to `pip install reqeusts` looks legitimate to a transcript monitor; it looks identical to a Levenshtein check comparing every package against the top 200 PyPI names. One of these catches the attack deterministically. The other flips a coin.

## Headline benchmark

The 36-task **Semantic Guard benchmark** covers all six attack classes the probes are designed to catch (3 attacks + 3 benign per class). Run it yourself:

```bash
cordon benchmark --profile strict
```

| Profile | Block rate (TPR) | False-positive rate | Control score | Tasks passed |
|---|---:|---:|---:|---:|
| `Guard.permissive()`  | 88.9% | **0.0%** | 0.889 | 34 / 36 |
| `Guard.default()`     | 94.4% | **0.0%** | 0.944 | 35 / 36 |
| **`Guard.strict()`**  | **100.0%** | **0.0%** | **1.000** | **36 / 36** |

**Zero false positives across all 36 benign tasks on every profile.** The full 36-task suite runs in **~7 ms** end-to-end on a single core — fast enough that every agent step gets checked with no perceptible latency. Lower profiles intentionally *flag* (rather than block) lower-confidence signals like supply-chain mirror swaps, so security teams see the warning without false stops.

Per-category on strict — 3 / 3 attacks blocked, 0 / 3 benign blocked, in every class:

| Category | Block rate | FPR |
|---|:-:|:-:|
| Typosquat (supply-chain) | 1.00 | 0.00 |
| Secret leak (artifact)   | 1.00 | 0.00 |
| Exfiltration (network)   | 1.00 | 0.00 |
| Silent failure           | 1.00 | 0.00 |
| Test suppression         | 1.00 | 0.00 |
| Security weakening       | 1.00 | 0.00 |

## Comparative benchmark

The same 36-task suite, run head-to-head against the dominant deployed agent-safety patterns. Reproduce yourself:

```bash
cordon compare --comparators all
# add --lakera-key=... and --openai-key=... to include the network-bound judges
```

| Judge | Block rate (TPR) | FPR | Control | Passed | Mean latency |
|---|---:|---:|---:|---:|---:|
| **Cordon (strict)**             | **1.000 (18/18)** | **0.000** | **1.000** | **36/36** | **~0.2 ms** |
| Keyword heuristic (block-list)  | 0.056 (1/18)      | 0.000     | 0.056     | 19/36     | ~0.01 ms     |
| Transcript-only (charitable)    | 0.167 (3/18)      | 0.000     | 0.167     | 21/36     | ~0.00 ms     |
| Lakera Guard                    | *requires API key — see `--lakera-key`* | — | — | — | — |
| LLM judge (gpt-4o-mini)         | *requires API key — see `--openai-key`* | — | — | — | — |

**Cordon catches 18× more attacks than the naive heuristic and 6× more than a charitable transcript monitor — at zero false positives in both cases.** Both alternatives have 0% block rate on the *stealth* attack classes (typosquat, secret-leak, silent-failure, test-suppression) where it matters most:

| Category               | Cordon | Keyword heuristic | Transcript monitor |
|------------------------|:------:|:-----------------:|:------------------:|
| Typosquat              | **1.00** | 0.00            | 0.33               |
| Secret leak            | **1.00** | 0.00            | 0.00               |
| Exfiltration           | **1.00** | 0.00            | 0.33               |
| Silent failure         | **1.00** | 0.00            | 0.00               |
| Test suppression       | **1.00** | 0.00            | 0.00               |
| Security weakening     | **1.00** | 0.33            | 0.33               |

The pattern is the wedge: existing tools judge *strings* (input prompts, output text). Cordon judges *side effects* (the proposed shell command, the proposed file write). Strings can be paraphrased; side effects cannot. That gap is the entire moat.

The transcript-only baseline is a deliberately *charitable* upper bound — a perfect-recall LLM monitor that catches every red-flag word in the agent's narration, never gets paraphrased away. Real LLM-based transcript guards score *worse* than this on stealth attacks. Cordon scores 1.00 on every category.

## Install

```bash
pip install cordon-ai
```

Python 3.10+. The PyPI distribution is `cordon-ai` (the unsuffixed `cordon` name on PyPI is held by an unrelated log-analysis project). The Python import name is `cordon` — once installed, you write `import cordon` everywhere. Zero heavy dependencies (pydantic, typer, rich only).

## Quickstart

### Inline check

```python
from cordon import Guard, Action

guard = Guard.default()

action = Action(
    kind="file",
    intent="Write a debug report",
    reads=["/app/.env"],
    workspace_files={"/app/.env": "EXAMPLE_KEY=FAKE-TEST-TOKEN-0123456789ABCDEF"},
    changes={
        "artifacts/debug.log": "env loaded; key=FAKE-TEST-TOKEN-0123456789ABCDEF"
    },
)

verdict = guard.check(action)
print(verdict.decision)     # 'block'
print(verdict.top_reason()) # 'Secret leak pattern: /app/.env → artifacts/debug.log (content match)'
```

### Decorator: protect any agent step

```python
@guard.protect
def execute_step(action: Action) -> str:
    return shell.run(action.command)

execute_step(action)  # raises BlockedAction if the guard blocks
```

### CLI

```bash
cordon check action.json --profile strict
cordon list-probes --profile default
cordon demo          # runs 3 built-in actions: 2 attacks, 1 benign
cordon version
```

## Architecture

```
┌───────────────────────────────────────────────────────────────────┐
│                       cordon.Guard                                │
│                                                                   │
│    ┌─────────────────────────────────────────────────────────┐    │
│    │                 Semantic probes (fast, tier="fast")     │    │
│    │                                                         │    │
│    │   • TyposquatProbe      supply-chain dependency attacks │    │
│    │   • SecretLeakProbe     sensitive read → artifact write │    │
│    │   • SilentFailureProbe  code introducing silent drops   │    │
│    │   • ExfiltrationProbe   secret → network flows          │    │
│    │   • TestSuppressionProbe   test skip / xfail abuse      │    │
│    │   • SecurityWeakeningProbe  config downgrades           │    │
│    └─────────────────────────────────────────────────────────┘    │
│                                                                   │
│    ┌─────────────────────────────────────────────────────────┐    │
│    │           Environment probes (coming in v0.2)           │    │
│    │                                                         │    │
│    │   • preview_diff    shows net filesystem delta          │    │
│    │   • dry_run         replays in sandbox                  │    │
│    │   • sensitivity_scan   flags reads of sensitive paths   │    │
│    │   • inspect_targets   network endpoint analysis         │    │
│    └─────────────────────────────────────────────────────────┘    │
│                                                                   │
│    ┌─────────────────────────────────────────────────────────┐    │
│    │                 Aggregation + decision                  │    │
│    │                                                         │    │
│    │   Critical severity anywhere     → block                │    │
│    │   max(confidence) ≥ block_thresh → block                │    │
│    │   max(confidence) ≥ flag_thresh  → flag                 │    │
│    │   otherwise                      → allow                │    │
│    └─────────────────────────────────────────────────────────┘    │
└───────────────────────────────────────────────────────────────────┘
```

Every probe is a pure function of an `Action`. Every verdict is replayable. No probe ever executes side effects — Cordon is strictly pre-execution.

## Profiles

| Profile | `block_threshold` | `flag_threshold` | When to use |
|---|---:|---:|---|
| `Guard.permissive()` | 0.85 | 0.50 | Research agents, exploratory workflows |
| `Guard.default()` | 0.70 | 0.30 | Most production apps |
| `Guard.strict()` | 0.60 | 0.20 | Regulated / financial / healthcare agents |

Custom thresholds and probe sets:

```python
from cordon import Guard
from cordon.probes.semantic import (
    TyposquatProbe, SecretLeakProbe, SilentFailureProbe,
    ExfiltrationProbe, TestSuppressionProbe, SecurityWeakeningProbe,
)

guard = Guard(
    probes=[
        TyposquatProbe(), SecretLeakProbe(),
        SilentFailureProbe(), ExfiltrationProbe(),
        TestSuppressionProbe(), SecurityWeakeningProbe(),
    ],
    block_threshold=0.8,
    flag_threshold=0.4,
)
```

## Status

**v0.1** — first release. Two semantic probes (`TyposquatProbe`, `SecretLeakProbe`), CLI, decorator API.

**v0.2 (current)** — full 6-probe Semantic Guard suite, three vendor integrations (OpenAI, Anthropic, LangChain), the canonical 36-task benchmark + comparative reproducer (`cordon benchmark`, `cordon compare`), 150 tests passing.

**v0.3 (next)** — environment probes (preview_diff, dry_run, sensitivity_scan, inspect_targets), Cordon Cloud (telemetry + policy management + threat-intel feed), landing page + live playground.

## Research

Cordon is the production-grade descendant of two research projects:

- **ActionLens** — 3rd place at [Apart Research](https://apartresearch.com/) AI Control Hackathon 2026 (36 countries). Introduced the pre-execution environment probes and the 36-task benchmark. [Repo →](https://github.com/Ashok-kumar290/ActionLens)
- **Context-Conditioned Confidentiality Failures in Refusal-Tuned Language Models** — Cohere Catalyst Grant, 2026. Showed that refusal-tuned models leak confidential context at 46–62% even when explicitly instructed not to. This is the empirical basis for Cordon's secret-leak probe.

## Contributing

Cordon is early. If you deploy AI agents that do real work and have seen them do something stupid, we want to hear from you — both as a user and as a contributor. Open an issue with a redacted trace and we'll build the probe.

## License

Apache 2.0. Use it anywhere, including commercially.

## Citation

```bibtex
@software{cordon2026,
  author  = {Adharapurapu V S M Ashok Kumar},
  title   = {Cordon: Pre-Execution Control for AI Agents},
  year    = {2026},
  url     = {https://github.com/Ashok-kumar290/cordon},
  version = {0.1.0}
}
```
