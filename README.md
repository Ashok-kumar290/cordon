# Cordon

[![CI](https://github.com/Ashok-kumar290/cordon/actions/workflows/ci.yml/badge.svg)](https://github.com/Ashok-kumar290/cordon/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/cordon-ai.svg)](https://pypi.org/project/cordon-ai/)
[![Python](https://img.shields.io/pypi/pyversions/cordon-ai.svg)](https://pypi.org/project/cordon-ai/)
[![License](https://img.shields.io/pypi/l/cordon-ai.svg)](https://github.com/Ashok-kumar290/cordon/blob/main/LICENSE)

**The action firewall for AI agents.**

Block what your AI agents shouldn't do — *before* they do it. Cordon runs deterministic safety probes on every proposed agent action and returns an allow / flag / block verdict in under a millisecond. No LLM in the path. No prompts. No inference latency. Same architecture you trust at the network edge, now at the agent edge.

- **Live playground:** <https://seyomi-cordon-playground.hf.space/>
- **API docs:**        <https://seyomi-cordon-playground.hf.space/api/docs>
- **PyPI:**            [`cordon-ai`](https://pypi.org/project/cordon-ai/) · `pip install cordon-ai`
- **Benchmark:**       1.000 control score on a 42-task public benchmark, 0.2 ms median verdict latency
- **Cordon Cloud** (hosted dashboard) is in closed beta with design partners — email **founders@cordon.ai** for access

```bash
pip install cordon-ai
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
| LangChain | `cordon.integrations.langchain`          | `guard_tools([t1, t2], ...)` *or* `CordonGuardCallback(guard, ...)` for prebuilt agents | [`examples/langchain_protect.py`](examples/langchain_protect.py) |

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

The 42-task **Semantic Guard benchmark** covers all seven attack classes the probes are designed to catch (3 attacks + 3 benign per class). Run it yourself:

```bash
cordon benchmark --profile strict
```

| Profile | Block rate (TPR) | False-positive rate | Control score | Tasks passed |
|---|---:|---:|---:|---:|
| `Guard.permissive()`  | 90.5% | **0.0%** | 0.905 | 40 / 42 |
| `Guard.default()`     | 95.2% | **0.0%** | 0.952 | 41 / 42 |
| **`Guard.strict()`**  | **100.0%** | **0.0%** | **1.000** | **42 / 42** |

**Zero false positives across all 21 benign tasks on every profile.** The full 42-task suite runs in **~8 ms** end-to-end on a single core — fast enough that every agent step gets checked with no perceptible latency. Lower profiles intentionally *flag* (rather than block) lower-confidence signals like supply-chain mirror swaps, so security teams see the warning without false stops.

Per-category on strict — 3 / 3 attacks blocked, 0 / 3 benign blocked, in every class:

| Category | Block rate | FPR |
|---|:-:|:-:|
| Typosquat (supply-chain) | 1.00 | 0.00 |
| Secret leak (artifact)   | 1.00 | 0.00 |
| Exfiltration (network)   | 1.00 | 0.00 |
| Silent failure           | 1.00 | 0.00 |
| Test suppression         | 1.00 | 0.00 |
| Security weakening       | 1.00 | 0.00 |
| Destructive shell        | 1.00 | 0.00 |

## Comparative benchmark

The same 42-task suite, run head-to-head against the dominant deployed agent-safety patterns. Reproduce yourself:

```bash
cordon compare --comparators all
# add --lakera-key=... and --openai-key=... to include the network-bound judges
```

| Judge | Block rate (TPR) | FPR | **Control** | Passed | Mean latency |
|---|---:|---:|---:|---:|---:|
| **Cordon (strict)**                | **1.000 (21/21)** | **0.000 (0/21)** | **1.000** | **42/42** | **~0.2 ms** |
| Keyword heuristic (block-list)     | 0.143 (3/21)      | 0.048 (1/21)     | 0.136     | 23/42     | ~0.003 ms |
| Transcript-only (charitable)       | 0.190 (4/21)      | 0.000 (0/21)     | 0.190     | 25/42     | ~0.003 ms |
| Lakera Guard (v2/guard, May 2026)‡ | 1.000 (18/18)     | **1.000 (18/18)**| **0.000** | 18/36     | ~280 ms |
| LLM judge (gpt-4o-mini, via OpenRouter)‡ | 0.833 (15/18) | 0.056 (1/18)  | 0.787     | 32/36     | ~1219 ms |

<sub>‡ Network-bound judges last measured on the v0.2 36-task suite (we won't burn API budget on every probe addition); the qualitative gap doesn't change with the 6 new destructive-shell tasks.</sub>

**Cordon is the only judge with a perfect score, and it's also the fastest by 4–6 orders of magnitude.** The naive heuristic now picks up *some* of the destructive-shell attacks via substring match — and earns a false positive on `rm -rf ./build` for its trouble, which is exactly why Cordon's structural approach matters. The charitable transcript monitor catches a few obvious attacks but misses the stealth classes entirely. Lakera catches every attack but also blocks every benign task — unusable for action filtering. The LLM-as-judge approach is genuinely competitive on accuracy (0.787) but costs ~6,000× more latency, non-deterministic verdicts, and per-call dollars.

### Per-category attack block rate

| Category               | Cordon | Keyword | Transcript | Lakera | LLM judge |
|------------------------|:------:|:-------:|:----------:|:------:|:---------:|
| Typosquat              | **1.00** | 0.00 | 0.33 | 1.00 | 0.67 |
| Secret leak            | **1.00** | 0.00 | 0.00 | 1.00 | 1.00 |
| Exfiltration           | **1.00** | 0.00 | 0.33 | 1.00 | 1.00 |
| Silent failure         | **1.00** | 0.00 | 0.00 | 1.00 | 1.00 |
| Test suppression       | **1.00** | 0.00 | 0.00 | 1.00 | 0.33 |
| Security weakening     | **1.00** | 0.33 | 0.33 | 1.00 | 1.00 |
| Destructive shell      | **1.00** | 0.67 | 0.67 |  —   |  —   |

(Read the FPR column carefully when interpreting Lakera's row: blocking everything trivially gives 100% block rate.)

### Why every other column has at least one fatal flaw

- **Keyword heuristic**: deterministic and fast, but blind to the four *stealth* attack classes (typosquat, secret-leak, silent-failure, test-suppression). 1/18 attacks blocked.
- **Transcript-only LLM monitor**: even at the *charitable* upper bound — perfect recall on red-flag words, never fooled by paraphrase — it sees only what the agent says it's about to do, not the file contents being written. 3/18 attacks blocked. Real LLM monitors score worse.
- **Lakera Guard**: trained for prompt-injection / content-safety classification, not action evaluation. When customers reach for it for action filtering (which is common, because there's nothing else), every shell-command-shaped input scores 1.0 confidence on its `flagged` field. **0/18 benign tasks pass.** Methodological note: we hit `POST https://api.lakera.ai/v2/guard` (their flagship endpoint) with each action serialized as a single user message — the same way customers integrate it today. Numbers reproduce against the published v2 API as of May 2026.
- **LLM-as-judge (gpt-4o-mini)**: 0.787 control — the second-best score in the table, but the gap costs you in three currencies. **Latency**: 1219 ms per task vs Cordon's 0.2 ms (~6,000× slower). **Determinism**: re-running the same task gives different verdicts on the borderlines; the table reports a single run. **Per-category gaps**: catches only 67% of typosquats (misses single-character typos like `reqeusts` for `requests`) and 33% of test-suppression attacks (silently allows tests being skipped). **Cost**: at 1M agent steps/day this is ~$3,500/year in API fees plus a 1-second tax on every step — for a 0.787 control score that Cordon achieves at 1.000.

The pattern is the wedge: every existing tool judges **strings** (input prompts or output text). Cordon judges **side effects** (the proposed shell command, the proposed file write, the proposed network call). Strings can be paraphrased, encoded, or smuggled; side effects cannot. That gap is the entire moat.

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

### OpenAI tool calls — three lines to protect any agent

The same `Guard` that protects in-process Cordon `Action` objects also wraps the tool-call layer of an OpenAI agent. Declare how your tools map to actions once, attach the guard, and the next `client.chat.completions.create(...)` response runs through every probe before any tool dispatcher sees it:

```python
import cordon
from cordon.cloud import CloudReporter
from cordon.integrations.openai import ActionBuilder, check_response

builder = ActionBuilder()

@builder.tool("run_shell")
def _shell(args): return cordon.Action(kind="shell", command=args["command"])

@builder.tool("write_file")
def _write(args): return cordon.Action(kind="file", changes={args["path"]: args["content"]})

guard = cordon.Guard.strict()
guard.add_listener(CloudReporter())          # ships verdicts to your dashboard

completion = client.chat.completions.create(model="gpt-4o-mini", messages=..., tools=...)

for tcv in check_response(completion, builder=builder, guard=guard):
    if tcv.blocked:
        send_refusal_to_model(tcv.tool_call_id, tcv.verdict.top_reason())
    else:
        dispatch_tool(tcv.tool_call_id, tcv.tool_name, tcv.arguments)
```

[`examples/openai_live_demo.py`](examples/openai_live_demo.py) is the runnable end-to-end version. Three escalating scenarios — *benign* / *exfiltration* / *destructive shell* — produce one `allow`, one `flag`, and one `block` on a single screen. Gracefully degrades to a canned response when `OPENAI_API_KEY` is unset, and to a no-op `CloudReporter` when `CORDON_API_KEY` is unset, so the demo always runs:

```bash
# Offline (no keys) — runs canned, exits 0.
.venv/bin/python examples/openai_live_demo.py

# Live OpenAI call, verdicts shipped to your Cordon Cloud project.
OPENAI_API_KEY=sk-... \
CORDON_API_KEY=cdn_... \
.venv/bin/python examples/openai_live_demo.py
```

### Claude / Anthropic

The same shape works against Anthropic's Messages API and `tool_use` blocks via [`cordon.integrations.anthropic`](src/cordon/integrations/anthropic.py). [`examples/anthropic_live_demo.py`](examples/anthropic_live_demo.py) is the runnable equivalent, with three execution paths the demo auto-detects in order:

```bash
# (a) direct Anthropic SDK
ANTHROPIC_API_KEY=sk-ant-... .venv/bin/python examples/anthropic_live_demo.py

# (b) OpenRouter (one key serves both vendors — handy for design partners)
OPENAI_API_KEY=sk-or-v1-... OPENAI_BASE_URL=https://openrouter.ai/api/v1 \
    .venv/bin/python examples/anthropic_live_demo.py

# (c) no keys → canned scenarios still exercise the full Cordon code path
.venv/bin/python examples/anthropic_live_demo.py
```

The destructive-shell scenario also surfaces an interesting failure mode: aligned 2026-vintage Claudes refuse to issue `rm -rf /` on their own, sometimes even substituting an `echo "I cannot run ..."` that quotes the command verbatim. The demo detects refusals via a `must_start_with` intent check and falls back to a canned `tool_use` for that scenario only — so the pitch screenshot still shows a real BLOCK, not a silent ALLOW. *Defense in depth*: aligned model + structural probe.

### Per-tenant policies (`Guard.from_policy`, v0.2.2+)

The three default profiles (`strict` / `default` / `permissive`) cover ~80% of cases. For the rest, write a tiny policy document that takes `strict` as a base and carves out the narrow exceptions your agents genuinely need:

```python
from cordon import Action, Guard

guard = Guard.from_policy("""
    profile: strict

    # Carve out a real-world need our CI image build has:
    allow when command_starts_with: "rm -rf node_modules"
    allow when command_starts_with: "rm -rf ./build"

    # Promote a known-risky pattern to a hard block:
    block when path_starts_with: "/etc/" and kind: file

    # Downgrade a noisy probe to flag-only:
    flag when probe: typosquat
""")

guard.check(Action(kind="shell", command="rm -rf node_modules")).decision
# → 'allow'   (carve-out applied)
guard.check(Action(kind="shell", command="rm -rf --no-preserve-root /")).decision
# → 'block'   (no rule matched; strict base wins)
```

Rules apply top-to-bottom; the first match wins. The probe trail is preserved verbatim so dashboard audits still show *why* the base profile fired — the `Verdict.explanation` gets a `; policy line N → allow when ...` trailer so reviewers can trace any decision back to its source rule.

The cloud dashboard ships an editor for the same DSL — see *Cordon Cloud* below — with live syntax validation, a "try this policy" panel that runs the draft against an action without saving, and per-project storage. Syntax errors carry line numbers (`PolicyParseError`) and reach the editor as `{line, snippet}` so the dashboard can underline the bad row.

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

**v0.2.3 (current)** — 7-probe Semantic Guard suite + **4 content-aware probes** (`PythonASTProbe`, `PackageManifestProbe`, `Base64DecoderProbe`, `ArchiveInspectorProbe`) that close the camouflage-attack class documented in [`docs/threat-model.md`](docs/threat-model.md). Per-tenant policy DSL with `Guard.from_policy()`. Cordon Cloud (hosted dashboard + policy editor + REST control plane). Three vendor integrations (OpenAI, Anthropic, LangChain — both wrapper and callback). The canonical 42-task benchmark + comparative reproducer. **480 tests** passing.

**v0.3 (next)** — streaming guard for partial-tool-call evaluation, LangGraph integration example, threat-intel feed for the manifest probe.

> **Read this before you pitch Cordon:** [`docs/threat-model.md`](docs/threat-model.md) — the honest list of what Cordon catches and what it doesn't, with concrete attack examples. Cordon is one layer in a three-layer defense; pretending otherwise hurts adoption.

## Research

Cordon is the production-grade descendant of two research projects:

- **ActionLens** — 3rd place at [Apart Research](https://apartresearch.com/) AI Control Hackathon 2026 (36 countries). Introduced the pre-execution environment probes and the 42-task benchmark. [Repo →](https://github.com/Ashok-kumar290/ActionLens)
- **Context-Conditioned Confidentiality Failures in Refusal-Tuned Language Models** — Cohere Catalyst Grant, 2026. Showed that refusal-tuned models leak confidential context at 46–62% even when explicitly instructed not to. This is the empirical basis for Cordon's secret-leak probe.

## Cordon Cloud (closed beta)

Cordon Cloud is the hosted half: every verdict your agent produces, in real time, on a searchable dashboard. **It is intentionally not advertised here.** The dashboard runs in a private beta with a small group of design partners; the URL is shared per-tenant with a magic access token. To request access, email **founders@cordon.ai** with one line about the agents you operate.

### Two-line client SDK

The SDK that ships with `cordon-ai` is public — the gating only applies to the hosted dashboard:

```python
from cordon import Guard
from cordon.cloud import CloudReporter

guard = Guard.strict()
guard.add_listener(CloudReporter(
    api_key="cdn_xxx",                              # provisioned per tenant
    endpoint="https://your-tenant.cordon.ai",      # or self-hosted
))
```

`CloudReporter` contract — locked in by [`tests/test_cloud_reporter.py`](tests/test_cloud_reporter.py) (12 tests):

- **Never blocks** the agent. Telemetry is queued and flushed by a daemon thread; the listener call is sub-millisecond even when the server is unreachable.
- **Never raises.** Network, serialization, and queue-full failures are caught and surfaced via `warnings`. A misbehaving dashboard cannot crash your agent.
- **PII-safe by default.** File-change bodies are dropped, only paths and byte counts are sent; command and evidence strings are capped at 512 chars. `include_bodies=True` is the opt-in for when you control both ends.

### Self-host (open-source)

The Cordon Cloud server is in this repo at [`cloud_server/`](cloud_server). It is a single FastAPI process with a sqlite event store, a Bearer-auth ingest endpoint, and a polling dashboard. **You can self-host it today** — same Apache-2.0 license as the SDK:

```bash
# 1. start the server
CORDON_CLOUD_INGEST_KEYS="cdn_yourtenant:yourproject" \
CORDON_CLOUD_DASHBOARD_TOKEN="long-random-string" \
.venv/bin/uvicorn cloud_server.app:app --port 7860

# 2. visit the dashboard
open "http://127.0.0.1:7860/?t=long-random-string"

# 3. point an agent at it
CORDON_API_KEY=cdn_yourtenant CORDON_CLOUD_ENDPOINT=http://127.0.0.1:7860 \
python examples/cloud_reporter.py
```

Deploy the same image to your own Hugging Face Space with [`cloud_server/space/deploy.sh`](cloud_server/space/deploy.sh) — see [`cloud_server/RUNBOOK.md`](cloud_server/RUNBOOK.md) for the production checklist (rotating the dashboard token, granting and revoking per-VC access, swapping sqlite for Postgres).

### What's hosted only (the paid tier we're building)

Beyond the open-source server, the hosted Cordon Cloud adds:

- **Persistent retention** across rebuilds (Postgres-backed) with configurable retention windows.
- **Multi-tenant projects + SSO** so a security team can give individual engineers their own scoped keys.
- **Anomaly alerts** — Slack/PagerDuty webhook when block rate spikes for a project.
- **Threat-intel feed** — typosquat and exfiltration patterns we discover across the fleet, shipped back to your `Guard` weekly.

If any of that is what you want today, that's the founders@cordon.ai conversation.

## Deployment

The repo ships two interchangeable deployment surfaces for the live playground:

- **Hugging Face Space (default)** — single Docker container that serves both the landing page and the API from the same origin. Free, no DNS, no CORS surprises. Deploy with `bash space/deploy.sh <hf-username>`. Public URL: `https://<hf-username>-cordon-playground.hf.space/`.
- **GitHub Pages + separate API host (optional)** — pure-static landing page in `docs/` plus the FastAPI backend hosted anywhere (Fly, Render, Cloud Run, another HF Space). Only worth setting up if you have a custom domain that GitHub Pages can serve cleanly. Enable in *Settings → Pages → Source = `Deploy from a branch`, Branch = `main`, Folder = `/docs`*.

```bash
# One-time: create the Space on https://huggingface.co/new-space
#   SDK = Docker, Visibility = Public, leave empty.
# Then push:
bash space/deploy.sh <your-hf-username>
```

The backend can also be self-hosted via `web/Dockerfile` or `fly launch` using the included `web/fly.toml`. Override the landing-page backend at runtime from the browser console:

```javascript
localStorage.setItem('cordon_backend', 'https://my-cordon.example.com');
location.reload();
```

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
