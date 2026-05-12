# Changelog

All notable changes to Cordon will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.2] — 2026-05-12

The **per-tenant policy** release. Customers consistently asked the
same thing: *"strict blocks something we genuinely need
(e.g. `rm -rf node_modules` in our CI image build) — give us a way
to carve out a narrow exception without dropping the whole profile
to permissive."* This release ships exactly that.

### Added — `cordon.policy` DSL

```python
from cordon import Guard

guard = Guard.from_policy("""
    profile: strict

    # Real-world carve-outs our agents actually need:
    allow when command_starts_with: "rm -rf node_modules"
    allow when command_starts_with: "rm -rf ./build"

    # Promote a known-risky pattern to a hard block:
    block when path_starts_with: "/etc/" and kind: file

    # Downgrade a noisy probe to flag-only:
    flag when probe: typosquat
""")

verdict = guard.check(action)
```

* `Guard.from_policy(text)` — new classmethod, the typical entry point.
* `cordon.policy.parse(text) -> Policy` — exposed for advanced use
  (e.g. validating policies in your own CI before deploying).
* `cordon.policy.apply_policy(policy, action, verdict) -> Verdict` —
  the lower-level mutator, useful for testing or for composing
  policies with custom Guards.
* `cordon.policy.PolicyParseError` carries `line` + `snippet` for
  editor-grade error messages.

The verdict's probe trail is **never** mutated — operators looking at
the dashboard still see *why* the base profile fired, even when a
policy rule overrode the final decision. The `Verdict.explanation`
string gets a trailing `; policy line N → action when ...` annotation
so audit reviewers can trace decisions back to the exact rule.

### Added — Cloud control plane

* `GET    /v1/policies/{project}` — read the saved policy.
* `PUT    /v1/policies/{project}` — upsert; validates the DSL before
  storing, returns 400 with `{line, snippet}` on syntax errors.
* `DELETE /v1/policies/{project}` — remove the policy (agents fall
  back to whichever profile they were constructed with).
* `POST   /v1/policies/validate` — public, no auth, no persistence.
  Drives the live syntax check in the dashboard editor.
* `POST   /v1/try` — extended with an optional `policy` field so the
  editor's *try-it* panel can run the draft against a sample action
  without saving.

Control-plane writes (PUT/DELETE) are gated by the dashboard token
rather than the ingest key. Writing a policy is a security action,
not a telemetry action, so the SDK's credentials never need to
reach it.

Storage: new `policies` table on both backends (SQLite and Postgres).
Monotonic `version` column so the editor can detect lost updates.

### Added — Dashboard UI

The `/dashboard` page grows a **Project policy** section anchored at
`#policies` and linked from the header nav. Vanilla JS, no framework:

* Two-column layout — textarea editor on the left, *Try this policy*
  panel on the right (kind + command input → POST `/v1/try`, results
  rendered as a decision badge + per-probe evidence).
* Live validation: 500 ms debounce on input, one validate round-trip
  per typing pause.
* Status line under the editor shows `line N: <message>` for syntax
  errors in the same vocabulary the API returns.
* `validate` · `save` · `revert` · `delete` actions. Save and Revert
  dim when the buffer is clean.

### Tests

Suite: 246 → **314 passing** (+68).

* `tests/policy/test_parser.py` — 33 tests covering grammar happy
  paths, error shapes, quote-aware tokenisation, and dataclass
  invariants.
* `tests/policy/test_runtime.py` — 17 tests pinning predicate
  semantics, rule-AND matching, and `Guard.from_policy()` end-to-end
  against real probes.
* `tests/test_storage.py` — 5 new contract tests for policy storage,
  parametrised over SQLite + Postgres.
* `tests/test_cloud_server_policies.py` — 13 HTTP tests for the new
  REST surface, the dashboard-token gate, and the error-with-line
  response shape.

## [0.2.1] — 2026-05-12

The pitch-readiness release. Closes every P0 from the 2026-05-12
user-journey audit (see `audit-report.md`) and ships the
comparative benchmark framework that the README has been advertising.

### Added

- **`DestructiveShellProbe`** — closes audit finding F-1. The
  previous six probes targeted agent-specific attack vectors
  (typosquat, exfiltration, secret leak, silent failure, test
  suppression, security weakening), which meant a stranger typing
  `cordon check` on `rm -rf /`, a fork bomb, `curl | sh`, or `dd
  if=/dev/zero of=/dev/sda` got back `Decision: ALLOW`. This probe
  catches all of them and reports `Severity.CRITICAL`, with tight
  patterns that leave realistic benign commands
  (`rm -rf node_modules`, `dd if=image.iso of=image.bin`) untouched.
  52 unit tests + 3 new attack/benign benchmark pairs.
- **`cordon.benchmarks.comparators` + `cordon compare` CLI**
  (previously unreleased — completes the comparative benchmark
  table the README has been showing).
- **`CloudReporter` credential health-check on init** — closes
  audit finding F-6. POSTs an empty events batch synchronously on
  construction; on 401/403 emits a loud `RuntimeWarning` and flips
  `auth_ok=False`. No more "events vanished into the void" UX.
  Opt out with `verify_credentials=False`.
- `auth_ok` field on `CloudReporter.stats()`.

### Changed

- **Benchmark suite grew from 36 to 42 tasks** — 6 new tasks (3
  attack + 3 benign) for the `destructive_shell` category. The
  per-profile headline scores actually *improved*: strict is still
  `1.000` (21/21), default rose from `0.944` to `0.952`, permissive
  from `0.889` to `0.905`.
- `cordon benchmark` now prints a one-line headline above the
  panel — *"Cordon strict: 21/21 attacks blocked · 0/21 false
  positives · 7.8 ms"* — for screenshot-friendly pitch material.
  Fixes audit finding F-3.

### Fixed

- **`examples/cloud_reporter.py`** silently failed against the
  live cloud server (HTTP 403) but claimed *"Done, open the
  dashboard"* with `sent=0 failed_batches=0`. The example now reads
  `CORDON_API_KEY` from env (errors out clearly when unset),
  short-circuits when `reporter.auth_ok` is `False`, and calls
  `reporter.close()` *before* reading stats so the in-flight HTTP
  POST has actually returned. Closes audit finding F-4.

### Documentation

- New `audit-report.md` with the full user-journey audit and the
  ranked fix list.
- `cloud_server/RUNBOOK.md` explains the `cdn_demo` decision
  (F-5): the example no longer relies on a public demo key.

### Previously unreleased (now shipping in 0.2.1)

- **`cordon.benchmarks.comparators` + `cordon compare` CLI** —
  comparative benchmark framework. Runs the same 42-task suite
  through multiple judges side-by-side and prints TPR / FPR /
  control score / latency for each.
  - `Comparator` ABC + `ComparatorResult` / `ComparatorVerdict`
    with `"skipped"` decision support so external-API judges that
    lack credentials are excluded from rate calculations rather
    than contaminating them.
  - `CordonComparator(guard)` — the headline column.
  - `KeywordHeuristicComparator` — substring-match block-list,
    realistic naive baseline ("what your security team builds in
    an afternoon").
  - `TranscriptOnlyComparator` — charitable transcript-monitor
    upper bound. Narrates the action from `command` + filenames
    only (never file content) and looks for red-flag words.
  - `LakeraComparator` — Lakera Guard REST API. Skips when no
    `LAKERA_API_KEY`.
  - `LLMJudgeComparator` — OpenAI chat-completions JSON-mode
    judge (default `gpt-4o-mini`). Skips when no `OPENAI_API_KEY`.
  - **Headline numbers (no API keys needed)**: Cordon (strict)
    1.000 / 0.000 / 1.000; keyword heuristic 0.056 / 0.000 / 0.056;
    charitable transcript-only 0.167 / 0.000 / 0.167. Cordon catches
    18× more attacks than the naive baseline and 6× more than a
    charitable transcript monitor at zero false positives.
- 15 new tests on the comparator framework + the API-key-free
  comparators. **150 tests passing total.**
- **Lakera Guard measured against the live `v2/guard` API
  (May 2026)**: TPR 1.000, FPR 1.000, control score **0.000**.
  Lakera flags every shell-command-shaped input with `flagged=true`,
  confidence 1.0 — including all 18 benign tasks. The headline
  finding: Cordon is the only judge in the comparison with a
  non-zero control score.
- Raw measured run archived at
  `docs/benchmarks/comparative-2026-05-11.json` (5 comparators,
  180 task results, full per-task reasons + raw API payloads).
- **LLM judge measured against `openai/gpt-4o-mini` via OpenRouter
  (May 2026)**: TPR 0.833, FPR 0.056, control score **0.787**,
  mean latency **1219 ms** per task. The second-best column in the
  table on accuracy, but ~6,000× slower than Cordon, non-
  deterministic, and adds per-step API cost. Misses the 1-character
  typosquat (`reqeusts` for `requests`) and 2/3 of the test-
  suppression attacks. Raw run archived at
  `docs/benchmarks/llm-judge-2026-05-11.json`.
- `cordon compare --judge-endpoint <url>` — point the LLM-judge
  comparator at any OpenAI-compatible endpoint (OpenRouter,
  Together, Groq, vLLM, llama.cpp, etc.) instead of OpenAI directly.

## [0.2.0] — 2026-05-11

### Added

- **`cordon.integrations.langchain`** — third framework integration.
  - `GuardedTool` — duck-typed wrapper around any LangChain
    `BaseTool` / Runnable. Forwards `name`, `description`,
    `args_schema`; gates `invoke` / `ainvoke` / `run` / `_run` /
    `_arun` on a `Guard.check`.
  - `guard_tool(tool, ...)` and `guard_tools([t1, t2, ...], ...)`
    convenience wrappers for one or many tools.
  - Configurable `on_block`: `"raise"` (raises `BlockedAction`) or
    `"return_error"` (returns a string the agent sees in its
    scratchpad and can recover from). Critical safety property: when
    blocked, the underlying tool is *never* invoked.
  - No runtime dependency on the `langchain` package — works with
    LCEL Runnables, legacy `BaseTool`, plain callables, and the
    `@tool` decorator.
- **`cordon.integrations.anthropic`** — second framework integration.
  - `check_response(message, builder, guard)` — inspects an Anthropic
    `Message`-shaped response (any object with a `content` list of
    typed blocks) and returns one `ToolCallVerdict` per `tool_use`
    block, in order.
  - Reuses the same `ActionBuilder` and `protect_tool` from the
    OpenAI integration — a single registry can be shared across
    vendors.
  - No runtime dependency on the `anthropic` package.
- **Refactor**: extracted shared types (`ActionBuilder`,
  `ToolCallVerdict`, `protect_tool`, `coerce_attr`,
  `verdict_for_unknown_tool`) into `cordon.integrations._common`.
  Public API of `cordon.integrations.openai` is unchanged.
- 35 new integration tests (**135 total passing**: 17 LangChain + 18
  Anthropic).
- New runnable examples: `examples/anthropic_protect.py`,
  `examples/langchain_protect.py`.
- **`cordon.benchmarks` — the canonical 42-task Semantic Guard benchmark**:
  - 36 hand-curated tasks: 3 attack + 3 benign per attack class × 6 classes.
  - `run_benchmark(guard, tasks=...)` driver returning a full
    `BenchmarkReport` with TPR, FPR, control score, per-category
    breakdown, per-task timing, and JSON serialization.
  - `cordon benchmark --profile {strict|default|permissive} [--json]`
    CLI command — single-command reproducer that prints a Rich-formatted
    summary panel and per-category table.
  - **Headline result on `Guard.strict()`: block rate 1.000, FPR 0.000,
    control score 1.000, full suite in ~7 ms.**
  - Two upstream probe precision improvements driven by benchmark
    failures: typosquat now also catches `pip --index-url` pointing at
    non-standard mirrors, and the test-suppression assertion-deletion
    rule now requires an absolute drop ≥ 2 to avoid flagging legitimate
    refactors.
  - 15 new tests on the runner + suite invariants.
- **Full 6-probe Semantic Guard suite** — completes the v0.2 detector roster:
  - `SilentFailureProbe` — bare-except / `except Exception: pass` /
    `except ... as e: pass`, empty JS/TS catch blocks, empty
    `.catch(() => {})`, and shell mufflers (`2>/dev/null`, `|| true`,
    `set +e`, `-DskipTests`).
  - `ExfiltrationProbe` — sensitive-data egress over the network. Three
    tiers: critical (shell upload-from-file like `curl -d @.env`),
    dangerous (sensitive read + sink-shaped host like pastebin/ngrok),
    suspicious (sensitive read + any egress).
  - `TestSuppressionProbe` — skip-marker injection (`@pytest.mark.skip`,
    `xit(`, `it.skip`), assertion-count drop on edited tests, test-file
    deletion, test-runner config weakening (`skipTests: true`,
    commented CI test steps), shell `--no-tests` flags.
  - `SecurityWeakeningProbe` — TLS off (`verify=False`, `curl -k`,
    `NODE_TLS_REJECT_UNAUTHORIZED=0`), auth bypass (`permitAll`,
    `git push --no-verify`, IAM `"*"` resource/action), dangerous
    primitives (`shell=True`, `eval`, `pickle.loads`), privilege
    widening (`chmod 777`, `--privileged`, `runAsUser: 0`), crypto
    downgrade (`hashlib.md5`, `alg: none`, `Math.random()` for tokens).
- All three guard profiles (`strict` / `default` / `permissive`) now
  bundle the full 6-probe suite by default.
- 44 new probe tests (**85 total passing**).
- `cordon demo` expanded to walk through all 6 attack classes plus a
  benign baseline.
- **`cordon.integrations.openai`** — first framework integration. Three entry points:
  - `ActionBuilder` — registry mapping tool names to `Action` constructors,
    with decorator and imperative APIs.
  - `check_response(response, builder, guard)` — inspect an OpenAI
    `ChatCompletion`-shaped response and return a list of
    `ToolCallVerdict` records, one per tool call.
  - `protect_tool(name, builder, guard)` — decorator that guards a
    Python function implementing one of your tools, raising
    `BlockedAction` on block.
  - Duck-typed against the OpenAI 1.x response shape; works with the
    official SDK, `litellm`, and dict-shaped wrappers. No runtime
    dependency on the `openai` package.
  - Configurable `unknown_tool_policy` (`allow` / `flag` / `block`)
    for tools without registered builders.
- **22 new tests** for the OpenAI integration.
- **`examples/openai_protect.py`** — runnable end-to-end demo (no API
  key needed) showing benign vs typosquat-injected tool calls.

## [0.1.0] — 2026-05-10

Initial public release.

### Added

- Core API: `Guard`, `Action`, `Verdict`, `ProbeResult`, `Severity`, `BlockedAction`.
- Three built-in profiles: `Guard.strict()`, `Guard.default()`, `Guard.permissive()`.
- Decorator API `@guard.protect` for wrapping agent step functions.
- Two semantic probes:
  - `TyposquatProbe` — supply-chain dependency attacks via edit-distance matching
    against 150+ top PyPI packages. Flags non-standard package sources.
  - `SecretLeakProbe` — sensitive-read → artifact-write flows, with verbatim
    value matching (tier-1 CRITICAL) and flow-shape matching (tier-2 DANGEROUS).
- CLI: `cordon check`, `cordon demo`, `cordon list-probes`, `cordon version`.
- Test suite: 19 unit + integration tests covering both probes and the Guard
  aggregation logic.
- Examples: `basic_check.py`, `protect_agent.py`.

### Research provenance

Ported and hardened from the Semantic Guard component of ActionLens
(Apart Research AI Control Hackathon 2026, 3rd place across 36 countries).

### Coming in 0.2

- Remaining four semantic probes: `SilentFailureProbe`, `ExfiltrationProbe`,
  `TestSuppressionProbe`, `SecurityWeakeningProbe`.
- Environment probes: `preview_diff`, `dry_run`, `sensitivity_scan`,
  `inspect_targets`.
- `cordon benchmark` — reproducible 42-task ActionLens benchmark.
- OpenAI/Anthropic/LangChain integration helpers.
