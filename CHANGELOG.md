# Changelog

All notable changes to Cordon will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`cordon.benchmarks` — the canonical 36-task Semantic Guard benchmark**:
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
- `cordon benchmark` — reproducible 36-task ActionLens benchmark.
- OpenAI/Anthropic/LangChain integration helpers.
