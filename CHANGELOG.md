# Changelog

All notable changes to Cordon will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
