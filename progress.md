# Cordon — session log, 2026-05-12

A pickup point for the next session. Everything that's *shipped*
plus everything that's *pending*. Skimmable on purpose.

## Shipped in this session

Nine commits between `2b272c2` (session start) and `e02d927`
(session end). The two PyPI releases — `0.2.1` and `0.2.2` — are
live; the HF Space is rebuilt against `0.2.2` and serving the
new policy endpoints.

| Lane | Commit | Result |
|------|--------|--------|
| 0 — release **0.2.1** (audit fixes + benchmark headline) | `41c2759` | Live on PyPI, 233 tests passing |
| 1 — landing page + Anthropic live demo | `5160152` | Both visible on `https://seyomi-cordon-cloud.hf.space/` |
| 2 — policy DSL (`cordon.policy` + `Guard.from_policy`) | `1863a86` | 50 tests, +50 in suite |
| 3 — cloud control plane for policies (REST API) | `4de2137` | 5 storage + 13 endpoint tests |
| 4 — dashboard policy editor (`/dashboard#policies`) | `dff7829` | Vanilla JS, live validation, try-it panel |
| 5 — release **0.2.2** | `218290d` | Live on PyPI, HF Space rebuilt, 314 tests |
| 6 — `CordonGuardCallback` for prebuilt LangChain agents | `c490536` | 13 new tests, 327 total |
| 7 — GitHub Actions CI + tag-triggered release pipeline | `5e32c11` | OIDC trusted publisher, matrix on 3.10/3.11/3.12 + Postgres |
| 8 — GTM artifacts (pitch / screenshots / blog post) | `e02d927` | All under `docs/` |

Session test delta: **233 → 327 passing** (+94).
Session PyPI delta: **`0.2.0` → `0.2.1` → `0.2.2`**.

## Hosted state

| Surface | URL | Auth |
|---|---|---|
| Public landing | <https://seyomi-cordon-cloud.hf.space/> | none |
| Public probe try | `POST /v1/try` | none, 30/min/IP |
| Public DSL validate | `POST /v1/policies/validate` | none |
| Dashboard | `/dashboard?t=<TOKEN>` | `CORDON_CLOUD_DASHBOARD_TOKEN` |
| Policies CRUD | `/v1/policies/{project}` | `CORDON_CLOUD_DASHBOARD_TOKEN` |
| Ingest | `/v1/ingest` | `CORDON_CLOUD_INGEST_KEYS` |
| API docs (FastAPI) | `/api/docs` | none |

Active Space secrets cached locally at `/tmp/cordon-demo-creds.env`
(chmod 600). Rotate via the `huggingface_hub` snippet at the bottom
of this file.

## Pending followups

Sorted by urgency.

### Before the next demo call

1. **Rotate the two credentials I pasted in chat history** —
   OpenRouter `sk-or-v1-3a44…9216af` at
   <https://openrouter.ai/keys>, and the HF user token `hf_cfex…UJMtGk`
   at <https://huggingface.co/settings/tokens>. Both are in the
   chat transcript and trivially exfiltratable.

2. **One-time PyPI trusted-publisher setup** so the `release.yml`
   workflow can publish. At
   <https://pypi.org/manage/account/publishing/> add:
   - Owner: `Ashok-kumar290`
   - Repository: `cordon`
   - Workflow filename: `release.yml`
   - Environment name: `pypi-release`

   Until that's done, releases still work via the manual
   `twine upload` path we used today.

### Worth doing soon

3. **CI-on-Postgres needs a real Postgres instance**. The
   `ci.yml` `postgres` job spins up a service container, so it
   should "just work" on the first CI run — verify after the
   first push that the storage tests actually exercise both
   adapters (not just SQLite).

4. **The dashboard editor is a textarea, not Monaco.** Fine for
   v0.2.2, but a Monaco-style editor with token highlighting on
   our six keywords would be a one-day polish that's worth it
   before the design-partner pitches. Hook: the `policies.js`
   module already isolates the editor under `#pol-editor`; swap
   the `<textarea>` for a Monaco `<div>` and rewire `editor.value`
   to `monacoInstance.getValue()`.

5. **Streaming guard.** Right now `Guard.check()` is called once
   per tool call. For LLM agents that stream partial tool calls
   over SSE, we want a `guard.check_partial(action_so_far)` that
   short-circuits as soon as a probe fires. Design lives in
   `docs/research/streaming-guard.md` (not yet written).

### Background

6. **LangGraph integration example** — the `CordonGuardCallback`
   works, but `examples/langgraph_protect.py` doesn't exist yet.
   Should be a 50-line example: `create_react_agent` + a real
   destructive shell tool + the callback registered, showing
   a block + a graceful recovery via the agent's scratchpad.

7. **HN / X launch.** Use `docs/pitch/screenshot-kit.md` Scene 1
   as the hero image. Recommended timing: Tuesday morning PT
   (highest HN front-page hit rate per
   <https://news.ycombinator.com/best>).

8. **Customer pipeline.** Three design-partner conversations are
   warm. The pitch script in `docs/pitch/pitch-script-90s.md` is
   designed to be read straight through at ~150 wpm; total runtime
   90 s with the live OpenAI demo embedded at 0:40-1:10.

## Quick-resume commands

```bash
# Smoke-test the local SDK
.venv/bin/python -c '
from cordon import Action, Guard
print(Guard.strict().check(Action(kind="shell", command="rm -rf /")).decision)
'

# Run the whole suite
.venv/bin/pytest -q          # → 327 passed, 10 skipped (postgres)

# Re-deploy the Space (after any cloud_server/ change)
bash cloud_server/space/deploy.sh Seyomi

# Bump version + release (once OIDC is configured)
sed -i 's/version = "0.2.2"/version = "0.2.3"/' pyproject.toml
git commit -am "release v0.2.3"
git tag -a v0.2.3 -m "release v0.2.3"
git push origin main v0.2.3       # release.yml takes it from here

# Rotate the Space secrets (if/when needed)
.venv/bin/python -c '
from huggingface_hub import HfApi
import secrets
api = HfApi()
new_ingest = "cdn_live_" + secrets.token_urlsafe(20) + ":demo"
new_dashbd = "tk_" + secrets.token_urlsafe(20)
api.add_space_secret("Seyomi/cordon-cloud", "CORDON_CLOUD_INGEST_KEYS",     new_ingest)
api.add_space_secret("Seyomi/cordon-cloud", "CORDON_CLOUD_DASHBOARD_TOKEN", new_dashbd)
print("ingest:", new_ingest)
print("dash:  ", new_dashbd)
' > /tmp/cordon-demo-creds.env
chmod 600 /tmp/cordon-demo-creds.env
```

---

*Last touched: 2026-05-12 ~23:30 UTC+05:30 · 9 commits · 314→327 tests · 0.2.0→0.2.2*
