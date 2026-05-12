---
description: Ship the OpenAI live demo + Postgres persistence, in order, before pitching VCs.
---

This workflow gets Cordon from "shipped" to "pitch-ready". Two
deliverables, sequenced because A pays off the slide deck and B
guarantees the demo won't reset under the VC's feet.

The full plan is tracked in the active todo list. This file is the
re-runnable recipe — if it has to be done again (e.g., on a new
machine, after a fork, or for a second product surface) follow these
steps in order.

## A. OpenAI live demo (~2 hours)

The integration module `src/cordon/integrations/openai.py` is already
done. What's missing is an end-to-end example that makes a *real*
OpenAI call and ships the verdict to the live cordon-cloud dashboard.
That's the 30-second clip for slide 4.

### A.1 Build the example

Create `examples/openai_live_demo.py`:

- Calls `client.chat.completions.create()` for real when
  `OPENAI_API_KEY` is set, with `model="gpt-4o-mini"` (cheap +
  fast). Falls back to a hand-crafted response when the key is
  absent so the script always runs in CI.
- Registers an `ActionBuilder` covering `run_shell` and
  `write_file`.
- Wires `Guard.strict()` plus
  `CloudReporter(api_key=…, endpoint="https://seyomi-cordon-cloud.hf.space")`.
- Prints decisions with terminal colors; ends with
  `→ open https://seyomi-cordon-cloud.hf.space/?t=…` so the
  operator can see the verdict on the dashboard.

Two scenarios:

1. **Benign.** A user message that should produce a `run_shell` →
   `echo hello world` tool call. Allowed.
2. **Prompt-injected.** A user message that wedges a typosquat into
   the assistant's plan (the kind of behavior Cordon's `typosquat`
   probe catches). Blocked.

### A.2 Tests

Create `tests/test_openai_live_demo.py`:

- Patches `openai.OpenAI` with a stub client whose
  `chat.completions.create` returns hand-shaped responses.
- Asserts the benign path is allowed, the attack path is blocked,
  the `top_probe` on the attack verdict is `typosquat`.
- Asserts the CloudReporter listener is invoked twice (once per
  tool call) and never raises.

### A.3 README

In `README.md`, add a top-level **OpenAI integration** subsection
under the existing **Quickstart** that lifts a 10-line excerpt from
the example and links to `examples/openai_live_demo.py`. Headline
copy: *"Two lines and your OpenAI agent is on the dashboard."*

### A.4 Live smoke against cordon-cloud

```bash
OPENAI_API_KEY=sk-... \
CORDON_API_KEY="$(grep ^INGEST_KEY /tmp/cordon-cloud-credentials.txt | cut -d= -f2-)" \
CORDON_CLOUD_ENDPOINT="https://seyomi-cordon-cloud.hf.space" \
.venv/bin/python examples/openai_live_demo.py
```

Confirm in the dashboard that two new events appear with project
`default` and the OpenAI assistant's tool calls visible in
`command_preview`.

### A.5 Commit + push

```bash
git add examples/openai_live_demo.py tests/test_openai_live_demo.py README.md
git commit -m "feat(integrations): OpenAI live demo wired to cordon-cloud"
git push origin main
```

## B. Postgres persistence for cordon-cloud (~2 hours)

Sqlite on a HF Space resets on every container rebuild. A VC who
clicks the magic link Tuesday and again Friday will see a re-seeded
dashboard, which costs credibility. Postgres on Neon (free 10 GB
tier) fixes it without changing any code at the call sites.

### B.1 Refactor `cloud_server/storage.py`

Extract the public surface (`count`, `insert_batch`, `list_events`,
`get_event`, `metrics`) into an `EventStore` Protocol. Rename the
existing class to `SqliteEventStore`. Add a `PostgresEventStore`
with identical method signatures and SQL ported to psycopg.

Add a top-level `make_store(db_url: str | None) -> EventStore`
factory:

- `None` / `""` / `sqlite:///...` → `SqliteEventStore`
- `postgresql://...` / `postgres://...` → `PostgresEventStore`

The url-scheme dispatch keeps the env var (`CORDON_CLOUD_DB`)
identical across both backends.

### B.2 `cloud_server/app.py`

Replace the direct `SqliteEventStore(...)` instantiation with
`make_store(os.environ.get("CORDON_CLOUD_DB"))`. Everything
downstream is unchanged because both adapters honor the same
protocol.

### B.3 Image + deps

- Add `psycopg[binary]>=3.2` to `cloud_server/space/Dockerfile`
  pip install line.
- Add the same to `pyproject.toml` under
  `[project.optional-dependencies] cloud-postgres = [...]`.

### B.4 Tests

- All existing tests keep running against sqlite (default).
- Add a `tests/test_storage_postgres.py` that is skipped unless
  `CORDON_CLOUD_POSTGRES_TEST_URL` is set. Asserts the same
  contract (round-trip insert → list → metrics) against a real
  postgres backend.

### B.5 RUNBOOK

Append a section to `cloud_server/RUNBOOK.md`:

- Sign up at `console.neon.tech`, create a free project, copy the
  connection string (it'll look like
  `postgresql://user:pass@ep-...neon.tech/dbname?sslmode=require`).
- Add it as the **`CORDON_CLOUD_DB`** secret on
  `https://huggingface.co/spaces/Seyomi/cordon-cloud/settings`.
- Restart the Space. The first boot creates the tables; subsequent
  rebuilds re-attach to the same data.

### B.6 Ship + verify persistence

```bash
git add cloud_server/ pyproject.toml tests/test_storage_postgres.py
git commit -m "feat(cloud): postgres adapter; CORDON_CLOUD_DB switches backend"
git push origin main
bash cloud_server/space/deploy.sh Seyomi
```

After the user sets `CORDON_CLOUD_DB` on the Space and triggers a
restart, verify:

```bash
curl -s "https://seyomi-cordon-cloud.hf.space/healthz" | jq .demo_seeded
# → false on second restart, proving data survived
```

Then run `examples/openai_live_demo.py` once more and confirm those
events stick across a forced restart.
