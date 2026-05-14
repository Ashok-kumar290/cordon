# Cordon Cloud — data-handling policy

This document is the load-bearing answer to *"what does Cordon Cloud
do with the verdict data my agents send you?"* It's the kind of
policy a design partner's security team will challenge in a closed-
beta evaluation; this version is honest about the closed-beta state
of the product and identifies exactly what changes when we move to
GA.

**Scope.** This policy covers Cordon Cloud (the hosted dashboard
service at `https://seyomi-cordon-cloud.hf.space`, currently in
closed beta). The Cordon SDK (`pip install cordon-ai`) runs entirely
in your own process and sends no data anywhere by default; the
policy below only takes effect when you explicitly opt in by
attaching a `CloudReporter` listener with a real API key.

**Effective date.** 2026-05-13. Matches `cordon-ai==0.2.3` and the
Space build at git ref `2134787`. We rev this document with every
release that materially changes the data flow.

---

## 1. What we collect

For every verdict your `CloudReporter` ships, Cordon Cloud stores:

| Field | What it is | Why we keep it |
|---|---|---|
| `action_id` | Your client-provided UUID for the action | Joins our event to your trace logs |
| `project` | Your client-provided project tag | Multi-project filtering in the dashboard |
| `ts` | UNIX timestamp the verdict was produced | Sparkline, retention math |
| `kind` | `"shell"` / `"file"` / `"http"` etc. | Filter / search |
| `command_preview` | First 200 chars of `Action.command`, **truncated** | Dashboard row text |
| `decision` | `"allow"` / `"flag"` / `"block"` | The thing that matters |
| `blocked` | Boolean mirror of `decision == "block"` | Index-friendly |
| `suspicion_score` | Max confidence across probes | Sparkline + filtering |
| `top_probe` | Name of the highest-severity probe that fired | Dashboard label |
| `top_severity` | That probe's severity tier | Dashboard colour |
| `top_evidence` | First 400 chars of the top probe's evidence, **truncated** | Dashboard expansion |
| `guard_profile` | `"strict"` / `"default"` / `"permissive"` / `"<name>+policy"` | Audit context |
| `sdk_version` | `cordon-ai` version that produced the verdict | Debug the SDK side |
| `raw_json` | The full Verdict object as serialised JSON | Replay / audit |

### What we explicitly do **not** collect

* **The full action payload.** `command_preview` is truncated at 200
  chars; we never see beyond that on the network. If your action
  contains an API key past character 200, we never received it.
* **File contents.** Even though the SDK's probes inspect file
  changesets in your process, `CloudReporter` only ships the
  *verdict* — never the changeset itself.
* **PII deliberately.** We have no fields for user IDs, IP addresses
  of end-users, customer names, or anything you didn't explicitly
  put inside an action.
* **LLM input or output.** Cordon doesn't see the prompt or the
  completion — only the action the model decided to take.

### What sneaks through accidentally

* **Secrets in command previews.** If your agent runs
  `aws --secret-access-key=AKIA... s3 ls`, the first 200 chars of
  that command land in our database. The `SecretLeakProbe` should
  have blocked this before the SDK even shipped the event, but we
  document this gap explicitly because it's the most likely
  accidental data exposure.
  * **Mitigation we recommend:** run `Guard.strict()` (which
    includes `SecretLeakProbe`), and add a custom redactor before
    constructing `Action.command` if your domain has command-line
    secrets that aren't on the standard secret list.

---

## 2. Where it's stored

* **Closed beta (today).** A single SQLite file on the Hugging Face
  Space's ephemeral disk:
  `https://huggingface.co/spaces/Seyomi/cordon-cloud`. The Space's
  filesystem is reset on every container rebuild — so the database
  is wiped any time we redeploy. This is intentional for closed
  beta; it limits blast radius if the Space is compromised.
* **Optional Postgres backend.** Set `CORDON_CLOUD_DB=postgresql://...`
  on the Space and `make_store()` will switch to a Postgres adapter.
  Same schema, persistent storage. Recommended target: Neon free
  tier (Frankfurt region for EU partners; Virginia for US partners).
  The Postgres path is exercised by the same 5-test contract suite
  as the SQLite path (`tests/test_storage.py`), so adapter drift is
  pinned.
* **Backups.** None today, by design. The closed beta sqlite is
  ephemeral and the Postgres path is your-own-DB. When we move to
  GA we'll publish a backup policy as a separate document.

### Sub-processors

| Vendor | What they receive | Why |
|---|---|---|
| Hugging Face Spaces | Everything in §1 (it's their disk) | Hosts the Space |
| Neon / Supabase / RDS *(optional, your choice)* | Everything in §1 | When you set `CORDON_CLOUD_DB=postgresql://...` |
| Cloudflare *(transit only)* | TLS-encrypted requests | DNS / CDN for `*.hf.space` |

We use no analytics tools, no error trackers, and no third-party
session recorders.

---

## 3. Retention

* **Closed beta default:** until the next Space rebuild (typically
  within 30 days). This is enforced *by* the ephemeral filesystem,
  not by a policy job.
* **Postgres backend:** indefinite by default. A retention job is
  on the roadmap; for now you can use the `DELETE /v1/events`
  endpoint described in §5.
* **At GA:** 30-day rolling default with per-project configuration,
  enforced by a daily retention sweep. Will be added when we move
  out of closed beta.

---

## 4. Access controls

* **Ingest** (`POST /v1/ingest`) is authenticated by a per-tenant
  Bearer key configured via the `CORDON_CLOUD_INGEST_KEYS` env var
  on the Space. Multiple projects can share a Space; each ingest
  key is scoped to one `project` tag.
* **Dashboard** (`GET /dashboard?t=<token>`) and all the management
  REST endpoints are gated by a single
  `CORDON_CLOUD_DASHBOARD_TOKEN`. **This is intentional in closed
  beta** — design partners receive a magic link rather than
  individual SSO. At GA, dashboard auth will move to a per-user
  token model with audit logs.

The two credentials are deliberately separate so that the SDK key
that ships with an agent (potentially many copies, potentially
leaked) cannot read the dashboard or mutate policies.

---

## 5. Export and delete (your right to your data)

A partner-grade product has to let you get your data out and have it
deleted on demand. We implement both as documented REST endpoints,
gated by the dashboard token.

### `GET /v1/events/export`

Returns every event for a project, as either newline-delimited JSON
(default) or CSV. No pagination — this is meant for one-shot exports
during security reviews or contract termination, not for streaming.

```bash
# Export everything as JSONL
curl 'https://seyomi-cordon-cloud.hf.space/v1/events/export?project=demo&t=<TOKEN>' \
    -o demo-events.jsonl

# Or as CSV for spreadsheet review
curl 'https://seyomi-cordon-cloud.hf.space/v1/events/export?project=demo&format=csv&t=<TOKEN>' \
    -o demo-events.csv
```

The export is the **full row from §1** — same columns, no
truncation beyond what was stored at ingest time.

### `DELETE /v1/events`

Wipes every event for a project. Idempotent — running it twice
returns the same response. Returns the number of rows deleted.

```bash
curl -X DELETE 'https://seyomi-cordon-cloud.hf.space/v1/events?project=demo&t=<TOKEN>'
# → {"project": "demo", "deleted": 12483}

curl -X DELETE 'https://seyomi-cordon-cloud.hf.space/v1/events?project=demo&t=<TOKEN>'
# → {"project": "demo", "deleted": 0}
```

There is no "soft-delete" or recovery period. Once the request
returns, the rows are gone.

---

## 6. Incident reporting

If we discover unauthorised access to data we hold, we will:

1. Notify affected design-partner contacts within 24 hours of
   discovery via the founders@cordon.ai inbox you used to enrol.
2. Publish a public incident report on the GitHub repo within 7
   days.
3. Co-operate with your incident response process.

We have not yet had an incident.

---

## 7. What's missing in closed beta

We're naming these explicitly so a security reviewer doesn't have to
discover them by interrogation.

* **No SOC 2.** We're building toward it; closed-beta evidence is
  available on request via email.
* **No formal DPA.** When you sign on as a design partner, we
  exchange a one-page Memorandum of Intent that covers the closed-
  beta data flow. A full DPA arrives with GA.
* **No SSO.** Dashboard auth is a single shared token. At GA this
  becomes per-user.
* **No region pinning.** The Space runs wherever HF schedules it.
  Run your own self-hosted instance (the open-source code in
  `cloud_server/`) if you need region pinning today.

---

## 8. Self-hosting

Every line of code that processes your data is open-source. The
Space we run is `cloud_server/app.py` from the public repository,
running unchanged. You can run the same code on your own infra —
the deploy script at `cloud_server/space/deploy.sh` works against
any HF Space owner; for non-HF deploys the FastAPI app accepts any
ASGI server and any DB scheme `make_store()` understands.

Self-hosting eliminates every item in this policy that begins
*"we"* — you become the data controller.

---

*Reviewed by: (founders only, closed beta) · Last touched:
2026-05-13 · Filed against: `cordon-ai==0.2.3`*
