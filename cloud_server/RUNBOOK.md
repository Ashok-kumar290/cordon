# Cordon Cloud operator runbook

This is the practical checklist for running a Cordon Cloud instance —
either the closed-beta production one on Hugging Face Spaces, or a
self-hosted clone for an enterprise design partner.

There are two distinct populations you give credentials to. **Do not
mix them up.**

| Population              | Secret                                     | Set via                                 | Used for                              |
| ----------------------- | ------------------------------------------ | --------------------------------------- | ------------------------------------- |
| Design-partner viewers  | one shared **dashboard token**             | `CORDON_CLOUD_DASHBOARD_TOKEN`          | Visiting `/?t=...`; reading `/v1/*`   |
| Customer agents (SDK)   | one **bearer API key** per tenant          | `CORDON_CLOUD_INGEST_KEYS` (CSV)        | `POST /v1/ingest`                     |

The two are independent. A VC viewing the dashboard never sees a
customer's API key; a customer's agent never sees the dashboard token.
Rotate them on separate cadences.

## Initial deploy (closed beta on Hugging Face)

1. Create the empty Space at <https://huggingface.co/new-space>:
   owner = `Seyomi`, name = `cordon-cloud`, SDK = Docker → Blank,
   visibility = **Public** (see [Why public, not private](#why-public-not-private) below).

2. Generate the two secrets locally:

   ```bash
   python3 -c 'import secrets; print("DASHBOARD =", secrets.token_urlsafe(32))'
   python3 -c 'import secrets; print("INGEST    =", "cdn_" + secrets.token_urlsafe(24))'
   ```

   Store them in your password manager. Do not paste them in chat,
   email, or commit them.

3. Set them as **Space secrets** at
   `https://huggingface.co/spaces/Seyomi/cordon-cloud/settings`
   under **Variables and secrets**:

   - `CORDON_CLOUD_DASHBOARD_TOKEN` = `<32-byte URL-safe string from step 2>`
   - `CORDON_CLOUD_INGEST_KEYS`     = `cdn_<...>:default`
     (one `<key>:<project>` per tenant, comma-separated as you grow)

   HF Space secrets are injected as env vars on every container boot;
   they never appear in the image or in logs.

4. Push the code from your machine:

   ```bash
   cd /media/seyominaoto/x/cordon_workspace/cordon
   bash cloud_server/space/deploy.sh Seyomi
   ```

5. The Space builds in ~60-90 s. Verify:

   ```bash
   curl -s https://seyomi-cordon-cloud.hf.space/healthz
   # → {"ok":true,"version":"0.1.0", ...}
   curl -s -o /dev/null -w "%{http_code}\n" https://seyomi-cordon-cloud.hf.space/
   # → 401  (good: the gate is on)
   curl -s -o /dev/null -w "%{http_code}\n" "https://seyomi-cordon-cloud.hf.space/?t=<DASHBOARD>"
   # → 200  (good: your magic link works)
   ```

## Why public, not private

Hugging Face's "Private Space" flag gates *every* HTTP request to the
Space behind an HF account. That breaks two important flows:

- **Customer ingest.** A customer's agent running `CloudReporter` does
  not have HF cookies. With the Space private, every `POST /v1/ingest`
  fails before our Bearer-auth check runs.
- **Magic-link sharing.** A private Space requires you to add each VC
  as a collaborator — they need an HF account and accept an invite.
  High friction; also exposes who's looking.

The application-layer gate (`CORDON_CLOUD_DASHBOARD_TOKEN`) gives you
strictly better access control: tokens are stateless, you control
rotation, and you can give a VC a clean link to click. Defense in
depth: the bare `.hf.space` URL is unguessable by attackers (32 bytes
of subdomain) and the read API is 401 until they present the token.

If you ever want full HF-level privacy on top of this — e.g., you
don't want the *existence* of the Space publicly discoverable — flip
it to private after the design-partner stage and add VCs as
collaborators. The code path supports both.

## Day-to-day operations

### Granting access to a new VC / prospect

For the closed beta where one shared token is fine:

1. Send the existing magic link:
   `https://seyomi-cordon-cloud.hf.space/?t=<DASHBOARD_TOKEN>`
2. Log the share in your CRM: who, when, why.
3. Send a short context message about what they're looking at and
   when you'll rotate the token next.

### Revoking access

There is no per-user revocation in v0 — that's a paid-tier feature.
To revoke a token (e.g., the call didn't go well or a quarter has
passed):

1. Generate a new token:

   ```bash
   python3 -c 'import secrets; print(secrets.token_urlsafe(32))'
   ```

2. Update `CORDON_CLOUD_DASHBOARD_TOKEN` in the Space's secrets UI.
3. Trigger a Space restart from the Space's settings menu.
4. Re-share the new magic link with the prospects you still want to
   keep. The old link instantly returns 401.

This is intentionally a single rotate-everyone operation — it makes
"audit the room" trivially correct.

### Provisioning a new ingest key (paid tenant)

1. Generate: `python3 -c 'import secrets; print("cdn_" + secrets.token_urlsafe(24))'`
2. Append `<new_key>:<project_name>` to `CORDON_CLOUD_INGEST_KEYS`.
3. Restart the Space.
4. Hand the key to the tenant alongside the `endpoint=` URL.

### Smoke test after every restart

```bash
URL="https://seyomi-cordon-cloud.hf.space"
DT="<dashboard-token>"
IK="<ingest-key>"

# Health
curl -s "$URL/healthz" | jq .

# Gate is on
curl -s -o /dev/null -w "no-token=%{http_code}\n" "$URL/v1/metrics"          # expect 401
curl -s -o /dev/null -w "good-token=%{http_code}\n" "$URL/v1/metrics?t=$DT"  # expect 200

# Ingest works for tenants
curl -s -X POST "$URL/v1/ingest" \
  -H "Authorization: Bearer $IK" \
  -H 'content-type: application/json' \
  -d "{\"events\":[{\"ts\":$(date +%s),\"action_id\":\"runbook-smoke\",\"kind\":\"shell\",\"command_preview\":\"echo runbook\",\"decision\":\"allow\",\"blocked\":false,\"suspicion_score\":0.01}]}"
```

## Upgrade path

The areas of this image you will outgrow first, in roughly this order:

1. **Persistence** (~weeks). Sqlite is fine until your first paying
   customer expects retention across rebuilds. The `EventStore`
   interface in `cloud_server/storage.py` is small (six public
   methods); a Postgres adapter is a one-file change. Use Neon's free
   tier (~10 GB) until you outgrow it.

2. **Multi-tenant projects** (~months). Today, one ingest key maps to
   one project, all projects share the dashboard token. The next
   iteration adds per-project dashboard tokens (or just real users
   via Clerk/Auth0) and per-project audit logs.

3. **Anomaly alerts** (~quarter). When a tenant's block rate spikes
   2× over their 7-day baseline, fire a Slack/PagerDuty webhook.
   The metrics endpoint already has the right shape for this.

4. **Threat-intel feed** (the real moat). Aggregate the typosquat
   strings, exfil patterns, and secret shapes the fleet sees, ship
   them back to every `Guard` as a weekly probe update. This is the
   network effect.

## Local equivalent (for development + offline VC demos)

Everything above also works locally — same image, same env vars,
same gate:

```bash
CORDON_CLOUD_DB=/tmp/cordon-demo.db \
CORDON_CLOUD_INGEST_KEYS="cdn_local:demo" \
CORDON_CLOUD_DASHBOARD_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(16))')" \
.venv/bin/uvicorn cloud_server.app:app --port 7860

# In another shell:
echo "open http://127.0.0.1:7860/?t=$CORDON_CLOUD_DASHBOARD_TOKEN"
```

Run `examples/cloud_reporter.py` against it to populate live events.
The example reads `CORDON_API_KEY` from the environment; export
`cdn_local` (the ingest key you just configured) before running.

## On the `cdn_demo` ingest key

Prior to the 2026-05-12 audit, `cloud_server/app.py` exposed a public
`cdn_demo` ingest key (controlled by `CORDON_CLOUD_ALLOW_DEMO_KEY`)
so the example script worked with zero configuration. We've now
removed that requirement from the example — it errors out cleanly
with `"set CORDON_API_KEY=..."` if no key is configured, and the
`CloudReporter` SDK verifies credentials synchronously on init so a
typoed key surfaces immediately instead of silently dropping events.

The `cdn_demo` fallback in `app.py` remains, but only kicks in when
`CORDON_CLOUD_INGEST_KEYS` is *unset* (i.e. local development). In
production we always set `CORDON_CLOUD_INGEST_KEYS`, so the demo key
is effectively off. If you want a publicly-usable demo key on the
hosted Space again, the right pattern is to make the demo key
*additive* (always-on alongside real keys) and rate-limit the demo
project — not a binary fallback.
