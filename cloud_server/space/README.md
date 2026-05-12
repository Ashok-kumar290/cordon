---
title: Cordon Cloud
emoji: 📊
colorFrom: indigo
colorTo: gray
sdk: docker
app_port: 7860
pinned: true
license: apache-2.0
short_description: Cordon Cloud (closed beta) — design-partner access.
---

# Cordon Cloud — closed beta

> What did your AI agents *try* to do today, and what stopped them?

This Space is the hosted backend + dashboard for
[Cordon](https://github.com/Ashok-kumar290/cordon) — the action firewall
for AI agents.

**The dashboard at `/` is gated.** Visiting the bare URL returns an
"Access required" page; design-partner investors and prospects are
given a magic link of the form `/?t=<token>`. The token is rotated
out of band. To request access, email **founders@cordon.ai**.

The ingest endpoint (`POST /v1/ingest`) is reachable without the
dashboard token — customer agents authenticate with their own
per-tenant Bearer API key. Same Space, two different audiences, two
different secrets.

## Endpoints

| Method | Path                | Auth                                  | Audience               |
| ------ | ------------------- | ------------------------------------- | ---------------------- |
| GET    | `/`                 | `?t=<dashboard-token>` (or header)    | Design partners        |
| GET    | `/v1/events`        | `?t=<dashboard-token>` (or header)    | Design partners        |
| GET    | `/v1/events/{id}`   | `?t=<dashboard-token>` (or header)    | Design partners        |
| GET    | `/v1/metrics`       | `?t=<dashboard-token>` (or header)    | Design partners        |
| POST   | `/v1/ingest`        | `Authorization: Bearer <api-key>`     | Customer agents (SDK)  |
| GET    | `/healthz`          | none                                  | Uptime monitors        |

The header form is `X-Cordon-Dashboard-Token: <token>` — prefer it
for scripted API access so the token isn't logged in URLs.

The dashboard JS reads `?t=` once on page load and forwards it on
every `/v1/*` call, so once you're in via the magic link, navigation
just works.

## SDK wiring (after you've been provisioned a key)

```python
# pip install cordon-ai
from cordon import Guard
from cordon.cloud import CloudReporter

guard = Guard.strict()
guard.add_listener(CloudReporter(
    api_key="cdn_<your-tenant>",                # provisioned per tenant
    endpoint="https://seyomi-cordon-cloud.hf.space",
))
```

Every `guard.check()` ships a verdict to this dashboard from a
background thread, without blocking your agent.

## What's in the dashboard right now

On a cold start with an empty database, the server seeds 240
representative verdicts spread across the last 24 hours so the
dashboard never shows an empty state during a sales call. Once real
ingest traffic arrives under a project name configured in
`CORDON_CLOUD_INGEST_KEYS`, that traffic appears alongside (or in
place of) the seeded demo events.

## Caveats this beta deliberately ships with

- **Ephemeral storage.** The sqlite file is reset on every container
  rebuild. Persistent retention (`CORDON_CLOUD_DB=postgresql://...`)
  is a paid-tier upgrade.
- **One shared dashboard token.** Per-VC tokens + audit logs ship
  with the paid tier.
- **No anomaly alerts yet.** Slack/PagerDuty webhooks are next.

## License

Apache-2.0. Source: <https://github.com/Ashok-kumar290/cordon>
