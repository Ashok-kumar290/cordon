---
title: Cordon Cloud
emoji: 📊
colorFrom: indigo
colorTo: gray
sdk: docker
app_port: 7860
pinned: true
license: apache-2.0
short_description: Live telemetry for AI agent verdicts.
---

# Cordon Cloud — live agent verdict dashboard

> What did your AI agents *try* to do today, and what stopped them?

This Space is the hosted backend + dashboard for
[Cordon](https://github.com/Ashok-kumar290/cordon) — the pre-execution
control layer for AI agents. It receives verdict events from
`cordon.cloud.CloudReporter` (a two-line addition to any Cordon-protected
agent) and shows them on a real-time dashboard.

## Endpoints

| Method | Path                | What it does                              |
| ------ | ------------------- | ----------------------------------------- |
| GET    | `/`                 | Live dashboard.                           |
| GET    | `/healthz`          | Liveness probe.                           |
| POST   | `/v1/ingest`        | Receive a batch of events. `Authorization: Bearer <api_key>` required. |
| GET    | `/v1/events`        | Paged list of recent events (read-only). |
| GET    | `/v1/events/{id}`   | Single event with full evidence + probes. |
| GET    | `/v1/metrics`       | Aggregates over a rolling time window.    |

## Try it without writing code

```bash
curl -X POST https://seyomi-cordon-cloud.hf.space/v1/ingest \
     -H 'Authorization: Bearer cdn_demo' \
     -H 'content-type: application/json' \
     -d '{
       "events": [{
         "ts": '"$(date +%s)"',
         "action_id": "manual-test-1",
         "kind": "shell",
         "command_preview": "rm -rf /etc/passwd",
         "decision": "block",
         "blocked": true,
         "suspicion_score": 0.97,
         "top_probe": "exfiltration",
         "top_severity": "critical",
         "top_evidence": "shell deletes a system file"
       }]
     }'
```

Refresh the dashboard at the top of this page; your event appears with
an enter animation at the top of the live table.

## SDK usage

```python
# pip install cordon-ai
from cordon import Guard
from cordon.cloud import CloudReporter

guard = Guard.strict()
guard.add_listener(CloudReporter(
    api_key="cdn_demo",  # or your tenant key in production
    endpoint="https://seyomi-cordon-cloud.hf.space",
))
# every guard.check() now ships a verdict to this dashboard,
# from a background thread, without blocking your agent.
```

## What's the demo data?

On a cold start with an empty database, the server seeds 240
representative verdicts spread across the last 24 hours so the
dashboard never shows an empty state. Once real ingest traffic
arrives under project `default` (or any other configured project),
that traffic is shown alongside the seeded demo events.

## Limitations of the free Space

- **Ephemeral storage.** The sqlite file is reset on every container
  rebuild. For persistent retention, the same image accepts
  `CORDON_CLOUD_DB=postgresql://...` (TODO).
- **Single instance.** Free Spaces run one replica. Rate limit is
  bounded by uvicorn's defaults.
- **One auth tenant.** Multi-tenant API keys and SSO ship with the
  paid tier.

## License

Apache-2.0. Source: <https://github.com/Ashok-kumar290/cordon>
