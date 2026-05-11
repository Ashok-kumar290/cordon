---
title: Cordon Playground
emoji: 🛡️
colorFrom: gray
colorTo: indigo
sdk: docker
app_port: 7860
pinned: true
license: apache-2.0
short_description: Pre-execution control for AI agents — judge actions before they run.
---

# Cordon — live playground

> Lakera judges what the model **said**. Cordon judges what the model is **about to do**.

This Space hosts the live FastAPI backend for the
[Cordon](https://github.com/Ashok-kumar290/cordon) landing page. It exposes
three endpoints used by the static playground at
[ashok-kumar290.github.io/cordon](https://ashok-kumar290.github.io/cordon/):

| Method | Path             | What it does                                 |
| ------ | ---------------- | -------------------------------------------- |
| GET    | `/healthz`       | Liveness check.                              |
| GET    | `/api/examples`  | Showcase actions powering the playground UI. |
| POST   | `/api/check`     | Judge an `Action` with `Guard.{strict,default,permissive}`. |
| GET    | `/api/benchmark` | Canonical comparative-benchmark numbers.     |

Built from the same `cordon-ai` PyPI package end users install
locally — so every verdict served here is byte-identical to what
their own machines compute.

## Try it

Pick a showcase action on the
[playground page](https://ashok-kumar290.github.io/cordon/#playground)
and watch the verdict appear. Or hit the API directly:

```bash
curl -X POST https://ashok-kumar290-cordon-playground.hf.space/api/check \
     -H 'content-type: application/json' \
     -d '{
       "kind": "shell",
       "command": "pip install -r requirements.txt",
       "changes": {"requirements.txt": "reqeusts==2.31.0\n"},
       "profile": "strict"
     }'
```

```json
{
  "decision": "block",
  "blocked": true,
  "suspicion_score": 0.95,
  "top_reason": "1 supply-chain indicator(s): 'reqeusts' is 2 edit(s) from 'requests' (likely typosquat)",
  "probes_triggered": [
    {
      "probe": "typosquat",
      "severity": "critical",
      "suspicion_score": 0.95,
      "evidence": "1 supply-chain indicator(s): ..."
    }
  ],
  "profile": "strict",
  "elapsed_ms": 0.21
}
```

## Rate limit

The public endpoint is throttled to **30 checks per minute per IP**.
For unlimited evaluations run Cordon locally — that's the whole
point of the project:

```bash
pip install cordon-ai
```

## License

Apache-2.0. Source: [github.com/Ashok-kumar290/cordon](https://github.com/Ashok-kumar290/cordon)
