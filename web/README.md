# Cordon — landing page & live playground

A single FastAPI app that serves the Cordon marketing page plus a live
playground backed by the published `cordon-ai` PyPI package.

```
web/
├── app.py                 # FastAPI app + /api/check + rate limiting
├── templates/index.html   # Hero, comparative table, playground UI
├── static/main.js         # Playground client logic (vanilla JS)
├── Dockerfile             # Production image
├── fly.toml               # Fly.io deploy config
└── README.md              # This file
```

## Run locally

```bash
# from the repo root
pip install -e ".[web]" \
    || pip install fastapi "uvicorn[standard]" pydantic cordon-ai

uvicorn web.app:app --reload --port 8080
```

Then open <http://localhost:8080>.

### Smoke test the API

```bash
curl -s -X POST http://localhost:8080/api/check \
  -H 'content-type: application/json' \
  -d '{
    "kind": "shell",
    "command": "pip install -r requirements.txt",
    "changes": {"requirements.txt": "reqeusts==2.31.0\n"},
    "profile": "strict"
  }' | jq
```

You should get `"blocked": true` with `cordon.typosquat` in
`probes_triggered`.

## Deploy to Fly.io

One-time:

```bash
fly auth login
fly launch --no-deploy --copy-config --name cordon-demo --config web/fly.toml
fly secrets set --config web/fly.toml -a cordon-demo  # (no secrets needed yet)
```

Subsequent deploys:

```bash
# Build context is the repo root so the Dockerfile can `COPY web/`.
fly deploy --remote-only --config web/fly.toml --dockerfile web/Dockerfile .
```

Public URL: `https://cordon-demo.fly.dev`.

## Deploy with plain Docker

```bash
docker build -t cordon-web -f web/Dockerfile .
docker run --rm -p 8080:8080 cordon-web
```

## Surface area

| Route             | Purpose                                              |
| ----------------- | ---------------------------------------------------- |
| `GET /`           | Marketing page (Tailwind via CDN)                    |
| `GET /static/*`   | Frontend assets                                      |
| `GET /healthz`    | Liveness check (used by Fly)                         |
| `GET /api/docs`   | FastAPI auto-docs                                    |
| `GET /api/examples`  | Showcase actions for the playground               |
| `GET /api/benchmark` | Hard-coded comparative numbers (from a real run)  |
| `POST /api/check` | Run a `Guard` against a user-submitted action        |

## Sandboxing notes

The playground is intentionally narrow:

- Submitted actions are **never executed** — only inspected by Cordon.
- `/api/check` is rate-limited per IP via an in-memory token bucket
  (30 requests / minute). Run `pip install cordon-ai` locally to lift
  the limit.
- `command` is capped at 4 KB, each file body at 8 KB, and the
  `reads`/`changes` lists at 50 entries.
- A catch-all exception handler ensures we never leak tracebacks to
  unauthenticated callers.

## Updating the comparative table

The numbers shown in `/api/benchmark` are constants in `web/app.py`,
sourced from an archived run in
`docs/benchmarks/comparative-2026-05-11.json`. To refresh them:

```bash
cordon compare \
    --comparators all \
    --lakera-key "$LAKERA_KEY" \
    --llm-judge-key "$OPENROUTER_KEY" \
    --llm-judge-endpoint https://openrouter.ai/api/v1/chat/completions \
    --llm-judge-model openai/gpt-4o-mini \
    --json > docs/benchmarks/comparative-$(date -I).json
```

Then update the constants in `benchmark_summary()` and redeploy.
