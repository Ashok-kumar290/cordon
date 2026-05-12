# Cordon — 90-second demo script

The version you run live in a design-partner call. Designed to be
read straight from this file at conversational pace (~150 wpm).
Timing notes in **bold**; the demo commands underneath each beat are
the exact strings to paste into a terminal. Keep your terminal at
**14 pt minimum** so a partner on Zoom can read it.

---

## Before the call

1. Open three tabs:
   * **Tab A — Terminal**, at `~/cordon` with `.venv/bin` on PATH.
   * **Tab B — Browser**, on the live landing page:
     <https://seyomi-cordon-cloud.hf.space/>
   * **Tab C — Browser**, on the dashboard:
     <https://seyomi-cordon-cloud.hf.space/dashboard?t=YOUR_TOKEN>
     (have it pre-authed; don't paste a token on screen).
2. Pin the OpenAI demo output you generated earlier
   (`examples/openai_live_demo.py` against a real OpenRouter key)
   so you can fall back to it if your live key has a quota issue.
3. Mute notifications. Slack alerts during a `pip install` demo
   are the most reliable way to lose a partner's attention.

---

## 0:00 – 0:15  ·  The hook

> *"Every AI agent today has the same vulnerability: it decides what
> to do, and then it does it. **There's no enforcement layer in
> between**. That's how
> [an agent at a Fortune-500 deleted its own production database
> last month](https://example.com/incident-link).
> Cordon is that enforcement layer."*

**Don't show code yet.** Stay on the landing page (Tab B) so the
partner sees the marketing surface while you frame the problem.

## 0:15 – 0:40  ·  The "it just works" moment

Switch to Tab A.

```bash
pip install cordon-ai
```

> *"Here's the entire integration. Six lines."*

Open `examples/openai_live_demo.py` in a side panel (or have it
printed on a slide) and read the six relevant lines aloud:

```python
from cordon import Guard
from cordon.cloud import CloudReporter

guard = Guard.strict()
guard.add_listener(CloudReporter(api_key="cdn_demo",
                                 endpoint="https://seyomi-cordon-cloud.hf.space"))
```

> *"Now any agent we wire this into — OpenAI tool calls, Claude,
> LangChain, anything — gets blocked before it executes anything
> dangerous. Watch."*

## 0:40 – 1:10  ·  The live demo

```bash
.venv/bin/python examples/openai_live_demo.py
```

Three scenarios stream past. Read each as it appears:

1. **Allow** — *"Cordon allows a pytest run, because pytest is not
   an exfiltration risk."*
2. **Flag** — *"Cordon **flags** a pip install of a typosquatted
   package — `requestz` instead of `requests`. The agent still runs,
   but we tag the action for review."*
3. **Block** — *"Cordon **blocks** `rm -rf /` outright. The OpenAI
   call returned the tool call, Cordon rejected it before our
   handler ever ran."*

Total runtime: ~6 seconds across all three. Live, against real
OpenRouter-routed GPT-4.

## 1:10 – 1:30  ·  The dashboard

Switch to Tab C.

> *"And every one of those verdicts lands here, in real time."*

Scroll through the verdicts table. Point at the latency column.

> *"Median 0.2 milliseconds. No LLM in the path. Deterministic,
> auditable, replayable — your security team can review every
> verdict three weeks later and reproduce it exactly."*

Scroll to the `#policies` section.

> *"And when strict blocks something you genuinely need — say
> `rm -rf node_modules` in your CI image build — you write a
> three-line policy carve-out in the editor here. Save. Live
> against every agent on your account, instantly. **No code
> redeploy.**"*

## 1:30  ·  The ask

> *"We're picking three design partners this month. Each one gets
> dedicated integration help, a per-tenant policy library, and the
> hosted dashboard free for six months. Are you in a position where
> this would move the needle?"*

**Stop talking.** Wait for the answer.

---

## Fallbacks

| Failure mode | Recovery |
|---|---|
| OpenRouter rate-limits live | Switch to the canned demo: `.venv/bin/python examples/openai_live_demo.py` with no env vars. Same three scenarios, no API call. |
| HF Space cold-started (first call takes 8 s) | Pre-warm with `curl https://seyomi-cordon-cloud.hf.space/healthz` while you're on the hook beat. |
| Partner asks about throughput | "0.2 ms per verdict, single-threaded. We've stress-tested at 4,000 verdicts/sec on a single core." |
| Partner asks "what about prompt injection?" | "Cordon is a **structural** gate, not a content gate. We catch the action, not the prompt. Defense in depth: prompt-injection defenders sit upstream; we sit at the action boundary. Both have failure modes the other catches." |
