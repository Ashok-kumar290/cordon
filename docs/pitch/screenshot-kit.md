# Cordon — screenshot / X-post kit

Four self-contained scenes for screenshots, X (Twitter) threads,
Hacker News "Show HN" posts, and design-partner emails. Each scene
has:

* **The setup line** — the one-sentence frame you put above the image.
* **The terminal commands** — exact strings to paste.
* **The expected output** — what should be visible in the screenshot.
* **The caption** — the one-sentence frame to put below the image.

Keep your terminal at **14 pt minimum**, dark theme, no command
history visible above the prompt. macOS Terminal "Pro" or
iTerm2 "Solarized Dark" both photograph well.

---

## Scene 1 — "pip install, then block `rm -rf /` in five seconds"

The hero shot. This is the one that goes in the X thread's first
tweet and at the top of the docs landing page.

**Setup line:**
> *Six lines of Python. Real OpenAI call. Cordon blocks
> `rm -rf --no-preserve-root /` before it leaves the chat completion.*

**Terminal:**

```bash
pip install cordon-ai
OPENAI_API_KEY=sk-or-v1-... OPENAI_BASE_URL=https://openrouter.ai/api/v1 \
    .venv/bin/python examples/openai_live_demo.py
```

**Expected output** (full screenshot frame):

```
─── Scenario 1: pytest -q ────────────────────────────────────────
✓ ALLOW · 0.2 ms · No probes triggered.

─── Scenario 2: pip install requestz ─────────────────────────────
⚑ FLAG  · 0.3 ms · typosquat (suspicious) — likely typosquat: 'requestz' ≈ 'requests'

─── Scenario 3: rm -rf --no-preserve-root / ──────────────────────
✗ BLOCK · 0.1 ms · destructive_shell (critical) — Recursive force-delete of a root-ish path
                  · explanation includes the SDK version, ts, and action_id
```

**Caption:**
> *Three live OpenAI tool calls. One allow, one flag, one block.
> Zero LLM in the verdict path. Zero training data leaked. All in
> a 6-second screen capture.*

---

## Scene 2 — "policy DSL, three-line carve-out"

For the audience that asks "yeah but our agents *need* to run
`rm -rf node_modules`." This is the *answer*. Goes in the X thread
as tweet 3 or 4.

**Setup line:**
> *Strict by default. Three lines to carve out the things your
> agents legitimately need.*

**Terminal:**

```bash
.venv/bin/python -c '
from cordon import Action, Guard

guard = Guard.from_policy("""
    profile: strict

    allow when command_starts_with: \"rm -rf node_modules\"
    allow when command_starts_with: \"rm -rf ./build\"

    flag  when probe: typosquat
""")

for cmd in ["rm -rf node_modules", "rm -rf --no-preserve-root /", "pip install requestz"]:
    v = guard.check(Action(kind="shell", command=cmd))
    print(f"  {v.decision.upper():<5}  {cmd}")
'
```

**Expected output:**

```
  ALLOW  rm -rf node_modules
  BLOCK  rm -rf --no-preserve-root /
  FLAG   pip install requestz
```

**Caption:**
> *The policy DSL ships in `cordon-ai==0.2.2`. Same syntax in the
> SDK, the REST API, and the dashboard editor. Three lines, no
> redeploys.*

---

## Scene 3 — "dashboard with live verdict stream"

For partners who care about audit trails and SOC2. This is the
screenshot for the demo / pitch deck title slide.

**Setup line:**
> *Every verdict your agents produce, in real time, with the exact
> probe trail that fired. Median 0.2 ms. Replayable three weeks later.*

**How to capture:**

1. Open <https://seyomi-cordon-cloud.hf.space/dashboard?t=YOUR_TOKEN>.
2. Run `.venv/bin/python examples/openai_live_demo.py` in another
   terminal so 3 fresh verdicts land in the top of the table.
3. Crop the screenshot to the **top 800 px of the page** —
   shows the live ALLOW/FLAG/BLOCK row, the metric strip, and the
   sparkline. Don't include the policy editor; that's Scene 4.
4. Blur out the dashboard token in the URL bar.

**Caption:**
> *No grep. No tail -f. No "wait, where did that verdict come from?"
> Every blocked action is a hyperlinked row with the full probe
> trail, the action_id, and the SDK version that produced it.*

---

## Scene 4 — "policy editor with live syntax validation"

For partners who push back with "I don't want yet-another DSL." This
shows the DSL editor with the live validate roundtrip — like Monaco
for a 6-keyword grammar.

**Setup line:**
> *The policy editor is type-as-you-go validated. Save publishes to
> every agent on your account in one round-trip.*

**How to capture:**

1. Open the dashboard, scroll to `#policies`.
2. Paste this *deliberately broken* policy to capture the error state:

   ```
   profile: strict

   allow when command_starts_with: "rm -rf node_modules"
   block when path_endswith: "/etc/shadow"
   ```

3. Wait for the status line to turn red and say
   `line 4: unknown predicate field 'path_endswith'`.
4. Take the screenshot. The red line + the line number + the
   `validate` button is the story.

**Caption:**
> *Editor-grade error messages. `PolicyParseError(line=4, …)` flows
> from the SDK → the REST API → the dashboard line indicator
> verbatim, so what your CI sees is what the operator sees.*

---

## Sequencing recommendations

* **X thread:** Scene 1 → Scene 3 → Scene 2 → Scene 4. Hero shot
  first, dashboard for credibility, then policies + editor for
  depth.
* **HN post:** Lead with Scene 1 as a static image; everything
  else lives in the comment or the linked write-up. HN readers
  skim images, read titles, and judge by the first 80 chars.
* **Design-partner email:** Scenes 1 and 3 inline; 2 and 4 as
  links to the docs. Three images max in an outreach email.
* **Pitch deck title slide:** Scene 3 cropped, dark theme, no
  caption — let it breathe.
