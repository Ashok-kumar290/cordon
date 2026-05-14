# Target design partners — first 20

**Research-quality only.** This list is a starting point for cold
outreach, not a vetted CRM. Before you email anyone here, verify
their current status (are they still in the role, is the company
still shipping the product, are they actively running agents).
Things change fast in this space; this list was assembled
2026-05-13 and should be re-validated weekly until you've worked
through it.

## The profile we're looking for

Filter for *all* of these:

* **Ships AI agents to real users in production.** Not "exploring
  AI." Not "considering an agent platform." Agents that *do
  things* on behalf of users right now.
* **Technical CEO or CTO.** Founder still in the building. Has
  written code in the last 90 days.
* **< 200 employees.** Above that, security review cycles kill
  the partnership timeline.
* **Public signal of caring about safety.** A blog post, an X
  thread, a hiring listing that mentions "AI safety," "agent
  alignment," or "responsible deployment."
* **English-speaking technical leadership.** For the first cohort.

## The list

Twenty candidates across five archetypes, four per archetype. Each
entry has the archetype, the specific company, the public signal
that surfaced them, and the *single concrete* hook the cold email
should lead with. **Verify the company is still active before
sending; some will have pivoted, shut down, or grown past the
profile.**

---

### Archetype A — Coding-agent platforms

These ship agents that *run shell commands and edit files in real
user repos*. Cordon's strongest fit, by far. Failure mode they care
about: the agent destroying user code. The DestructiveShellProbe is
the exact thing they need.

| # | Company | Public signal | Hook |
|---|---|---|---|
| 1 | **Cursor** | Their `cursor-agent` mode runs shell commands in user terminals; public blog discusses sandboxing | "We catch `rm -rf /` before the agent issues it. Demo runs in 90 seconds." |
| 2 | **Cognition (Devin)** | Devin operates a full Linux VM per task; public incidents of destructive commands | "We've documented the four camouflage patterns Devin can't catch with substring matchers. Want the doc?" |
| 3 | **Replit Agent** | Runs in the Replit container, modifying user files | "Per-tenant policy DSL lets your customers carve out `rm -rf node_modules` without dropping to permissive." |
| 4 | **Sourcegraph (Cody / Amp)** | Code-modification agents in enterprise repos | "Our content-aware probes (Python AST, package manifest) catch what regex matchers miss in agent-generated code." |

### Archetype B — Customer-support / sales agents

These run *tool calls* against customer data — CRM lookups, ticket
creation, email drafts. Failure mode: data exfiltration or
unauthorized actions. Cordon's `SecretLeakProbe` + `ExfiltrationProbe`
+ policy DSL are the fit.

| # | Company | Public signal | Hook |
|---|---|---|---|
| 5 | **Decagon** | Enterprise AI customer support; takes actions on tickets | "When your agent decides to refund a $10K invoice, Cordon's policy DSL gates it without code redeploy." |
| 6 | **Sierra** | Customer-experience agents for retail | "We sit between your agent and Stripe. Three lines of policy gives Ops a kill-switch." |
| 7 | **Cresta** | Real-time agent assist in contact centers | "Audit trail for every action your agent proposed but didn't execute. Replayable, deterministic, no LLM in the path." |
| 8 | **Ada** | Customer-service agent platform | "Per-tenant policies mean each of your customers gets their own carve-outs without you forking your codebase." |

### Archetype C — Agent infrastructure (sells to agent builders)

These build the *platform* others build agents on. They feel the
"how do we make our customers' agents safe?" problem acutely. The
fit is white-label probes + the policy DSL as a feature they expose
to their customers.

| # | Company | Public signal | Hook |
|---|---|---|---|
| 9 | **LangChain** | Already integrated; could deepen to first-party | "We have a wrapper + callback; what would you want from a deeper integration? `Guard.from_langgraph(...)` is on the table." |
| 10 | **CrewAI** | Multi-agent framework, no built-in safety layer | "Your users keep asking 'how do I stop my crew from doing X.' Here's the layer. Embed it." |
| 11 | **Mastra** | TypeScript agent framework | "WASM build of the Cordon SDK is on our roadmap — would a Cloudflare-Workers-compatible action firewall move the needle for your customers?" |
| 12 | **Pydantic-AI** | Python agent framework | "Pydantic's structural-typing aesthetic is exactly Cordon's vibe. Want a `pydantic_ai.cordon` extension?" |

### Archetype D — Vertical agents (legal / finance / healthcare)

The buyers most likely to *fund* an action firewall because their
domain has regulators. Failure mode: the agent does something the
domain forbids (sends sensitive data, executes a transaction,
modifies a record). Cordon's audit-trail design is the headline.

| # | Company | Public signal | Hook |
|---|---|---|---|
| 13 | **Harvey** | Legal AI; agents draft and modify documents | "Your audit-trail requirement matches Cordon's design exactly. Every verdict is replayable, deterministic, no LLM in the audit path." |
| 14 | **EvenUp** | Personal-injury legal AI | "Cordon's `package_manifest` probe catches supply-chain attacks in the dependencies your agents propose. Compliance-relevant." |
| 15 | **Hippocratic AI** | Clinical agents | "PII handling is your existential concern. Cordon never sees patient prompts — only the action. That's the architectural answer." |
| 16 | **Mercury** (Finance agent stories) | Business banking with embedded AI | "Action-level audit trails are the SOC2 evidence your customers' security reviews ask for. We generate them by design." |

### Archetype E — Open-source maintainers who'd self-host

The mission-aligned partners. They'll never pay for the hosted
dashboard, but they'll *integrate the SDK*, find bugs we wouldn't,
and write the blog post that brings the next ten partners.

| # | Company | Public signal | Hook |
|---|---|---|---|
| 17 | **HuggingFace (smolagents / transformers agents)** | We're already on their Space platform; bridge to their agent libs | "Want to bundle Cordon as the default safety layer for `smolagents`? It's `from cordon import Guard` and one decorator." |
| 18 | **OpenHands (formerly OpenDevin)** | Open-source autonomous developer | "Open-source coding agents are where the camouflage attacks first hit. We have the threat-model doc that maps to your roadmap." |
| 19 | **AutoGen (Microsoft / community fork)** | Multi-agent research framework | "AutoGen needs a per-agent firewall. Right now it has none. Six lines of code, deterministic, zero latency." |
| 20 | **Letta (memGPT)** | Long-running stateful agents | "Stateful agents accumulate authority over time. The policy DSL lets your users tighten the action surface as the agent learns." |

---

## How to actually use this list

This week:

1. **Pick 5** from the table above where the company is *clearly*
   still active and the hook *clearly* maps to their public roadmap.
2. **Spend 30 minutes per company** verifying current status:
   recent blog post / X activity / GitHub commits / public CTO
   name. If the company has gone quiet, drop it.
3. **Find the right person.** Founder, CTO, or head of safety. Not
   a generic `hello@`.
4. **Send 3-line emails** in the shape `docs/design-partner-
   program.md §"How to enrol"` describes. *They* tell you what
   problem they have; you don't pitch yours.

Goal for the week: **3 replies**. Goal for the month: **3 calls
booked**.

## What I (the assistant) can't verify

The companies on this list were chosen for *category fit* based on
public signals known as of mid-2026. Specifically I cannot verify:

* That any individual company is still active.
* That the CEO/CTO still works there.
* That the product still ships agents (vs. having pivoted).
* That the contact information you can find for them is current.

**You** need to verify each of those before you send anything. The
list saves you the research on "which archetypes matter and what
hook fits each" — it doesn't save you the per-company validation.

---

*Last researched: 2026-05-13. Re-validate before each outreach
cohort.*
