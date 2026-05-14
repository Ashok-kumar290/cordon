# Cordon design-partner program

If you're shipping AI agents to real users and one bug away from a
public incident, the design-partner program is for you. It's the
first cohort of teams getting Cordon in production. Three slots are
open this month.

## What we'll do for you

* **Free hosted dashboard** for the duration of the partnership
  (6 months minimum, renewable). Includes the per-tenant policy
  editor, real-time verdict stream, export/delete endpoints, and the
  full 11-probe Semantic + Content Guard suite.
* **Dedicated integration help.** A weekly 30-minute slot for the
  first 8 weeks — usually a screenshare where we wire Cordon into
  whatever agent framework you're running (OpenAI tool calls,
  Anthropic, LangChain wrapper or callback, LangGraph, anything
  custom). We've seen most stacks; what we haven't, we ship a probe
  for during the partnership.
* **Custom probes for your domain.** If your agents fail in a way
  the existing 11 probes don't catch — and they will, every domain
  has a long-tail — we ship a new probe. Average turnaround in the
  first cohort: 36 hours from "here's the attack" to "it's in the
  next release."
* **First-look at unreleased capabilities.** Streaming guard,
  WASM build for Cloudflare Workers, threat-intel feed for the
  package manifest probe — partners see these 4-8 weeks before
  public release.
* **A public testimonial slot** when you're ready (not a condition,
  see below).

## What we ask in return

Three things. None of them is "a check."

1. **One hour a week, for 8 weeks.** Either a live call or async
   slack. You bring real attacks, edge cases, false positives, or
   "the dashboard told me X but I expected Y" reports; we close
   them.
2. **Candid feedback.** "This is bad, fix it" is more useful than
   "this is interesting." We optimise for partners who tell us
   what's broken, not what's nice.
3. **An eventual public quote.** When you're satisfied with the
   integration — typically 8-12 weeks in — you give us a one-
   sentence quote we can put on the landing page, and the right to
   mention you as a customer in our pitch. *Eventually*, not on
   day one. Not a condition of enrolment; a condition of mutual
   success.

We deliberately don't ask for payment. The partnership is the
testimonial; the testimonial is what unlocks paying customers; the
paying customers are how we get to GA. That's the exchange.

## What we'll send you when you say yes

Within 24 hours of your "yes":

* A one-page **Memorandum of Intent** (not a binding contract; a
  shared description of the partnership). The standard text is
  available at `docs/partner-memo-template.md`. It exists so your
  legal team has *something* to file when they ask "have we signed
  anything?" and the answer to "is this binding" is "no, it's a
  good-faith memo until we both want a real contract."
* A **per-tenant ingest API key** and a **dashboard token** for
  Cordon Cloud, plus access to a private Slack Connect channel
  for async questions.
* Read access to the **`docs/threat-model.md`** document and the
  **`docs/data-policy.md`** document, both of which are public but
  worth your security team reviewing before integration.
* A **calendar link** for the first integration call.

## What we won't do

Equally important — these are the things some "design-partner"
programs do that we think are anti-pattern:

* We won't ask for case-study rights up front. Mutual success first.
* We won't lock you into pricing tiers we haven't earned yet.
  Closed-beta pricing is $0; when we move to GA, partners get
  grandfathered pricing for 12 months.
* We won't use you as a sales reference without your written
  approval, every time. You won't see "X uses Cordon" anywhere
  unless you've personally said yes to that exact placement.
* We won't ship features without partner pull. If the existing
  11 probes plus per-tenant policy cover your case, we'll spend
  our time on partner success calls, not pre-emptive features.

## Who this isn't for

Be honest about fit. The program is **not** for you if:

* You're evaluating "AI security vendors" generally and want a
  comparison spreadsheet. Cordon is one layer; we won't pretend
  to be the others.
* You haven't shipped agents to real users yet. We need real
  attack data to make this useful. Build the agent first, come
  back when it has traffic.
* You need a SOC 2 report on day one. Closed beta is closed beta;
  we have an evidence binder, not an attestation. Talk to us at GA.

If any of those describes you, the **public SDK is free, the
playground is live, and the GitHub repo is open** — go build with
those, and come back when the fit changes.

## How to enrol

One email to **founders@cordon.ai** with three lines:

1. The agent product you're shipping (one URL or one paragraph).
2. The closest agent-induced incident you can describe — public or
   private, real or hypothetical. *We're filtering for "can name
   the threat" not "have a CVE."*
3. The single capability that would make Cordon useful to you in
   the next 30 days.

We reply within 24 hours during business days, US/India hours
combined. If the fit is good, we book a 30-minute scoping call
within the same week.

---

*Open slots this cohort: 3. Last touched: 2026-05-13. Matches
`cordon-ai==0.2.3`.*
