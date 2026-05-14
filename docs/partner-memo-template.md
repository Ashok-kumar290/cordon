# Memorandum of Intent — Cordon design-partner program

**This is not a binding contract.** It is a one-page good-faith
description of the partnership between Cordon (the company) and the
design-partner counterparty named below, intended to be exchanged at
enrolment so both sides have something concrete on file. A real
agreement (MSA + DPA + SLA) arrives when we move out of closed beta
and a paid relationship begins.

Both parties may end the partnership at any time, in writing, with
no obligation beyond data-handling commitments (see §5).

---

## 1. Parties

**Provider:** Cordon (legal entity TBD pre-GA; founders contactable
at `founders@cordon.ai`).

**Partner:** _____________________________________________________

**Partnership start date:** ______________________

## 2. What Cordon provides

* Free access to Cordon Cloud (hosted dashboard at
  `https://seyomi-cordon-cloud.hf.space`) for the duration of the
  partnership.
* A dedicated weekly 30-minute integration slot for the first 8
  weeks.
* Custom probe development for partner-specific attack patterns.
* First-look access to unreleased capabilities (streaming guard,
  WASM build, threat-intel feed) at least 4 weeks before public
  release.
* GA-pricing grandfathering for 12 months when paid plans launch.

## 3. What the partner provides

* Approximately one hour of partner time per week, for 8 weeks,
  via the partner's preferred channel (call, Slack, or email).
* Candid feedback on the SDK, dashboard, threat-model coverage,
  and false positives.
* A one-sentence public testimonial and right to be named as a
  customer, **at the partner's discretion and only after the
  partner is satisfied with the integration** (typically week
  8-12).

## 4. Confidentiality

Each party will protect the other's confidential information with
the same reasonable care it uses for its own. "Confidential
information" specifically excludes: (a) information already public,
(b) information independently developed, (c) verdict telemetry the
partner sends to Cordon Cloud via the documented ingest endpoint
(handling of which is governed by §5).

Cordon will not name the partner publicly without written approval
for each placement.

## 5. Data handling

All verdict telemetry the partner ships to Cordon Cloud is governed
by `docs/data-policy.md` as of the partnership start date, version-
pinned to `cordon-ai==X.Y.Z`. Either party may invoke the documented
export (`GET /v1/events/export`) and delete (`DELETE /v1/events`)
endpoints at any time without notice or cause. On partnership
termination, the partner has 30 days to export and 90 days before
all partner data is purged.

## 6. No warranties, no SLA, no payment

Closed beta. No uptime guarantee. No data warranty. No invoice.
Both sides accept that the software, dashboard, and probes may
break; both sides agree to report breakage and triage in good faith.

## 7. Term and termination

The partnership runs for 6 months from the start date, renewable
by mutual written agreement. Either party may terminate immediately
with written notice. Section 5 (data handling) survives termination.

## 8. Signatures

This memo takes effect when both parties confirm receipt by email.
No physical signature is required; an email reply containing
"acknowledged" or the equivalent suffices.

**For Cordon:**
Name: __________________________  Date: ____________
Email: founders@cordon.ai

**For Partner:**
Name: __________________________  Date: ____________
Email: __________________________

---

*Template version 1.0 · last updated 2026-05-13. Replace
`<Partner Name>` placeholders before exchange. Get a lawyer if you
need a binding contract.*
