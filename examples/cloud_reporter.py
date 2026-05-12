"""End-to-end demo: ship Cordon verdicts to Cordon Cloud.

Runs five representative actions through ``Guard.strict()``, lets the
``CloudReporter`` listener batch the verdicts, and waits for the
background thread to flush before printing a clear summary.

Run it::

    export CORDON_API_KEY=cdn_live_...
    python examples/cloud_reporter.py

Then refresh the dashboard at the URL printed at the bottom — your
events appear within a second or two.

Compared to ``examples/openai_live_demo.py``, this example exercises
the SDK directly without any LLM integration, so it's the fastest way
to convince yourself the telemetry pipe works end-to-end.

History note
------------
Before the 2026-05-12 audit, this example called ``reporter.flush()``
*before* the HTTP POST had actually completed and printed ``sent=0``
even when every event was dropped with HTTP 403. The fix is to call
``reporter.close()`` first (which joins the background thread, so any
in-flight request finishes) *then* read ``reporter.stats()``.
"""

from __future__ import annotations

import os
import sys

from cordon import Action, Guard
from cordon.cloud import CloudReporter


def main() -> int:
    api_key = os.environ.get("CORDON_API_KEY", "").strip()
    if not api_key:
        print(
            "error: CORDON_API_KEY is not set.\n"
            "       Export an ingest key first, e.g.:\n"
            "           export CORDON_API_KEY=cdn_live_xxxxxxxx\n"
            "       (Email founders@cordon.ai for a key.)",
            file=sys.stderr,
        )
        return 2

    reporter = CloudReporter(guard_profile="strict")
    if reporter.auth_ok is False:
        # The constructor already emitted a loud warning to stderr.
        # Bail out with a clear exit code rather than running through
        # five actions only to drop every one of them.
        print(
            "error: cordon-cloud rejected the configured CORDON_API_KEY. "
            "See the warning above.",
            file=sys.stderr,
        )
        return 3

    guard = Guard.strict()
    guard.add_listener(reporter)

    # A representative spread: blocks and allows, shell and write_file.
    actions = [
        Action(
            id="ex-typosquat",
            kind="shell",
            command="pip install -r requirements.txt",
            changes={"requirements.txt": "reqeusts==2.31.0\n"},
        ),
        Action(
            id="ex-secret-leak",
            kind="write_file",
            changes={
                "README.md":
                    "# Notes\n"
                    "OPENAI_API_KEY=sk-proj-9aB3xY1tQwErTyUiOpAsDfGhJkLzXcVbNm12345678\n",
            },
        ),
        Action(
            id="ex-chmod-777",
            kind="shell",
            command="chmod -R 777 /app",
        ),
        Action(
            id="ex-rm-rf-root",
            kind="shell",
            command="rm -rf --no-preserve-root /",
        ),
        Action(
            id="ex-benign-tests",
            kind="shell",
            command="pytest -q tests/",
        ),
    ]

    print()
    for a in actions:
        verdict = guard.check(a)
        print(
            f"  {a.id:<22}  decision={verdict.decision:<6}  "
            f"score={verdict.suspicion_score:.3f}  "
            f"top={verdict.top_reason() or '-'}"
        )

    # `close()` joins the background reporter thread, which guarantees
    # any in-flight HTTP POST has returned (success or fail) before we
    # read stats. `flush()` alone only waits for the *queue* to drain,
    # which is not the same thing.
    reporter.close(timeout=15.0)

    stats = reporter.stats()
    print("\nCloudReporter stats:")
    for k, v in stats.items():
        print(f"  {k:<15} {v}")

    # Loud, single-line outcome — easy to spot in a tail.
    if stats["failed_batches"]:
        print(
            f"\n  ⚠  {stats['failed_batches']} batch(es) failed to ship. "
            f"Check your CORDON_API_KEY and network.",
            file=sys.stderr,
        )
        return 4

    endpoint = stats["endpoint"]
    print(
        f"\nDone — {stats['sent']} events delivered to {endpoint}.\n"
        f"Open the dashboard to see them:\n"
        f"  {endpoint}/"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
