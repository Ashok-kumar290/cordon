"""Two-line Cordon Cloud wiring.

Run:

    pip install cordon-ai
    python examples/cloud_reporter.py

The script sends a handful of varied verdicts to the hosted demo at
``https://seyomi-cordon-cloud.hf.space`` under the public project key
``cdn_demo``. Refresh the dashboard at that URL — your events appear
with an enter animation at the top of the live table.

For your own project, replace ``cdn_demo`` with a tenant-specific key
and (optionally) the ``endpoint=`` with your self-hosted Cordon Cloud.
"""

from __future__ import annotations

import time

from cordon import Action, Guard
from cordon.cloud import CloudReporter


def main() -> None:
    reporter = CloudReporter(
        api_key="cdn_demo",
        guard_profile="strict",
    )
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
            id="ex-benign-install",
            kind="shell",
            command="pip install -r requirements.txt",
            changes={"requirements.txt": "requests==2.31.0\n"},
        ),
        Action(
            id="ex-benign-tests",
            kind="shell",
            command="pytest -q tests/",
        ),
    ]

    for a in actions:
        verdict = guard.check(a)
        print(f"  {a.id:<22}  decision={verdict.decision:<6}  "
              f"score={verdict.suspicion_score:.3f}  "
              f"top={verdict.top_reason() or '-'}")

    # Block until the background reporter thread drains its queue, then
    # stop it cleanly. Safe to skip on long-running agents — the thread
    # is a daemon and will go away on process exit.
    reporter.flush(timeout=5.0)
    stats = reporter.stats()
    print("\nCloudReporter stats:")
    for k, v in stats.items():
        print(f"  {k:<15} {v}")
    reporter.close()

    print(
        "\nDone. Open the dashboard to see your events:\n"
        "  https://seyomi-cordon-cloud.hf.space/"
    )


if __name__ == "__main__":
    main()
