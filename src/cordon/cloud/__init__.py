"""Cordon Cloud SDK — ship every verdict to a hosted dashboard.

A two-line addition to any agent::

    from cordon import Guard
    from cordon.cloud import CloudReporter

    guard = Guard.strict()
    guard.add_listener(CloudReporter(api_key="cdn_..."))

What you get:

* Real-time event ingestion to ``https://cloud.cordon.ai`` (or any
  self-hosted Cordon Cloud instance via ``endpoint=``).
* Aggregated metrics: events/min, block rate, top probes, p50/p99
  latency.
* Forensics: searchable history of every blocked action, with the
  triggering probe and full evidence string.

Design contract
---------------

* **Never blocks the agent.** Verdicts are buffered in-memory and
  flushed by a background thread. The listener call returns in
  microseconds.
* **Never raises.** Network errors, timeouts, server 5xx — every
  failure is swallowed (and surfaced via ``warnings``).
* **PII-safe by default.** ``Action.command`` and file bodies are
  truncated; you can opt into raw bodies with
  ``CloudReporter(include_bodies=True)`` only when you control both
  ends.
"""

from cordon.cloud.reporter import CloudReporter

__all__ = ["CloudReporter"]
