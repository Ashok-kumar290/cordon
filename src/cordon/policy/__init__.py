"""Per-tenant policy DSL for Cordon.

Customers consistently ask for the same kind of customization: *"the
strict profile blocks something we genuinely need (e.g. ``rm -rf
node_modules`` in our CI image build) — give us a way to carve out a
narrow exception without dropping the whole profile to permissive."*

That's what this module is for. A policy is a small text document
that declares a **base profile** plus an ordered list of **override
rules**::

    profile: strict

    # Exceptions our CI image actually needs.
    allow when command_starts_with: "rm -rf node_modules"
    allow when command_starts_with: "rm -rf ./build"
    allow when command_starts_with: "rm -rf /tmp/"

    # Promote a known-risky pattern to a hard block, even though the
    # default thresholds would only flag it.
    block when path_starts_with: "/etc/" and kind: file

    # Downgrade an entire probe to flag-only — useful when a probe
    # has known false positives in your environment but you still
    # want the dashboard signal.
    flag when probe: typosquat

Rules apply top-to-bottom against the *verdict the base profile
produces*; the first matching rule mutates the decision. Use
:func:`parse` to turn a string into a :class:`Policy`, then either
hand it to :func:`apply_policy` for ad-hoc use, or pass it through
:meth:`cordon.Guard.from_policy` for a Guard that does this
automatically on every check.

This module ships as part of the public ``cordon`` SDK (no extra
install). The cloud server uses it to enforce per-project rules
configured through the dashboard.
"""

from __future__ import annotations

from cordon.policy.errors import PolicyParseError
from cordon.policy.parser import parse
from cordon.policy.runtime import apply_policy
from cordon.policy.types import Policy, Predicate, Rule, RuleAction

__all__ = [
    "Policy",
    "PolicyParseError",
    "Predicate",
    "Rule",
    "RuleAction",
    "apply_policy",
    "parse",
]
