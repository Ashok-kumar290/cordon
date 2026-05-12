"""Policy DSL errors.

Distinct from :class:`ValueError` so cloud-server endpoints can render
a clean ``400 Bad Request`` with the exact line number and the
offending token, instead of a generic 500 plus a stack trace.
"""

from __future__ import annotations


class PolicyParseError(ValueError):
    """Raised when a policy document can't be parsed.

    Carries a ``line`` (1-indexed) and the offending ``snippet`` so
    callers can produce IDE-style error messages — and so the
    dashboard editor can underline the bad line.

    Args:
        message: Human-readable explanation.
        line: 1-indexed source line.
        snippet: Substring of the line that triggered the error.
            Truncated to 80 chars by the constructor.
    """

    def __init__(self, message: str, *, line: int, snippet: str = "") -> None:
        self.line = int(line)
        self.snippet = (snippet or "")[:80]
        # Compose a single-line representation for ``str(err)`` so
        # operators tailing logs immediately see line + context.
        prefix = f"line {self.line}: "
        if self.snippet:
            prefix += f"{self.snippet!r}: "
        super().__init__(prefix + message)
