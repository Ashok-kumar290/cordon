"""Line-based parser for the Cordon policy DSL.

Grammar (informal, in pseudo-EBNF)::

    policy   = profile_line { rule_line | blank_or_comment } ;
    profile_line = "profile:" WS profile_name ;
    rule_line    = action "when" predicate { "and" predicate } ;
    action       = "allow" | "flag" | "block" ;
    predicate    = field ":" WS value ;
    field        = "command_starts_with" | "command_contains"
                 | "path_starts_with"    | "path_contains"
                 | "probe"               | "kind" ;
    value        = '"' STRING '"' | BARE_WORD ;
    profile_name = "strict" | "default" | "permissive" ;
    blank_or_comment = ( "#" REST_OF_LINE | "" ) ;

Design choices
--------------

* **Hand-written, ~150 lines.** A real LL/LR parser is overkill for
  a six-keyword grammar; this stays trivial to read, modify, and
  produce IDE-style errors from.

* **Line-based.** Every line is either the profile declaration, a
  rule, a comment, or blank. No multi-line constructs — that means
  the dashboard editor can underline the exact bad line without
  span-tracking gymnastics.

* **Tight error messages.** Every :class:`PolicyParseError` carries
  a 1-indexed source line and a short snippet of the offending text.
  See :class:`cordon.policy.errors.PolicyParseError`.

* **Tolerant whitespace.** Tokens are separated by any run of
  spaces or tabs; trailing whitespace on a line is ignored. Inline
  comments (``#`` outside a string) terminate the line.
"""

from __future__ import annotations

import re

from cordon.policy.errors import PolicyParseError
from cordon.policy.types import (
    PREDICATE_FIELDS,
    PROFILES,
    Policy,
    Predicate,
    Rule,
    RuleAction,
)

# ─── Public API ──────────────────────────────────────────────────────────────


def parse(text: str) -> Policy:
    """Parse a policy document string into a :class:`Policy`.

    Args:
        text: The full text of the policy. May contain blank lines
            and ``#``-prefixed comments anywhere; the first non-blank
            non-comment line must be the ``profile: <name>``
            declaration.

    Returns:
        A fully-validated :class:`Policy`.

    Raises:
        PolicyParseError: On any syntactic or semantic error, with
            line number and snippet attached.
    """
    if not isinstance(text, str):
        raise PolicyParseError(
            "policy text must be a string", line=0, snippet=type(text).__name__
        )

    profile: str | None = None
    rules: list[Rule] = []

    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        line = _strip_inline_comment(raw_line).strip()
        if not line:
            continue

        # First non-blank non-comment line: must be ``profile: <name>``.
        if profile is None:
            profile = _parse_profile_line(line, lineno=lineno)
            continue

        rules.append(_parse_rule_line(line, lineno=lineno))

    if profile is None:
        raise PolicyParseError(
            "policy must declare a base profile as its first non-comment line, "
            "e.g. `profile: strict`",
            line=0,
        )

    return Policy(profile=profile, rules=rules, source=text)


# ─── Lexer helpers ──────────────────────────────────────────────────────────


_QUOTED_STRING = re.compile(r'"((?:[^"\\]|\\.)*)"')


def _strip_inline_comment(line: str) -> str:
    """Strip a trailing ``# comment``, respecting quoted strings.

    Naive ``str.split('#', 1)`` would break on
    ``command_starts_with: "rm #stuff"``; this implementation walks
    the line a character at a time and only honours ``#`` when not
    inside a double-quoted string.
    """
    in_quote = False
    escape = False
    for i, ch in enumerate(line):
        if escape:
            escape = False
            continue
        if ch == "\\" and in_quote:
            escape = True
            continue
        if ch == '"':
            in_quote = not in_quote
            continue
        if ch == "#" and not in_quote:
            return line[:i]
    return line


def _parse_profile_line(line: str, *, lineno: int) -> str:
    """Validate ``profile: <name>`` and return the name."""
    match = re.match(r"^profile\s*:\s*(\S+)\s*$", line)
    if not match:
        raise PolicyParseError(
            "expected the first non-comment line to be "
            "`profile: strict|default|permissive`",
            line=lineno,
            snippet=line,
        )
    name = match.group(1).lower()
    if name not in PROFILES:
        raise PolicyParseError(
            f"unknown profile {name!r}; expected one of {', '.join(PROFILES)}",
            line=lineno,
            snippet=line,
        )
    return name


# ─── Rule parser ─────────────────────────────────────────────────────────────


_RULE_HEAD = re.compile(r"^(allow|flag|block)\b(.*)$", re.IGNORECASE)


def _parse_rule_line(line: str, *, lineno: int) -> Rule:
    """Parse one ``<action> when <pred> [and <pred>...]`` line."""
    head = _RULE_HEAD.match(line)
    if not head:
        raise PolicyParseError(
            "rule must start with `allow`, `flag`, or `block`",
            line=lineno,
            snippet=line,
        )
    action: RuleAction = head.group(1).lower()  # type: ignore[assignment]
    rest = head.group(2).strip()

    if not rest:
        # Bare ``allow``/``flag``/``block`` with no condition.
        # Permitted but warned-against — see Rule docstring.
        return Rule(action=action, predicates=(), line=lineno)

    # Optional ``when`` keyword. We tolerate its absence (so
    # ``allow command_starts_with: ...`` works too) because user
    # research showed half of operators omit it in the first draft.
    if rest.lower().startswith("when"):
        rest = rest[4:].lstrip()
        if not rest:
            raise PolicyParseError(
                "`when` must be followed by at least one predicate",
                line=lineno,
                snippet=line,
            )

    predicates = _split_predicates(rest, lineno=lineno, original=line)
    return Rule(action=action, predicates=tuple(predicates), line=lineno)


def _split_predicates(
    body: str, *, lineno: int, original: str,
) -> list[Predicate]:
    """Split ``pred and pred and ...`` into parsed Predicate objects.

    The split is performed in a quote-aware way so a literal " and "
    inside a quoted value (e.g.
    ``command_contains: "foo and bar"``) is preserved.
    """
    out: list[Predicate] = []
    for chunk in _quote_aware_split_on_and(body):
        chunk = chunk.strip()
        if not chunk:
            continue
        out.append(_parse_predicate(chunk, lineno=lineno, original=original))
    if not out:
        raise PolicyParseError(
            "expected at least one predicate after `when`",
            line=lineno,
            snippet=original,
        )
    return out


def _quote_aware_split_on_and(body: str) -> list[str]:
    """Split on `` and `` outside double-quoted strings."""
    parts: list[str] = []
    buf: list[str] = []
    i = 0
    in_quote = False
    escape = False
    while i < len(body):
        ch = body[i]
        if escape:
            buf.append(ch)
            escape = False
            i += 1
            continue
        if ch == "\\" and in_quote:
            buf.append(ch)
            escape = True
            i += 1
            continue
        if ch == '"':
            in_quote = not in_quote
            buf.append(ch)
            i += 1
            continue
        if (
            not in_quote
            and body[i:i + 5].lower() == " and "
        ):
            parts.append("".join(buf))
            buf.clear()
            i += 5
            continue
        buf.append(ch)
        i += 1
    parts.append("".join(buf))
    return parts


_PRED_HEAD = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*)$")


def _parse_predicate(text: str, *, lineno: int, original: str) -> Predicate:
    """Parse a single ``field: value`` clause."""
    match = _PRED_HEAD.match(text)
    if not match:
        raise PolicyParseError(
            f"predicate must be `field: value`, got {text!r}",
            line=lineno,
            snippet=original,
        )
    field = match.group(1).lower()
    if field not in PREDICATE_FIELDS:
        raise PolicyParseError(
            f"unknown predicate field {field!r}; expected one of "
            f"{', '.join(PREDICATE_FIELDS)}",
            line=lineno,
            snippet=original,
        )
    value = _parse_value(match.group(2).strip(), lineno=lineno, original=original)
    return Predicate(field=field, value=value)


def _parse_value(text: str, *, lineno: int, original: str) -> str:
    """Parse a value: either a quoted string or a bare token.

    Quoted strings allow ``\\"`` and ``\\\\`` escapes. Bare tokens
    are matched against ``[A-Za-z_][A-Za-z0-9_\\-./]*`` so things
    like probe names (``typosquat``) and kinds (``shell``,
    ``file``) work without quoting.
    """
    if not text:
        raise PolicyParseError(
            "predicate value is empty", line=lineno, snippet=original,
        )

    if text.startswith('"'):
        match = _QUOTED_STRING.match(text)
        if not match or match.end() != len(text):
            raise PolicyParseError(
                "unterminated quoted string in predicate value",
                line=lineno,
                snippet=original,
            )
        # Decode the two escape sequences we honour. Anything else
        # is passed through literally so users can write regex-like
        # values in the future without us re-interpreting them.
        return match.group(1).replace('\\"', '"').replace("\\\\", "\\")

    # Bare tokens cover: probe names (`typosquat`), kinds (`shell`),
    # filesystem paths (`/etc/shadow`, `./build`), version strings
    # (`1.2.3`). Anything with a space, colon, hash, or quote must be
    # quoted — those are the punctuation we use elsewhere in the
    # grammar so leaving them unquoted causes ambiguity.
    if not re.fullmatch(r"[A-Za-z0-9_./\-][A-Za-z0-9_./\-]*", text):
        raise PolicyParseError(
            f"bare predicate value {text!r} contains unsupported characters; "
            "wrap it in double quotes",
            line=lineno,
            snippet=original,
        )
    return text
