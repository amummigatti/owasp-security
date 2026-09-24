#!/usr/bin/env python3
# Author: Akshatha Mummigatti
"""Mask secret-looking values in text before it is written to a report or a tracker.

Scan reports quote code as evidence, and a report is copied onward: into a Markdown
file people share, and into a tracker whose audience is wider than the repository's.
A credential that was masked by the scanner but retyped, pasted or quoted during
review would otherwise travel with the finding. So redaction is applied where text
leaves the tool, not only where it is first collected.

The rules are conservative in one direction: they would rather hide a harmless value
than leak a live one. They are also readable - a placeholder names what was hidden
(<redacted:aws-access-key-id>) so evidence still makes sense to a developer.

This file is copied, byte for byte, into each skill that needs it, so that a skill can
be installed on its own. tests/ asserts the copies are identical; edit them together.

Usage as a library:
    from redact import redact_text
    clean, count = redact_text(text)

Usage from a shell (reads stdin, writes stdout, reports the count on stderr):
    echo 'password = "hunter2hunter2"' | python redact.py
"""

from __future__ import annotations

import re
import sys

_NAMES = (
    r"(?:secret|passw(?:or)?d|passwd|pwd|token|api[_-]?key|apikey|access[_-]?key|"
    r"private[_-]?key|credential|auth(?:orization)?)"
)

# (label, regex, group). group 0 masks the whole match; group N masks only that part,
# so the surrounding code ("password = ...") stays readable.
PATTERNS = [
    ("private-key-block",
     r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)", 0),
    ("aws-access-key-id", r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b", 0),
    ("github-token", r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b", 0),
    ("slack-token", r"\bxox[abprs]-[A-Za-z0-9-]{10,}", 0),
    ("api-key", r"\b(?:sk|pk|rk)-(?:live|test|proj)?[-_]?[A-Za-z0-9_-]{20,}\b", 0),
    ("google-api-key", r"\bAIza[0-9A-Za-z_-]{30,}\b", 0),
    ("jwt", r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b", 0),
    ("bearer-token", r"(?i)\bBearer\s+([A-Za-z0-9._~+/=-]{16,})", 1),
    ("url-credentials", r"(?i)\b[a-z][a-z0-9+.-]*://[^\s/:@]+:([^\s/@]+)@", 1),
    # name = "value" and name: 'value' where the name says it is a secret. A quoted
    # literal is the strongest signal that a value was written into the source.
    ("secret-assignment", r'(?i)\b[\w.-]*' + _NAMES + r'[\w.-]*["\']?\s*[:=]\s*"([^"\s]{8,})"', 1),
    ("secret-assignment", r"(?i)\b[\w.-]*" + _NAMES + r"[\w.-]*[\"']?\s*[:=]\s*'([^'\s]{8,})'", 1),
    # Unquoted (.env style) values: require a digit and a letter so identifiers such as
    # SOME_LONG_CONSTANT_NAME or os.getenv(...) are left alone.
    ("secret-assignment",
     r"(?i)\b[\w.-]*" + _NAMES + r"[\w.-]*\s*[:=]\s*(?=[A-Za-z0-9+/_.=-]*\d)(?=[A-Za-z0-9+/_.=-]*[A-Za-z])"
     r"([A-Za-z0-9+/_.=-]{16,})(?![\w(])", 1),
]

_COMPILED = [(label, re.compile(regex), group) for label, regex, group in PATTERNS]


def redact_text(text: str) -> tuple:
    """Return (redacted_text, number_of_values_masked)."""
    if not text:
        return text, 0
    total = 0
    for label, pattern, group in _COMPILED:
        placeholder = "<redacted:" + label + ">"

        def replace(match, group=group, placeholder=placeholder):
            nonlocal total
            start, end = match.span(group)
            if start < 0 or match.group(group).startswith("<redacted:"):
                return match.group(0)
            total += 1
            offset = match.start()
            whole = match.group(0)
            return whole[: start - offset] + placeholder + whole[end - offset:]

        text = pattern.sub(replace, text)
    return text, total


def redact_list(values: list) -> tuple:
    out, count = [], 0
    for value in values:
        cleaned, n = redact_text(value if isinstance(value, str) else str(value))
        out.append(cleaned)
        count += n
    return out, count


def main() -> int:
    cleaned, count = redact_text(sys.stdin.read())
    sys.stdout.write(cleaned)
    print("redacted " + str(count) + " value(s)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
