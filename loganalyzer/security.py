"""Conservative handling for secrets and untrusted log text."""

from __future__ import annotations

import re

_SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?i)(\b(?:password|passwd|pwd|token|api[_-]?key|secret|cookie|authorization|proxy-authorization)\b\s*[:=]\s*)([\"']?)([^\s,;\"']+)"
)
_BEARER_RE = re.compile(r"(?i)(\b(?:bearer|basic)\s+)([^\s,;]+)")
_QUERY_SECRET_RE = re.compile(
    r"(?i)([?&](?:token|access_token|api[_-]?key|password|secret|session(?:id)?|auth)=)[^&#\s]+"
)


def redact_sensitive_text(value: str) -> str:
    """Redact obvious credential values while preserving useful log context."""
    redacted = _BEARER_RE.sub(r"\1[REDACTED]", value)
    redacted = _SENSITIVE_ASSIGNMENT_RE.sub(r"\1\2[REDACTED]", redacted)
    return _QUERY_SECRET_RE.sub(r"\1[REDACTED]", redacted)