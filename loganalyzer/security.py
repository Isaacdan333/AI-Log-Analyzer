"""Conservative handling for secrets and untrusted log text."""

from __future__ import annotations

import re

_SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?i)(\b(?:password|passwd|pwd|token|api[_ -]?key|secret|cookie|authorization|proxy-authorization)\b\s*[:=]\s*)([\"']?)([^\s,;\"']+)"
)
_BEARER_RE = re.compile(r"(?i)(\b(?:bearer|basic)\s+)([^\s,;]+)")
_KNOWN_SECRET_RE = re.compile(
    r"(?i)\b(?:sk-[A-Za-z0-9_-]{12,}|AKIA[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9_]{20,})\b"
)
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    re.DOTALL,
)
_URL_CREDENTIAL_RE = re.compile(r"(?i)(https?://)[^/@\s:]+:[^/@\s]+@")
_QUERY_SECRET_RE = re.compile(
    r"(?i)([?&](?:token|access_token|api[_-]?key|password|secret|session(?:id)?|auth)=)[^&#\s]+"
)


def redact_sensitive_text(value: str) -> str:
    """Redact obvious credential values while preserving useful log context."""
    redacted = _PRIVATE_KEY_RE.sub("[REDACTED]", value)
    redacted = _KNOWN_SECRET_RE.sub("[REDACTED]", redacted)
    redacted = _URL_CREDENTIAL_RE.sub(r"\1[REDACTED]@", redacted)
    redacted = _BEARER_RE.sub(r"\1[REDACTED]", redacted)
    redacted = _SENSITIVE_ASSIGNMENT_RE.sub(r"\1\2[REDACTED]", redacted)
    return _QUERY_SECRET_RE.sub(r"\1[REDACTED]", redacted)