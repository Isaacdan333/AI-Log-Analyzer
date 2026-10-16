"""Optional, advisory summaries for deterministic alerts."""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal, InvalidOperation
from typing import Any, Protocol

from loganalyzer.models import Alert
from loganalyzer.security import redact_sensitive_text

_REQUIRED_FIELDS = frozenset(
    {
        "incident_summary",
        "explanation",
        "recommendations",
        "investigation_questions",
    }
)
_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\d)")
_IPV6_RE = re.compile(
    r"(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])"
)
_TIMESTAMP_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}"
    r"(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?\b"
)
_TIME_RE = re.compile(r"\b(?:[01]?\d|2[0-3]):[0-5]\d(?::[0-5]\d)?\b")
_NUMBER_RE = re.compile(r"(?<![\w.])-?\d+(?:\.\d+)?(?![\w.])")
_IDENTIFIER_RE = re.compile(r"\b[A-Za-z0-9_][A-Za-z0-9_.@-]{0,63}\b")
_NAMED_USER_RE = re.compile(
    r"\b(?:username|user|account)(?:\s+(?:name|account))?\s*"
    r"(?:(?:is|was|=|:|named)\s*)?['\"`]?([A-Za-z0-9_][A-Za-z0-9_.@-]{0,63})",
    re.IGNORECASE,
)
_SEVERITY_RE = re.compile(r"\b(?:LOW|MEDIUM|HIGH|CRITICAL)\b", re.IGNORECASE)
_DETECTOR_RE = re.compile(
    r"\bdetector(?:\s+name)?\s*(?:is|was|:|=)\s*([A-Za-z][A-Za-z0-9_.-]{0,63})",
    re.IGNORECASE,
)
_SECRET_RE = re.compile(
    r"(?i)\b(?:password|passwd|pwd|token|secret|api[_ -]?key|credential)"
    r"\s*(?:is|=|:)\s*\S+|\bsk-[A-Za-z0-9_-]{8,}\b"
)
_NUMBERS_AS_WORDS = {
    "zero": Decimal(0),
    "one": Decimal(1),
    "two": Decimal(2),
    "three": Decimal(3),
    "four": Decimal(4),
    "five": Decimal(5),
    "six": Decimal(6),
    "seven": Decimal(7),
    "eight": Decimal(8),
    "nine": Decimal(9),
    "ten": Decimal(10),
    "eleven": Decimal(11),
    "twelve": Decimal(12),
    "thirteen": Decimal(13),
    "fourteen": Decimal(14),
    "fifteen": Decimal(15),
    "sixteen": Decimal(16),
    "seventeen": Decimal(17),
    "eighteen": Decimal(18),
    "nineteen": Decimal(19),
    "twenty": Decimal(20),
    "thirty": Decimal(30),
    "forty": Decimal(40),
    "fifty": Decimal(50),
    "sixty": Decimal(60),
    "seventy": Decimal(70),
    "eighty": Decimal(80),
    "ninety": Decimal(90),
}
_USERNAME_KEYS = frozenset(
    {"user", "username", "user_name", "account", "account_name", "target_user", "subject_user"}
)
_SENSITIVE_KEY_RE = re.compile(
    r"(?i)(?:password|passwd|pwd|token|secret|api[_ -]?key|cookie|authorization|credential)"
)


class SummaryProvider(Protocol):
    """Minimal interface for an optional structured-summary provider."""

    def generate(
        self,
        alert_data: Mapping[str, Any],
        *,
        model: str,
        timeout_seconds: float,
    ) -> str:
        """Return a JSON object matching the summary response schema."""
        ...


@dataclass(frozen=True, slots=True)
class AlertSummary:
    """Supplementary prose; never a replacement for the authoritative alert."""

    incident_summary: str
    explanation: str
    recommendations: tuple[str, ...]
    investigation_questions: tuple[str, ...]
    source: str


def alert_input(alert: Alert) -> dict[str, Any]:
    """Build the minimal provider payload from one structured alert."""
    return {
        "severity": alert.severity,
        "title": _redact_provider_text(alert.title),
        "summary": _redact_provider_text(alert.summary),
        "evidence": _provider_value(alert.evidence),
        "detector": _redact_provider_text(alert.detector),
        "recommended_actions": [
            _redact_provider_text(action) for action in alert.recommended_actions
        ],
        "source_ips": list(alert.source_ips),
        "time_start": _provider_value(alert.time_start),
        "time_end": _provider_value(alert.time_end),
    }


def summarize_alert(
    alert: Alert,
    provider: SummaryProvider | None = None,
    *,
    model: str = "",
    timeout_seconds: float = 20.0,
) -> AlertSummary:
    """Return a validated provider summary or a deterministic fallback."""
    if provider is None:
        return deterministic_summary(alert)

    try:
        response = provider.generate(
            alert_input(alert),
            model=model,
            timeout_seconds=timeout_seconds,
        )
        return validate_summary(response, alert)
    except Exception:
        # Provider errors and untrusted output are intentionally not exposed.
        return deterministic_summary(alert)


def deterministic_summary(alert: Alert) -> AlertSummary:
    """Create useful report prose solely from authoritative alert fields."""
    evidence = (
        "; ".join(f"{key.replace('_', ' ')}: {_display_value(value)}"
                  for key, value in alert.evidence.items())
        if alert.evidence
        else "No structured evidence values were supplied."
    )
    recommendations = alert.recommended_actions or (
        "No response actions were supplied by the deterministic detector.",
    )
    questions = (
        "Can the supplied evidence be confirmed against the relevant system records?",
        "Is the observed activity expected and authorized?",
        "What additional context is needed before deciding on a response?",
    )
    return AlertSummary(
        incident_summary=f"{alert.title} ({alert.severity}).",
        explanation=f"{alert.summary} Evidence recorded by the detector: {evidence}",
        recommendations=tuple(recommendations),
        investigation_questions=questions,
        source="fallback",
    )


def validate_summary(response: str, alert: Alert) -> AlertSummary:
    """Validate JSON shape, facts, and allowed actions; raise on any uncertainty."""
    if not isinstance(response, str) or len(response) > 20_000:
        raise ValueError("summary response must be a bounded JSON string")
    data = json.loads(response)
    if not isinstance(data, dict) or set(data) != _REQUIRED_FIELDS:
        raise ValueError("summary response has an unexpected schema")

    incident_summary = _required_text(data["incident_summary"])
    explanation = _required_text(data["explanation"])
    recommendations = _required_text_list(data["recommendations"])
    questions = _required_text_list(data["investigation_questions"])
    allowed_actions = set(alert.recommended_actions)
    if any(item not in allowed_actions for item in recommendations):
        raise ValueError("summary contains a recommendation outside the allowed actions")
    if len(set(recommendations)) != len(recommendations):
        raise ValueError("summary contains duplicate recommendations")

    output = "\n".join((incident_summary, explanation, *recommendations, *questions))
    _validate_facts(output, alert)
    return AlertSummary(
        incident_summary=incident_summary,
        explanation=explanation,
        recommendations=tuple(recommendations),
        investigation_questions=tuple(questions),
        source="llm",
    )


def _validate_facts(output: str, alert: Alert) -> None:
    if _SECRET_RE.search(output):
        raise ValueError("summary contains a credential-like value")
    mentioned_severities = {match.group(0).upper() for match in _SEVERITY_RE.finditer(output)}
    if mentioned_severities - {alert.severity.upper()}:
        raise ValueError("summary refers to a different severity")
    for match in _DETECTOR_RE.finditer(output):
        if match.group(1).casefold() != alert.detector.casefold():
            raise ValueError("summary refers to a different detector")

    source = alert_input(alert)
    source_text = json.dumps(source, ensure_ascii=True, sort_keys=True)
    allowed_ips = _supported_ips(source)
    if not _ip_addresses(output) <= allowed_ips:
        raise ValueError("summary refers to an unsupported IP address")

    allowed_numbers = _supported_numbers(source)
    if not _mentioned_numbers(output) <= allowed_numbers:
        raise ValueError("summary refers to an unsupported number or count")

    allowed_timestamps = _supported_timestamps(source)
    mentioned_timestamps = _mentioned_timestamps(output)
    if not mentioned_timestamps <= allowed_timestamps:
        raise ValueError("summary refers to an unsupported timestamp")

    allowed_usernames = _supported_usernames(source)
    for match in _NAMED_USER_RE.finditer(output):
        username = match.group(1).rstrip(".,;:!?").casefold()
        if username not in allowed_usernames:
            raise ValueError("summary refers to an unsupported username")
    for match in _IDENTIFIER_RE.finditer(output):
        value = match.group(0)
        if any(char in value for char in "_@") and value.casefold() not in allowed_usernames:
            if not _is_supported_identifier(value, source_text):
                raise ValueError("summary refers to an unsupported identifier")


def _required_text(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("summary section must be text")
    normalized = value.strip()
    if not normalized or len(normalized) > 2_000 or any(ord(char) < 32 for char in normalized):
        raise ValueError("summary section is empty, too long, or contains control characters")
    return normalized


def _required_text_list(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or len(value) > 8:
        raise ValueError("summary list must contain between one and eight entries")
    return tuple(_required_text(item) for item in value)


def _json_safe(value: Any) -> Any:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_safe(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError(f"unsupported alert value type: {type(value).__name__}")


def _provider_value(value: Any, key: str = "") -> Any:
    if _SENSITIVE_KEY_RE.search(key):
        return "[REDACTED]"
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Mapping):
        return {
            str(child_key): _provider_value(child, str(child_key))
            for child_key, child in value.items()
        }
    if isinstance(value, (tuple, list)):
        return [_provider_value(child, key) for child in value]
    if isinstance(value, str):
        return _redact_provider_text(value)
    if value is None or isinstance(value, (int, float, bool)):
        return value
    raise TypeError(f"unsupported alert value type: {type(value).__name__}")


def _redact_provider_text(value: str) -> str:
    return redact_sensitive_text(value)


def _display_value(value: Any) -> str:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(_json_safe(value), ensure_ascii=True, sort_keys=True)
    return str(value)


def _ip_addresses(text: str) -> set[str]:
    candidates = set(_IPV4_RE.findall(text)) | set(_IPV6_RE.findall(text))
    addresses: set[str] = set()
    for candidate in candidates:
        try:
            addresses.add(str(ipaddress.ip_address(candidate)))
        except ValueError:
            addresses.add(candidate.casefold())
    return addresses


def _supported_numbers(value: Any, key: str = "") -> set[Decimal]:
    numbers: set[Decimal] = set()
    if isinstance(value, bool) or value is None:
        return numbers
    if isinstance(value, (int, float)):
        try:
            numbers.add(Decimal(str(value)).normalize())
        except InvalidOperation:
            pass
    elif isinstance(value, str):
        if key in {"title", "summary", "recommended_actions"} or re.search(
            r"(?:count|threshold|port|bytes|size|status|attempt|window|minute|second|duration|event_id|code|ratio|observed)",
            key,
        ):
            cleaned = _IPV4_RE.sub(" ", value)
            cleaned = _IPV6_RE.sub(" ", cleaned)
            cleaned = _TIMESTAMP_RE.sub(" ", cleaned)
            cleaned = _TIME_RE.sub(" ", cleaned)
            for match in _NUMBER_RE.findall(cleaned):
                try:
                    numbers.add(Decimal(match).normalize())
                except InvalidOperation:
                    continue
            numbers.update(
                number
                for word, number in _NUMBERS_AS_WORDS.items()
                if re.search(rf"\b{word}\b", cleaned, re.IGNORECASE)
            )
    elif isinstance(value, Mapping):
        for child_key, child in value.items():
            numbers.update(_supported_numbers(child, str(child_key).lower()))
    elif isinstance(value, (list, tuple)):
        for child in value:
            numbers.update(_supported_numbers(child, key))
    return numbers


def _mentioned_numbers(text: str) -> set[Decimal]:
    cleaned = _IPV4_RE.sub(" ", text)
    cleaned = _IPV6_RE.sub(" ", cleaned)
    cleaned = _TIMESTAMP_RE.sub(" ", cleaned)
    cleaned = _TIME_RE.sub(" ", cleaned)
    found: set[Decimal] = set()
    for match in _NUMBER_RE.findall(cleaned):
        try:
            found.add(Decimal(match).normalize())
        except InvalidOperation:
            continue
    found.update(
        value
        for word, value in _NUMBERS_AS_WORDS.items()
        if re.search(rf"\b{word}\b", cleaned, re.IGNORECASE)
    )
    return found


def _supported_timestamps(value: Any, key: str = "") -> set[str]:
    timestamps: set[str] = set()
    if isinstance(value, (datetime, date)):
        iso = value.isoformat()
        timestamps.update((iso, iso[:10]))
        if isinstance(value, datetime):
            timestamps.add(value.strftime("%H:%M"))
            timestamps.add(value.strftime("%H:%M:%S"))
    elif isinstance(value, str):
        if key in {"title", "summary", "recommended_actions"} or re.search(
            r"(?:time|date|timestamp)", key
        ):
            timestamps.update(_TIMESTAMP_RE.findall(value))
            timestamps.update(_TIME_RE.findall(value))
    elif isinstance(value, Mapping):
        for child_key, child in value.items():
            timestamps.update(_supported_timestamps(child, str(child_key).lower()))
    elif isinstance(value, (list, tuple)):
        for child in value:
            timestamps.update(_supported_timestamps(child, key))
    return timestamps


def _mentioned_timestamps(value: str) -> set[str]:
    return set(_TIMESTAMP_RE.findall(value)) | set(_TIME_RE.findall(value))


def _supported_usernames(value: Any, key: str = "") -> set[str]:
    usernames: set[str] = set()
    if isinstance(value, str) and key in _USERNAME_KEYS:
        usernames.add(value.casefold())
    elif isinstance(value, Mapping):
        for child_key, child in value.items():
            normalized_key = str(child_key).lower().replace("-", "_")
            usernames.update(_supported_usernames(child, normalized_key))
    elif isinstance(value, (list, tuple)):
        for child in value:
            usernames.update(_supported_usernames(child, key))
    return usernames


def _supported_ips(value: Any, key: str = "") -> set[str]:
    addresses: set[str] = set()
    if isinstance(value, str) and (
        key == "title"
        or key == "summary"
        or key == "source_ips"
        or re.search(r"(?:^|_)(?:src|source|dst|destination)?_?ip(?:$|_)", key)
    ):
        addresses.update(_ip_addresses(value))
    elif isinstance(value, Mapping):
        for child_key, child in value.items():
            addresses.update(_supported_ips(child, str(child_key).lower()))
    elif isinstance(value, (list, tuple)):
        for child in value:
            addresses.update(_supported_ips(child, key))
    return addresses


def _is_supported_identifier(value: str, source_text: str) -> bool:
    return value.casefold() in {
        match.group(0).casefold() for match in _IDENTIFIER_RE.finditer(source_text)
    }
