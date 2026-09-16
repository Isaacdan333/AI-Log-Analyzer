"""Parser for common Linux SSH authentication log entries."""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from datetime import datetime, timezone
from pathlib import Path

from loganalyzer.models import NormalizedEvent

_TIMESTAMP_RE = re.compile(r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})")
_IP_RE = r"(?P<ip>[^\s]+)"
_SSH_EVENT_RE = re.compile(
    rf"sshd(?:\[[^]]+\])?:\s+(?P<message>.*?)(?:\s+port\s+\d+)?(?:\s+ssh\S*)?$"
)


class SSHLogParser:
    """Parse SSH authentication and privilege-related auth.log messages."""

    def __init__(self, default_year: int = 2026) -> None:
        self.default_year = default_year

    def parse_lines(
        self, lines: Iterable[str], source: str = "<memory>"
    ) -> Sequence[NormalizedEvent]:
        events: list[NormalizedEvent] = []
        for line in lines:
            event = self.parse_line(line, source)
            if event is not None:
                events.append(event)
        return events

    def parse_file(self, path: Path) -> Sequence[NormalizedEvent]:
        with path.open("r", encoding="utf-8", errors="replace") as log_file:
            return self.parse_lines(log_file, str(path))

    def parse_line(self, line: str, source: str = "<memory>") -> NormalizedEvent | None:
        """Parse one line, returning None for malformed or unsupported input."""
        timestamp_match = _TIMESTAMP_RE.match(line)
        if timestamp_match is None:
            return None

        timestamp = self._parse_timestamp(timestamp_match)
        message_match = _SSH_EVENT_RE.search(line[timestamp_match.end() :])
        if message_match is None:
            message = line[timestamp_match.end() :].strip()
        else:
            message = message_match.group("message").strip()

        event = self._parse_authentication(message, timestamp, source, line)
        if event is not None:
            return event
        return self._parse_privilege_action(message, timestamp, source, line)

    def _parse_timestamp(self, match: re.Match[str]) -> datetime:
        parsed = datetime.strptime(
            f"{self.default_year} {match.group('month')} {match.group('day')} {match.group('time')}",
            "%Y %b %d %H:%M:%S",
        )
        return parsed.replace(tzinfo=timezone.utc)

    def _parse_authentication(
        self,
        message: str,
        timestamp: datetime,
        source: str,
        raw_line: str,
    ) -> NormalizedEvent | None:
        patterns = (
            ("login_failure", "failure", "password", r"Failed password for (?:invalid user )?(?P<user>\S+) from " + _IP_RE),
            ("login_success", "success", "password", r"Accepted password for (?P<user>\S+) from " + _IP_RE),
            ("login_success", "success", "publickey", r"Accepted publickey for (?P<user>\S+) from " + _IP_RE),
            ("login_failure", "failure", None, r"Invalid user (?P<user>\S+) from " + _IP_RE),
        )
        for event_type, status, method, pattern in patterns:
            match = re.search(pattern, message)
            if match is not None:
                metadata = {"service": "sshd"}
                if method is not None:
                    metadata["authentication_method"] = method
                return NormalizedEvent(
                    timestamp=timestamp,
                    source=source,
                    log_type="ssh",
                    event_type=event_type,
                    src_ip=match.group("ip"),
                    user=match.group("user"),
                    status=status,
                    metadata=metadata,
                    raw_line=self._safe_raw_line(raw_line),
                )
        return None

    def _parse_privilege_action(
        self,
        message: str,
        timestamp: datetime,
        source: str,
        raw_line: str,
    ) -> NormalizedEvent | None:
        sudo_match = re.search(r"sudo:\s+(?P<user>\S+)\s*:\s+", message)
        if sudo_match is not None:
            return NormalizedEvent(
                timestamp=timestamp,
                source=source,
                log_type="ssh",
                event_type="privilege_action",
                user=sudo_match.group("user"),
                status="executed",
                metadata={"action": "sudo", "service": "sudo"},
                raw_line=self._safe_raw_line(raw_line),
            )

        su_match = re.search(r"su:\s+\((?:to\s+)?(?P<target>\S+)\)\s+(?P<action>.*)", message)
        if su_match is not None:
            return NormalizedEvent(
                timestamp=timestamp,
                source=source,
                log_type="ssh",
                event_type="privilege_action",
                user=su_match.group("target"),
                status="executed",
                metadata={"action": "su", "service": "su"},
                raw_line=self._safe_raw_line(raw_line),
            )
        return None

    @staticmethod
    def _safe_raw_line(line: str) -> str:
        """Keep source context while removing control characters."""
        return " ".join(line.strip().split())
