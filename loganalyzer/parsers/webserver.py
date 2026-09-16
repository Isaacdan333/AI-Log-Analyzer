"""Parser for Apache/Nginx combined access log entries."""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from datetime import datetime, timezone
from pathlib import Path

from loganalyzer.models import NormalizedEvent

# Combined log format:
# %h %l %u [%t] "%r" %>s %b "%{Referer}i" "%{User-Agent}i"
_COMBINED_RE = re.compile(
    r'^(?P<ip>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+'
    r'(?P<status>\d{3}|-)\s+'
    r'(?P<bytes>\d+|-)'
    r'(?:\s+"(?P<referrer>[^"]*)")?'
    r'(?:\s+"(?P<user_agent>[^"]*)")?'
)

_REQUEST_RE = re.compile(r"^(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+(?P<protocol>\S+)$")

_TIMESTAMP_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


class WebServerLogParser:
    """Parse Apache/Nginx combined-format access log lines into normalized events."""

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
        match = _COMBINED_RE.match(line.strip())
        if match is None:
            return None

        timestamp = self._parse_timestamp(match.group("timestamp"))
        if timestamp is None:
            return None

        method, path, protocol = self._parse_request(match.group("request"))

        status = match.group("status")
        status_value = status if status != "-" else None

        bytes_sent = self._parse_int(match.group("bytes"))

        metadata: dict[str, object] = {}
        ident = match.group("ident")
        if ident and ident != "-":
            metadata["ident"] = ident
        if protocol is not None:
            metadata["protocol_version"] = protocol
        referrer = match.group("referrer")
        if referrer and referrer != "-":
            metadata["referrer"] = referrer
        user_agent = match.group("user_agent")
        if user_agent and user_agent != "-":
            metadata["user_agent"] = user_agent
        if method is not None:
            metadata["method"] = method

        user = match.group("user")
        user_value = user if user and user != "-" else None

        return NormalizedEvent(
            timestamp=timestamp,
            source=source,
            log_type="web",
            event_type="http_request",
            src_ip=match.group("ip"),
            user=user_value,
            status=status_value,
            bytes_sent=bytes_sent,
            path=path,
            metadata=metadata,
            raw_line=self._safe_raw_line(line),
        )

    @staticmethod
    def _parse_timestamp(raw_timestamp: str) -> datetime | None:
        try:
            parsed = datetime.strptime(raw_timestamp, _TIMESTAMP_FORMAT)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _parse_request(raw_request: str) -> tuple[str | None, str | None, str | None]:
        match = _REQUEST_RE.match(raw_request.strip())
        if match is None:
            return None, None, None
        return match.group("method"), match.group("path"), match.group("protocol")

    @staticmethod
    def _parse_int(value: str | None) -> int | None:
        if not value or value == "-":
            return None
        try:
            return int(value)
        except ValueError:
            return None

    @staticmethod
    def _safe_raw_line(line: str) -> str:
        """Keep source context while removing control characters."""
        return " ".join(line.strip().split())
