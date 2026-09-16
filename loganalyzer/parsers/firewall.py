"""Parser for iptables/netfilter-style syslog firewall log entries."""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from datetime import datetime, timezone
from pathlib import Path

from loganalyzer.models import NormalizedEvent

_TIMESTAMP_RE = re.compile(r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})")
_KV_RE = re.compile(r"(?P<key>[A-Za-z]+)=(?P<value>\S*)")

_ACCEPTED_RE = re.compile(r"\b(ACCEPT(?:ED)?|ALLOW(?:ED)?)\b", re.IGNORECASE)
_DENIED_RE = re.compile(r"\b(REJECT(?:ED)?|DENY|DENIED)\b", re.IGNORECASE)
_DROPPED_RE = re.compile(r"\b(DROP(?:PED)?|BLOCK(?:ED)?)\b", re.IGNORECASE)

# Fields that indicate the line is a firewall/netfilter-style entry.
_IDENTIFYING_KEYS = {"SRC", "DST", "PROTO", "DPT"}
_INT_KEYS = {"DPT", "SPT", "LEN", "BYTES", "PKTS", "COUNT"}


class FirewallLogParser:
    """Parse iptables/netfilter-style firewall log lines into normalized events."""

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

        remainder = line[timestamp_match.end() :]
        fields = {
            match.group("key").upper(): match.group("value")
            for match in _KV_RE.finditer(remainder)
        }
        if not _IDENTIFYING_KEYS.intersection(fields):
            return None

        timestamp = self._parse_timestamp(timestamp_match)
        status = self._parse_status(remainder)
        metadata: dict[str, object] = {}

        if fields.get("IN"):
            metadata["in_interface"] = fields["IN"]
        if fields.get("OUT"):
            metadata["out_interface"] = fields["OUT"]
        if fields.get("SPT"):
            spt = self._parse_int(fields.get("SPT"))
            if spt is not None:
                metadata["src_port"] = spt

        bytes_sent = self._parse_int(fields.get("LEN")) or self._parse_int(fields.get("BYTES"))
        packet_count = self._parse_int(fields.get("PKTS")) or self._parse_int(fields.get("COUNT"))
        if packet_count is not None:
            metadata["packet_count"] = packet_count

        protocol = fields.get("PROTO")

        return NormalizedEvent(
            timestamp=timestamp,
            source=source,
            log_type="firewall",
            event_type="network_connection",
            src_ip=fields.get("SRC"),
            dst_ip=fields.get("DST"),
            dst_port=self._parse_int(fields.get("DPT")),
            protocol=protocol.upper() if protocol else None,
            status=status,
            bytes_sent=bytes_sent,
            metadata=metadata,
            raw_line=self._safe_raw_line(line),
        )

    def _parse_timestamp(self, match: re.Match[str]) -> datetime:
        parsed = datetime.strptime(
            f"{self.default_year} {match.group('month')} {match.group('day')} {match.group('time')}",
            "%Y %b %d %H:%M:%S",
        )
        return parsed.replace(tzinfo=timezone.utc)

    @staticmethod
    def _parse_status(remainder: str) -> str:
        if _ACCEPTED_RE.search(remainder):
            return "accepted"
        if _DENIED_RE.search(remainder):
            return "denied"
        if _DROPPED_RE.search(remainder):
            return "dropped"
        return "unknown"

    @staticmethod
    def _parse_int(value: str | None) -> int | None:
        if not value:
            return None
        try:
            return int(value)
        except ValueError:
            return None

    @staticmethod
    def _safe_raw_line(line: str) -> str:
        """Keep source context while removing control characters."""
        return " ".join(line.strip().split())
