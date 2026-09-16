"""Parser for exported Windows Security Event Log CSV files."""

from __future__ import annotations

import csv
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path

from loganalyzer.models import NormalizedEvent

_EVENT_TYPES = {
    "4624": "login_success",
    "4625": "login_failure",
    "4672": "privilege_assignment",
    "4720": "user_created",
    "4728": "privileged_group_membership",
    "4732": "privileged_group_membership",
    "4688": "process_creation",
}

# Names derived from the supplied XML schemas. Friendly CSV spellings are
# accepted only where they identify the same XML field unambiguously.
_REAL_HEADER_ALIASES = {
    "event_id": ("eventid", "event id"),
    "timestamp": ("timecreated systemtime", "timecreated", "timestamp"),
    "computer": ("computer",),
    "target_user": ("targetusername", "target user name"),
    "target_domain": ("targetdomainname", "target domain name"),
    "subject_user": ("subjectusername", "subject user name"),
    "subject_domain": ("subjectdomainname", "subject domain name"),
    "logon_type": ("logontype", "logon type"),
    "source_ip": ("ipaddress", "ip address"),
    "process_name": ("processname", "process name"),
    "process_id": ("processid", "process id"),
    "privileges": ("privilegelist", "privilege list"),
    "event_record_id": ("eventrecordid", "event record id"),
    "channel": ("channel",),
    "execution_process_id": ("execution processid", "execution process id"),
    "execution_thread_id": ("execution threadid", "execution thread id"),
    "provider_name": ("providername", "provider name"),
    "provider_guid": ("providerguid", "provider guid"),
    "parent_process_name": ("parentprocessname", "parent process name"),
    "command_line": ("commandline", "command line"),
    "new_process_name": ("newprocessname", "new process name"),
    "new_process_id": ("newprocessid", "new process id"),
    "token_elevation_type": ("tokenelevationtype", "token elevation type"),
    "mandatory_label": ("mandatorylabel", "mandatory label"),
    "status_code": ("status",),
    "failure_reason": ("failurereason", "failure reason"),
    "sub_status": ("substatus", "sub status"),
    "authentication_package": (
        "authenticationpackagename",
        "authentication package name",
    ),
    "logon_process": ("logonprocessname", "logon process name"),
}

# The supplied schemas omit these events. Their fixture fields stay isolated
# so real schemas can replace this table later.
_SYNTHETIC_HEADER_ALIASES = {
    "group_name": ("group name",),
    "member_name": ("membername", "member name"),
}

_METADATA_FIELDS = tuple(_REAL_HEADER_ALIASES) + tuple(_SYNTHETIC_HEADER_ALIASES)
_SYNTHETIC_EVENT_IDS = {"4720", "4728", "4732"}


class WindowsEventLogParser:
    """Parse exported Windows Security Event Log CSV rows."""

    def parse_lines(
        self, lines: Iterable[str], source: str = "<memory>"
    ) -> Sequence[NormalizedEvent]:
        events: list[NormalizedEvent] = []
        reader = csv.DictReader(lines)
        if reader.fieldnames is None:
            return events

        headers = {
            self._normalize_header(header): header
            for header in reader.fieldnames
            if header is not None
        }
        for row in reader:
            if None in row:
                continue
            event = self._parse_row(row, headers, source)
            if event is not None:
                events.append(event)
        return events

    def parse_file(self, path: Path) -> Sequence[NormalizedEvent]:
        with path.open(
            "r", encoding="utf-8-sig", errors="replace", newline=""
        ) as log_file:
            return self.parse_lines(log_file, str(path))

    def _parse_row(
        self,
        row: Mapping[str, str | None],
        headers: Mapping[str, str],
        source: str,
    ) -> NormalizedEvent | None:
        event_id = self._value(row, headers, "event_id")
        timestamp = self._parse_timestamp(self._value(row, headers, "timestamp"))
        if event_id is None or timestamp is None:
            return None

        target_user = self._value(row, headers, "target_user")
        subject_user = self._value(row, headers, "subject_user")
        metadata: dict[str, object] = {"event_id": event_id}
        for field_name in _METADATA_FIELDS:
            value = self._value(row, headers, field_name, event_id)
            if value is None:
                continue
            if field_name in {
                "process_id",
                "new_process_id",
                "execution_process_id",
                "execution_thread_id",
            }:
                metadata[field_name] = self._coerce_process_id(value)
            else:
                metadata[field_name] = value

        return NormalizedEvent(
            timestamp=timestamp,
            source=source,
            log_type="windows",
            event_type=_EVENT_TYPES.get(event_id, "windows_event"),
            src_ip=self._value(row, headers, "source_ip"),
            user=self._user_for_event(event_id, target_user, subject_user),
            status={"4624": "success", "4625": "failure"}.get(event_id),
            metadata=metadata,
            raw_line=self._safe_raw_line(row),
        )

    @staticmethod
    def _user_for_event(
        event_id: str, target_user: str | None, subject_user: str | None
    ) -> str | None:
        if event_id in _SYNTHETIC_EVENT_IDS:
            return target_user
        if event_id in {"4672", "4688"}:
            return subject_user
        return target_user or subject_user

    @staticmethod
    def _normalize_header(header: str) -> str:
        return " ".join(header.strip().lower().replace("_", " ").split())

    @classmethod
    def _value(
        cls,
        row: Mapping[str, str | None],
        headers: Mapping[str, str],
        field_name: str,
        event_id: str | None = None,
    ) -> str | None:
        aliases = _REAL_HEADER_ALIASES.get(field_name, ())
        if field_name in _SYNTHETIC_HEADER_ALIASES and event_id in _SYNTHETIC_EVENT_IDS:
            aliases = _SYNTHETIC_HEADER_ALIASES[field_name]
        for alias in aliases:
            header = headers.get(cls._normalize_header(alias))
            if header is None:
                continue
            value = row.get(header)
            if value is not None:
                value = value.strip()
                if value and value != "-":
                    return value
        return None

    @staticmethod
    def _parse_timestamp(value: str | None) -> datetime | None:
        if value is None:
            return None
        normalized = value.strip()
        if normalized.endswith("Z"):
            normalized = normalized[:-1] + "+00:00"
        try:
            timestamp = datetime.fromisoformat(normalized)
        except ValueError:
            return None
        if timestamp.tzinfo is not None:
            return timestamp.astimezone(timezone.utc)
        return timestamp

    @staticmethod
    def _coerce_process_id(value: str) -> int | str:
        try:
            return int(value, 0)
        except ValueError:
            return value

    @staticmethod
    def _safe_raw_line(row: Mapping[str, str | None]) -> str:
        return " ".join(
            f"{key}={value}" for key, value in row.items() if key is not None and value
        ).replace("\r", " ").replace("\n", " ")
