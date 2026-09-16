"""Coordinates parsing, detection, and reporting inputs.

This module is the unified multi-file analysis pipeline. It discovers input
files, selects the appropriate parser for each one, normalizes their events,
runs the full deterministic detector set, and returns a structured result.
The engine never implements parser- or detector-specific logic itself; it
only coordinates the existing components in ``loganalyzer.parsers`` and
``loganalyzer.detectors``.
"""

from __future__ import annotations

import csv
import itertools
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path

from loganalyzer.detectors.base import Detector
from loganalyzer.detectors.bruteforce import BruteForceDetector
from loganalyzer.detectors.impossible_travel import ImpossibleTravelDetector, LocationValue
from loganalyzer.detectors.port_scan import PortScanDetector
from loganalyzer.detectors.privilege_escalation import PrivilegeEscalationDetector
from loganalyzer.detectors.suspicious_login import SuspiciousLoginDetector
from loganalyzer.detectors.unusual_traffic import UnusualTrafficDetector
from loganalyzer.models import Alert, NormalizedEvent
from loganalyzer.parsers.base import LogParser
from loganalyzer.parsers.firewall import FirewallLogParser
from loganalyzer.parsers.ssh import SSHLogParser
from loganalyzer.parsers.webserver import WebServerLogParser
from loganalyzer.parsers.windows_evt import WindowsEventLogParser


def analyze_ssh_file(
    path: Path,
    parser: SSHLogParser | None = None,
    detector: BruteForceDetector | None = None,
) -> tuple[Sequence[NormalizedEvent], Sequence[Alert]]:
    """Parse one SSH log and run the configured brute-force detector."""
    active_parser = parser or SSHLogParser()
    active_detector = detector or BruteForceDetector()
    events = active_parser.parse_file(path)
    alerts = active_detector.detect(events)
    return events, alerts


# --- Structured analysis result -------------------------------------------


@dataclass(frozen=True, slots=True)
class ParserDiagnostic:
    """A non-fatal problem encountered while selecting a parser or parsing a file."""

    path: Path
    message: str
    format: str | None = None


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    """Structured output of the multi-file analysis pipeline."""

    events: tuple[NormalizedEvent, ...]
    alerts: tuple[Alert, ...]
    diagnostics: tuple[ParserDiagnostic, ...]
    files_processed: tuple[Path, ...]
    files_skipped: tuple[Path, ...]

    @property
    def event_count(self) -> int:
        return len(self.events)


# --- Parser selection -------------------------------------------------------

_SUPPORTED_SUFFIXES = frozenset({".log", ".txt", ".csv"})

_TEXT_PARSER_FACTORIES: dict[str, Callable[[], LogParser]] = {
    "ssh": SSHLogParser,
    "firewall": FirewallLogParser,
    "web": WebServerLogParser,
}

# Filename keywords checked before falling back to content sniffing.
_NAME_HINTS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("ssh", ("ssh", "auth", "secure")),
    ("firewall", ("firewall", "iptables", "netfilter", "fw")),
    ("web", ("web", "access", "nginx", "apache", "http")),
)

_SNIFF_LINE_LIMIT = 50


def discover_log_files(directory: Path) -> list[Path]:
    """Return supported log files in a directory, sorted for determinism."""
    if not directory.exists():
        raise FileNotFoundError(f"input directory does not exist: {directory}")
    if not directory.is_dir():
        raise NotADirectoryError(f"input path is not a directory: {directory}")
    return sorted(
        path
        for path in directory.iterdir()
        if path.is_file() and path.suffix.lower() in _SUPPORTED_SUFFIXES
    )


def _hint_from_filename(path: Path) -> str | None:
    name = path.stem.lower()
    for format_name, keywords in _NAME_HINTS:
        if any(keyword in name for keyword in keywords):
            return format_name
    return None


def _sniff_text_format(path: Path) -> str | None:
    """Pick the text parser that recognizes the most sampled lines, if any."""
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            sample_lines = [
                line for line in itertools.islice(handle, _SNIFF_LINE_LIMIT) if line.strip()
            ]
    except OSError:
        return None
    if not sample_lines:
        return None

    scores = {format_name: 0 for format_name in _TEXT_PARSER_FACTORIES}
    for format_name, factory in _TEXT_PARSER_FACTORIES.items():
        candidate_parser = factory()
        scores[format_name] = sum(
            1 for line in sample_lines if candidate_parser.parse_line(line) is not None
        )

    best_score = max(scores.values())
    if best_score == 0:
        return None
    winners = [name for name, score in scores.items() if score == best_score]
    if len(winners) != 1:
        return None
    return winners[0]


def _normalize_csv_header(header: str) -> str:
    return " ".join(header.strip().lower().replace("_", " ").split())


def _looks_like_windows_csv(path: Path) -> bool:
    try:
        with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
            header = next(csv.reader(handle), None)
    except OSError:
        return False
    if not header:
        return False
    normalized = {_normalize_csv_header(column) for column in header if column}
    return "event id" in normalized or "eventid" in normalized


def select_parser(
    path: Path, explicit_format: str | None = None
) -> tuple[LogParser | None, str | None, str | None]:
    """Return ``(parser, format_name, diagnostic_reason)`` for one file.

    When ``explicit_format`` is given, it is trusted directly. Otherwise the
    parser is chosen from filename hints, falling back to sniffing sample
    lines against each text parser. If no format can be identified
    confidently, ``parser`` is ``None`` and a diagnostic reason is returned
    instead of guessing.
    """
    if explicit_format is not None:
        if explicit_format == "windows":
            return WindowsEventLogParser(), "windows", None
        factory = _TEXT_PARSER_FACTORIES.get(explicit_format)
        if factory is None:
            return None, None, f"unknown explicit format '{explicit_format}'"
        return factory(), explicit_format, None

    suffix = path.suffix.lower()
    if suffix == ".csv":
        if _looks_like_windows_csv(path):
            return WindowsEventLogParser(), "windows", None
        return None, None, "CSV file does not match the Windows Security Event Log schema"

    format_name = _hint_from_filename(path) or _sniff_text_format(path)
    if format_name is None:
        return None, None, "unable to determine log format from filename or content"
    return _TEXT_PARSER_FACTORIES[format_name](), format_name, None


# --- Multi-file analysis pipeline ------------------------------------------


def _as_aware_utc(event: NormalizedEvent) -> NormalizedEvent:
    """Normalize a naive timestamp to UTC so detectors never compare naive/aware datetimes.

    Per the shared event model, ``timestamp`` is meant to be timezone-aware;
    this only backfills a missing zone and never reinterprets an existing one.
    """
    if event.timestamp.tzinfo is None:
        return replace(event, timestamp=event.timestamp.replace(tzinfo=timezone.utc))
    return event


def _event_sort_key(event: NormalizedEvent) -> datetime:
    timestamp = event.timestamp
    if timestamp.tzinfo is None:
        return timestamp.replace(tzinfo=timezone.utc)
    return timestamp.astimezone(timezone.utc)


_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
_MIN_TIME = datetime.min.replace(tzinfo=timezone.utc)


def _alert_sort_key(alert: Alert) -> tuple[int, datetime]:
    rank = _SEVERITY_RANK.get(alert.severity, len(_SEVERITY_RANK))
    time_start = alert.time_start or alert.time_end or _MIN_TIME
    if time_start.tzinfo is None:
        time_start = time_start.replace(tzinfo=timezone.utc)
    else:
        time_start = time_start.astimezone(timezone.utc)
    return (rank, time_start)


def _alert_identity(alert: Alert) -> tuple[object, ...]:
    return (
        alert.detector,
        alert.severity,
        alert.title,
        tuple(sorted(alert.source_ips)),
        alert.time_start,
        alert.time_end,
    )


def _deduplicate_alerts(alerts: Iterable[Alert]) -> list[Alert]:
    """Collapse alerts that share detector, severity, title, sources, and time range.

    This is intentionally conservative: it only merges alerts that are
    identical across every identity field above. Alerts that differ in
    evidence-driven fields such as source IPs or time range - even from the
    same detector and severity - are preserved as distinct incidents.
    """
    seen: dict[tuple[object, ...], Alert] = {}
    for alert in alerts:
        seen.setdefault(_alert_identity(alert), alert)
    return list(seen.values())


def _default_detectors(
    impossible_travel_locations: Mapping[str, LocationValue] | None,
) -> list[Detector]:
    return [
        BruteForceDetector(),
        PortScanDetector(),
        SuspiciousLoginDetector(),
        PrivilegeEscalationDetector(),
        ImpossibleTravelDetector(impossible_travel_locations or {}),
        UnusualTrafficDetector(),
    ]


def analyze_paths(
    paths: Iterable[Path],
    *,
    formats: Mapping[Path, str] | None = None,
    detectors: Sequence[Detector] | None = None,
    impossible_travel_locations: Mapping[str, LocationValue] | None = None,
) -> AnalysisResult:
    """Run the full deterministic pipeline over an explicit collection of files.

    Each file is parsed independently; a malformed or unrecognized file is
    recorded as a diagnostic and skipped without stopping analysis of the
    remaining files.
    """
    format_overrides = formats or {}
    events: list[NormalizedEvent] = []
    diagnostics: list[ParserDiagnostic] = []
    files_processed: list[Path] = []
    files_skipped: list[Path] = []

    for path in paths:
        if not path.is_file():
            diagnostics.append(ParserDiagnostic(path=path, message="path is not a file"))
            files_skipped.append(path)
            continue

        parser, format_name, reason = select_parser(path, format_overrides.get(path))
        if parser is None:
            diagnostics.append(
                ParserDiagnostic(path=path, message=reason or "unrecognized log format")
            )
            files_skipped.append(path)
            continue

        try:
            file_events = parser.parse_file(path)
        except Exception as error:  # noqa: BLE001 - untrusted input must not abort the run
            diagnostics.append(
                ParserDiagnostic(
                    path=path,
                    message=f"failed to parse file: {error}",
                    format=format_name,
                )
            )
            files_skipped.append(path)
            continue

        events.extend(file_events)
        files_processed.append(path)

    events = [_as_aware_utc(event) for event in events]
    events.sort(key=_event_sort_key)

    active_detectors = (
        list(detectors)
        if detectors is not None
        else _default_detectors(impossible_travel_locations)
    )
    raw_alerts: list[Alert] = []
    for detector in active_detectors:
        raw_alerts.extend(detector.detect(events))

    ordered_alerts = sorted(_deduplicate_alerts(raw_alerts), key=_alert_sort_key)

    return AnalysisResult(
        events=tuple(events),
        alerts=tuple(ordered_alerts),
        diagnostics=tuple(diagnostics),
        files_processed=tuple(files_processed),
        files_skipped=tuple(files_skipped),
    )


def analyze_directory(
    directory: Path,
    *,
    formats: Mapping[Path, str] | None = None,
    detectors: Sequence[Detector] | None = None,
    impossible_travel_locations: Mapping[str, LocationValue] | None = None,
) -> AnalysisResult:
    """Discover supported log files in ``directory`` and run the full pipeline."""
    return analyze_paths(
        discover_log_files(directory),
        formats=formats,
        detectors=detectors,
        impossible_travel_locations=impossible_travel_locations,
    )
