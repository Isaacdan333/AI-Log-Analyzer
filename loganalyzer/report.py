"""Deterministic text and JSON formatting for analysis results."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
import json
from pathlib import Path
from typing import Any

from loganalyzer.engine import AnalysisResult, ParserDiagnostic
from loganalyzer.models import Alert


def format_alert(alert: Alert) -> str:
    """Format one alert without adding facts beyond its structured fields."""
    lines = [
        f"Severity: {alert.severity}",
        f"Detector: {alert.detector}",
        f"Title: {alert.title}",
        f"Summary: {alert.summary}",
        "",
        "Observed evidence:",
    ]
    if alert.evidence:
        for key, value in alert.evidence.items():
            lines.append(f"{_label(key)}: {_format_value(value)}")
    else:
        lines.append("None supplied")

    if alert.source_ips:
        lines.append(f"Source IPs: {_format_value(alert.source_ips)}")
    lines.append(f"Time range: {_format_time_range(alert.time_start, alert.time_end)}")
    if alert.confidence is not None:
        lines.append(f"Confidence: {_format_value(alert.confidence)}")

    lines.extend(["", "Recommended actions:"])
    if alert.recommended_actions:
        lines.extend(
            f"{index}. {action}"
            for index, action in enumerate(alert.recommended_actions, start=1)
        )
    else:
        lines.append("None supplied")
    return "\n".join(lines)


def format_alerts(alerts: Iterable[Alert]) -> str:
    """Format multiple alerts separated by a blank line."""
    return "\n\n".join(format_alert(alert) for alert in alerts)


def format_text_report(result: AnalysisResult) -> str:
    """Format an analysis result without altering its findings or their order."""
    lines = [
        "Analysis report",
        "",
        "Files processed:",
        *_format_paths(result.files_processed),
        "",
        "Files skipped:",
        *_format_paths(result.files_skipped),
        "",
        f"Total normalized events: {result.event_count}",
        f"Number of alerts: {len(result.alerts)}",
        "",
        "Parser diagnostics/errors:",
        *_format_diagnostics(result.diagnostics),
        "",
        "Alerts:",
    ]
    if result.alerts:
        lines.extend(["", format_alerts(result.alerts)])
    else:
        lines.append("None")
    return "\n".join(lines)


def format_json_report(result: AnalysisResult) -> str:
    """Serialize an analysis result into deterministic, machine-readable JSON."""
    payload = {
        "files_processed": [_json_value(path) for path in result.files_processed],
        "files_skipped": [_json_value(path) for path in result.files_skipped],
        "event_count": result.event_count,
        "diagnostics": [_diagnostic_data(diagnostic) for diagnostic in result.diagnostics],
        "alerts": [_alert_data(alert) for alert in result.alerts],
    }
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True)


def _format_paths(paths: Iterable[Path]) -> list[str]:
    entries = [str(path) for path in paths]
    return [f"- {entry}" for entry in entries] or ["None"]


def _format_diagnostics(diagnostics: Iterable[ParserDiagnostic]) -> list[str]:
    entries = []
    for diagnostic in diagnostics:
        format_suffix = f" (format: {diagnostic.format})" if diagnostic.format else ""
        entries.append(f"- {diagnostic.path}: {diagnostic.message}{format_suffix}")
    return entries or ["None"]


def _alert_data(alert: Alert) -> dict[str, Any]:
    return {
        "severity": alert.severity,
        "title": alert.title,
        "summary": alert.summary,
        "evidence": _json_value(alert.evidence),
        "recommended_actions": _json_value(alert.recommended_actions),
        "source_ips": _json_value(alert.source_ips),
        "time_start": _json_value(alert.time_start),
        "time_end": _json_value(alert.time_end),
        "detector": alert.detector,
        "confidence": _json_value(alert.confidence),
    }


def _diagnostic_data(diagnostic: ParserDiagnostic) -> dict[str, Any]:
    return {
        "path": str(diagnostic.path),
        "message": diagnostic.message,
        "format": diagnostic.format,
    }


def _json_value(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_value(item) for item in value]
    return value


def _label(key: str) -> str:
    return key.replace("_", " ").capitalize()


def _format_value(value: Any) -> str:
    if isinstance(value, tuple):
        return ", ".join(str(item) for item in value)
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _format_time_range(start: datetime | None, end: datetime | None) -> str:
    if start is None and end is None:
        return "Not available"
    if start == end:
        return _format_value(start)
    return f"{_format_value(start)} - {_format_value(end)}"
