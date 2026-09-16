from datetime import datetime, timezone

import json
from pathlib import Path

import pytest

from loganalyzer.engine import AnalysisResult, ParserDiagnostic
from loganalyzer.models import Alert
from loganalyzer.report import format_alert, format_alerts, format_json_report, format_text_report


ALERT = Alert(
    severity="HIGH",
    title="Potential brute-force attack detected",
    summary="Five failed SSH login attempts were observed.",
    evidence={
        "observed_count": 5,
        "source_ip": "192.0.2.10",
        "username": "admin",
        "window_minutes": 5,
    },
    recommended_actions=("Review successful logins", "Apply a network block after review"),
    source_ips=("192.0.2.10",),
    time_start=datetime(2026, 3, 10, 2, 14, tzinfo=timezone.utc),
    time_end=datetime(2026, 3, 10, 2, 18, tzinfo=timezone.utc),
    detector="brute_force",
)


def test_format_alert_contains_observations_and_recommendations() -> None:
    report = format_alert(ALERT)

    assert "Severity: HIGH" in report
    assert "Potential brute-force attack detected" in report
    assert "Five failed SSH login attempts were observed." in report
    assert "Observed evidence:" in report
    assert "Observed count: 5" in report
    assert "Detector: brute_force" in report
    assert "Source IPs: 192.0.2.10" in report
    assert "Time range: 2026-03-10T02:14:00+00:00 - 2026-03-10T02:18:00+00:00" in report
    assert "Recommended actions:" in report
    assert "1. Review successful logins" in report
    assert "2. Apply a network block after review" in report


def test_format_alert_does_not_add_unprovided_facts() -> None:
    report = format_alert(ALERT)

    assert "185." not in report
    assert "47 failed" not in report
    assert "CRITICAL" not in report


def test_format_alerts_separates_multiple_alerts() -> None:
    report = format_alerts([ALERT, ALERT])

    assert report.count("Severity: HIGH") == 2
    assert "Recommended actions:" in report
    assert "\n\nSeverity: HIGH" in report


def _result(
    *,
    alerts: tuple[Alert, ...] = (),
    events: tuple[object, ...] = (),
    diagnostics: tuple[ParserDiagnostic, ...] = (),
    files_processed: tuple[Path, ...] = (),
    files_skipped: tuple[Path, ...] = (),
) -> AnalysisResult:
    return AnalysisResult(
        events=events,  # type: ignore[arg-type]
        alerts=alerts,
        diagnostics=diagnostics,
        files_processed=files_processed,
        files_skipped=files_skipped,
    )


def test_empty_analysis_result_formats_cleanly() -> None:
    report = format_text_report(_result())

    assert "Files processed:\nNone" in report
    assert "Files skipped:\nNone" in report
    assert "Total normalized events: 0" in report
    assert "Number of alerts: 0" in report
    assert "Parser diagnostics/errors:\nNone" in report
    assert report.endswith("Alerts:\nNone")


def test_analysis_with_no_alerts_preserves_event_count() -> None:
    result = _result(events=(object(),))

    assert "Total normalized events: 1" in format_text_report(result)


def test_text_report_renders_alerts_in_supplied_order() -> None:
    low_alert = Alert(
        severity="LOW",
        title="Low priority",
        summary="Low finding.",
        evidence={},
        recommended_actions=(),
        detector="low_detector",
    )
    result = _result(alerts=(low_alert, ALERT))
    report = format_text_report(result)

    assert report.index("Low priority") < report.index(ALERT.title)
    assert "Number of alerts: 2" in report


def test_text_report_renders_diagnostics_and_skipped_files() -> None:
    skipped = Path("unknown.log")
    result = _result(
        diagnostics=(ParserDiagnostic(skipped, "unrecognized log format"),),
        files_processed=(Path("ssh.log"),),
        files_skipped=(skipped,),
    )
    report = format_text_report(result)

    assert "- ssh.log" in report
    assert "- unknown.log" in report
    assert "- unknown.log: unrecognized log format" in report


def test_alert_handles_empty_optional_fields() -> None:
    alert = Alert("LOW", "Sparse finding", "Observed finding.", {}, (), confidence=None)
    report = format_alert(alert)

    assert "Observed evidence:\nNone supplied" in report
    assert "Recommended actions:\nNone supplied" in report
    assert "Source IPs:" not in report
    assert "Confidence:" not in report


def test_json_report_preserves_structured_fields_and_datetimes() -> None:
    alert = Alert(
        **{
            "severity": "HIGH", "title": "Structured finding", "summary": "Details.",
            "evidence": {"nested": {"observed_at": ALERT.time_start}},
            "recommended_actions": ("Review",), "source_ips": ("192.0.2.10",),
            "time_start": ALERT.time_start, "time_end": ALERT.time_end,
            "detector": "brute_force", "confidence": "high",
        }
    )
    payload = json.loads(format_json_report(_result(alerts=(alert,))))

    assert payload["event_count"] == 0
    assert payload["alerts"][0]["evidence"] == {
        "nested": {"observed_at": "2026-03-10T02:14:00+00:00"}
    }
    assert payload["alerts"][0]["time_end"] == "2026-03-10T02:18:00+00:00"
    assert payload["alerts"][0]["confidence"] == "high"
    assert set(payload) == {"files_processed", "files_skipped", "event_count", "diagnostics", "alerts"}


def test_json_report_includes_null_confidence_and_diagnostic_structure() -> None:
    diagnostic = ParserDiagnostic(Path("bad.csv"), "invalid schema", "windows")
    payload = json.loads(format_json_report(_result(alerts=(ALERT,), diagnostics=(diagnostic,))))

    assert payload["alerts"][0]["confidence"] is None
    assert payload["diagnostics"] == [
        {"path": "bad.csv", "message": "invalid schema", "format": "windows"}
    ]


def test_reports_are_deterministic() -> None:
    result = _result(alerts=(ALERT,), files_processed=(Path("ssh.log"),))

    assert format_text_report(result) == format_text_report(result)
    assert format_json_report(result) == format_json_report(result)


@pytest.mark.parametrize(
    "detector",
    ("brute_force", "port_scan", "suspicious_login", "privilege_escalation", "impossible_travel", "unusual_traffic"),
)
def test_all_detector_alert_types_appear_in_reports(detector: str) -> None:
    alert = Alert("MEDIUM", f"{detector} finding", "Observed finding.", {}, (), detector=detector)
    result = _result(alerts=(alert,))

    assert f"Detector: {detector}" in format_text_report(result)
    assert json.loads(format_json_report(result))["alerts"][0]["detector"] == detector
