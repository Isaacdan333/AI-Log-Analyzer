from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from loganalyzer.detectors.bruteforce import BruteForceDetector
from loganalyzer.detectors.impossible_travel import ImpossibleTravelDetector, Location
from loganalyzer.detectors.port_scan import PortScanDetector
from loganalyzer.detectors.privilege_escalation import PrivilegeEscalationDetector
from loganalyzer.detectors.suspicious_login import SuspiciousLoginDetector
from loganalyzer.detectors.unusual_traffic import UnusualTrafficDetector
from loganalyzer.engine import (
    AnalysisResult,
    analyze_directory,
    analyze_paths,
    analyze_ssh_file,
    discover_log_files,
)
from loganalyzer.models import Alert
from loganalyzer.parsers.ssh import SSHLogParser
from loganalyzer.synthetic.generate_logs import generate_logs

SAMPLES_DIR = Path(__file__).parents[1] / "samples"


def test_sample_log_runs_through_parser_and_detector() -> None:
    sample_path = SAMPLES_DIR / "ssh_bruteforce.log"

    events, alerts = analyze_ssh_file(
        sample_path,
        detector=BruteForceDetector(threshold=5, window_minutes=5),
    )

    assert len(events) == 8
    assert len(alerts) == 1
    assert alerts[0].severity == "HIGH"
    assert alerts[0].evidence["source_ip"] == "192.0.2.10"
    assert alerts[0].evidence["observed_count"] == 5


# --- Multi-file pipeline: parser selection and combination -----------------


def test_single_ssh_file_detects_brute_force() -> None:
    sample_path = SAMPLES_DIR / "ssh_bruteforce.log"

    result = analyze_paths([sample_path])

    assert result.event_count == 8
    assert [path.name for path in result.files_processed] == ["ssh_bruteforce.log"]
    assert result.files_skipped == ()
    assert result.diagnostics == ()
    assert {alert.detector for alert in result.alerts} == {"brute_force"}
    assert result.alerts[0].evidence["source_ip"] == "192.0.2.10"


def test_multiple_ssh_files_are_combined_into_one_analysis(tmp_path: Path) -> None:
    generated = generate_logs(tmp_path, seed=3)
    paths = [generated["ssh_bruteforce"], generated["ssh_post_burst_success"]]

    result = analyze_paths(paths)

    assert len(result.files_processed) == 2
    assert {alert.detector for alert in result.alerts} == {"brute_force", "suspicious_login"}


def test_mixed_ssh_and_firewall_files_run_both_detectors(tmp_path: Path) -> None:
    generated = generate_logs(tmp_path, seed=5)
    paths = [generated["ssh_bruteforce"], generated["firewall_port_scan"]]

    result = analyze_paths(paths)

    assert {alert.detector for alert in result.alerts} == {"brute_force", "port_scan"}


def test_mixed_four_format_directory_parses_each_supported_type(tmp_path: Path) -> None:
    generate_logs(tmp_path, seed=6)

    result = analyze_directory(tmp_path)

    assert {event.log_type for event in result.events} == {"ssh", "firewall", "web", "windows"}
    assert len(result.files_processed) == 7
    assert result.diagnostics == ()


def test_multiple_files_with_same_source_ip_produce_distinct_alerts(tmp_path: Path) -> None:
    base = datetime(2026, 3, 10, 2, 0, tzinfo=timezone.utc)
    first_lines = [
        f"{(base + timedelta(minutes=index)).strftime('%b %d %H:%M:%S')} host sshd[{4000 + index}]: "
        "Failed password for alice from 192.0.2.10 port 22 ssh2"
        for index in range(5)
    ]
    second_lines = [
        f"{(base + timedelta(hours=3, minutes=index)).strftime('%b %d %H:%M:%S')} host sshd[{5000 + index}]: "
        "Failed password for bob from 192.0.2.10 port 22 ssh2"
        for index in range(5)
    ]
    (tmp_path / "ssh_alice.log").write_text("\n".join(first_lines) + "\n", encoding="utf-8")
    (tmp_path / "ssh_bob.log").write_text("\n".join(second_lines) + "\n", encoding="utf-8")

    result = analyze_paths([tmp_path / "ssh_alice.log", tmp_path / "ssh_bob.log"])

    brute_force_alerts = [alert for alert in result.alerts if alert.detector == "brute_force"]
    assert len(brute_force_alerts) == 2
    assert {alert.evidence["username"] for alert in brute_force_alerts} == {"alice", "bob"}
    assert all(alert.evidence["source_ip"] == "192.0.2.10" for alert in brute_force_alerts)


def test_events_from_multiple_files_are_chronologically_ordered(tmp_path: Path) -> None:
    later_path = tmp_path / "ssh_later.log"
    earlier_path = tmp_path / "ssh_earlier.log"
    later_path.write_text(
        "Mar 10 05:00:00 host sshd[1]: Accepted publickey for zoe from 192.0.2.40 port 22 ssh2\n",
        encoding="utf-8",
    )
    earlier_path.write_text(
        "Mar 10 01:00:00 host sshd[1]: Accepted publickey for amy from 192.0.2.41 port 22 ssh2\n",
        encoding="utf-8",
    )

    # Feed the later file first to confirm ordering comes from timestamps, not input order.
    result = analyze_paths([later_path, earlier_path])

    assert [event.user for event in result.events] == ["amy", "zoe"]


def test_events_with_naive_and_aware_timestamps_are_ordered_consistently(tmp_path: Path) -> None:
    windows_header = (
        "EventID,TimeCreated,Computer,IpAddress,TargetUserName,TargetDomainName,"
        "SubjectUserName,SubjectDomainName,LogonType,ProcessName,NewProcessName,"
        "NewProcessId,MemberName,PrivilegeList,Group Name,Unused Column\n"
    )
    windows_path = tmp_path / "windows_security.csv"
    windows_path.write_text(
        windows_header
        + "4624,2026-03-10 02:30:00,host,192.0.2.80,heidi,EXAMPLE,-,-,10,-,-,-,-,-,-,ignored\n",
        encoding="utf-8",
    )
    ssh_path = tmp_path / "ssh_ok.log"
    ssh_path.write_text(
        "Mar 10 02:00:00 host sshd[1]: Accepted publickey for ivan from 192.0.2.81 port 22 ssh2\n",
        encoding="utf-8",
    )

    result = analyze_paths([windows_path, ssh_path])

    assert [event.user for event in result.events] == ["ivan", "heidi"]


# --- Error handling and diagnostics -----------------------------------------


def test_parser_exception_on_one_file_does_not_abort_other_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    good_path = tmp_path / "ssh_good.log"
    good_path.write_text(
        "Mar 10 02:00:00 host sshd[1]: Accepted publickey for dana from 192.0.2.60 port 22 ssh2\n",
        encoding="utf-8",
    )
    broken_path = tmp_path / "ssh_broken.log"
    broken_path.write_text(
        "Mar 10 02:05:00 host sshd[2]: Accepted publickey for erin from 192.0.2.61 port 22 ssh2\n",
        encoding="utf-8",
    )

    original_parse_file = SSHLogParser.parse_file

    def flaky_parse_file(self: SSHLogParser, path: Path):
        if path == broken_path:
            raise ValueError("simulated unreadable log file")
        return original_parse_file(self, path)

    monkeypatch.setattr(SSHLogParser, "parse_file", flaky_parse_file)

    result = analyze_paths([good_path, broken_path])

    assert [event.user for event in result.events] == ["dana"]
    assert result.files_processed == (good_path,)
    assert result.files_skipped == (broken_path,)
    assert len(result.diagnostics) == 1
    assert result.diagnostics[0].path == broken_path
    assert "simulated unreadable log file" in result.diagnostics[0].message


def test_diagnostics_are_recorded_for_unrecognized_format(tmp_path: Path) -> None:
    mystery_path = tmp_path / "mystery.log"
    mystery_path.write_text("nothing here matches a known log format\n", encoding="utf-8")
    valid_path = tmp_path / "ssh_ok.log"
    valid_path.write_text(
        "Mar 10 02:10:00 host sshd[1]: Accepted publickey for frank from 192.0.2.70 port 22 ssh2\n",
        encoding="utf-8",
    )

    result = analyze_paths([mystery_path, valid_path])

    assert result.files_skipped == (mystery_path,)
    assert result.files_processed == (valid_path,)
    assert len(result.diagnostics) == 1
    assert result.diagnostics[0].path == mystery_path
    assert "unable to determine" in result.diagnostics[0].message


def test_csv_file_with_unrecognized_schema_produces_diagnostic(tmp_path: Path) -> None:
    unknown_csv = tmp_path / "unknown.csv"
    unknown_csv.write_text("Column1,Column2\nvalue1,value2\n", encoding="utf-8")

    result = analyze_paths([unknown_csv])

    assert result.files_skipped == (unknown_csv,)
    assert "Windows Security Event Log schema" in result.diagnostics[0].message


def test_empty_input_directory_returns_empty_result(tmp_path: Path) -> None:
    result = analyze_directory(tmp_path)

    assert result == AnalysisResult(
        events=(), alerts=(), diagnostics=(), files_processed=(), files_skipped=()
    )
    assert discover_log_files(tmp_path) == []


def test_unsupported_file_extension_is_not_discovered(tmp_path: Path) -> None:
    (tmp_path / "notes.bin").write_bytes(b"\x00\x01binary data")
    (tmp_path / "ssh_ok.log").write_text(
        "Mar 10 02:11:00 host sshd[1]: Accepted publickey for gary from 192.0.2.71 port 22 ssh2\n",
        encoding="utf-8",
    )

    discovered = discover_log_files(tmp_path)

    assert [path.name for path in discovered] == ["ssh_ok.log"]


# --- Alert deduplication and ordering ---------------------------------------


class _StaticDetector:
    """A fixed-output detector used to test engine-level dedup/sort in isolation."""

    def __init__(self, alerts: tuple[Alert, ...]) -> None:
        self._alerts = alerts

    def detect(self, events: object) -> tuple[Alert, ...]:
        return self._alerts


def _alert(
    *,
    severity: str = "MEDIUM",
    title: str = "Test alert",
    detector: str = "dummy",
    source_ips: tuple[str, ...] = ("192.0.2.1",),
    time_start: datetime | None = None,
) -> Alert:
    start = time_start or datetime(2026, 3, 10, 2, 0, tzinfo=timezone.utc)
    return Alert(
        severity=severity,
        title=title,
        summary="synthetic alert for dedup/sort testing",
        evidence={"note": "synthetic"},
        recommended_actions=("Review",),
        source_ips=source_ips,
        time_start=start,
        time_end=start,
        detector=detector,
    )


def test_duplicate_alerts_from_the_same_incident_are_merged() -> None:
    duplicate = _alert()
    distinct = _alert(time_start=datetime(2026, 3, 10, 3, 0, tzinfo=timezone.utc))

    result = analyze_paths([], detectors=[_StaticDetector((duplicate, duplicate, distinct))])

    assert len(result.alerts) == 2
    assert duplicate in result.alerts
    assert distinct in result.alerts


def test_alerts_with_different_source_ips_are_not_merged() -> None:
    first = _alert(source_ips=("192.0.2.1",))
    second = _alert(source_ips=("192.0.2.2",))

    result = analyze_paths([], detectors=[_StaticDetector((first, second))])

    assert len(result.alerts) == 2


def test_alerts_are_sorted_by_severity_then_time() -> None:
    early_high = _alert(
        severity="HIGH", title="early high", time_start=datetime(2026, 3, 10, 1, 0, tzinfo=timezone.utc)
    )
    late_critical = _alert(
        severity="CRITICAL", title="late critical", time_start=datetime(2026, 3, 10, 5, 0, tzinfo=timezone.utc)
    )
    late_high = _alert(
        severity="HIGH", title="late high", time_start=datetime(2026, 3, 10, 4, 0, tzinfo=timezone.utc)
    )
    early_medium = _alert(
        severity="MEDIUM", title="early medium", time_start=datetime(2026, 3, 10, 0, 0, tzinfo=timezone.utc)
    )

    result = analyze_paths(
        [], detectors=[_StaticDetector((early_medium, late_high, late_critical, early_high))]
    )

    assert [alert.title for alert in result.alerts] == [
        "late critical",
        "early high",
        "late high",
        "early medium",
    ]


# --- End-to-end integration test ---------------------------------------------


def test_end_to_end_pipeline_detects_all_deterministic_alert_types(tmp_path: Path) -> None:
    """samples -> parser selection -> parsers -> NormalizedEvent -> engine -> detectors -> Alert."""
    generate_logs(tmp_path, seed=21)

    # Regenerate the traffic spike two hours after the baseline window so the
    # unusual-traffic detector has an established baseline before the spike,
    # matching the pattern already verified in tests/test_detectors.py.
    base_time = datetime(2026, 3, 10, 2, 0, tzinfo=timezone.utc)
    spike_lines = [
        f'198.51.100.44 - - [{(base_time + timedelta(hours=2, seconds=index * 3)).strftime("%d/%b/%Y:%H:%M:%S %z")}] '
        '"GET /api/search HTTP/1.1" 200 900 "-" "SyntheticBrowser/1.0"'
        for index in range(30)
    ]
    (tmp_path / "web_spike.log").write_text("\n".join(spike_lines) + "\n", encoding="utf-8")

    travel_locations = {
        "192.0.2.201": Location(40.7128, -74.0060, "Synthetic New York"),
        "198.51.100.201": Location(51.5074, -0.1278, "Synthetic London"),
    }

    result = analyze_directory(
        tmp_path,
        detectors=[
            BruteForceDetector(),
            PortScanDetector(),
            SuspiciousLoginDetector(),
            PrivilegeEscalationDetector(),
            ImpossibleTravelDetector(travel_locations),
            UnusualTrafficDetector(grouping="service"),
        ],
    )

    assert result.diagnostics == ()
    assert len(result.files_processed) == 7

    detector_names = {alert.detector for alert in result.alerts}
    assert detector_names == {
        "brute_force",
        "port_scan",
        "suspicious_login",
        "privilege_escalation",
        "impossible_travel",
        "unusual_traffic",
    }
