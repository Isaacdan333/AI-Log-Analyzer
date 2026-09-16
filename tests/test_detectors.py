from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from loganalyzer.detectors.bruteforce import BruteForceDetector
from loganalyzer.detectors.impossible_travel import ImpossibleTravelDetector, Location
from loganalyzer.detectors.port_scan import PortScanDetector
from loganalyzer.detectors.privilege_escalation import PrivilegeEscalationDetector
from loganalyzer.detectors.suspicious_login import SuspiciousLoginDetector
from loganalyzer.detectors.unusual_traffic import UnusualTrafficDetector
from loganalyzer.models import NormalizedEvent
from loganalyzer.parsers.firewall import FirewallLogParser
from loganalyzer.parsers.ssh import SSHLogParser
from loganalyzer.parsers.webserver import WebServerLogParser
from loganalyzer.parsers.windows_evt import WindowsEventLogParser
from loganalyzer.synthetic.generate_logs import generate_logs


BASE_TIME = datetime(2026, 3, 10, 2, 0, tzinfo=timezone.utc)


def failed_event(minutes_after: int, user: str = "admin") -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=BASE_TIME + timedelta(minutes=minutes_after),
        source="auth.log",
        log_type="ssh",
        event_type="login_failure",
        src_ip="192.0.2.10",
        user=user,
        status="failure",
    )


def test_below_threshold_does_not_alert() -> None:
    detector = BruteForceDetector(threshold=5, window_minutes=5)

    assert detector.detect([failed_event(index) for index in range(4)]) == []


def test_exactly_at_threshold_alerts() -> None:
    detector = BruteForceDetector(threshold=5, window_minutes=5)

    alerts = detector.detect([failed_event(index) for index in range(5)])

    assert len(alerts) == 1
    assert alerts[0].severity == "HIGH"
    assert alerts[0].evidence["observed_count"] == 5


def test_activity_outside_window_does_not_alert() -> None:
    detector = BruteForceDetector(threshold=5, window_minutes=5)
    events = [failed_event(index * 6) for index in range(5)]

    assert detector.detect(events) == []


def test_alert_contains_structured_evidence() -> None:
    detector = BruteForceDetector(threshold=5, window_minutes=5)

    alert = detector.detect([failed_event(index) for index in range(5)])[0]

    assert alert.evidence["source_ip"] == "192.0.2.10"
    assert alert.evidence["username"] == "admin"
    assert alert.evidence["threshold"] == 5
    assert alert.evidence["window_minutes"] == 5
    assert alert.source_ips == ("192.0.2.10",)
    assert alert.detector == "brute_force"
    assert alert.time_start == BASE_TIME
    assert alert.time_end == BASE_TIME + timedelta(minutes=4)


def test_successful_login_is_not_a_brute_force_failure() -> None:
    parser = SSHLogParser(default_year=2026)
    events = parser.parse_lines(
        [
            "Mar 10 02:00:00 host sshd[123]: Accepted password for admin from 192.0.2.10 port 22 ssh2"
        ]
    )

    assert events[0].event_type == "login_success"
    assert BruteForceDetector().detect(events) == []


def network_event(
    seconds_after: int,
    destination_port: int,
    *,
    source_ip: str = "203.0.113.99",
    destination_ip: str = "198.51.100.10",
    status: str = "dropped",
) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=BASE_TIME + timedelta(seconds=seconds_after),
        source="firewall.log",
        log_type="firewall",
        event_type="network_connection",
        src_ip=source_ip,
        dst_ip=destination_ip,
        dst_port=destination_port,
        protocol="TCP",
        status=status,
    )


def test_port_scan_below_threshold_does_not_alert() -> None:
    detector = PortScanDetector()

    assert detector.detect([network_event(index, 1000 + index) for index in range(9)]) == []


def test_port_scan_exactly_at_medium_threshold_alerts() -> None:
    alert = PortScanDetector().detect(
        [network_event(index, 1000 + index) for index in range(10)]
    )[0]

    assert alert.severity == "MEDIUM"
    assert alert.evidence["threshold_crossed"] == "medium"


def test_port_scan_high_threshold_alerts() -> None:
    alert = PortScanDetector().detect(
        [network_event(index, 1000 + index) for index in range(25)]
    )[0]

    assert alert.severity == "HIGH"
    assert alert.evidence["threshold_crossed"] == "high"


def test_port_scan_outside_window_does_not_alert() -> None:
    events = [network_event(index * 61, 1000 + index) for index in range(10)]

    assert PortScanDetector().detect(events) == []


def test_repeated_destination_ports_count_once() -> None:
    events = [network_event(index, 1000 + index % 9) for index in range(20)]

    assert PortScanDetector().detect(events) == []


def test_port_scan_counts_multiple_destination_hosts() -> None:
    events = [
        network_event(index, 1000 + index, destination_ip=f"198.51.100.{index % 2 + 10}")
        for index in range(10)
    ]

    alert = PortScanDetector().detect(events)[0]

    assert alert.evidence["distinct_destination_ports"] == 10
    assert alert.evidence["distinct_destination_hosts"] == 2


def test_mostly_denied_multi_host_activity_can_be_critical() -> None:
    events = [
        network_event(index, 1000 + index, destination_ip=f"198.51.100.{index % 2 + 10}")
        for index in range(50)
    ]
    events[0] = network_event(0, 1000, status="accepted")

    alert = PortScanDetector().detect(events)[0]

    assert alert.severity == "CRITICAL"
    assert alert.evidence["denied_rejected_count"] == 49
    assert alert.evidence["distinct_destination_hosts"] == 2


def test_port_scan_analyzes_sources_independently() -> None:
    events = [
        network_event(index, 1000 + index, source_ip="192.0.2.10")
        for index in range(9)
    ] + [
        network_event(index, 2000 + index, source_ip="192.0.2.11")
        for index in range(10)
    ]

    alerts = PortScanDetector().detect(events)

    assert len(alerts) == 1
    assert alerts[0].source_ips == ("192.0.2.11",)


def test_port_scan_alert_contains_evidence_and_time_range() -> None:
    events = [network_event(index, 1000 + index) for index in range(10)]
    alert = PortScanDetector().detect(events)[0]

    assert alert.evidence["source_ip"] == "203.0.113.99"
    assert alert.evidence["distinct_destination_ports"] == 10
    assert alert.evidence["distinct_destination_hosts"] == 1
    assert alert.evidence["accepted_count"] == 0
    assert alert.evidence["denied_rejected_count"] == 10
    assert alert.time_start == BASE_TIME
    assert alert.time_end == BASE_TIME + timedelta(seconds=9)
    assert alert.detector == "port_scan"


def test_normal_firewall_activity_does_not_create_excessive_alerts() -> None:
    events = [
        network_event(index, 443, source_ip=f"192.0.2.{index + 1}", status="accepted")
        for index in range(20)
    ]

    assert PortScanDetector().detect(events) == []


# --- Impossible travel detector ------------------------------------------


TRAVEL_LOCATIONS = {
    "192.0.2.201": Location(40.7128, -74.0060, "Synthetic New York"),
    "198.51.100.201": Location(51.5074, -0.1278, "Synthetic London"),
    "192.0.2.202": Location(40.7306, -73.9352, "Synthetic Nearby"),
}


def travel_event(
    minutes_after: int,
    source_ip: str,
    *,
    user: str = "traveler",
    timestamp: datetime | str | None = None,
) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=timestamp or BASE_TIME + timedelta(minutes=minutes_after),
        source="Security.csv",
        log_type="windows",
        event_type="login_success",
        src_ip=source_ip,
        user=user,
        status="success",
    )


def test_nearby_successful_logins_do_not_alert() -> None:
    events = [travel_event(0, "192.0.2.201"), travel_event(60, "192.0.2.202")]

    assert ImpossibleTravelDetector(TRAVEL_LOCATIONS, min_distance_km=100).detect(events) == []


def test_distant_logins_with_plenty_of_time_do_not_alert() -> None:
    events = [travel_event(0, "192.0.2.201"), travel_event(600, "198.51.100.201")]

    assert ImpossibleTravelDetector(TRAVEL_LOCATIONS).detect(events) == []


def test_distant_logins_with_little_time_alert() -> None:
    alerts = ImpossibleTravelDetector(TRAVEL_LOCATIONS).detect(
        [travel_event(0, "192.0.2.201"), travel_event(15, "198.51.100.201")]
    )

    assert len(alerts) == 1
    assert alerts[0].severity == "MEDIUM"
    assert alerts[0].confidence == "low"
    assert alerts[0].detector == "impossible_travel"


def test_exact_threshold_does_not_alert_but_just_above_does() -> None:
    first = travel_event(0, "192.0.2.201")
    second = travel_event(60, "198.51.100.201")
    distance = ImpossibleTravelDetector.distance_km(TRAVEL_LOCATIONS[first.src_ip], TRAVEL_LOCATIONS[second.src_ip])
    threshold = distance / 1

    detector = ImpossibleTravelDetector(TRAVEL_LOCATIONS, max_speed_kmh=threshold)
    assert detector.detect([first, second]) == []
    assert detector.detect([first, travel_event(59, "198.51.100.201")])


def test_users_are_compared_independently() -> None:
    events = [
        travel_event(0, "192.0.2.201", user="alice"),
        travel_event(1, "198.51.100.201", user="bob"),
    ]

    assert ImpossibleTravelDetector(TRAVEL_LOCATIONS).detect(events) == []


def test_unknown_ip_single_login_and_invalid_data_do_not_alert() -> None:
    detector = ImpossibleTravelDetector(
        {"192.0.2.201": TRAVEL_LOCATIONS["192.0.2.201"], "198.51.100.201": (None, 0, "bad")}
    )
    events = [
        travel_event(0, "192.0.2.201"),
        travel_event(1, "203.0.113.250"),
        travel_event(2, "198.51.100.201", timestamp="invalid"),
    ]

    assert detector.detect(events) == []


def test_private_ip_filter_is_configurable() -> None:
    events = [travel_event(0, "192.0.2.201"), travel_event(1, "198.51.100.201")]

    assert ImpossibleTravelDetector(TRAVEL_LOCATIONS, ignore_private_ips=True).detect(events) == []
    assert ImpossibleTravelDetector(TRAVEL_LOCATIONS, ignore_private_ips=False).detect(events)


def test_alert_preserves_calculations_and_approximate_geolocation_note() -> None:
    first = travel_event(0, "192.0.2.201")
    second = travel_event(15, "198.51.100.201")
    alert = ImpossibleTravelDetector(TRAVEL_LOCATIONS).detect([first, second])[0]

    assert alert.evidence["username"] == "traveler"
    assert alert.evidence["first_source_ip"] == first.src_ip
    assert alert.evidence["second_source_ip"] == second.src_ip
    assert alert.evidence["first_login_timestamp"] == first.timestamp
    assert alert.evidence["second_login_timestamp"] == second.timestamp
    assert alert.evidence["first_location"] == "Synthetic New York"
    assert alert.evidence["second_location"] == "Synthetic London"
    assert alert.evidence["elapsed_seconds"] == 900.0
    assert alert.evidence["distance_km"] == pytest.approx(5570, rel=0.01)
    assert alert.evidence["implied_speed_kmh"] == pytest.approx(
        alert.evidence["distance_km"] / 0.25
    )
    assert "synthetic" in alert.evidence["geolocation_note"].lower()
    assert "approximate" in alert.summary.lower()


def test_distance_formula_and_windows_synthetic_integration(tmp_path: Path) -> None:
    assert ImpossibleTravelDetector.distance_km(Location(0, 0, "A"), Location(0, 1, "B")) == pytest.approx(111.195, rel=1e-3)

    path = generate_logs(tmp_path, scenario="windows_security")["windows_security"]
    events = WindowsEventLogParser().parse_file(path)
    alerts = ImpossibleTravelDetector(TRAVEL_LOCATIONS).detect(events)

    traveler_alerts = [alert for alert in alerts if alert.evidence["username"] == "traveler"]
    assert len(traveler_alerts) == 1
    assert traveler_alerts[0].evidence["elapsed_seconds"] == 900.0


def test_synthetic_firewall_log_reaches_port_scan_detector(tmp_path: Path) -> None:
    path = generate_logs(tmp_path, scenario="firewall_port_scan")["firewall_port_scan"]
    events = FirewallLogParser(default_year=2026).parse_file(path)

    alerts = PortScanDetector().detect(events)

    assert len(events) == 10
    assert len(alerts) == 1
    assert alerts[0].severity == "MEDIUM"
    assert alerts[0].evidence["distinct_destination_ports"] == 10
    assert alerts[0].evidence["source_ip"] == "203.0.113.99"


def success_event(
    minutes_after: int,
    user: str = "admin",
    source_ip: str = "192.0.2.10",
    log_type: str = "ssh",
) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=BASE_TIME + timedelta(minutes=minutes_after),
        source="auth.log" if log_type == "ssh" else "Security.csv",
        log_type=log_type,
        event_type="login_success",
        src_ip=source_ip,
        user=user,
        status="success",
    )


def test_post_burst_success_triggers_high_alert() -> None:
    events = [
        failed_event(index, user="target.user")
        for index in range(3)
    ] + [
        success_event(4, user="target.user")
    ]

    detector = SuspiciousLoginDetector(failure_burst_threshold=3, post_burst_window_minutes=10)
    alerts = detector.detect(events)

    assert len(alerts) == 1
    assert alerts[0].severity == "HIGH"
    assert alerts[0].evidence["signal"] == "post_burst_success"
    assert alerts[0].evidence["failed_attempts_count"] == 3
    assert alerts[0].evidence["source_ip"] == "192.0.2.10"
    assert alerts[0].evidence["username"] == "target.user"
    assert alerts[0].detector == "suspicious_login"
    assert alerts[0].time_start == BASE_TIME
    assert alerts[0].time_end == BASE_TIME + timedelta(minutes=4)


def test_post_burst_success_critical_for_large_failure_burst() -> None:
    events = [
        failed_event(index, user="admin")
        for index in range(6)
    ] + [
        success_event(7, user="admin")
    ]

    detector = SuspiciousLoginDetector(failure_burst_threshold=3, post_burst_window_minutes=10)
    alerts = detector.detect(events)

    assert len(alerts) == 1
    assert alerts[0].severity == "CRITICAL"
    assert alerts[0].evidence["failed_attempts_count"] == 6


def test_isolated_success_does_not_trigger_post_burst_alert() -> None:
    events = [
        failed_event(0, user="admin"),
        failed_event(1, user="admin"),
        success_event(2, user="admin"),
    ]

    detector = SuspiciousLoginDetector(failure_burst_threshold=3, post_burst_window_minutes=10)
    assert detector.detect(events) == []


def test_success_outside_post_burst_window_does_not_alert() -> None:
    events = [
        failed_event(0, user="admin"),
        failed_event(1, user="admin"),
        failed_event(2, user="admin"),
        success_event(20, user="admin"),  # 20 mins later, window is 10 mins
    ]

    detector = SuspiciousLoginDetector(failure_burst_threshold=3, post_burst_window_minutes=10)
    assert detector.detect(events) == []


def test_multi_account_success_triggers_alert() -> None:
    events = [
        success_event(0, user="user1", source_ip="198.51.100.50"),
        success_event(2, user="user2", source_ip="198.51.100.50"),
        success_event(4, user="user3", source_ip="198.51.100.50"),
    ]

    detector = SuspiciousLoginDetector(
        multi_account_threshold=3,
        multi_account_window_minutes=15,
    )
    alerts = detector.detect(events)

    assert len(alerts) == 1
    assert alerts[0].severity == "HIGH"
    assert alerts[0].evidence["signal"] == "multi_account_login"
    assert alerts[0].evidence["distinct_users_count"] == 3
    assert alerts[0].evidence["users"] == ["user1", "user2", "user3"]


def test_multi_account_outside_window_does_not_alert() -> None:
    events = [
        success_event(0, user="user1", source_ip="198.51.100.50"),
        success_event(20, user="user2", source_ip="198.51.100.50"),
        success_event(40, user="user3", source_ip="198.51.100.50"),
    ]

    detector = SuspiciousLoginDetector(
        multi_account_threshold=3,
        multi_account_window_minutes=15,
    )
    assert detector.detect(events) == []


def test_off_hours_login_detected_when_enabled() -> None:
    # 02:00 UTC is outside 08:00 - 18:00
    events = [success_event(0, user="analyst", source_ip="192.0.2.10")]

    detector = SuspiciousLoginDetector(
        enable_off_hours=True,
        normal_hours_start=8,
        normal_hours_end=18,
    )
    alerts = detector.detect(events)

    assert len(alerts) == 1
    assert alerts[0].severity == "MEDIUM"
    assert alerts[0].evidence["signal"] == "off_hours_login"


def test_off_hours_login_ignored_when_disabled() -> None:
    events = [success_event(0, user="analyst", source_ip="192.0.2.10")]

    detector = SuspiciousLoginDetector(enable_off_hours=False)
    assert detector.detect(events) == []


def test_synthetic_ssh_post_burst_log_detected(tmp_path: Path) -> None:
    path = generate_logs(tmp_path, scenario="ssh_post_burst_success")["ssh_post_burst_success"]
    events = SSHLogParser(default_year=2026).parse_file(path)

    detector = SuspiciousLoginDetector(failure_burst_threshold=3, post_burst_window_minutes=10)
    alerts = detector.detect(events)

    assert len(alerts) == 1
    assert alerts[0].severity == "HIGH"
    assert alerts[0].evidence["signal"] == "post_burst_success"
    assert alerts[0].evidence["source_ip"] == "198.51.100.99"
    assert alerts[0].evidence["username"] == "target.user"
    assert alerts[0].evidence["failed_attempts_count"] == 5


def test_windows_logon_events_evaluated() -> None:
    events = [
        NormalizedEvent(
            timestamp=BASE_TIME + timedelta(minutes=index),
            source="Security.csv",
            log_type="windows",
            event_type="login_failure",
            src_ip="198.51.100.50",
            user="demo.admin",
            status="failure",
        )
        for index in range(4)
    ] + [
        NormalizedEvent(
            timestamp=BASE_TIME + timedelta(minutes=5),
            source="Security.csv",
            log_type="windows",
            event_type="login_success",
            src_ip="198.51.100.50",
            user="demo.admin",
            status="success",
        )
    ]

    detector = SuspiciousLoginDetector(failure_burst_threshold=3, post_burst_window_minutes=10)
    alerts = detector.detect(events)

    assert len(alerts) == 1
    assert alerts[0].severity == "HIGH"
    assert alerts[0].evidence["failed_attempts_count"] == 4


# --- Privilege escalation detector ---------------------------------------


def windows_event(
    event_id: str,
    minutes_after: int,
    *,
    user: str | None = None,
    computer: str | None = "win-host-01",
    src_ip: str | None = None,
    status: str | None = None,
    metadata: dict[str, object] | None = None,
) -> NormalizedEvent:
    event_types = {
        "4672": "privilege_assignment",
        "4720": "user_created",
        "4728": "privileged_group_membership",
        "4732": "privileged_group_membership",
        "4688": "process_creation",
        "4625": "login_failure",
    }
    merged_metadata: dict[str, object] = {"event_id": event_id}
    if computer is not None:
        merged_metadata["computer"] = computer
    merged_metadata.update(metadata or {})
    return NormalizedEvent(
        timestamp=BASE_TIME + timedelta(minutes=minutes_after),
        source="Security.csv",
        log_type="windows",
        event_type=event_types[event_id],
        src_ip=src_ip,
        user=user,
        status=status,
        metadata=merged_metadata,
    )


def ssh_privilege_action(
    minutes_after: int,
    user: str,
    action: str,
    src_ip: str | None = None,
) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=BASE_TIME + timedelta(minutes=minutes_after),
        source="auth.log",
        log_type="ssh",
        event_type="privilege_action",
        src_ip=src_ip,
        user=user,
        status="executed",
        metadata={"action": action, "service": action},
    )


def test_privilege_assignment_alone_is_isolated_low() -> None:
    events = [windows_event("4672", 0, user="svc.account")]

    alerts = PrivilegeEscalationDetector().detect(events)

    assert len(alerts) == 1
    assert alerts[0].severity == "LOW"
    assert alerts[0].evidence["rule"] == "isolated_privilege_assignment"
    assert alerts[0].evidence["event_id"] == "4672"
    assert alerts[0].evidence["username"] == "svc.account"
    assert alerts[0].detector == "privilege_escalation"
    assert "Special privileges were assigned to a new logon" in alerts[0].summary
    assert "privilege escalation attack confirmed" not in alerts[0].summary.lower()


def test_unrelated_privilege_assignments_do_not_become_high() -> None:
    events = [
        windows_event("4672", 0, user="svc.account.a", computer="host-a"),
        windows_event("4672", 2, user="svc.account.b", computer="host-b"),
    ]

    alerts = PrivilegeEscalationDetector().detect(events)

    assert len(alerts) == 2
    assert all(alert.severity == "LOW" for alert in alerts)


def test_privilege_assignment_after_suspicious_login_is_high() -> None:
    events = [
        windows_event("4625", 0, user="admin", src_ip="203.0.113.5"),
        windows_event("4672", 5, user="admin"),
    ]

    alerts = PrivilegeEscalationDetector().detect(events)

    assert len(alerts) == 1
    assert alerts[0].severity == "HIGH"
    assert alerts[0].evidence["rule"] == "privilege_assignment_after_suspicious_login"
    assert alerts[0].evidence["event_id"] == "4672"
    assert alerts[0].evidence["login_event_id"] == "4625"


def test_privilege_assignment_outside_correlation_window_does_not_escalate() -> None:
    events = [
        windows_event("4625", 0, user="admin", src_ip="203.0.113.5"),
        windows_event("4672", 20, user="admin"),
    ]

    alerts = PrivilegeEscalationDetector(process_correlation_window_minutes=15).detect(events)

    assert len(alerts) == 1
    assert alerts[0].severity == "LOW"
    assert alerts[0].evidence["rule"] == "isolated_privilege_assignment"


def test_new_account_privileged_group_then_4672_is_critical() -> None:
    events = [
        windows_event("4720", 0, user="new.user"),
        windows_event(
            "4728",
            5,
            metadata={"group_name": "Domain Admins", "member_name": "new.user"},
        ),
        windows_event("4672", 10, user="new.user"),
    ]

    alerts = PrivilegeEscalationDetector(correlation_window_minutes=30).detect(events)

    assert len(alerts) == 1
    assert alerts[0].severity == "CRITICAL"
    assert alerts[0].evidence["rule"] == "privilege_escalation_chain"
    assert alerts[0].evidence["related_event_ids"] == ["4720", "4728", "4672"]


def test_4672_followed_by_process_creation_is_high() -> None:
    events = [
        windows_event("4672", 0, user="admin"),
        windows_event(
            "4688",
            5,
            user="admin",
            metadata={"new_process_name": "cmd.exe", "new_process_id": 4096},
        ),
    ]

    alerts = PrivilegeEscalationDetector().detect(events)

    assert len(alerts) == 1
    assert alerts[0].severity == "HIGH"
    assert alerts[0].evidence["rule"] == "process_creation_after_suspicious_login"
    assert alerts[0].evidence["login_event_id"] == "4672"
    assert alerts[0].evidence["process_event_id"] == "4688"


def test_known_administrative_account_downgrades_severity() -> None:
    events = [
        windows_event("4720", 0, user="new.user"),
        windows_event(
            "4728",
            5,
            metadata={"group_name": "Domain Admins", "member_name": "new.user"},
        ),
        windows_event("4672", 10, user="new.user"),
    ]

    alerts = PrivilegeEscalationDetector(
        correlation_window_minutes=30,
        known_administrative_accounts=["new.user"],
    ).detect(events)

    assert len(alerts) == 1
    assert alerts[0].severity == "HIGH"
    assert alerts[0].evidence["known_administrative_account"] is True


def test_account_created_alone_is_isolated_low() -> None:
    events = [windows_event("4720", 0, user="new.user")]

    alerts = PrivilegeEscalationDetector().detect(events)

    assert len(alerts) == 1
    assert alerts[0].severity == "LOW"
    assert alerts[0].evidence["rule"] == "isolated_account_created"
    assert alerts[0].evidence["event_id"] == "4720"


def test_global_group_membership_alone_is_isolated_medium() -> None:
    events = [
        windows_event(
            "4728",
            0,
            metadata={"group_name": "Domain Admins", "member_name": "new.user"},
        )
    ]

    alerts = PrivilegeEscalationDetector().detect(events)

    assert len(alerts) == 1
    assert alerts[0].severity == "MEDIUM"
    assert alerts[0].evidence["rule"] == "isolated_privileged_group_membership"
    assert alerts[0].evidence["group_name"] == "Domain Admins"
    assert alerts[0].evidence["username"] == "new.user"


def test_local_group_membership_alone_is_isolated_medium() -> None:
    events = [
        windows_event(
            "4732",
            0,
            metadata={"group_name": "Administrators", "member_name": "new.user"},
        )
    ]

    alerts = PrivilegeEscalationDetector().detect(events)

    assert len(alerts) == 1
    assert alerts[0].severity == "MEDIUM"
    assert alerts[0].evidence["rule"] == "isolated_privileged_group_membership"
    assert alerts[0].evidence["group_name"] == "Administrators"


def test_non_privileged_group_membership_is_ignored() -> None:
    events = [
        windows_event(
            "4728",
            0,
            metadata={"group_name": "Marketing Team", "member_name": "new.user"},
        )
    ]

    assert PrivilegeEscalationDetector().detect(events) == []


def test_sudo_alone_is_isolated_low() -> None:
    events = [ssh_privilege_action(0, "analyst", "sudo")]

    alerts = PrivilegeEscalationDetector().detect(events)

    assert len(alerts) == 1
    assert alerts[0].severity == "LOW"
    assert alerts[0].evidence["rule"] == "isolated_sudo_activity"
    assert alerts[0].evidence["username"] == "analyst"


def test_su_alone_is_isolated_low() -> None:
    events = [ssh_privilege_action(0, "root", "su")]

    alerts = PrivilegeEscalationDetector().detect(events)

    assert len(alerts) == 1
    assert alerts[0].severity == "LOW"
    assert alerts[0].evidence["rule"] == "isolated_su_activity"


def test_process_creation_after_suspicious_login_is_high() -> None:
    events = [
        windows_event("4625", 0, user="admin", src_ip="203.0.113.5"),
        windows_event(
            "4688",
            5,
            user="admin",
            metadata={"new_process_name": "cmd.exe", "new_process_id": 4096},
        ),
    ]

    alerts = PrivilegeEscalationDetector().detect(events)

    assert len(alerts) == 1
    assert alerts[0].severity == "HIGH"
    assert alerts[0].evidence["rule"] == "process_creation_after_suspicious_login"
    assert alerts[0].evidence["process_name"] == "cmd.exe"
    assert alerts[0].evidence["process_id"] == 4096
    assert alerts[0].evidence["login_event_id"] == "4625"
    assert alerts[0].evidence["process_event_id"] == "4688"


def test_new_account_followed_by_privileged_group_membership_is_high() -> None:
    events = [
        windows_event("4720", 0, user="new.user"),
        windows_event(
            "4728",
            10,
            metadata={"group_name": "Domain Admins", "member_name": "new.user"},
        ),
    ]

    alerts = PrivilegeEscalationDetector().detect(events)

    assert len(alerts) == 1
    assert alerts[0].severity == "HIGH"
    assert alerts[0].evidence["rule"] == "account_created_then_privileged_group_membership"
    assert alerts[0].evidence["created_event_id"] == "4720"
    assert alerts[0].evidence["group_event_id"] == "4728"


def test_new_account_followed_by_privileged_activity_is_high() -> None:
    events = [
        windows_event("4720", 0, user="new.user"),
        windows_event("4672", 10, user="new.user"),
    ]

    alerts = PrivilegeEscalationDetector().detect(events)

    assert len(alerts) == 1
    assert alerts[0].severity == "HIGH"
    assert alerts[0].evidence["rule"] == "privileged_activity_following_new_account"


def test_full_chain_within_window_is_critical() -> None:
    events = [
        windows_event("4720", 0, user="new.user"),
        windows_event(
            "4728",
            5,
            metadata={"group_name": "Domain Admins", "member_name": "new.user"},
        ),
        windows_event("4688", 10, user="new.user", metadata={"new_process_name": "powershell.exe"}),
    ]

    alerts = PrivilegeEscalationDetector(correlation_window_minutes=30).detect(events)

    assert len(alerts) == 1
    assert alerts[0].severity == "CRITICAL"
    assert alerts[0].evidence["rule"] == "privilege_escalation_chain"
    assert alerts[0].evidence["related_event_ids"] == ["4720", "4728", "4688"]
    assert alerts[0].evidence["process_name"] == "powershell.exe"


def test_events_outside_correlation_window_remain_isolated() -> None:
    events = [
        windows_event("4720", 0, user="new.user"),
        windows_event(
            "4728",
            45,
            metadata={"group_name": "Domain Admins", "member_name": "new.user"},
        ),
    ]

    alerts = PrivilegeEscalationDetector(correlation_window_minutes=30).detect(events)

    assert len(alerts) == 2
    rules = {alert.evidence["rule"] for alert in alerts}
    assert rules == {"isolated_account_created", "isolated_privileged_group_membership"}


def test_correlation_window_boundary_is_inclusive() -> None:
    events = [
        windows_event("4720", 0, user="new.user"),
        windows_event(
            "4728",
            30,
            metadata={"group_name": "Domain Admins", "member_name": "new.user"},
        ),
    ]

    alerts = PrivilegeEscalationDetector(correlation_window_minutes=30).detect(events)

    assert len(alerts) == 1
    assert alerts[0].evidence["rule"] == "account_created_then_privileged_group_membership"


def test_correlation_window_boundary_excludes_next_minute() -> None:
    events = [
        windows_event("4720", 0, user="new.user"),
        windows_event(
            "4728",
            31,
            metadata={"group_name": "Domain Admins", "member_name": "new.user"},
        ),
    ]

    alerts = PrivilegeEscalationDetector(correlation_window_minutes=30).detect(events)

    assert len(alerts) == 2
    rules = {alert.evidence["rule"] for alert in alerts}
    assert rules == {"isolated_account_created", "isolated_privileged_group_membership"}


def test_different_users_are_not_correlated() -> None:
    events = [
        windows_event("4720", 0, user="new.user"),
        windows_event(
            "4728",
            5,
            metadata={"group_name": "Domain Admins", "member_name": "other.user"},
        ),
    ]

    alerts = PrivilegeEscalationDetector().detect(events)

    assert len(alerts) == 2
    rules = {alert.evidence["rule"] for alert in alerts}
    assert rules == {"isolated_account_created", "isolated_privileged_group_membership"}


def test_different_hosts_are_not_correlated() -> None:
    events = [
        windows_event("4720", 0, user="new.user", computer="host-a"),
        windows_event(
            "4728",
            5,
            computer="host-b",
            metadata={"group_name": "Domain Admins", "member_name": "new.user"},
        ),
    ]

    alerts = PrivilegeEscalationDetector().detect(events)

    assert len(alerts) == 2
    rules = {alert.evidence["rule"] for alert in alerts}
    assert rules == {"isolated_account_created", "isolated_privileged_group_membership"}


def test_missing_fields_do_not_crash_or_invent_correlation() -> None:
    events = [
        windows_event("4720", 0, user=None, computer=None),
        windows_event(
            "4728",
            5,
            computer=None,
            metadata={"group_name": "Domain Admins", "member_name": None},
        ),
        ssh_privilege_action(10, "analyst", "sudo", src_ip=None),
    ]

    alerts = PrivilegeEscalationDetector().detect(events)

    assert len(alerts) == 3
    assert all(alert.severity in {"LOW", "MEDIUM"} for alert in alerts)


def test_unrelated_events_produce_no_alert() -> None:
    events = [
        NormalizedEvent(
            timestamp=BASE_TIME,
            source="Security.csv",
            log_type="windows",
            event_type="login_success",
            user="analyst",
            status="success",
            metadata={"event_id": "4624", "computer": "win-host-01"},
        ),
        NormalizedEvent(
            timestamp=BASE_TIME + timedelta(minutes=1),
            source="firewall.log",
            log_type="firewall",
            event_type="network_connection",
            src_ip="203.0.113.5",
            dst_ip="198.51.100.10",
            dst_port=443,
            status="accepted",
        ),
    ]

    assert PrivilegeEscalationDetector().detect(events) == []


def test_privilege_escalation_alert_evidence_contains_supporting_fields() -> None:
    events = [
        windows_event("4720", 0, user="new.user", computer="win-host-01"),
        windows_event(
            "4728",
            5,
            computer="win-host-01",
            metadata={"group_name": "Domain Admins", "member_name": "new.user"},
        ),
        windows_event(
            "4688",
            10,
            user="new.user",
            computer="win-host-01",
            metadata={"new_process_name": "powershell.exe", "new_process_id": 2048},
        ),
    ]

    alert = PrivilegeEscalationDetector(correlation_window_minutes=30).detect(events)[0]

    assert alert.severity == "CRITICAL"
    assert alert.evidence["created_event_id"] == "4720"
    assert alert.evidence["group_event_id"] == "4728"
    assert alert.evidence["activity_event_id"] == "4688"
    assert alert.evidence["process_name"] == "powershell.exe"
    assert alert.evidence["process_id"] == 2048
    assert alert.evidence["group_name"] == "Domain Admins"
    assert alert.evidence["username"] == "new.user"
    assert alert.evidence["computer"] == "win-host-01"
    assert alert.evidence["correlation_window_minutes"] == 30
    assert "Potential privilege escalation detected" in alert.summary
    assert alert.detector == "privilege_escalation"


def test_privilege_escalation_integration_from_parsed_logs() -> None:
    windows_header = (
        "EventID,TimeCreated,Computer,IpAddress,TargetUserName,TargetDomainName,"
        "SubjectUserName,SubjectDomainName,LogonType,ProcessName,NewProcessName,"
        "NewProcessId,MemberName,PrivilegeList,Group Name,Unused Column\n"
    )
    windows_lines = windows_header + (
        '4720,2026-03-10T02:00:00Z,synthetic-win,-,new.user,EXAMPLE,demo.admin,EXAMPLE,-,-,-,-,-,-,-,ignored\n'
        '4728,2026-03-10T02:05:00Z,synthetic-win,-,Domain Admins,EXAMPLE,demo.admin,EXAMPLE,-,-,-,-,new.user,-,-,ignored\n'
        '4688,2026-03-10T02:10:00Z,synthetic-win,-,-,-,new.user,EXAMPLE,-,-,"C:\\Windows\\System32\\whoami.exe",0x800,-,-,-,ignored\n'
    )
    ssh_lines = [
        "Mar 10 02:00:00 synthetic-ssh sshd[100]: Failed password for invalid user backdoor from 198.51.100.77 port 22 ssh2",
        "Mar 10 02:00:05 synthetic-ssh sudo: backdoor : TTY=pts/0 ; PWD=/home ; USER=root ; COMMAND=/bin/bash",
    ]

    windows_events = WindowsEventLogParser().parse_lines(windows_lines.splitlines())
    ssh_events = SSHLogParser(default_year=2026).parse_lines(ssh_lines)

    detector = PrivilegeEscalationDetector(correlation_window_minutes=30)
    alerts = detector.detect(list(windows_events) + list(ssh_events))

    rules = {alert.evidence["rule"]: alert for alert in alerts}
    assert "privilege_escalation_chain" in rules
    chain_alert = rules["privilege_escalation_chain"]
    assert chain_alert.severity == "CRITICAL"
    assert chain_alert.evidence["related_event_ids"] == ["4720", "4728", "4688"]

    assert "isolated_sudo_activity" in rules


# --- Unusual traffic detector ---------------------------------------------


def traffic_events(
    bucket_index: int,
    count: int,
    *,
    source_ip: str = "192.0.2.44",
    log_type: str = "web",
    event_type: str = "http_request",
    bytes_sent: int | None = 500,
    path: str = "/",
    status: str = "200",
) -> list[NormalizedEvent]:
    return [
        NormalizedEvent(
            timestamp=BASE_TIME + timedelta(minutes=bucket_index * 5, seconds=second),
            source="access.log",
            log_type=log_type,
            event_type=event_type,
            src_ip=source_ip,
            status=status,
            bytes_sent=bytes_sent,
            path=path,
        )
        for second in range(count)
    ]


def test_insufficient_baseline_history_does_not_alert() -> None:
    events = [event for index in range(4) for event in traffic_events(index, 2)]
    events += traffic_events(4, 20)

    assert UnusualTrafficDetector().detect(events) == []


def test_stable_normal_traffic_does_not_alert() -> None:
    events = [event for index in range(10) for event in traffic_events(index, 3)]

    assert UnusualTrafficDetector().detect(events) == []


def test_clear_traffic_spike_alerts() -> None:
    events = [
        event
        for index, count in enumerate([1, 6, 6, 6, 6])
        for event in traffic_events(index, count)
    ]
    events += traffic_events(5, 50)

    alerts = UnusualTrafficDetector().detect(events)

    assert len(alerts) == 1
    assert alerts[0].title == "Unusual traffic pattern detected"
    assert alerts[0].severity in {"HIGH", "CRITICAL"}
    assert alerts[0].detector == "unusual_traffic"


def test_anomaly_exactly_at_threshold_alerts() -> None:
    events = [
        event
        for index, count in enumerate([1, 6, 6, 6, 6])
        for event in traffic_events(index, count)
    ]
    events += traffic_events(5, 11)

    alerts = UnusualTrafficDetector().detect(events)

    assert len(alerts) == 1
    assert alerts[0].evidence["score"] == pytest.approx(3.0)
    assert alerts[0].severity == "MEDIUM"


def test_just_below_threshold_does_not_alert() -> None:
    events = [
        event
        for index, count in enumerate([1, 6, 6, 6, 6])
        for event in traffic_events(index, count)
    ]
    events += traffic_events(5, 10)

    assert UnusualTrafficDetector().detect(events) == []


def test_different_source_ips_remain_isolated() -> None:
    events = [
        event
        for index, count in enumerate([1, 6, 6, 6, 6])
        for event in traffic_events(index, count, source_ip="192.0.2.44")
    ]
    events += traffic_events(5, 50, source_ip="192.0.2.44")
    events += [
        event
        for index, count in enumerate([1, 6, 6, 6, 6])
        for event in traffic_events(index, count, source_ip="198.51.100.44")
    ]

    alerts = UnusualTrafficDetector().detect(events)

    assert len(alerts) == 1
    assert alerts[0].evidence["source_ip"] == "192.0.2.44"


def test_different_services_remain_isolated() -> None:
    events = [
        event
        for index, count in enumerate([1, 6, 6, 6, 6])
        for event in traffic_events(
            index, count, source_ip=f"192.0.2.{index + 10}", log_type="web", event_type="http_request"
        )
    ]
    events += traffic_events(5, 50, source_ip="192.0.2.99", log_type="web", event_type="http_request")
    events += [
        NormalizedEvent(
            timestamp=BASE_TIME + timedelta(minutes=index * 5, seconds=second),
            source="firewall.log",
            log_type="firewall",
            event_type="network_connection",
            src_ip=f"203.0.113.{second + 1}",
            dst_port=443,
            status="accepted",
        )
        for index, count in enumerate([1, 6, 6, 6, 6])
        for second in range(count)
    ]

    detector = UnusualTrafficDetector(grouping="service")
    alerts = detector.detect(events)

    assert len(alerts) == 1
    assert alerts[0].evidence["service"] == "web"


def test_baseline_statistic_and_sample_count_are_correct() -> None:
    events = [
        event
        for index, count in enumerate([1, 6, 6, 6, 6])
        for event in traffic_events(index, count)
    ]
    events += traffic_events(5, 50)

    alert = UnusualTrafficDetector().detect(events)[0]

    assert alert.evidence["baseline_statistic"] == pytest.approx(5.0)
    assert alert.evidence["baseline_sample_count"] == 5


def test_missing_timestamps_are_handled_safely() -> None:
    events = [
        event
        for index, count in enumerate([1, 6, 6, 6, 6])
        for event in traffic_events(index, count)
    ]
    events += traffic_events(5, 50)
    events.append(replace(events[0], timestamp=None))

    alerts = UnusualTrafficDetector().detect(events)

    assert len(alerts) == 1
    assert alerts[0].evidence["observed_count"] == 50


def test_missing_grouping_fields_are_handled_safely() -> None:
    events = [
        event
        for index, count in enumerate([1, 6, 6, 6, 6])
        for event in traffic_events(index, count)
    ]
    events += traffic_events(5, 50)
    events.append(replace(events[0], src_ip=None))

    alerts = UnusualTrafficDetector().detect(events)

    assert len(alerts) == 1
    assert alerts[0].evidence["observed_count"] == 50


def test_evidence_contains_required_statistical_fields() -> None:
    events = [
        event
        for index, count in enumerate([1, 6, 6, 6, 6])
        for event in traffic_events(index, count)
    ]
    events += traffic_events(5, 50)

    alert = UnusualTrafficDetector().detect(events)[0]

    assert alert.evidence["source_ip"] == "192.0.2.44"
    assert alert.evidence["observed_count"] == 50
    assert alert.evidence["baseline_statistic"] == pytest.approx(5.0)
    assert alert.evidence["baseline_sample_count"] == 5
    assert alert.evidence["score"] > alert.evidence["threshold"]
    assert alert.evidence["threshold"] == 3.0
    assert alert.evidence["statistical_method"] == "zscore"
    assert alert.evidence["time_bucket_start"] == BASE_TIME + timedelta(minutes=25)
    assert "bytes_sent_total" in alert.evidence
    assert "distinct_paths" in alert.evidence
    assert "status_code_distribution" in alert.evidence


def test_synthetic_web_traffic_spike_is_detected(tmp_path: Path) -> None:
    generated = generate_logs(tmp_path, seed=11)
    parser = WebServerLogParser()
    baseline_events = parser.parse_file(generated["web_baseline"])
    spike_events = parser.parse_file(generated["web_spike"])
    shifted_spike_events = [
        replace(event, timestamp=event.timestamp + timedelta(hours=2)) for event in spike_events
    ]

    detector = UnusualTrafficDetector(grouping="service")
    alerts = detector.detect(list(baseline_events) + shifted_spike_events)

    assert len(alerts) == 1
    assert alerts[0].evidence["service"] == "web"
    assert alerts[0].evidence["observed_count"] == 30
    assert alerts[0].title == "Unusual traffic pattern detected"


def test_repeated_normal_traffic_does_not_continuously_alert() -> None:
    events = [event for index in range(30) for event in traffic_events(index, 4)]

    assert UnusualTrafficDetector().detect(events) == []

