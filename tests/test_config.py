from pathlib import Path

import pytest

from loganalyzer.config import AnalyzerConfig, ConfigurationError, load_config
from loganalyzer.detectors.bruteforce import BruteForceDetector
from loganalyzer.detectors.impossible_travel import ImpossibleTravelDetector
from loganalyzer.detectors.port_scan import PortScanDetector
from loganalyzer.detectors.privilege_escalation import PrivilegeEscalationDetector
from loganalyzer.detectors.suspicious_login import SuspiciousLoginDetector
from loganalyzer.detectors.unusual_traffic import UnusualTrafficDetector
from loganalyzer.engine import _default_detectors


ROOT = Path(__file__).parents[1]


def test_default_configuration_preserves_constructor_defaults() -> None:
    config = load_config()

    assert config == AnalyzerConfig()
    detectors = _default_detectors(None, config)
    assert isinstance(detectors[0], BruteForceDetector)
    assert detectors[0].threshold == 5
    assert detectors[0].window.total_seconds() == 300
    assert detectors[1].medium_ports == 10
    assert detectors[2].failure_burst_threshold == 3
    assert detectors[3].correlation_window_minutes == 30
    assert detectors[4].max_speed_kmh == 900.0
    assert detectors[5].zscore_threshold == 3.0


def test_loads_checked_in_example_configuration() -> None:
    config = load_config(ROOT / "config.example.toml")

    assert set(config.detector_options) == {
        "brute_force",
        "port_scan",
        "suspicious_login",
        "privilege_escalation",
        "impossible_travel",
        "unusual_traffic",
    }
    assert config.detector_options["brute_force"]["threshold"] == 5
    assert config.report_options == {"minimum_severity": "LOW", "timezone": "UTC"}


def test_custom_values_reach_all_detector_constructors(tmp_path: Path) -> None:
    path = tmp_path / "custom.toml"
    path.write_text(
        """
[brute_force]
threshold = 7
window_minutes = 9
[port_scan]
window_seconds = 90
medium_ports = 12
high_ports = 20
critical_ports = 40
critical_hosts = 3
critical_denied_ratio = 0.75
[suspicious_login]
post_burst_window_minutes = 11
failure_burst_threshold = 4
multi_account_threshold = 4
multi_account_window_minutes = 20
enable_off_hours = true
normal_hours_start = 7
normal_hours_end = 19
[privilege_escalation]
correlation_window_minutes = 45
process_correlation_window_minutes = 12
[impossible_travel]
max_speed_kmh = 700.0
min_elapsed_minutes = 2.0
min_distance_km = 150.0
ignore_private_ips = true
[unusual_traffic]
bucket_seconds = 120
min_baseline_buckets = 6
statistical_method = "iqr"
zscore_threshold = 2.5
iqr_multiplier = 2.0
grouping = "service"
min_observed_volume = 2
high_multiplier = 1.75
critical_multiplier = 3.0
""",
        encoding="utf-8",
    )

    detectors = _default_detectors(None, load_config(path))

    brute_force, port_scan, suspicious_login, privilege, travel, traffic = detectors
    assert (brute_force.threshold, brute_force.window.total_seconds()) == (7, 540)
    assert (port_scan.window_seconds, port_scan.medium_ports, port_scan.critical_hosts) == (90, 12, 3)
    assert (suspicious_login.failure_burst_threshold, suspicious_login.enable_off_hours) == (4, True)
    assert (privilege.correlation_window_minutes, privilege.process_correlation_window_minutes) == (45, 12)
    assert (travel.max_speed_kmh, travel.min_distance_km, travel.ignore_private_ips) == (700.0, 150.0, True)
    assert (traffic.bucket_seconds, traffic.statistical_method, traffic.zscore_threshold) == (120, "iqr", 2.5)


def test_missing_configuration_is_rejected_only_when_requested(tmp_path: Path) -> None:
    assert load_config() == AnalyzerConfig()

    with pytest.raises(ConfigurationError, match="does not exist"):
        load_config(tmp_path / "missing.toml")


def test_malformed_configuration_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "malformed.toml"
    path.write_text("[brute_force\nthreshold = 5", encoding="utf-8")

    with pytest.raises(ConfigurationError, match="could not load configuration"):
        load_config(path)


def test_invalid_report_configuration_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "invalid.toml"
    path.write_text("[report]\nminimum_severity = \"URGENT\"\n", encoding="utf-8")

    with pytest.raises(ConfigurationError, match="minimum_severity"):
        load_config(path)