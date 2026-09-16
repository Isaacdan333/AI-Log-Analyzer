from pathlib import Path

import pytest

from loganalyzer.parsers.firewall import FirewallLogParser
from loganalyzer.parsers.ssh import SSHLogParser
from loganalyzer.parsers.webserver import WebServerLogParser
from loganalyzer.parsers.windows_evt import WindowsEventLogParser
from loganalyzer.synthetic.generate_logs import SCENARIOS, generate_logs


def test_generates_all_requested_files(tmp_path: Path) -> None:
    generated = generate_logs(tmp_path, seed=7)

    assert tuple(generated) == SCENARIOS
    assert all(path.is_file() for path in generated.values())


def test_same_seed_produces_identical_output(tmp_path: Path) -> None:
    first = generate_logs(tmp_path / "first", seed=42)
    second = generate_logs(tmp_path / "second", seed=42)

    assert {name: path.read_text(encoding="utf-8") for name, path in first.items()} == {
        name: path.read_text(encoding="utf-8") for name, path in second.items()
    }


def test_selected_scenario_only_writes_its_file(tmp_path: Path) -> None:
    generated = generate_logs(tmp_path, scenario="ssh_bruteforce")

    assert tuple(generated) == ("ssh_bruteforce",)
    assert not (tmp_path / "web_spike.log").exists()


def test_rejects_unknown_scenario(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unknown scenario"):
        generate_logs(tmp_path, scenario="not-a-scenario")


def test_generated_scenarios_parse_and_contain_expected_activity(tmp_path: Path) -> None:
    generated = generate_logs(tmp_path, seed=9)
    ssh_parser = SSHLogParser(default_year=2026)

    normal_events = ssh_parser.parse_file(generated["ssh_normal"])
    assert {event.event_type for event in normal_events} == {"login_success", "login_failure"}

    burst_events = ssh_parser.parse_file(generated["ssh_bruteforce"])
    assert len(burst_events) == 5
    assert {event.src_ip for event in burst_events} == {"192.0.2.99"}
    assert {event.event_type for event in burst_events} == {"login_failure"}

    post_burst_events = ssh_parser.parse_file(generated["ssh_post_burst_success"])
    assert [event.event_type for event in post_burst_events].count("login_failure") == 5
    assert post_burst_events[-1].event_type == "login_success"

    firewall_events = FirewallLogParser(default_year=2026).parse_file(generated["firewall_port_scan"])
    assert len({event.dst_port for event in firewall_events}) == 10
    assert {event.src_ip for event in firewall_events} == {"203.0.113.99"}

    baseline_events = WebServerLogParser().parse_file(generated["web_baseline"])
    spike_events = WebServerLogParser().parse_file(generated["web_spike"])
    assert len(baseline_events) == 12
    assert len(spike_events) == 30

    windows_events = WindowsEventLogParser().parse_file(generated["windows_security"])
    assert {event.metadata["event_id"] for event in windows_events} >= {
        "4624", "4625", "4672", "4720", "4728", "4732", "4688"
    }
    traveler_events = [event for event in windows_events if event.user == "traveler"]
    assert [event.src_ip for event in traveler_events] == ["192.0.2.201", "198.51.100.201"]
    assert (traveler_events[1].timestamp - traveler_events[0].timestamp).total_seconds() == 900