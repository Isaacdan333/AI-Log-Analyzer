"""Generate parser-compatible synthetic log files for rule-based testing."""

from __future__ import annotations

import argparse
import csv
import random
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path

_BASE_TIME = datetime(2026, 3, 10, 2, 0, tzinfo=timezone.utc)
_DEFAULT_OUTPUT_DIRECTORY = Path(__file__).parents[2] / "samples"
_WINDOWS_HEADER = (
    "EventID",
    "TimeCreated",
    "Computer",
    "IpAddress",
    "TargetUserName",
    "TargetDomainName",
    "SubjectUserName",
    "SubjectDomainName",
    "LogonType",
    "ProcessName",
    "NewProcessName",
    "NewProcessId",
    "MemberName",
    "PrivilegeList",
    "Group Name",
    "Unused Column",
)


def generate_logs(
    output_dir: Path | None = None,
    scenario: str = "all",
    seed: int = 2026,
) -> dict[str, Path]:
    """Generate one scenario or all scenarios and return their file paths."""
    if scenario != "all" and scenario not in SCENARIOS:
        options = ", ".join(("all", *SCENARIOS))
        raise ValueError(f"unknown scenario '{scenario}'; choose one of: {options}")

    destination = output_dir or _DEFAULT_OUTPUT_DIRECTORY
    destination.mkdir(parents=True, exist_ok=True)
    randomizer = random.Random(seed)
    selected = SCENARIOS if scenario == "all" else (scenario,)
    generated: dict[str, Path] = {}
    for name in selected:
        path = destination / _SCENARIO_FILENAMES[name]
        _SCENARIO_WRITERS[name](path, randomizer)
        generated[name] = path
    return generated


def _syslog_timestamp(timestamp: datetime) -> str:
    return timestamp.strftime("%b %d %H:%M:%S")


def _write_lines(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_ssh_normal(path: Path, randomizer: random.Random) -> None:
    source_ip = randomizer.choice(("192.0.2.21", "198.51.100.21"))
    lines = [
        f"{_syslog_timestamp(_BASE_TIME)} synthetic-ssh sshd[1001]: Accepted publickey for analyst from {source_ip} port 22 ssh2",
        f"{_syslog_timestamp(_BASE_TIME + timedelta(minutes=8))} synthetic-ssh sshd[1002]: Failed password for demo.user from 203.0.113.21 port 22 ssh2",
        f"{_syslog_timestamp(_BASE_TIME + timedelta(minutes=12))} synthetic-ssh sshd[1003]: Accepted password for demo.user from 203.0.113.21 port 22 ssh2",
    ]
    _write_lines(path, lines)


def _write_ssh_bruteforce(path: Path, randomizer: random.Random) -> None:
    process_id = randomizer.randint(2000, 2999)
    lines = [
        f"{_syslog_timestamp(_BASE_TIME + timedelta(minutes=index))} synthetic-ssh sshd[{process_id + index}]: Failed password for target.user from 192.0.2.99 port 22 ssh2"
        for index in range(5)
    ]
    _write_lines(path, lines)


def _write_ssh_post_burst_success(path: Path, randomizer: random.Random) -> None:
    process_id = randomizer.randint(3000, 3999)
    lines = [
        f"{_syslog_timestamp(_BASE_TIME + timedelta(minutes=index))} synthetic-ssh sshd[{process_id + index}]: Failed password for target.user from 198.51.100.99 port 22 ssh2"
        for index in range(5)
    ]
    lines.append(
        f"{_syslog_timestamp(_BASE_TIME + timedelta(minutes=5))} synthetic-ssh sshd[{process_id + 5}]: Accepted publickey for target.user from 198.51.100.99 port 22 ssh2"
    )
    _write_lines(path, lines)


def _write_firewall_port_scan(path: Path, randomizer: random.Random) -> None:
    ports = randomizer.sample(range(1024, 9000), 10)
    lines = [
        f"{_syslog_timestamp(_BASE_TIME + timedelta(seconds=index * 5))} synthetic-fw kernel: DROP IN=eth0 OUT= SRC=203.0.113.99 DST=198.51.100.10 LEN=60 PROTO=TCP SPT=40000 DPT={port} SYN"
        for index, port in enumerate(ports)
    ]
    _write_lines(path, lines)


def _web_line(timestamp: datetime, source_ip: str, path: str, byte_count: int) -> str:
    return (
        f'{source_ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S %z")}] '
        f'"GET {path} HTTP/1.1" 200 {byte_count} "-" "SyntheticBrowser/1.0"'
    )


def _write_web_baseline(path: Path, randomizer: random.Random) -> None:
    lines = [
        _web_line(
            _BASE_TIME + timedelta(minutes=index * 5),
            "192.0.2.44",
            randomizer.choice(("/", "/docs", "/status")),
            randomizer.randint(300, 1200),
        )
        for index in range(12)
    ]
    _write_lines(path, lines)


def _write_web_spike(path: Path, randomizer: random.Random) -> None:
    lines = [
        _web_line(
            _BASE_TIME + timedelta(seconds=index * 3),
            "198.51.100.44",
            "/api/search",
            randomizer.randint(800, 1600),
        )
        for index in range(30)
    ]
    _write_lines(path, lines)


def _write_windows_security(path: Path, randomizer: random.Random) -> None:
    computer = f"synthetic-win-{randomizer.randint(1, 9):02d}"
    rows = [
        ("4624", _BASE_TIME, "192.0.2.50", "analyst", "EXAMPLE", "-", "-", "10", "C:\\Windows\\System32\\services.exe", "-", "-", "-", "-", "-", "synthetic successful logon"),
        ("4625", _BASE_TIME + timedelta(minutes=1), "198.51.100.50", "demo.admin", "EXAMPLE", "-", "-", "3", "C:\\Windows\\System32\\svchost.exe", "-", "-", "-", "-", "-", "synthetic failed logon"),
        ("4672", _BASE_TIME + timedelta(minutes=2), "-", "-", "-", "SYSTEM", "NT AUTHORITY", "-", "-", "-", "-", "-", "SeDebugPrivilege", "-", "synthetic privilege assignment"),
        ("4720", _BASE_TIME + timedelta(minutes=3), "-", "new.user", "EXAMPLE", "demo.admin", "EXAMPLE", "-", "-", "-", "-", "-", "-", "-", "synthetic account creation"),
        ("4728", _BASE_TIME + timedelta(minutes=4), "-", "Domain Admins", "EXAMPLE", "demo.admin", "EXAMPLE", "-", "-", "-", "-", "new.user", "-", "-", "synthetic global group membership"),
        ("4732", _BASE_TIME + timedelta(minutes=5), "-", "Administrators", "EXAMPLE", "demo.admin", "EXAMPLE", "-", "-", "-", "-", "new.user", "-", "-", "synthetic local group membership"),
        ("4688", _BASE_TIME + timedelta(minutes=6), "-", "-", "-", "demo.admin", "EXAMPLE", "-", "-", "C:\\Windows\\System32\\whoami.exe", "0x7a4", "-", "-", "-", "synthetic process creation"),
        ("4624", _BASE_TIME + timedelta(minutes=10), "192.0.2.201", "traveler", "EXAMPLE", "-", "-", "10", "C:\\Windows\\System32\\services.exe", "-", "-", "-", "-", "-", "synthetic distant location login A"),
        ("4624", _BASE_TIME + timedelta(minutes=25), "198.51.100.201", "traveler", "EXAMPLE", "-", "-", "10", "C:\\Windows\\System32\\services.exe", "-", "-", "-", "-", "-", "synthetic distant location login B"),
    ]
    with path.open("w", encoding="utf-8", newline="") as output_file:
        writer = csv.writer(output_file)
        writer.writerow(_WINDOWS_HEADER)
        for event_id, timestamp, *fields in rows:
            writer.writerow((event_id, timestamp.isoformat(), computer, *fields))


_SCENARIO_FILENAMES = {
    "ssh_normal": "ssh_normal.log",
    "ssh_bruteforce": "ssh_bruteforce.log",
    "ssh_post_burst_success": "ssh_post_burst_success.log",
    "firewall_port_scan": "firewall_port_scan.log",
    "web_baseline": "web_baseline.log",
    "web_spike": "web_spike.log",
    "windows_security": "windows_security.csv",
}
_SCENARIO_WRITERS: dict[str, Callable[[Path, random.Random], None]] = {
    "ssh_normal": _write_ssh_normal,
    "ssh_bruteforce": _write_ssh_bruteforce,
    "ssh_post_burst_success": _write_ssh_post_burst_success,
    "firewall_port_scan": _write_firewall_port_scan,
    "web_baseline": _write_web_baseline,
    "web_spike": _write_web_spike,
    "windows_security": _write_windows_security,
}
SCENARIOS = tuple(_SCENARIO_FILENAMES)


def main() -> int:
    """Generate synthetic files from the command line."""
    parser = argparse.ArgumentParser(description="Generate synthetic analyzer log files.")
    parser.add_argument("--output-dir", type=Path, default=_DEFAULT_OUTPUT_DIRECTORY)
    parser.add_argument("--scenario", choices=("all", *SCENARIOS), default="all")
    parser.add_argument("--seed", type=int, default=2026)
    arguments = parser.parse_args()
    for path in generate_logs(arguments.output_dir, arguments.scenario, arguments.seed).values():
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())