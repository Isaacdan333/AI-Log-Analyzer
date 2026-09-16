from datetime import timezone

from loganalyzer.parsers.firewall import FirewallLogParser
from loganalyzer.parsers.ssh import SSHLogParser
from loganalyzer.parsers.webserver import WebServerLogParser
from loganalyzer.parsers.windows_evt import WindowsEventLogParser


PARSER = SSHLogParser(default_year=2026)
FIREWALL_PARSER = FirewallLogParser(default_year=2026)
WEB_PARSER = WebServerLogParser()
WINDOWS_PARSER = WindowsEventLogParser()

WINDOWS_HEADER = (
    "EventID,TimeCreated,Computer,IpAddress,TargetUserName,TargetDomainName,"
    "SubjectUserName,SubjectDomainName,LogonType,ProcessName,NewProcessName,"
    "NewProcessId,MemberName,PrivilegeList,Group Name,Unused Column\n"
)


def test_parses_failed_ssh_login() -> None:
    line = "Mar 10 02:14:03 host sshd[123]: Failed password for admin from 192.0.2.10 port 22 ssh2"

    events = PARSER.parse_lines([line], source="auth.log")

    assert len(events) == 1
    event = events[0]
    assert event.timestamp.year == 2026
    assert event.timestamp.tzinfo == timezone.utc
    assert event.src_ip == "192.0.2.10"
    assert event.user == "admin"
    assert event.event_type == "login_failure"
    assert event.status == "failure"
    assert event.metadata["authentication_method"] == "password"


def test_parses_successful_ssh_login() -> None:
    line = "Mar 10 02:20:03 host sshd[124]: Accepted publickey for analyst from 192.0.2.20 port 22 ssh2"

    events = PARSER.parse_lines([line])

    assert len(events) == 1
    event = events[0]
    assert event.src_ip == "192.0.2.20"
    assert event.user == "analyst"
    assert event.event_type == "login_success"
    assert event.status == "success"
    assert event.metadata["authentication_method"] == "publickey"


def test_skips_invalid_or_malformed_input() -> None:
    lines = [
        "this is not an SSH log entry",
        "Mar 10 02:20:03 host unrelated service message",
        "Mar 10 02:20:03 host sshd[125]: Failed password with no source address",
    ]

    assert PARSER.parse_lines(lines) == []


def test_parses_accepted_firewall_connection() -> None:
    line = (
        "Mar 10 03:01:15 fw01 kernel: ACCEPT IN=eth0 OUT= MAC=00:1a:2b:3c:4d:5e "
        "SRC=203.0.113.7 DST=198.51.100.20 LEN=60 PROTO=TCP SPT=51820 DPT=443 SYN"
    )

    events = FIREWALL_PARSER.parse_lines([line], source="firewall.log")

    assert len(events) == 1
    event = events[0]
    assert event.timestamp.year == 2026
    assert event.timestamp.tzinfo == timezone.utc
    assert event.log_type == "firewall"
    assert event.event_type == "network_connection"
    assert event.status == "accepted"


def test_parses_dropped_firewall_connection() -> None:
    line = (
        "Mar 10 03:02:41 fw01 kernel: DROP IN=eth0 OUT= SRC=198.51.100.55 "
        "DST=10.0.0.5 LEN=52 PROTO=TCP SPT=443 DPT=22 SYN"
    )

    events = FIREWALL_PARSER.parse_lines([line])

    assert len(events) == 1
    assert events[0].status == "dropped"


def test_parses_rejected_firewall_connection() -> None:
    line = (
        "Mar 10 03:06:20 fw01 iptables: REJECT IN=eth1 OUT= SRC=203.0.113.99 "
        "DST=10.0.0.9 PROTO=TCP SPT=4444 DPT=3389 LEN=48"
    )

    events = FIREWALL_PARSER.parse_lines([line])

    assert len(events) == 1
    assert events[0].status == "denied"


def test_extracts_source_ip_from_firewall_line() -> None:
    line = "Mar 10 03:01:15 fw01 kernel: ACCEPT IN=eth0 SRC=203.0.113.7 DST=198.51.100.20 PROTO=TCP DPT=443"

    events = FIREWALL_PARSER.parse_lines([line])

    assert events[0].src_ip == "203.0.113.7"


def test_extracts_destination_ip_from_firewall_line() -> None:
    line = "Mar 10 03:01:15 fw01 kernel: ACCEPT IN=eth0 SRC=203.0.113.7 DST=198.51.100.20 PROTO=TCP DPT=443"

    events = FIREWALL_PARSER.parse_lines([line])

    assert events[0].dst_ip == "198.51.100.20"


def test_extracts_destination_port_from_firewall_line() -> None:
    line = "Mar 10 03:01:15 fw01 kernel: ACCEPT IN=eth0 SRC=203.0.113.7 DST=198.51.100.20 PROTO=TCP DPT=443"

    events = FIREWALL_PARSER.parse_lines([line])

    assert events[0].dst_port == 443


def test_extracts_protocol_from_firewall_line() -> None:
    line = "Mar 10 03:01:15 fw01 kernel: ACCEPT IN=eth0 SRC=203.0.113.7 DST=198.51.100.20 PROTO=UDP DPT=53"

    events = FIREWALL_PARSER.parse_lines([line])

    assert events[0].protocol == "UDP"


def test_extracts_byte_and_packet_counts_when_present() -> None:
    line = (
        "Mar 10 03:05:09 fw01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=192.0.2.44 "
        "DST=10.0.0.5 PROTO=UDP SPT=33122 DPT=53 LEN=76 PKTS=1"
    )

    events = FIREWALL_PARSER.parse_lines([line])

    assert len(events) == 1
    event = events[0]
    assert event.bytes_sent == 76
    assert event.metadata["packet_count"] == 1


def test_skips_malformed_or_unrelated_firewall_lines() -> None:
    lines = [
        "this is not a firewall log line at all",
        "Mar 10 03:09:30 fw01 unrelated service message with no fields",
    ]

    assert FIREWALL_PARSER.parse_lines(lines) == []


def test_parses_firewall_line_with_missing_optional_fields() -> None:
    line = "Mar 10 03:08:00 fw01 kernel: ACCEPT IN=eth0 OUT=eth1 SRC=10.0.0.5 DST=203.0.113.7 PROTO=TCP DPT=443"

    events = FIREWALL_PARSER.parse_lines([line])

    assert len(events) == 1
    event = events[0]
    assert event.dst_port == 443
    assert event.bytes_sent is None
    assert "packet_count" not in event.metadata
    assert event.metadata["in_interface"] == "eth0"
    assert event.metadata["out_interface"] == "eth1"


def test_parses_valid_combined_web_log_entry() -> None:
    line = (
        '203.0.113.10 - - [10/Mar/2026:02:14:03 +0000] "GET /index.html HTTP/1.1" '
        '200 512 "https://example.com/" "Mozilla/5.0 SyntheticAgent/1.0"'
    )

    events = WEB_PARSER.parse_lines([line], source="access.log")

    assert len(events) == 1
    event = events[0]
    assert event.log_type == "web"
    assert event.event_type == "http_request"


def test_extracts_client_ip_from_web_log() -> None:
    line = (
        '203.0.113.10 - - [10/Mar/2026:02:14:03 +0000] "GET /index.html HTTP/1.1" '
        '200 512 "https://example.com/" "Mozilla/5.0 SyntheticAgent/1.0"'
    )

    events = WEB_PARSER.parse_lines([line])

    assert events[0].src_ip == "203.0.113.10"


def test_extracts_timestamp_from_web_log() -> None:
    line = (
        '203.0.113.10 - - [10/Mar/2026:02:14:03 +0000] "GET /index.html HTTP/1.1" '
        '200 512 "https://example.com/" "Mozilla/5.0 SyntheticAgent/1.0"'
    )

    events = WEB_PARSER.parse_lines([line])

    event = events[0]
    assert event.timestamp.year == 2026
    assert event.timestamp.month == 3
    assert event.timestamp.day == 10
    assert event.timestamp.hour == 2
    assert event.timestamp.minute == 14
    assert event.timestamp.second == 3
    assert event.timestamp.tzinfo == timezone.utc


def test_extracts_http_method_from_web_log() -> None:
    line = (
        '203.0.113.10 - - [10/Mar/2026:02:14:03 +0000] "GET /index.html HTTP/1.1" '
        '200 512 "https://example.com/" "Mozilla/5.0 SyntheticAgent/1.0"'
    )

    events = WEB_PARSER.parse_lines([line])

    assert events[0].metadata["method"] == "GET"


def test_extracts_requested_path_from_web_log() -> None:
    line = (
        '203.0.113.10 - - [10/Mar/2026:02:14:03 +0000] "GET /index.html HTTP/1.1" '
        '200 512 "https://example.com/" "Mozilla/5.0 SyntheticAgent/1.0"'
    )

    events = WEB_PARSER.parse_lines([line])

    assert events[0].path == "/index.html"


def test_extracts_http_status_code_from_web_log() -> None:
    line = (
        '198.51.100.23 - alice [10/Mar/2026:02:15:41 +0000] "POST /login HTTP/1.1" '
        '401 128 "https://example.com/login" "Mozilla/5.0"'
    )

    events = WEB_PARSER.parse_lines([line])

    assert events[0].status == "401"


def test_extracts_response_bytes_from_web_log() -> None:
    line = (
        '203.0.113.10 - - [10/Mar/2026:02:16:45 +0000] "GET /assets/app.js HTTP/1.1" '
        '200 2048 "-" "curl/8.0.1"'
    )

    events = WEB_PARSER.parse_lines([line])

    assert events[0].bytes_sent == 2048


def test_extracts_referrer_from_web_log() -> None:
    line = (
        '198.51.100.23 - alice [10/Mar/2026:02:15:41 +0000] "POST /login HTTP/1.1" '
        '401 128 "https://example.com/login" "Mozilla/5.0"'
    )

    events = WEB_PARSER.parse_lines([line])

    assert events[0].metadata["referrer"] == "https://example.com/login"


def test_extracts_user_agent_from_web_log() -> None:
    line = (
        '198.51.100.23 - alice [10/Mar/2026:02:15:41 +0000] "POST /login HTTP/1.1" '
        '401 128 "https://example.com/login" "Mozilla/5.0 SyntheticAgent/1.0"'
    )

    events = WEB_PARSER.parse_lines([line])

    assert events[0].metadata["user_agent"] == "Mozilla/5.0 SyntheticAgent/1.0"


def test_parses_web_log_with_missing_optional_values() -> None:
    line = '192.0.2.55 - - [10/Mar/2026:02:16:02 +0000] "GET /missing-page HTTP/1.1" 404 0 "-" "-"'

    events = WEB_PARSER.parse_lines([line])

    assert len(events) == 1
    event = events[0]
    assert event.status == "404"
    assert event.bytes_sent == 0
    assert "referrer" not in event.metadata
    assert "user_agent" not in event.metadata
    assert event.user is None


def test_skips_malformed_web_log_line() -> None:
    lines = [
        "this line is not a valid access log entry at all",
        "also not valid [missing brackets closed improperly",
    ]

    assert WEB_PARSER.parse_lines(lines) == []


def test_parses_windows_successful_logon() -> None:
    lines = WINDOWS_HEADER + '4624,2026-03-10T02:14:03+00:00,isaac,192.0.2.10,analyst,EXAMPLE,-,-,10,C:\\Windows\\System32\\services.exe,-,-,-,-,-,ignored\n'

    events = WINDOWS_PARSER.parse_lines(lines.splitlines(), source="security.csv")

    assert len(events) == 1
    event = events[0]
    assert event.event_type == "login_success"
    assert event.status == "success"
    assert event.user == "analyst"
    assert event.src_ip == "192.0.2.10"
    assert event.timestamp.tzinfo == timezone.utc
    assert event.metadata["event_id"] == "4624"
    assert event.metadata["computer"] == "isaac"
    assert event.metadata["logon_type"] == "10"
    assert event.metadata["process_name"] == r"C:\Windows\System32\services.exe"


def test_parses_windows_failed_logon_with_quoted_username() -> None:
    lines = WINDOWS_HEADER + '4625,"2026-03-10T02:15:03-05:00",isaac,198.51.100.8,"svc,backup",EXAMPLE,-,-,3,C:\\Windows\\System32\\svchost.exe,-,-,-,-,-,ignored\n'

    event = WINDOWS_PARSER.parse_lines(lines.splitlines())[0]

    assert event.event_type == "login_failure"
    assert event.status == "failure"
    assert event.user == "svc,backup"
    assert event.timestamp.hour == 7
    assert event.timestamp.tzinfo == timezone.utc


def test_parses_windows_privilege_assignment() -> None:
    lines = WINDOWS_HEADER + '4672,2026-09-15T18:27:07.3907018Z,isaac,-,-,-,SYSTEM,NT AUTHORITY,-,-,-,-,-,"SeDebugPrivilege, SeTcbPrivilege",-,ignored\n'

    event = WINDOWS_PARSER.parse_lines(lines.splitlines())[0]

    assert event.event_type == "privilege_assignment"
    assert event.user == "SYSTEM"
    assert event.metadata["privileges"] == "SeDebugPrivilege, SeTcbPrivilege"
    assert event.metadata["subject_domain"] == "NT AUTHORITY"


def test_parses_windows_account_and_group_events() -> None:
    lines = WINDOWS_HEADER + (
        '4720,2026-03-10T02:17:03Z,synthetic,-,new.user,EXAMPLE,admin,EXAMPLE,-,-,-,-,-,-,ignored\n'
        '4728,2026-03-10T02:18:03Z,synthetic,-,Domain Admins,EXAMPLE,admin,EXAMPLE,-,-,-,-,new.user,-,-,ignored\n'
        '4732,2026-03-10T02:19:03Z,synthetic,-,Administrators,EXAMPLE,admin,EXAMPLE,-,-,-,-,new.user,-,-,ignored\n'
    )

    events = WINDOWS_PARSER.parse_lines(lines.splitlines())

    assert [event.event_type for event in events] == [
        "user_created",
        "privileged_group_membership",
        "privileged_group_membership",
    ]
    assert events[0].user == "new.user"
    assert events[1].metadata["member_name"] == "new.user"
    assert events[2].metadata["member_name"] == "new.user"


def test_parses_windows_process_creation() -> None:
    lines = WINDOWS_HEADER + '4688,2026-09-15T16:40:02.7904932Z,isaac,-,-,-,admin,EXAMPLE,-,-,"C:\\Windows\\System32\\SbUpdateWorker.exe",0x7a4,-,-,-,ignored\n'

    event = WINDOWS_PARSER.parse_lines(lines.splitlines())[0]

    assert event.event_type == "process_creation"
    assert event.user == "admin"
    assert event.metadata["new_process_name"] == r"C:\Windows\System32\SbUpdateWorker.exe"
    assert event.metadata["new_process_id"] == 1956


def test_skips_malformed_rows_and_preserves_unknown_event_ids() -> None:
    lines = WINDOWS_HEADER + (
        "not-a-row\n"
        "9999,not-a-timestamp,synthetic,-,-,-,-,-,-,-,-,-,-,-,-,ignored\n"
        "9998,2026-03-10T02:21:03Z,synthetic,-,-,-,-,-,-,-,-,-,-,-,-,ignored\n"
    )

    events = WINDOWS_PARSER.parse_lines(lines.splitlines())

    assert len(events) == 1
    assert events[0].event_type == "windows_event"
    assert events[0].metadata["event_id"] == "9998"


def test_preserves_naive_windows_timestamp_without_reinterpreting_it() -> None:
    lines = WINDOWS_HEADER + '4624,2026-03-10 02:22:03,synthetic,192.0.2.10,analyst,-,-,-,-,-,-,-,-,-,-,ignored\n'

    event = WINDOWS_PARSER.parse_lines(lines.splitlines())[0]

    assert event.timestamp.tzinfo is None
