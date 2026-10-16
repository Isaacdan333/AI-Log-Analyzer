import json
from pathlib import Path

from loganalyzer.config import AnalyzerConfig
from loganalyzer.engine import AnalysisResult, analyze_paths
from loganalyzer.limits import InputLimits
from loganalyzer.models import Alert
from loganalyzer.parsers.firewall import FirewallLogParser
from loganalyzer.parsers.ssh import SSHLogParser
from loganalyzer.parsers.webserver import WebServerLogParser
from loganalyzer.parsers.windows_evt import WindowsEventLogParser
from loganalyzer.report import format_json_report, format_text_report


WINDOWS_HEADER = (
    "EventID,TimeCreated,Computer,IpAddress,TargetUserName,TargetDomainName,"
    "SubjectUserName,SubjectDomainName,LogonType,ProcessName,NewProcessName,"
    "NewProcessId,MemberName,PrivilegeList,Group Name,Unused Column\n"
)


def test_secret_bearing_parser_values_are_redacted() -> None:
    ssh_event = SSHLogParser().parse_lines(
        [
            "Mar 10 02:00:00 host sshd: Accepted password for admin from "
            "192.0.2.10 password=ssh-secret token=ssh-token"
        ]
    )[0]
    web_event = WebServerLogParser().parse_lines(
        [
            '203.0.113.10 - - [10/Mar/2026:02:00:00 +0000] '
            '"GET /login?token=url-secret HTTP/1.1" 200 10 "-" '
            '"Authorization: Bearer header-secret"'
        ]
    )[0]
    windows_event = WindowsEventLogParser().parse_lines(
        [
            WINDOWS_HEADER,
            "4688,2026-03-10T02:00:00+00:00,host,-,-,-,admin,EXAMPLE,-,-,"
            "cmd.exe password=win-secret cookie=win-cookie,-,-,-,-\n",
        ]
    )[0]

    values = (
        ssh_event.raw_line,
        web_event.raw_line,
        web_event.path,
        web_event.metadata["user_agent"],
        windows_event.raw_line,
        windows_event.metadata["new_process_name"],
    )
    for value in values:
        assert value is not None
        assert "secret" not in value.lower()
        assert "win-cookie" not in value


def test_reports_redact_secret_strings_in_text_and_json() -> None:
    alert = Alert(
        "HIGH",
        "Secret test",
        "token=summary-secret",
        {
            "header": "Authorization: Bearer evidence-secret",
            "cookie": "cookie=secret-cookie",
            "api_key": "sk-live-never-send-this",
            "unlabeled": "api key=also-secret",
        },
        ("Review",),
    )
    result = AnalysisResult((), (alert,), (), (), ())

    text = format_text_report(result)
    payload = json.loads(format_json_report(result))
    output = text + json.dumps(payload)

    assert "summary-secret" not in output
    assert "evidence-secret" not in output
    assert "secret-cookie" not in output
    assert "sk-live-never-send-this" not in output
    assert "also-secret" not in output
    assert output.count("[REDACTED]") >= 3


def test_each_parser_records_malformed_lines_and_keeps_valid_records() -> None:
    ssh = SSHLogParser()
    assert len(
        ssh.parse_lines(
            [
                "bad ssh",
                "Mar 10 02:00:00 host sshd: Accepted publickey for a from 192.0.2.1",
            ]
        )
    ) == 1
    assert ssh.diagnostics[0].line_number == 1

    firewall = FirewallLogParser()
    assert len(
        firewall.parse_lines(
            [
                "bad firewall",
                "Mar 10 02:00:00 fw ACCEPT SRC=192.0.2.1 DST=198.51.100.1 PROTO=TCP DPT=443",
            ]
        )
    ) == 1
    assert firewall.diagnostics[0].line_number == 1

    web = WebServerLogParser()
    assert len(
        web.parse_lines(
            [
                "bad web",
                '203.0.113.1 - - [10/Mar/2026:02:00:00 +0000] "GET / HTTP/1.1" 200 1',
            ]
        )
    ) == 1
    assert web.diagnostics[0].line_number == 1

    windows = WindowsEventLogParser()
    assert len(
        windows.parse_lines(
            [
                WINDOWS_HEADER,
                "bad,csv,row",
                "4624,2026-03-10T02:00:00+00:00,host,192.0.2.1,user,EXAMPLE,-,-,10,-,-,-,-,-,-,-",
            ]
        )
    ) == 1
    assert windows.diagnostics[0].line_number == 2


def test_engine_reports_malformed_lines_and_continues(tmp_path: Path) -> None:
    path = tmp_path / "ssh_mixed.log"
    path.write_text(
        "bad ssh\n"
        "Mar 10 02:00:00 host sshd: Accepted publickey for a from 192.0.2.1\n",
        encoding="utf-8",
    )

    result = analyze_paths([path])

    assert result.event_count == 1
    assert result.files_processed == (path,)
    assert len(result.diagnostics) == 1
    assert result.diagnostics[0].path == path
    assert "line 1" in result.diagnostics[0].message


def test_engine_rejects_oversized_file_and_continues(tmp_path: Path) -> None:
    oversized = tmp_path / "ssh_oversized.log"
    valid = tmp_path / "ssh_valid.log"
    oversized.write_text("x" * 101, encoding="utf-8")
    valid.write_text(
        "Mar 10 02:00:00 host sshd: Accepted publickey for a from 192.0.2.1\n",
        encoding="utf-8",
    )

    result = analyze_paths(
        [oversized, valid],
        config=AnalyzerConfig(input_limits=InputLimits(max_file_size_bytes=100)),
    )

    assert result.event_count == 1
    assert result.files_skipped == (oversized,)
    assert result.files_processed == (valid,)
    assert "maximum size" in result.diagnostics[0].message


def test_engine_rejects_excessively_long_line(tmp_path: Path) -> None:
    path = tmp_path / "ssh_long.log"
    path.write_text("x" * 101 + "\n", encoding="utf-8")

    result = analyze_paths(
        [path], config=AnalyzerConfig(input_limits=InputLimits(max_line_length=100))
    )

    assert result.event_count == 0
    assert result.files_skipped == (path,)
    assert "maximum length" in result.diagnostics[0].message
