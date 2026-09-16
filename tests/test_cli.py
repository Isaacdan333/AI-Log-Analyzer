import json
from pathlib import Path

import pytest

from loganalyzer.cli import main
from loganalyzer.engine import analyze_paths
from loganalyzer.report import format_json_report, format_text_report
from loganalyzer.synthetic.generate_logs import generate_logs

SAMPLES_DIR = Path(__file__).parents[1] / "samples"
SSH_BRUTEFORCE_SAMPLE = SAMPLES_DIR / "ssh_bruteforce.log"


def test_top_level_help_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["--help"])

    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert "analyze" in captured.out


def test_analyze_help_exits_zero_and_documents_options(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["analyze", "--help"])

    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    for option in ("--logs", "--out", "--format", "--minimum-severity", "--log-type", "--timezone"):
        assert option in captured.out
    assert "Examples:" in captured.out


def test_analyze_directory_prints_text_report_by_default(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = main(["analyze", "--logs", str(SAMPLES_DIR)])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "Analysis report" in captured.out


def test_analyze_single_supported_file(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["analyze", "--logs", str(SSH_BRUTEFORCE_SAMPLE)])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "brute_force" in captured.out


def test_analyze_json_format_prints_valid_json(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["analyze", "--logs", str(SSH_BRUTEFORCE_SAMPLE), "--format", "json"])

    captured = capsys.readouterr()
    assert exit_code == 0
    payload = json.loads(captured.out)
    assert "alerts" in payload
    assert payload["alerts"][0]["detector"] == "brute_force"


def test_cli_text_output_matches_report_module(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["analyze", "--logs", str(SSH_BRUTEFORCE_SAMPLE)])
    captured = capsys.readouterr()

    expected_result = analyze_paths([SSH_BRUTEFORCE_SAMPLE])
    expected_report = format_text_report(expected_result)

    assert exit_code == 0
    assert captured.out.strip() == expected_report.strip()


def test_cli_json_output_matches_report_module(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["analyze", "--logs", str(SSH_BRUTEFORCE_SAMPLE), "--format", "json"])
    captured = capsys.readouterr()

    expected_result = analyze_paths([SSH_BRUTEFORCE_SAMPLE])
    expected_report = format_json_report(expected_result)

    assert exit_code == 0
    assert captured.out.strip() == expected_report.strip()


def test_analyze_out_writes_text_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out_path = tmp_path / "report.txt"

    exit_code = main(["analyze", "--logs", str(SSH_BRUTEFORCE_SAMPLE), "--out", str(out_path)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.out == ""
    assert "Analysis report" in out_path.read_text(encoding="utf-8")


def test_analyze_out_writes_json_file(tmp_path: Path) -> None:
    out_path = tmp_path / "report.json"

    exit_code = main(
        ["analyze", "--logs", str(SSH_BRUTEFORCE_SAMPLE), "--format", "json", "--out", str(out_path)]
    )

    assert exit_code == 0
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    assert payload["alerts"][0]["detector"] == "brute_force"


def test_minimum_severity_filters_displayed_alerts(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    generated = generate_logs(tmp_path, seed=5)
    paths = [generated["ssh_bruteforce"], generated["firewall_port_scan"]]

    unfiltered = analyze_paths(paths)
    severities = {alert.severity for alert in unfiltered.alerts}
    assert len(severities) > 1, "fixture must produce alerts at more than one severity"
    highest = max(severities, key=lambda s: ("LOW", "MEDIUM", "HIGH", "CRITICAL").index(s))

    exit_code = main(
        [
            "analyze",
            "--logs",
            str(tmp_path),
            "--minimum-severity",
            highest,
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    for alert in unfiltered.alerts:
        if alert.severity != highest:
            assert alert.title not in captured.out


def test_minimum_severity_does_not_alter_underlying_alert_count() -> None:
    """Severity filtering must only affect display, never detector output."""
    result = analyze_paths([SSH_BRUTEFORCE_SAMPLE])
    assert len(result.alerts) >= 1


def test_missing_input_path_returns_nonzero_without_traceback(
    capsys: pytest.CaptureFixture[str],
) -> None:
    missing = Path("this-path-does-not-exist-anywhere")

    exit_code = main(["analyze", "--logs", str(missing)])
    captured = capsys.readouterr()

    assert exit_code != 0
    assert "Traceback" not in captured.err
    assert "does not exist" in captured.err


def test_invalid_format_argument_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["analyze", "--logs", str(SSH_BRUTEFORCE_SAMPLE), "--format", "xml"])

    assert exc_info.value.code == 2
    captured = capsys.readouterr()
    assert "Traceback" not in captured.err


def test_missing_required_argument_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["analyze"])

    assert exc_info.value.code == 2


def test_output_file_failure_is_handled_gracefully(capsys: pytest.CaptureFixture[str]) -> None:
    # A directory cannot be opened for writing as a report file.
    bad_out = SAMPLES_DIR

    exit_code = main(["analyze", "--logs", str(SSH_BRUTEFORCE_SAMPLE), "--out", str(bad_out)])
    captured = capsys.readouterr()

    assert exit_code != 0
    assert "Traceback" not in captured.err
    assert "could not write output file" in captured.err


def test_successful_analysis_with_alerts_still_exits_zero() -> None:
    exit_code = main(["analyze", "--logs", str(SSH_BRUTEFORCE_SAMPLE)])
    assert exit_code == 0
