"""Tests for the optional ML workflow, CLI flags and ML report sections.

All data is clearly synthetic and deterministic. These tests demonstrate the
wiring and separation guarantees; they do not claim general detection accuracy.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import loganalyzer.ml.workflow as workflow
from loganalyzer.cli import main
from loganalyzer.engine import analyze_paths
from loganalyzer.ml.workflow import MLAnalysisError, run_ml_analysis
from loganalyzer.report import format_json_report, format_text_report

SAMPLES_DIR = Path(__file__).parents[1] / "samples"
BASE_TIME = datetime(2026, 3, 1, 10, 0, 0, tzinfo=timezone.utc)
ANOMALOUS_IP = "192.0.2.99"


def _web_line(timestamp: datetime, source_ip: str, status: int, byte_count: int) -> str:
    return (
        f'{source_ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S %z")}] '
        f'"GET /index.html HTTP/1.1" {status} {byte_count} "-" "SyntheticBrowser/1.0"'
    )


def _baseline_lines(clients: int = 12, minutes: int = 8) -> list[str]:
    """Synthetic normal traffic: 1-3 modest 200 responses per client per minute."""
    lines = []
    for client in range(clients):
        ip = f"198.51.100.{client + 1}"
        for minute in range(minutes):
            for request in range(1 + (client + minute) % 3):
                moment = BASE_TIME + timedelta(minutes=minute, seconds=request * 15 + client)
                lines.append(_web_line(moment, ip, 200, 800 + 40 * ((client + minute) % 5)))
    return lines


def _write(path: Path, lines: list[str]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _anomaly_lines() -> list[str]:
    return [
        _web_line(BASE_TIME + timedelta(seconds=index // 2), ANOMALOUS_IP, 500, 5_000_000)
        for index in range(240)
    ]


@pytest.fixture
def training_dir(tmp_path: Path) -> Path:
    _write(tmp_path / "training" / "baseline.log", _baseline_lines())
    return tmp_path / "training"


@pytest.fixture
def normal_dir(tmp_path: Path) -> Path:
    _write(tmp_path / "normal" / "web.log", _baseline_lines(clients=6, minutes=4))
    return tmp_path / "normal"


@pytest.fixture
def anomaly_dir(tmp_path: Path) -> Path:
    _write(tmp_path / "anomaly" / "web.log", _baseline_lines(clients=6, minutes=4) + _anomaly_lines())
    return tmp_path / "anomaly"


def _json(capsys: pytest.CaptureFixture[str]) -> dict:
    return json.loads(capsys.readouterr().out)


def test_ml_disabled_by_default_json_has_no_ml_fields(
    capsys: pytest.CaptureFixture[str], anomaly_dir: Path
) -> None:
    assert main(["analyze", "--logs", str(anomaly_dir), "--format", "json"]) == 0
    payload = _json(capsys)
    assert "ml_findings" not in payload and "ml_analysis" not in payload


def test_ml_disabled_text_output_unchanged(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["analyze", "--logs", str(SAMPLES_DIR)]) == 0
    out = capsys.readouterr().out
    assert "ML Anomaly Findings" not in out
    assert out.rstrip("\n") == format_text_report(analyze_paths(sorted(SAMPLES_DIR.glob("*.*"))))


def test_enable_ml_without_training_logs_is_usage_error(
    capsys: pytest.CaptureFixture[str], normal_dir: Path
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["analyze", "--logs", str(normal_dir), "--enable-ml"])
    assert exc_info.value.code == 2
    assert "--ml-training-logs" in capsys.readouterr().err


def test_training_logs_without_enable_ml_is_usage_error(
    normal_dir: Path, training_dir: Path
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["analyze", "--logs", str(normal_dir), "--ml-training-logs", str(training_dir)])
    assert exc_info.value.code == 2


def test_end_to_end_flags_anomaly_with_separate_training(
    capsys: pytest.CaptureFixture[str], anomaly_dir: Path, training_dir: Path
) -> None:
    exit_code = main(
        ["analyze", "--logs", str(anomaly_dir), "--enable-ml",
         "--ml-training-logs", str(training_dir), "--format", "json"]
    )
    payload = _json(capsys)
    assert exit_code == 0
    sources = {finding["source_ip"] for finding in payload["ml_findings"]}
    assert ANOMALOUS_IP in sources
    finding = next(f for f in payload["ml_findings"] if f["source_ip"] == ANOMALOUS_IP)
    assert finding["classification"] == "anomaly"
    assert finding["model_name"] == "IsolationForest"
    assert finding["time_bucket"].startswith("2026-03-01T10:0")
    assert finding["feature_values"]["bytes_sent_total"] > 1_000_000
    assert finding["training_context"][0]["training_maximum"] is not None
    assert finding["model_settings"]["random_state"] == 42
    assert "not a confirmed attack" in finding["explanation"]
    assert payload["ml_analysis"]["training_observation_count"] > 0
    assert payload["ml_analysis"]["scored_observation_count"] > 0


def test_normal_scoring_data_yields_no_anomalies(
    capsys: pytest.CaptureFixture[str], normal_dir: Path, training_dir: Path
) -> None:
    main(["analyze", "--logs", str(normal_dir), "--enable-ml",
          "--ml-training-logs", str(training_dir), "--format", "json"])
    payload = _json(capsys)
    assert payload["ml_findings"] == []
    assert payload["ml_analysis"]["anomaly_count"] == 0


def test_text_output_has_separate_ml_section(
    capsys: pytest.CaptureFixture[str], anomaly_dir: Path, training_dir: Path
) -> None:
    main(["analyze", "--logs", str(anomaly_dir), "--enable-ml",
          "--ml-training-logs", str(training_dir)])
    out = capsys.readouterr().out
    assert out.index("Alerts:") < out.index("ML Anomaly Findings")
    ml_section = out[out.index("ML Anomaly Findings"):]
    assert "Anomalous activity pattern" in ml_section
    assert "not causal feature importance" in ml_section
    assert "attack confirmed" not in out.lower()
    assert ANOMALOUS_IP in ml_section


def test_output_is_deterministic(
    capsys: pytest.CaptureFixture[str], anomaly_dir: Path, training_dir: Path
) -> None:
    args = ["analyze", "--logs", str(anomaly_dir), "--enable-ml",
            "--ml-training-logs", str(training_dir), "--format", "json"]
    main(args)
    first = capsys.readouterr().out
    main(args)
    assert first == capsys.readouterr().out


def test_ml_does_not_change_deterministic_alerts_or_exit_code(
    capsys: pytest.CaptureFixture[str], training_dir: Path
) -> None:
    logs = SAMPLES_DIR / "ssh_bruteforce.log"
    main(["analyze", "--logs", str(logs), "--format", "json"])
    plain = _json(capsys)
    exit_code = main(["analyze", "--logs", str(logs), "--enable-ml",
                      "--ml-training-logs", str(training_dir), "--format", "json"])
    with_ml = _json(capsys)
    assert exit_code == 0
    assert with_ml["alerts"] == plain["alerts"]
    assert [a["severity"] for a in with_ml["alerts"]] == [a["severity"] for a in plain["alerts"]]


def test_overlapping_training_and_scoring_logs_rejected(
    capsys: pytest.CaptureFixture[str], training_dir: Path
) -> None:
    exit_code = main(["analyze", "--logs", str(training_dir), "--enable-ml",
                      "--ml-training-logs", str(training_dir)])
    assert exit_code == 1
    assert "separate" in capsys.readouterr().err


def test_missing_training_path_is_error(
    capsys: pytest.CaptureFixture[str], normal_dir: Path, tmp_path: Path
) -> None:
    exit_code = main(["analyze", "--logs", str(normal_dir), "--enable-ml",
                      "--ml-training-logs", str(tmp_path / "missing")])
    assert exit_code == 1
    assert "does not exist" in capsys.readouterr().err


def test_unparseable_training_logs_are_error(
    capsys: pytest.CaptureFixture[str], normal_dir: Path, tmp_path: Path
) -> None:
    _write(tmp_path / "bad" / "garbage.log", ["not a log line", "still not"])
    exit_code = main(["analyze", "--logs", str(normal_dir), "--enable-ml",
                      "--ml-training-logs", str(tmp_path / "bad")])
    assert exit_code == 1
    assert "no parseable events" in capsys.readouterr().err


def test_insufficient_training_logs_are_error(
    capsys: pytest.CaptureFixture[str], normal_dir: Path, tmp_path: Path
) -> None:
    _write(tmp_path / "tiny" / "one.log", _baseline_lines(clients=1, minutes=1)[:1])
    exit_code = main(["analyze", "--logs", str(normal_dir), "--enable-ml",
                      "--ml-training-logs", str(tmp_path / "tiny")])
    assert exit_code == 1
    assert "at least 2 training observations" in capsys.readouterr().err


def test_missing_scikit_learn_gives_clear_error(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    normal_dir: Path,
    training_dir: Path,
) -> None:
    def fail(name: str) -> None:
        raise ImportError("No module named 'sklearn'")

    monkeypatch.setattr(workflow, "import_module", fail)
    exit_code = main(["analyze", "--logs", str(normal_dir), "--enable-ml",
                      "--ml-training-logs", str(training_dir)])
    err = capsys.readouterr().err
    assert exit_code == 1
    assert "scikit-learn" in err and 'pip install -e ".[ml]"' in err


def test_ml_configuration_is_respected(
    capsys: pytest.CaptureFixture[str], anomaly_dir: Path, training_dir: Path, tmp_path: Path
) -> None:
    config = tmp_path / "config.toml"
    config.write_text(
        "[ml.isolation_forest]\nn_estimators = 25\nrandom_state = 7\ncontamination = 0.1\n",
        encoding="utf-8",
    )
    main(["analyze", "--logs", str(anomaly_dir), "--enable-ml",
          "--ml-training-logs", str(training_dir), "--config", str(config), "--format", "json"])
    settings = _json(capsys)["ml_analysis"]["settings"]
    assert settings["n_estimators"] == 25
    assert settings["random_state"] == 7
    assert settings["contamination"] == 0.1


def test_invalid_ml_configuration_is_error(
    capsys: pytest.CaptureFixture[str], normal_dir: Path, training_dir: Path, tmp_path: Path
) -> None:
    config = tmp_path / "config.toml"
    config.write_text("[ml.isolation_forest]\nn_estimators = -3\n", encoding="utf-8")
    exit_code = main(["analyze", "--logs", str(normal_dir), "--enable-ml",
                      "--ml-training-logs", str(training_dir), "--config", str(config)])
    assert exit_code == 1
    assert "error:" in capsys.readouterr().err


def test_workflow_api_without_events_scores_nothing(training_dir: Path) -> None:
    result = run_ml_analysis(sorted(training_dir.glob("*.log")), ())
    assert result.findings == () and result.scored_observation_count == 0


def test_workflow_rejects_empty_training_paths() -> None:
    with pytest.raises(MLAnalysisError, match="no training log files"):
        run_ml_analysis([], ())


def test_report_without_ml_matches_report_with_none(normal_dir: Path) -> None:
    result = analyze_paths(sorted(normal_dir.glob("*.log")))
    assert format_json_report(result) == format_json_report(result, None)
    assert format_text_report(result) == format_text_report(result, None)
