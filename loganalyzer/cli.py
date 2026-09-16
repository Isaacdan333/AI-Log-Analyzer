"""Command-line interface: argument parsing and orchestration only.

This module wires together the existing pipeline (``engine.analyze_paths`` /
``engine.discover_log_files``) and the deterministic formatters in
``report.py``. It must not implement parsing, detection, or reporting logic
itself.
"""

from __future__ import annotations

import sys
from argparse import ArgumentParser, Namespace, RawDescriptionHelpFormatter
from collections.abc import Sequence
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from loganalyzer.engine import AnalysisResult, analyze_paths, discover_log_files
from loganalyzer.models import Alert
from loganalyzer.report import format_json_report, format_text_report

EXIT_SUCCESS = 0
EXIT_RUNTIME_ERROR = 1
# argparse itself exits with 2 for usage errors (missing/invalid arguments).

_SEVERITY_LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
_SEVERITY_RANK = {name: rank for rank, name in enumerate(_SEVERITY_LEVELS)}
_LOG_TYPES = ("ssh", "firewall", "web", "windows")


class CliError(Exception):
    """A user-facing CLI failure. Caught by ``main`` to avoid a traceback."""


def build_parser() -> ArgumentParser:
    parser = ArgumentParser(
        prog="loganalyzer",
        description="Analyze cybersecurity logs and produce deterministic alert reports.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser(
        "analyze",
        help="Analyze a log directory or a single supported log file.",
        description=(
            "Parse the given logs, run the full detector set, and print or "
            "save the resulting deterministic report."
        ),
        formatter_class=RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m loganalyzer.cli analyze --logs ./samples\n"
            "  python -m loganalyzer.cli analyze --logs ./samples --out report.txt\n"
            "  python -m loganalyzer.cli analyze --logs ./samples --format json\n"
            "  python -m loganalyzer.cli analyze --logs ./samples --format json --out report.json\n"
            "  python -m loganalyzer.cli analyze --logs ./samples --minimum-severity HIGH"
        ),
    )
    analyze.add_argument(
        "--logs",
        required=True,
        type=Path,
        help="Path to a directory of log files or a single supported log file.",
    )
    analyze.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Optional output file path. Defaults to printing the report to stdout.",
    )
    analyze.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Report output format (default: text).",
    )
    analyze.add_argument(
        "--minimum-severity",
        choices=_SEVERITY_LEVELS,
        default=None,
        help="Only display alerts at or above this severity.",
    )
    analyze.add_argument(
        "--log-type",
        choices=_LOG_TYPES,
        default=None,
        help="Explicit parser override applied to every discovered file (default: auto-detect).",
    )
    analyze.add_argument(
        "--timezone",
        default=None,
        metavar="TIMEZONE",
        help="IANA timezone name used to display alert timestamps (default: UTC).",
    )
    return parser


def _resolve_input_paths(logs: Path) -> list[Path]:
    """Return the concrete files to analyze, or raise ``CliError`` for a bad path."""
    if not logs.exists():
        raise CliError(f"input path does not exist: {logs}")
    if logs.is_dir():
        paths = discover_log_files(logs)
        if not paths:
            raise CliError(f"no supported log files found in directory: {logs}")
        return paths
    if logs.is_file():
        return [logs]
    raise CliError(f"input path is neither a file nor a directory: {logs}")


def _convert_alert_timezone(alert: Alert, tz: ZoneInfo) -> Alert:
    converted_evidence = {
        key: (value.astimezone(tz) if isinstance(value, datetime) else value)
        for key, value in alert.evidence.items()
    }
    return replace(
        alert,
        evidence=converted_evidence,
        time_start=alert.time_start.astimezone(tz) if alert.time_start else None,
        time_end=alert.time_end.astimezone(tz) if alert.time_end else None,
    )


def _apply_timezone(result: AnalysisResult, timezone_name: str) -> AnalysisResult:
    """Convert alert timestamps for display only; detection facts are unchanged."""
    try:
        tz = ZoneInfo(timezone_name)
    except ZoneInfoNotFoundError as error:
        raise CliError(f"unknown timezone '{timezone_name}'") from error
    converted_alerts = tuple(_convert_alert_timezone(alert, tz) for alert in result.alerts)
    return replace(result, alerts=converted_alerts)


def _filter_by_minimum_severity(result: AnalysisResult, minimum: str | None) -> AnalysisResult:
    """Filter displayed alerts only; never rerun detectors or alter severities."""
    if minimum is None:
        return result
    threshold = _SEVERITY_RANK[minimum]
    filtered = tuple(
        alert
        for alert in result.alerts
        if _SEVERITY_RANK.get(alert.severity, -1) >= threshold
    )
    return replace(result, alerts=filtered)


def _run_analysis(args: Namespace) -> AnalysisResult:
    paths = _resolve_input_paths(args.logs)
    formats = {path: args.log_type for path in paths} if args.log_type else None
    result = analyze_paths(paths, formats=formats)
    if args.timezone:
        result = _apply_timezone(result, args.timezone)
    return _filter_by_minimum_severity(result, args.minimum_severity)


def _render_report(result: AnalysisResult, output_format: str) -> str:
    if output_format == "json":
        return format_json_report(result)
    return format_text_report(result)


def _write_report(report: str, out: Path | None) -> None:
    if out is None:
        print(report)
        return
    try:
        out.write_text(report + "\n", encoding="utf-8")
    except OSError as error:
        raise CliError(f"could not write output file '{out}': {error}") from error


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        result = _run_analysis(args)
        report = _render_report(result, args.format)
        _write_report(report, args.out)
    except CliError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_RUNTIME_ERROR
    return EXIT_SUCCESS


if __name__ == "__main__":
    raise SystemExit(main())
