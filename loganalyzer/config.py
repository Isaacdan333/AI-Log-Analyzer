"""Optional TOML configuration for deterministic analyzer components."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from math import isfinite
from pathlib import Path
from typing import Any

from loganalyzer.limits import InputLimits

class ConfigurationError(ValueError):
    """Raised when an explicitly supplied configuration cannot be used."""


_DETECTOR_SECTIONS = frozenset(
    {
        "brute_force",
        "port_scan",
        "suspicious_login",
        "privilege_escalation",
        "impossible_travel",
        "unusual_traffic",
    }
)
_TOP_LEVEL_SECTIONS = _DETECTOR_SECTIONS | {"report", "input", "ml", "llm"}
_REPORT_OPTIONS = frozenset({"minimum_severity", "timezone"})
_INPUT_OPTIONS = frozenset({"max_file_size_bytes", "max_line_length"})
_ML_SECTIONS = frozenset({"isolation_forest"})
_ISOLATION_FOREST_OPTIONS = frozenset(
    {"n_estimators", "max_samples", "contamination", "random_state"}
)
_LLM_OPTIONS = frozenset({"enabled", "provider", "model", "timeout_seconds"})
_SEVERITIES = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})


@dataclass(frozen=True, slots=True)
class AnalyzerConfig:
    """Validated detector constructor options and display settings."""

    detector_options: dict[str, dict[str, Any]] = field(default_factory=dict)
    report_options: dict[str, Any] = field(default_factory=dict)
    input_limits: InputLimits = field(default_factory=InputLimits)
    ml_options: dict[str, dict[str, Any]] = field(default_factory=dict)
    llm_options: dict[str, Any] = field(default_factory=dict)


def load_config(path: Path | None = None) -> AnalyzerConfig:
    """Load optional TOML configuration, preserving constructor defaults when absent."""
    if path is None:
        return AnalyzerConfig()
    if not path.is_file():
        raise ConfigurationError(f"configuration file does not exist: {path}")

    try:
        with path.open("rb") as config_file:
            raw_config = tomllib.load(config_file)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ConfigurationError(f"could not load configuration '{path}': {error}") from error

    if not isinstance(raw_config, dict):
        raise ConfigurationError("configuration must contain TOML tables")
    unknown_sections = set(raw_config) - _TOP_LEVEL_SECTIONS
    if unknown_sections:
        names = ", ".join(sorted(unknown_sections))
        raise ConfigurationError(f"unknown configuration section(s): {names}")

    ml_values = raw_config.get("ml", {})
    if not isinstance(ml_values, dict):
        raise ConfigurationError("configuration section 'ml' must be a table")
    unknown_ml_sections = set(ml_values) - _ML_SECTIONS
    if unknown_ml_sections:
        names = ", ".join(sorted(unknown_ml_sections))
        raise ConfigurationError(f"unknown ML configuration section(s): {names}")
    ml_options: dict[str, dict[str, Any]] = {}
    for section in _ML_SECTIONS:
        values = ml_values.get(section, {})
        if not isinstance(values, dict):
            raise ConfigurationError(f"configuration section 'ml.{section}' must be a table")
        unknown_options = set(values) - _ISOLATION_FOREST_OPTIONS
        if unknown_options:
            names = ", ".join(sorted(unknown_options))
            raise ConfigurationError(f"unknown {section} option(s): {names}")
        if values:
            ml_options[section] = dict(values)

    llm_values = raw_config.get("llm", {})
    if not isinstance(llm_values, dict):
        raise ConfigurationError("configuration section 'llm' must be a table")
    unknown_llm_options = set(llm_values) - _LLM_OPTIONS
    if unknown_llm_options:
        names = ", ".join(sorted(unknown_llm_options))
        raise ConfigurationError(f"unknown llm option(s): {names}")
    llm_options = dict(llm_values)
    enabled = llm_options.get("enabled", False)
    if not isinstance(enabled, bool):
        raise ConfigurationError("llm.enabled must be true or false")
    provider = llm_options.get("provider", "openai")
    if provider != "openai":
        raise ConfigurationError("llm.provider must be 'openai'")
    model = llm_options.get("model", "gpt-4o-mini")
    if not isinstance(model, str) or not model.strip():
        raise ConfigurationError("llm.model must be a non-empty string")
    timeout_seconds = llm_options.get("timeout_seconds", 20)
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not isfinite(timeout_seconds)
        or not 0 < timeout_seconds <= 300
    ):
        raise ConfigurationError("llm.timeout_seconds must be greater than 0 and at most 300")

    detector_options: dict[str, dict[str, Any]] = {}
    for section in _DETECTOR_SECTIONS:
        values = raw_config.get(section, {})
        if not isinstance(values, dict):
            raise ConfigurationError(f"configuration section '{section}' must be a table")
        detector_options[section] = dict(values)

    report_options = raw_config.get("report", {})
    if not isinstance(report_options, dict):
        raise ConfigurationError("configuration section 'report' must be a table")
    unknown_report_options = set(report_options) - _REPORT_OPTIONS
    if unknown_report_options:
        names = ", ".join(sorted(unknown_report_options))
        raise ConfigurationError(f"unknown report option(s): {names}")
    minimum_severity = report_options.get("minimum_severity")
    if minimum_severity is not None and minimum_severity not in _SEVERITIES:
        raise ConfigurationError(
            "report.minimum_severity must be one of LOW, MEDIUM, HIGH, or CRITICAL"
        )

    input_options = raw_config.get("input", {})
    if not isinstance(input_options, dict):
        raise ConfigurationError("configuration section 'input' must be a table")
    unknown_input_options = set(input_options) - _INPUT_OPTIONS
    if unknown_input_options:
        names = ", ".join(sorted(unknown_input_options))
        raise ConfigurationError(f"unknown input option(s): {names}")
    try:
        input_limits = InputLimits(**input_options)
    except (TypeError, ValueError) as error:
        raise ConfigurationError(f"invalid input limits: {error}") from error

    return AnalyzerConfig(
        detector_options=detector_options,
        report_options=dict(report_options),
        input_limits=input_limits,
        ml_options=ml_options,
        llm_options=llm_options,
    )