"""Deterministic text and JSON formatting for analysis results."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import datetime
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from loganalyzer.engine import AnalysisResult, ParserDiagnostic
from loganalyzer.models import Alert
from loganalyzer.security import redact_sensitive_text
from loganalyzer.summarization import AlertSummary

if TYPE_CHECKING:
    from loganalyzer.ml.isolation_forest import MLAnomalyFinding
    from loganalyzer.ml.workflow import MLAnalysisResult

ML_DISCLAIMER = (
    "Anomalous activity patterns are statistical deviations from the supplied training "
    "baseline, not confirmed attacks. IsolationForest does not attribute a finding to "
    "any individual feature; the training-range comparisons below are context only."
)
ML_SCORE_SEMANTICS = (
    "score_samples is the raw IsolationForest score (lower is more abnormal); "
    "an observation is classified as an outlier when score_samples is below "
    "raw_score_threshold. decision_function equals score_samples minus "
    "raw_score_threshold; negative values are outliers and zero is its boundary."
)


def format_alert(alert: Alert) -> str:
    """Format one alert without adding facts beyond its structured fields."""
    lines = [
        f"Severity: {redact_sensitive_text(alert.severity)}",
        f"Detector: {redact_sensitive_text(alert.detector)}",
        f"Title: {redact_sensitive_text(alert.title)}",
        f"Summary: {redact_sensitive_text(alert.summary)}",
        "",
        "Observed evidence:",
    ]
    if alert.evidence:
        for key, value in alert.evidence.items():
            lines.append(f"{_label(key)}: {_format_value(value)}")
    else:
        lines.append("None supplied")

    if alert.source_ips:
        lines.append(f"Source IPs: {_format_value(alert.source_ips)}")
    lines.append(f"Time range: {_format_time_range(alert.time_start, alert.time_end)}")
    if alert.confidence is not None:
        lines.append(f"Confidence: {_format_value(alert.confidence)}")

    lines.extend(["", "Recommended actions:"])
    if alert.recommended_actions:
        lines.extend(
            f"{index}. {redact_sensitive_text(action)}"
            for index, action in enumerate(alert.recommended_actions, start=1)
        )
    else:
        lines.append("None supplied")
    return "\n".join(lines)


def format_alerts(alerts: Iterable[Alert]) -> str:
    """Format multiple alerts separated by a blank line."""
    return "\n\n".join(format_alert(alert) for alert in alerts)


def format_text_report(
    result: AnalysisResult,
    ml_result: MLAnalysisResult | None = None,
    summaries: Sequence[AlertSummary] | None = None,
) -> str:
    """Format an analysis result without altering its findings or their order.

    ML findings, when supplied, are appended in a separate labelled section.
    """
    lines = [
        "Analysis report",
        "",
        "Files processed:",
        *_format_paths(result.files_processed),
        "",
        "Files skipped:",
        *_format_paths(result.files_skipped),
        "",
        f"Total normalized events: {result.event_count}",
        f"Number of alerts: {len(result.alerts)}",
        "",
        "Parser diagnostics/errors:",
        *_format_diagnostics(result.diagnostics),
        "",
        "Alerts:",
    ]
    if result.alerts:
        lines.extend(["", format_alerts(result.alerts)])
    else:
        lines.append("None")
    if summaries is not None:
        lines.extend(["", *_format_summary_section(summaries)])
    if ml_result is not None:
        lines.extend(["", *_format_ml_section(ml_result)])
    return "\n".join(lines)


def format_json_report(
    result: AnalysisResult,
    ml_result: MLAnalysisResult | None = None,
    summaries: Sequence[AlertSummary] | None = None,
) -> str:
    """Serialize an analysis result into deterministic, machine-readable JSON.

    ``ml_analysis`` and ``ml_findings`` are added only when ML results are supplied.
    """
    payload: dict[str, Any] = {
        "files_processed": [_json_value(path) for path in result.files_processed],
        "files_skipped": [_json_value(path) for path in result.files_skipped],
        "event_count": result.event_count,
        "diagnostics": [_diagnostic_data(diagnostic) for diagnostic in result.diagnostics],
        "alerts": [_alert_data(alert) for alert in result.alerts],
    }
    if ml_result is not None:
        payload["ml_analysis"] = _ml_summary_data(ml_result)
        payload["ml_findings"] = [_ml_finding_data(f) for f in ml_result.findings]
    if summaries is not None:
        payload["llm_summaries"] = [
            _summary_data(index, summary) for index, summary in enumerate(summaries, start=1)
        ]
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True)


def _format_summary_section(summaries: Sequence[AlertSummary]) -> list[str]:
    lines = [
        "LLM Analyst Summaries",
        "(advisory prose only; deterministic alert fields and evidence remain authoritative)",
    ]
    if not summaries:
        lines.append("None (no deterministic alerts to summarize)")
        return lines
    for index, summary in enumerate(summaries, start=1):
        lines.extend(
            [
                "",
                f"Summary for alert {index} ({summary.source}):",
                f"Incident summary: {redact_sensitive_text(summary.incident_summary)}",
                f"Plain-language explanation: {redact_sensitive_text(summary.explanation)}",
                "Prioritized recommendations:",
            ]
        )
        if summary.recommendations:
            lines.extend(
                f"{rank}. {redact_sensitive_text(action)}"
                for rank, action in enumerate(summary.recommendations, start=1)
            )
        else:
            lines.append("No response actions were supplied by the deterministic detector.")
        lines.append("Analyst investigation questions:")
        lines.extend(
            f"- {redact_sensitive_text(question)}" for question in summary.investigation_questions
        )
    return lines


def _summary_data(index: int, summary: AlertSummary) -> dict[str, Any]:
    return {
        "alert_index": index,
        "source": summary.source,
        "incident_summary": _json_value(summary.incident_summary),
        "explanation": _json_value(summary.explanation),
        "recommendations": _json_value(summary.recommendations),
        "investigation_questions": _json_value(summary.investigation_questions),
    }


def _settings_data(ml_result: MLAnalysisResult) -> dict[str, Any]:
    metadata = ml_result.metadata
    settings = metadata.settings
    return {
        "n_estimators": settings.n_estimators,
        "max_samples": settings.max_samples,
        "contamination": settings.contamination,
        "random_state": settings.random_state,
        "effective_max_samples": metadata.effective_max_samples,
    }


def _ml_summary_data(ml_result: MLAnalysisResult) -> dict[str, Any]:
    metadata = ml_result.metadata
    return {
        "model_name": metadata.model_name,
        "settings": _settings_data(ml_result),
        "raw_score_threshold": metadata.raw_score_threshold,
        "score_semantics": ML_SCORE_SEMANTICS,
        "feature_names": list(metadata.feature_names),
        "training_event_count": ml_result.training_event_count,
        "training_observation_count": ml_result.training_observation_count,
        "scored_observation_count": ml_result.scored_observation_count,
        "anomaly_count": len(ml_result.findings),
        "disclaimer": ML_DISCLAIMER,
    }


def _ml_finding_data(finding: MLAnomalyFinding) -> dict[str, Any]:
    settings = finding.model_metadata.settings
    return {
        "model_name": finding.model_name,
        "classification": finding.classification,
        "is_anomaly": finding.is_anomaly,
        "score_samples": finding.model_score,
        "raw_score_threshold": finding.raw_score_threshold,
        "decision_function": finding.decision_score,
        "decision_boundary": 0.0,
        "score_semantics": ML_SCORE_SEMANTICS,
        "source_ip": _json_value(finding.source_ip),
        "source_group": _json_value(finding.source_group),
        "log_types": _json_value(finding.log_types),
        "time_bucket": finding.time_bucket.isoformat(),
        "feature_names": list(finding.feature_names),
        "feature_values": dict(zip(finding.feature_names, finding.feature_values)),
        "training_context": [
            {
                "name": ref.name,
                "observed_value": ref.observed_value,
                "training_minimum": ref.reference_minimum,
                "training_maximum": ref.reference_maximum,
                "training_percentile": ref.reference_percentile,
                "outside_training_range": ref.outside_reference_range,
            }
            for ref in finding.feature_context
        ],
        "model_settings": {
            "n_estimators": settings.n_estimators,
            "max_samples": settings.max_samples,
            "contamination": settings.contamination,
            "random_state": settings.random_state,
            "effective_max_samples": finding.model_metadata.effective_max_samples,
        },
        "explanation": _ml_explanation(finding),
    }


def _ml_explanation(finding: MLAnomalyFinding) -> str:
    return (
        "Anomalous activity pattern: score_samples is below the raw_score_threshold, "
        "and decision_function is negative relative to its zero boundary. This is not "
        "a confirmed attack and does not identify which feature drove the score."
    )


def _format_ml_section(ml_result: MLAnalysisResult) -> list[str]:
    metadata = ml_result.metadata
    settings = _settings_data(ml_result)
    lines = [
        "ML Anomaly Findings",
        "(separate from deterministic alerts; they do not affect alert severity)",
        ML_DISCLAIMER,
        f"Model: {metadata.model_name}",
        "Settings: " + ", ".join(f"{key}={value}" for key, value in settings.items()),
        f"Raw score threshold (offset_): {metadata.raw_score_threshold:.6f}",
        "Score rule: lower score_samples is more abnormal; outlier when "
        "score_samples < raw score threshold. decision_function = score_samples - "
        "raw score threshold; negative is outlier, zero is the decision boundary.",
        f"Training events: {ml_result.training_event_count}",
        f"Training observations: {ml_result.training_observation_count}",
        f"Scored observations: {ml_result.scored_observation_count}",
        f"Anomalous observations: {len(ml_result.findings)}",
    ]
    if not ml_result.findings:
        lines.append("None")
        return lines
    for index, finding in enumerate(ml_result.findings, start=1):
        lines.extend(
            [
                "",
                f"ML finding {index}: Anomalous activity pattern",
                f"Source: {redact_sensitive_text(finding.source_group)}",
                f"Time bucket (UTC): {finding.time_bucket.isoformat()}",
                f"Classification: {finding.classification}",
                f"Raw score (score_samples; lower is more abnormal): {finding.model_score:.6f}",
                f"Raw-score threshold (offset_; outlier below): {finding.raw_score_threshold:.6f}",
                f"Decision function (negative is outlier; zero boundary): {finding.decision_score:.6f}",
                "Training-baseline context (not causal feature importance):",
            ]
        )
        for ref in finding.feature_context:
            marker = " [outside training range]" if ref.outside_reference_range else ""
            lines.append(
                f"- {ref.name}: observed={ref.observed_value:g}, "
                f"training range={ref.reference_minimum:g}..{ref.reference_maximum:g}, "
                f"percentile={ref.reference_percentile:g}{marker}"
            )
        lines.append(f"Explanation: {_ml_explanation(finding)}")
    return lines


def _format_paths(paths: Iterable[Path]) -> list[str]:
    entries = [str(path) for path in paths]
    return [f"- {entry}" for entry in entries] or ["None"]


def _format_diagnostics(diagnostics: Iterable[ParserDiagnostic]) -> list[str]:
    entries = []
    for diagnostic in diagnostics:
        format_suffix = f" (format: {diagnostic.format})" if diagnostic.format else ""
        entries.append(
            f"- {diagnostic.path}: {redact_sensitive_text(diagnostic.message)}{format_suffix}"
        )
    return entries or ["None"]


def _alert_data(alert: Alert) -> dict[str, Any]:
    return {
        "severity": redact_sensitive_text(alert.severity),
        "title": redact_sensitive_text(alert.title),
        "summary": redact_sensitive_text(alert.summary),
        "evidence": _json_value(alert.evidence),
        "recommended_actions": _json_value(alert.recommended_actions),
        "source_ips": _json_value(alert.source_ips),
        "time_start": _json_value(alert.time_start),
        "time_end": _json_value(alert.time_end),
        "detector": redact_sensitive_text(alert.detector),
        "confidence": _json_value(alert.confidence),
    }


def _diagnostic_data(diagnostic: ParserDiagnostic) -> dict[str, Any]:
    return {
        "path": str(diagnostic.path),
        "message": diagnostic.message,
        "format": diagnostic.format,
    }


def _json_value(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, str):
        return redact_sensitive_text(value)
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_value(item) for item in value]
    return value


def _label(key: str) -> str:
    return key.replace("_", " ").capitalize()


def _format_value(value: Any) -> str:
    if isinstance(value, tuple):
        return ", ".join(str(item) for item in value)
    if isinstance(value, datetime):
        return value.isoformat()
    return redact_sensitive_text(str(value))


def _format_time_range(start: datetime | None, end: datetime | None) -> str:
    if start is None and end is None:
        return "Not available"
    if start == end:
        return _format_value(start)
    return f"{_format_value(start)} - {_format_value(end)}"
