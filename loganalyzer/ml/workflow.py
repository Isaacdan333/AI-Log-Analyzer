"""Optional ML orchestration: baseline training logs -> fitted model -> scored findings.

This module reuses the existing parser/engine and ``engineer_features``; it
never runs deterministic detectors and never produces ``Alert`` objects.
scikit-learn is imported lazily so the rule-based pipeline works without it.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from importlib import import_module
from pathlib import Path
from typing import TYPE_CHECKING, Any

from loganalyzer.config import AnalyzerConfig
from loganalyzer.engine import analyze_paths
from loganalyzer.features import FEATURE_NAMES, FeatureObservation, engineer_features
from loganalyzer.models import NormalizedEvent

if TYPE_CHECKING:
    from loganalyzer.ml.isolation_forest import IsolationForestMetadata, MLAnomalyFinding

INSTALL_HINT = 'install the optional ML dependencies with: pip install -e ".[ml]"'
_ALLOWED_OPTIONS = ("n_estimators", "max_samples", "contamination", "random_state")


class MLAnalysisError(Exception):
    """An actionable failure of the optional ML workflow."""


@dataclass(frozen=True, slots=True)
class MLAnalysisResult:
    """Structured output of one ML run, kept separate from ``AnalysisResult``."""

    findings: tuple[MLAnomalyFinding, ...]
    scored_observation_count: int
    training_observation_count: int
    training_event_count: int
    metadata: IsolationForestMetadata


def _load_model_module() -> Any:
    try:
        return import_module("loganalyzer.ml.isolation_forest")
    except ImportError as error:
        raise MLAnalysisError(
            f"ML analysis requires scikit-learn, which is not installed; {INSTALL_HINT}"
        ) from error


def _model_options(ml_options: Mapping[str, Mapping[str, Any]] | None) -> dict[str, Any]:
    options = dict((ml_options or {}).get("isolation_forest", {}))
    unknown = sorted(set(options) - set(_ALLOWED_OPTIONS))
    if unknown:
        raise MLAnalysisError(f"unsupported IsolationForest options: {', '.join(unknown)}")
    return options


def load_training_observations(
    training_paths: Sequence[Path],
    *,
    formats: Mapping[Path, str] | None = None,
    config: AnalyzerConfig | None = None,
) -> tuple[tuple[FeatureObservation, ...], int]:
    """Parse baseline logs with the existing engine and engineer features."""
    if not training_paths:
        raise MLAnalysisError("no training log files were provided for the ML baseline")
    try:
        parsed = analyze_paths(training_paths, formats=formats, detectors=[], config=config)
    except (OSError, TypeError, ValueError) as error:
        raise MLAnalysisError(f"could not parse ML training logs: {error}") from error
    if not parsed.events:
        detail = "; ".join(f"{d.path}: {d.message}" for d in parsed.diagnostics)
        raise MLAnalysisError(
            "ML training logs contained no parseable events"
            + (f" ({detail})" if detail else "")
            + "; provide representative baseline logs"
        )
    observations = engineer_features(parsed.events)
    return observations, len(parsed.events)


def run_ml_analysis(
    training_paths: Sequence[Path],
    scoring_events: Sequence[NormalizedEvent],
    *,
    ml_options: Mapping[str, Mapping[str, Any]] | None = None,
    formats: Mapping[Path, str] | None = None,
    config: AnalyzerConfig | None = None,
) -> MLAnalysisResult:
    """Fit on baseline training logs, then score observations from other events.

    Only anomalous observations are returned in ``findings``; the counts show
    how many observations were scored.
    """
    module = _load_model_module()
    options = _model_options(ml_options)
    training, training_events = load_training_observations(
        training_paths, formats=formats, config=config
    )
    try:
        detector = module.IsolationForestAnomalyDetector(**options)
        detector.fit(training)
    except (TypeError, ValueError) as error:
        raise MLAnalysisError(
            f"could not train the IsolationForest baseline ({error}); provide more "
            "representative training logs or check the [ml.isolation_forest] settings"
        ) from error

    scoring = engineer_features(scoring_events)
    scored = detector.score(scoring) if scoring else ()
    findings = tuple(finding for finding in scored if finding.is_anomaly)
    metadata = detector.metadata
    if tuple(metadata.feature_names) != FEATURE_NAMES:
        raise MLAnalysisError("model feature names do not match the feature contract")
    return MLAnalysisResult(
        findings=findings,
        scored_observation_count=len(scoring),
        training_observation_count=len(training),
        training_event_count=training_events,
        metadata=metadata,
    )
