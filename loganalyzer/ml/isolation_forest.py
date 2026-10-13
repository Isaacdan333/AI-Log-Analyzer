"""Isolated IsolationForest training and scoring for engineered observations."""

from __future__ import annotations

import math
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from numbers import Real
from typing import Literal

from sklearn.ensemble import IsolationForest

from loganalyzer.features import FEATURE_NAMES, FeatureObservation

_MODEL_NAME = "IsolationForest"
_DEFAULT_MAX_SAMPLES = 256


@dataclass(frozen=True, slots=True)
class IsolationForestSettings:
    """Requested IsolationForest hyperparameters."""

    n_estimators: int = 100
    max_samples: int | Literal["auto"] = _DEFAULT_MAX_SAMPLES
    contamination: float | Literal["auto"] = 0.05
    random_state: int | None = 42


@dataclass(frozen=True, slots=True)
class IsolationForestMetadata:
    """Effective settings and feature contract for a fitted model."""

    model_name: str
    feature_names: tuple[str, ...]
    settings: IsolationForestSettings
    training_observation_count: int
    effective_max_samples: int
    decision_threshold: float


@dataclass(frozen=True, slots=True)
class FeatureReference:
    """Empirical training-data context, not a causal feature explanation."""

    name: str
    observed_value: float
    reference_minimum: float
    reference_maximum: float
    reference_percentile: float
    outside_reference_range: bool


@dataclass(frozen=True, slots=True)
class MLAnomalyFinding:
    """One model classification with observation context and score details."""

    source_ip: str | None
    source_group: str
    time_bucket: datetime
    log_types: tuple[str, ...]
    model_name: str
    classification: Literal["normal", "anomaly"]
    is_anomaly: bool
    model_score: float
    decision_score: float
    decision_threshold: float
    feature_names: tuple[str, ...]
    feature_values: tuple[float, ...]
    feature_context: tuple[FeatureReference, ...]
    model_metadata: IsolationForestMetadata


class IsolationForestAnomalyDetector:
    """Train and score feature observations without affecting rule findings.

    Feature context compares observations with the training sample's empirical
    ranges and percentiles. It is descriptive context only: IsolationForest
    does not establish that any individual feature caused its classification.
    """

    def __init__(
        self,
        *,
        n_estimators: int = 100,
        max_samples: int | Literal["auto"] = _DEFAULT_MAX_SAMPLES,
        contamination: float | Literal["auto"] = 0.05,
        random_state: int | None = 42,
    ) -> None:
        _validate_settings(n_estimators, max_samples, contamination, random_state)
        self.settings = IsolationForestSettings(
            n_estimators=n_estimators,
            max_samples=max_samples,
            contamination=contamination,
            random_state=random_state,
        )
        self._model: IsolationForest | None = None
        self._metadata: IsolationForestMetadata | None = None
        self._reference_values: tuple[tuple[float, ...], ...] | None = None

    @property
    def metadata(self) -> IsolationForestMetadata:
        """Return effective model metadata; raise if training has not succeeded."""
        if self._metadata is None:
            raise RuntimeError("IsolationForest model has not been fitted")
        return self._metadata

    def fit(self, observations: Iterable[FeatureObservation]) -> IsolationForestAnomalyDetector:
        """Fit using normal training observations only and return this detector."""
        training = tuple(observations)
        if len(training) < 2:
            raise ValueError(
                "IsolationForest requires at least 2 training observations; "
                f"received {len(training)}"
            )

        vectors = _validated_vectors(training, "training")
        effective_max_samples = (
            min(_DEFAULT_MAX_SAMPLES, len(vectors))
            if self.settings.max_samples == "auto"
            else min(self.settings.max_samples, len(vectors))
        )
        model = IsolationForest(
            n_estimators=self.settings.n_estimators,
            max_samples=effective_max_samples,
            contamination=self.settings.contamination,
            random_state=self.settings.random_state,
        )
        model.fit(vectors)

        self._model = model
        self._reference_values = tuple(
            tuple(vector[index] for vector in vectors)
            for index in range(len(FEATURE_NAMES))
        )
        self._metadata = IsolationForestMetadata(
            model_name=_MODEL_NAME,
            feature_names=FEATURE_NAMES,
            settings=self.settings,
            training_observation_count=len(vectors),
            effective_max_samples=effective_max_samples,
            decision_threshold=float(model.offset_),
        )
        return self

    def score(
        self, observations: Iterable[FeatureObservation]
    ) -> tuple[MLAnomalyFinding, ...]:
        """Classify observations, preserving source/time and empirical context."""
        if self._model is None or self._reference_values is None:
            raise RuntimeError("IsolationForest model has not been fitted")

        scored_observations = tuple(observations)
        vectors = _validated_vectors(scored_observations, "scoring")
        if not vectors:
            return ()

        classifications = self._model.predict(vectors)
        model_scores = self._model.score_samples(vectors)
        decision_scores = self._model.decision_function(vectors)
        return tuple(
            self._finding(observation, vector, int(prediction), float(score), float(decision))
            for observation, vector, prediction, score, decision in zip(
                scored_observations,
                vectors,
                classifications,
                model_scores,
                decision_scores,
                strict=True,
            )
        )

    def _finding(
        self,
        observation: FeatureObservation,
        vector: tuple[float, ...],
        prediction: int,
        model_score: float,
        decision_score: float,
    ) -> MLAnomalyFinding:
        assert self._reference_values is not None
        is_anomaly = prediction == -1
        log_types = tuple(observation.log_types)
        source_group = (
            observation.source_ip
            if observation.source_ip
            else f"log_type:{','.join(log_types) or 'unknown'}"
        )
        time_bucket = observation.bucket_start
        if time_bucket.tzinfo is None:
            time_bucket = time_bucket.replace(tzinfo=timezone.utc)
        else:
            time_bucket = time_bucket.astimezone(timezone.utc)

        context = tuple(
            _feature_reference(name, value, reference)
            for name, value, reference in zip(
                FEATURE_NAMES,
                vector,
                self._reference_values,
                strict=True,
            )
        )
        return MLAnomalyFinding(
            source_ip=observation.source_ip,
            source_group=source_group,
            time_bucket=time_bucket,
            log_types=log_types,
            model_name=_MODEL_NAME,
            classification="anomaly" if is_anomaly else "normal",
            is_anomaly=is_anomaly,
            model_score=model_score,
            decision_score=decision_score,
            decision_threshold=self.metadata.decision_threshold,
            feature_names=FEATURE_NAMES,
            feature_values=vector,
            feature_context=context,
            model_metadata=self.metadata,
        )


def _validate_settings(
    n_estimators: int,
    max_samples: int | Literal["auto"],
    contamination: float | Literal["auto"],
    random_state: int | None,
) -> None:
    if isinstance(n_estimators, bool) or not isinstance(n_estimators, int) or n_estimators < 1:
        raise ValueError("n_estimators must be a positive integer")
    if max_samples != "auto" and (
        isinstance(max_samples, bool) or not isinstance(max_samples, int) or max_samples < 1
    ):
        raise ValueError("max_samples must be a positive integer or 'auto'")
    if contamination != "auto" and (
        isinstance(contamination, bool)
        or not isinstance(contamination, Real)
        or not math.isfinite(contamination)
        or not 0 < contamination <= 0.5
    ):
        raise ValueError("contamination must be 'auto' or a number in (0, 0.5]")
    if random_state is not None and (
        isinstance(random_state, bool)
        or not isinstance(random_state, int)
        or random_state < 0
    ):
        raise ValueError("random_state must be a non-negative integer or None")


def _validated_vectors(
    observations: tuple[FeatureObservation, ...], context: str
) -> list[tuple[float, ...]]:
    vectors: list[tuple[float, ...]] = []
    for index, observation in enumerate(observations):
        if not isinstance(observation, FeatureObservation):
            raise TypeError(
                f"{context} observation {index} must be a FeatureObservation"
            )
        raw_vector = observation.to_vector()
        if len(raw_vector) != len(FEATURE_NAMES):
            raise ValueError(
                f"{context} observation {index} has {len(raw_vector)} features; "
                f"expected {len(FEATURE_NAMES)}"
            )
        values: list[float] = []
        for feature_name, value in zip(FEATURE_NAMES, raw_vector, strict=True):
            if isinstance(value, bool) or not isinstance(value, Real):
                raise ValueError(
                    f"{context} observation {index} feature '{feature_name}' "
                    "must be a finite number"
                )
            numeric_value = float(value)
            if not math.isfinite(numeric_value):
                raise ValueError(
                    f"{context} observation {index} feature '{feature_name}' "
                    "must be finite"
                )
            values.append(numeric_value)
        vectors.append(tuple(values))
    return vectors


def _feature_reference(
    name: str, observed_value: float, training_values: tuple[float, ...]
) -> FeatureReference:
    ordered = sorted(training_values)
    reference_minimum = ordered[0]
    reference_maximum = ordered[-1]
    percentile = 100.0 * sum(value <= observed_value for value in ordered) / len(ordered)
    return FeatureReference(
        name=name,
        observed_value=observed_value,
        reference_minimum=reference_minimum,
        reference_maximum=reference_maximum,
        reference_percentile=percentile,
        outside_reference_range=(
            observed_value < reference_minimum or observed_value > reference_maximum
        ),
    )
