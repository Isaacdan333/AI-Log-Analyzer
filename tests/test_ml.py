from dataclasses import replace
from datetime import datetime, timedelta, timezone
import math
from pathlib import Path

import pytest

from loganalyzer.engine import analyze_paths
from loganalyzer.features import FEATURE_NAMES, FeatureObservation, engineer_features
from loganalyzer.ml import IsolationForestAnomalyDetector, MLAnomalyFinding
from loganalyzer.models import Alert
from loganalyzer.synthetic.generate_logs import generate_logs

BASE_TIME = datetime(2026, 3, 10, tzinfo=timezone.utc)


def synthetic_observation(
    index: int,
    *,
    values: tuple[float, ...] | None = None,
    source_ip: str | None = None,
    timestamp: datetime | None = None,
    observation_type: type[FeatureObservation] = FeatureObservation,
) -> FeatureObservation:
    """Build deterministic model-level fixtures labelled as synthetic data."""
    if values is None:
        status_4xx = 0.05 + (index % 3) * 0.02
        status_3xx = 0.1
        values = (
            float(3 + index % 5),
            (index % 4) * 0.05,
            float(1 + index % 3),
            float(1 + index % 2),
            float(1 + index % 4),
            float(300 + index % 8 * 75),
            0.0,
            1.0 - status_3xx - status_4xx,
            status_3xx,
            status_4xx,
            0.0,
            0.0,
        )
    return observation_type(
        source_ip=source_ip or f"192.0.2.{100 + index % 100}",
        log_types=("synthetic",),
        bucket_start=timestamp or BASE_TIME + timedelta(minutes=index),
        events_per_minute=values[0],
        failed_login_ratio=values[1],
        distinct_ports=values[2],
        distinct_destination_hosts=values[3],
        distinct_users=values[4],
        bytes_sent_total=values[5],
        status_1xx_ratio=values[6],
        status_2xx_ratio=values[7],
        status_3xx_ratio=values[8],
        status_4xx_ratio=values[9],
        status_5xx_ratio=values[10],
        status_other_ratio=values[11],
    )


def synthetic_training() -> tuple[FeatureObservation, ...]:
    return tuple(synthetic_observation(index) for index in range(64))


def conspicuous_anomaly(
    *,
    source_ip: str = "203.0.113.200",
    timestamp: datetime = BASE_TIME + timedelta(days=2),
) -> FeatureObservation:
    return synthetic_observation(
        100,
        values=(
            500.0,
            1.0,
            100.0,
            100.0,
            100.0,
            1_000_000_000.0,
            0.0,
            0.0,
            0.0,
            0.0,
            1.0,
            0.0,
        ),
        source_ip=source_ip,
        timestamp=timestamp,
    )


def fitted_detector(
    training: tuple[FeatureObservation, ...] | None = None,
) -> IsolationForestAnomalyDetector:
    return IsolationForestAnomalyDetector(
        n_estimators=128,
        max_samples=32,
        contamination=0.05,
        random_state=17,
    ).fit(training if training is not None else synthetic_training())


def test_trains_on_synthetic_normal_observations_and_scores_held_out_normal() -> None:
    training = synthetic_training()
    held_out_normal = tuple(
        synthetic_observation(
            index,
            timestamp=BASE_TIME + timedelta(days=1, minutes=index),
        )
        for index in range(10, 18)
    )
    assert not {id(item) for item in training} & {id(item) for item in held_out_normal}

    detector = fitted_detector(training)
    findings = detector.score(held_out_normal)

    assert len(findings) == len(held_out_normal)
    assert all(not finding.is_anomaly for finding in findings)
    assert all(finding.classification == "normal" for finding in findings)
    assert detector.metadata.training_observation_count == len(training)


def test_detects_a_conspicuous_synthetic_anomaly_with_reference_context() -> None:
    detector = fitted_detector()
    anomaly = conspicuous_anomaly()

    (finding,) = detector.score([anomaly])

    assert finding.is_anomaly
    assert finding.classification == "anomaly"
    assert finding.model_name == "IsolationForest"
    assert finding.model_score < finding.decision_threshold
    assert finding.decision_score < 0
    assert any(item.outside_reference_range for item in finding.feature_context)
    assert "anomaly" in finding.classification
    assert not isinstance(finding, Alert)


def test_fixed_seed_reproduces_scores_and_classifications() -> None:
    training = synthetic_training()
    scoring = (synthetic_observation(0, timestamp=BASE_TIME + timedelta(days=1)), conspicuous_anomaly())

    first = fitted_detector(training).score(scoring)
    second = fitted_detector(training).score(scoring)

    assert [(item.model_score, item.decision_score, item.classification) for item in first] == [
        (item.model_score, item.decision_score, item.classification) for item in second
    ]


def test_feature_names_and_vector_order_reuse_the_existing_contract() -> None:
    observation = synthetic_observation(
        0,
        values=tuple(float(index) for index in range(len(FEATURE_NAMES))),
    )

    finding = fitted_detector().score([observation])[0]

    assert finding.feature_names is FEATURE_NAMES
    assert finding.feature_values == observation.to_vector()
    assert finding.feature_values == tuple(float(index) for index in range(12))
    assert tuple(item.name for item in finding.feature_context) == FEATURE_NAMES


@pytest.mark.parametrize("bad_value", [math.nan, math.inf, -math.inf])
def test_rejects_non_finite_training_features(bad_value: float) -> None:
    invalid = replace(synthetic_observation(0), bytes_sent_total=bad_value)

    with pytest.raises(ValueError, match="must be finite"):
        fitted_detector((synthetic_observation(1), invalid))


def test_rejects_non_finite_scoring_features() -> None:
    invalid = replace(synthetic_observation(90), failed_login_ratio=math.nan)

    with pytest.raises(ValueError, match="must be finite"):
        fitted_detector().score([invalid])


def test_rejects_invalid_feature_dimensions() -> None:
    class ShortObservation(FeatureObservation):
        __slots__ = ()

        def to_vector(self) -> tuple[float, ...]:
            return super().to_vector()[:-1]

    invalid = synthetic_observation(0, observation_type=ShortObservation)

    with pytest.raises(ValueError, match="11 features; expected 12"):
        fitted_detector((synthetic_observation(1), invalid))


@pytest.mark.parametrize(
    ("training", "message"),
    [
        ((), "at least 2 training observations; received 0"),
        ((synthetic_observation(0),), "at least 2 training observations; received 1"),
    ],
)
def test_rejects_insufficient_training_data(
    training: tuple[FeatureObservation, ...], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        fitted_detector(training)


def test_unfitted_model_and_invalid_settings_fail_explicitly() -> None:
    model = IsolationForestAnomalyDetector()

    with pytest.raises(RuntimeError, match="has not been fitted"):
        model.score([])
    with pytest.raises(RuntimeError, match="has not been fitted"):
        _ = model.metadata
    with pytest.raises(ValueError, match="n_estimators"):
        IsolationForestAnomalyDetector(n_estimators=0)
    with pytest.raises(ValueError, match="contamination"):
        IsolationForestAnomalyDetector(contamination=0.8)


def test_results_preserve_source_utc_bucket_and_model_metadata() -> None:
    naive_bucket = BASE_TIME.replace(tzinfo=None) + timedelta(days=1)
    observation = synthetic_observation(
        0, source_ip="198.51.100.7", timestamp=naive_bucket
    )
    detector = fitted_detector()

    (finding,) = detector.score([observation])

    assert finding.source_ip == "198.51.100.7"
    assert finding.source_group == "198.51.100.7"
    assert finding.time_bucket == naive_bucket.replace(tzinfo=timezone.utc)
    assert finding.time_bucket.utcoffset() == timedelta(0)
    assert finding.log_types == ("synthetic",)
    assert finding.model_metadata == detector.metadata
    assert finding.model_metadata.settings.n_estimators == 128
    assert finding.model_metadata.settings.max_samples == 32
    assert finding.model_metadata.settings.contamination == 0.05
    assert finding.model_metadata.settings.random_state == 17
    assert finding.model_metadata.effective_max_samples == 32
    assert finding.model_metadata.feature_names == FEATURE_NAMES
    assert finding.decision_threshold == detector.metadata.decision_threshold


def test_feature_context_covers_each_requested_anomaly_dimension() -> None:
    detector = fitted_detector()
    base = synthetic_observation(0).to_vector()
    scenarios = {
        "events_per_minute": (500.0, *base[1:]),
        "failed_login_ratio": (base[0], 1.0, *base[2:]),
        "distinct_ports": (*base[:2], 100.0, *base[3:]),
        "distinct_destination_hosts": (*base[:3], 100.0, *base[4:]),
        "distinct_users": (*base[:4], 100.0, *base[5:]),
        "bytes_sent_total": (*base[:5], 1_000_000_000.0, *base[6:]),
        "status_5xx_ratio": (*base[:10], 1.0, 0.0),
    }

    findings = detector.score(
        [
            synthetic_observation(
                100 + index,
                values=tuple(values),
                timestamp=BASE_TIME + timedelta(days=3, minutes=index),
            )
            for index, values in enumerate(scenarios.values())
        ]
    )

    for (feature_name, _), finding in zip(scenarios.items(), findings, strict=True):
        context = {item.name: item for item in finding.feature_context}
        assert context[feature_name].outside_reference_range
        assert context[feature_name].reference_percentile in {0.0, 100.0}


def test_synthetic_generator_and_normalized_event_pipeline_feed_model(tmp_path: Path) -> None:
    ssh_path = generate_logs(
        tmp_path / "ssh", scenario="ssh_normal", seed=12
    )["ssh_normal"]
    web_path = generate_logs(
        tmp_path / "web", scenario="web_baseline", seed=12
    )["web_baseline"]
    spike_path = generate_logs(
        tmp_path / "scoring", scenario="web_spike", seed=13
    )["web_spike"]
    parsed = analyze_paths(
        [ssh_path, web_path],
        formats={ssh_path: "ssh", web_path: "web"},
        detectors=[],
    )
    parsed_spike = analyze_paths(
        [spike_path], formats={spike_path: "web"}, detectors=[]
    )
    observations = engineer_features(parsed.events)
    spike_observations = engineer_features(parsed_spike.events)

    training_observations = (*synthetic_training(), *observations)
    detector = fitted_detector(training_observations)
    findings = detector.score(spike_observations)

    assert parsed.events
    assert len(observations) == 15
    assert spike_observations
    assert not {id(item) for item in observations} & {
        id(item) for item in spike_observations
    }
    assert detector.metadata.training_observation_count == 79
    assert len(findings) == len(spike_observations)
    assert all(item.is_anomaly for item in findings)


def test_training_and_evaluation_observations_are_separate() -> None:
    training = synthetic_training()
    evaluation = tuple(
        synthetic_observation(
            index,
            timestamp=BASE_TIME + timedelta(days=4, minutes=index),
        )
        for index in range(12)
    )
    anomalies = (conspicuous_anomaly(timestamp=BASE_TIME + timedelta(days=5)),)
    detector = fitted_detector(training)

    normal_findings = detector.score(evaluation)
    anomaly_findings = detector.score(anomalies)

    assert not {id(item) for item in training} & {
        id(item) for item in (*evaluation, *anomalies)
    }
    assert all(not result.is_anomaly for result in normal_findings)
    assert anomaly_findings[0].is_anomaly
    assert detector.metadata.training_observation_count == len(training)


def test_ml_findings_are_a_separate_result_type_from_deterministic_alerts() -> None:
    (finding,) = fitted_detector().score([conspicuous_anomaly()])

    assert isinstance(finding, MLAnomalyFinding)
    assert not isinstance(finding, Alert)
