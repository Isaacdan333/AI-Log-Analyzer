"""Deterministic baseline-deviation detection for request/connection volume."""

from __future__ import annotations

import statistics
from collections import Counter, defaultdict
from collections.abc import Iterable, Sequence
from datetime import datetime, timedelta, timezone
from typing import Any

from loganalyzer.models import Alert, NormalizedEvent

_DEFAULT_EVENT_TYPES = frozenset({"http_request", "network_connection"})
_VALID_GROUPINGS = frozenset({"source_ip", "service", "source_ip_service"})
_VALID_METHODS = frozenset({"zscore", "iqr"})
_ZERO_VARIANCE_EPSILON = 1e-9


class UnusualTrafficDetector:
    """Flag traffic buckets that deviate from an established per-group baseline.

    This detector reports a statistical anomaly, not confirmed malicious
    activity. It requires a sufficient number of prior baseline buckets for a
    group before it will evaluate any deviation; without enough history it
    returns no finding rather than inventing a baseline.
    """

    def __init__(
        self,
        bucket_seconds: int = 300,
        min_baseline_buckets: int = 5,
        statistical_method: str = "zscore",
        zscore_threshold: float = 3.0,
        iqr_multiplier: float = 1.5,
        grouping: str = "source_ip",
        min_observed_volume: int = 1,
        event_types: frozenset[str] = _DEFAULT_EVENT_TYPES,
        high_multiplier: float = 1.5,
        critical_multiplier: float = 2.5,
    ) -> None:
        if bucket_seconds <= 0:
            raise ValueError("bucket_seconds must be positive")
        if min_baseline_buckets < 2:
            raise ValueError("min_baseline_buckets must be at least 2")
        if statistical_method not in _VALID_METHODS:
            raise ValueError(f"statistical_method must be one of {sorted(_VALID_METHODS)}")
        if zscore_threshold <= 0:
            raise ValueError("zscore_threshold must be positive")
        if iqr_multiplier <= 0:
            raise ValueError("iqr_multiplier must be positive")
        if grouping not in _VALID_GROUPINGS:
            raise ValueError(f"grouping must be one of {sorted(_VALID_GROUPINGS)}")
        if min_observed_volume < 0:
            raise ValueError("min_observed_volume must be non-negative")
        if not event_types:
            raise ValueError("event_types must not be empty")
        if high_multiplier <= 1:
            raise ValueError("high_multiplier must be greater than 1")
        if critical_multiplier <= high_multiplier:
            raise ValueError("critical_multiplier must be greater than high_multiplier")

        self.bucket_seconds = bucket_seconds
        self.min_baseline_buckets = min_baseline_buckets
        self.statistical_method = statistical_method
        self.zscore_threshold = zscore_threshold
        self.iqr_multiplier = iqr_multiplier
        self.grouping = grouping
        self.min_observed_volume = min_observed_volume
        self.event_types = frozenset(event_types)
        self.high_multiplier = high_multiplier
        self.critical_multiplier = critical_multiplier

    def detect(self, events: Iterable[NormalizedEvent]) -> Sequence[Alert]:
        grouped: defaultdict[tuple[str, ...], dict[datetime, list[NormalizedEvent]]] = defaultdict(dict)
        for event in events:
            if event.event_type not in self.event_types:
                continue
            if not isinstance(event.timestamp, datetime):
                continue
            group_key = self._group_key(event)
            if group_key is None:
                continue
            bucket_start = self._bucket_start(event.timestamp)
            grouped[group_key].setdefault(bucket_start, []).append(event)

        alerts: list[Alert] = []
        for group_key, buckets in grouped.items():
            baseline_counts: list[int] = []
            for bucket_start, bucket_events in sorted(buckets.items(), key=lambda item: item[0]):
                observed_count = len(bucket_events)
                if len(baseline_counts) >= self.min_baseline_buckets:
                    alert = self._evaluate_bucket(
                        group_key, bucket_start, bucket_events, observed_count, baseline_counts
                    )
                    if alert is not None:
                        alerts.append(alert)
                baseline_counts.append(observed_count)

        return alerts

    def _evaluate_bucket(
        self,
        group_key: tuple[str, ...],
        bucket_start: datetime,
        bucket_events: list[NormalizedEvent],
        observed_count: int,
        baseline_counts: list[int],
    ) -> Alert | None:
        if observed_count < self.min_observed_volume:
            return None

        score, baseline_stat, sample_count = self._score(observed_count, baseline_counts)
        threshold = self.zscore_threshold if self.statistical_method == "zscore" else self.iqr_multiplier
        if score < threshold:
            return None

        severity = self._severity(score, threshold)
        grouping_evidence = self._grouping_evidence(group_key)
        metrics = self._bucket_metrics(bucket_events)
        bucket_end = bucket_start + timedelta(seconds=self.bucket_seconds)

        source_ip = grouping_evidence.get("source_ip")
        summary_subject = " / ".join(str(value) for value in grouping_evidence.values())
        summary = (
            f"Traffic for {summary_subject} in the bucket starting at "
            f"{bucket_start.isoformat()} was {observed_count} events, compared with a "
            f"baseline of {baseline_stat:.2f} over {sample_count} prior buckets "
            f"({self.statistical_method} score {score:.2f} vs threshold {threshold:.2f})."
        )

        evidence: dict[str, Any] = {
            **grouping_evidence,
            "grouping": self.grouping,
            "time_bucket_start": bucket_start,
            "time_bucket_end": bucket_end,
            "bucket_seconds": self.bucket_seconds,
            "observed_count": observed_count,
            "baseline_statistic": baseline_stat,
            "baseline_sample_count": sample_count,
            "statistical_method": self.statistical_method,
            "score": score,
            "threshold": threshold,
            **metrics,
        }

        return Alert(
            severity=severity,
            title="Unusual traffic pattern detected",
            summary=summary,
            evidence=evidence,
            recommended_actions=(
                "Compare the traffic change against known application or deployment changes",
                "Inspect the high-volume endpoints or hosts involved for a legitimate cause",
                "Apply rate limiting only after confirming the traffic is not authorized activity",
            ),
            source_ips=(source_ip,) if source_ip else (),
            time_start=bucket_start,
            time_end=bucket_end,
            detector="unusual_traffic",
            confidence="low",
        )

    def _score(
        self, observed_count: int, baseline_counts: list[int]
    ) -> tuple[float, float, int]:
        sample_count = len(baseline_counts)
        if self.statistical_method == "zscore":
            mean = statistics.fmean(baseline_counts)
            stdev = statistics.pstdev(baseline_counts)
            stdev = stdev if stdev > 0 else _ZERO_VARIANCE_EPSILON
            score = (observed_count - mean) / stdev
            return score, mean, sample_count

        quartiles = statistics.quantiles(baseline_counts, n=4, method="inclusive")
        first_quartile, _, third_quartile = quartiles
        median = statistics.median(baseline_counts)
        interquartile_range = third_quartile - first_quartile
        interquartile_range = (
            interquartile_range if interquartile_range > 0 else _ZERO_VARIANCE_EPSILON
        )
        score = (observed_count - median) / interquartile_range
        return score, median, sample_count

    def _severity(self, score: float, threshold: float) -> str:
        ratio = score / threshold
        if ratio >= self.critical_multiplier:
            return "CRITICAL"
        if ratio >= self.high_multiplier:
            return "HIGH"
        return "MEDIUM"

    def _group_key(self, event: NormalizedEvent) -> tuple[str, ...] | None:
        if self.grouping == "source_ip":
            return (event.src_ip,) if event.src_ip else None
        if self.grouping == "service":
            return (event.log_type,) if event.log_type else None
        if event.src_ip and event.log_type:
            return (event.src_ip, event.log_type)
        return None

    def _grouping_evidence(self, group_key: tuple[str, ...]) -> dict[str, Any]:
        if self.grouping == "source_ip":
            return {"source_ip": group_key[0]}
        if self.grouping == "service":
            return {"service": group_key[0]}
        return {"source_ip": group_key[0], "service": group_key[1]}

    @staticmethod
    def _bucket_metrics(bucket_events: list[NormalizedEvent]) -> dict[str, Any]:
        bytes_values = [event.bytes_sent for event in bucket_events if event.bytes_sent is not None]
        paths = {event.path for event in bucket_events if event.path}
        status_counts = Counter(event.status for event in bucket_events if event.status)
        return {
            "bytes_sent_total": sum(bytes_values) if bytes_values else None,
            "distinct_paths": len(paths),
            "status_code_distribution": dict(status_counts),
        }

    def _bucket_start(self, timestamp: datetime) -> datetime:
        aware_timestamp = (
            timestamp.astimezone(timezone.utc)
            if timestamp.tzinfo is not None
            else timestamp.replace(tzinfo=timezone.utc)
        )
        epoch_seconds = aware_timestamp.timestamp()
        bucket_epoch = (epoch_seconds // self.bucket_seconds) * self.bucket_seconds
        return datetime.fromtimestamp(bucket_epoch, tz=timezone.utc)
