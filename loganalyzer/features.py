"""Model-independent feature engineering for normalized log events."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone

from loganalyzer.models import NormalizedEvent

FEATURE_NAMES = (
    "events_per_minute",
    "failed_login_ratio",
    "distinct_ports",
    "distinct_destination_hosts",
    "distinct_users",
    "bytes_sent_total",
    "status_1xx_ratio",
    "status_2xx_ratio",
    "status_3xx_ratio",
    "status_4xx_ratio",
    "status_5xx_ratio",
    "status_other_ratio",
)

_AUTHENTICATION_EVENT_TYPES = frozenset({"login_failure", "login_success"})
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


@dataclass(frozen=True, slots=True)
class FeatureObservation:
    """One fixed-width numeric feature vector for a source and time bucket."""

    source_ip: str | None
    log_types: tuple[str, ...]
    bucket_start: datetime
    events_per_minute: float
    failed_login_ratio: float
    distinct_ports: float
    distinct_destination_hosts: float
    distinct_users: float
    bytes_sent_total: float
    status_1xx_ratio: float
    status_2xx_ratio: float
    status_3xx_ratio: float
    status_4xx_ratio: float
    status_5xx_ratio: float
    status_other_ratio: float

    def to_vector(self) -> tuple[float, ...]:
        """Return features in the stable order defined by ``FEATURE_NAMES``."""
        return (
            self.events_per_minute,
            self.failed_login_ratio,
            self.distinct_ports,
            self.distinct_destination_hosts,
            self.distinct_users,
            self.bytes_sent_total,
            self.status_1xx_ratio,
            self.status_2xx_ratio,
            self.status_3xx_ratio,
            self.status_4xx_ratio,
            self.status_5xx_ratio,
            self.status_other_ratio,
        )


@dataclass(slots=True)
class _Bucket:
    event_count: int = 0
    failed_login_count: int = 0
    login_count: int = 0
    ports: set[int] = field(default_factory=set)
    destination_hosts: set[str] = field(default_factory=set)
    users: set[str] = field(default_factory=set)
    log_types: set[str] = field(default_factory=set)
    bytes_sent_total: int = 0
    status_counts: list[int] = field(default_factory=lambda: [0] * 6)

    def add(self, event: NormalizedEvent) -> None:
        self.event_count += 1
        self.log_types.add(event.log_type)

        if event.event_type in _AUTHENTICATION_EVENT_TYPES:
            self.login_count += 1
            if event.event_type == "login_failure":
                self.failed_login_count += 1

        if event.dst_port is not None:
            self.ports.add(event.dst_port)
        if event.dst_ip:
            self.destination_hosts.add(event.dst_ip)
        if event.user:
            self.users.add(event.user)
        if event.bytes_sent is not None:
            self.bytes_sent_total += event.bytes_sent

        if event.log_type == "web" and event.status is not None:
            self.status_counts[_status_class_index(event.status)] += 1

    def observation(
        self,
        source_ip: str | None,
        bucket_start: datetime,
        bucket_seconds: int,
    ) -> FeatureObservation:
        status_count = sum(self.status_counts)
        status_ratios = tuple(
            count / status_count if status_count else 0.0
            for count in self.status_counts
        )
        return FeatureObservation(
            source_ip=source_ip,
            log_types=tuple(sorted(self.log_types)),
            bucket_start=bucket_start,
            events_per_minute=self.event_count * 60.0 / bucket_seconds,
            failed_login_ratio=(
                self.failed_login_count / self.login_count if self.login_count else 0.0
            ),
            distinct_ports=float(len(self.ports)),
            distinct_destination_hosts=float(len(self.destination_hosts)),
            distinct_users=float(len(self.users)),
            bytes_sent_total=float(self.bytes_sent_total),
            status_1xx_ratio=status_ratios[0],
            status_2xx_ratio=status_ratios[1],
            status_3xx_ratio=status_ratios[2],
            status_4xx_ratio=status_ratios[3],
            status_5xx_ratio=status_ratios[4],
            status_other_ratio=status_ratios[5],
        )


def engineer_features(
    events: Iterable[NormalizedEvent], *, bucket_seconds: int = 60
) -> tuple[FeatureObservation, ...]:
    """Aggregate normalized events into per-source, per-time-bucket vectors.

    Buckets are UTC-aligned and combine log types for the same source IP.
    Naive timestamps are interpreted as UTC, matching the analyzer's
    timestamp-ordering convention. Events without a source IP are grouped by
    log type and bucket rather than mixed across log types.
    """
    if (
        isinstance(bucket_seconds, bool)
        or not isinstance(bucket_seconds, int)
        or bucket_seconds <= 0
    ):
        raise ValueError("bucket_seconds must be a positive integer")

    buckets: defaultdict[tuple[str | None, str | None, datetime], _Bucket] = defaultdict(
        _Bucket
    )
    for event in events:
        timestamp = event.timestamp
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        else:
            timestamp = timestamp.astimezone(timezone.utc)
        elapsed = timestamp - _EPOCH
        elapsed_microseconds = (
            (elapsed.days * 86_400 + elapsed.seconds) * 1_000_000
            + elapsed.microseconds
        )
        bucket_microseconds = bucket_seconds * 1_000_000
        bucket_start = _EPOCH + timedelta(
            microseconds=(elapsed_microseconds // bucket_microseconds)
            * bucket_microseconds
        )
        source_ip = event.src_ip or None
        ungrouped_log_type = event.log_type if source_ip is None else None
        buckets[(source_ip, ungrouped_log_type, bucket_start)].add(event)

    observations = [
        bucket.observation(source_ip, bucket_start, bucket_seconds)
        for (source_ip, _, bucket_start), bucket in sorted(
            buckets.items(),
            key=lambda item: (
                item[0][0] or "",
                item[0][1] or "",
                item[0][2],
            ),
        )
    ]
    return tuple(observations)


def _status_class_index(status: str) -> int:
    if len(status) == 3 and status.isdecimal():
        status_code = int(status)
        if 100 <= status_code <= 599:
            return status_code // 100 - 1
    return 5
