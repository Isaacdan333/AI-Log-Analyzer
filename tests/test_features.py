from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from loganalyzer.features import FEATURE_NAMES, FeatureObservation, engineer_features
from loganalyzer.models import NormalizedEvent

BASE_TIME = datetime(2026, 3, 10, 2, 0, tzinfo=timezone.utc)


def make_event(
    *,
    offset_seconds: int = 0,
    log_type: str = "ssh",
    event_type: str = "login_success",
    src_ip: str | None = "192.0.2.10",
    **fields: object,
) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=BASE_TIME + timedelta(seconds=offset_seconds),
        source="test",
        log_type=log_type,
        event_type=event_type,
        src_ip=src_ip,
        **fields,
    )


def test_engineers_fixed_width_features_across_log_types() -> None:
    events = [
        make_event(event_type="login_failure", user="alice", status="failure"),
        make_event(event_type="login_success", user="bob", status="success"),
        make_event(
            log_type="firewall",
            event_type="network_connection",
            dst_ip="198.51.100.4",
            dst_port=443,
            bytes_sent=500,
            status="accepted",
        ),
        make_event(
            log_type="firewall",
            event_type="network_connection",
            dst_ip="198.51.100.5",
            dst_port=22,
            bytes_sent=0,
            status="denied",
        ),
        make_event(
            log_type="web",
            event_type="http_request",
            status="404",
            bytes_sent=100,
        ),
        make_event(
            log_type="web",
            event_type="http_request",
            status="500",
            bytes_sent=None,
        ),
    ]

    observation = engineer_features(events)[0]

    assert observation.log_types == ("firewall", "ssh", "web")
    assert observation.events_per_minute == 6.0
    assert observation.failed_login_ratio == 0.5
    assert observation.distinct_ports == 2.0
    assert observation.distinct_destination_hosts == 2.0
    assert observation.distinct_users == 2.0
    assert observation.bytes_sent_total == 600.0
    assert observation.status_4xx_ratio == 0.5
    assert observation.status_5xx_ratio == 0.5
    assert observation.status_other_ratio == 0.0
    assert len(observation.to_vector()) == len(FEATURE_NAMES)
    assert observation.to_vector() == (
        6.0,
        0.5,
        2.0,
        2.0,
        2.0,
        600.0,
        0.0,
        0.0,
        0.0,
        0.5,
        0.5,
        0.0,
    )


def test_buckets_are_utc_aligned_and_separate_sources() -> None:
    events = [
        make_event(offset_seconds=60, src_ip="192.0.2.11"),
        make_event(offset_seconds=59, src_ip="192.0.2.10"),
        make_event(offset_seconds=5, src_ip="192.0.2.10"),
        replace(
            make_event(src_ip="192.0.2.10"),
            timestamp=BASE_TIME + timedelta(minutes=1) - timedelta(microseconds=1),
        ),
        replace(
            make_event(offset_seconds=60, src_ip="192.0.2.10"),
            timestamp=BASE_TIME.replace(tzinfo=None) + timedelta(minutes=1),
        ),
    ]

    observations = engineer_features(events)

    assert [
        (observation.source_ip, observation.bucket_start)
        for observation in observations
    ] == [
        ("192.0.2.10", BASE_TIME),
        ("192.0.2.10", BASE_TIME + timedelta(minutes=1)),
        ("192.0.2.11", BASE_TIME + timedelta(minutes=1)),
    ]
    assert [observation.events_per_minute for observation in observations] == [
        3.0,
        1.0,
        1.0,
    ]
    assert all(isinstance(observation, FeatureObservation) for observation in observations)


def test_unknown_sources_are_kept_separate_by_log_type_and_missing_values_are_zero() -> None:
    ssh_event = make_event(src_ip=None)
    web_event = make_event(
        src_ip=None,
        log_type="web",
        event_type="http_request",
        status=None,
    )

    observations = engineer_features([web_event, ssh_event])

    assert [observation.log_types for observation in observations] == [("ssh",), ("web",)]
    assert all(observation.source_ip is None for observation in observations)
    assert all(observation.failed_login_ratio == 0.0 for observation in observations)
    assert all(observation.bytes_sent_total == 0.0 for observation in observations)
    assert all(sum(observation.to_vector()[6:]) == 0.0 for observation in observations)


def test_http_status_classes_have_stable_distribution_slots() -> None:
    events = [
        make_event(log_type="web", event_type="http_request", status=status)
        for status in ("100", "200", "302", "404", "503", "600")
    ]

    observation = engineer_features(events)[0]

    assert observation.to_vector()[6:] == (1 / 6, 1 / 6, 1 / 6, 1 / 6, 1 / 6, 1 / 6)


def test_bucket_rate_uses_configured_bucket_length() -> None:
    events = [
        make_event(offset_seconds=1),
        make_event(offset_seconds=29),
        make_event(offset_seconds=30),
    ]

    observations = engineer_features(events, bucket_seconds=30)

    assert [item.events_per_minute for item in observations] == [4.0, 2.0]


@pytest.mark.parametrize("bucket_seconds", [0, -1, 1.5, True])
def test_bucket_length_must_be_a_positive_integer(bucket_seconds: int) -> None:
    with pytest.raises(ValueError, match="positive integer"):
        engineer_features([], bucket_seconds=bucket_seconds)
