"""Deterministic detection for suspicious authentication patterns."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Sequence
from datetime import timedelta

from loganalyzer.models import Alert, NormalizedEvent


class SuspiciousLoginDetector:
    """Detect suspicious login patterns across normalized authentication events.

    Detects:
    1. Post-burst success: A successful login immediately following multiple failed
       attempts from the same source IP.
    2. Multi-account login: A single source IP successfully logging into multiple
       distinct accounts within a short time window.
    3. Off-hours login (optional): Successful logins occurring outside configured
       business hours.
    """

    def __init__(
        self,
        post_burst_window_minutes: int = 10,
        failure_burst_threshold: int = 3,
        multi_account_threshold: int = 3,
        multi_account_window_minutes: int = 15,
        enable_off_hours: bool = False,
        normal_hours_start: int = 8,
        normal_hours_end: int = 18,
    ) -> None:
        if post_burst_window_minutes <= 0:
            raise ValueError("post_burst_window_minutes must be positive")
        if failure_burst_threshold < 1:
            raise ValueError("failure_burst_threshold must be at least 1")
        if multi_account_threshold < 1:
            raise ValueError("multi_account_threshold must be at least 1")
        if multi_account_window_minutes <= 0:
            raise ValueError("multi_account_window_minutes must be positive")
        if not (0 <= normal_hours_start < normal_hours_end <= 24):
            raise ValueError("normal hours must satisfy 0 <= start < end <= 24")

        self.post_burst_window = timedelta(minutes=post_burst_window_minutes)
        self.post_burst_window_minutes = post_burst_window_minutes
        self.failure_burst_threshold = failure_burst_threshold
        self.multi_account_threshold = multi_account_threshold
        self.multi_account_window = timedelta(minutes=multi_account_window_minutes)
        self.multi_account_window_minutes = multi_account_window_minutes
        self.enable_off_hours = enable_off_hours
        self.normal_hours_start = normal_hours_start
        self.normal_hours_end = normal_hours_end

    def detect(self, events: Iterable[NormalizedEvent]) -> Sequence[Alert]:
        auth_events = [
            event
            for event in events
            if event.event_type in {"login_success", "login_failure"} and event.src_ip
        ]
        if not auth_events:
            return []

        auth_events.sort(key=lambda event: event.timestamp)

        alerts: list[Alert] = []
        alerts.extend(self._detect_post_burst_success(auth_events))
        alerts.extend(self._detect_multi_account_logins(auth_events))
        if self.enable_off_hours:
            alerts.extend(self._detect_off_hours_logins(auth_events))

        return alerts

    def _detect_post_burst_success(
        self, auth_events: list[NormalizedEvent]
    ) -> list[Alert]:
        # Group by source IP
        by_source: defaultdict[str, list[NormalizedEvent]] = defaultdict(list)
        for event in auth_events:
            by_source[event.src_ip].append(event)

        alerts: list[Alert] = []
        for source_ip, source_events in by_source.items():
            for idx, event in enumerate(source_events):
                if event.event_type != "login_success":
                    continue

                # Find failure attempts within the rolling window prior to this success
                window_start = event.timestamp - self.post_burst_window
                prior_failures = [
                    prior
                    for prior in source_events[:idx]
                    if prior.event_type == "login_failure"
                    and window_start <= prior.timestamp <= event.timestamp
                ]

                if len(prior_failures) >= self.failure_burst_threshold:
                    time_start = prior_failures[0].timestamp
                    time_end = event.timestamp
                    observed_count = len(prior_failures)
                    severity = (
                        "CRITICAL"
                        if observed_count >= self.failure_burst_threshold * 2
                        else "HIGH"
                    )
                    username = event.user or prior_failures[-1].user
                    alerts.append(
                        Alert(
                            severity=severity,
                            title="Successful login after failure burst",
                            summary=(
                                f"A successful login for user '{username}' was observed from {source_ip} "
                                f"following {observed_count} failed authentication attempts."
                            ),
                            evidence={
                                "signal": "post_burst_success",
                                "source_ip": source_ip,
                                "username": username,
                                "failed_attempts_count": observed_count,
                                "threshold": self.failure_burst_threshold,
                                "window_minutes": self.post_burst_window_minutes,
                                "success_time": event.timestamp,
                                "first_failure_time": time_start,
                            },
                            recommended_actions=(
                                "Review recent activity for potential account compromise",
                                "Verify whether the authentication was authorized by the user",
                                "Rotate user credentials or access keys if compromised",
                                "Apply rate limiting or temporary IP blocking on repeated failures",
                            ),
                            source_ips=(source_ip,),
                            time_start=time_start,
                            time_end=time_end,
                            detector="suspicious_login",
                            confidence="high",
                        )
                    )
        return alerts

    def _detect_multi_account_logins(
        self, auth_events: list[NormalizedEvent]
    ) -> list[Alert]:
        by_source: defaultdict[str, list[NormalizedEvent]] = defaultdict(list)
        for event in auth_events:
            if event.event_type == "login_success" and event.user:
                by_source[event.src_ip].append(event)

        alerts: list[Alert] = []
        for source_ip, success_events in by_source.items():
            window_start_index = 0
            for index, event in enumerate(success_events):
                while (
                    event.timestamp - success_events[window_start_index].timestamp
                    > self.multi_account_window
                ):
                    window_start_index += 1

                window_events = success_events[window_start_index : index + 1]
                distinct_users = sorted({item.user for item in window_events if item.user})
                if len(distinct_users) >= self.multi_account_threshold:
                    time_start = window_events[0].timestamp
                    time_end = window_events[-1].timestamp
                    alerts.append(
                        Alert(
                            severity="HIGH",
                            title="Multiple account logins from single source",
                            summary=(
                                f"Source {source_ip} successfully logged into {len(distinct_users)} "
                                f"distinct accounts within {self.multi_account_window_minutes} minutes."
                            ),
                            evidence={
                                "signal": "multi_account_login",
                                "source_ip": source_ip,
                                "distinct_users_count": len(distinct_users),
                                "users": distinct_users,
                                "threshold": self.multi_account_threshold,
                                "window_minutes": self.multi_account_window_minutes,
                            },
                            recommended_actions=(
                                "Investigate source IP for potential credential stuffing or account takeover",
                                "Review access logs for all targeted user accounts",
                                "Enforce multi-factor authentication across all affected accounts",
                            ),
                            source_ips=(source_ip,),
                            time_start=time_start,
                            time_end=time_end,
                            detector="suspicious_login",
                            confidence="high",
                        )
                    )
                    break  # Alert once per source IP window
        return alerts

    def _detect_off_hours_logins(
        self, auth_events: list[NormalizedEvent]
    ) -> list[Alert]:
        alerts: list[Alert] = []
        for event in auth_events:
            if event.event_type != "login_success":
                continue

            hour = event.timestamp.hour
            is_weekend = event.timestamp.weekday() >= 5
            is_off_hours = (
                is_weekend
                or hour < self.normal_hours_start
                or hour >= self.normal_hours_end
            )

            if is_off_hours:
                alerts.append(
                    Alert(
                        severity="MEDIUM",
                        title="Off-hours login detected",
                        summary=(
                            f"User '{event.user}' logged in outside normal business hours "
                            f"from {event.src_ip}."
                        ),
                        evidence={
                            "signal": "off_hours_login",
                            "source_ip": event.src_ip,
                            "username": event.user,
                            "timestamp": event.timestamp,
                            "normal_hours": f"{self.normal_hours_start:02d}:00-{self.normal_hours_end:02d}:00",
                            "is_weekend": is_weekend,
                        },
                        recommended_actions=(
                            "Confirm with the user that the off-hours access was legitimate",
                            "Check for any abnormal activity or commands executed during this session",
                        ),
                        source_ips=(event.src_ip,),
                        time_start=event.timestamp,
                        time_end=event.timestamp,
                        detector="suspicious_login",
                        confidence="medium",
                    )
                )
        return alerts
