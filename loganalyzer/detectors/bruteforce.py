"""Deterministic rolling-window brute-force detection."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Sequence
from datetime import datetime, timedelta

from loganalyzer.models import Alert, NormalizedEvent


class BruteForceDetector:
    """Detect repeated failed SSH authentication from a source and user."""

    def __init__(self, threshold: int = 5, window_minutes: int = 5) -> None:
        if threshold < 1:
            raise ValueError("threshold must be at least 1")
        if window_minutes <= 0:
            raise ValueError("window_minutes must be positive")
        self.threshold = threshold
        self.window = timedelta(minutes=window_minutes)

    def detect(self, events: Iterable[NormalizedEvent]) -> Sequence[Alert]:
        grouped: defaultdict[tuple[str, str | None], list[NormalizedEvent]] = defaultdict(list)
        for event in events:
            if (
                event.log_type == "ssh"
                and event.event_type == "login_failure"
                and event.status == "failure"
                and event.src_ip
            ):
                grouped[(event.src_ip, event.user)].append(event)

        alerts: list[Alert] = []
        for (source_ip, username), attempts in grouped.items():
            attempts.sort(key=lambda event: event.timestamp)
            window_start_index = 0
            for index, attempt in enumerate(attempts):
                while attempt.timestamp - attempts[window_start_index].timestamp > self.window:
                    window_start_index += 1
                observed_count = index - window_start_index + 1
                if observed_count >= self.threshold:
                    window_events = attempts[window_start_index : index + 1]
                    time_start = window_events[0].timestamp
                    time_end = window_events[-1].timestamp
                    severity = "CRITICAL" if observed_count >= self.threshold * 2 else "HIGH"
                    alerts.append(
                        Alert(
                            severity=severity,
                            title="Potential brute-force attack detected",
                            summary=(
                                f"{observed_count} failed SSH login attempts were observed "
                                f"from {source_ip}."
                            ),
                            evidence={
                                "observed_count": observed_count,
                                "threshold": self.threshold,
                                "source_ip": source_ip,
                                "username": username,
                                "window_minutes": self.window.total_seconds() / 60,
                                "window_start": time_start,
                                "window_end": time_end,
                            },
                            recommended_actions=(
                                "Review successful logins from this source",
                                "Apply an appropriate network block or rate limit after review",
                                "Prefer key-based authentication over passwords",
                            ),
                            source_ips=(source_ip,),
                            time_start=time_start,
                            time_end=time_end,
                            detector="brute_force",
                            confidence="high",
                        )
                    )
                    break
        return alerts
