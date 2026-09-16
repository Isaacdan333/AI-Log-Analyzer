"""Deterministic rolling-window port-scan detection."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Sequence
from datetime import timedelta

from loganalyzer.models import Alert, NormalizedEvent


class PortScanDetector:
    """Detect many destination ports contacted by one source in a short window."""

    def __init__(
        self,
        window_seconds: int = 60,
        medium_ports: int = 10,
        high_ports: int = 25,
        critical_ports: int = 50,
        critical_hosts: int = 2,
        critical_denied_ratio: float = 0.8,
    ) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if not 1 <= medium_ports <= high_ports <= critical_ports:
            raise ValueError("port thresholds must be positive and ordered")
        if critical_hosts < 1:
            raise ValueError("critical_hosts must be positive")
        if not 0 <= critical_denied_ratio <= 1:
            raise ValueError("critical_denied_ratio must be between 0 and 1")

        self.window = timedelta(seconds=window_seconds)
        self.window_seconds = window_seconds
        self.medium_ports = medium_ports
        self.high_ports = high_ports
        self.critical_ports = critical_ports
        self.critical_hosts = critical_hosts
        self.critical_denied_ratio = critical_denied_ratio

    def detect(self, events: Iterable[NormalizedEvent]) -> Sequence[Alert]:
        grouped: defaultdict[str, list[NormalizedEvent]] = defaultdict(list)
        for event in events:
            if (
                event.log_type == "firewall"
                and event.event_type == "network_connection"
                and event.src_ip
                and event.dst_port is not None
            ):
                grouped[event.src_ip].append(event)

        alerts: list[Alert] = []
        for source_ip, source_events in grouped.items():
            source_events.sort(key=lambda event: event.timestamp)
            window_start_index = 0
            best_alert: Alert | None = None
            for index, event in enumerate(source_events):
                while (
                    event.timestamp - source_events[window_start_index].timestamp
                    > self.window
                ):
                    window_start_index += 1

                window_events = source_events[window_start_index : index + 1]
                distinct_ports = {item.dst_port for item in window_events}
                if len(distinct_ports) < self.medium_ports:
                    continue

                distinct_hosts = {item.dst_ip for item in window_events if item.dst_ip}
                accepted_count = sum(item.status == "accepted" for item in window_events)
                denied_count = sum(
                    item.status in {"denied", "rejected", "dropped"}
                    for item in window_events
                )
                denied_ratio = denied_count / len(window_events)

                if (
                    len(distinct_ports) >= self.critical_ports
                    and len(distinct_hosts) >= self.critical_hosts
                    and denied_ratio >= self.critical_denied_ratio
                ):
                    severity = "CRITICAL"
                    threshold = "critical"
                elif len(distinct_ports) >= self.high_ports:
                    severity = "HIGH"
                    threshold = "high"
                else:
                    severity = "MEDIUM"
                    threshold = "medium"

                time_start = window_events[0].timestamp
                time_end = window_events[-1].timestamp
                candidate = Alert(
                        severity=severity,
                        title="Potential port scan detected",
                        summary=(
                            f"{len(distinct_ports)} distinct destination ports were "
                            f"contacted by {source_ip}."
                        ),
                        evidence={
                            "source_ip": source_ip,
                            "distinct_destination_ports": len(distinct_ports),
                            "distinct_destination_hosts": len(distinct_hosts),
                            "time_start": time_start,
                            "time_end": time_end,
                            "accepted_count": accepted_count,
                            "denied_rejected_count": denied_count,
                            "denied_ratio": denied_ratio,
                            "threshold_crossed": threshold,
                            "window_seconds": self.window_seconds,
                        },
                        recommended_actions=(
                            "Review the source activity and affected destination hosts",
                            "Apply an appropriate network block or rate limit after review",
                        ),
                        source_ips=(source_ip,),
                        time_start=time_start,
                        time_end=time_end,
                        detector="port_scan",
                        confidence="high",
                    )
                severity_rank = {"MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
                if best_alert is None or severity_rank[candidate.severity] > severity_rank[best_alert.severity]:
                    best_alert = candidate

            if best_alert is not None:
                alerts.append(best_alert)

        return alerts