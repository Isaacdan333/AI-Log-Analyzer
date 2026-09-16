"""Shared data structures used across the analyzer pipeline."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True, slots=True)
class NormalizedEvent:
    """A security-relevant event represented independently of its log format."""

    timestamp: datetime
    source: str
    log_type: str
    event_type: str
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    protocol: str | None = None
    user: str | None = None
    status: str | None = None
    bytes_sent: int | None = None
    path: str | None = None
    geo: dict[str, Any] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    raw_line: str | None = None


@dataclass(frozen=True, slots=True)
class Alert:
    """A deterministic finding with structured evidence and response guidance."""

    severity: str
    title: str
    summary: str
    evidence: dict[str, Any]
    recommended_actions: tuple[str, ...]
    source_ips: tuple[str, ...] = ()
    time_start: datetime | None = None
    time_end: datetime | None = None
    detector: str = ""
    confidence: str | None = None
