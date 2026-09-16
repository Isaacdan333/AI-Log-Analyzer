"""Interfaces shared by event detectors."""

from collections.abc import Iterable, Sequence
from typing import Protocol

from loganalyzer.models import Alert, NormalizedEvent


class Detector(Protocol):
    """Minimal interface implemented by each detector."""

    def detect(self, events: Iterable[NormalizedEvent]) -> Sequence[Alert]:
        """Analyze normalized events and return structured alerts."""
        ...
