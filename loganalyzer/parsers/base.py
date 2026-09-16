"""Interfaces shared by log parsers."""

from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Protocol

from loganalyzer.models import NormalizedEvent


class LogParser(Protocol):
    """Minimal interface implemented by each log parser."""

    def parse_lines(
        self, lines: Iterable[str], source: str = "<memory>"
    ) -> Sequence[NormalizedEvent]:
        """Parse input lines into normalized events."""
        ...

    def parse_file(self, path: Path) -> Sequence[NormalizedEvent]:
        """Parse a UTF-8 text log file into normalized events."""
        ...
