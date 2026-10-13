"""Operational limits for untrusted input files."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class InputLimits:
    """Conservative limits that still accommodate ordinary exported logs."""

    max_file_size_bytes: int = 50 * 1024 * 1024
    max_line_length: int = 1024 * 1024

    def __post_init__(self) -> None:
        if self.max_file_size_bytes < 1:
            raise ValueError("max_file_size_bytes must be positive")
        if self.max_line_length < 1:
            raise ValueError("max_line_length must be positive")