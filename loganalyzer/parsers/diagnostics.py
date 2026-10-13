"""Parser-local diagnostics that the engine can attach to a source file."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ParseDiagnostic:
    line_number: int
    message: str