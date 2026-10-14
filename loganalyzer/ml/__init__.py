"""Optional machine-learning analysis components.

Names are resolved lazily so importing ``loganalyzer.ml.workflow`` does not
require scikit-learn until a model is actually requested.
"""

from __future__ import annotations

from importlib import import_module
from typing import Any

_MODEL_EXPORTS = (
    "FeatureReference",
    "IsolationForestAnomalyDetector",
    "IsolationForestMetadata",
    "IsolationForestSettings",
    "MLAnomalyFinding",
)

__all__ = _MODEL_EXPORTS


def __getattr__(name: str) -> Any:
    if name in _MODEL_EXPORTS:
        return getattr(import_module("loganalyzer.ml.isolation_forest"), name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
