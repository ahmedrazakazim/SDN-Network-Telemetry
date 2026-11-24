"""SDN Telemetry Anomaly Detection Subsystem.

Provides statistical anomaly detection (destination-port Shannon entropy, EWMA z-scores)
and machine learning anomaly detection (Isolation Forest on flow-level telemetry features).
"""

from detection.baseline_detector import (
    StatisticalAnomalyDetector,
    calculate_shannon_entropy,
    EWMATracker,
)
from detection.ml_detector import (
    IsolationForestAnomalyDetector,
    FEATURE_NAMES,
)
from detection.model_trainer import (
    train_baseline_model,
    build_training_and_eval_datasets,
)
from detection.evaluator import (
    run_evaluation,
    compute_metrics,
)

__all__ = [
    "StatisticalAnomalyDetector",
    "calculate_shannon_entropy",
    "EWMATracker",
    "IsolationForestAnomalyDetector",
    "FEATURE_NAMES",
    "train_baseline_model",
    "build_training_and_eval_datasets",
    "run_evaluation",
    "compute_metrics",
]
