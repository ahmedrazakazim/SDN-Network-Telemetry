#!/usr/bin/env python3
"""Machine-Learning Anomaly Detector using Scikit-Learn Isolation Forest.

Features:
- Operates on 6 flow-level features:
  [packet_rate, byte_rate, duration, packet_count, byte_count, average_packet_size]
- Strict benign-only training baseline with standard feature scaling.
- Single-sample flow inference with sub-millisecond latency tracking.
- Serialization support via joblib for reproducible production deployment.
"""

import os
import time
from typing import Any, Dict, List, Optional, Union

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


FEATURE_NAMES = [
    "packet_rate",
    "byte_rate",
    "duration",
    "packet_count",
    "byte_count",
    "average_packet_size",
]


class IsolationForestAnomalyDetector:
    """Anomaly detector wrapping scikit-learn's IsolationForest for SDN telemetry flows.

    Interface conforms to PROJECT.md Contract 3:
    - fit(benign_feature_matrix: np.ndarray) -> None
    - predict_flow(feature_vector: list) -> dict:
        {'is_anomaly': bool, 'anomaly_score': float, 'latency_us': float}
    - save(path: str, scaler_path: Optional[str] = None)
    - load(path: str, scaler_path: Optional[str] = None)
    """

    def __init__(
        self,
        model_path: Optional[str] = None,
        scaler_path: Optional[str] = None,
        contamination: float = 0.01,
        n_estimators: int = 100,
        random_state: int = 42,
    ):
        self.contamination = float(contamination)
        self.n_estimators = int(n_estimators)
        self.random_state = int(random_state)
        self.feature_names = list(FEATURE_NAMES)

        self.model: Optional[IsolationForest] = None
        self.scaler: Optional[StandardScaler] = None
        self.is_fitted: bool = False

        if model_path is not None:
            self.load(model_path, scaler_path)
        else:
            self.model = IsolationForest(
                n_estimators=self.n_estimators,
                contamination=self.contamination,
                random_state=self.random_state,
                n_jobs=-1,
            )
            self.scaler = StandardScaler()

    def fit(
        self,
        benign_feature_matrix: Union[List[List[float]], np.ndarray],
        fit_scaler: bool = True,
    ) -> "IsolationForestAnomalyDetector":
        """Fit Isolation Forest strictly on benign baseline data.

        Args:
            benign_feature_matrix: Array-like of shape (N, 6) with benign flows.
            fit_scaler: Whether to fit StandardScaler on the benign data.

        Returns:
            self
        """
        X = np.asarray(benign_feature_matrix, dtype=np.float64)
        if X.ndim == 1:
            X = X.reshape(1, -1)

        if X.shape[1] != len(self.feature_names):
            raise ValueError(
                f"Expected feature matrix with {len(self.feature_names)} features, got {X.shape[1]}"
            )

        if self.scaler is None:
            self.scaler = StandardScaler()

        if fit_scaler:
            X_scaled = self.scaler.fit_transform(X)
        else:
            X_scaled = self.scaler.transform(X)

        if self.model is None:
            self.model = IsolationForest(
                n_estimators=self.n_estimators,
                contamination=self.contamination,
                random_state=self.random_state,
                n_jobs=-1,
            )

        self.model.fit(X_scaled)
        self.is_fitted = True
        return self

    def _extract_feature_vector(
        self, feature_input: Union[List[float], np.ndarray, Dict[str, Any]]
    ) -> np.ndarray:
        """Parse raw feature input (list, dict, or numpy array) into standardized 1x6 vector."""
        if isinstance(feature_input, dict):
            # Extract features by name, allowing 'avg_packet_size' alias
            avg_size = feature_input.get("average_packet_size")
            if avg_size is None:
                avg_size = feature_input.get("avg_packet_size", 0.0)

            vector = [
                float(feature_input.get("packet_rate", 0.0)),
                float(feature_input.get("byte_rate", 0.0)),
                float(feature_input.get("duration", feature_input.get("duration_sec", 0.0))),
                float(feature_input.get("packet_count", 0.0)),
                float(feature_input.get("byte_count", 0.0)),
                float(avg_size),
            ]
            return np.array(vector, dtype=np.float64).reshape(1, -1)

        arr = np.asarray(feature_input, dtype=np.float64)
        if arr.ndim == 1:
            if arr.shape[0] != len(self.feature_names):
                raise ValueError(
                    f"Expected vector of length {len(self.feature_names)}, got {arr.shape[0]}"
                )
            return arr.reshape(1, -1)
        elif arr.ndim == 2:
            if arr.shape[1] != len(self.feature_names):
                raise ValueError(
                    f"Expected 2D array with {len(self.feature_names)} columns, got {arr.shape[1]}"
                )
            return arr
        else:
            raise ValueError(f"Invalid input dimensions: {arr.ndim}")

    def predict_flow(
        self, feature_vector: Union[List[float], np.ndarray, Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Perform real-time anomaly inference on a single network flow.

        Args:
            feature_vector: List or dict with 6 flow features:
                [packet_rate, byte_rate, duration, packet_count, byte_count, average_packet_size]

        Returns:
            dict containing:
            {
                'is_anomaly': bool,
                'anomaly_score': float,  # Higher score indicates stronger anomaly
                'latency_us': float      # Inference latency in microseconds
            }
        """
        if not self.is_fitted or self.model is None:
            raise RuntimeError("IsolationForestAnomalyDetector has not been fitted or loaded.")

        x = self._extract_feature_vector(feature_vector)

        t_start = time.perf_counter()

        # Scale features if scaler is present
        if self.scaler is not None:
            x_scaled = self.scaler.transform(x)
        else:
            x_scaled = x

        # decision_function returns negative values for anomalies, positive for normal.
        # Calling decision_function directly avoids traversing all trees twice.
        dec_func = float(self.model.decision_function(x_scaled)[0])
        anomaly_score = -dec_func
        is_anomaly = bool(dec_func < 0.0)

        t_end = time.perf_counter()
        latency_us = float((t_end - t_start) * 1_000_000.0)

        return {
            "is_anomaly": is_anomaly,
            "anomaly_score": round(anomaly_score, 6),
            "latency_us": round(latency_us, 2),
        }

    def predict_batch(
        self, feature_matrix: Union[List[List[float]], np.ndarray]
    ) -> List[Dict[str, Any]]:
        """Perform anomaly inference across a batch of flow vectors."""
        X = np.asarray(feature_matrix, dtype=np.float64)
        if X.ndim == 1:
            X = X.reshape(1, -1)

        results = []
        for row in X:
            results.append(self.predict_flow(row))
        return results

    def save(self, model_path: str, scaler_path: Optional[str] = None):
        """Serialize trained Isolation Forest model and standard scaler.

        Args:
            model_path: File path to save the IsolationForest model.
            scaler_path: Optional file path to save the StandardScaler. If None,
                         defaults to 'scaler.joblib' in the same directory.
        """
        os.makedirs(os.path.dirname(os.path.abspath(model_path)), exist_ok=True)

        joblib.dump(self.model, model_path)

        if scaler_path is None:
            model_dir = os.path.dirname(os.path.abspath(model_path))
            scaler_path = os.path.join(model_dir, "scaler.joblib")

        os.makedirs(os.path.dirname(os.path.abspath(scaler_path)), exist_ok=True)
        joblib.dump(self.scaler, scaler_path)

    def load(self, model_path: str, scaler_path: Optional[str] = None):
        """Deserialize trained Isolation Forest model and standard scaler.

        Args:
            model_path: File path to load the IsolationForest model from.
            scaler_path: Optional file path to load the StandardScaler. If None,
                         checks for 'scaler.joblib' in the model's directory.
        """
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model file not found at {model_path}")

        loaded_obj = joblib.load(model_path)
        if isinstance(loaded_obj, dict) and "model" in loaded_obj:
            self.model = loaded_obj["model"]
            self.scaler = loaded_obj.get("scaler", StandardScaler())
        else:
            self.model = loaded_obj
            if scaler_path is None:
                model_dir = os.path.dirname(os.path.abspath(model_path))
                candidate_scaler = os.path.join(model_dir, "scaler.joblib")
                if os.path.exists(candidate_scaler):
                    scaler_path = candidate_scaler

            if scaler_path and os.path.exists(scaler_path):
                self.scaler = joblib.load(scaler_path)
            else:
                self.scaler = None

        self.is_fitted = True
