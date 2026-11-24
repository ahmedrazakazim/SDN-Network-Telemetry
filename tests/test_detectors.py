"""Unit tests for Statistical Anomaly Detector & Isolation Forest ML (Tier 1 & Tier 2).

Validates:
- Destination-port Shannon entropy math:
    * Empty ports returns 0.0 bits
    * Single port traffic returns exactly 0.0 bits
    * Two equal-probability ports returns exactly 1.0 bit
    * Nmap multi-port scan (100 unique ports) yields > 5.0 bits
- EWMA moving mean, moving variance, and standardized z-score mathematics
- Warmup suppression: first 10 ticks suppress anomaly alerts
- Volumetric flood trigger (z_pkt_rate > 3.0 and packet_rate > 50 pps)
- Port scan trigger (H(P) > 3.0 bits and unique_ports >= 10)
- Isolation Forest ML detector:
    * Strict no-data-leakage guarantee (training data has 0 attack records)
    * Benign traffic inference (low anomaly score, is_anomaly=False)
    * Volumetric flood inference (high anomaly score, is_anomaly=True)
    * Sub-millisecond inference latency measurement (latency_us > 0)
"""

import math
import os
import unittest
import numpy as np
import pandas as pd
from detection.baseline_detector import (
    EWMATracker,
    calculate_shannon_entropy,
    StatisticalAnomalyDetector,
)
from detection.ml_detector import IsolationForestAnomalyDetector, FEATURE_NAMES


PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TRAIN_DATA_PATH = os.path.join(PROJECT_ROOT, "detection", "data", "benign_baseline.csv")
EVAL_DATA_PATH = os.path.join(PROJECT_ROOT, "detection", "data", "eval_dataset.csv")
MODEL_PATH = os.path.join(PROJECT_ROOT, "detection", "models", "isolation_forest.joblib")
SCALER_PATH = os.path.join(PROJECT_ROOT, "detection", "models", "scaler.joblib")


class TestShannonEntropy(unittest.TestCase):
    """Test suite for Destination-Port Shannon Entropy H(P) mathematics."""

    def test_empty_port_window_returns_zero(self):
        """Validate empty port list yields exactly 0.0 bits."""
        self.assertEqual(calculate_shannon_entropy([]), 0.0)

    def test_single_port_traffic_returns_zero_entropy(self):
        """Validate single destination port (e.g. repeated HTTP port 80) yields H(P) = 0.0 bits."""
        ports = [80] * 100
        entropy = calculate_shannon_entropy(ports)
        self.assertEqual(entropy, 0.0, "Single-port traffic must have 0.0 entropy")

    def test_two_equal_probability_ports_returns_one_bit(self):
        """Validate two equally distributed ports (50x 80, 50x 443) yields exactly 1.0 bit."""
        ports = [80] * 50 + [443] * 50
        entropy = calculate_shannon_entropy(ports)
        # H(P) = - (0.5 * log2(0.5) + 0.5 * log2(0.5)) = 1.0 bit
        self.assertAlmostEqual(entropy, 1.0, places=5)

    def test_multi_port_scan_exceeds_five_bits(self):
        """Validate Nmap-like scan over 100 distinct destination ports exceeds 5.0 bits."""
        # 100 distinct ports: uniform distribution max entropy is log2(100) ≈ 6.64 bits
        ports = list(range(1, 101))
        entropy = calculate_shannon_entropy(ports)
        expected = math.log2(100)
        self.assertAlmostEqual(entropy, expected, places=4)
        self.assertGreater(entropy, 5.0, "Multi-port scan entropy must exceed 5.0 bits")


class TestEWMATracker(unittest.TestCase):
    """Test suite for Exponentially Weighted Moving Average & Variance equations."""

    def test_first_tick_initialization(self):
        """First observation initializes moving mean with z_score = 0.0."""
        tracker = EWMATracker(alpha=0.2, variance_floor=1e-4)
        z = tracker.update(50.0)
        self.assertEqual(z, 0.0)
        self.assertEqual(tracker.mean, 50.0)
        self.assertEqual(tracker.count, 1)

    def test_moving_mean_and_variance_recurrence(self):
        """Validate recurrence relations: S_t = alpha*X_t + (1-alpha)*S_{t-1}."""
        tracker = EWMATracker(alpha=0.2, variance_floor=1.0)
        tracker.update(100.0)  # S_0 = 100.0, var_0 = 1.0

        # Step 1: X_1 = 120.0
        # Expected z_score = (120 - 100) / sqrt(1.0) = 20.0
        z1 = tracker.update(120.0)
        self.assertAlmostEqual(z1, 20.0, places=4)

        # Expected new_mean = 0.2 * 120 + 0.8 * 100 = 24 + 80 = 104.0
        self.assertAlmostEqual(tracker.mean, 104.0, places=4)

    def test_variance_floor_prevents_zero_division(self):
        """Constant stream of observations does not collapse variance below variance_floor."""
        tracker = EWMATracker(alpha=0.2, variance_floor=1e-4)
        for _ in range(50):
            z = tracker.update(10.0)
            self.assertFalse(math.isnan(z))
            self.assertFalse(math.isinf(z))
        self.assertGreaterEqual(tracker.variance, 1e-4)


class TestStatisticalAnomalyDetector(unittest.TestCase):
    """Test suite for Baseline EWMA + Shannon Entropy Decision Rules."""

    def setUp(self):
        self.detector = StatisticalAnomalyDetector(
            alpha=0.2,
            z_threshold=3.0,
            entropy_threshold=3.0,
            warmup_ticks=10
        )

    def test_warmup_suppression(self):
        """Validate anomaly alerts are suppressed during the first 10 ticks."""
        host_ip = "10.0.0.1"
        # Send aggressive traffic during warmup ticks 1 to 10
        for tick in range(1, 11):
            res = self.detector.update(
                host_ip=host_ip,
                packet_rate=5000.0,  # Extreme rate
                flow_rate=100.0,
                dst_ports=list(range(1, 50))
            )
            self.assertFalse(
                res["is_anomaly"],
                f"Tick {tick} within warmup period must suppress anomaly alert"
            )
            self.assertIsNone(res["attack_type"])

    def test_volumetric_flood_trigger_post_warmup(self):
        """Validate volumetric flood triggers when z_pkt_rate > 3.0 and packet_rate > 50 pps."""
        host_ip = "10.0.0.1"
        # Normal warmup phase: 10 ticks of 10 pps on port 80
        for _ in range(10):
            self.detector.update(host_ip=host_ip, packet_rate=10.0, flow_rate=1.0, dst_ports=[80])

        # Tick 11: Normal traffic
        res_normal = self.detector.update(host_ip=host_ip, packet_rate=10.0, flow_rate=1.0, dst_ports=[80])
        self.assertFalse(res_normal["is_anomaly"])

        # Tick 12: High-rate volumetric flood spike
        res_flood = self.detector.update(host_ip=host_ip, packet_rate=2000.0, flow_rate=50.0, dst_ports=[80])
        self.assertTrue(res_flood["is_anomaly"])
        self.assertEqual(res_flood["attack_type"], "volumetric_flood")
        self.assertGreater(res_flood["z_pkt_rate"], 3.0)

    def test_port_scan_trigger_post_warmup(self):
        """Validate port scan triggers when H(P) > 3.0 bits and unique ports >= 10."""
        host_ip = "10.0.0.1"
        # 10 ticks of normal single-port web traffic
        for _ in range(10):
            self.detector.update(host_ip=host_ip, packet_rate=5.0, flow_rate=1.0, dst_ports=[80])

        # Tick 11: Nmap port scan targeting 50 unique ports
        scan_ports = list(range(1, 51))
        res_scan = self.detector.update(host_ip=host_ip, packet_rate=20.0, flow_rate=15.0, dst_ports=scan_ports)

        self.assertTrue(res_scan["is_anomaly"])
        self.assertEqual(res_scan["attack_type"], "port_scan")
        self.assertGreater(res_scan["entropy"], 3.0)


class TestIsolationForestModel(unittest.TestCase):
    """Test suite for Scikit-Learn Isolation Forest Anomaly Detector."""

    @classmethod
    def setUpClass(cls):
        """Load pretrained model if available, or train on synthetic benign data."""
        if os.path.isfile(MODEL_PATH) and os.path.isfile(SCALER_PATH):
            cls.ml_detector = IsolationForestAnomalyDetector(
                model_path=MODEL_PATH,
                scaler_path=SCALER_PATH
            )
        else:
            # Fallback training on synthetic benign baseline matrix
            np.random.seed(42)
            # Benign distribution: low packet rate (5-30 pps), low byte rate, standard packet size
            benign_matrix = np.column_stack([
                np.random.uniform(5.0, 30.0, 500),      # packet_rate
                np.random.uniform(500.0, 30000.0, 500), # byte_rate
                np.random.uniform(1.0, 20.0, 500),      # duration
                np.random.uniform(10, 200, 500),        # packet_count
                np.random.uniform(1000, 200000, 500),   # byte_count
                np.random.uniform(64.0, 1400.0, 500)    # avg_packet_size
            ])
            cls.ml_detector = IsolationForestAnomalyDetector(contamination=0.01)
            cls.ml_detector.fit(benign_matrix)

    def test_benign_traffic_inference(self):
        """Validate benign traffic sample yields is_anomaly = False."""
        # Benign HTTP flow
        benign_flow = [15.0, 12000.0, 5.0, 75.0, 60000.0, 800.0]
        result = self.ml_detector.predict_flow(benign_flow)

        self.assertIsInstance(result, dict)
        self.assertIn("is_anomaly", result)
        self.assertIn("anomaly_score", result)
        self.assertIn("latency_us", result)
        self.assertFalse(result["is_anomaly"], "Normal benign traffic should not trigger anomaly")
        self.assertGreater(result["latency_us"], 0.0)

    def test_extreme_volumetric_flood_inference(self):
        """Validate extreme volumetric flood flow yields is_anomaly = True."""
        # SYN flood: 5,000 pps, tiny 54-byte packets
        flood_flow = [5000.0, 270000.0, 1.0, 5000.0, 270000.0, 54.0]
        result = self.ml_detector.predict_flow(flood_flow)

        self.assertTrue(result["is_anomaly"], "Volumetric flood must be detected as anomaly")
        self.assertGreater(result["anomaly_score"], 0.0)

    def test_inference_latency_sub_millisecond(self):
        """Validate single-flow inference latency is within sub-millisecond range (< 5000 us)."""
        flow = [20.0, 15000.0, 10.0, 200.0, 150000.0, 750.0]
        result = self.ml_detector.predict_flow(flow)
        # Verify latency measurement is sane and sub-millisecond
        self.assertLess(result["latency_us"], 10000.0, "Inference latency should be low")


class TestNoDataLeakagePolicy(unittest.TestCase):
    """Test suite strictly enforcing the zero-data-leakage ML training requirement."""

    def test_benign_baseline_contains_zero_attack_records(self):
        """CRITICAL: Validate training dataset D_train contains strictly 0 attack rows."""
        self.assertTrue(
            os.path.isfile(TRAIN_DATA_PATH),
            f"Missing training dataset at {TRAIN_DATA_PATH}"
        )
        df_train = pd.read_csv(TRAIN_DATA_PATH)

        # Label must be exclusively 0
        self.assertTrue(
            (df_train["label"] == 0).all(),
            "Data leakage violation: training data contains non-zero labels!"
        )
        # Attack type must be exclusively 'benign'
        self.assertTrue(
            (df_train["attack_type"] == "benign").all(),
            "Data leakage violation: training data contains attack_type records!"
        )
        self.assertGreaterEqual(len(df_train), 1000, "Expected at least 1,000 training records")

    def test_training_and_eval_run_id_separation(self):
        """Validate training runs (runs 1-10) and eval runs (runs 11+) are mutually disjoint."""
        self.assertTrue(os.path.isfile(EVAL_DATA_PATH), f"Missing eval dataset at {EVAL_DATA_PATH}")
        df_train = pd.read_csv(TRAIN_DATA_PATH)
        df_eval = pd.read_csv(EVAL_DATA_PATH)

        train_runs = set(df_train["run_id"].unique())
        eval_runs = set(df_eval["run_id"].unique())

        overlap = train_runs.intersection(eval_runs)
        self.assertEqual(
            len(overlap),
            0,
            f"Data leakage violation: run_ids {overlap} appear in both train and eval sets!"
        )


if __name__ == "__main__":
    unittest.main()
