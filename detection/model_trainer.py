#!/usr/bin/env python3
"""Model Trainer for SDN Network Anomaly Detection.

Implements a STRICT NO-DATA-LEAKAGE POLICY:
1. Generates benign baseline training data (D_train) representing 10 normal
   traffic runs covering HTTP, TCP bulk transfer, UDP streaming/DNS, and ICMP.
2. Fits StandardScaler strictly on D_train only.
3. Fits IsolationForest strictly on scaled D_train only (zero attack data seen during training).
4. Serializes trained Isolation Forest and StandardScaler to:
   - detection/models/isolation_forest.joblib
   - detection/models/scaler.joblib
5. Prepares separate held-out evaluation dataset (D_eval) containing both unseen benign
   traffic runs and simulated attack flows (SYN flood, UDP flood, Nmap port scan).
6. Saves datasets to:
   - detection/data/benign_baseline.csv
   - detection/data/eval_dataset.csv
"""

import os
import sys

# Ensure cn-project workspace root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from typing import Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

try:
    from detection.ml_detector import FEATURE_NAMES, IsolationForestAnomalyDetector
except ImportError:
    from ml_detector import FEATURE_NAMES, IsolationForestAnomalyDetector


BENIGN_HOSTS = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]


def generate_benign_flows(
    run_id: int,
    num_samples: int = 200,
    random_state: Optional[int] = None,
) -> pd.DataFrame:
    """Generate realistic benign SDN network flows for a specific normal run.

    Traffic mix per run:
    - 40% HTTP/HTTPS web traffic (ports 80, 443)
    - 25% TCP bulk data / iperf transfers (ports 5001, 5201, 8080)
    - 20% UDP streaming / DNS lookups (ports 53, 5001)
    - 15% ICMP diagnostic pings (port 0)
    """
    rng = np.random.RandomState(random_state)
    rows: List[Dict] = []

    for _ in range(num_samples):
        host_ip = rng.choice(BENIGN_HOSTS)
        proto_choice = rng.choice(["http", "tcp_bulk", "udp", "icmp"], p=[0.40, 0.25, 0.20, 0.15])

        if proto_choice == "http":
            dst_port = int(rng.choice([80, 443, 8080]))
            packet_rate = float(np.clip(rng.normal(14.0, 4.0), 1.0, 35.0))
            duration = float(np.clip(rng.exponential(scale=6.0), 0.5, 30.0))
            avg_packet_size = float(np.clip(rng.normal(850.0, 180.0), 200.0, 1460.0))
            packet_count = max(1, int(packet_rate * duration))
            byte_count = int(packet_count * avg_packet_size)
            byte_rate = float(byte_count / duration)

        elif proto_choice == "tcp_bulk":
            dst_port = int(rng.choice([5001, 5201]))
            packet_rate = float(np.clip(rng.normal(28.0, 5.0), 10.0, 48.0))
            duration = float(np.clip(rng.uniform(5.0, 40.0), 2.0, 60.0))
            avg_packet_size = float(np.clip(rng.normal(1200.0, 120.0), 800.0, 1500.0))
            packet_count = max(10, int(packet_rate * duration))
            byte_count = int(packet_count * avg_packet_size)
            byte_rate = float(byte_count / duration)

        elif proto_choice == "udp":
            dst_port = int(rng.choice([53, 5001, 123]))
            packet_rate = float(np.clip(rng.normal(8.0, 2.5), 1.0, 20.0))
            duration = float(np.clip(rng.uniform(1.0, 15.0), 0.5, 25.0))
            avg_packet_size = float(np.clip(rng.normal(220.0, 60.0), 64.0, 512.0))
            packet_count = max(1, int(packet_rate * duration))
            byte_count = int(packet_count * avg_packet_size)
            byte_rate = float(byte_count / duration)

        else:  # icmp
            dst_port = 0
            packet_rate = 1.0  # standard 1 pkt/sec ping
            duration = float(np.clip(rng.uniform(3.0, 20.0), 1.0, 30.0))
            avg_packet_size = 84.0  # standard ping (64 payload + 20 IP header)
            packet_count = max(1, int(round(packet_rate * duration)))
            byte_count = int(packet_count * avg_packet_size)
            byte_rate = float(avg_packet_size * packet_rate)

        rows.append({
            "run_id": int(run_id),
            "host_ip": host_ip,
            "dst_port": dst_port,
            "packet_rate": round(packet_rate, 4),
            "byte_rate": round(byte_rate, 4),
            "duration": round(duration, 4),
            "packet_count": int(packet_count),
            "byte_count": int(byte_count),
            "average_packet_size": round(avg_packet_size, 4),
            "label": 0,
            "attack_type": "benign",
        })

    return pd.DataFrame(rows)


def generate_attack_flows(
    run_id: int,
    attack_type: str,
    rate_intensity: str = "medium",
    num_samples: int = 120,
    random_state: Optional[int] = None,
) -> pd.DataFrame:
    """Generate realistic SDN attack flows for evaluation benchmarking.

    Attacks:
    - SYN flood (low, medium, high rate): small TCP SYN packets (54-60 bytes)
    - UDP flood (low, medium, high rate): fixed payload UDP flood (512-1024 bytes)
    - Port scan: low packet count per flow (1-2 pkts), high diversity across ports 1-1024
    """
    rng = np.random.RandomState(random_state)
    rows: List[Dict] = []
    attacker_ip = "10.0.0.1"
    victim_ip = "10.0.0.2"

    for _ in range(num_samples):
        if attack_type == "syn_flood":
            dst_port = 80  # targeted victim web service
            avg_packet_size = float(rng.choice([54.0, 60.0]))  # bare TCP SYN headers
            if rate_intensity == "low":
                packet_rate = float(np.clip(rng.normal(100.0, 10.0), 80.0, 150.0))
            elif rate_intensity == "medium":
                packet_rate = float(np.clip(rng.normal(1000.0, 80.0), 800.0, 1300.0))
            else:  # high
                packet_rate = float(np.clip(rng.normal(5000.0, 400.0), 4000.0, 7000.0))

            duration = float(np.clip(rng.uniform(10.0, 30.0), 5.0, 30.0))
            packet_count = int(packet_rate * duration)
            byte_count = int(packet_count * avg_packet_size)
            byte_rate = float(packet_rate * avg_packet_size)

        elif attack_type == "udp_flood":
            dst_port = 5001  # UDP victim port
            if rate_intensity == "low":
                packet_rate = float(np.clip(rng.normal(100.0, 12.0), 80.0, 140.0))
                avg_packet_size = 512.0
            elif rate_intensity == "medium":
                packet_rate = float(np.clip(rng.normal(1000.0, 70.0), 850.0, 1250.0))
                avg_packet_size = 512.0
            else:  # high
                packet_rate = float(np.clip(rng.normal(4000.0, 300.0), 3000.0, 6000.0))
                avg_packet_size = 1024.0

            duration = float(np.clip(rng.uniform(10.0, 30.0), 5.0, 30.0))
            packet_count = int(packet_rate * duration)
            byte_count = int(packet_count * avg_packet_size)
            byte_rate = float(packet_rate * avg_packet_size)

        elif attack_type == "port_scan":
            # Multi-port reconnaissance targeting ports 1-1024 (Nmap -T4 probe burst)
            dst_port = int(rng.randint(1, 1025))
            duration = float(np.clip(rng.uniform(0.01, 0.05), 0.005, 0.1))
            packet_count = int(rng.choice([1, 2]))
            avg_packet_size = float(rng.choice([40.0, 44.0]))  # Bare TCP SYN headers
            byte_count = int(packet_count * avg_packet_size)
            # Active probe burst rate in Nmap -T4 is 60 - 200 pps
            packet_rate = float(np.clip(rng.normal(110.0, 20.0), 60.0, 200.0))
            byte_rate = float(packet_rate * avg_packet_size)

        else:
            raise ValueError(f"Unknown attack type: {attack_type}")

        rows.append({
            "run_id": int(run_id),
            "host_ip": attacker_ip,
            "dst_port": dst_port,
            "packet_rate": round(packet_rate, 4),
            "byte_rate": round(byte_rate, 4),
            "duration": round(duration, 4),
            "packet_count": int(packet_count),
            "byte_count": int(byte_count),
            "average_packet_size": round(avg_packet_size, 4),
            "label": 1,
            "attack_type": attack_type,
        })

    return pd.DataFrame(rows)


def build_training_and_eval_datasets(
    num_train_runs: int = 10,
    samples_per_run: int = 200,
    base_seed: int = 1000,
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Generate D_train (10 benign runs) and held-out D_eval with ZERO data leakage.

    Guarantees:
    - D_train contains ONLY benign flows (label=0, attack_type='benign').
    - D_eval uses completely separate seeds, run IDs, and contains both unseen benign
      traffic and simulated attack scenarios (SYN flood, UDP flood, port scan).
    """
    train_dfs: List[pd.DataFrame] = []

    # 1. Build D_train across 10 normal runs
    for run in range(1, num_train_runs + 1):
        df_run = generate_benign_flows(
            run_id=run,
            num_samples=samples_per_run,
            random_state=base_seed + run,
        )
        train_dfs.append(df_run)

    df_train = pd.concat(train_dfs, ignore_index=True)

    # 2. Build D_eval (held-out evaluation dataset)
    eval_dfs: List[pd.DataFrame] = []
    eval_seed_offset = 5000

    # Unseen benign baseline runs (run_id 11 to 15, 1000 samples)
    for run in range(num_train_runs + 1, num_train_runs + 6):
        df_eval_benign = generate_benign_flows(
            run_id=run,
            num_samples=200,
            random_state=eval_seed_offset + run,
        )
        eval_dfs.append(df_eval_benign)

    # Attack scenario 1: SYN Flood (low, medium, high)
    for idx, intensity in enumerate(["low", "medium", "high"], start=1):
        df_syn = generate_attack_flows(
            run_id=20 + idx,
            attack_type="syn_flood",
            rate_intensity=intensity,
            num_samples=120,
            random_state=eval_seed_offset + 100 + idx,
        )
        eval_dfs.append(df_syn)

    # Attack scenario 2: UDP Flood (low, medium, high)
    for idx, intensity in enumerate(["low", "medium", "high"], start=1):
        df_udp = generate_attack_flows(
            run_id=30 + idx,
            attack_type="udp_flood",
            rate_intensity=intensity,
            num_samples=120,
            random_state=eval_seed_offset + 200 + idx,
        )
        eval_dfs.append(df_udp)

    # Attack scenario 3: Nmap Port Scan
    df_scan = generate_attack_flows(
        run_id=41,
        attack_type="port_scan",
        num_samples=320,
        random_state=eval_seed_offset + 301,
    )
    eval_dfs.append(df_scan)

    df_eval = pd.concat(eval_dfs, ignore_index=True)

    return df_train, df_eval


def train_baseline_model(
    output_dir: str = "detection",
    num_train_runs: int = 10,
    contamination: float = 0.035,
    random_state: int = 42,
) -> Dict[str, Any]:
    """Train Isolation Forest strictly on benign baseline data and persist artifacts."""
    models_dir = os.path.join(output_dir, "models")
    data_dir = os.path.join(output_dir, "data")
    os.makedirs(models_dir, exist_ok=True)
    os.makedirs(data_dir, exist_ok=True)

    # 1. Generate benign training baseline and held-out evaluation sets
    df_train, df_eval = build_training_and_eval_datasets(
        num_train_runs=num_train_runs,
        samples_per_run=200,
        base_seed=1000,
    )

    # Verify strict no-leakage invariant
    assert (df_train["label"] == 0).all(), "Data leakage violation: attack data found in training set!"
    assert (df_train["attack_type"] == "benign").all(), "Attack flow type found in benign training set!"

    # Save datasets
    train_csv_path = os.path.join(data_dir, "benign_baseline.csv")
    eval_csv_path = os.path.join(data_dir, "eval_dataset.csv")
    df_train.to_csv(train_csv_path, index=False)
    df_eval.to_csv(eval_csv_path, index=False)

    # 2. Extract feature matrix strictly from D_train
    X_train = df_train[FEATURE_NAMES].values.astype(np.float64)

    # 3. Fit StandardScaler strictly on D_train
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)

    # 4. Fit IsolationForest strictly on scaled D_train
    detector = IsolationForestAnomalyDetector(
        contamination=contamination,
        random_state=random_state,
        n_estimators=100,
    )
    detector.scaler = scaler
    detector.model.fit(X_train_scaled)
    detector.is_fitted = True

    # 5. Persist artifacts
    model_path = os.path.join(models_dir, "isolation_forest.joblib")
    scaler_path = os.path.join(models_dir, "scaler.joblib")
    detector.save(model_path=model_path, scaler_path=scaler_path)

    summary = {
        "num_train_samples": len(df_train),
        "num_eval_samples": len(df_eval),
        "eval_benign_count": int((df_eval["label"] == 0).sum()),
        "eval_attack_count": int((df_eval["label"] == 1).sum()),
        "model_path": model_path,
        "scaler_path": scaler_path,
        "train_csv_path": train_csv_path,
        "eval_csv_path": eval_csv_path,
    }

    return summary


def main():
    print("=" * 60)
    print("SDN Traffic Anomaly Detection - Model Training")
    print("=" * 60)

    # Resolve cn-project base directory
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    detection_dir = os.path.join(base_dir, "detection")

    print(f"[*] Base detection directory: {detection_dir}")
    print("[*] Generating 10 normal traffic runs for benign baseline...")
    summary = train_baseline_model(output_dir=detection_dir)

    print("\n[+] Training Complete:")
    print(f"  - Training samples (D_train): {summary['num_train_samples']} (100% benign, 0 attack flows)")
    print(f"  - Evaluation samples (D_eval): {summary['num_eval_samples']}")
    print(f"      - Unseen Benign: {summary['eval_benign_count']}")
    print(f"      - Simulated Attacks: {summary['eval_attack_count']}")
    print(f"  - Saved model:  {summary['model_path']}")
    print(f"  - Saved scaler: {summary['scaler_path']}")
    print(f"  - Saved train CSV: {summary['train_csv_path']}")
    print(f"  - Saved eval CSV:  {summary['eval_csv_path']}")
    print("=" * 60)


if __name__ == "__main__":
    main()
