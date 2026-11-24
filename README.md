# SDN Network Telemetry and Traffic Anomaly Detection System

[![OpenFlow 1.3](https://img.shields.io/badge/OpenFlow-1.3-blue.svg)](https://opennetworking.org)
[![Python 3.14](https://img.shields.io/badge/Python-3.14-green.svg)](https://python.org)
[![Tests Passing](https://img.shields.io/badge/Tests-82%2F82%20Pass-brightgreen.svg)]()
[![Forensic Audit](https://img.shields.io/badge/Audit-CLEAN-success.svg)]()

A comprehensive, multi-agent developed Software-Defined Networking (SDN) system featuring network telemetry polling, dual-engine statistical and machine-learning anomaly detection, automated high-priority OpenFlow flow mitigation, Prometheus/Grafana monitoring, and an automated 51-run benchmarking evaluation suite.

Developed for university course showcase and viva demonstration.

---

## Architecture Overview

```
                              +--------------------------+
                              |   Grafana Dashboards     |
                              |   (Port 3000 Web UI)     |
                              +-------------+------------+
                                            ^
                                            | PromQL queries
                              +-------------+------------+
                              |    Prometheus Server     |
                              |       (Port 9090)        |
                              +-------------+------------+
                                            ^
                                            | HTTP Scrape (/metrics every 1s)
+-------------------------------------------+-----------------------------------------------+
| os-ken OpenFlow 1.3 Controller (127.0.0.1:6653)                                           |
|                                                                                           |
|  +--------------------+   +-----------------------+   +--------------------------------+  |
|  | Forwarding & L2    |   | Telemetry Poller      |   | Prometheus Exporter            |  |
|  | Learning Switch    |   | (1s, 2s, 5s intervals)|   | (Port 8000 HTTP Server)        |  |
|  +---------+----------+   +-----------+-----------+   +---------------+----------------+  |
|            |                          |                               ^                   |
|            |                          v                               |                   |
|            |              +-----------------------+                   |                   |
|            |              | Flow Feature          |-------------------+                   |
|            |              | Extraction Engine     |                                       |
|            |              +-----------+-----------+                                       |
|            |                          | Flow Features & Host Metrics                      |
|            |                          v                                                   |
|            |              +-------------------------------------------+                   |
|            |              | Anomaly Detection Pipeline                |                   |
|            |              | 1. EWMA / Z-Score + Shannon Entropy       |                   |
|            |              | 2. Isolation Forest (Scikit-Learn)        |                   |
|            |              +-------------------+-----------------------+                   |
|            |                                  | Anomaly Alert (Offending IP)              |
|            v                                  v                                           |
|  +--------------------+           +-----------------------+                               |
|  | Flow Manager       |<----------| Automated Mitigation  |                               |
|  | (Install / Delete) |           | Engine (Drop Rules)   |                               |
|  +---------+----------+           +-----------------------+                               |
+------------|------------------------------------------------------------------------------+
             | OpenFlow 1.3 Protocol (TCP 6653)
             v
+-------------------------------------------------------------------------------------------+
| Mininet Network Emulation (10.0.0.0/24 Subnet)                                            |
|                                                                                           |
|                           [ Root Switch s1 ]                                              |
|                               /        \                                                  |
|                              /          \                                                 |
|                 [ Pod Switch s2 ]      [ Pod Switch s3 ]                                  |
|                     /       \              /       \                                      |
|                  h1          h2          h3         h4                                    |
|              10.0.0.1     10.0.0.2    10.0.0.3   10.0.0.4                                 |
|              (Attacker)   (Victim)    (Benign)   (Benign)                                 |
+-------------------------------------------------------------------------------------------+
```

---

## Key Modules & Capabilities

### 1. Mininet Topology & Controller (`topo/`, `controller/`)
- **Topology**: Tree topology (depth=2, fanout=2) comprising 3 OpenFlow switches (`s1` root, `s2` pod 1, `s3` pod 2) and 4 hosts (`h1`–`h4` on subnet `10.0.0.0/24`: `10.0.0.1`–`10.0.0.4/24`) with fixed MAC addresses (`00:00:00:00:00:01`–`04`).
- **Controller**: OpenFlow 1.3 controller logic (`sdn_controller.py`) subclassing `OSKenApp`/`RyuApp`.
- **Flow Rules**:
  - `priority=0`: Table-miss flow entry forwarding unmatched packets to controller.
  - `priority=1`: Reactive L2 learning switch forwarding with IPv4 prerequisite enforcement (`eth_type=0x0800`).
  - `priority=1000`: Dynamic flow drop rules installed upon anomaly detection.

### 2. Telemetry Collection & Feature Extraction (`telemetry/`)
- Asynchronous polling loop supporting configurable intervals (**1s, 2s, and 5s**).
- Dispatches OpenFlow `OFPFlowStatsRequest` and `OFPPortStatsRequest` messages.
- Computes mathematical rate derivatives across consecutive snapshots:
  - $\text{packet\_rate} = \Delta \text{packets} / \Delta t$
  - $\text{byte\_rate} = \Delta \text{bytes} / \Delta t$
  - $\text{average\_packet\_size} = \text{byte\_count} / \text{packet\_count}$
  - Duration, cumulative counts, and switch port throughput/drop rates.
- Aggregates per-host metrics: packet rate, new flow creation rate, and sliding destination-port windows.
- Dynamic cardinality pruning (`gauge.remove(*labels)`) protects Prometheus memory during high-flow attacks.

### 3. Dual Detection Pipeline (`detection/`)
- **Statistical Detector (EWMA & Shannon Entropy)**:
  - Destination-Port Shannon Entropy: $H(P) = -\sum_{i=1}^K p_i \log_2(p_i)$ over sliding window. Dispersed reconnaissance port scans cause $H(P)$ to spike from $0.0$ to $> 5.0$ bits.
  - EWMA Moving Mean & Variance: $S_t = \alpha X_t + (1-\alpha)S_{t-1}$ with variance floor ($\epsilon=10^{-4}$) to prevent zero division.
  - Standardized Z-Score: $z = (X_t - S_{t-1}) / \sigma_{t-1}$ with 10-tick warmup suppression to avoid cold-start false alarms.
- **Machine Learning Detector (Isolation Forest)**:
  - Trained via `scikit-learn` on 6 flow features: `[packet_rate, byte_rate, duration, packet_count, byte_count, average_packet_size]`.
  - **Strict No-Data-Leakage Policy**: Training set ($D_{train}$) contains 2,000 samples from 10 normal baseline runs (**100% benign, strictly 0 attack samples**). Evaluated on held-out dataset ($D_{eval}$) of 2,040 samples.
- **Quantitative Comparison Summary**:
  | Metric | Baseline EWMA & Entropy | Isolation Forest |
  |---|---|---|
  | **Precision** | **1.0000 (100.0%)** | 0.9656 (96.56%) |
  | **Recall** | **1.0000 (100.0%)** | **1.0000 (100.0%)** |
  | **F1 Score** | **1.0000 (100.0%)** | 0.9825 (98.25%) |
  | **False Positive Rate (FPR)** | **0.0000 (0.0%)** | 0.0370 (3.70%) |
  | **Inference Latency** | **7.49 μs / sample** | 5,004.16 μs / sample |

### 4. Automated Flow Mitigation (`mitigation/`)
- Upon anomaly trigger, dynamically installs OpenFlow 1.3 drop rules (`priority=1000`, `eth_type=0x0800`, `ipv4_src=offending_ip`, `instructions=[]`, `hard_timeout=300`).
- **Source-Isolation Non-Disruption Guarantee**: Benign communication ($h2 \leftrightarrow h3 \leftrightarrow h4$) retains 100% throughput and 0% packet loss while attack traffic from $h1$ is dropped at wire rate.

### 5. Prometheus & Grafana Monitoring (`monitoring/`, `configs/`)
- Prometheus configuration scraping `127.0.0.1:8000/metrics` every 1s.
- Interactive Grafana Dashboard (`sdn_telemetry_dashboard.json`, schemaVersion 38) with 11 visual panels:
  - Anomaly Alert Status Banner, Mitigation Active Banner, Active Flows Count.
  - Real-time Flow Packet Rates & Byte Rates.
  - Switch Port RX/TX Rates & Dropped Packets.
  - Destination-Port Shannon Entropy & EWMA Z-Score Deviations.
  - Controller CPU Utilization & Control-Channel Overhead.

### 6. Attack Simulation & Systematic Benchmark Suite (`attacks/`, `evaluation/`)
- Attack simulations:
  - SYN Flood: low (100 pps), medium (1,000 pps), high (wire rate).
  - UDP Flood: low (100 pps, 512B), medium (1,000 pps, 512B), high (wire rate, 1KB).
  - Nmap Port Scan: TCP SYN stealth (`-sS -T4`) and TCP connect (`-sT -T4`).
- **51-Run Systematic Benchmark Matrix**:
  - 10 normal baseline runs + 7 attack scenarios evaluated across 1s, 2s, and 5s polling intervals (17 $\times$ 3 = 51 runs).
  - Summary logs stored in `evaluation/results/benchmark_summary.csv` and `evaluation/results/evaluation_report.md`.

---

## Project Structure & File Ownership

```
/home/zen/cn-project/
├── configs/
│   ├── sdn_config.yaml                # Global SDN configuration
│   └── prometheus.yml                 # Prometheus scrape configuration
├── topo/
│   ├── __init__.py
│   └── sdn_tree_topo.py               # Mininet tree topology (depth=2, fanout=2)
├── controller/
│   ├── __init__.py
│   ├── sdn_controller.py              # os-ken OpenFlow 1.3 controller application
│   └── flow_manager.py                # OpenFlow 1.3 flow table manager & drop rules
├── telemetry/
│   ├── __init__.py
│   ├── collector.py                   # Periodic stats poller (1s, 2s, 5s)
│   ├── feature_extractor.py           # Flow rate derivatives & host metrics
│   └── exporter.py                    # Prometheus metrics HTTP exporter (port 8000)
├── detection/
│   ├── __init__.py
│   ├── baseline_detector.py           # EWMA, z-score, destination-port Shannon entropy
│   ├── ml_detector.py                 # Isolation Forest inference engine
│   ├── model_trainer.py               # Strict no-data-leakage training pipeline
│   ├── evaluator.py                   # Precision/Recall/F1/FPR/Latency comparison
│   ├── models/                        # Serialized models (isolation_forest.joblib, scaler.joblib)
│   └── data/                          # Benign baseline (D_train) and eval (D_eval) CSVs
├── mitigation/
│   ├── __init__.py
│   └── mitigation_engine.py           # Dynamic OpenFlow drop rule management
├── monitoring/
│   ├── prometheus/                    # Prometheus runner script & storage
│   └── grafana/                       # 11-panel Grafana dashboard & provisioning
├── attacks/
│   ├── __init__.py
│   ├── syn_flood.py                   # Low/med/high SYN flood generator
│   ├── udp_flood.py                   # Low/med/high UDP flood generator
│   └── port_scan.py                   # Nmap port scan generator
├── evaluation/
│   ├── __init__.py
│   ├── benchmark_runner.py            # 51-run systematic evaluation runner
│   ├── metrics_collector.py           # Detection delay, FPR, CPU, overhead profiler
│   └── results/                       # benchmark_summary.csv & evaluation_report.md
├── scripts/
│   ├── setup_env.sh                   # Environment setup & dependency verification
│   ├── run_controller.sh              # Controller launcher
│   ├── run_topology.sh                # Mininet topology launcher
│   ├── run_monitoring.sh              # Prometheus & Grafana stack launcher
│   └── run_evaluation.sh              # 51-run benchmark evaluation runner
├── tests/
│   ├── test_topology.py               # Topology validation tests (11 tests)
│   ├── test_controller_forwarding.py  # Controller forwarding & OpenFlow 1.3 tests (9 tests)
│   ├── test_telemetry.py              # Rate derivatives & polling tests (11 tests)
│   ├── test_detectors.py              # EWMA, entropy & ML leakage tests (15 tests)
│   ├── test_mitigation.py             # Drop rules & non-disruption tests (7 tests)
│   ├── test_monitoring.py             # Prometheus & Grafana dashboard tests (9 tests)
│   ├── test_attacks.py                # Attack generator parameter tests (15 tests)
│   └── test_e2e_integration.py        # Tier 4 closed-loop integration tests (5 tests)
├── PROJECT.md                         # Architecture, contracts, and file boundaries
├── TEST_INFRA.md                      # E2E test methodology and coverage matrix
├── TEST_READY.md                      # E2E test suite readiness certificate
└── requirements.txt                   # Documented Python dependencies
```

---

## Quickstart & Viva Demonstration Guide

### 1. Verify Dependencies & Environment
```bash
cd /home/zen/cn-project
bash scripts/setup_env.sh
```

### 2. Execute the Full E2E Test Suite (82/82 Passing Tests)
```bash
python3 -m unittest discover tests -v
# or
python3 -m pytest tests -v
```

### 3. Run Quantitative ML vs Baseline Comparison
```bash
python3 detection/evaluator.py
```
Outputs side-by-side comparison table to terminal and updates `detection/data/evaluation_comparison.md`.

### 4. Run the 51-Run Systematic Benchmark Suite
```bash
bash scripts/run_evaluation.sh
```
Executes 10 normal runs and 7 attack scenarios across 1s, 2s, and 5s polling intervals, logging metrics to `evaluation/results/benchmark_summary.csv`.

### 5. Live Showcase & Viva Demo Walkthrough
1. **Terminal 1 - Launch os-ken Controller**:
   ```bash
   bash scripts/run_controller.sh
   ```
   Controller starts on `127.0.0.1:6653` and telemetry exporter starts on `http://127.0.0.1:8000/metrics`.

2. **Terminal 2 - Launch Mininet Topology**:
   ```bash
   sudo python3 topo/sdn_tree_topo.py
   ```
   Enters the interactive Mininet CLI (`mininet>`).
   Verify connectivity:
   ```
   mininet> pingall
   ```

3. **Terminal 3 - Launch Monitoring Stack**:
   ```bash
   bash scripts/run_monitoring.sh start
   ```
   Prometheus: `http://localhost:9090`, Grafana: `http://localhost:3000`.

4. **Step 4 - Inject Attack Traffic & Observe Automated Mitigation (Mininet CLI)**:
   Inside the Mininet CLI (Terminal 2), execute the attack from `h1` in the background (avoiding `xterm` since Ubuntu 26.04 is Wayland-only and avoids namespace isolation issues of running in host terminals):
   ```
   mininet> h1 python3 attacks/syn_flood.py --rate high --target 10.0.0.2 &
   ```
   - **Controller Detection**: In Terminal 1 controller logs, observe the volumetric EWMA alert triggered for source `10.0.0.1`.
   - **Automated OpenFlow Drop Rule**: Controller installs a `priority=1000` drop rule on switch `s2`. Verify via:
     ```bash
     sudo ovs-ofctl -O OpenFlow13 dump-flows s2
     ```
     Notice the rule: `priority=1000,ip,nw_src=10.0.0.1 actions=drop`.
   - **Non-Disruption Verification**: While `h1`'s attack traffic is actively dropped, confirm benign traffic continues without interruption in Mininet CLI:
     ```
     mininet> h3 ping -c 5 h4
     ```
     Verify `0% packet loss` between benign hosts `h3` and `h4` while attacker `h1` is completely isolated.
