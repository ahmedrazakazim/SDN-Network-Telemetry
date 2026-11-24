# E2E Test Infra: SDN Network Telemetry and Traffic Anomaly Detection System

## Test Philosophy
- Opaque-box, requirement-driven verification directly mapped to Acceptance Criteria and Requirements R1-R7 in `ORIGINAL_REQUEST.md`.
- Methodology: Category-Partition + Boundary Value Analysis (BVA) + Pairwise Combinatorial Testing + Real-World Workload Testing.
- Dual testing channels:
  1. Isolated Unit & Algorithmic Mock Testing: Validates detection math, entropy calculations, z-scores, ML isolation forest training/inference, Prometheus metric generation, and flow rule generation without requiring live kernel/root Mininet execution.
  2. Live SDN Integration Testing: Exercises the full Mininet tree topology, os-ken OpenFlow 1.3 switch handshakes, dynamic drop installation, host traffic generation, Prometheus scraping, and benchmark logging.

## Feature Inventory & Test Matrix
| # | Feature | Source (Requirement) | Tier 1 (Feature Coverage) | Tier 2 (Boundary & Corner) | Tier 3 (Cross-Feature) | Tier 4 (Real-World) |
|---|---------|----------------------|:-------------------------:|:--------------------------:|:----------------------:|:-------------------:|
| 1 | Tree Topology (depth=2, fanout=2) | R2 | 5 | 5 | ✓ | ✓ |
| 2 | os-ken OpenFlow 1.3 Forwarding | R2 | 5 | 5 | ✓ | ✓ |
| 3 | Flow & Port Stats Polling (1s, 2s, 5s) | R3 | 5 | 5 | ✓ | ✓ |
| 4 | Flow-Level Feature Extraction | R3 | 5 | 5 | ✓ | ✓ |
| 5 | EWMA / Z-Score Anomaly Detector | R4 | 5 | 5 | ✓ | ✓ |
| 6 | Destination-Port Shannon Entropy | R4 | 5 | 5 | ✓ | ✓ |
| 7 | Isolation Forest Baseline Training & Inference | R4 | 5 | 5 | ✓ | ✓ |
| 8 | Model Comparison Framework (Precision/Recall/F1/FPR/Latency) | R4 | 5 | 5 | ✓ | ✓ |
| 9 | Automated High-Priority Flow Mitigation | R5 | 5 | 5 | ✓ | ✓ |
| 10 | Benign Host Non-Disruption Guarantee | R5 | 5 | 5 | ✓ | ✓ |
| 11 | Prometheus Metric Exporter & Scrape | R6 | 5 | 5 | ✓ | ✓ |
| 12 | Grafana Dashboard Visualization | R6 | 5 | 5 | ✓ | ✓ |
| 13 | SYN Flood Attack Simulation (Low/Med/High) | R7 | 5 | 5 | ✓ | ✓ |
| 14 | UDP Flood Attack Simulation (Low/Med/High) | R7 | 5 | 5 | ✓ | ✓ |
| 15 | Nmap Port Scan Reconnaissance | R7 | 5 | 5 | ✓ | ✓ |
| 16 | 51-Run Systematic Evaluation Runner | R7 | 5 | 5 | ✓ | ✓ |

## Test Architecture
- **Test Runner**: `pytest` or standalone Python unittest runner (`python3 -m unittest discover tests`).
- **Pass/Fail Semantics**: All test assertions must pass with exit code 0.
- **Directory Layout**:
  ```
  tests/
  ├── test_topology.py               # Tier 1/2: Validates tree topology object, node counts, IP allocations
  ├── test_controller_forwarding.py  # Tier 1/2/3: Validates table-miss, flow mods, eth_type prerequisite
  ├── test_telemetry.py              # Tier 1/2/3: Validates rate derivatives, duration math, zero-division guards
  ├── test_detectors.py              # Tier 1/2/3: Validates EWMA, z-score, Shannon entropy, Isolation Forest no-leakage
  ├── test_mitigation.py             # Tier 1/2/3: Validates drop rule syntax, priority=1000, unblock mechanics
  ├── test_monitoring.py             # Tier 1/2: Validates Prometheus gauges, metric exposition, Grafana JSON schema
  ├── test_attacks.py                # Tier 1/2: Validates CLI parameters, argument validation, rates
  └── test_e2e_integration.py        # Tier 3/4: End-to-end integration and mock pipeline verification
  ```

## Real-World Application Scenarios (Tier 4)
| # | Scenario | Features Exercised | Complexity |
|---|----------|--------------------|------------|
| 1 | Baseline Benign Quiescent State | F1, F2, F3, F4, F11, F12 | Medium |
| 2 | High-Rate SYN Flood with Dynamic Mitigation | F1, F2, F4, F5, F7, F9, F10, F11, F13 | High |
| 3 | UDP Flood Across Polling Intervals (1s, 2s, 5s) | F3, F4, F5, F7, F9, F10, F14, F16 | High |
| 4 | Stealth Nmap Port Scan Reconnaissance | F4, F6, F8, F11, F12, F15 | High |
| 5 | Simultaneous Multi-Host Benign Traffic + Attack Isolation | F1, F2, F9, F10, F13, F14, F16 | High |

## Coverage Thresholds
- Tier 1: ≥5 per feature
- Tier 2: ≥5 per feature (where boundaries exist)
- Tier 3: Pairwise coverage of major feature interactions
- Tier 4: ≥5 realistic application scenarios
