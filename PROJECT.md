# Project: SDN Network Telemetry and Traffic Anomaly Detection System

## Architecture
The system consists of an OpenFlow 1.3 Software-Defined Networking testbed (Mininet tree topology), an os-ken controller managing forwarding and mitigation, an asynchronous telemetry engine polling flow and port statistics, an anomaly detection subsystem combining statistical EWMA/z-score/Shannon entropy with an Isolation Forest ML model, a Prometheus and Grafana monitoring stack, an attack simulation harness (SYN flood, UDP flood, Nmap port scan), and an automated benchmark evaluation suite.

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

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | Tree Topology (depth=2, fanout=2) | 3 OpenFlow 1.3 switches (s1 root, s2/s3 pods), 4 hosts (h1-h4 on 10.0.0.0/24) | M1 | Survey |
| 2 | OpenFlow 1.3 Switch Protocol | Configure OVSSwitch with `protocols='OpenFlow13'` | M1 | Survey |
| 3 | RemoteController Attachment | Point Mininet switches to 127.0.0.1:6653 | M1 | Survey |
| 4 | Dual CLI & Batch Execution | Interactive CLI for viva demo and python API for automated test runs | M1 | Survey |
| 5 | os-ken Base Controller App | Subclass `RyuApp` / `OSKenApp` with `OFP_VERSIONS=[ofproto_v1_3.OFP_VERSION]` | M1 | Survey |
| 6 | Table-Miss Flow Entry | Install `priority=0` rule directing unmatched packets to controller | M1 | Survey |
| 7 | Packet-In L2 Learning | Handle `EventOFPPacketIn`, learn MAC-port mapping, install forwarding rules | M1 | Survey |
| 8 | Flow Match Prerequisite Compliance | Always include `eth_type=0x0800` when matching IPv4 fields to prevent `OFPBAC_BAD_PREREQ` | M1 | Survey |
| 9 | Telemetry Polling Loop | Asynchronous Eventlet greenlet querying flow & port stats at 1s, 2s, 5s | M2 | Survey |
| 10 | Flow Feature Extraction | Compute packet rate, byte rate, duration, packet count, byte count, average packet size | M2 | Survey |
| 11 | Port Feature Extraction | Compute rx/tx packet & byte rates, drops, and errors | M2 | Survey |
| 12 | Prometheus Metrics Exporter | Expose flow, port, anomaly, and mitigation gauges on HTTP port 8000 | M2 | Survey |
| 13 | Cardinality Pruning | Clean up expired flow label series in Prometheus gauges to prevent memory leaks | M2 | Survey |
| 14 | Destination-Port Shannon Entropy | Calculate $H(P) = -\sum p_i \log_2 p_i$ to detect port scans | M3 | Survey |
| 15 | EWMA & Z-Score Tracker | Per-host moving mean, variance, and standardized score with 10-tick warmup | M3 | Survey |
| 16 | Volumetric & Scan Decision Rules | Trigger alerts on volumetric floods ($z > 3.0$) and scans ($H(P) > 3.0$ & $z > 2.5$) | M3 | Survey |
| 17 | Isolation Forest Training | Train `IsolationForest` strictly on benign baseline runs with zero data leakage | M3 | Survey |
| 18 | ML Inference & Metric Evaluation | Compute Precision, Recall, F1, FPR, and sample inference latency ($\mu$s) | M3 | Survey |
| 19 | Side-by-Side Comparison Framework | Generate comparative performance report between Isolation Forest and EWMA detector | M3 | Survey |
| 20 | Automated Flow Mitigation Engine | Install high-priority (`priority=1000`) drop rules matching offending `ipv4_src` | M4 | Survey |
| 21 | Source-Isolation Non-Disruption | Guarantee benign host communications ($h2 \leftrightarrow h3 \leftrightarrow h4$) continue at 100% throughput | M4 | Survey |
| 22 | Mitigation Timeout & Unblock | Support rule expiration (`hard_timeout`) and explicit unblock API | M4 | Survey |
| 23 | Prometheus Scrape Configuration | Configure `prometheus.yml` with 1s scrape interval for controller exporter | M5 | Survey |
| 24 | Grafana Visualization Dashboards | 8-panel dashboard for traffic rates, flow counts, entropy, z-scores, and alerts | M5 | Survey |
| 25 | Attack Simulation Suite | Automated scripts for SYN flood (low/med/high), UDP flood (low/med/high), Nmap scan | M6 | Survey |
| 26 | 51-Run Systematic Benchmark Matrix | Benchmark 10 normal runs + 7 attack scenarios across 1s, 2s, 5s polling intervals | M6 | Survey |
| 27 | Benchmark Metric Profiler | Measure Detection Delay, Mitigation Time, False Positive Rate, CPU %, Control Overhead | M6 | Survey |
| 28 | Comprehensive Test Suite & Verification | Unit tests, mock telemetry tests, integration validation, viva demonstration script | M7 | Survey |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Mininet Topology & Controller Forwarding | Tree topology (`sdn_tree_topo.py`), os-ken OpenFlow 1.3 controller (`sdn_controller.py`), flow manager (`flow_manager.py`) | none | DONE |
| M2 | Telemetry & Metric Collection | Stats polling (`collector.py`), feature extractor (`feature_extractor.py`), Prometheus exporter (`exporter.py`) | M1 | DONE |
| M3 | Statistical Anomaly Detection & ML | EWMA/z-score/Shannon entropy detector (`baseline_detector.py`), Isolation Forest (`ml_detector.py`, `model_trainer.py`), evaluation comparison | M2 | DONE |
| M4 | Automated Flow Mitigation | Dynamic drop rule installation (`mitigation_engine.py`), host isolation, non-disruption verification | M1, M3 | DONE |
| M5 | Prometheus & Grafana Monitoring | Scrape configuration (`configs/prometheus.yml`), Grafana dashboards (`monitoring/grafana/`) | M2, M4 | DONE |
| M6 | Attack Simulation & Benchmark Suite | Attack scripts (`attacks/`), benchmark runner (`evaluation/benchmark_runner.py`), metrics profiler | M1, M3, M4 | DONE |
| M7 | E2E Testing & Integration Review | Comprehensive tests (`tests/`), run scripts (`scripts/`), independent verification report | M1–M6 | DONE |

## Interface Contracts

### 1. Topology ↔ Controller (`topo` ↔ `controller`)
- **Protocol**: OpenFlow 1.3 over TCP.
- **Controller Endpoint**: `127.0.0.1:6653`.
- **Switch DPIDs**: `s1` (`0x1`), `s2` (`0x2`), `s3` (`0x3`).
- **Subnet & Hosts**: `10.0.0.0/24`:
  - `h1`: IP `10.0.0.1/24`, MAC `00:00:00:00:00:01`
  - `h2`: IP `10.0.0.2/24`, MAC `00:00:00:00:00:02`
  - `h3`: IP `10.0.0.3/24`, MAC `00:00:00:00:00:03`
  - `h4`: IP `10.0.0.4/24`, MAC `00:00:00:00:00:04`
- **CLI / Programmatic Entry**:
  - `SDNTreeTopo()` class inheriting `mininet.topo.Topo`.
  - `create_network(controller_ip, controller_port) -> Mininet`.

### 2. Controller ↔ Telemetry (`controller` ↔ `telemetry`)
- **Polling Loop**: Triggered via Eventlet `hub.spawn(self._monitor)`.
- **Polling Intervals**: Configurable via `--poll-interval` argument or `config.yaml` (`1`, `2`, `5` seconds).
- **Stats Request/Reply**:
  - Requests: `parser.OFPFlowStatsRequest(datapath)`, `parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)`.
  - Event Handlers: `@set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)`, `@set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)`.
- **Feature Extractor Contract**:
  - Input: raw `OFPFlowStats` entry list, datapath ID, current timestamp $t$.
  - Output: List of flow feature dictionaries:
    ```python
    {
        'dpid': int,
        'table_id': int,
        'duration_sec': float,
        'priority': int,
        'match': dict,       # {'in_port': int, 'eth_src': str, 'eth_dst': str, 'ipv4_src': str, 'ipv4_dst': str, 'ip_proto': int}
        'packet_count': int,
        'byte_count': int,
        'packet_rate': float, # delta_packets / delta_t
        'byte_rate': float,   # delta_bytes / delta_t
        'avg_packet_size': float # byte_count / packet_count (0.0 if packet_count == 0)
    }
    ```
- **Port Stats Output**:
  ```python
  {
      'dpid': int,
      'port_no': int,
      'rx_packets': int,
      'tx_packets': int,
      'rx_bytes': int,
      'tx_bytes': int,
      'rx_dropped': int,
      'tx_dropped': int,
      'rx_packet_rate': float,
      'tx_packet_rate': float,
      'rx_byte_rate': float,
      'tx_byte_rate': float
  }
  ```

### 3. Telemetry ↔ Detection Pipeline (`telemetry` ↔ `detection`)
- **Host Metrics Aggregator**:
  - Input: Flow records from telemetry extractor.
  - Aggregation: Per source IP (`ipv4_src`):
    - `packet_rate`: Sum of packet rates for flows originating from host.
    - `flow_rate`: Number of new flow entries originating from host per second.
    - `dst_ports`: List/window of destination ports targeted by host.
- **Statistical Detector Contract (`baseline_detector.py`)**:
  - Class: `StatisticalAnomalyDetector(alpha=0.2, z_threshold=3.0, entropy_threshold=3.0, warmup_ticks=10)`.
  - Methods:
    - `update(host_ip: str, packet_rate: float, flow_rate: float, dst_ports: list) -> dict`
    - Returns:
      ```python
      {
          'is_anomaly': bool,
          'attack_type': str or None, # 'volumetric_flood', 'port_scan', or None
          'host_ip': str,
          'entropy': float,
          'z_pkt_rate': float,
          'z_flow_rate': float,
          'z_entropy': float
      }
      ```
- **Isolation Forest Model Contract (`ml_detector.py`)**:
  - Class: `IsolationForestAnomalyDetector(model_path=None, contamination=0.01)`.
  - Methods:
    - `fit(benign_feature_matrix: np.ndarray) -> None` (strict benign data only)
    - `predict_flow(feature_vector: list) -> dict`:
      - Input: `[packet_rate, byte_rate, duration, packet_count, byte_count, avg_packet_size]`.
      - Returns: `{'is_anomaly': bool, 'anomaly_score': float, 'latency_us': float}`.
    - `save(path: str)`, `load(path: str)`.

### 4. Detection Pipeline ↔ Mitigation Engine (`detection` ↔ `mitigation` ↔ `controller`)
- **Mitigation Trigger Contract (`mitigation_engine.py`)**:
  - Class: `MitigationEngine(controller: SDNTelemetryController, default_timeout=300)`.
  - Methods:
    - `mitigate_host(offending_ip: str, reason: str = "") -> dict`:
      - Installs high-priority drop rule:
        - `priority`: `1000`
        - `match`: `parser.OFPMatch(eth_type=0x0800, ipv4_src=offending_ip)`
        - `instructions`: `[]` (empty instructions = drop)
        - `hard_timeout`: `300` (auto-expiry or explicit unblock)
      - Returns: `{'success': bool, 'offending_ip': str, 'installed_rules': int, 'timestamp': float}`
    - `unblock_host(offending_ip: str) -> dict`:
      - Removes drop rule using `OFPFC_DELETE`.
    - `is_blocked(host_ip: str) -> bool`.

### 5. Telemetry & Controller ↔ Prometheus Exporter (`telemetry` ↔ `monitoring`)
- **Exporter Endpoint**: Port `8000` HTTP (`http://127.0.0.1:8000/metrics`).
- **Exported Gauges**:
  - `sdn_flow_packet_rate{dpid, src_ip, dst_ip, ip_proto}`
  - `sdn_flow_byte_rate{dpid, src_ip, dst_ip, ip_proto}`
  - `sdn_flow_packet_count{dpid, src_ip, dst_ip, ip_proto}`
  - `sdn_flow_byte_count{dpid, src_ip, dst_ip, ip_proto}`
  - `sdn_flow_duration_seconds{dpid, src_ip, dst_ip, ip_proto}`
  - `sdn_active_flows_count{dpid}`
  - `sdn_port_rx_packets{dpid, port_no}`
  - `sdn_port_tx_packets{dpid, port_no}`
  - `sdn_port_rx_bytes{dpid, port_no}`
  - `sdn_port_tx_bytes{dpid, port_no}`
  - `sdn_port_rx_dropped{dpid, port_no}`
  - `sdn_port_tx_dropped{dpid, port_no}`
  - `sdn_host_packet_rate{host}`
  - `sdn_host_port_entropy{host}`
  - `sdn_host_z_score{host, metric}`
  - `sdn_anomaly_alert{host, attack_type}` (0 or 1)
  - `sdn_mitigation_active{offending_ip}` (0 or 1)
  - `sdn_controller_cpu_percent`
- **Cardinality Management**: Clean up expired labelsets using `gauge.remove(*labels)` when flows terminate.

### 6. Attacks & Evaluation Suite ↔ Testbed (`attacks` ↔ `evaluation`)
- **Attack Drivers**:
  - `syn_flood(target_ip, rate='low'|'medium'|'high', duration=30)`:
    - low: `hping3 -S -p 80 -i u10000` (100 pps)
    - medium: `hping3 -S -p 80 -i u1000` (1,000 pps)
    - high: `hping3 -S -p 80 --flood`
  - `udp_flood(target_ip, rate='low'|'medium'|'high', duration=30)`:
    - low: `hping3 --udp -p 5001 -i u10000 -d 512`
    - medium: `hping3 --udp -p 5001 -i u1000 -d 512`
    - high: `hping3 --udp -p 5001 --flood -d 1024`
  - `port_scan(target_ip, scan_type='syn'|'connect')`:
    - syn: `nmap -sS -p 1-1024 -T4 <target_ip>`
    - connect: `nmap -sT -p 1-1024 -T4 <target_ip>`
- **Benchmark Runner Contract**:
  - Matrix: 10 normal runs + 7 attack runs across `[1, 2, 5]` second polling intervals.
  - Output Metrics Recorded per run:
    - `detection_delay_sec`
    - `mitigation_time_sec`
    - `false_positive_rate`
    - `controller_cpu_mean_pct`, `controller_cpu_peak_pct`
    - `control_overhead_pkts_per_sec`, `control_overhead_bytes_per_sec`
    - `benign_traffic_delivery_ratio` (percentage of packets delivered between $h3 \leftrightarrow h4$ during attack)

## Code Layout & File Ownership Boundaries

Strict file ownership rules ensure parallel development agents do not edit the same files simultaneously:

```
/home/zen/cn-project/
├── configs/
│   ├── sdn_config.yaml                # [Agent 1] Controller IP, ports, intervals
│   └── prometheus.yml                 # [Agent 4] Prometheus scrape configuration
├── topo/
│   ├── __init__.py                    # [Agent 1]
│   └── sdn_tree_topo.py               # [Agent 1] Mininet tree topology depth=2, fanout=2
├── controller/
│   ├── __init__.py                    # [Agent 1]
│   ├── sdn_controller.py              # [Agent 1] os-ken OpenFlow 1.3 controller
│   └── flow_manager.py                # [Agent 1] FlowMod table programming
├── telemetry/
│   ├── __init__.py                    # [Agent 2]
│   ├── collector.py                   # [Agent 2] Flow and port statistics poller
│   ├── feature_extractor.py           # [Agent 2] Rate and flow feature calculations
│   └── exporter.py                    # [Agent 2] Prometheus metrics exporter
├── detection/
│   ├── __init__.py                    # [Agent 3]
│   ├── baseline_detector.py           # [Agent 3] EWMA, z-score, destination-port entropy
│   ├── ml_detector.py                 # [Agent 3] Isolation Forest inference engine
│   ├── model_trainer.py               # [Agent 3] Model training strictly on benign baseline
│   ├── evaluator.py                   # [Agent 3] Precision, recall, F1, FPR, latency comparison
│   ├── models/                        # [Agent 3] Serialized model files (.joblib)
│   └── data/                          # [Agent 3] Benign and attack datasets (.csv)
├── mitigation/
│   ├── __init__.py                    # [Agent 5]
│   └── mitigation_engine.py           # [Agent 5] Dynamic drop rules and non-disruption logic
├── monitoring/
│   ├── prometheus/                    # [Agent 4] Prometheus runner and configuration
│   └── grafana/                       # [Agent 4] Grafana dashboard JSON & provisioning
├── attacks/
│   ├── __init__.py                    # [Agent 5]
│   ├── syn_flood.py                   # [Agent 5] SYN flood generator (low/med/high)
│   ├── udp_flood.py                   # [Agent 5] UDP flood generator (low/med/high)
│   └── port_scan.py                   # [Agent 5] Nmap scan generator
├── evaluation/
│   ├── __init__.py                    # [Agent 5]
│   ├── benchmark_runner.py            # [Agent 5] 51-run systematic evaluation runner
│   ├── metrics_collector.py           # [Agent 5] Overhead, delay, FPR, CPU profiler
│   └── results/                       # [Agent 5] CSV results and benchmark comparison tables
├── scripts/
│   ├── setup_env.sh                   # [Agent 1 & Orchestrator] Environment setup
│   ├── run_controller.sh              # [Agent 1] Controller startup
│   ├── run_topology.sh                # [Agent 1] Mininet startup
│   ├── run_monitoring.sh              # [Agent 4] Prometheus & Grafana startup
│   └── run_evaluation.sh              # [Agent 5] Benchmark suite execution
├── tests/                             # [E2E Testing Track / Verifier]
│   ├── __init__.py
│   ├── test_topology.py               # Topology validation
│   ├── test_controller_forwarding.py  # Forwarding & packet-in validation
│   ├── test_telemetry.py              # Polling & feature extraction validation
│   ├── test_detectors.py              # EWMA, entropy & Isolation Forest tests
│   ├── test_mitigation.py             # Drop rule and non-disruption tests
│   ├── test_monitoring.py             # Prometheus & Grafana dashboard tests
│   ├── test_attacks.py                # Attack generator parameter tests
│   └── test_e2e_integration.py        # End-to-end integration and viva verification
├── README.md                          # [Verifier / Human Liaison]
└── requirements.txt                   # [Agent 1]
```
