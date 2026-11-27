SDN Network Telemetry & Traffic Anomaly Detection

Real-time Software-Defined Networking (SDN) telemetry, hybrid statistical + Machine Learning anomaly detection, and automated OpenFlow 1.3 mitigation using **Mininet**, **Open vSwitch**, **OS-Ken**, **Prometheus**, and **Grafana OSS**.

---

## 1. Environment Requirements (Ubuntu vs. WSL2)

* **Recommended (Full Live Stack):** Native Ubuntu (22.04 / 24.04 / 26.04) or an Ubuntu VM (VirtualBox / VMware).
* **WSL2 Limitation:** Microsoft's default WSL2 kernel **does not include the `openvswitch` kernel module**, so live Mininet (`OVSKernelSwitch`) will fail on standard WSL2 unless you compile a custom WSL2 kernel with `CONFIG_OPENVSWITCH=m`.
  * **Works in WSL2:** Running unit tests (`pytest`), inspecting/editing code, and running Prometheus/Grafana (`localhost:9090` and `localhost:3000` forward to Windows automatically).
  * **Requires Ubuntu VM / Dual-Boot:** Running live Mininet topologies, attack scripts, live benchmarks, and packet captures.

---

## 2. Installation (Ubuntu / WSL2)

### A. System Packages (Mininet, Open vSwitch, Attack Tools, Prometheus)
```bash
sudo apt update
sudo apt install -y \
  python3 python3-pip git curl gnupg2 \
  mininet openvswitch-switch \
  hping3 nmap tcpdump \
  prometheus
```

Start the Open vSwitch service:
```bash
sudo service openvswitch-switch start
```

### B. Grafana OSS
```bash
sudo mkdir -p /etc/apt/keyrings/
curl -fsSL https://apt.grafana.com/gpg.key | gpg --dearmor | sudo tee /etc/apt/keyrings/grafana.gpg > /dev/null
echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main" | sudo tee /etc/apt/sources.list.d/grafana.list
sudo apt update
sudo apt install -y grafana
```

### C. Python Dependencies
```bash
cd /path/to/SDN-Network-Telemetry
pip install --break-system-packages -r requirements.txt
```

If any package is missing, install the core dependencies explicitly:
```bash
pip install --break-system-packages os-ken eventlet scikit-learn joblib psutil prometheus-client pyyaml pytest
```

---

## 3. Running the Full Stack (3-Terminal Live Demo)

### Terminal 1 — Monitoring Stack & SDN Controller
```bash
bash scripts/run_monitoring.sh
bash scripts/run_controller.sh
```

Verify the controller startup logs show:
* `Prometheus telemetry exporter listening at http://0.0.0.0:8000/metrics`
* `StatisticalAnomalyDetector initialized and wired to telemetry`
* `IsolationForestAnomalyDetector loaded from .../isolation_forest.joblib`

### Terminal 2 — Mininet Tree Topology
```bash
sudo mn -c
sudo python3 topo/sdn_tree_topo.py
```

Wait for Terminal 1 to log `Switch connected: DPID=1`, `2`, and `3`.

Inside the `mininet>` CLI, verify connectivity and warm up the EWMA baseline (10+ ticks):
```text
pingall
h1 ping -c 12 h2
h3 ping -c 12 h4
```

### Terminal 3 — Verify Metrics & Trigger Live Attack

1. **Check benign baseline metrics:**
   ```bash
   curl -s http://127.0.0.1:8000/metrics | grep -E "sdn_ml_|sdn_mitigation_active"
   ```
   *Expected:* Negative `sdn_ml_anomaly_score` (benign) and no active mitigations.

2. **Launch a live SYN flood from `h1` to `h2` (in Terminal 2 `mininet>`):**
   ```text
   h1 python3 attacks/syn_flood.py --target 10.0.0.2 --rate high --duration 8
   ```

3. **Verify selective mitigation (in Terminal 2 `mininet>`):**
   ```text
   h1 ping -c 3 h2
   h3 ping -c 5 h4
   ```
   *Expected:* `h1 -> h2` shows **100% packet loss** (blocked); `h3 -> h4` shows **0% packet loss** (benign traffic unaffected).

4. **Verify OpenFlow `priority=1000` drop rule & live alerts (in Terminal 3):**
   ```bash
   sudo ovs-ofctl -O OpenFlow13 dump-flows s2 | grep "priority=1000"
   curl -s http://127.0.0.1:8000/metrics | grep -E "sdn_ml_|sdn_anomaly_alert|sdn_mitigation_active"
   ```

### Dashboards
* **Grafana:** `http://localhost:3000` (login: `admin` / `admin` → open **SDN Network Telemetry & Traffic Anomaly Detection**).
* **Prometheus:** `http://localhost:9090` (open **Status → Targets** to confirm `localhost:8000/metrics` is `UP`).

### Clean Shutdown
1. **Terminal 2 (`mininet>`):** type `exit`
2. **Terminal 1:** press `Ctrl+C`

---

## 4. Unit Tests, Live Benchmarks & Packet Captures

* **Run all 83 unit tests:**
  ```bash
  pytest tests -q
  ```

* **Run the 36-run live Mininet benchmark (`1s`, `2s`, `5s` polling intervals):**
  ```bash
  sudo python3 evaluation/live_benchmark.py --intervals 1 2 5 --repeats 3
  ```
  Outputs are saved to `evaluation/results/live_benchmark_summary.csv` and `evaluation/results/live_evaluation_report.md`.

* **Record `.pcapng` protocol traces:**
  ```bash
  sudo python3 scripts/capture_traces.py
  ```
  Captures are saved under `captures/`.

---

## 5. Troubleshooting

* **Grafana login fails with `admin`/`admin` or shows `STOPPED`:**
  ```bash
  pkill -9 -f grafana-server || true
  find monitoring/grafana -name "grafana.db*" -delete
  find monitoring /tmp -maxdepth 3 -name "*grafana*.pid" -delete 2>/dev/null || true
  bash scripts/run_monitoring.sh
  ```

* **Mininet reports `Unable to contact the remote controller at 127.0.0.1:6653`:**
  Ensure `bash scripts/run_controller.sh` is running in Terminal 1 before starting `topo/sdn_tree_topo.py`.

* **Stale Mininet or Open vSwitch interfaces:**
  Run `sudo mn -c` before restarting the topology.
