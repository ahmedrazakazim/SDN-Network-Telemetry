#!/usr/bin/env python3
"""
Real Live Mininet + OS-Ken Benchmark Driver.
Measures authentic detection delay, mitigation latency, ML anomaly score/latency,
controller CPU %, and benign h3<->h4 retention across polling intervals (1s, 2s, 5s)
with mean and standard deviation across repeated runs.
"""

import argparse
import csv
import os
import re
import statistics
import subprocess
import sys
import time
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

import psutil

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.link import TCLink
from topo.sdn_tree_topo import SDNTreeTopo

METRICS_URL = "http://127.0.0.1:8000/metrics"


def fetch_metrics() -> str:
    try:
        with urllib.request.urlopen(METRICS_URL, timeout=1.0) as resp:
            return resp.read().decode("utf-8", errors="ignore")
    except Exception:
        return ""


def parse_metric(text: str, name: str, label_substr: str = "") -> Optional[float]:
    for line in text.splitlines():
        if line.startswith("#") or not line.startswith(name):
            continue
        if label_substr and label_substr not in line:
            continue
        parts = line.rsplit(" ", 1)
        if len(parts) == 2:
            try:
                return float(parts[1])
            except ValueError:
                pass
    return None


def has_drop_rule(switch: str = "s2", src_ip: str = "10.0.0.1") -> bool:
    try:
        out = subprocess.check_output(
            ["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", switch],
            stderr=subprocess.DEVNULL,
            text=True,
        )
        for line in out.splitlines():
            if "priority=1000" in line and f"nw_src={src_ip}" in line and "actions=drop" in line:
                return True
    except Exception:
        pass
    return False


def parse_ping_loss(output: str) -> Tuple[int, int]:
    sent, recvd = 0, 0
    m = re.search(r"(\d+)\s+packets transmitted,\s+(\d+)\s+received", output)
    if m:
        sent, recvd = int(m.group(1)), int(m.group(2))
    return sent, recvd


def start_controller(poll_interval: int) -> subprocess.Popen:
    env = os.environ.copy()
    env["PYTHONPATH"] = PROJECT_ROOT
    env["SDN_POLL_INTERVAL"] = str(poll_interval)
    log_path = os.path.join(PROJECT_ROOT, "evaluation", "results", f"controller_p{poll_interval}s.log")
    log_file = open(log_path, "w")
    sudo_user = os.environ.get("SUDO_USER")
    ctrl_cmd = ["/usr/bin/python3", os.path.join(PROJECT_ROOT, "controller", "sdn_controller.py"), "--ofp-tcp-listen-port", "6653"]
    if sudo_user:
        ctrl_cmd = [
            "sudo", "-u", sudo_user, "env",
            f"PYTHONPATH={PROJECT_ROOT}",
            f"SDN_POLL_INTERVAL={poll_interval}",
        ] + ctrl_cmd
    proc = subprocess.Popen(
        ctrl_cmd,
        cwd=PROJECT_ROOT,
        env=env,
        stdout=log_file,
        stderr=subprocess.STDOUT,
    )
    # Wait for Prometheus exporter on :8000
    for _ in range(40):
        if fetch_metrics():
            return proc
        time.sleep(0.25)
    return proc


def stop_controller(proc: Optional[subprocess.Popen]) -> None:
    if proc is None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=4)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def get_controller_process(ctrl_proc: subprocess.Popen) -> psutil.Process:
    proc = psutil.Process(ctrl_proc.pid)
    children = proc.children(recursive=True)
    return children[-1] if children else proc


def run_single_attack(
    net: Mininet,
    ctrl_proc: subprocess.Popen,
    poll_interval: int,
    scenario: str,
    run_idx: int,
) -> Dict[str, Any]:
    h1, h3 = net.get("h1"), net.get("h3")
    ps_ctrl = get_controller_process(ctrl_proc)
    ps_ctrl.cpu_percent(interval=None)

    # Warmup so EWMA baseline has >= 10 ticks
    warmup_secs = max(12, poll_interval * 11)
    h1.cmd(f"ping -c {warmup_secs} -i 1 10.0.0.2 > /dev/null 2>&1 &")
    h3.cmd(f"ping -c {warmup_secs} -i 1 10.0.0.4 > /dev/null 2>&1")
    time.sleep(1.5)

    # Launch attack from h1 -> h2
    t0 = time.perf_counter()
    if scenario == "syn_flood_high":
        atk_proc = h1.popen(["python3", "attacks/syn_flood.py", "--target", "10.0.0.2", "--rate", "high", "--duration", "12"])
    elif scenario == "udp_flood_high":
        atk_proc = h1.popen(["python3", "attacks/udp_flood.py", "--target", "10.0.0.2", "--rate", "high", "--duration", "12"])
    elif scenario == "port_scan_nmap":
        atk_proc = h1.popen(["python3", "attacks/port_scan.py", "--target", "10.0.0.2", "--scan-type", "syn", "--ports", "1-100"])
    else:
        raise ValueError(f"Unknown scenario: {scenario}")

    t_alert = None
    t_mit = None
    ml_peak_score = -1.0
    ml_latency_us = 0.0
    ml_flagged = False
    cpu_samples: List[float] = []

    deadline = t0 + max(14.0, poll_interval * 4.0)
    while time.perf_counter() < deadline:
        text = fetch_metrics()
        now = time.perf_counter()

        cpu_samples.append(ps_ctrl.cpu_percent(interval=None))

        ml_score = parse_metric(text, "sdn_ml_anomaly_score", 'host="10.0.0.1"')
        if ml_score is not None and ml_score > ml_peak_score:
            ml_peak_score = ml_score
        ml_lat = parse_metric(text, "sdn_ml_inference_latency_us")
        if ml_lat is not None and ml_lat > 0:
            ml_latency_us = ml_lat
        if parse_metric(text, "sdn_anomaly_alert", 'attack_type="ml_isolation_forest",host="10.0.0.1"') == 1.0:
            ml_flagged = True

        # Check baseline or mitigation alert
        base_alert = (
            parse_metric(text, "sdn_anomaly_alert", 'attack_type="volumetric_flood",host="10.0.0.1"') == 1.0
            or parse_metric(text, "sdn_anomaly_alert", 'attack_type="port_scan",host="10.0.0.1"') == 1.0
            or parse_metric(text, "sdn_mitigation_active", 'offending_ip="10.0.0.1"') == 1.0
        )
        if t_alert is None and base_alert:
            t_alert = now

        if t_mit is None and has_drop_rule("s2", "10.0.0.1"):
            t_mit = now
            if t_alert is None:
                t_alert = now
            break

        time.sleep(0.1)

    # Measure benign retention (h3 <-> h4) while attacker is blocked / active
    ping_out = h3.cmd("ping -c 10 -i 0.2 -W 1 10.0.0.4")
    sent, recvd = parse_ping_loss(ping_out)
    retention_pct = round((recvd / sent) * 100.0, 2) if sent > 0 else 0.0

    try:
        atk_proc.terminate()
        atk_proc.wait(timeout=3)
    except Exception:
        pass

    det_delay = round(t_alert - t0, 3) if t_alert else -1.0
    mit_latency_ms = round(max(0.0, (t_mit - t_alert) * 1000.0), 2) if (t_alert and t_mit) else -1.0
    avg_cpu = round(statistics.mean(cpu_samples), 2) if cpu_samples else 0.0

    return {
        "polling_interval_s": poll_interval,
        "scenario": scenario,
        "run_idx": run_idx,
        "detection_delay_s": det_delay,
        "mitigation_latency_ms": mit_latency_ms,
        "drop_rule_installed": t_mit is not None,
        "benign_retention_pct": retention_pct,
        "false_positive": False,
        "ml_peak_score": round(ml_peak_score, 4),
        "ml_flagged": ml_flagged,
        "ml_inference_latency_us": round(ml_latency_us, 2),
        "controller_cpu_pct": avg_cpu,
    }


def run_single_normal(
    net: Mininet,
    ctrl_proc: subprocess.Popen,
    poll_interval: int,
    run_idx: int,
) -> Dict[str, Any]:
    h1, h3 = net.get("h1"), net.get("h3")
    ps_ctrl = get_controller_process(ctrl_proc)
    ps_ctrl.cpu_percent(interval=None)

    h1.cmd("ping -c 10 -i 0.5 10.0.0.2 > /dev/null 2>&1 &")
    ping_out = h3.cmd("ping -c 10 -i 0.5 -W 1 10.0.0.4")
    sent, recvd = parse_ping_loss(ping_out)
    retention_pct = round((recvd / sent) * 100.0, 2) if sent > 0 else 0.0

    text = fetch_metrics()
    cpu_pct = round(ps_ctrl.cpu_percent(interval=0.2), 2)
    fp = (
        parse_metric(text, "sdn_mitigation_active", 'offending_ip="10.0.0.1"') == 1.0
        or parse_metric(text, "sdn_mitigation_active", 'offending_ip="10.0.0.2"') == 1.0
        or parse_metric(text, "sdn_mitigation_active", 'offending_ip="10.0.0.3"') == 1.0
        or parse_metric(text, "sdn_mitigation_active", 'offending_ip="10.0.0.4"') == 1.0
    )
    ml_score = parse_metric(text, "sdn_ml_anomaly_score", 'host="10.0.0.1"') or 0.0
    ml_lat = parse_metric(text, "sdn_ml_inference_latency_us") or 0.0

    return {
        "polling_interval_s": poll_interval,
        "scenario": "normal_baseline",
        "run_idx": run_idx,
        "detection_delay_s": 0.0,
        "mitigation_latency_ms": 0.0,
        "drop_rule_installed": False,
        "benign_retention_pct": retention_pct,
        "false_positive": fp,
        "ml_peak_score": round(ml_score, 4),
        "ml_flagged": False,
        "ml_inference_latency_us": round(ml_lat, 2),
        "controller_cpu_pct": cpu_pct,
    }


def fmt_mean_std(vals: List[float], suffix: str = "") -> str:
    clean = [v for v in vals if v >= 0]
    if not clean:
        return "N/A"
    mean = statistics.mean(clean)
    std = statistics.stdev(clean) if len(clean) > 1 else 0.0
    return f"{mean:.2f} ± {std:.2f}{suffix}"


def main():
    parser = argparse.ArgumentParser(description="Live Mininet + OS-Ken Benchmark Suite")
    parser.add_argument("--intervals", nargs="+", type=int, default=[1, 2, 5])
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--output-dir", default=os.path.join(PROJECT_ROOT, "evaluation", "results"))
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    all_rows: List[Dict[str, Any]] = []
    scenarios = ["normal_baseline", "syn_flood_high", "udp_flood_high", "port_scan_nmap"]

    for interval in args.intervals:
        print(f"\n=== Live Benchmark Tier: Polling Interval = {interval}s (repeats={args.repeats}) ===")
        for scenario in scenarios:
            for r in range(1, args.repeats + 1):
                subprocess.run(["mn", "-c"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                ctrl = start_controller(interval)
                topo = SDNTreeTopo()
                net = Mininet(topo=topo, controller=None, switch=OVSKernelSwitch, link=TCLink, autoSetMacs=True)
                net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=6653)
                try:
                    net.start()
                    time.sleep(2.0)
                    net.pingAll(timeout=1)
                    if scenario == "normal_baseline":
                        row = run_single_normal(net, ctrl, interval, r)
                    else:
                        row = run_single_attack(net, ctrl, interval, scenario, r)
                    all_rows.append(row)
                    print(
                        f"  [p={interval}s] {scenario} run {r}/{args.repeats}: "
                        f"det={row['detection_delay_s']}s, mit={row['mitigation_latency_ms']}ms, "
                        f"drop={row['drop_rule_installed']}, benign={row['benign_retention_pct']}%, "
                        f"ml_score={row['ml_peak_score']}, cpu={row['controller_cpu_pct']}%"
                    )
                finally:
                    net.stop()
                    stop_controller(ctrl)

    csv_path = os.path.join(args.output_dir, "live_benchmark_summary.csv")
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(all_rows[0].keys()))
        writer.writeheader()
        writer.writerows(all_rows)

    md_path = os.path.join(args.output_dir, "live_evaluation_report.md")
    with open(md_path, "w") as f:
        f.write("# Live Mininet SDN Telemetry & Anomaly Detection Evaluation Report\n\n")
        f.write(f"- **Execution Mode**: 100% Live Mininet + Open vSwitch + OS-Ken Controller\n")
        f.write(f"- **Polling Intervals Tested**: {args.intervals} seconds\n")
        f.write(f"- **Repeats per Condition**: {args.repeats} (reported as Mean ± Std Dev)\n")
        f.write(f"- **Total Live Runs**: {len(all_rows)}\n\n")
        f.write("## Summary by Polling Interval (Attack Scenarios)\n\n")
        f.write("| Polling Interval | Detection Delay (s) | Mitigation Latency (ms) | Benign Retention (%) | Controller CPU (%) | ML Inference (µs) | Normal FPR |\n")
        f.write("|---|:---:|:---:|:---:|:---:|:---:|:---:|\n")
        for interval in args.intervals:
            atks = [x for x in all_rows if x["polling_interval_s"] == interval and x["scenario"] != "normal_baseline"]
            norms = [x for x in all_rows if x["polling_interval_s"] == interval and x["scenario"] == "normal_baseline"]
            fpr = (sum(1 for x in norms if x["false_positive"]) / len(norms) * 100.0) if norms else 0.0
            f.write(
                f"| **{interval}s** | "
                f"{fmt_mean_std([x['detection_delay_s'] for x in atks])} | "
                f"{fmt_mean_std([x['mitigation_latency_ms'] for x in atks])} | "
                f"{fmt_mean_std([x['benign_retention_pct'] for x in atks], '%')} | "
                f"{fmt_mean_std([x['controller_cpu_pct'] for x in atks], '%')} | "
                f"{fmt_mean_std([x['ml_inference_latency_us'] for x in atks])} | "
                f"{fpr:.1f}% |\n"
            )

    print(f"\nSaved live CSV: {csv_path}")
    print(f"Saved live Report: {md_path}")


if __name__ == "__main__":
    main()
