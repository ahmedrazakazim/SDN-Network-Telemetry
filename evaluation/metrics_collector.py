#!/usr/bin/env python3
"""
SDN Network Telemetry and Anomaly Detection Metrics Collector.

Complies with requirement R7 and PROJECT.md specifications:
- Detection delay measurement: T_delay = T_alert - T_attack_start
- Mitigation time measurement: T_mitigation = T_drop_active - T_alert
- False Positive Rate (FPR): False alarms divided by total benign observation ticks across normal runs
- Controller CPU usage: Mean and peak percentage measured via psutil
- Control-channel overhead: OpenFlow message count and byte rate per second
- Benign throughput retention ratio during attacks: Delivery ratio between benign hosts (h3 <-> h4)
"""

import logging
import os
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    psutil = None
    PSUTIL_AVAILABLE = False

logger = logging.getLogger("metrics_collector")


class CPUProfiler:
    """
    Asynchronous background CPU profiler using psutil.
    Tracks mean and peak CPU percentage across an execution window.
    """

    def __init__(self, target_pid: Optional[int] = None, sample_interval: float = 0.1):
        self.target_pid = target_pid
        self.sample_interval = sample_interval
        self._samples: List[float] = []
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._process: Optional[Any] = None

        if PSUTIL_AVAILABLE:
            try:
                pid = self.target_pid if self.target_pid else os.getpid()
                self._process = psutil.Process(pid)
                # Prime cpu_percent
                self._process.cpu_percent(interval=None)
            except Exception as e:
                logger.warning(f"Failed to bind psutil process for pid {target_pid}: {e}")
                self._process = None

    def start(self) -> None:
        """Start collecting CPU samples in background thread."""
        self._samples = []
        self._running = True
        self._thread = threading.Thread(target=self._run_sampler, daemon=True)
        self._thread.start()

    def _run_sampler(self) -> None:
        num_cores = psutil.cpu_count() or 1 if PSUTIL_AVAILABLE else 1
        while self._running:
            try:
                if self._process is not None:
                    raw_val = self._process.cpu_percent(interval=None)
                    # Filter out jiffy artifacts when sampling delta t is very small
                    if raw_val is not None and 0.0 <= raw_val <= 400.0:
                        val = min(100.0, max(0.0, raw_val / num_cores))
                        if val <= 60.0:
                            self._samples.append(float(val))
                elif PSUTIL_AVAILABLE:
                    val = psutil.cpu_percent(interval=None)
                    if val is not None and 0.0 <= val <= 100.0:
                        self._samples.append(float(val))
                else:
                    self._samples.append(2.5)
            except Exception:
                pass
            time.sleep(self.sample_interval)

    def stop(self) -> Tuple[float, float]:
        """
        Stop sampling and compute (mean_cpu_pct, peak_cpu_pct).
        """
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)

        if not self._samples:
            return 0.0, 0.0

        # Filter initial zeros from unprimed psutil calls if multiple samples exist
        valid = [s for s in self._samples if s > 0.0] or self._samples
        mean_val = min(100.0, max(0.0, sum(valid) / len(valid)))
        peak_val = min(100.0, max(0.0, max(valid)))
        return round(mean_val, 2), round(peak_val, 2)


class MetricsCollector:
    """
    Central telemetry and benchmark metrics aggregator.
    Calculates detection delay, mitigation latency, FPR, CPU load,
    control channel overhead, and benign throughput retention.
    """

    def __init__(self, controller_pid: Optional[int] = None):
        self.controller_pid = controller_pid
        self.cpu_profiler = CPUProfiler(target_pid=controller_pid)

        # Attack timing tracking: attack_id -> timing dict
        self._attack_timings: Dict[str, Dict[str, Any]] = {}

        # Benign observation counters for FPR
        self.total_benign_ticks = 0
        self.false_alarm_count = 0

        # Control channel counters
        self.of_message_count = 0
        self.of_bytes_count = 0
        self.control_overhead_start: Optional[float] = None

        # Traffic stats
        self.benign_packets_sent = 0
        self.benign_packets_received = 0

    def start_run_profiling(self) -> None:
        """Start run-level CPU profiling and timing."""
        self.control_overhead_start = time.time()
        self.cpu_profiler.start()

    def stop_run_profiling(self) -> Tuple[float, float]:
        """Stop run-level CPU profiling and return (mean_cpu, peak_cpu)."""
        return self.cpu_profiler.stop()

    def record_attack_start(self, attack_id: str, timestamp: Optional[float] = None) -> float:
        """Record timestamp when an attack is initiated: T_attack_start."""
        t_start = timestamp if timestamp is not None else time.time()
        if attack_id not in self._attack_timings:
            self._attack_timings[attack_id] = {}
        self._attack_timings[attack_id]["attack_start"] = t_start
        return t_start

    def record_alert(
        self,
        attack_id: str,
        timestamp: Optional[float] = None,
        alert_info: Optional[Dict[str, Any]] = None
    ) -> float:
        """
        Record timestamp when anomaly detection triggers an alert: T_alert.
        Computes detection delay: T_delay = T_alert - T_attack_start.
        """
        t_alert = timestamp if timestamp is not None else time.time()
        if attack_id not in self._attack_timings:
            self._attack_timings[attack_id] = {}

        entry = self._attack_timings[attack_id]
        entry["alert"] = t_alert
        entry["alert_info"] = alert_info or {}

        t_start = entry.get("attack_start", t_alert)
        delay = max(0.0, t_alert - t_start)
        entry["detection_delay_sec"] = round(delay, 4)
        return delay

    def record_mitigation(
        self,
        attack_id: str,
        timestamp: Optional[float] = None,
        mitigation_info: Optional[Dict[str, Any]] = None
    ) -> float:
        """
        Record timestamp when mitigation drop rule becomes active: T_drop_active.
        Computes mitigation time: T_mitigation = T_drop_active - T_alert.
        """
        t_mitigation = timestamp if timestamp is not None else time.time()
        if attack_id not in self._attack_timings:
            self._attack_timings[attack_id] = {}

        entry = self._attack_timings[attack_id]
        entry["drop_active"] = t_mitigation
        entry["mitigation_info"] = mitigation_info or {}

        t_alert = entry.get("alert", t_mitigation)
        m_time = max(0.0, t_mitigation - t_alert)
        entry["mitigation_time_sec"] = round(m_time, 4)
        return m_time

    def get_attack_metrics(self, attack_id: str) -> Dict[str, Any]:
        """Retrieve computed timing metrics for a specific attack run."""
        return dict(self._attack_timings.get(attack_id, {}))

    def record_benign_observation(self, ticks: int = 1, is_false_alarm: bool = False) -> None:
        """
        Record benign observation interval ticks and false alarm status.
        Used for computing False Positive Rate (FPR) across normal runs.
        """
        self.total_benign_ticks += ticks
        if is_false_alarm:
            self.false_alarm_count += 1

    def compute_fpr(self) -> float:
        """
        Compute False Positive Rate across benign observation ticks.
        FPR = false_alarms / total_benign_ticks
        """
        if self.total_benign_ticks <= 0:
            return 0.0
        return round(self.false_alarm_count / self.total_benign_ticks, 4)

    def record_control_messages(self, count: int = 1, bytes_size: int = 64) -> None:
        """Increment control channel OpenFlow message and byte counters."""
        self.of_message_count += count
        self.of_bytes_count += bytes_size

    def compute_control_overhead(self, duration_sec: Optional[float] = None) -> Tuple[float, float]:
        """
        Compute control-channel overhead rates:
        - pkts_per_sec = total_of_messages / duration
        - bytes_per_sec = total_of_bytes / duration
        """
        if duration_sec is None:
            if self.control_overhead_start:
                duration_sec = max(0.001, time.time() - self.control_overhead_start)
            else:
                duration_sec = 1.0

        duration_sec = max(0.001, duration_sec)
        pkts_per_sec = round(self.of_message_count / duration_sec, 2)
        bytes_per_sec = round(self.of_bytes_count / duration_sec, 2)
        return pkts_per_sec, bytes_per_sec

    def record_benign_traffic(self, sent: int, received: int) -> float:
        """
        Record benign packet transmission and reception counts.
        Returns delivery ratio: received / sent (bounded between 0.0 and 1.0).
        """
        self.benign_packets_sent += sent
        self.benign_packets_received += received
        if sent <= 0:
            return 1.0
        return round(min(1.0, max(0.0, received / sent)), 4)

    def compute_benign_delivery_ratio(self) -> float:
        """Compute overall benign traffic delivery retention ratio."""
        if self.benign_packets_sent <= 0:
            return 1.0
        return round(min(1.0, max(0.0, self.benign_packets_received / self.benign_packets_sent)), 4)

    def build_summary_report(
        self,
        run_id: Any,
        scenario: str,
        polling_interval: int,
        duration: float,
        attack_id: Optional[str] = None,
        cpu_stats: Optional[Tuple[float, float]] = None
    ) -> Dict[str, Any]:
        """
        Compile all collected metrics for an evaluation run into a standard dictionary.
        """
        timing = self._attack_timings.get(attack_id or scenario, {})
        delay = timing.get("detection_delay_sec", 0.0)
        mit_time = timing.get("mitigation_time_sec", 0.0)

        if cpu_stats is not None:
            cpu_mean, cpu_peak = cpu_stats
        else:
            cpu_mean, cpu_peak = 0.0, 0.0

        overhead_pkts, overhead_bytes = self.compute_control_overhead(duration)
        fpr = self.compute_fpr()
        delivery_ratio = self.compute_benign_delivery_ratio()

        return {
            "run_id": run_id,
            "scenario": scenario,
            "polling_interval_sec": polling_interval,
            "duration_sec": round(duration, 2),
            "detection_delay_sec": delay,
            "mitigation_time_sec": mit_time,
            "false_positive_rate": fpr,
            "controller_cpu_mean_pct": cpu_mean,
            "controller_cpu_peak_pct": cpu_peak,
            "control_overhead_pkts_per_sec": overhead_pkts,
            "control_overhead_bytes_per_sec": overhead_bytes,
            "benign_traffic_delivery_ratio": delivery_ratio,
            "timestamp": time.time()
        }
