#!/usr/bin/env python3
"""Baseline Statistical Anomaly Detector for SDN Network Telemetry.

Implements:
1. Destination-port Shannon Entropy:
   H(P) = - sum_{i=1}^K p_i * log2(p_i)
   Calculated over a sliding window W of observed destination ports per host.
   - H(P) = 0.0 for single-port traffic (e.g. HTTP on port 80).
   - H(P) > 5.0 bits during multi-port reconnaissance (e.g. Nmap scan).
   - Returns 0.0 if port window is empty; ignores p_i == 0.

2. Exponentially Weighted Moving Average (EWMA) Tracker:
   - Moving mean: S_t = alpha * X_t + (1 - alpha) * S_{t-1} (default alpha=0.2)
   - Moving variance: sigma^2_t = (1 - alpha) * sigma^2_{t-1} + alpha * (X_t - S_t)^2
   - Z-Score: z_t = (X_t - S_{t-1}) / sigma_{t-1} with variance floor epsilon to prevent zero division
   - Warmup: Suppresses anomaly alerts for the first 10 ticks (warmup_ticks=10)

3. Decision Rules:
   - Volumetric flood (SYN / UDP flood):
     (z_pkt_rate > 3.0 and packet_rate > 50.0 pps) or (z_flow_rate > 3.0)
   - Port scan (Nmap):
     (H(P) > 3.0 bits and unique_ports >= 10) or (z_entropy > 2.5 and z_flow_rate > 2.0)
"""

import math
from collections import Counter, deque
from typing import Dict, List, Optional, Any


class EWMATracker:
    """Tracks Exponentially Weighted Moving Average and standard deviation.

    Equations:
        S_t = alpha * X_t + (1 - alpha) * S_{t-1}
        sigma^2_t = (1 - alpha) * sigma^2_{t-1} + alpha * (X_t - S_t)^2
        z_t = (X_t - S_{t-1}) / sigma_{t-1}
    """

    def __init__(self, alpha: float = 0.2, variance_floor: float = 1e-4):
        self.alpha = float(alpha)
        self.variance_floor = float(variance_floor)
        self.mean: Optional[float] = None
        self.variance: Optional[float] = None
        self.count: int = 0

    def get_z_score(self, x: float) -> float:
        """Calculate standardized z-score against current moving statistics without modifying state."""
        if self.count == 0 or self.mean is None:
            return 0.0
        prev_var = max(self.variance if self.variance is not None else self.variance_floor, self.variance_floor)
        prev_std = math.sqrt(prev_var)
        return float((x - self.mean) / prev_std)

    def update(self, x: float) -> float:
        """Update tracker with new observation X_t and return z-score z_t."""
        x = float(x)
        if self.count == 0:
            self.mean = x
            self.variance = self.variance_floor
            self.count = 1
            return 0.0

        prev_mean = self.mean
        prev_var = max(self.variance, self.variance_floor)
        prev_std = math.sqrt(prev_var)

        # Standardized z-score against prior moving statistics
        z_score = (x - prev_mean) / prev_std

        # Update moving mean
        new_mean = self.alpha * x + (1.0 - self.alpha) * prev_mean

        # Update moving variance
        new_var = (1.0 - self.alpha) * prev_var + self.alpha * ((x - new_mean) ** 2)
        new_var = max(new_var, self.variance_floor)

        self.mean = new_mean
        self.variance = new_var
        self.count += 1

        return float(z_score)

    def reset(self):
        """Reset EWMA tracker state."""
        self.mean = None
        self.variance = None
        self.count = 0


def calculate_shannon_entropy(ports: List[int]) -> float:
    """Calculate Destination-Port Shannon Entropy H(P) = -sum(p_i * log2(p_i)).

    Args:
        ports: List of destination port numbers in the window.

    Returns:
        float: Shannon entropy in bits (>= 0.0). Returns 0.0 if empty or single port.
    """
    if not ports:
        return 0.0

    total_count = len(ports)
    if total_count <= 1:
        return 0.0

    port_counts = Counter(ports)
    entropy = 0.0
    for count in port_counts.values():
        if count <= 0:
            continue
        p_i = count / total_count
        entropy -= p_i * math.log2(p_i)

    return max(0.0, float(entropy))


class HostState:
    """Maintains statistical state and sliding port window for a single host."""

    def __init__(self, alpha: float = 0.2, window_size: int = 100, variance_floor: float = 1e-4):
        self.port_window: deque = deque(maxlen=window_size)
        self.ewma_pkt_rate = EWMATracker(alpha=alpha, variance_floor=variance_floor)
        self.ewma_flow_rate = EWMATracker(alpha=alpha, variance_floor=variance_floor)
        self.ewma_entropy = EWMATracker(alpha=alpha, variance_floor=variance_floor)
        self.tick_count: int = 0

    def add_ports(self, ports: List[int]):
        """Append observed destination ports to the sliding window."""
        if ports:
            self.port_window.extend(ports)

    def get_entropy(self) -> float:
        """Compute current Shannon entropy over the sliding port window."""
        return calculate_shannon_entropy(list(self.port_window))

    def get_unique_ports_count(self) -> int:
        """Count unique destination ports in current window."""
        return len(set(self.port_window))


class StatisticalAnomalyDetector:
    """Baseline statistical anomaly detector using EWMA z-scores and Shannon entropy.

    Interface adheres to PROJECT.md Contract 3:
    StatisticalAnomalyDetector(alpha=0.2, z_threshold=3.0, entropy_threshold=3.0, warmup_ticks=10)
    update(host_ip: str, packet_rate: float, flow_rate: float, dst_ports: list) -> dict
    """

    def __init__(
        self,
        alpha: float = 0.2,
        z_threshold: float = 3.0,
        entropy_threshold: float = 3.0,
        warmup_ticks: int = 10,
        window_size: int = 100,
        variance_floor: float = 1e-4,
    ):
        self.alpha = float(alpha)
        self.z_threshold = float(z_threshold)
        self.entropy_threshold = float(entropy_threshold)
        self.warmup_ticks = int(warmup_ticks)
        self.window_size = int(window_size)
        self.variance_floor = float(variance_floor)

        self.hosts: Dict[str, HostState] = {}

    def _get_or_create_host(self, host_ip: str) -> HostState:
        if host_ip not in self.hosts:
            self.hosts[host_ip] = HostState(
                alpha=self.alpha,
                window_size=self.window_size,
                variance_floor=self.variance_floor,
            )
        return self.hosts[host_ip]

    @staticmethod
    def compute_entropy(ports: List[int]) -> float:
        """Static utility to calculate destination-port Shannon entropy."""
        return calculate_shannon_entropy(ports)

    def evaluate_telemetry(
        self,
        host_ip: str,
        packet_rate: float,
        flow_rate: float,
        dst_ports: Optional[List[int]] = None,
    ) -> Dict[str, Any]:
        """Evaluate host telemetry metrics against current baseline without mutating state.

        Args:
            host_ip: IPv4 address of source host.
            packet_rate: Packets per second.
            flow_rate: Flows per second.
            dst_ports: Observed destination ports.

        Returns:
            dict containing anomaly detection results and z-scores.
        """
        host = self._get_or_create_host(host_ip)

        if dst_ports:
            observed_ports = list(host.port_window) + list(dst_ports)
            entropy = calculate_shannon_entropy(observed_ports)
            unique_ports = len(set(observed_ports))
        else:
            entropy = host.get_entropy()
            unique_ports = host.get_unique_ports_count()

        z_pkt_rate = host.ewma_pkt_rate.get_z_score(packet_rate)
        z_flow_rate = host.ewma_flow_rate.get_z_score(flow_rate)
        z_entropy = host.ewma_entropy.get_z_score(entropy)

        if host.tick_count < self.warmup_ticks:
            return {
                "is_anomaly": False,
                "attack_type": None,
                "host_ip": host_ip,
                "entropy": float(round(entropy, 4)),
                "z_pkt_rate": float(round(z_pkt_rate, 4)),
                "z_flow_rate": float(round(z_flow_rate, 4)),
                "z_entropy": float(round(z_entropy, 4)),
            }

        is_port_scan = (
            (entropy > self.entropy_threshold and unique_ports >= 10)
            or (z_entropy > 2.5 and z_flow_rate > 2.0)
        )

        is_volumetric_flood = (
            (z_pkt_rate > self.z_threshold and packet_rate > 50.0)
            or (z_flow_rate > self.z_threshold and flow_rate > 10.0)
        )

        attack_type: Optional[str] = None
        if is_port_scan:
            attack_type = "port_scan"
        elif is_volumetric_flood:
            attack_type = "volumetric_flood"

        return {
            "is_anomaly": attack_type is not None,
            "attack_type": attack_type,
            "host_ip": host_ip,
            "entropy": float(round(entropy, 4)),
            "z_pkt_rate": float(round(z_pkt_rate, 4)),
            "z_flow_rate": float(round(z_flow_rate, 4)),
            "z_entropy": float(round(z_entropy, 4)),
        }

    def update(
        self,
        host_ip: str,
        packet_rate: float,
        flow_rate: float,
        dst_ports: Optional[List[int]] = None,
    ) -> Dict[str, Any]:
        """Update host telemetry metrics and evaluate anomaly detection rules.

        Args:
            host_ip: IPv4 address of source host (e.g. '10.0.0.1').
            packet_rate: Packets per second originating from host.
            flow_rate: New flows per second originating from host.
            dst_ports: List of destination ports observed during this interval.

        Returns:
            dict containing:
            {
                'is_anomaly': bool,
                'attack_type': str or None,  # 'volumetric_flood', 'port_scan', or None
                'host_ip': str,
                'entropy': float,
                'z_pkt_rate': float,
                'z_flow_rate': float,
                'z_entropy': float
            }
        """
        host = self._get_or_create_host(host_ip)
        host.tick_count += 1

        if dst_ports:
            host.add_ports(dst_ports)

        entropy = host.get_entropy()
        unique_ports = host.get_unique_ports_count()

        # Update EWMA trackers and compute standardized z-scores
        z_pkt_rate = host.ewma_pkt_rate.update(packet_rate)
        z_flow_rate = host.ewma_flow_rate.update(flow_rate)
        z_entropy = host.ewma_entropy.update(entropy)

        # Warmup suppression: suppress anomaly alerts for first warmup_ticks
        if host.tick_count <= self.warmup_ticks:
            return {
                "is_anomaly": False,
                "attack_type": None,
                "host_ip": host_ip,
                "entropy": float(round(entropy, 4)),
                "z_pkt_rate": float(round(z_pkt_rate, 4)),
                "z_flow_rate": float(round(z_flow_rate, 4)),
                "z_entropy": float(round(z_entropy, 4)),
            }

        # Decision Rule 1: Port scan (Nmap)
        # H(P) > 3.0 bits and unique ports >= 10, or z_entropy > 2.5 and z_flow_rate > 2.0
        is_port_scan = (
            (entropy > self.entropy_threshold and unique_ports >= 10)
            or (z_entropy > 2.5 and z_flow_rate > 2.0)
        )

        # Decision Rule 2: Volumetric flood (SYN / UDP flood)
        # z_pkt_rate > 3.0 and packet_rate > 50 pps, or z_flow_rate > 3.0
        is_volumetric_flood = (
            (z_pkt_rate > self.z_threshold and packet_rate > 50.0)
            or (z_flow_rate > self.z_threshold and flow_rate > 10.0)
        )

        attack_type: Optional[str] = None
        if is_port_scan:
            attack_type = "port_scan"
        elif is_volumetric_flood:
            attack_type = "volumetric_flood"

        is_anomaly = attack_type is not None

        return {
            "is_anomaly": is_anomaly,
            "attack_type": attack_type,
            "host_ip": host_ip,
            "entropy": float(round(entropy, 4)),
            "z_pkt_rate": float(round(z_pkt_rate, 4)),
            "z_flow_rate": float(round(z_flow_rate, 4)),
            "z_entropy": float(round(z_entropy, 4)),
        }

    def reset_host(self, host_ip: str):
        """Reset tracker for a single host."""
        if host_ip in self.hosts:
            del self.hosts[host_ip]

    def reset(self):
        """Reset all host tracking state."""
        self.hosts.clear()
