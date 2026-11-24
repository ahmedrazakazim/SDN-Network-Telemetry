"""
Prometheus Metrics Exporter for SDN Network Telemetry.

Exposes OpenFlow flow statistics, port metrics, host-level traffic rates,
Shannon port entropy, statistical anomaly detection alerts, and mitigation
states to Prometheus via HTTP port 8000 (configurable).

Implements dynamic cardinality pruning for ephemeral flow labelsets to prevent
memory exhaustion during SYN floods and Nmap port scans.
"""

import logging
from typing import Any, Dict, List, Optional, Set, Tuple

from prometheus_client import CollectorRegistry, Gauge, generate_latest, start_http_server

logger = logging.getLogger(__name__)


class PrometheusTelemetryExporter:
    """
    Prometheus metrics exporter managing telemetry gauges and cardinality pruning.
    """

    def __init__(self, port: int = 8000, host: str = "0.0.0.0",
                 registry: Optional[CollectorRegistry] = None):
        self.port = port
        self.host = host
        self.registry = registry if registry is not None else CollectorRegistry(auto_describe=True)
        self.server_started = False
        self._server_handle = None

        # Track active labelsets for cardinality pruning
        # Set of (dpid_str, src_ip, dst_ip, ip_proto_str)
        self.active_flow_keys: Set[Tuple[str, str, str, str]] = set()

        # Track active port keys: Set of (dpid_str, port_no_str)
        self.active_port_keys: Set[Tuple[str, str]] = set()

        # Track active alert keys: Set of (host, attack_type)
        self.active_alert_keys: Set[Tuple[str, str]] = set()

        # Track active mitigation keys: Set of (offending_ip,)
        self.active_mitigation_keys: Set[Tuple[str]] = set()

        # Track active z-score keys: Set of (host, metric)
        self.active_z_score_keys: Set[Tuple[str, str]] = set()

        # Initialize Gauges
        self._init_gauges()

    def _init_gauges(self) -> None:
        """Register all Prometheus gauges with the registry."""
        flow_labels = ["dpid", "src_ip", "dst_ip", "ip_proto"]

        # Flow-level gauges
        self.flow_packet_rate = Gauge(
            "sdn_flow_packet_rate",
            "Instantaneous packet rate for OpenFlow flow (packets/sec)",
            flow_labels,
            registry=self.registry
        )
        self.flow_byte_rate = Gauge(
            "sdn_flow_byte_rate",
            "Instantaneous byte rate for OpenFlow flow (bytes/sec)",
            flow_labels,
            registry=self.registry
        )
        self.flow_packet_count = Gauge(
            "sdn_flow_packet_count",
            "Cumulative packet count for OpenFlow flow",
            flow_labels,
            registry=self.registry
        )
        self.flow_byte_count = Gauge(
            "sdn_flow_byte_count",
            "Cumulative byte count for OpenFlow flow",
            flow_labels,
            registry=self.registry
        )
        self.flow_duration_seconds = Gauge(
            "sdn_flow_duration_seconds",
            "Flow lifetime duration in seconds",
            flow_labels,
            registry=self.registry
        )

        # Switch-level active flow count
        self.active_flows_count = Gauge(
            "sdn_active_flows_count",
            "Total number of active OpenFlow flows on switch datapath",
            ["dpid"],
            registry=self.registry
        )

        # Port-level gauges
        port_labels = ["dpid", "port_no"]
        self.port_rx_packets = Gauge(
            "sdn_port_rx_packets",
            "Port received packet count",
            port_labels,
            registry=self.registry
        )
        self.port_tx_packets = Gauge(
            "sdn_port_tx_packets",
            "Port transmitted packet count",
            port_labels,
            registry=self.registry
        )
        self.port_rx_bytes = Gauge(
            "sdn_port_rx_bytes",
            "Port received byte count",
            port_labels,
            registry=self.registry
        )
        self.port_tx_bytes = Gauge(
            "sdn_port_tx_bytes",
            "Port transmitted byte count",
            port_labels,
            registry=self.registry
        )
        self.port_rx_dropped = Gauge(
            "sdn_port_rx_dropped",
            "Port received packets dropped",
            port_labels,
            registry=self.registry
        )
        self.port_tx_dropped = Gauge(
            "sdn_port_tx_dropped",
            "Port transmitted packets dropped",
            port_labels,
            registry=self.registry
        )

        # Host-level telemetry gauges
        self.host_packet_rate = Gauge(
            "sdn_host_packet_rate",
            "Aggregate packet rate per source host (packets/sec)",
            ["host"],
            registry=self.registry
        )
        self.host_port_entropy = Gauge(
            "sdn_host_port_entropy",
            "Shannon entropy of destination ports targeted by host",
            ["host"],
            registry=self.registry
        )
        self.host_z_score = Gauge(
            "sdn_host_z_score",
            "Standardized EWMA z-score for host metric",
            ["host", "metric"],
            registry=self.registry
        )

        # Anomaly and Mitigation status gauges
        self.anomaly_alert = Gauge(
            "sdn_anomaly_alert",
            "Anomaly alert state for host (1=alert active, 0=normal)",
            ["host", "attack_type"],
            registry=self.registry
        )
        self.mitigation_active = Gauge(
            "sdn_mitigation_active",
            "Mitigation active status for offending host IP (1=blocked, 0=unblocked)",
            ["offending_ip"],
            registry=self.registry
        )

        # Controller resource metrics
        self.controller_cpu_percent = Gauge(
            "sdn_controller_cpu_percent",
            "Controller CPU utilization percentage",
            registry=self.registry
        )

    def start_server(self, port: Optional[int] = None, host: Optional[str] = None) -> bool:
        """
        Start the Prometheus metrics HTTP server on specified port and host.
        Gracefully handles already-running server instances.
        """
        if self.server_started:
            return True

        if port is not None:
            self.port = port
        if host is not None:
            self.host = host

        try:
            start_http_server(self.port, addr=self.host, registry=self.registry)
            self.server_started = True
            logger.info("Prometheus telemetry exporter running at http://%s:%d/metrics", self.host, self.port)
            return True
        except OSError as e:
            logger.warning("Could not start Prometheus HTTP server on %s:%d: %s", self.host, self.port, e)
            return False

    def update_flow_metrics(self, flow_features: List[Dict[str, Any]]) -> None:
        """
        Update flow-level gauges and execute cardinality pruning.

        Vanished flows (present in previous snapshot but missing in current)
        are cleanly removed via gauge.remove(*labels) to prevent memory leaks.
        """
        current_flow_keys: Set[Tuple[str, str, str, str]] = set()
        flows_per_dpid: Dict[str, int] = {}

        for record in flow_features:
            dpid_str = str(record.get("dpid", ""))
            match = record.get("match", {})

            # Filter or extract IPv4 addresses
            src_ip = match.get("ipv4_src") or "0.0.0.0"
            dst_ip = match.get("ipv4_dst") or "0.0.0.0"
            ip_proto = str(match.get("ip_proto", "0"))

            label_key = (dpid_str, src_ip, dst_ip, ip_proto)
            current_flow_keys.add(label_key)

            # Update count per switch
            flows_per_dpid[dpid_str] = flows_per_dpid.get(dpid_str, 0) + 1

            # Update flow gauges
            self.flow_packet_rate.labels(*label_key).set(record.get("packet_rate", 0.0))
            self.flow_byte_rate.labels(*label_key).set(record.get("byte_rate", 0.0))
            self.flow_packet_count.labels(*label_key).set(record.get("packet_count", 0))
            self.flow_byte_count.labels(*label_key).set(record.get("byte_count", 0))
            self.flow_duration_seconds.labels(*label_key).set(record.get("duration_sec", 0.0))

        # Update active flow counts per DPID
        for dpid_str, count in flows_per_dpid.items():
            self.active_flows_count.labels(dpid=dpid_str).set(count)

        # Cardinality pruning: remove vanished flow labelsets
        vanished_keys = self.active_flow_keys - current_flow_keys
        for key in vanished_keys:
            try:
                self.flow_packet_rate.remove(*key)
                self.flow_byte_rate.remove(*key)
                self.flow_packet_count.remove(*key)
                self.flow_byte_count.remove(*key)
                self.flow_duration_seconds.remove(*key)
            except (KeyError, ValueError):
                pass

        self.active_flow_keys = current_flow_keys

    def update_port_metrics(self, port_features: List[Dict[str, Any]]) -> None:
        """
        Update switch port gauges from port features.
        """
        current_port_keys: Set[Tuple[str, str]] = set()

        for record in port_features:
            dpid_str = str(record.get("dpid", ""))
            port_no_str = str(record.get("port_no", ""))
            label_key = (dpid_str, port_no_str)
            current_port_keys.add(label_key)

            self.port_rx_packets.labels(*label_key).set(record.get("rx_packets", 0))
            self.port_tx_packets.labels(*label_key).set(record.get("tx_packets", 0))
            self.port_rx_bytes.labels(*label_key).set(record.get("rx_bytes", 0))
            self.port_tx_bytes.labels(*label_key).set(record.get("tx_bytes", 0))
            self.port_rx_dropped.labels(*label_key).set(record.get("rx_dropped", 0))
            self.port_tx_dropped.labels(*label_key).set(record.get("tx_dropped", 0))

        self.active_port_keys = current_port_keys

    def update_host_metrics(self, host_metrics: Dict[str, Dict[str, Any]]) -> None:
        """
        Update host-level packet rates and port metrics.
        """
        for host_ip, metrics in host_metrics.items():
            pkt_rate = metrics.get("packet_rate", 0.0)
            self.host_packet_rate.labels(host=host_ip).set(pkt_rate)

    def update_host_entropy(self, host_ip: str, entropy: float) -> None:
        """
        Update destination port Shannon entropy gauge for host.
        """
        self.host_port_entropy.labels(host=host_ip).set(float(entropy))

    def update_host_z_score(self, host_ip: str, metric_name: str, z_score: float) -> None:
        """
        Update standardized EWMA z-score for a host and metric.
        """
        label_key = (host_ip, metric_name)
        self.active_z_score_keys.add(label_key)
        self.host_z_score.labels(host=host_ip, metric=metric_name).set(float(z_score))

    def update_anomaly_alert(self, host_ip: str, attack_type: str, is_active: bool = True) -> None:
        """
        Update anomaly alert state (1 for active alert, 0 for clear).
        """
        label_key = (host_ip, attack_type)
        self.active_alert_keys.add(label_key)
        self.anomaly_alert.labels(host=host_ip, attack_type=attack_type).set(1.0 if is_active else 0.0)

    def update_mitigation_active(self, offending_ip: str, is_active: bool = True) -> None:
        """
        Update mitigation active state (1 for blocked, 0 for unblocked).
        """
        label_key = (offending_ip,)
        self.active_mitigation_keys.add(label_key)
        self.mitigation_active.labels(offending_ip=offending_ip).set(1.0 if is_active else 0.0)

    def update_controller_cpu(self, cpu_percent: float) -> None:
        """
        Update controller CPU utilization gauge.
        """
        self.controller_cpu_percent.set(float(cpu_percent))

    def get_metrics_text(self) -> str:
        """
        Return the current scraped metrics in Prometheus exposition text format.
        Useful for programmatic inspection and unit testing.
        """
        return generate_latest(self.registry).decode("utf-8")

    def prune_all(self) -> None:
        """
        Clear all dynamically registered metric time series from flow gauges.
        """
        for key in list(self.active_flow_keys):
            try:
                self.flow_packet_rate.remove(*key)
                self.flow_byte_rate.remove(*key)
                self.flow_packet_count.remove(*key)
                self.flow_byte_count.remove(*key)
                self.flow_duration_seconds.remove(*key)
            except (KeyError, ValueError):
                pass
        self.active_flow_keys.clear()
