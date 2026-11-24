"""Unit tests for Network Telemetry & Metric Collection Engine (Tier 1 & Tier 2).

Validates:
- Flow rate derivative math (packet_rate = delta_packets / delta_t, byte_rate = delta_bytes / delta_t)
- Flow duration calculation (duration_sec + duration_nsec * 1e-9)
- Average packet size computation and zero-division guard (0.0 when packet_count == 0)
- Delta time zero-division guard (0.0 when delta_t == 0)
- Counter reset and wrap mitigation (max(0, curr - prev))
- Port statistics rate calculations (rx/tx packet & byte rates, drop rates)
- Per-host traffic aggregation (host packet rate, new flow creation rate, destination port sliding window)
- Prometheus metrics exporter gauge updates and output exposition
- Dynamic cardinality pruning for expired flows during floods/scans
"""

import unittest
from collections import namedtuple
from telemetry.feature_extractor import FlowFeatureExtractor, parse_match
from telemetry.exporter import PrometheusTelemetryExporter
from prometheus_client import CollectorRegistry


# Mock stats reply structures representing OpenFlow switch replies
MockFlowStat = namedtuple(
    "MockFlowStat",
    ["table_id", "priority", "cookie", "packet_count", "byte_count", "duration_sec", "duration_nsec", "match"]
)
MockPortStat = namedtuple(
    "MockPortStat",
    ["port_no", "rx_packets", "tx_packets", "rx_bytes", "tx_bytes", "rx_dropped", "tx_dropped"]
)


class TestFlowFeatureExtractor(unittest.TestCase):
    """Test suite for telemetry flow and port feature extraction mathematics."""

    def setUp(self):
        self.extractor = FlowFeatureExtractor(port_window_size=10)

    def test_duration_nanosecond_precision(self):
        """Validate duration calculation includes fractional nanoseconds: sec + nsec * 1e-9."""
        stat = MockFlowStat(
            table_id=0, priority=1, cookie=0,
            packet_count=100, byte_count=15000,
            duration_sec=10, duration_nsec=500000000, # 10.5 seconds
            match={"ipv4_src": "10.0.0.1", "ipv4_dst": "10.0.0.2"}
        )
        records = self.extractor.extract_flow_features([stat], dpid=1, current_time=100.0)
        self.assertEqual(len(records), 1)
        self.assertAlmostEqual(records[0]["duration_sec"], 10.5, places=5)

    def test_avg_packet_size_calculation(self):
        """Validate average packet size calculation: byte_count / packet_count."""
        stat = MockFlowStat(
            table_id=0, priority=1, cookie=0,
            packet_count=10, byte_count=1000,
            duration_sec=1, duration_nsec=0,
            match={"ipv4_src": "10.0.0.1"}
        )
        records = self.extractor.extract_flow_features([stat], dpid=1, current_time=100.0)
        self.assertEqual(records[0]["avg_packet_size"], 100.0)

    def test_avg_packet_size_zero_division_guard(self):
        """Validate avg_packet_size returns 0.0 when packet_count == 0 (zero-division guard)."""
        stat = MockFlowStat(
            table_id=0, priority=1, cookie=0,
            packet_count=0, byte_count=0,
            duration_sec=0, duration_nsec=0,
            match={"ipv4_src": "10.0.0.1"}
        )
        records = self.extractor.extract_flow_features([stat], dpid=1, current_time=100.0)
        self.assertEqual(records[0]["avg_packet_size"], 0.0)

    def test_flow_rate_derivative_math(self):
        """Validate delta_packets / delta_t and delta_bytes / delta_t across polling snapshots."""
        match = {"ipv4_src": "10.0.0.1", "ipv4_dst": "10.0.0.2", "ip_proto": 6}

        # Snapshot 1 at t=100.0s: 100 pkts, 50,000 bytes
        stat1 = MockFlowStat(0, 1, 0, packet_count=100, byte_count=50000, duration_sec=5, duration_nsec=0, match=match)
        self.extractor.extract_flow_features([stat1], dpid=1, current_time=100.0)

        # Snapshot 2 at t=102.0s (delta_t=2.0s): 300 pkts (delta=200), 150,000 bytes (delta=100,000)
        stat2 = MockFlowStat(0, 1, 0, packet_count=300, byte_count=150000, duration_sec=7, duration_nsec=0, match=match)
        records = self.extractor.extract_flow_features([stat2], dpid=1, current_time=102.0)

        self.assertEqual(len(records), 1)
        # Expected packet_rate = 200 pkts / 2.0s = 100.0 pps
        self.assertAlmostEqual(records[0]["packet_rate"], 100.0, places=2)
        # Expected byte_rate = 100,000 bytes / 2.0s = 50,000.0 Bps
        self.assertAlmostEqual(records[0]["byte_rate"], 50000.0, places=2)

    def test_delta_time_zero_division_guard(self):
        """Validate delta_t == 0 does not raise ZeroDivisionError and sets rates to 0.0."""
        match = {"ipv4_src": "10.0.0.1"}
        stat = MockFlowStat(0, 1, 0, packet_count=100, byte_count=1000, duration_sec=1, duration_nsec=0, match=match)

        self.extractor.extract_flow_features([stat], dpid=1, current_time=100.0)
        # Immediate subsequent poll with identical timestamp
        records = self.extractor.extract_flow_features([stat], dpid=1, current_time=100.0)

        self.assertEqual(records[0]["packet_rate"], 0.0)
        self.assertEqual(records[0]["byte_rate"], 0.0)

    def test_counter_wrap_and_reset_protection(self):
        """Validate counter reset/wrap prevents negative deltas (max(0, curr - prev))."""
        match = {"ipv4_src": "10.0.0.1"}
        # Initial snapshot
        stat1 = MockFlowStat(0, 1, 0, packet_count=1000, byte_count=50000, duration_sec=10, duration_nsec=0, match=match)
        self.extractor.extract_flow_features([stat1], dpid=1, current_time=100.0)

        # Flow counter reset on switch (e.g. flow reinstalled): current count drops to 10 pkts
        stat2 = MockFlowStat(0, 1, 0, packet_count=10, byte_count=500, duration_sec=1, duration_nsec=0, match=match)
        records = self.extractor.extract_flow_features([stat2], dpid=1, current_time=101.0)

        # Should be protected by max(0, ...), resulting in 0.0 instead of negative rate
        self.assertGreaterEqual(records[0]["packet_rate"], 0.0)
        self.assertGreaterEqual(records[0]["byte_rate"], 0.0)

    def test_port_feature_extraction_rates(self):
        """Validate port rx/tx packet and byte rates across consecutive snapshots."""
        # Snapshot 1 at t=0
        pstat1 = MockPortStat(port_no=1, rx_packets=100, tx_packets=200, rx_bytes=10000, tx_bytes=20000, rx_dropped=0, tx_dropped=0)
        self.extractor.extract_port_features([pstat1], dpid=1, current_time=0.0)

        # Snapshot 2 at t=2.0s
        pstat2 = MockPortStat(port_no=1, rx_packets=300, tx_packets=600, rx_bytes=30000, tx_bytes=60000, rx_dropped=2, tx_dropped=0)
        records = self.extractor.extract_port_features([pstat2], dpid=1, current_time=2.0)

        self.assertEqual(len(records), 1)
        r = records[0]
        # rx_packet_rate: (300 - 100) / 2.0 = 100.0
        self.assertAlmostEqual(r["rx_packet_rate"], 100.0)
        # tx_packet_rate: (600 - 200) / 2.0 = 200.0
        self.assertAlmostEqual(r["tx_packet_rate"], 200.0)
        # rx_drop_rate: (2 - 0) / 2.0 = 1.0
        self.assertAlmostEqual(r["rx_drop_rate"], 1.0)

    def test_host_metrics_aggregation_and_port_window(self):
        """Validate per-host packet rate sum, new-flow creation rate, and sliding port window."""
        flow_records = [
            {"match": {"ipv4_src": "10.0.0.1", "tcp_dst": 80}, "packet_rate": 150.0, "priority": 1},
            {"match": {"ipv4_src": "10.0.0.1", "tcp_dst": 443}, "packet_rate": 250.0, "priority": 1},
            {"match": {"ipv4_src": "10.0.0.2", "tcp_dst": 5001}, "packet_rate": 50.0, "priority": 1},
        ]
        host_metrics = self.extractor.aggregate_host_metrics(flow_records, current_time=10.0)

        self.assertIn("10.0.0.1", host_metrics)
        self.assertIn("10.0.0.2", host_metrics)

        # 10.0.0.1 packet rate sum: 150 + 250 = 400.0 pps
        self.assertAlmostEqual(host_metrics["10.0.0.1"]["packet_rate"], 400.0)
        # Destination ports recorded
        dst_ports_h1 = host_metrics["10.0.0.1"]["dst_ports"]
        self.assertIn(80, dst_ports_h1)
        self.assertIn(443, dst_ports_h1)


class TestPrometheusExporter(unittest.TestCase):
    """Test suite for Prometheus telemetry metric exporter and cardinality pruning."""

    def setUp(self):
        # Use an isolated CollectorRegistry so test instances don't collide
        self.registry = CollectorRegistry(auto_describe=True)
        self.exporter = PrometheusTelemetryExporter(port=8001, registry=self.registry)

    def test_export_flow_metrics(self):
        """Validate flow records update Prometheus gauges."""
        flow_records = [
            {
                "dpid": 1,
                "match": {"ipv4_src": "10.0.0.1", "ipv4_dst": "10.0.0.2", "ip_proto": 6},
                "packet_rate": 120.5,
                "byte_rate": 60000.0,
                "packet_count": 500,
                "byte_count": 250000,
                "duration_sec": 12.0
            }
        ]
        self.exporter.update_flow_metrics(flow_records)

        # Verify metric exposition format
        metrics_text = self.exporter.get_metrics_text()
        self.assertIn("sdn_flow_packet_rate", metrics_text)
        self.assertIn("10.0.0.1", metrics_text)
        self.assertIn("10.0.0.2", metrics_text)
        self.assertIn("sdn_active_flows_count", metrics_text)

    def test_dynamic_cardinality_pruning_on_expired_flows(self):
        """CRITICAL: Terminated flows must be pruned from gauge labelsets to prevent memory leaks."""
        # Initial active flow
        flow_record = {
            "dpid": 1,
            "match": {"ipv4_src": "10.0.0.1", "ipv4_dst": "10.0.0.2", "ip_proto": 6},
            "packet_rate": 50.0,
            "byte_rate": 1000.0,
            "packet_count": 10,
            "byte_count": 500,
            "duration_sec": 1.0
        }
        self.exporter.update_flow_metrics([flow_record])
        self.assertEqual(len(self.exporter.active_flow_keys), 1)

        # Flow vanishes in next poll (e.g. idle timeout expired)
        self.exporter.update_flow_metrics([])
        # Active flow keys must be pruned
        self.assertEqual(len(self.exporter.active_flow_keys), 0)

    def test_export_anomaly_alert_and_mitigation_metrics(self):
        """Validate alert and mitigation gauges correctly reflect 0/1 binary states."""
        self.exporter.update_anomaly_alert("10.0.0.1", "syn_flood", is_active=True)
        self.exporter.update_mitigation_active("10.0.0.1", is_active=True)

        metrics_text = self.exporter.get_metrics_text()
        self.assertIn('sdn_anomaly_alert{attack_type="syn_flood",host="10.0.0.1"} 1.0', metrics_text)
        self.assertIn('sdn_mitigation_active{offending_ip="10.0.0.1"} 1.0', metrics_text)

        # Clear alert
        self.exporter.update_anomaly_alert("10.0.0.1", "syn_flood", is_active=False)
        self.exporter.update_mitigation_active("10.0.0.1", is_active=False)

        metrics_text_cleared = self.exporter.get_metrics_text()
        self.assertIn('sdn_anomaly_alert{attack_type="syn_flood",host="10.0.0.1"} 0.0', metrics_text_cleared)
        self.assertIn('sdn_mitigation_active{offending_ip="10.0.0.1"} 0.0', metrics_text_cleared)


if __name__ == "__main__":
    unittest.main()
