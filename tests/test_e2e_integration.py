"""End-to-End Integration Tests for Closed-Loop Pipeline (Tier 3 & Tier 4).

Validates the complete closed-loop SDN defense lifecycle:
    Telemetry -> Feature Extraction -> Anomaly Detection -> Automated Mitigation -> Prometheus Logging

Exercises Tier 4 Application Scenarios from TEST_INFRA.md:
1. Scenario 1: Baseline Benign Quiescent State:
   - Benign flows pass through switches
   - Telemetry calculates baseline rates
   - No anomalies triggered, no drop rules installed
2. Scenario 2: High-Rate SYN Flood Attack & Automated Dynamic Mitigation:
   - Attacking host (h1: 10.0.0.1) launches volumetric flood
   - Telemetry extractor calculates packet rate derivative spike
   - Statistical detector triggers volumetric_flood alert
   - Mitigation engine installs priority=1000 drop rule on all switches
   - Prometheus exporter logs alert and mitigation state = 1.0
3. Scenario 3: Stealth Nmap Port Scan Reconnaissance:
   - Host scans wide range of destination ports
   - Telemetry collects sliding port window
   - Destination-port Shannon entropy spikes (> 3.0 bits)
   - Port scan alert triggers and isolates attacker
4. Scenario 4: Non-Disruption Guarantee for Benign Hosts During Attack:
   - Attacker (h1) is isolated
   - Benign hosts (h3, h4) remain unblocked with 0% packet disruption
   - Mitigation engine rejects attempts to block protected benign hosts
5. Scenario 5: Mitigation Unblock & System Recovery:
   - Offending host is unblocked via API
   - Drop rules deleted (OFPFC_DELETE_STRICT) across all switches
   - Exporter metrics transition back to normal (0.0)
"""

import time
import unittest
from collections import namedtuple
from controller.flow_manager import ofproto_v1_3, ofproto_parser
from controller.sdn_controller import SDNController
from telemetry.feature_extractor import FlowFeatureExtractor
from telemetry.exporter import PrometheusTelemetryExporter
from detection.baseline_detector import StatisticalAnomalyDetector
from detection.ml_detector import IsolationForestAnomalyDetector
from mitigation.mitigation_engine import MitigationEngine
from prometheus_client import CollectorRegistry


MockOFPFlowStat = namedtuple(
    "MockOFPFlowStat",
    ["table_id", "priority", "cookie", "packet_count", "byte_count", "duration_sec", "duration_nsec", "match"]
)


class MockSwitchDatapath:
    """Mock OpenFlow 1.3 switch datapath for pipeline integration testing."""

    def __init__(self, dpid: int):
        self.id = dpid
        self.ofproto = ofproto_v1_3
        self.ofproto_parser = ofproto_parser
        self.sent_msgs = []

    def send_msg(self, msg):
        self.sent_msgs.append(msg)


class ClosedLoopSDNPipeline:
    """Integrated SDN Closed-Loop Defense Pipeline Testbed Harness."""

    def __init__(self, poll_interval: float = 1.0):
        self.poll_interval = poll_interval
        # 1. Controller & Datapaths (s1=root, s2=pod1, s3=pod2)
        self.controller = SDNController()
        self.datapaths = {
            1: MockSwitchDatapath(dpid=1),
            2: MockSwitchDatapath(dpid=2),
            3: MockSwitchDatapath(dpid=3),
        }
        for dpid, dp in self.datapaths.items():
            self.controller.datapaths[dpid] = dp
            self.controller.mac_to_port[dpid] = {}

        # 2. Telemetry Extractor & Prometheus Exporter
        self.extractor = FlowFeatureExtractor(port_window_size=100)
        self.registry = CollectorRegistry(auto_describe=True)
        self.exporter = PrometheusTelemetryExporter(port=8002, registry=self.registry)

        # 3. Anomaly Detectors
        self.detector = StatisticalAnomalyDetector(
            alpha=0.2,
            z_threshold=3.0,
            entropy_threshold=3.0,
            warmup_ticks=10
        )

        # 4. Mitigation Engine
        self.mitigation = MitigationEngine(
            controller=self.controller,
            default_timeout=300,
            protected_hosts={"10.0.0.3", "10.0.0.4"}
        )

    def process_telemetry_tick(self, switch_raw_stats: dict, current_time: float):
        """Simulate single telemetry polling interval cycle."""
        all_flow_records = []

        # Step 1: Feature Extraction
        for dpid, stats in switch_raw_stats.items():
            records = self.extractor.extract_flow_features(stats, dpid=dpid, current_time=current_time)
            all_flow_records.extend(records)

        # Step 2: Per-Host Aggregation
        host_metrics = self.extractor.aggregate_host_metrics(all_flow_records, current_time=current_time)

        # Step 3: Anomaly Detection & Closed-Loop Mitigation Trigger
        detection_alerts = {}
        for host_ip, metrics in host_metrics.items():
            pkt_rate = metrics["packet_rate"]
            flow_rate = metrics["flow_rate"]
            dst_ports = metrics["dst_ports"]

            det_result = self.detector.update(
                host_ip=host_ip,
                packet_rate=pkt_rate,
                flow_rate=flow_rate,
                dst_ports=dst_ports
            )
            detection_alerts[host_ip] = det_result

            # Trigger automated mitigation upon anomaly
            if det_result["is_anomaly"]:
                self.mitigation.mitigate_host(
                    offending_ip=host_ip,
                    reason=det_result["attack_type"]
                )

        # Step 4: Prometheus Metric Export
        self.exporter.update_flow_metrics(all_flow_records)
        self.exporter.update_host_metrics(host_metrics)

        for host_ip, det_res in detection_alerts.items():
            self.exporter.update_host_entropy(host_ip, det_res["entropy"])
            self.exporter.update_host_z_score(host_ip, "packet_rate", det_res["z_pkt_rate"])
            if det_res["is_anomaly"]:
                self.exporter.update_anomaly_alert(host_ip, det_res["attack_type"], is_active=True)
            self.exporter.update_mitigation_active(host_ip, is_active=self.mitigation.is_blocked(host_ip))

        return {
            "flow_records": all_flow_records,
            "host_metrics": host_metrics,
            "detection_alerts": detection_alerts
        }


class TestClosedLoopPipelineIntegration(unittest.TestCase):
    """Integration test suite for the complete closed-loop defense pipeline."""

    def setUp(self):
        self.pipeline = ClosedLoopSDNPipeline(poll_interval=1.0)

    def _generate_quiescent_stats(self, packet_count_h1, byte_count_h1, current_time):
        """Generate benign stats for switches."""
        match_h1 = {"ipv4_src": "10.0.0.1", "ipv4_dst": "10.0.0.2", "tcp_dst": 80, "ip_proto": 6}
        match_h3 = {"ipv4_src": "10.0.0.3", "ipv4_dst": "10.0.0.4", "tcp_dst": 5001, "ip_proto": 6}

        stat_s2_h1 = MockOFPFlowStat(0, 1, 0, packet_count_h1, byte_count_h1, int(current_time), 0, match_h1)
        stat_s3_h3 = MockOFPFlowStat(0, 1, 0, 50, 25000, int(current_time), 0, match_h3)

        return {
            1: [],
            2: [stat_s2_h1],
            3: [stat_s3_h3],
        }

    def test_scenario_1_baseline_quiescent_state(self):
        """Scenario 1: Benign traffic runs without triggering false alarms or mitigation."""
        # Run 10 ticks of normal 10 pps traffic
        for tick in range(1, 11):
            stats = self._generate_quiescent_stats(
                packet_count_h1=tick * 10,
                byte_count_h1=tick * 5000,
                current_time=float(tick)
            )
            result = self.pipeline.process_telemetry_tick(stats, current_time=float(tick))

        # Assert no hosts are blocked
        self.assertFalse(self.pipeline.mitigation.is_blocked("10.0.0.1"))
        self.assertFalse(self.pipeline.mitigation.is_blocked("10.0.0.3"))

        # Verify Prometheus metrics are exported and normal
        metrics_text = self.pipeline.exporter.get_metrics_text()
        self.assertIn("sdn_flow_packet_rate", metrics_text)
        self.assertNotIn('sdn_anomaly_alert{attack_type="volumetric_flood",host="10.0.0.1"} 1.0', metrics_text)

    def test_scenario_2_syn_flood_automated_mitigation(self):
        """Scenario 2: High-rate SYN flood triggers closed-loop mitigation and drops attack."""
        # 1. Warmup pipeline with 10 normal ticks
        for tick in range(1, 11):
            stats = self._generate_quiescent_stats(
                packet_count_h1=tick * 10,
                byte_count_h1=tick * 5000,
                current_time=float(tick)
            )
            self.pipeline.process_telemetry_tick(stats, current_time=float(tick))

        # Clear prior messages from switch datapaths
        for dp in self.pipeline.datapaths.values():
            dp.sent_msgs.clear()

        # 2. Tick 11: Attacker h1 (10.0.0.1) launches massive SYN flood (5,000 pkts in 1 second)
        attack_stats = {
            2: [
                MockOFPFlowStat(
                    0, 1, 0,
                    packet_count=100 + 5000,
                    byte_count=50000 + 270000,
                    duration_sec=11,
                    duration_nsec=0,
                    match={"ipv4_src": "10.0.0.1", "ipv4_dst": "10.0.0.2", "tcp_dst": 80, "ip_proto": 6}
                )
            ]
        }
        res_tick_11 = self.pipeline.process_telemetry_tick(attack_stats, current_time=11.0)

        # 3. Verify closed-loop detection and mitigation
        alert_h1 = res_tick_11["detection_alerts"]["10.0.0.1"]
        self.assertTrue(alert_h1["is_anomaly"], "Anomaly detector must flag volumetric flood")
        self.assertEqual(alert_h1["attack_type"], "volumetric_flood")

        # 4. Verify mitigation engine automatically blocked offending source 10.0.0.1
        self.assertTrue(self.pipeline.mitigation.is_blocked("10.0.0.1"))

        # 5. Verify drop rules (priority=1000, eth_type=0x0800, ipv4_src=10.0.0.1) installed across switches
        for dp in self.pipeline.datapaths.values():
            drop_mods = [m for m in dp.sent_msgs if getattr(m, "priority", 0) == 1000]
            self.assertEqual(len(drop_mods), 1, f"Switch {dp.id} should have received exactly 1 drop rule")
            self.assertEqual(drop_mods[0].match.get("eth_type"), 0x0800)
            self.assertEqual(drop_mods[0].match.get("ipv4_src"), "10.0.0.1")
            self.assertEqual(drop_mods[0].instructions, [])

        # 6. Verify Prometheus metrics exporter reflects active alert and mitigation
        metrics = self.pipeline.exporter.get_metrics_text()
        self.assertIn('sdn_anomaly_alert{attack_type="volumetric_flood",host="10.0.0.1"} 1.0', metrics)
        self.assertIn('sdn_mitigation_active{offending_ip="10.0.0.1"} 1.0', metrics)

    def test_scenario_3_port_scan_detection_and_isolation(self):
        """Scenario 3: Multi-port scan causes entropy spike and triggers mitigation."""
        # 1. Warmup
        for tick in range(1, 11):
            stats = self._generate_quiescent_stats(tick * 5, tick * 2500, float(tick))
            self.pipeline.process_telemetry_tick(stats, current_time=float(tick))

        # 2. Tick 11: Attacker h1 generates flows targeting 60 distinct ports
        scan_flow_stats = []
        for port in range(1, 61):
            scan_flow_stats.append(
                MockOFPFlowStat(
                    0, 1, 0,
                    packet_count=1,
                    byte_count=64,
                    duration_sec=11,
                    duration_nsec=0,
                    match={"ipv4_src": "10.0.0.1", "ipv4_dst": "10.0.0.2", "tcp_dst": port, "ip_proto": 6}
                )
            )

        res_scan = self.pipeline.process_telemetry_tick({2: scan_flow_stats}, current_time=11.0)

        # 3. Assert port scan detected and attacker blocked
        alert_h1 = res_scan["detection_alerts"]["10.0.0.1"]
        self.assertTrue(alert_h1["is_anomaly"])
        self.assertEqual(alert_h1["attack_type"], "port_scan")
        self.assertGreater(alert_h1["entropy"], 3.0)
        self.assertTrue(self.pipeline.mitigation.is_blocked("10.0.0.1"))

    def test_scenario_4_benign_host_non_disruption(self):
        """Scenario 4: Benign hosts (h3, h4) are guaranteed non-disruption during mitigation."""
        # Mitigation active for attacker h1
        self.pipeline.mitigation.mitigate_host("10.0.0.1", reason="syn_flood")
        self.assertTrue(self.pipeline.mitigation.is_blocked("10.0.0.1"))

        # Benign hosts must NOT be blocked
        self.assertFalse(self.pipeline.mitigation.is_blocked("10.0.0.3"))
        self.assertFalse(self.pipeline.mitigation.is_blocked("10.0.0.4"))

        # Accidental or malicious attempts to mitigate benign host h3 must be rejected
        res = self.pipeline.mitigation.mitigate_host("10.0.0.3", reason="attack_spoofed")
        self.assertFalse(res["success"], "Must refuse mitigation against protected benign host")
        self.assertFalse(self.pipeline.mitigation.is_blocked("10.0.0.3"))

    def test_scenario_5_unblock_and_lifecycle_recovery(self):
        """Scenario 5: Offending host unblocked via API removes drop rules and clears metrics."""
        # 1. Mitigate attacker
        self.pipeline.mitigation.mitigate_host("10.0.0.1", reason="volumetric_flood")
        self.assertTrue(self.pipeline.mitigation.is_blocked("10.0.0.1"))
        self.pipeline.exporter.update_mitigation_active("10.0.0.1", is_active=True)

        # 2. Clear datapath records
        for dp in self.pipeline.datapaths.values():
            dp.sent_msgs.clear()

        # 3. Unblock attacker
        unblock_res = self.pipeline.mitigation.unblock_host("10.0.0.1")
        self.assertTrue(unblock_res["success"])
        self.assertFalse(self.pipeline.mitigation.is_blocked("10.0.0.1"))

        # 4. Verify OFPFC_DELETE_STRICT sent to all switches
        for dp in self.pipeline.datapaths.values():
            del_mods = [m for m in dp.sent_msgs if getattr(m, "command", None) == ofproto_v1_3.OFPFC_DELETE_STRICT]
            self.assertEqual(len(del_mods), 1)

        # 5. Update and assert exporter metric reflects unblock
        self.pipeline.exporter.update_mitigation_active("10.0.0.1", is_active=False)
        metrics = self.pipeline.exporter.get_metrics_text()
        self.assertIn('sdn_mitigation_active{offending_ip="10.0.0.1"} 0.0', metrics)


if __name__ == "__main__":
    unittest.main()
