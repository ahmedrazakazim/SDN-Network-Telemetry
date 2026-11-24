"""Test L4 Destination-Port Matching and Shannon Entropy Spikes."""

import unittest
from controller.sdn_controller import SDNController
from controller.flow_manager import ofproto_v1_3, ofproto_parser
from telemetry.collector import TelemetryCollector
from telemetry.exporter import PrometheusTelemetryExporter
from prometheus_client import CollectorRegistry

try:
    from os_ken.lib.packet import packet, ethernet, ipv4, tcp, udp, ether_types
except ImportError:
    try:
        from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, ether_types
    except ImportError:
        packet = None


def make_tcp_packet(src_mac, dst_mac, src_ip, dst_ip, dst_port, src_port=12345):
    """Create raw Ethernet/IPv4/TCP packet."""
    if packet is not None:
        p = packet.Packet()
        p.add_protocol(ethernet.ethernet(ethertype=0x0800, dst=dst_mac, src=src_mac))
        p.add_protocol(ipv4.ipv4(dst=dst_ip, src=src_ip, proto=6))
        p.add_protocol(tcp.tcp(src_port=src_port, dst_port=dst_port))
        p.serialize()
        return p.data
    return b"dummy_tcp_data"


class MockDatapath:
    def __init__(self, dpid=1):
        self.id = dpid
        self.ofproto = ofproto_v1_3
        self.ofproto_parser = ofproto_parser
        self.sent_msgs = []

    def send_msg(self, msg):
        self.sent_msgs.append(msg)


class MockPacketInMsg:
    def __init__(self, datapath, in_port, data):
        self.datapath = datapath
        self.match = {"in_port": in_port}
        self.data = data
        self.buffer_id = ofproto_v1_3.OFP_NO_BUFFER


class TestL4PortEntropy(unittest.TestCase):
    def setUp(self):
        self.controller = SDNController()
        self.dp = MockDatapath(dpid=2)
        self.controller.datapaths[self.dp.id] = self.dp
        self.controller.mac_to_port[self.dp.id] = {"00:00:00:00:00:02": 2}

        # Wire dedicated test registry for Prometheus exporter
        self.registry = CollectorRegistry(auto_describe=True)
        self.exporter = PrometheusTelemetryExporter(port=8999, registry=self.registry)
        self.collector = TelemetryCollector(
            datapaths=self.controller.datapaths,
            poll_interval=1.0,
            exporter=self.exporter
        )
        self.controller.telemetry_collector = self.collector
        self.controller.exporter = self.exporter

    def test_nmap_scan_causes_entropy_spike(self):
        """Simulate port scan to multiple destination ports and verify entropy spikes above 0."""
        target_ports = [80, 443, 22, 21, 25, 53, 8080, 3306, 8443, 8888]
        src_ip = "10.0.0.1"
        dst_ip = "10.0.0.2"

        # 1. Send packets targeting multiple ports via packet_in_handler
        for port in target_ports:
            data = make_tcp_packet(
                src_mac="00:00:00:00:00:01",
                dst_mac="00:00:00:00:00:02",
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=port
            )
            msg = MockPacketInMsg(datapath=self.dp, in_port=1, data=data)
            ev = type("Event", (), {"msg": msg})()
            self.controller.packet_in_handler(ev)

        # Verify host_dst_ports was populated directly from PacketIn
        fe = self.collector.feature_extractor
        observed_ports = list(fe.host_dst_ports[src_ip])
        self.assertEqual(len(observed_ports), len(target_ports))
        self.assertCountEqual(observed_ports, target_ports)

        # Verify flow rules installed have tcp_dst and idle_timeout=10
        installed_flow_mods = [m for m in self.dp.sent_msgs if hasattr(m, "match") and m.priority == 1]
        self.assertEqual(len(installed_flow_mods), len(target_ports))
        for mod in installed_flow_mods:
            self.assertEqual(mod.idle_timeout, 10)
            self.assertEqual(mod.match.get("ip_proto"), 6)
            self.assertIn(mod.match.get("tcp_dst"), target_ports)

        # 2. Simulate telemetry polling cycle
        mock_body = []
        for mod in installed_flow_mods:
            mock_body.append(type("MockFlowStat", (), {
                "table_id": 0,
                "duration_sec": 1,
                "duration_nsec": 0,
                "priority": mod.priority,
                "match": mod.match,
                "packet_count": 5,
                "byte_count": 300,
                "cookie": 0
            })())

        reply_msg = type("MockFlowStatsReply", (), {
            "body": mock_body,
            "datapath": self.dp,
            "dpid": 2
        })()

        # Handle flow stats reply
        self.collector.handle_flow_stats_reply(reply_msg)

        # 3. Verify destination-port Shannon entropy
        entropy_gauge = self.exporter.host_port_entropy.labels(host=src_ip)._value.get()
        print(f"\n[TEST VERIFICATION] Observed {len(target_ports)} scanned ports: entropy = {entropy_gauge:.4f} bits")
        # For 10 unique uniform ports, theoretical entropy is log2(10) ~ 3.3219 bits
        self.assertGreater(entropy_gauge, 3.0)


if __name__ == "__main__":
    unittest.main()
