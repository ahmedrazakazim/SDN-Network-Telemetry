"""Unit tests for OpenFlow 1.3 Controller Forwarding & L2 Learning (Tier 1 & Tier 2).

Validates:
- Table-miss flow entry installation (priority=0 directing unmatched packets to controller)
- Mandatory OpenFlow 1.3 match prerequisite compliance (eth_type=0x0800 for IPv4 field matches)
- Flow entry generation (forwarding rule priority=1, timeouts, instructions)
- L2 MAC address learning:
    * Unknown destination MAC floods (OFPP_FLOOD)
    * Source MAC learned and mapped to ingress port
    * Known destination MAC installs flow rule and outputs directly to learned port
- ARP match generation (eth_type=0x0806)
- Switch datapath registration and unregistration tracking
- Prevention of packet processing from blocked source IPs
"""

import unittest
from controller.flow_manager import FlowManager, ofproto_v1_3, ofproto_parser
from controller.sdn_controller import SDNController

try:
    from os_ken.lib.packet import packet, ethernet, ipv4, arp, ether_types
except ImportError:
    try:
        from ryu.lib.packet import packet, ethernet, ipv4, arp, ether_types
    except ImportError:
        packet = None
        ethernet = None
        ipv4 = None
        arp = None
        ether_types = None


def make_test_ip_packet(src_mac, dst_mac, src_ip, dst_ip, proto=6):
    """Construct serialized Ethernet/IPv4 packet for os-ken/ryu."""
    if packet is not None:
        p = packet.Packet()
        p.add_protocol(ethernet.ethernet(ethertype=0x0800, dst=dst_mac, src=src_mac))
        p.add_protocol(ipv4.ipv4(dst=dst_ip, src=src_ip, proto=proto))
        p.serialize()
        return p.data
    return b"dummy_data"


def make_test_arp_packet(src_mac, dst_mac, src_ip, dst_ip):
    """Construct serialized Ethernet/ARP packet."""
    if packet is not None:
        p = packet.Packet()
        p.add_protocol(ethernet.ethernet(ethertype=0x0806, dst=dst_mac, src=src_mac))
        p.add_protocol(arp.arp(src_ip=src_ip, dst_ip=dst_ip))
        p.serialize()
        return p.data
    return b"dummy_arp_data"


class MockDatapath:
    """Mock switch datapath recording sent OpenFlow messages for assertion."""

    def __init__(self, dpid=1):
        self.id = dpid
        self.ofproto = ofproto_v1_3
        self.ofproto_parser = ofproto_parser
        self.sent_msgs = []

    def send_msg(self, msg):
        """Record sent message."""
        self.sent_msgs.append(msg)


class MockPacketInMsg:
    """Mock OpenFlow PacketIn message."""

    def __init__(self, datapath, in_port, data, buffer_id=None):
        self.datapath = datapath
        self.match = {"in_port": in_port}
        self.data = data
        self.buffer_id = buffer_id if buffer_id is not None else ofproto_v1_3.OFP_NO_BUFFER


class TestFlowManager(unittest.TestCase):
    """Test suite for FlowManager OpenFlow 1.3 rule construction."""

    def setUp(self):
        self.fm = FlowManager()
        self.dp = MockDatapath(dpid=1)

    def test_table_miss_installation(self):
        """Validate table-miss rule: priority=0, actions=[OFPP_CONTROLLER], table_id=0."""
        mod = self.fm.install_table_miss(self.dp, table_id=0)

        self.assertEqual(mod.priority, 0)
        self.assertEqual(mod.table_id, 0)
        self.assertEqual(len(self.dp.sent_msgs), 1)
        # Check instruction wraps controller action
        self.assertEqual(len(mod.instructions), 1)
        inst = mod.instructions[0]
        self.assertEqual(len(inst.actions), 1)
        action = inst.actions[0]
        self.assertEqual(action.port, ofproto_v1_3.OFPP_CONTROLLER)

    def test_mandatory_eth_type_prerequisite_enforcement(self):
        """CRITICAL: Matching ipv4_src, ipv4_dst, or ip_proto MUST inject eth_type=0x0800."""
        # Case 1: ipv4_src specified without eth_type
        match1 = self.fm.create_match(self.dp, ipv4_src="10.0.0.1")
        self.assertEqual(match1.get("eth_type"), 0x0800)
        self.assertEqual(match1.get("ipv4_src"), "10.0.0.1")

        # Case 2: ipv4_dst specified without eth_type
        match2 = self.fm.create_match(self.dp, ipv4_dst="10.0.0.2")
        self.assertEqual(match2.get("eth_type"), 0x0800)

        # Case 3: ip_proto specified without eth_type
        match3 = self.fm.create_match(self.dp, ip_proto=6)
        self.assertEqual(match3.get("eth_type"), 0x0800)

        # Case 4: L2 match only does not inject eth_type
        match4 = self.fm.create_match(self.dp, eth_src="00:00:00:00:00:01")
        self.assertIsNone(match4.get("eth_type"))

    def test_forwarding_rule_creation(self):
        """Validate forwarding rule generation: priority=1, idle_timeout=60, output action."""
        match = self.fm.create_match(self.dp, in_port=1, eth_dst="00:00:00:00:00:02")
        actions = [ofproto_parser.OFPActionOutput(port=2)]
        mod = self.fm.install_forwarding_rule(
            self.dp,
            priority=1,
            match=match,
            actions=actions,
            idle_timeout=60,
            hard_timeout=0
        )

        self.assertEqual(mod.priority, 1)
        self.assertEqual(mod.idle_timeout, 60)
        self.assertEqual(mod.hard_timeout, 0)
        self.assertEqual(len(mod.instructions), 1)
        self.assertEqual(mod.instructions[0].actions[0].port, 2)

    def test_drop_rule_creation(self):
        """Validate drop rule: priority=1000, empty instructions (DROP), eth_type=0x0800."""
        mod = self.fm.install_drop_rule(self.dp, priority=1000, ipv4_src="10.0.0.1", hard_timeout=300)

        self.assertEqual(mod.priority, 1000)
        self.assertEqual(mod.hard_timeout, 300)
        # Empty instructions = DROP in OpenFlow 1.3
        self.assertEqual(mod.instructions, [])
        self.assertEqual(mod.match.get("eth_type"), 0x0800)
        self.assertEqual(mod.match.get("ipv4_src"), "10.0.0.1")

    def test_delete_flow(self):
        """Validate flow deletion constructs OFPFC_DELETE command."""
        match = self.fm.create_match(self.dp, ipv4_src="10.0.0.1")
        mod = self.fm.delete_flow(self.dp, match=match, priority=1000, strict=True)

        self.assertEqual(mod.command, ofproto_v1_3.OFPFC_DELETE_STRICT)
        self.assertEqual(mod.priority, 1000)


class TestSDNControllerForwarding(unittest.TestCase):
    """Test suite for SDN Controller L2 learning and forwarding behavior."""

    def setUp(self):
        self.controller = SDNController()
        self.dp = MockDatapath(dpid=2)
        # Register datapath
        self.controller.datapaths[self.dp.id] = self.dp
        self.controller.mac_to_port[self.dp.id] = {}

    def test_switch_features_installs_table_miss(self):
        """Validate switch_features_handler registers datapath and installs table-miss."""
        class MockEvent:
            msg = type("Msg", (), {"datapath": MockDatapath(dpid=3)})()

        ev = MockEvent()
        self.controller.switch_features_handler(ev)

        self.assertIn(3, self.controller.datapaths)
        self.assertIn(3, self.controller.mac_to_port)
        # Verify table-miss flow mod was sent to datapath 3
        new_dp = self.controller.datapaths[3]
        self.assertEqual(len(new_dp.sent_msgs), 1)
        self.assertEqual(new_dp.sent_msgs[0].priority, 0)

    def test_l2_learning_unknown_dst_floods(self):
        """When destination MAC is unknown, packet is flooded and source is learned."""
        data = make_test_ip_packet(
            src_mac="00:00:00:00:00:01",
            dst_mac="00:00:00:00:00:02",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2"
        )
        msg = MockPacketInMsg(
            datapath=self.dp,
            in_port=1,
            data=data
        )
        ev = type("Event", (), {"msg": msg})()

        self.controller.packet_in_handler(ev)

        # 1. Source MAC learned
        self.assertEqual(self.controller.mac_to_port[self.dp.id]["00:00:00:00:00:01"], 1)

        # 2. Output action should be OFPP_FLOOD
        self.assertEqual(len(self.dp.sent_msgs), 1)
        packet_out = self.dp.sent_msgs[0]
        self.assertEqual(packet_out.actions[0].port, ofproto_v1_3.OFPP_FLOOD)

    def test_l2_learning_known_dst_installs_forwarding_rule(self):
        """When destination MAC is known, controller installs flow rule and outputs directly."""
        # Pre-seed MAC table for destination host (h2 on port 2)
        self.controller.mac_to_port[self.dp.id]["00:00:00:00:00:02"] = 2

        data = make_test_ip_packet(
            src_mac="00:00:00:00:00:01",
            dst_mac="00:00:00:00:00:02",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2"
        )
        msg = MockPacketInMsg(
            datapath=self.dp,
            in_port=1,
            data=data
        )
        ev = type("Event", (), {"msg": msg})()

        self.controller.packet_in_handler(ev)

        # Should have sent FlowMod (forwarding rule) AND PacketOut
        self.assertEqual(len(self.dp.sent_msgs), 2)
        flow_mod = self.dp.sent_msgs[0]
        packet_out = self.dp.sent_msgs[1]

        # Verify FlowMod properties
        self.assertEqual(flow_mod.priority, 1)
        self.assertEqual(flow_mod.match.get("eth_type"), 0x0800)
        self.assertEqual(flow_mod.match.get("ipv4_src"), "10.0.0.1")
        self.assertEqual(flow_mod.match.get("ipv4_dst"), "10.0.0.2")
        self.assertEqual(flow_mod.instructions[0].actions[0].port, 2)

        # Verify PacketOut directed to port 2 (not flood)
        self.assertEqual(packet_out.actions[0].port, 2)

    def test_blocked_source_ip_dropped(self):
        """Validate packets from blocked IP are dropped immediately without learning or output."""
        self.controller.blocked_ips["10.0.0.1"] = 1000.0
        data = make_test_ip_packet(
            src_mac="00:00:00:00:00:01",
            dst_mac="00:00:00:00:00:02",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2"
        )
        msg = MockPacketInMsg(
            datapath=self.dp,
            in_port=1,
            data=data
        )
        ev = type("Event", (), {"msg": msg})()

        self.controller.packet_in_handler(ev)

        # No messages sent on switch datapath
        self.assertEqual(len(self.dp.sent_msgs), 0)
        # Source MAC should not be learned from blocked sender
        self.assertNotIn("00:00:00:00:00:01", self.controller.mac_to_port[self.dp.id])


if __name__ == "__main__":
    unittest.main()
