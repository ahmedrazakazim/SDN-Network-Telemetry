"""Unit tests for Dynamic Flow Mitigation Engine (Tier 1 & Tier 2).

Validates:
- High-priority drop rule construction:
    * priority = 1000 (strictly higher than forwarding priority 1 and table-miss 0)
    * OpenFlow 1.3 drop semantic: empty instructions list
    * OpenFlow 1.3 match prerequisite compliance: eth_type = 0x0800 with ipv4_src
- Dynamic drop rule installation across all active switch datapaths
- Host blocking state tracking (is_blocked and get_blocked_hosts)
- Unblock mechanics (unblock_host deletes drop rules via OFPFC_DELETE)
- Automatic drop rule expiration via hard_timeout
- Source-Isolation Non-Disruption Guarantee:
    * Protected benign hosts (10.0.0.3, 10.0.0.4) cannot be blocked accidentally
    * Mitigation attempts against protected hosts are rejected
"""

import time
import unittest
from controller.flow_manager import ofproto_v1_3, ofproto_parser
from mitigation.mitigation_engine import MitigationEngine


class MockSwitchDatapath:
    """Mock datapath capturing installed and deleted flow mods for mitigation tests."""

    def __init__(self, dpid: int):
        self.id = dpid
        self.ofproto = ofproto_v1_3
        self.ofproto_parser = ofproto_parser
        self.sent_msgs = []

    def send_msg(self, msg):
        self.sent_msgs.append(msg)


class MockSDNController:
    """Mock controller holding registered datapaths."""

    def __init__(self):
        self.datapaths = {
            1: MockSwitchDatapath(dpid=1),
            2: MockSwitchDatapath(dpid=2),
            3: MockSwitchDatapath(dpid=3),
        }
        self.blocked_ips = {}


class TestMitigationEngine(unittest.TestCase):
    """Test suite for OpenFlow 1.3 automated mitigation engine."""

    def setUp(self):
        self.mock_controller = MockSDNController()
        self.engine = MitigationEngine(
            controller=self.mock_controller,
            default_timeout=300,
            protected_hosts={"10.0.0.3", "10.0.0.4"}
        )

    def test_mitigate_host_drop_rule_structure(self):
        """Validate drop rule parameters: priority=1000, empty instructions, eth_type=0x0800."""
        res = self.engine.mitigate_host(offending_ip="10.0.0.1", reason="syn_flood_detected")

        self.assertTrue(res["success"])
        self.assertEqual(res["offending_ip"], "10.0.0.1")
        self.assertEqual(res["installed_rules"], 3, "Rule must be installed on all 3 switches")
        self.assertEqual(res["priority"], 1000)

        # Inspect messages on switches
        for dp in self.mock_controller.datapaths.values():
            self.assertEqual(len(dp.sent_msgs), 1)
            flow_mod = dp.sent_msgs[0]

            # Priority 1000
            self.assertEqual(flow_mod.priority, 1000)
            # Empty instructions = DROP in OpenFlow 1.3
            self.assertEqual(flow_mod.instructions, [])
            # Eth type prerequisite
            self.assertEqual(flow_mod.match.get("eth_type"), 0x0800)
            self.assertEqual(flow_mod.match.get("ipv4_src"), "10.0.0.1")
            # Timeout
            self.assertEqual(flow_mod.hard_timeout, 300)

    def test_is_blocked_status_tracking(self):
        """Validate is_blocked accurately reflects blocked status."""
        self.assertFalse(self.engine.is_blocked("10.0.0.1"))
        self.engine.mitigate_host("10.0.0.1", reason="volumetric_flood")
        self.assertTrue(self.engine.is_blocked("10.0.0.1"))
        self.assertFalse(self.engine.is_blocked("10.0.0.2"))

    def test_unblock_host_mechanics(self):
        """Validate unblocking deletes drop rules across switches and removes host from blocked list."""
        self.engine.mitigate_host("10.0.0.1", reason="test_block")
        self.assertTrue(self.engine.is_blocked("10.0.0.1"))

        # Clear sent messages to verify delete commands
        for dp in self.mock_controller.datapaths.values():
            dp.sent_msgs.clear()

        unblock_res = self.engine.unblock_host("10.0.0.1")
        self.assertTrue(unblock_res["success"])
        self.assertEqual(unblock_res["deleted_rules"], 3)
        self.assertFalse(self.engine.is_blocked("10.0.0.1"))

        # Verify OFPFC_DELETE command sent to each switch
        for dp in self.mock_controller.datapaths.values():
            self.assertEqual(len(dp.sent_msgs), 1)
            del_mod = dp.sent_msgs[0]
            self.assertEqual(del_mod.command, ofproto_v1_3.OFPFC_DELETE_STRICT)
            self.assertEqual(del_mod.priority, 1000)
            self.assertEqual(del_mod.match.get("ipv4_src"), "10.0.0.1")

    def test_unblock_non_blocked_host(self):
        """Validate attempting to unblock a host that is not tracked returns was_tracked=False."""
        res = self.engine.unblock_host("10.0.0.2")
        self.assertTrue(res["success"])
        self.assertFalse(res["was_tracked"])

    def test_automatic_expiration_via_hard_timeout(self):
        """Validate drop rule expires after its hard_timeout elapses."""
        # Block host with 1 second timeout
        self.engine.mitigate_host("10.0.0.1", reason="quick_timeout", hard_timeout=1)
        self.assertTrue(self.engine.is_blocked("10.0.0.1"))

        # Sleep past timeout
        time.sleep(1.1)
        self.assertFalse(self.engine.is_blocked("10.0.0.1"), "Rule should have auto-expired")

    def test_non_disruption_guarantee_for_benign_hosts(self):
        """CRITICAL: Enforce non-disruption guarantee by refusing mitigation for protected hosts."""
        # Attempt to block benign host h3 (10.0.0.3)
        res_h3 = self.engine.mitigate_host("10.0.0.3", reason="false_positive_alert")
        self.assertFalse(res_h3["success"])
        self.assertEqual(res_h3["installed_rules"], 0)
        self.assertIn("protected benign host", res_h3["error"])
        self.assertFalse(self.engine.is_blocked("10.0.0.3"))

        # Attempt to block benign host h4 (10.0.0.4)
        res_h4 = self.engine.mitigate_host("10.0.0.4", reason="false_positive_alert")
        self.assertFalse(res_h4["success"])
        self.assertFalse(self.engine.is_blocked("10.0.0.4"))

        # Verify no drop rules were installed on any switches
        for dp in self.mock_controller.datapaths.values():
            self.assertEqual(len(dp.sent_msgs), 0)

    def test_override_protection_flag(self):
        """Validate emergency override flag allows blocking protected host if explicitly requested."""
        res = self.engine.mitigate_host("10.0.0.3", reason="admin_override", override_protection=True)
        self.assertTrue(res["success"])
        self.assertEqual(res["installed_rules"], 3)
        self.assertTrue(self.engine.is_blocked("10.0.0.3"))


if __name__ == "__main__":
    unittest.main()
