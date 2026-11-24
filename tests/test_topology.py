"""Unit tests for SDN Tree Topology (Tier 1 & Tier 2).

Validates:
- SDNTreeTopo class instantiation and hierarchy (depth=2, fanout=2)
- Node counts: 3 OpenFlow switches (s1, s2, s3) and 4 hosts (h1, h2, h3, h4)
- Host IP assignments on 10.0.0.0/24 subnet (10.0.0.1/24 - 10.0.0.4/24)
- Host MAC address allocations (00:00:00:00:00:01 - 00:00:00:00:00:04)
- Switch OpenFlow 1.3 protocol settings
- Switch DPID 16-hex character formatting
- Link topology structure (tree backbone and edge links)
- Programmatic network creation API (create_network)
- Error handling on unknown node lookup
"""

import unittest
from topo.sdn_tree_topo import SDNTreeTopo, format_dpid, create_network


class TestSDNTreeTopology(unittest.TestCase):
    """Test suite for Mininet Tree Topology implementation."""

    def setUp(self):
        """Initialize topology instance before each test."""
        self.topo = SDNTreeTopo(depth=2, fanout=2)

    def test_switch_count_and_names(self):
        """Validate switch count is exactly 3 with names s1, s2, s3."""
        switches = self.topo.switches()
        self.assertEqual(len(switches), 3, "Expected 3 switches in depth=2, fanout=2 tree")
        self.assertListEqual(sorted(switches), ["s1", "s2", "s3"])

    def test_host_count_and_names(self):
        """Validate host count is exactly 4 with names h1, h2, h3, h4."""
        hosts = self.topo.hosts()
        self.assertEqual(len(hosts), 4, "Expected 4 hosts in depth=2, fanout=2 tree")
        self.assertListEqual(sorted(hosts), ["h1", "h2", "h3", "h4"])

    def test_host_ip_assignments(self):
        """Validate host IP addresses conform to subnet 10.0.0.0/24 requirement."""
        expected_ips = {
            "h1": "10.0.0.1/24",
            "h2": "10.0.0.2/24",
            "h3": "10.0.0.3/24",
            "h4": "10.0.0.4/24",
        }
        for host_name, expected_ip in expected_ips.items():
            info = self.topo.nodeInfo(host_name)
            self.assertEqual(
                info.get("ip"),
                expected_ip,
                f"Host {host_name} should have IP {expected_ip}"
            )

    def test_host_mac_assignments(self):
        """Validate deterministic MAC address allocations for hosts."""
        expected_macs = {
            "h1": "00:00:00:00:00:01",
            "h2": "00:00:00:00:00:02",
            "h3": "00:00:00:00:00:03",
            "h4": "00:00:00:00:00:04",
        }
        for host_name, expected_mac in expected_macs.items():
            info = self.topo.nodeInfo(host_name)
            self.assertEqual(
                info.get("mac"),
                expected_mac,
                f"Host {host_name} should have MAC {expected_mac}"
            )

    def test_switch_openflow_13_protocol(self):
        """Validate all switches are explicitly configured with OpenFlow 1.3 protocol."""
        for s in ["s1", "s2", "s3"]:
            info = self.topo.nodeInfo(s)
            self.assertEqual(
                info.get("protocols"),
                "OpenFlow13",
                f"Switch {s} must be configured with OpenFlow13 protocol"
            )

    def test_switch_dpid_formatting(self):
        """Validate switch DPIDs are 16-hex characters representing switch indices."""
        expected_dpids = {
            "s1": "0000000000000001",
            "s2": "0000000000000002",
            "s3": "0000000000000003",
        }
        for s, expected_dpid in expected_dpids.items():
            info = self.topo.nodeInfo(s)
            self.assertEqual(info.get("dpid"), expected_dpid)

    def test_format_dpid_helper(self):
        """Validate format_dpid helper handles various integer values correctly."""
        self.assertEqual(format_dpid(1), "0000000000000001")
        self.assertEqual(format_dpid(16), "0000000000000010")
        self.assertEqual(format_dpid(255), "00000000000000ff")
        self.assertEqual(format_dpid(0xabc), "0000000000000abc")

    def test_link_topology(self):
        """Validate all 6 links connecting root, pods, and edge hosts exist."""
        expected_links = {
            tuple(sorted(["s1", "s2"])),
            tuple(sorted(["s1", "s3"])),
            tuple(sorted(["s2", "h1"])),
            tuple(sorted(["s2", "h2"])),
            tuple(sorted(["s3", "h3"])),
            tuple(sorted(["s3", "h4"])),
        }
        actual_links = {tuple(sorted([src, dst])) for src, dst in self.topo.links()}
        self.assertEqual(len(actual_links), 6, "Expected exactly 6 links in the topology")
        self.assertEqual(actual_links, expected_links, "Link connectivity does not match tree structure")

    def test_is_switch_method(self):
        """Validate isSwitch accurately distinguishes switches from hosts."""
        self.assertTrue(self.topo.isSwitch("s1"))
        self.assertTrue(self.topo.isSwitch("s2"))
        self.assertTrue(self.topo.isSwitch("s3"))
        self.assertFalse(self.topo.isSwitch("h1"))
        self.assertFalse(self.topo.isSwitch("h4"))

    def test_unknown_node_lookup_raises_error(self):
        """Validate querying nodeInfo for a non-existent node raises KeyError."""
        with self.assertRaises(KeyError):
            self.topo.nodeInfo("s999")
        with self.assertRaises(KeyError):
            self.topo.nodeInfo("h10")

    def test_create_network_programmatic_api(self):
        """Validate create_network returns a functional network instance."""
        net = create_network(controller_ip="127.0.0.1", controller_port=6653)
        self.assertIsNotNone(net)
        # Should be able to access hosts and switches
        h1 = net.get("h1")
        s1 = net.get("s1")
        self.assertIsNotNone(h1)
        self.assertIsNotNone(s1)
        self.assertEqual(h1.IP(), "10.0.0.1")
        self.assertEqual(h1.MAC(), "00:00:00:00:00:01")


if __name__ == "__main__":
    unittest.main()
