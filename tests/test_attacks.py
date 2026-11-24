"""Unit tests for Attack Generators (Tier 1 & Tier 2).

Validates:
- SYN flood attack command construction across low, medium, and high traffic rates
- SYN flood avoidance of --rand-source and enforcement of explicit source IP
- UDP flood attack command construction with varying rates and payload sizes (512B, 1024B)
- Nmap port scan command construction for TCP SYN (-sS) and TCP Connect (-sT) modes
- Parameter validation, invalid rate rejection, and port range parsing
- Dry-run programmatic API execution for testbed harnesses
"""

import unittest
from attacks.syn_flood import build_hping3_command, syn_flood, RATE_CONFIGS as SYN_RATES
from attacks.udp_flood import build_hping3_udp_command, udp_flood, RATE_CONFIGS as UDP_RATES
from attacks.port_scan import build_nmap_command, count_ports_in_range, port_scan, SCAN_MODES


class TestSYNFloodAttack(unittest.TestCase):
    """Test suite for SYN flood attack generator."""

    def test_syn_flood_low_rate_parameters(self):
        """Validate low-rate SYN flood produces 100 pps parameters (-i u10000)."""
        cmd = build_hping3_command("10.0.0.2", rate="low", target_port=80, source_ip="10.0.0.1")
        self.assertIn("-S", cmd)
        self.assertIn("-p", cmd)
        self.assertIn("80", cmd)
        self.assertIn("-i", cmd)
        self.assertIn("u10000", cmd)
        self.assertIn("-a", cmd)
        self.assertIn("10.0.0.1", cmd)
        self.assertEqual(cmd[-1], "10.0.0.2")
        self.assertNotIn("--rand-source", cmd, "Must not use random source IP to allow attribution")

    def test_syn_flood_medium_rate_parameters(self):
        """Validate medium-rate SYN flood produces 1,000 pps parameters (-i u1000)."""
        cmd = build_hping3_command("10.0.0.2", rate="medium", target_port=80, source_ip="10.0.0.1")
        self.assertIn("-i", cmd)
        self.assertIn("u1000", cmd)
        self.assertNotIn("--flood", cmd)

    def test_syn_flood_high_rate_parameters(self):
        """Validate high-rate SYN flood produces wire rate parameters (--flood)."""
        cmd = build_hping3_command("10.0.0.2", rate="high", target_port=80, source_ip="10.0.0.1")
        self.assertIn("--flood", cmd)
        self.assertNotIn("-i", cmd)

    def test_syn_flood_invalid_rate_raises_error(self):
        """Validate invalid rate specification raises ValueError."""
        with self.assertRaises(ValueError):
            build_hping3_command("10.0.0.2", rate="extreme")

    def test_syn_flood_dry_run_execution(self):
        """Validate dry-run execution returns expected execution metadata without running process."""
        result = syn_flood(
            target_ip="10.0.0.2",
            rate="low",
            duration=1,
            source_ip="10.0.0.1",
            dry_run=True
        )
        self.assertEqual(result["attack_type"], "syn_flood")
        self.assertEqual(result["rate"], "low")
        self.assertEqual(result["target_ip"], "10.0.0.2")
        self.assertEqual(result["source_ip"], "10.0.0.1")
        self.assertEqual(result["status"], "success")
        self.assertTrue(result["dry_run"])


class TestUDPFloodAttack(unittest.TestCase):
    """Test suite for UDP flood attack generator."""

    def test_udp_flood_low_rate_parameters(self):
        """Validate low-rate UDP flood produces 100 pps with 512B payload."""
        cmd = build_hping3_udp_command("10.0.0.2", rate="low", target_port=5001, source_ip="10.0.0.1")
        self.assertIn("--udp", cmd)
        self.assertIn("-p", cmd)
        self.assertIn("5001", cmd)
        self.assertIn("-i", cmd)
        self.assertIn("u10000", cmd)
        self.assertIn("-d", cmd)
        self.assertIn("512", cmd)
        self.assertIn("-a", cmd)
        self.assertIn("10.0.0.1", cmd)
        self.assertEqual(cmd[-1], "10.0.0.2")

    def test_udp_flood_medium_rate_parameters(self):
        """Validate medium-rate UDP flood produces 1,000 pps with 512B payload."""
        cmd = build_hping3_udp_command("10.0.0.2", rate="medium", target_port=5001)
        self.assertIn("-i", cmd)
        self.assertIn("u1000", cmd)
        self.assertIn("-d", cmd)
        self.assertIn("512", cmd)

    def test_udp_flood_high_rate_parameters(self):
        """Validate high-rate UDP flood produces wire rate with 1024B (1KB) payload."""
        cmd = build_hping3_udp_command("10.0.0.2", rate="high", target_port=5001)
        self.assertIn("--flood", cmd)
        self.assertIn("-d", cmd)
        self.assertIn("1024", cmd)

    def test_udp_flood_invalid_rate_raises_error(self):
        """Validate invalid rate specification raises ValueError."""
        with self.assertRaises(ValueError):
            build_hping3_udp_command("10.0.0.2", rate="ultra")

    def test_udp_flood_dry_run_execution(self):
        """Validate dry-run execution returns expected execution metadata."""
        result = udp_flood(
            target_ip="10.0.0.2",
            rate="medium",
            duration=1,
            source_ip="10.0.0.1",
            dry_run=True
        )
        self.assertEqual(result["attack_type"], "udp_flood")
        self.assertEqual(result["rate"], "medium")
        self.assertEqual(result["payload_size"], 512)
        self.assertEqual(result["status"], "success")
        self.assertTrue(result["dry_run"])


class TestPortScanAttack(unittest.TestCase):
    """Test suite for Nmap port scan generator."""

    def test_syn_stealth_scan_parameters(self):
        """Validate TCP SYN stealth scan flags (-sS -p 1-1024 -T4)."""
        cmd = build_nmap_command("10.0.0.2", scan_type="syn", port_range="1-1024", timing="T4")
        self.assertIn("nmap", cmd)
        self.assertIn("-sS", cmd)
        self.assertIn("-p", cmd)
        self.assertIn("1-1024", cmd)
        self.assertIn("-T4", cmd)
        self.assertEqual(cmd[-1], "10.0.0.2")

    def test_connect_scan_parameters(self):
        """Validate TCP Connect scan flags (-sT -p 1-1024 -T4)."""
        cmd = build_nmap_command("10.0.0.2", scan_type="connect", port_range="1-1024", timing="T4")
        self.assertIn("-sT", cmd)
        self.assertIn("-p", cmd)
        self.assertIn("1-1024", cmd)
        self.assertIn("-T4", cmd)

    def test_port_scan_invalid_mode_raises_error(self):
        """Validate invalid scan type raises ValueError."""
        with self.assertRaises(ValueError):
            build_nmap_command("10.0.0.2", scan_type="xmas_scan")

    def test_count_ports_in_range_calculation(self):
        """Validate port range counter calculates exact port count."""
        self.assertEqual(count_ports_in_range("1-1024"), 1024)
        self.assertEqual(count_ports_in_range("80,443,8080"), 3)
        self.assertEqual(count_ports_in_range("1-10,20-30,80"), 22)
        # Empty string defaults to 1024 ports fallback
        self.assertEqual(count_ports_in_range(""), 1024)

    def test_port_scan_dry_run_execution(self):
        """Validate dry-run execution returns expected execution metadata."""
        result = port_scan(
            target_ip="10.0.0.2",
            scan_type="syn",
            port_range="1-1024",
            dry_run=True
        )
        self.assertEqual(result["attack_type"], "port_scan")
        self.assertEqual(result["scan_type"], "syn")
        self.assertEqual(result["target_ip"], "10.0.0.2")
        self.assertEqual(result["status"], "success")
        self.assertTrue(result["dry_run"])
        self.assertTrue(result["elapsed_sec"] >= 0.0)


if __name__ == "__main__":
    unittest.main()
