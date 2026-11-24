"""
Attacks package for SDN Telemetry & Anomaly Detection Testbed.

Provides automated attack simulations:
- syn_flood: TCP SYN flood at low (100 pps), medium (1,000 pps), and high (wire rate) speeds.
- udp_flood: UDP flood at low (100 pps), medium (1,000 pps), and high (wire rate) speeds with variable payloads.
- port_scan: TCP SYN stealth and Connect port scans using Nmap.
"""

from attacks.syn_flood import syn_flood, build_hping3_command, SYNFloodAttack
from attacks.udp_flood import udp_flood, build_hping3_udp_command, UDPFloodAttack
from attacks.port_scan import port_scan, build_nmap_command, PortScanAttack

__all__ = [
    "syn_flood",
    "build_hping3_command",
    "SYNFloodAttack",
    "udp_flood",
    "build_hping3_udp_command",
    "UDPFloodAttack",
    "port_scan",
    "build_nmap_command",
    "PortScanAttack"
]
