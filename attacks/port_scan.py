#!/usr/bin/env python3
"""
Port Scan Attack Generator for SDN Telemetry & Anomaly Detection Testbed.

Generates reconnaissance port scans against target hosts using Nmap.
Complies with requirement R7:
- TCP SYN stealth scan: nmap -sS -p 1-1024 -T4 <target_ip>
- TCP Connect scan: nmap -sT -p 1-1024 -T4 <target_ip>
- Targets a range of destination ports to trigger destination-port Shannon entropy alerts.
"""

import argparse
import logging
import os
import shutil
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [port_scan] %(message)s")
logger = logging.getLogger("port_scan")

SCAN_MODES = {
    "syn": {
        "flag": "-sS",
        "name": "TCP SYN Stealth Scan",
        "description": "Half-open TCP SYN scan"
    },
    "connect": {
        "flag": "-sT",
        "name": "TCP Connect Scan",
        "description": "Full three-way handshake TCP connect scan"
    }
}


def build_nmap_command(
    target_ip: str,
    scan_type: str = "syn",
    port_range: str = "1-1024",
    timing: str = "T4",
    extra_args: Optional[List[str]] = None
) -> List[str]:
    """
    Construct the nmap command line arguments for port scan.
    """
    scan_key = scan_type.lower()
    if scan_key not in SCAN_MODES:
        raise ValueError(f"Invalid scan_type '{scan_type}'. Allowed values: {list(SCAN_MODES.keys())}")

    timing_flag = timing if timing.startswith("-") else f"-{timing}"
    cmd = ["nmap", SCAN_MODES[scan_key]["flag"], "-n", "-Pn", "-p", port_range, timing_flag]

    if extra_args:
        cmd.extend(extra_args)

    cmd.append(target_ip)
    return cmd


def count_ports_in_range(port_range: str) -> int:
    """Calculate the number of ports in a range specification like '1-1024' or '80,443'."""
    total = 0
    parts = port_range.split(",")
    for part in parts:
        part = part.strip()
        if "-" in part:
            sub = part.split("-")
            if len(sub) == 2 and sub[0].isdigit() and sub[1].isdigit():
                start, end = int(sub[0]), int(sub[1])
                total += max(0, end - start + 1)
        elif part.isdigit():
            total += 1
    return total if total > 0 else 1024


def port_scan(
    target_ip: str = "10.0.0.2",
    scan_type: str = "syn",
    port_range: str = "1-1024",
    timing: str = "T4",
    host: Any = None,
    dry_run: bool = False
) -> Dict[str, Any]:
    """
    Execute a port scan reconnaissance attack against target_ip.

    :param target_ip: IP address of the target host (e.g. 10.0.0.2)
    :param scan_type: 'syn' for stealth SYN scan (-sS) or 'connect' for TCP connect scan (-sT)
    :param port_range: Port range to scan (default: '1-1024')
    :param timing: Nmap timing template (default: 'T4')
    :param host: Optional Mininet Host object
    :param dry_run: If True or if nmap is unavailable, simulate the scan
    :return: Dictionary containing execution summary
    """
    cmd_args = build_nmap_command(target_ip, scan_type, port_range, timing)
    cmd_str = " ".join(cmd_args)
    scanned_port_count = count_ports_in_range(port_range)
    mode_info = SCAN_MODES[scan_type.lower()]

    nmap_available = shutil.which("nmap") is not None
    should_dry_run = dry_run or (not nmap_available and host is None)

    start_time = time.time()
    result = {
        "attack_type": "port_scan",
        "target_ip": target_ip,
        "scan_type": scan_type,
        "scan_name": mode_info["name"],
        "port_range": port_range,
        "ports_scanned": scanned_port_count,
        "timing": timing,
        "command": cmd_str,
        "start_time": start_time,
        "end_time": None,
        "elapsed_sec": 0.0,
        "status": "pending",
        "open_ports": [],
        "output": "",
        "error": None
    }

    logger.info(f"Initiating {mode_info['name']}: target={target_ip}, ports={port_range}, timing={timing}")

    if should_dry_run:
        logger.info(f"Executing in dry-run/simulation mode (nmap available: {nmap_available})")
        time.sleep(0.3)
        end_time = time.time()
        result.update({
            "end_time": end_time,
            "elapsed_sec": end_time - start_time,
            "status": "success",
            "dry_run": True,
            "output": f"Nmap scan report for {target_ip}\nHost is up (0.001s latency).\nPORT 80/tcp open http\nPORT 5001/tcp open commplex-link\nNmap done: 1 IP address (1 host up) scanned in {end_time - start_time:.2f} seconds",
            "open_ports": [80, 5001]
        })
        logger.info(f"Port scan completed (simulated): {scanned_port_count} ports evaluated")
        return result

    try:
        if host is not None:
            logger.info(f"Executing command on Mininet host {getattr(host, 'name', host)}: {cmd_str}")
            output = host.cmd(cmd_str)
        else:
            logger.info(f"Executing local subprocess: {cmd_str}")
            proc = subprocess.run(
                cmd_args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=60
            )
            output = proc.stdout
            if proc.returncode != 0 and not output:
                output = proc.stderr

        end_time = time.time()
        elapsed = end_time - start_time

        # Basic parse of open ports
        open_ports = []
        for line in output.splitlines():
            if "/tcp" in line and "open" in line:
                part = line.split("/")[0].strip()
                if part.isdigit():
                    open_ports.append(int(part))

        result.update({
            "end_time": end_time,
            "elapsed_sec": elapsed,
            "status": "success",
            "dry_run": False,
            "open_ports": open_ports,
            "output": output
        })
        logger.info(f"Port scan completed: elapsed={elapsed:.2f}s, open_ports={open_ports}")
    except Exception as e:
        end_time = time.time()
        logger.error(f"Port scan failed: {e}")
        result.update({
            "end_time": end_time,
            "elapsed_sec": end_time - start_time,
            "status": "failed",
            "error": str(e)
        })

    return result


def run_attack(*args, **kwargs) -> Dict[str, Any]:
    """Compatibility wrapper for run_attack API."""
    return port_scan(*args, **kwargs)


class PortScanAttack:
    """Object-oriented wrapper for Port Scan Attack."""

    def __init__(
        self,
        target_ip: str = "10.0.0.2",
        scan_type: str = "syn",
        port_range: str = "1-1024",
        timing: str = "T4"
    ):
        self.target_ip = target_ip
        self.scan_type = scan_type
        self.port_range = port_range
        self.timing = timing

    def execute(self, host: Any = None, dry_run: bool = False) -> Dict[str, Any]:
        return port_scan(
            target_ip=self.target_ip,
            scan_type=self.scan_type,
            port_range=self.port_range,
            timing=self.timing,
            host=host,
            dry_run=dry_run
        )


def main():
    parser = argparse.ArgumentParser(description="SDN Testbed Port Scan Generator (nmap)")
    parser.add_argument("--target", default="10.0.0.2", help="Victim target IP (default: 10.0.0.2)")
    parser.add_argument("--scan-type", choices=["syn", "connect"], default="syn", help="Scan type (default: syn)")
    parser.add_argument("--ports", default="1-1024", help="Port range to scan (default: 1-1024)")
    parser.add_argument("--timing", default="T4", help="Nmap timing flag (default: T4)")
    parser.add_argument("--dry-run", action="store_true", help="Dry run simulation mode")

    args = parser.parse_args()
    res = port_scan(
        target_ip=args.target,
        scan_type=args.scan_type,
        port_range=args.ports,
        timing=args.timing,
        dry_run=args.dry_run
    )
    print(f"Result: {res['status']}, elapsed={res['elapsed_sec']:.2f}s, open_ports={res['open_ports']}")
    if res["status"] != "success":
        sys.exit(1)


if __name__ == "__main__":
    main()
