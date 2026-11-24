#!/usr/bin/env python3
"""Automated Packet Capture Script for Project 27 Deliverable #4."""
import os, subprocess, sys, time

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.link import TCLink
from topo.sdn_tree_topo import SDNTreeTopo
from evaluation.live_benchmark import start_controller, stop_controller

CAP_DIR = os.path.join(PROJECT_ROOT, "captures")
os.makedirs(CAP_DIR, exist_ok=True)


def start_cap(iface: str, filename: str, bpf: str = "", count: int = 2000) -> subprocess.Popen:
    path = os.path.join(CAP_DIR, filename)
    cmd = ["tcpdump", "-i", iface, "-c", str(count), "-w", path]
    if bpf:
        cmd += bpf.split()
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def stop_cap(proc: subprocess.Popen) -> None:
    try:
        proc.terminate()
        proc.wait(timeout=3)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def main():
    subprocess.run(["mn", "-c"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ctrl = start_controller(poll_interval=1)
    net = Mininet(topo=SDNTreeTopo(), controller=None, switch=OVSKernelSwitch, link=TCLink, autoSetMacs=True)
    net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=6653)

    try:
        net.start()
        time.sleep(2.0)
        net.pingAll(timeout=1)
        h1, h3 = net.get("h1"), net.get("h3")

        # 1. Start OpenFlow 1.3 control-plane capture on loopback port 6653
        print("[1/4] Capturing OpenFlow 1.3 control plane (lo, tcp port 6653)...")
        cap_of = start_cap("lo", "01_openflow_stats_and_flowmod.pcapng", "tcp port 6653", count=4000)

        # 2. Capture normal benign traffic (h3 <-> h4 on s3-eth2)
        print("[2/4] Capturing normal benign traffic (h3 <-> h4)...")
        cap_norm = start_cap("s3-eth2", "02_normal_benign_traffic.pcapng", "icmp", count=500)
        h1.cmd("ping -c 12 -i 1 10.0.0.2 > /dev/null 2>&1 &")
        h3.cmd("ping -c 12 -i 1 10.0.0.4 > /dev/null 2>&1")
        stop_cap(cap_norm)

        # 3. Capture Nmap port scan (h3 -> h4 on s3-eth2)
        print("[3/4] Capturing Nmap SYN port scan (h3 -> h4, ports 1-50)...")
        cap_scan = start_cap("s3-eth2", "04_nmap_port_scan.pcapng", "tcp", count=1000)
        h3.cmd("nmap -sS -n -Pn -p 1-50 --max-retries 1 10.0.0.4 > /dev/null 2>&1")
        time.sleep(1.5)
        stop_cap(cap_scan)

        # 4. Capture SYN flood & mitigation cutoff (h1 -> h2 on s2-eth2)
        print("[4/4] Capturing SYN flood + OpenFlow drop mitigation (h1 -> h2)...")
        cap_syn = start_cap("s2-eth2", "03_syn_flood_and_mitigation.pcapng", "tcp", count=3000)
        h1.cmd("python3 attacks/syn_flood.py --target 10.0.0.2 --rate high --duration 5 > /dev/null 2>&1")
        time.sleep(1.5)
        stop_cap(cap_syn)
        stop_cap(cap_of)
    finally:
        net.stop()
        stop_controller(ctrl)

    print("\nCaptures saved in captures/:")
    subprocess.run(["ls", "-lh", CAP_DIR])


if __name__ == "__main__":
    main()
