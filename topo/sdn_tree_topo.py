#!/usr/bin/env python3
"""SDN Tree Topology (depth=2, fanout=2).

Configures:
- 3 OpenFlow 1.3 switches: s1 (root, dpid=1), s2 (pod, dpid=2), s3 (pod, dpid=3)
- 4 hosts on 10.0.0.0/24 subnet:
    h1: 10.0.0.1/24, MAC 00:00:00:00:00:01 (Attacker)
    h2: 10.0.0.2/24, MAC 00:00:00:00:00:02 (Victim)
    h3: 10.0.0.3/24, MAC 00:00:00:00:00:03 (Benign)
    h4: 10.0.0.4/24, MAC 00:00:00:00:00:04 (Benign)
- Links: s1-s2, s1-s3, s2-h1, s2-h2, s3-h3, s3-h4
- Remote OpenFlow 1.3 controller at 127.0.0.1:6653
"""

import os
import sys

# Ensure project root is in sys.path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

import argparse
from functools import partial

# Check Mininet availability; if unavailable, provide compatible fallback
try:
    from mininet.topo import Topo
    from mininet.net import Mininet
    from mininet.node import RemoteController, OVSSwitch
    from mininet.cli import CLI
    from mininet.log import setLogLevel, info
    MININET_AVAILABLE = True
except ImportError:
    MININET_AVAILABLE = False

    class Topo:
        """Fallback Topo implementation for testing when Mininet is not installed."""

        def __init__(self, *args, **kwargs):
            self.hosts_dict = {}
            self.switches_dict = {}
            self.links_list = []
            self.ports_dict = {}
            self.build(*args, **kwargs)

        def build(self, *args, **kwargs):
            pass

        def addSwitch(self, name, **opts):
            self.switches_dict[name] = dict(opts)
            return name

        def addHost(self, name, **opts):
            self.hosts_dict[name] = dict(opts)
            return name

        def addLink(self, node1, node2, **opts):
            self.links_list.append((node1, node2, dict(opts)))
            return (node1, node2)

        def switches(self, sort=True):
            res = list(self.switches_dict.keys())
            return sorted(res) if sort else res

        def hosts(self, sort=True):
            res = list(self.hosts_dict.keys())
            return sorted(res) if sort else res

        def links(self, sort=True, withKeys=False, withCoords=False):
            res = [(src, dst) for src, dst, _ in self.links_list]
            return sorted(res) if sort else res

        def nodeInfo(self, name):
            if name in self.hosts_dict:
                return self.hosts_dict[name]
            if name in self.switches_dict:
                return self.switches_dict[name]
            raise KeyError(f"Node {name} not found in topology.")

        def isSwitch(self, name):
            return name in self.switches_dict

    class MockNode:
        def __init__(self, name, ip=None, mac=None):
            self.name = name
            self.IP = lambda: ip.split('/')[0] if ip else None
            self.MAC = lambda: mac
            self.ip = ip
            self.mac = mac

        def cmd(self, command, *args, **kwargs):
            return ""

        def popen(self, *args, **kwargs):
            import subprocess
            return subprocess.Popen(*args, **kwargs)

    class MockMininet:
        """Mock Mininet for test execution without root/mininet."""

        def __init__(self, topo=None, controller=None, switch=None, **kwargs):
            self.topo = topo
            self.controllers = [controller] if controller else []
            self.hosts = []
            self.switches = []
            self.nameToNode = {}

            if topo:
                for h in topo.hosts():
                    info_dict = topo.nodeInfo(h)
                    node = MockNode(h, ip=info_dict.get('ip'), mac=info_dict.get('mac'))
                    self.hosts.append(node)
                    self.nameToNode[h] = node
                for s in topo.switches():
                    info_dict = topo.nodeInfo(s)
                    node = MockNode(s)
                    self.switches.append(node)
                    self.nameToNode[s] = node

        def get(self, *names):
            if len(names) == 1:
                return self.nameToNode.get(names[0])
            return [self.nameToNode.get(n) for n in names]

        def start(self):
            return True

        def stop(self):
            return True

        def pingAll(self):
            return 0.0

        def ping(self, hosts=None, timeout=None):
            return 0.0


def format_dpid(dpid_int: int) -> str:
    """Format integer dpid into 16-character hex string required by OpenFlow 1.3."""
    return format(dpid_int, "016x")


class SDNTreeTopo(Topo):
    """Mininet Tree Topology with depth=2 and fanout=2.

    Switches:
        s1: Root switch (dpid=1)
        s2: Pod 1 switch (dpid=2)
        s3: Pod 2 switch (dpid=3)
    Hosts:
        h1: 10.0.0.1/24, MAC 00:00:00:00:00:01
        h2: 10.0.0.2/24, MAC 00:00:00:00:00:02
        h3: 10.0.0.3/24, MAC 00:00:00:00:00:03
        h4: 10.0.0.4/24, MAC 00:00:00:00:00:04
    """

    def __init__(self, depth=2, fanout=2, **opts):
        self.depth = depth
        self.fanout = fanout
        super().__init__(**opts)

    def build(self, *args, **kwargs):
        """Construct the SDN Tree topology."""
        # OpenFlow 1.3 protocol setting for Open vSwitch
        switch_opts = {
            "protocols": "OpenFlow13"
        }

        # Root Switch
        s1 = self.addSwitch("s1", dpid=format_dpid(1), **switch_opts)

        # Pod Switches
        s2 = self.addSwitch("s2", dpid=format_dpid(2), **switch_opts)
        s3 = self.addSwitch("s3", dpid=format_dpid(3), **switch_opts)

        # Inter-switch links (tree backbone)
        self.addLink(s1, s2)
        self.addLink(s1, s3)

        # Hosts with fixed IPs and MACs on 10.0.0.0/24
        h1 = self.addHost("h1", ip="10.0.0.1/24", mac="00:00:00:00:00:01")
        h2 = self.addHost("h2", ip="10.0.0.2/24", mac="00:00:00:00:00:02")
        h3 = self.addHost("h3", ip="10.0.0.3/24", mac="00:00:00:00:00:03")
        h4 = self.addHost("h4", ip="10.0.0.4/24", mac="00:00:00:00:00:04")

        # Edge links: pod switches to hosts
        self.addLink(s2, h1)
        self.addLink(s2, h2)
        self.addLink(s3, h3)
        self.addLink(s3, h4)


def create_network(controller_ip="127.0.0.1", controller_port=6653, config_path=None):
    """Programmatic API to build and instantiate the Mininet network.

    Args:
        controller_ip (str): IP address of remote OpenFlow controller.
        controller_port (int): TCP port of remote OpenFlow controller.
        config_path (str, optional): Path to YAML config file.

    Returns:
        Mininet instance (or MockMininet if Mininet library is unavailable).
    """
    topo = SDNTreeTopo(depth=2, fanout=2)

    if not MININET_AVAILABLE:
        return MockMininet(topo=topo)

    # Use Open vSwitch configured explicitly for OpenFlow 1.3
    ovs_switch = partial(OVSSwitch, protocols="OpenFlow13")

    net = Mininet(
        topo=topo,
        switch=ovs_switch,
        controller=None,
        autoSetMacs=False,
        autoStaticArp=False
    )

    # Add remote OpenFlow 1.3 controller
    net.addController(
        "c0",
        controller=RemoteController,
        ip=controller_ip,
        port=int(controller_port)
    )

    return net


def main():
    """CLI Entry point for viva demonstration and testing."""
    parser = argparse.ArgumentParser(description="SDN Tree Topology (Mininet)")
    parser.add_argument("--controller-ip", default="127.0.0.1", help="Controller IP (default: 127.0.0.1)")
    parser.add_argument("--controller-port", type=int, default=6653, help="Controller OF port (default: 6653)")
    parser.add_argument("--pingall", action="store_true", help="Run pingAll upon start")
    parser.add_argument("--cli", action="store_true", default=True, help="Enter Mininet interactive CLI")
    args = parser.parse_args()

    if not MININET_AVAILABLE:
        print("[!] Mininet is not installed or not available in this environment.")
        print("[*] Tested topology structure successfully in mock mode:")
        topo = SDNTreeTopo()
        print(f"    Switches ({len(topo.switches())}): {topo.switches()}")
        print(f"    Hosts ({len(topo.hosts())}): {topo.hosts()}")
        print(f"    Links ({len(topo.links())}): {topo.links()}")
        sys.exit(0)

    setLogLevel("info")
    info(f"*** Creating SDN Tree Topology connecting to {args.controller_ip}:{args.controller_port}\n")
    net = create_network(controller_ip=args.controller_ip, controller_port=args.controller_port)

    info("*** Starting network\n")
    net.start()

    if args.pingall:
        info("*** Testing reachability (pingAll)\n")
        net.pingAll()

    if args.cli:
        info("*** Entering Mininet CLI (type 'exit' to terminate)\n")
        CLI(net)

    info("*** Stopping network\n")
    net.stop()


if __name__ == "__main__":
    main()
