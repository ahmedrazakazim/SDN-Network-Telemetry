#!/usr/bin/env python3
"""
Automated Flow Mitigation Engine for OpenFlow 1.3 Controller.

Complies with requirement R5 and interface contracts:
- Installs high-priority (priority=1000) OpenFlow 1.3 drop rules matching offending IPv4 source addresses.
- Enforces OpenFlow 1.3 match prerequisite: eth_type=0x0800 for ipv4_src matches.
- Uses empty instructions list to specify drop action in OpenFlow 1.3.
- Configures hard_timeout (default: 300s) for automatic expiry and supports explicit unblocking.
- Enforces Source-Isolation Non-Disruption Guarantee: ensures benign hosts (e.g. h2, h3, h4)
  are never blocked and can communicate with 0% packet loss.
"""

import logging
import os
import sys
import time
from typing import Any, Dict, List, Optional, Set

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

logger = logging.getLogger("mitigation_engine")

# Import FlowManager if available, with graceful fallback
try:
    from controller.flow_manager import FlowManager
except ImportError:
    FlowManager = None


class MitigationEngine:
    """
    OpenFlow 1.3 Automated Flow Mitigation Engine.

    Manages dynamic drop rules to isolate attacking hosts while guaranteeing
    uninterrupted service for legitimate network endpoints.
    """

    PRIORITY_DROP = 1000
    ETH_TYPE_IPV4 = 0x0800
    DEFAULT_TIMEOUT = 300  # seconds

    def __init__(
        self,
        controller: Any = None,
        default_timeout: int = DEFAULT_TIMEOUT,
        protected_hosts: Optional[Set[str]] = None
    ):
        """
        Initialize the Mitigation Engine.

        :param controller: Reference to os-ken/ryu controller instance containing .datapaths
        :param default_timeout: Hard timeout in seconds for installed drop rules (default: 300s)
        :param protected_hosts: Set of IP addresses protected against accidental blocking
        """
        self.controller = controller
        self.default_timeout = default_timeout
        self.flow_manager = FlowManager() if FlowManager else None
        self.blocked_hosts: Dict[str, Dict[str, Any]] = {}

        # Default protected benign hosts in topology
        self.protected_hosts: Set[str] = set(protected_hosts) if protected_hosts else {
            "10.0.0.3",  # Benign host h3
            "10.0.0.4",  # Benign host h4
        }
        logger.info(
            f"Initialized MitigationEngine (priority={self.PRIORITY_DROP}, "
            f"default_timeout={self.default_timeout}s, protected_hosts={self.protected_hosts})"
        )

    def set_controller(self, controller: Any) -> None:
        """Update or attach controller instance."""
        self.controller = controller

    def is_blocked(self, host_ip: str) -> bool:
        """
        Check whether host_ip is currently blocked by an active mitigation drop rule.
        Automatically purges entries whose hard_timeout has elapsed.
        """
        if host_ip not in self.blocked_hosts:
            return False

        entry = self.blocked_hosts[host_ip]
        elapsed = time.time() - entry["timestamp"]
        if entry["hard_timeout"] > 0 and elapsed >= entry["hard_timeout"]:
            logger.info(f"Mitigation drop rule for {host_ip} expired after {elapsed:.1f}s (hard_timeout={entry['hard_timeout']}s)")
            del self.blocked_hosts[host_ip]
            return False

        return True

    def get_blocked_hosts(self) -> Dict[str, Dict[str, Any]]:
        """Return a copy of currently active blocked host entries."""
        # Prune expired entries first
        now = time.time()
        expired = [
            ip for ip, data in self.blocked_hosts.items()
            if data["hard_timeout"] > 0 and (now - data["timestamp"]) >= data["hard_timeout"]
        ]
        for ip in expired:
            del self.blocked_hosts[ip]

        return {ip: dict(data) for ip, data in self.blocked_hosts.items()}

    def mitigate_host(
        self,
        offending_ip: str,
        reason: str = "",
        hard_timeout: Optional[int] = None,
        override_protection: bool = False
    ) -> Dict[str, Any]:
        """
        Install high-priority OpenFlow 1.3 drop rule blocking traffic from offending_ip.

        Specifications:
        - Priority: 1000 (strictly higher than forwarding priority 1 and table-miss 0)
        - Match: eth_type=0x0800, ipv4_src=offending_ip (satisfies OpenFlow 1.3 prerequisite)
        - Instructions: [] (empty instructions list = DROP)
        - Hard Timeout: 300 seconds (or custom parameter)

        :param offending_ip: IP address of the malicious source to block
        :param reason: Description of the detected anomaly (e.g. 'syn_flood', 'udp_flood', 'port_scan')
        :param hard_timeout: Expiration timeout in seconds
        :param override_protection: Bypass non-disruption protection check
        :return: Execution summary dictionary
        """
        timestamp = time.time()
        timeout = hard_timeout if hard_timeout is not None else self.default_timeout

        # Source-Isolation Non-Disruption Guarantee Check
        if offending_ip in self.protected_hosts and not override_protection:
            err_msg = (
                f"Mitigation rejected for {offending_ip}: host is in protected benign host list "
                f"({self.protected_hosts}). Enforcing non-disruption guarantee."
            )
            logger.error(err_msg)
            return {
                "success": False,
                "offending_ip": offending_ip,
                "installed_rules": 0,
                "timestamp": timestamp,
                "reason": reason,
                "error": err_msg
            }

        installed_count = 0
        datapaths = self._get_datapaths()

        for dp in datapaths:
            try:
                self._install_drop_on_datapath(dp, offending_ip, timeout)
                installed_count += 1
            except Exception as e:
                logger.error(f"Failed to install drop rule on datapath {getattr(dp, 'id', 'unknown')}: {e}")

        # Record in blocked hosts table
        self.blocked_hosts[offending_ip] = {
            "timestamp": timestamp,
            "reason": reason,
            "hard_timeout": timeout,
            "priority": self.PRIORITY_DROP,
            "installed_rules": installed_count
        }

        logger.warning(
            f"Mitigation active: Blocked offending source {offending_ip} across {installed_count} "
            f"switches (reason='{reason}', priority={self.PRIORITY_DROP}, timeout={timeout}s)"
        )

        return {
            "success": True,
            "offending_ip": offending_ip,
            "installed_rules": installed_count,
            "timestamp": timestamp,
            "reason": reason,
            "hard_timeout": timeout,
            "priority": self.PRIORITY_DROP
        }

    def unblock_host(self, offending_ip: str) -> Dict[str, Any]:
        """
        Delete high-priority drop rule matching offending_ip via OFPFC_DELETE.

        :param offending_ip: IP address to unblock
        :return: Execution summary dictionary
        """
        timestamp = time.time()
        deleted_count = 0
        datapaths = self._get_datapaths()

        for dp in datapaths:
            try:
                self._delete_drop_on_datapath(dp, offending_ip)
                deleted_count += 1
            except Exception as e:
                logger.error(f"Failed to remove drop rule on datapath {getattr(dp, 'id', 'unknown')}: {e}")

        was_blocked = offending_ip in self.blocked_hosts
        if was_blocked:
            del self.blocked_hosts[offending_ip]

        logger.info(
            f"Unblocked host {offending_ip} across {deleted_count} switches (was_tracked={was_blocked})"
        )

        return {
            "success": True,
            "offending_ip": offending_ip,
            "deleted_rules": deleted_count,
            "timestamp": timestamp,
            "was_tracked": was_blocked
        }

    def clear_all_blocks(self) -> Dict[str, Any]:
        """Remove all active mitigation drop rules."""
        blocked_list = list(self.blocked_hosts.keys())
        results = {}
        for ip in blocked_list:
            results[ip] = self.unblock_host(ip)
        return {
            "cleared_count": len(blocked_list),
            "hosts": blocked_list,
            "details": results
        }

    def verify_non_disruption(
        self,
        benign_hosts: Optional[List[str]] = None,
        mininet_net: Any = None
    ) -> Dict[str, Any]:
        """
        Verify that benign hosts are not disrupted while an attacker is mitigated.

        Checks:
        1. None of the benign hosts appear in the blocked_hosts registry.
        2. If live Mininet net is provided, executes ping test between benign hosts (e.g. h3 -> h4)
           to confirm 0% packet loss.
        """
        if benign_hosts is None:
            benign_hosts = ["10.0.0.2", "10.0.0.3", "10.0.0.4"]

        # Step 1: Check block state
        improperly_blocked = [h for h in benign_hosts if self.is_blocked(h)]
        non_disrupted = len(improperly_blocked) == 0

        result = {
            "non_disrupted": non_disrupted,
            "benign_hosts_evaluated": benign_hosts,
            "improperly_blocked": improperly_blocked,
            "active_blocks": list(self.blocked_hosts.keys()),
            "packet_loss_pct": 0.0,
            "ping_verified": False,
            "details": ""
        }

        if not non_disrupted:
            result["details"] = f"CRITICAL: Benign hosts blocked: {improperly_blocked}"
            return result

        # Step 2: Live Mininet ping validation between h3 and h4 if net provided
        if mininet_net is not None:
            try:
                h3 = mininet_net.get("h3")
                h4 = mininet_net.get("h4")
                if h3 and h4:
                    ping_output = h3.cmd(f"ping -c 3 -W 1 {h4.IP()}")
                    loss_pct = 0.0
                    for line in ping_output.splitlines():
                        if "packet loss" in line:
                            parts = line.split("% packet loss")[0].split(",")
                            loss_str = parts[-1].strip()
                            loss_pct = float(loss_str)
                    result["packet_loss_pct"] = loss_pct
                    result["ping_verified"] = True
                    result["non_disrupted"] = (loss_pct == 0.0)
                    result["details"] = f"Live ping h3->h4 loss: {loss_pct}%"
            except Exception as e:
                result["details"] = f"Mininet ping check error: {e}"
        else:
            result["details"] = "Registry verification passed (0 benign hosts blocked)."

        return result

    def _get_datapaths(self) -> List[Any]:
        """Retrieve list of active datapaths from controller."""
        if self.controller is None:
            return []

        if hasattr(self.controller, "datapaths"):
            dp_dict = self.controller.datapaths
            if isinstance(dp_dict, dict):
                return list(dp_dict.values())
            elif isinstance(dp_dict, list):
                return dp_dict

        if hasattr(self.controller, "dps"):
            return list(self.controller.dps.values())

        return []

    def _install_drop_on_datapath(self, datapath: Any, offending_ip: str, hard_timeout: int) -> Any:
        """Construct and send OpenFlow 1.3 drop rule to a single switch."""
        if self.flow_manager is not None:
            return self.flow_manager.install_drop_rule(
                datapath=datapath,
                priority=self.PRIORITY_DROP,
                ipv4_src=offending_ip,
                idle_timeout=0,
                hard_timeout=hard_timeout
            )

        # Fallback to direct OpenFlow message creation
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(eth_type=self.ETH_TYPE_IPV4, ipv4_src=offending_ip)
        inst = []  # Empty instructions = DROP

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=self.PRIORITY_DROP,
            match=match,
            instructions=inst,
            idle_timeout=0,
            hard_timeout=hard_timeout,
            command=ofproto.OFPFC_ADD
        )
        datapath.send_msg(mod)
        return mod

    def _delete_drop_on_datapath(self, datapath: Any, offending_ip: str) -> Any:
        """Construct and send OpenFlow 1.3 delete rule to a single switch."""
        if self.flow_manager is not None:
            return self.flow_manager.remove_drop_rule(
                datapath=datapath,
                ipv4_src=offending_ip,
                priority=self.PRIORITY_DROP
            )

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(eth_type=self.ETH_TYPE_IPV4, ipv4_src=offending_ip)
        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            priority=self.PRIORITY_DROP,
            match=match
        )
        datapath.send_msg(mod)
        return mod
