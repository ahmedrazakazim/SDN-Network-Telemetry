"""
Flow and Port Feature Extraction Engine for SDN Telemetry.

Computes mathematical derivatives across consecutive polling snapshots:
  - delta_t = t_current - t_prev
  - delta_packets = max(0, stat.packet_count - prev.packet_count)
  - delta_bytes = max(0, stat.byte_count - prev.byte_count)
  - packet_rate = delta_packets / delta_t
  - byte_rate = delta_bytes / delta_t
  - duration = duration_sec + duration_nsec * 1e-9
  - avg_packet_size = byte_count / packet_count (0.0 if packet_count == 0)

Provides zero-division guards, counter-wrap / reset protection, port-level
rate and drop calculations, and host-level metric aggregations (packet_rate,
flow_rate, sliding window of targeted destination ports).
"""

import time
from collections import defaultdict, deque
from typing import Any, Dict, List, Optional, Tuple, Union


def parse_match(match: Any) -> Dict[str, Any]:
    """
    Safely extract OpenFlow match fields into a standard dictionary.

    Supports os-ken / Ryu OFPMatch instances, plain dictionaries,
    and mock objects.
    """
    if match is None:
        return {}

    if isinstance(match, dict):
        return dict(match)

    # OFPMatch or objects implementing items()
    if hasattr(match, "items"):
        try:
            return dict(match.items())
        except Exception:
            pass

    # Fallback to os-ken to_jsondict representation
    if hasattr(match, "to_jsondict"):
        try:
            jd = match.to_jsondict()
            oxm_fields = jd.get("OFPMatch", {}).get("oxm_fields", [])
            parsed = {}
            for field in oxm_fields:
                if isinstance(field, dict) and "OXMTlv" in field:
                    tlv = field["OXMTlv"]
                    parsed[tlv.get("field")] = tlv.get("value")
            return parsed
        except Exception:
            pass

    # Inspect common attributes
    known_fields = [
        "in_port", "eth_src", "eth_dst", "eth_type",
        "ipv4_src", "ipv4_dst", "ip_proto",
        "tcp_src", "tcp_dst", "udp_src", "udp_dst",
        "sctp_src", "sctp_dst", "icmpv4_type", "icmpv4_code"
    ]
    parsed = {}
    for f in known_fields:
        if hasattr(match, f):
            val = getattr(match, f)
            if val is not None:
                parsed[f] = val
        elif hasattr(match, "get"):
            val = match.get(f)
            if val is not None:
                parsed[f] = val

    return parsed


class FlowFeatureExtractor:
    """
    Extracts flow-level features and rate derivatives across polling snapshots.
    Guards against zero-division, counter resets, and flow churn.
    """

    def __init__(self, port_window_size: int = 100):
        # Maps flow_key -> {'packet_count': int, 'byte_count': int, 'timestamp': float, 'duration': float}
        self.prev_flow_stats: Dict[Tuple, Dict[str, Union[int, float]]] = {}

        # Maps port_key -> {'rx_packets': int, 'tx_packets': int, 'rx_bytes': int,
        #                   'tx_bytes': int, 'rx_dropped': int, 'tx_dropped': int, 'timestamp': float}
        self.prev_port_stats: Dict[Tuple, Dict[str, Union[int, float]]] = {}

        # Host-level tracking
        self.port_window_size = port_window_size
        self.host_dst_ports: Dict[str, deque] = defaultdict(lambda: deque(maxlen=self.port_window_size))
        self.host_active_flows: Dict[str, set] = defaultdict(set)
        self.host_last_time: Dict[str, float] = {}
        self._dpid_host_active_flows: Dict[Tuple[Any, str], set] = defaultdict(set)
        self._dpid_host_last_time: Dict[Tuple[Any, str], float] = {}

    def _make_flow_key(self, dpid: int, table_id: int, priority: int,
                       match_dict: Dict[str, Any], cookie: int) -> Tuple:
        """Create a hashable, deterministic flow identifier."""
        # Convert match items to sorted tuples for consistent hashing
        match_tuple = tuple(sorted((k, str(v)) for k, v in match_dict.items()))
        return (dpid, table_id, priority, match_tuple, cookie)

    def extract_flow_features(self, flow_stats_list: List[Any], dpid: int,
                              current_time: Optional[float] = None) -> List[Dict[str, Any]]:
        """
        Compute flow features and rates from OFPFlowStats reply entries.

        Returns a list of dictionaries adhering to the PROJECT.md interface contract:
        {
            'dpid': int,
            'table_id': int,
            'duration_sec': float,
            'priority': int,
            'match': dict,
            'packet_count': int,
            'byte_count': int,
            'packet_rate': float,
            'byte_rate': float,
            'avg_packet_size': float
        }
        """
        if current_time is None:
            current_time = time.time()
        else:
            current_time = float(current_time)

        flow_records: List[Dict[str, Any]] = []
        current_flow_keys_dpid = set()

        for stat in flow_stats_list:
            table_id = int(getattr(stat, "table_id", 0))
            priority = int(getattr(stat, "priority", 0))
            cookie = int(getattr(stat, "cookie", 0))

            packet_count = int(getattr(stat, "packet_count", 0))
            byte_count = int(getattr(stat, "byte_count", 0))

            duration_sec = int(getattr(stat, "duration_sec", 0))
            duration_nsec = int(getattr(stat, "duration_nsec", 0))
            duration = float(duration_sec) + float(duration_nsec) * 1e-9

            raw_match = getattr(stat, "match", None)
            match_dict = parse_match(raw_match)

            flow_key = self._make_flow_key(dpid, table_id, priority, match_dict, cookie)
            current_flow_keys_dpid.add(flow_key)

            # Average packet size: byte_count / packet_count (0.0 if packet_count == 0)
            if packet_count > 0:
                avg_packet_size = float(byte_count) / float(packet_count)
            else:
                avg_packet_size = 0.0

            # Rate calculations across consecutive snapshots
            if flow_key in self.prev_flow_stats:
                prev_stat = self.prev_flow_stats[flow_key]
                prev_time = prev_stat["timestamp"]
                delta_t = current_time - prev_time

                if delta_t > 0:
                    prev_packets = prev_stat["packet_count"]
                    prev_bytes = prev_stat["byte_count"]

                    delta_packets = max(0, packet_count - prev_packets)
                    delta_bytes = max(0, byte_count - prev_bytes)

                    packet_rate = float(delta_packets) / float(delta_t)
                    byte_rate = float(delta_bytes) / float(delta_t)
                else:
                    packet_rate = 0.0
                    byte_rate = 0.0
            else:
                # First time seeing this flow
                if duration > 0:
                    packet_rate = float(packet_count) / float(duration)
                    byte_rate = float(byte_count) / float(duration)
                else:
                    packet_rate = 0.0
                    byte_rate = 0.0

            # Update cache for this flow
            self.prev_flow_stats[flow_key] = {
                "packet_count": packet_count,
                "byte_count": byte_count,
                "timestamp": current_time,
                "duration": duration,
            }

            flow_record = {
                "dpid": dpid,
                "table_id": table_id,
                "duration_sec": duration,
                "priority": priority,
                "match": match_dict,
                "packet_count": packet_count,
                "byte_count": byte_count,
                "packet_rate": packet_rate,
                "byte_rate": byte_rate,
                "avg_packet_size": avg_packet_size,
            }
            flow_records.append(flow_record)

        # Prune expired flows from previous stats for this dpid
        expired_keys = [
            k for k in self.prev_flow_stats.keys()
            if k[0] == dpid and k not in current_flow_keys_dpid
        ]
        for k in expired_keys:
            del self.prev_flow_stats[k]

        return flow_records

    def extract_port_features(self, port_stats_list: List[Any], dpid: int,
                              current_time: Optional[float] = None) -> List[Dict[str, Any]]:
        """
        Compute port statistics and rx/tx packet/byte/drop rates from OFPPortStats.

        Returns a list of dictionaries adhering to the PROJECT.md interface contract:
        {
            'dpid': int,
            'port_no': int,
            'rx_packets': int,
            'tx_packets': int,
            'rx_bytes': int,
            'tx_bytes': int,
            'rx_dropped': int,
            'tx_dropped': int,
            'rx_packet_rate': float,
            'tx_packet_rate': float,
            'rx_byte_rate': float,
            'tx_byte_rate': float,
            'rx_drop_rate': float,
            'tx_drop_rate': float
        }
        """
        if current_time is None:
            current_time = time.time()
        else:
            current_time = float(current_time)

        port_records: List[Dict[str, Any]] = []

        for pstat in port_stats_list:
            port_no = int(getattr(pstat, "port_no", 0))
            rx_packets = int(getattr(pstat, "rx_packets", 0))
            tx_packets = int(getattr(pstat, "tx_packets", 0))
            rx_bytes = int(getattr(pstat, "rx_bytes", 0))
            tx_bytes = int(getattr(pstat, "tx_bytes", 0))
            rx_dropped = int(getattr(pstat, "rx_dropped", 0))
            tx_dropped = int(getattr(pstat, "tx_dropped", 0))

            port_key = (dpid, port_no)

            if port_key in self.prev_port_stats:
                prev = self.prev_port_stats[port_key]
                delta_t = current_time - prev["timestamp"]

                if delta_t > 0:
                    rx_packet_rate = max(0, rx_packets - prev["rx_packets"]) / float(delta_t)
                    tx_packet_rate = max(0, tx_packets - prev["tx_packets"]) / float(delta_t)
                    rx_byte_rate = max(0, rx_bytes - prev["rx_bytes"]) / float(delta_t)
                    tx_byte_rate = max(0, tx_bytes - prev["tx_bytes"]) / float(delta_t)
                    rx_drop_rate = max(0, rx_dropped - prev["rx_dropped"]) / float(delta_t)
                    tx_drop_rate = max(0, tx_dropped - prev["tx_dropped"]) / float(delta_t)
                else:
                    rx_packet_rate = 0.0
                    tx_packet_rate = 0.0
                    rx_byte_rate = 0.0
                    tx_byte_rate = 0.0
                    rx_drop_rate = 0.0
                    tx_drop_rate = 0.0
            else:
                rx_packet_rate = 0.0
                tx_packet_rate = 0.0
                rx_byte_rate = 0.0
                tx_byte_rate = 0.0
                rx_drop_rate = 0.0
                tx_drop_rate = 0.0

            self.prev_port_stats[port_key] = {
                "rx_packets": rx_packets,
                "tx_packets": tx_packets,
                "rx_bytes": rx_bytes,
                "tx_bytes": tx_bytes,
                "rx_dropped": rx_dropped,
                "tx_dropped": tx_dropped,
                "timestamp": current_time,
            }

            port_record = {
                "dpid": dpid,
                "port_no": port_no,
                "rx_packets": rx_packets,
                "tx_packets": tx_packets,
                "rx_bytes": rx_bytes,
                "tx_bytes": tx_bytes,
                "rx_dropped": rx_dropped,
                "tx_dropped": tx_dropped,
                "rx_packet_rate": rx_packet_rate,
                "tx_packet_rate": tx_packet_rate,
                "rx_byte_rate": rx_byte_rate,
                "tx_byte_rate": tx_byte_rate,
                "rx_drop_rate": rx_drop_rate,
                "tx_drop_rate": tx_drop_rate,
            }
            port_records.append(port_record)

        return port_records

    def aggregate_host_metrics(self, flow_features: List[Dict[str, Any]],
                               current_time: Optional[float] = None) -> Dict[str, Dict[str, Any]]:
        """
        Aggregate flow metrics per source IP host (ipv4_src).

        Calculates:
          - packet_rate: Sum of packet rates for flows originating from host
          - byte_rate: Sum of byte rates for flows originating from host
          - flow_rate: New flows created per second
          - dst_ports: Sliding window of destination ports targeted by host
          - active_flows: Count of active flow entries for this host

        Returns a dictionary mapping host_ip -> host_metric_dict.
        """
        if current_time is None:
            current_time = time.time()
        else:
            current_time = float(current_time)

        # Group flow records by source IP
        host_flows: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        current_host_flow_ids: Dict[str, set] = defaultdict(set)

        for record in flow_features:
            match = record.get("match", {})
            src_ip = match.get("ipv4_src")
            if not src_ip:
                continue

            host_flows[src_ip].append(record)

            # Unique flow identifier for new-flow rate tracking
            flow_id = (
                record.get("dpid"),
                record.get("table_id"),
                record.get("priority"),
                tuple(sorted((k, str(v)) for k, v in match.items())),
            )
            current_host_flow_ids[src_ip].add(flow_id)

            # Extract destination port for sliding window
            dst_port = match.get("tcp_dst") or match.get("udp_dst") or match.get("tp_dst") or match.get("sctp_dst")
            if dst_port is not None:
                try:
                    self.host_dst_ports[src_ip].append(int(dst_port))
                except (ValueError, TypeError):
                    pass

        aggregated: Dict[str, Dict[str, Any]] = {}

        for host_ip, records in host_flows.items():
            total_packet_rate = sum(r.get("packet_rate", 0.0) for r in records)
            total_byte_rate = sum(r.get("byte_rate", 0.0) for r in records)
            total_packets = sum(r.get("packet_count", 0) for r in records)
            total_bytes = sum(r.get("byte_count", 0) for r in records)

            # New flow rate calculation (scoped per switch dpid to prevent cross-switch clobbering)
            current_flows = current_host_flow_ids[host_ip]
            dpid_flow_sets: Dict[Any, set] = defaultdict(set)
            for fid in current_flows:
                dpid_flow_sets[fid[0]].add(fid)

            flow_rate = 0.0
            for dpid_key, dpid_curr in dpid_flow_sets.items():
                state_key = (dpid_key, host_ip)
                prev_flows = self._dpid_host_active_flows.get(state_key, set())
                new_flows = len(dpid_curr - prev_flows)
                last_t = self._dpid_host_last_time.get(state_key)
                if last_t is not None and current_time > last_t:
                    delta_t = current_time - last_t
                    flow_rate += float(new_flows) / float(delta_t)
                else:
                    flow_rate += 0.0 if last_t is not None else float(new_flows)
                self._dpid_host_active_flows[state_key] = dpid_curr
                self._dpid_host_last_time[state_key] = current_time

            self.host_active_flows[host_ip] = current_flows
            self.host_last_time[host_ip] = current_time

            aggregated[host_ip] = {
                "host_ip": host_ip,
                "packet_rate": total_packet_rate,
                "byte_rate": total_byte_rate,
                "flow_rate": flow_rate,
                "dst_ports": list(self.host_dst_ports[host_ip]),
                "active_flows": len(records),
                "total_packets": total_packets,
                "total_bytes": total_bytes,
            }

        return aggregated

    def reset(self) -> None:
        """Clear all stored state and history."""
        self.prev_flow_stats.clear()
        self.prev_port_stats.clear()
        self.host_dst_ports.clear()
        self.host_active_flows.clear()
        self.host_last_time.clear()
        self._dpid_host_active_flows.clear()
        self._dpid_host_last_time.clear()
