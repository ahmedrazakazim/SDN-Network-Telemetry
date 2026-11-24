#!/usr/bin/env python3
import eventlet
eventlet.monkey_patch()

"""OpenFlow 1.3 SDN Controller Application.

Manages Mininet OpenFlow 1.3 switches:
- Installs table-miss flow rule (priority=0) to direct unmatched packets to controller
- Performs L2 learning and forwarding at priority=1
- Enforces OpenFlow 1.3 match prerequisites (eth_type=0x0800 for IPv4 matches)
- Tracks active switch datapaths (self.datapaths[dpid] = datapath)
- Provides dynamic flow mitigation hooks (installing priority=1000 drop rules)
- Exposes telemetry request hooks and stats reply handlers
"""

import os
import sys

# Ensure project root is in sys.path for direct script execution
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

import time
import logging
from typing import Dict, Any, Optional

import yaml

from controller.flow_manager import FlowManager

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("SDNController")

# Dynamic import support for os_ken, ryu, and standalone mock environments
try:
    import os_ken
    from os_ken.base import app_manager
    from os_ken.controller import ofp_event
    from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
    from os_ken.controller.handler import set_ev_cls
    from os_ken.ofproto import ofproto_v1_3
    from os_ken.lib.packet import packet, ethernet, ether_types, ipv4, arp, in_proto, tcp, udp
    CONTROLLER_BACKEND = "os_ken"
    BASE_APP = app_manager.OSKenApp
except ImportError:
    try:
        import ryu
        from ryu.base import app_manager
        from ryu.controller import ofp_event
        from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
        from ryu.controller.handler import set_ev_cls
        from ryu.ofproto import ofproto_v1_3
        from ryu.lib.packet import packet, ethernet, ether_types, ipv4, arp, in_proto, tcp, udp
        CONTROLLER_BACKEND = "ryu"
        BASE_APP = app_manager.RyuApp
    except ImportError:
        CONTROLLER_BACKEND = "mock"

        class MockTCP:
            class tcp:
                def __init__(self, dst_port=0, src_port=0):
                    self.dst_port = dst_port
                    self.src_port = src_port

        class MockUDP:
            class udp:
                def __init__(self, dst_port=0, src_port=0):
                    self.dst_port = dst_port
                    self.src_port = src_port

        tcp = MockTCP()
        udp = MockUDP()

        class MockBaseApp:
            def __init__(self, *args, **kwargs):
                pass

        class MockOFPEvent:
            class EventOFPSwitchFeatures:
                pass
            class EventOFPPacketIn:
                pass
            class EventOFPFlowStatsReply:
                pass
            class EventOFPPortStatsReply:
                pass
            class EventOFPStateChange:
                pass
            class EventOFPPortStatus:
                pass

        def mock_set_ev_cls(ev, dispatchers=None):
            def decorator(f):
                f._event = ev
                f._dispatchers = dispatchers
                return f
            return decorator

        class MockEtherTypes:
            ETH_TYPE_IP = 0x0800
            ETH_TYPE_ARP = 0x0806
            ETH_TYPE_LLDP = 0x88cc
            ETH_TYPE_IPV6 = 0x86dd

        class MockInProto:
            IPPROTO_TCP = 6
            IPPROTO_UDP = 17
            IPPROTO_ICMP = 1

        CONFIG_DISPATCHER = "config"
        MAIN_DISPATCHER = "main"
        DEAD_DISPATCHER = "dead"
        set_ev_cls = mock_set_ev_cls
        ofp_event = MockOFPEvent()
        ether_types = MockEtherTypes()
        in_proto = MockInProto()

        from controller.flow_manager import ofproto_v1_3
        BASE_APP = MockBaseApp


class SDNController(BASE_APP):
    """OpenFlow 1.3 Learning Switch and Telemetry/Mitigation Controller."""

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.flow_manager = FlowManager()
        self.datapaths: Dict[int, Any] = {}
        self.mac_to_port: Dict[int, Dict[str, int]] = {}
        self.blocked_ips: Dict[str, float] = {}
        self.telemetry_collector = None
        self.mitigation_engine = None
        self.anomaly_detector = None
        self.ml_detector = None
        self.exporter = None
        self.config: Dict[str, Any] = {}

        self.load_config()

        # 1. Instantiate Prometheus Telemetry Exporter and start HTTP server on port 8000
        try:
            from telemetry.exporter import PrometheusTelemetryExporter
            exporter_port = self.config.get("telemetry", {}).get("exporter_port", 8000)
            self.exporter = PrometheusTelemetryExporter(port=exporter_port, host="0.0.0.0")
            if self.exporter.start_server():
                logger.info(f"Prometheus telemetry exporter listening at http://0.0.0.0:{exporter_port}/metrics")
            else:
                logger.info(f"Prometheus telemetry exporter initialized on port {exporter_port}")
        except Exception as e:
            logger.warning(f"Could not initialize Prometheus exporter: {e}")

        # 2. Instantiate Statistical Anomaly Detector
        try:
            from detection.baseline_detector import StatisticalAnomalyDetector
            det_cfg = self.config.get("detection", {}).get("baseline", {})
            self.anomaly_detector = StatisticalAnomalyDetector(
                alpha=det_cfg.get("alpha", 0.2),
                z_threshold=det_cfg.get("z_threshold", 3.0),
                entropy_threshold=det_cfg.get("entropy_threshold", 3.0),
                warmup_ticks=det_cfg.get("warmup_ticks", 10)
            )
            logger.info("StatisticalAnomalyDetector initialized and wired to telemetry")
        except Exception as e:
            logger.warning(f"Could not initialize anomaly detector: {e}")

        # 2b. Instantiate Isolation Forest ML Anomaly Detector
        try:
            from detection.ml_detector import IsolationForestAnomalyDetector
            ml_cfg = self.config.get("detection", {}).get("ml", {})
            rel_model_path = ml_cfg.get("model_path", "detection/models/isolation_forest.joblib")
            project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
            model_path = rel_model_path if os.path.isabs(rel_model_path) else os.path.join(project_root, rel_model_path)
            if os.path.exists(model_path):
                self.ml_detector = IsolationForestAnomalyDetector(model_path=model_path)
                if getattr(self.ml_detector, "model", None) is not None:
                    self.ml_detector.model.n_jobs = 1
                logger.info(f"IsolationForestAnomalyDetector loaded from {model_path}")
            else:
                logger.warning(f"ML model file not found at {model_path}; live ML scoring disabled")
        except Exception as e:
            logger.warning(f"Could not initialize ML detector: {e}")

        # 3. Instantiate Mitigation Engine
        try:
            from mitigation.mitigation_engine import MitigationEngine
            mit_timeout = self.config.get("mitigation", {}).get("default_timeout", 300)
            self.mitigation_engine = MitigationEngine(controller=self, default_timeout=mit_timeout)
            logger.info("MitigationEngine initialized")
        except Exception as e:
            logger.warning(f"Could not initialize mitigation engine: {e}")

        # 4. Instantiate Telemetry Collector and start monitoring loop
        try:
            from telemetry.collector import TelemetryCollector
            poll_interval = float(os.environ.get("SDN_POLL_INTERVAL", self.config.get("telemetry", {}).get("default_poll_interval", 1.0)))
            self.telemetry_collector = TelemetryCollector(
                datapaths=self.datapaths,
                poll_interval=poll_interval,
                exporter=self.exporter,
                flow_callback=self._handle_telemetry_flow_stats
            )
            self.telemetry_collector.start(use_greenlet=True)
            logger.info(f"TelemetryCollector registered and polling loop started (interval={poll_interval}s)")
        except Exception as e:
            logger.warning(f"Could not initialize telemetry collector: {e}")

        logger.info(f"Initialized SDNController with backend: {CONTROLLER_BACKEND}")

    def load_config(self, config_path: Optional[str] = None):
        """Load YAML configuration from configs/sdn_config.yaml."""
        if not config_path:
            # Search candidate paths relative to workspace
            candidates = [
                os.path.join(os.getcwd(), "configs", "sdn_config.yaml"),
                os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "configs", "sdn_config.yaml"),
                "/home/zen/cn-project/configs/sdn_config.yaml"
            ]
            for path in candidates:
                if os.path.exists(path):
                    config_path = path
                    break

        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, "r") as f:
                    self.config = yaml.safe_load(f) or {}
                logger.info(f"Loaded configuration from {config_path}")
            except Exception as e:
                logger.warning(f"Failed to parse config from {config_path}: {e}")
        else:
            logger.info("Using default in-memory controller configuration")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Handle switch connection and install table-miss flow entry."""
        datapath = ev.msg.datapath
        dpid = getattr(datapath, "id", None)
        logger.info(f"Switch connected: DPID={dpid}")

        # Register datapath and MAC table
        if dpid is not None:
            self.datapaths[dpid] = datapath
            self.mac_to_port.setdefault(dpid, {})

        # Install table-miss entry (priority=0) to send unmatched packets to controller
        self.flow_manager.install_table_miss(datapath, table_id=0)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        """Track switches entering and leaving the network."""
        datapath = ev.datapath
        dpid = getattr(datapath, "id", None)
        if dpid is None:
            return

        if ev.state == MAIN_DISPATCHER:
            if dpid not in self.datapaths:
                logger.info(f"Datapath registered: DPID={dpid}")
                self.datapaths[dpid] = datapath
                self.mac_to_port.setdefault(dpid, {})
        elif ev.state == DEAD_DISPATCHER:
            if dpid in self.datapaths:
                logger.info(f"Datapath unregistered: DPID={dpid}")
                del self.datapaths[dpid]
                self.mac_to_port.pop(dpid, None)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Handle PacketIn event, perform L2 learning, and install forwarding rule."""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = getattr(datapath, "ofproto", self.flow_manager.ofproto)
        parser = getattr(datapath, "ofproto_parser", self.flow_manager.parser)
        dpid = getattr(datapath, "id", None)

        if dpid is None:
            return

        in_port = msg.match["in_port"] if "in_port" in msg.match else 0

        # Parse packet headers
        pkt = None
        eth = None
        ip_pkt = None
        arp_pkt = None
        tcp_pkt = None
        udp_pkt = None

        if hasattr(msg, "src_mac") and hasattr(msg, "dst_mac"):
            # Directly provided parsed attributes (e.g., in unit tests)
            src = msg.src_mac
            dst = msg.dst_mac
            eth_type = getattr(msg, "eth_type", 0x0800)
            ip_pkt = getattr(msg, "ip_pkt", None)
            arp_pkt = getattr(msg, "arp_pkt", None)
            tcp_pkt = getattr(msg, "tcp_pkt", None)
            udp_pkt = getattr(msg, "udp_pkt", None)
        elif CONTROLLER_BACKEND in ("os_ken", "ryu"):
            try:
                pkt = packet.Packet(msg.data)
                eth_list = pkt.get_protocols(ethernet.ethernet)
                if not eth_list:
                    return
                eth = eth_list[0]
                if eth.ethertype == ether_types.ETH_TYPE_LLDP:
                    # Ignore LLDP packet
                    return

                ip_proto_pkts = pkt.get_protocols(ipv4.ipv4)
                ip_pkt = ip_proto_pkts[0] if ip_proto_pkts else None

                arp_proto_pkts = pkt.get_protocols(arp.arp)
                arp_pkt = arp_proto_pkts[0] if arp_proto_pkts else None

                tcp_proto_pkts = pkt.get_protocols(tcp.tcp)
                tcp_pkt = tcp_proto_pkts[0] if tcp_proto_pkts else None

                udp_proto_pkts = pkt.get_protocols(udp.udp)
                udp_pkt = udp_proto_pkts[0] if udp_proto_pkts else None

                dst = eth.dst
                src = eth.src
                eth_type = eth.ethertype
            except Exception as e:
                logger.debug(f"Packet parsing error: {e}")
                return
        else:
            # Standalone / mock representation
            src = getattr(msg, "src_mac", "00:00:00:00:00:01")
            dst = getattr(msg, "dst_mac", "00:00:00:00:00:02")
            eth_type = getattr(msg, "eth_type", ether_types.ETH_TYPE_IP)
            ip_pkt = getattr(msg, "ip_pkt", None)
            arp_pkt = getattr(msg, "arp_pkt", None)
            tcp_pkt = getattr(msg, "tcp_pkt", None)
            udp_pkt = getattr(msg, "udp_pkt", None)

        # Check if source IP is actively blocked
        if ip_pkt and ip_pkt.src in self.blocked_ips:
            logger.debug(f"Dropping packet from blocked host: {ip_pkt.src}")
            return

        # Immediately record destination port from TCP/UDP PacketIn for entropy tracking
        if ip_pkt and self.telemetry_collector and hasattr(self.telemetry_collector, "feature_extractor"):
            fe = self.telemetry_collector.feature_extractor
            if tcp_pkt and hasattr(tcp_pkt, "dst_port"):
                fe.host_dst_ports[ip_pkt.src].append(int(tcp_pkt.dst_port))
            elif udp_pkt and hasattr(udp_pkt, "dst_port"):
                fe.host_dst_ports[ip_pkt.src].append(int(udp_pkt.dst_port))

        self.mac_to_port.setdefault(dpid, {})

        # Learn MAC address to port mapping
        self.mac_to_port[dpid][src] = in_port

        # Determine destination port
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Install forwarding rule when destination port is known (avoid flooding next time)
        if out_port != ofproto.OFPP_FLOOD:
            idle_timeout = 60
            # Build match rule satisfying OpenFlow 1.3 prerequisites
            if ip_pkt:
                if tcp_pkt and hasattr(tcp_pkt, "dst_port"):
                    match = parser.OFPMatch(
                        eth_type=0x0800,
                        ip_proto=6,
                        ipv4_src=ip_pkt.src,
                        ipv4_dst=ip_pkt.dst,
                        tcp_dst=int(tcp_pkt.dst_port)
                    )
                    idle_timeout = 10
                elif udp_pkt and hasattr(udp_pkt, "dst_port"):
                    match = parser.OFPMatch(
                        eth_type=0x0800,
                        ip_proto=17,
                        ipv4_src=ip_pkt.src,
                        ipv4_dst=ip_pkt.dst,
                        udp_dst=int(udp_pkt.dst_port)
                    )
                    idle_timeout = 10
                else:
                    # For IPv4 flows, explicitly specify eth_type=0x0800
                    match = parser.OFPMatch(
                        eth_type=0x0800,
                        ipv4_src=ip_pkt.src,
                        ipv4_dst=ip_pkt.dst
                    )
                    idle_timeout = 60
            elif arp_pkt:
                # For ARP flows
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_type=0x0806,
                    eth_dst=dst,
                    eth_src=src
                )
            else:
                # Standard L2 match
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_dst=dst,
                    eth_src=src
                )

            # Check if switch buffered the packet
            buffer_id = getattr(msg, "buffer_id", ofproto.OFP_NO_BUFFER)
            if buffer_id != ofproto.OFP_NO_BUFFER:
                self.flow_manager.install_forwarding_rule(
                    datapath=datapath,
                    priority=1,
                    match=match,
                    actions=actions,
                    buffer_id=buffer_id,
                    idle_timeout=idle_timeout,
                    hard_timeout=0
                )
                return
            else:
                self.flow_manager.install_forwarding_rule(
                    datapath=datapath,
                    priority=1,
                    match=match,
                    actions=actions,
                    idle_timeout=idle_timeout,
                    hard_timeout=0
                )

        # Send packet out
        data = None
        buffer_id = getattr(msg, "buffer_id", ofproto.OFP_NO_BUFFER)
        if buffer_id == ofproto.OFP_NO_BUFFER:
            data = getattr(msg, "data", None)

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )
        datapath.send_msg(out)

    # -------------------------------------------------------------------------
    # Dynamic Mitigation Hooks (Used by MitigationEngine / Worker 5)
    # -------------------------------------------------------------------------

    def block_ip(self, offending_ip: str, hard_timeout: int = 300) -> Dict[str, Any]:
        """Install high-priority OpenFlow drop rule blocking offending IPv4 source.

        Installs priority=1000 drop rule across all active datapaths.
        Always enforces eth_type=0x0800 prerequisite.

        Args:
            offending_ip (str): Attacker IPv4 address (e.g. '10.0.0.1').
            hard_timeout (int): Duration in seconds before automatic unblock.

        Returns:
            dict: Mitigation result summary.
        """
        logger.warning(f"[MITIGATION] Initiating block for offending IP: {offending_ip} (timeout={hard_timeout}s)")
        installed_count = 0

        for dpid, datapath in list(self.datapaths.items()):
            try:
                self.flow_manager.install_drop_rule(
                    datapath=datapath,
                    priority=1000,
                    ipv4_src=offending_ip,
                    hard_timeout=hard_timeout
                )
                installed_count += 1
            except Exception as e:
                logger.error(f"Failed to install drop rule on DPID={dpid}: {e}")

        self.blocked_ips[offending_ip] = time.time()

        return {
            "success": True,
            "offending_ip": offending_ip,
            "installed_rules": installed_count,
            "hard_timeout": hard_timeout,
            "timestamp": time.time()
        }

    def unblock_ip(self, offending_ip: str) -> Dict[str, Any]:
        """Remove previously installed drop rule for offending IPv4 source."""
        logger.info(f"[MITIGATION] Unblocking IP: {offending_ip}")
        removed_count = 0

        for dpid, datapath in list(self.datapaths.items()):
            try:
                self.flow_manager.remove_drop_rule(
                    datapath=datapath,
                    ipv4_src=offending_ip,
                    priority=1000
                )
                removed_count += 1
            except Exception as e:
                logger.error(f"Failed to remove drop rule on DPID={dpid}: {e}")

        self.blocked_ips.pop(offending_ip, None)

        return {
            "success": True,
            "offending_ip": offending_ip,
            "removed_rules": removed_count,
            "timestamp": time.time()
        }

    def is_blocked(self, host_ip: str) -> bool:
        """Check whether a host IP is actively blocked."""
        return host_ip in self.blocked_ips

    # -------------------------------------------------------------------------
    # Telemetry Polling Hooks (Used by TelemetryCollector / Worker 2)
    # -------------------------------------------------------------------------

    def register_telemetry_collector(self, collector):
        """Register telemetry collector for statistics event forwarding."""
        self.telemetry_collector = collector
        logger.info("Registered telemetry collector with SDNController")

    def register_mitigation_engine(self, engine):
        """Register mitigation engine."""
        self.mitigation_engine = engine
        logger.info("Registered mitigation engine with SDNController")

    def request_stats(self, datapath):
        """Send FlowStatsRequest and PortStatsRequest to a datapath."""
        ofproto = getattr(datapath, "ofproto", self.flow_manager.ofproto)
        parser = getattr(datapath, "ofproto_parser", self.flow_manager.parser)

        # Flow stats request
        req_flow = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req_flow)

        # Port stats request for all ports
        req_port = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req_port)

    def request_all_stats(self):
        """Request flow and port statistics from all connected datapaths."""
        for dpid, datapath in list(self.datapaths.items()):
            self.request_stats(datapath)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        """Handle flow statistics reply and delegate to registered collector."""
        if self.telemetry_collector and hasattr(self.telemetry_collector, "handle_flow_stats_reply"):
            self.telemetry_collector.handle_flow_stats_reply(ev)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        """Handle port statistics reply and delegate to registered collector."""
        if self.telemetry_collector and hasattr(self.telemetry_collector, "handle_port_stats_reply"):
            self.telemetry_collector.handle_port_stats_reply(ev)

    def _handle_telemetry_flow_stats(self, flow_features, host_metrics):
        """Callback from TelemetryCollector: evaluate anomaly detection and trigger mitigation."""
        if not self.anomaly_detector:
            return

        for host_ip, metrics in host_metrics.items():
            pkt_rate = metrics.get("packet_rate", 0.0)
            flow_rate = metrics.get("flow_rate", 0.0)
            dst_ports = metrics.get("dst_ports", [])

            det_result = self.anomaly_detector.update(
                host_ip=host_ip,
                packet_rate=pkt_rate,
                flow_rate=flow_rate,
                dst_ports=dst_ports
            )

            if self.exporter:
                self.exporter.update_host_z_score(host_ip, "packet_rate", det_result.get("z_pkt_rate", 0.0))
                self.exporter.update_host_z_score(host_ip, "flow_rate", det_result.get("z_flow_rate", 0.0))
                self.exporter.update_host_z_score(host_ip, "entropy", det_result.get("z_entropy", 0.0))

            if det_result.get("is_anomaly"):
                attack_type = det_result.get("attack_type", "volumetric_flood")
                logger.warning(
                    f"[ANOMALY ALERT] Host {host_ip} anomaly: {attack_type} "
                    f"(z_pkt={det_result.get('z_pkt_rate')}, entropy={det_result.get('entropy')})"
                )
                if self.exporter:
                    self.exporter.update_anomaly_alert(host_ip, attack_type, is_active=True)

                if self.mitigation_engine:
                    self.mitigation_engine.mitigate_host(host_ip, reason=attack_type)
                    if self.exporter:
                        self.exporter.update_mitigation_active(host_ip, is_active=True)

        # Run live Isolation Forest inference on active IPv4 forwarding flows
        if self.ml_detector and getattr(self.ml_detector, "is_fitted", False) and flow_features:
            host_ml_scores: Dict[str, float] = {}
            host_ml_anomalies: Dict[str, bool] = {}
            latencies: List[float] = []

            for rec in flow_features:
                if rec.get("priority", 0) != 1:
                    continue
                match = rec.get("match", {})
                src_ip = match.get("ipv4_src")
                if not src_ip:
                    continue
                feature_vec = [
                    float(rec.get("packet_rate", 0.0)),
                    float(rec.get("byte_rate", 0.0)),
                    float(rec.get("duration_sec", 0.0)),
                    float(rec.get("packet_count", 0)),
                    float(rec.get("byte_count", 0)),
                    float(rec.get("avg_packet_size", 0.0)),
                ]
                try:
                    ml_res = self.ml_detector.predict_flow(feature_vec)
                    score = ml_res["anomaly_score"]
                    latencies.append(ml_res["latency_us"])
                    if src_ip not in host_ml_scores or score > host_ml_scores[src_ip]:
                        host_ml_scores[src_ip] = score
                    if ml_res["is_anomaly"]:
                        host_ml_anomalies[src_ip] = True
                except Exception as e:
                    logger.debug(f"ML inference skipped for {src_ip}: {e}")

            avg_latency = (sum(latencies) / len(latencies)) if latencies else 0.0
            ml_mitigate = bool(self.config.get("detection", {}).get("ml", {}).get("trigger_mitigation", False))

            for src_ip, max_score in host_ml_scores.items():
                is_ml_anom = host_ml_anomalies.get(src_ip, False)
                if self.exporter:
                    self.exporter.update_ml_metrics(src_ip, max_score, avg_latency)
                    self.exporter.update_anomaly_alert(src_ip, "ml_isolation_forest", is_active=is_ml_anom)
                if is_ml_anom:
                    logger.warning(
                        f"[ML ANOMALY] Host {src_ip} flagged by IsolationForest "
                        f"(score={max_score:.4f}, latency={avg_latency:.1f}us)"
                    )
                    if ml_mitigate and self.mitigation_engine:
                        self.mitigation_engine.mitigate_host(src_ip, reason="ml_isolation_forest")
                        if self.exporter:
                            self.exporter.update_mitigation_active(src_ip, is_active=True)


# Interface compatibility alias as specified in PROJECT.md
SDNTelemetryController = SDNController


def main():
    """Main CLI execution to run controller via os-ken / ryu."""
    print(f"Starting SDN OpenFlow 1.3 Controller (Backend: {CONTROLLER_BACKEND})...")
    if CONTROLLER_BACKEND == "os_ken":
        try:
            import eventlet
            eventlet.monkey_patch()
            from os_ken.base.app_manager import AppManager
            from os_ken import cfg
            CONF = cfg.CONF
            ofp_port = "6653"
            for i, arg in enumerate(sys.argv):
                if arg == "--ofp-tcp-listen-port" and i + 1 < len(sys.argv):
                    ofp_port = sys.argv[i + 1]
            CONF(project="os-ken", args=["--ofp-tcp-listen-port", str(ofp_port)])
            AppManager.run_apps(["os_ken.controller.ofp_handler", "controller.sdn_controller"])
        except Exception as e:
            logger.error(f"Error starting os-ken app manager: {e}")
            raise
    elif CONTROLLER_BACKEND == "ryu":
        try:
            import eventlet
            eventlet.monkey_patch()
            from ryu.base.app_manager import AppManager
            from ryu import cfg
            CONF = cfg.CONF
            ofp_port = "6653"
            for i, arg in enumerate(sys.argv):
                if arg == "--ofp-tcp-listen-port" and i + 1 < len(sys.argv):
                    ofp_port = sys.argv[i + 1]
            CONF(project="ryu", args=["--ofp-tcp-listen-port", str(ofp_port)])
            AppManager.run_apps(["ryu.controller.ofp_handler", "controller.sdn_controller"])
        except Exception as e:
            logger.error(f"Error starting ryu app manager: {e}")
            raise
    else:
        print("[*] os-ken/ryu not installed in current python environment.")
        print("[*] Running SDNController in test verification mode...")
        ctrl = SDNController()
        print(f"    Datapaths: {ctrl.datapaths}")
        print(f"    Blocked IPs: {ctrl.blocked_ips}")
        print("SDNController self-test completed successfully.")


if __name__ == "__main__":
    main()
