"""
OpenFlow Flow and Port Statistics Telemetry Collector.

Manages periodic statistics polling across connected OpenFlow 1.3 switch datapaths.
Dispatches OFPFlowStatsRequest and OFPPortStatsRequest messages at configurable
intervals (supporting 1s, 2s, 5s), processes reply events, extracts flow and port
metrics, and coordinates metric exposition to Prometheus and detection engines.
"""

import logging
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

try:
    from os_ken.lib import hub
    HAS_OSKEN_HUB = True
except ImportError:
    try:
        import eventlet as hub
        HAS_OSKEN_HUB = True
    except ImportError:
        HAS_OSKEN_HUB = False

from telemetry.exporter import PrometheusTelemetryExporter
from telemetry.feature_extractor import FlowFeatureExtractor
from detection.baseline_detector import calculate_shannon_entropy

logger = logging.getLogger(__name__)


class TelemetryCollector:
    """
    OpenFlow 1.3 Telemetry Collector.

    Periodically queries switch datapaths for flow and port statistics,
    processes reply events, and pushes calculated derivatives to feature extractors,
    Prometheus exporters, and registered anomaly detection callbacks.
    """

    def __init__(
        self,
        datapaths: Optional[Union[Dict[int, Any], List[Any]]] = None,
        poll_interval: float = 1.0,
        feature_extractor: Optional[FlowFeatureExtractor] = None,
        exporter: Optional[PrometheusTelemetryExporter] = None,
        flow_callback: Optional[Callable[[List[Dict[str, Any]], Dict[str, Dict[str, Any]]], None]] = None,
        port_callback: Optional[Callable[[List[Dict[str, Any]]], None]] = None,
    ):
        """
        Initialize the Telemetry Collector.

        :param datapaths: Optional dictionary or list of switch datapath instances.
        :param poll_interval: Polling frequency in seconds (supports 1s, 2s, 5s).
        :param feature_extractor: Instance of FlowFeatureExtractor.
        :param exporter: Instance of PrometheusTelemetryExporter.
        :param flow_callback: Callback invoked when flow stats and host metrics are calculated:
                              callback(flow_features, host_metrics).
        :param port_callback: Callback invoked when port stats are calculated:
                              callback(port_features).
        """
        self._datapaths_ref = datapaths
        self._internal_datapaths: Dict[int, Any] = {}

        self.poll_interval = float(poll_interval)
        self.feature_extractor = feature_extractor or FlowFeatureExtractor()
        self.exporter = exporter

        self.flow_callback = flow_callback
        self.port_callback = port_callback

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._greenlet = None
        self._lock = threading.Lock()

    @property
    def datapaths(self) -> Dict[int, Any]:
        """Return the dictionary of active switch datapaths."""
        if self._datapaths_ref is not None:
            if isinstance(self._datapaths_ref, dict):
                return self._datapaths_ref
            elif isinstance(self._datapaths_ref, list):
                return {getattr(dp, "id", idx): dp for idx, dp in enumerate(self._datapaths_ref)}
        return self._internal_datapaths

    def register_datapath(self, datapath: Any) -> None:
        """Register a connected switch datapath."""
        with self._lock:
            dpid = getattr(datapath, "id", None)
            if dpid is not None:
                self._internal_datapaths[dpid] = datapath
                if isinstance(self._datapaths_ref, dict) and dpid not in self._datapaths_ref:
                    self._datapaths_ref[dpid] = datapath
                logger.info("Registered datapath DPID=%s for telemetry", dpid)

    def unregister_datapath(self, datapath_or_dpid: Any) -> None:
        """Unregister a disconnected switch datapath."""
        with self._lock:
            dpid = datapath_or_dpid if isinstance(datapath_or_dpid, int) else getattr(datapath_or_dpid, "id", None)
            if dpid is not None:
                self._internal_datapaths.pop(dpid, None)
                if isinstance(self._datapaths_ref, dict):
                    self._datapaths_ref.pop(dpid, None)
                logger.info("Unregistered datapath DPID=%s from telemetry", dpid)

    def set_poll_interval(self, interval: float) -> None:
        """
        Dynamically update the statistics polling interval.
        Common valid intervals: 1.0, 2.0, 5.0 seconds.
        """
        if interval <= 0:
            raise ValueError(f"Polling interval must be positive, got {interval}")
        self.poll_interval = float(interval)
        logger.info("Updated telemetry polling interval to %.2f seconds", self.poll_interval)

    def request_stats(self, datapath: Any) -> bool:
        """
        Dispatch OFPFlowStatsRequest and OFPPortStatsRequest to a datapath.
        Adheres to OpenFlow 1.3 request formats.
        """
        try:
            ofproto = getattr(datapath, "ofproto", None)
            parser = getattr(datapath, "ofproto_parser", None)

            if ofproto is None or parser is None:
                # Mock datapath handling for tests
                if hasattr(datapath, "send_msg"):
                    datapath.send_msg("OFPFlowStatsRequest")
                    datapath.send_msg("OFPPortStatsRequest")
                    return True
                logger.error("Datapath %s lacks ofproto or ofproto_parser", datapath)
                return False

            # OpenFlow 1.3 Flow Stats Request
            req_flow = parser.OFPFlowStatsRequest(datapath)
            datapath.send_msg(req_flow)

            # OpenFlow 1.3 Port Stats Request (query all ports via OFPP_ANY)
            port_any = getattr(ofproto, "OFPP_ANY", 0xFFFFFFFF)
            req_port = parser.OFPPortStatsRequest(datapath, 0, port_any)
            datapath.send_msg(req_port)

            return True
        except Exception as e:
            dpid = getattr(datapath, "id", "unknown")
            logger.error("Failed to send stats requests to datapath %s: %s", dpid, e)
            return False

    def poll_all_datapaths(self) -> int:
        """
        Query flow and port statistics from all currently registered datapaths.
        Returns the number of datapaths successfully polled.
        """
        dps = list(self.datapaths.values())
        success_count = 0
        for dp in dps:
            if self.request_stats(dp):
                success_count += 1
        return success_count

    def handle_flow_stats_reply(self, ev_or_msg: Any) -> Tuple[List[Dict[str, Any]], Dict[str, Dict[str, Any]]]:
        """
        Process an EventOFPFlowStatsReply (or message object).
        Calculates rates, aggregates host metrics, updates Prometheus gauges,
        and invokes registered callbacks.

        Returns:
            (flow_features, host_metrics)
        """
        msg = getattr(ev_or_msg, "msg", ev_or_msg)
        body = getattr(msg, "body", [])
        datapath = getattr(msg, "datapath", None)
        dpid = getattr(datapath, "id", getattr(msg, "dpid", 0))

        # Extract flow features and derivatives
        flow_features = self.feature_extractor.extract_flow_features(body, dpid)

        # Aggregate per-host metrics
        host_metrics = self.feature_extractor.aggregate_host_metrics(flow_features)

        # Update Prometheus exporter if attached
        if self.exporter is not None:
            self.exporter.update_flow_metrics(flow_features)
            self.exporter.update_host_metrics(host_metrics)
            for host_ip, metrics in host_metrics.items():
                dst_ports = metrics.get("dst_ports", [])
                entropy = calculate_shannon_entropy(dst_ports)
                self.exporter.update_host_entropy(host_ip, entropy)

        # Invoke callback if registered
        if self.flow_callback is not None:
            try:
                self.flow_callback(flow_features, host_metrics)
            except Exception as e:
                logger.error("Error in telemetry flow_callback: %s", e)

        return flow_features, host_metrics

    def handle_port_stats_reply(self, ev_or_msg: Any) -> List[Dict[str, Any]]:
        """
        Process an EventOFPPortStatsReply (or message object).
        Calculates port rates, updates Prometheus gauges, and invokes registered callbacks.

        Returns:
            port_features
        """
        msg = getattr(ev_or_msg, "msg", ev_or_msg)
        body = getattr(msg, "body", [])
        datapath = getattr(msg, "datapath", None)
        dpid = getattr(datapath, "id", getattr(msg, "dpid", 0))

        # Extract port features and rates
        port_features = self.feature_extractor.extract_port_features(body, dpid)

        # Update Prometheus exporter if attached
        if self.exporter is not None:
            self.exporter.update_port_metrics(port_features)

        # Invoke callback if registered
        if self.port_callback is not None:
            try:
                self.port_callback(port_features)
            except Exception as e:
                logger.error("Error in telemetry port_callback: %s", e)

        return port_features

    def _monitor_loop(self) -> None:
        """Continuous polling execution loop."""
        logger.info("Telemetry polling loop started with interval=%.2fs", self.poll_interval)
        while self._running:
            self.poll_all_datapaths()

            # Sleep supporting both greenlets and standard threads
            if HAS_OSKEN_HUB and hasattr(hub, "sleep"):
                hub.sleep(self.poll_interval)
            else:
                time.sleep(self.poll_interval)
        logger.info("Telemetry polling loop stopped")

    def start(self, use_greenlet: bool = False) -> None:
        """
        Start the asynchronous polling loop.

        :param use_greenlet: If True and os-ken hub / eventlet is available, spawn a greenlet.
                             Otherwise, spawns a standard background daemon thread.
        """
        if self._running:
            return

        self._running = True

        if use_greenlet and HAS_OSKEN_HUB and hasattr(hub, "spawn"):
            self._greenlet = hub.spawn(self._monitor_loop)
            logger.info("Spawned telemetry monitor greenlet")
        else:
            self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self._thread.start()
            logger.info("Spawned telemetry monitor background thread")

    def stop(self) -> None:
        """Stop the polling loop."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
            self._thread = None
        self._greenlet = None

    def is_running(self) -> bool:
        """Check if the collector polling loop is currently active."""
        return self._running
