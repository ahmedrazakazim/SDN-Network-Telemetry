"""
Telemetry Subsystem for SDN Traffic Monitoring and Anomaly Detection.

Modules:
- collector: Asynchronous OpenFlow statistics poller (supporting 1s, 2s, 5s intervals).
- feature_extractor: Mathematical derivative calculator for flow and port metrics.
- exporter: Prometheus metrics HTTP exporter with dynamic cardinality pruning.
"""

from telemetry.collector import TelemetryCollector
from telemetry.exporter import PrometheusTelemetryExporter
from telemetry.feature_extractor import FlowFeatureExtractor, parse_match

__all__ = [
    "TelemetryCollector",
    "FlowFeatureExtractor",
    "PrometheusTelemetryExporter",
    "parse_match",
]
