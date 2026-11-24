"""
Evaluation package for SDN Telemetry & Traffic Anomaly Detection System.

Provides:
- MetricsCollector: Detection delay, mitigation latency, FPR, CPU profiler, and control overhead.
- BenchmarkRunner: 51-run systematic evaluation runner across 1s, 2s, and 5s polling intervals.
"""

from evaluation.metrics_collector import MetricsCollector, CPUProfiler
from evaluation.benchmark_runner import BenchmarkRunner

__all__ = [
    "MetricsCollector",
    "CPUProfiler",
    "BenchmarkRunner"
]
