# Live Mininet SDN Telemetry & Anomaly Detection Evaluation Report

- **Execution Mode**: 100% Live Mininet + Open vSwitch + OS-Ken Controller
- **Polling Intervals Tested**: [1, 2, 5] seconds
- **Repeats per Condition**: 3 (reported as Mean ± Std Dev)
- **Total Live Runs**: 36

## Summary by Polling Interval (Attack Scenarios)

| Polling Interval | Detection Delay (s) | Mitigation Latency (ms) | Benign Retention (%) | Controller CPU (%) | ML Inference (µs) | Normal FPR |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **1s** | 0.96 ± 0.04 | 0.00 ± 0.00 | 100.00 ± 0.00% | 15.64 ± 2.99% | 5966.76 ± 667.86 | 0.0% |
| **2s** | 0.74 ± 0.03 | 0.00 ± 0.00 | 100.00 ± 0.00% | 15.54 ± 3.66% | 5861.72 ± 322.91 | 0.0% |
| **5s** | 0.90 ± 0.05 | 0.00 ± 0.00 | 100.00 ± 0.00% | 9.64 ± 5.44% | 5767.07 ± 324.59 | 0.0% |
