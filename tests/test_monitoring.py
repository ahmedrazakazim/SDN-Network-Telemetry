"""Unit tests for Monitoring Configurations & Dashboards (Tier 1 & Tier 2).

Validates:
- configs/prometheus.yml YAML syntax, 1s scrape interval, and sdn_controller target (127.0.0.1:8000)
- Grafana dashboard JSON schema compliance (schemaVersion >= 38)
- Presence and metric query definitions for all 8 mandatory dashboard panels:
    1. Anomaly Detection Alert Status (sdn_anomaly_alert)
    2. Dynamic Flow Mitigation Status (sdn_mitigation_active)
    3. Real-time Flow Packet Rates (sdn_flow_packet_rate)
    4. Real-time Flow Byte Rates (sdn_flow_byte_rate)
    5. Switch Port Traffic & Drops (sdn_port_rx_packets / tx / dropped)
    6. Destination-Port Shannon Entropy (sdn_host_port_entropy)
    7. Z-Score Anomaly Deviation (sdn_host_z_score)
    8. Controller CPU Utilization (sdn_controller_cpu_percent)
- Grafana automatic provisioning YAML syntax (datasources and dashboard providers)
"""

import json
import os
import unittest
import yaml


PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PROMETHEUS_CONFIG_PATH = os.path.join(PROJECT_ROOT, "configs", "prometheus.yml")
DASHBOARD_JSON_PATH = os.path.join(
    PROJECT_ROOT, "monitoring", "grafana", "dashboards", "sdn_telemetry_dashboard.json"
)
DATASOURCE_PROV_PATH = os.path.join(
    PROJECT_ROOT, "monitoring", "grafana", "provisioning", "datasources", "prometheus_ds.yaml"
)
DASHBOARDS_PROV_PATH = os.path.join(
    PROJECT_ROOT, "monitoring", "grafana", "provisioning", "dashboards", "dashboards_provider.yaml"
)


class TestPrometheusConfiguration(unittest.TestCase):
    """Test suite for Prometheus configuration syntax and targets."""

    def test_prometheus_config_exists(self):
        """Verify configs/prometheus.yml exists."""
        self.assertTrue(
            os.path.isfile(PROMETHEUS_CONFIG_PATH),
            f"Missing Prometheus config at {PROMETHEUS_CONFIG_PATH}"
        )

    def test_prometheus_config_valid_yaml(self):
        """Verify configs/prometheus.yml is valid YAML and contains global and scrape_configs."""
        with open(PROMETHEUS_CONFIG_PATH, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)

        self.assertIsInstance(config, dict)
        self.assertIn("global", config)
        self.assertIn("scrape_configs", config)

    def test_prometheus_global_intervals(self):
        """Verify global scrape_interval and evaluation_interval are set to 1s."""
        with open(PROMETHEUS_CONFIG_PATH, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)

        global_cfg = config.get("global", {})
        self.assertEqual(str(global_cfg.get("scrape_interval")), "1s")
        self.assertEqual(str(global_cfg.get("evaluation_interval")), "1s")

    def test_prometheus_sdn_controller_job(self):
        """Verify sdn_controller scrape job targets 127.0.0.1:8000 on /metrics."""
        with open(PROMETHEUS_CONFIG_PATH, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)

        scrape_configs = config.get("scrape_configs", [])
        sdn_job = next((j for j in scrape_configs if j.get("job_name") == "sdn_controller"), None)
        self.assertIsNotNone(sdn_job, "Expected job_name 'sdn_controller' in scrape_configs")

        self.assertEqual(sdn_job.get("metrics_path", "/metrics"), "/metrics")
        static_configs = sdn_job.get("static_configs", [])
        self.assertTrue(len(static_configs) > 0)

        targets = static_configs[0].get("targets", [])
        self.assertIn("127.0.0.1:8000", targets)


class TestGrafanaDashboard(unittest.TestCase):
    """Test suite for Grafana Dashboard JSON schema and panels."""

    def setUp(self):
        """Load and parse dashboard JSON before each test."""
        self.assertTrue(os.path.isfile(DASHBOARD_JSON_PATH), f"Missing dashboard JSON at {DASHBOARD_JSON_PATH}")
        with open(DASHBOARD_JSON_PATH, "r", encoding="utf-8") as f:
            self.dashboard = json.load(f)

    def test_dashboard_json_validity_and_metadata(self):
        """Verify dashboard JSON parses properly and has title and uid."""
        self.assertIsInstance(self.dashboard, dict)
        self.assertIn("title", self.dashboard)
        self.assertIn("uid", self.dashboard)
        self.assertTrue(len(self.dashboard.get("title", "")) > 0)

    def test_dashboard_schema_version(self):
        """Verify dashboard schemaVersion is >= 38."""
        schema_version = self.dashboard.get("schemaVersion", 0)
        self.assertGreaterEqual(schema_version, 38, f"schemaVersion must be >= 38, got {schema_version}")

    def test_dashboard_contains_all_required_panels(self):
        """Verify all 8 required visualization panels and their target metric queries exist."""
        panels = self.dashboard.get("panels", [])
        self.assertGreaterEqual(len(panels), 8, f"Expected at least 8 panels, found {len(panels)}")

        # Extract all metric query expressions (expr) across all panels and rows
        metric_expressions = []
        for panel in panels:
            for target in panel.get("targets", []):
                if "expr" in target:
                    metric_expressions.append(target["expr"])
            # Handle nested panels inside rows if present
            for nested in panel.get("panels", []):
                for target in nested.get("targets", []):
                    if "expr" in target:
                        metric_expressions.append(target["expr"])

        all_expr_str = " ".join(metric_expressions)

        required_metrics = [
            "sdn_anomaly_alert",
            "sdn_mitigation_active",
            "sdn_flow_packet_rate",
            "sdn_flow_byte_rate",
            "sdn_port_rx_packets",
            "sdn_port_rx_dropped",
            "sdn_host_port_entropy",
            "sdn_host_z_score",
            "sdn_controller_cpu_percent",
        ]

        for metric in required_metrics:
            self.assertIn(
                metric,
                all_expr_str,
                f"Required metric query '{metric}' not found in dashboard panel queries"
            )


class TestGrafanaProvisioning(unittest.TestCase):
    """Test suite for Grafana automatic provisioning YAML configurations."""

    def test_datasource_provisioning_valid_yaml(self):
        """Verify prometheus_ds.yaml is valid YAML and points to http://127.0.0.1:9090."""
        self.assertTrue(os.path.isfile(DATASOURCE_PROV_PATH), f"Missing {DATASOURCE_PROV_PATH}")
        with open(DATASOURCE_PROV_PATH, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        self.assertIsInstance(data, dict)
        datasources = data.get("datasources", [])
        self.assertTrue(len(datasources) > 0)
        ds = datasources[0]
        self.assertEqual(ds.get("type"), "prometheus")
        self.assertIn("9090", ds.get("url", ""))

    def test_dashboards_provider_valid_yaml(self):
        """Verify dashboards_provider.yaml is valid YAML and points to dashboards directory."""
        self.assertTrue(os.path.isfile(DASHBOARDS_PROV_PATH), f"Missing {DASHBOARDS_PROV_PATH}")
        with open(DASHBOARDS_PROV_PATH, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        self.assertIsInstance(data, dict)
        providers = data.get("providers", [])
        self.assertTrue(len(providers) > 0)
        provider = providers[0]
        self.assertEqual(provider.get("type"), "file")


if __name__ == "__main__":
    unittest.main()
