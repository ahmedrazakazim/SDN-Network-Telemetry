#!/usr/bin/env bash
# ==============================================================================
# Master Monitoring Startup Script for SDN Telemetry
# Manages Prometheus (port 9090) and Grafana (port 3000)
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PROM_CONFIG="${REPO_ROOT}/configs/prometheus.yml"
PROM_DATA="${REPO_ROOT}/monitoring/prometheus/data"
GRAFANA_DIR="${REPO_ROOT}/monitoring/grafana"
GRAFANA_PROV="${GRAFANA_DIR}/provisioning"
GRAFANA_DATA="${GRAFANA_DIR}/data"
GRAFANA_LOGS="${GRAFANA_DIR}/logs"

PID_DIR="${REPO_ROOT}/monitoring/.run"
PROM_PID_FILE="${PID_DIR}/prometheus.pid"
GRAFANA_PID_FILE="${PID_DIR}/grafana.pid"

mkdir -p "${PROM_DATA}" "${GRAFANA_DATA}" "${GRAFANA_LOGS}" "${PID_DIR}"

find_prometheus() {
    if command -v prometheus >/dev/null 2>&1; then
        command -v prometheus
    elif [ -x "/usr/local/bin/prometheus" ]; then
        echo "/usr/local/bin/prometheus"
    elif [ -x "/usr/bin/prometheus" ]; then
        echo "/usr/bin/prometheus"
    elif [ -x "/opt/prometheus/prometheus" ]; then
        echo "/opt/prometheus/prometheus"
    else
        echo ""
    fi
}

find_grafana() {
    if command -v grafana-server >/dev/null 2>&1; then
        command -v grafana-server
    elif command -v grafana >/dev/null 2>&1; then
        echo "$(command -v grafana) server"
    elif [ -x "/usr/sbin/grafana-server" ]; then
        echo "/usr/sbin/grafana-server"
    elif [ -x "/usr/share/grafana/bin/grafana-server" ]; then
        echo "/usr/share/grafana/bin/grafana-server"
    elif [ -x "/opt/grafana/bin/grafana-server" ]; then
        echo "/opt/grafana/bin/grafana-server"
    else
        echo ""
    fi
}

find_grafana_home() {
    if [ -d "/usr/share/grafana" ]; then
        echo "/usr/share/grafana"
    elif [ -d "/opt/grafana" ]; then
        echo "/opt/grafana"
    elif [ -d "/usr/local/share/grafana" ]; then
        echo "/usr/local/share/grafana"
    else
        echo "${GRAFANA_DIR}"
    fi
}

start_prometheus_bg() {
    local prom_bin
    prom_bin="$(find_prometheus)"
    if [ -z "${prom_bin}" ]; then
        echo "[WARN] Prometheus binary not found. Skipping Prometheus daemon launch." >&2
        echo "       Install Prometheus via: sudo apt install prometheus" >&2
        return 1
    fi

    if [ -f "${PROM_PID_FILE}" ] && kill -0 "$(cat "${PROM_PID_FILE}")" 2>/dev/null; then
        echo "[INFO] Prometheus is already running (PID $(cat "${PROM_PID_FILE}"))."
        return 0
    fi

    echo "[INFO] Launching Prometheus server on port 9090..."
    "${prom_bin}" \
        --config.file="${PROM_CONFIG}" \
        --storage.tsdb.path="${PROM_DATA}" \
        --web.listen-address="0.0.0.0:9090" \
        --web.enable-lifecycle \
        > "${PROM_DATA}/prometheus.log" 2>&1 &
    local pid=$!
    echo "${pid}" > "${PROM_PID_FILE}"
    echo "[INFO] Prometheus started successfully (PID ${pid}). Access at http://127.0.0.1:9090"
}

start_grafana_bg() {
    local grafana_bin
    grafana_bin="$(find_grafana)"
    if [ -z "${grafana_bin}" ]; then
        echo "[WARN] Grafana binary not found. Skipping Grafana daemon launch." >&2
        echo "       Install Grafana via: sudo apt install grafana" >&2
        return 1
    fi

    if [ -f "${GRAFANA_PID_FILE}" ] && kill -0 "$(cat "${GRAFANA_PID_FILE}")" 2>/dev/null; then
        echo "[INFO] Grafana is already running (PID $(cat "${GRAFANA_PID_FILE}"))."
        return 0
    fi

    local grafana_home
    grafana_home="$(find_grafana_home)"

    export GF_PATHS_PROVISIONING="${GRAFANA_PROV}"
    export GF_PATHS_DATA="${GRAFANA_DATA}"
    export GF_PATHS_LOGS="${GRAFANA_LOGS}"
    export GF_SERVER_HTTP_PORT=3000
    export GF_SECURITY_ADMIN_USER=admin
    export GF_SECURITY_ADMIN_PASSWORD=admin
    export GF_AUTH_ANONYMOUS_ENABLED=true
    export GF_AUTH_ANONYMOUS_ORG_ROLE=Admin

    echo "[INFO] Launching Grafana server on port 3000..."
    if [ -d "/usr/share/grafana" ]; then
        ${grafana_bin} --homepath="${grafana_home}" > "${GRAFANA_LOGS}/grafana.stdout.log" 2>&1 &
    else
        ${grafana_bin} > "${GRAFANA_LOGS}/grafana.stdout.log" 2>&1 &
    fi
    local pid=$!
    echo "${pid}" > "${GRAFANA_PID_FILE}"
    echo "[INFO] Grafana started successfully (PID ${pid}). Access at http://127.0.0.1:3000"
}

stop_services() {
    echo "[INFO] Stopping monitoring stack..."
    if [ -f "${PROM_PID_FILE}" ]; then
        local ppid
        ppid="$(cat "${PROM_PID_FILE}")"
        if kill -0 "${ppid}" 2>/dev/null; then
            echo "[INFO] Stopping Prometheus (PID ${ppid})..."
            kill "${ppid}" || true
        fi
        rm -f "${PROM_PID_FILE}"
    fi

    if [ -f "${GRAFANA_PID_FILE}" ]; then
        local gpid
        gpid="$(cat "${GRAFANA_PID_FILE}")"
        if kill -0 "${gpid}" 2>/dev/null; then
            echo "[INFO] Stopping Grafana (PID ${gpid})..."
            kill "${gpid}" || true
        fi
        rm -f "${GRAFANA_PID_FILE}"
    fi
    echo "[INFO] Monitoring stack stopped."
}

status_services() {
    echo "======================================================================"
    echo "SDN Monitoring Stack Status"
    echo "======================================================================"
    local prom_bin grafana_bin
    prom_bin="$(find_prometheus)"
    grafana_bin="$(find_grafana)"

    echo "Prometheus binary:   ${prom_bin:-NOT FOUND}"
    echo "Grafana binary:      ${grafana_bin:-NOT FOUND}"
    echo "Config file:         ${PROM_CONFIG}"
    echo "Dashboard file:      ${GRAFANA_DIR}/dashboards/sdn_telemetry_dashboard.json"
    echo "Datasource prov:     ${GRAFANA_PROV}/datasources/prometheus_ds.yaml"
    echo "Dashboard prov:      ${GRAFANA_PROV}/dashboards/dashboards_provider.yaml"
    echo "----------------------------------------------------------------------"

    if [ -f "${PROM_PID_FILE}" ] && kill -0 "$(cat "${PROM_PID_FILE}")" 2>/dev/null; then
        echo "Prometheus (Port 9090): RUNNING (PID $(cat "${PROM_PID_FILE}")) -> http://127.0.0.1:9090"
    else
        echo "Prometheus (Port 9090): STOPPED"
    fi

    if [ -f "${GRAFANA_PID_FILE}" ] && kill -0 "$(cat "${GRAFANA_PID_FILE}")" 2>/dev/null; then
        echo "Grafana (Port 3000):    RUNNING (PID $(cat "${GRAFANA_PID_FILE}")) -> http://127.0.0.1:3000"
    else
        echo "Grafana (Port 3000):    STOPPED"
    fi
    echo "======================================================================"
}

run_foreground() {
    trap stop_services EXIT INT TERM

    echo "======================================================================"
    echo "Starting SDN Telemetry Monitoring Stack in foreground mode"
    echo "Press Ctrl+C to terminate all services."
    echo "======================================================================"

    start_prometheus_bg || true
    start_grafana_bg || true

    status_services

    echo "[INFO] Monitoring stack is active. Waiting for interrupt..."
    while true; do
        sleep 2
    done
}

case "${1:-start}" in
    start)
        start_prometheus_bg || true
        start_grafana_bg || true
        status_services
        ;;
    stop)
        stop_services
        ;;
    restart)
        stop_services
        sleep 1
        start_prometheus_bg || true
        start_grafana_bg || true
        status_services
        ;;
    status)
        status_services
        ;;
    foreground)
        run_foreground
        ;;
    help|--help|-h)
        echo "Usage: $0 [start|stop|restart|status|foreground|help]"
        ;;
    *)
        echo "Unknown option: $1" >&2
        echo "Usage: $0 [start|stop|restart|status|foreground|help]" >&2
        exit 1
        ;;
esac
