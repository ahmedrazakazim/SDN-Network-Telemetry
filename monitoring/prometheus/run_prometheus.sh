#!/usr/bin/env bash
# ==============================================================================
# Prometheus Server Runner for SDN Telemetry
# Runs Prometheus server on port 9090 with TSDB storage in monitoring/prometheus/data
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CONFIG_FILE="${REPO_ROOT}/configs/prometheus.yml"
DATA_DIR="${SCRIPT_DIR}/data"
LISTEN_ADDR="0.0.0.0:9090"

mkdir -p "${DATA_DIR}"

# Locate prometheus binary
PROMETHEUS_BIN=""
if command -v prometheus >/dev/null 2>&1; then
    PROMETHEUS_BIN="$(command -v prometheus)"
elif [ -x "/usr/local/bin/prometheus" ]; then
    PROMETHEUS_BIN="/usr/local/bin/prometheus"
elif [ -x "/usr/bin/prometheus" ]; then
    PROMETHEUS_BIN="/usr/bin/prometheus"
elif [ -x "/opt/prometheus/prometheus" ]; then
    PROMETHEUS_BIN="/opt/prometheus/prometheus"
fi

if [ -z "${PROMETHEUS_BIN}" ]; then
    echo "======================================================================" >&2
    echo "[ERROR] 'prometheus' binary not found in PATH or standard locations." >&2
    echo "Please install Prometheus:" >&2
    echo "  sudo apt-get update && sudo apt-get install -y prometheus" >&2
    echo "Or download precompiled binary from:" >&2
    echo "  https://prometheus.io/download/" >&2
    echo "======================================================================" >&2
    exit 1
fi

echo "======================================================================"
echo "Starting Prometheus Server..."
echo "  Binary:      ${PROMETHEUS_BIN}"
echo "  Config:      ${CONFIG_FILE}"
echo "  Storage:     ${DATA_DIR}"
echo "  Listen:      ${LISTEN_ADDR}"
echo "======================================================================"

exec "${PROMETHEUS_BIN}" \
    --config.file="${CONFIG_FILE}" \
    --storage.tsdb.path="${DATA_DIR}" \
    --web.listen-address="${LISTEN_ADDR}" \
    --web.enable-lifecycle \
    "$@"
