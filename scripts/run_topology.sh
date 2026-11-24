#!/usr/bin/env bash
# ==============================================================================
# Mininet SDN Tree Topology Launcher
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

export PYTHONPATH="${PROJECT_ROOT}:${PYTHONPATH}"

CONTROLLER_IP="127.0.0.1"
CONTROLLER_PORT="6653"

EXTRA_ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --controller-ip)
            CONTROLLER_IP="$2"
            shift 2
            ;;
        --controller-port)
            CONTROLLER_PORT="$2"
            shift 2
            ;;
        *)
            if [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                CONTROLLER_IP="$1"
                shift
            elif [[ "$1" =~ ^[0-9]+$ ]]; then
                CONTROLLER_PORT="$1"
                shift
            else
                EXTRA_ARGS+=("$1")
                shift
            fi
            ;;
    esac
done

echo "=============================================================================="
echo "Launching Mininet Tree Topology (depth=2, fanout=2)..."
echo "Target Controller: ${CONTROLLER_IP}:${CONTROLLER_PORT}"
echo "=============================================================================="

CMD=(python3 "${PROJECT_ROOT}/topo/sdn_tree_topo.py" --controller-ip "${CONTROLLER_IP}" --controller-port "${CONTROLLER_PORT}" "${EXTRA_ARGS[@]}")

# Check if running as root or if sudo is available
if [ "$(id -u)" -eq 0 ]; then
    exec "${CMD[@]}"
elif sudo -n true 2>/dev/null; then
    exec sudo -E env "PYTHONPATH=${PYTHONPATH}" "${CMD[@]}"
else
    echo "[INFO] Running without root privileges (Mininet emulation mode)..."
    exec "${CMD[@]}"
fi
