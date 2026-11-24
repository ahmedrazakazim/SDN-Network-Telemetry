#!/usr/bin/env bash
# ==============================================================================
# SDN OpenFlow 1.3 Controller Launcher
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

export PYTHONPATH="${PROJECT_ROOT}:${PYTHONPATH}"

PORT="6653"
EXTRA_ARGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ofp-tcp-listen-port|--port)
            PORT="$2"
            shift 2
            ;;
        *)
            if [[ "$1" =~ ^[0-9]+$ ]]; then
                PORT="$1"
                shift
            else
                EXTRA_ARGS+=("$1")
                shift
            fi
            ;;
    esac
done

echo "=============================================================================="
echo "Launching SDN OpenFlow 1.3 Controller on port ${PORT}..."
echo "Project root: ${PROJECT_ROOT}"
echo "=============================================================================="

exec python3 "${PROJECT_ROOT}/controller/sdn_controller.py" --ofp-tcp-listen-port "${PORT}" "${EXTRA_ARGS[@]}"
