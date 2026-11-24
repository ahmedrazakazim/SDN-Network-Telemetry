#!/usr/bin/env bash
# ==============================================================================
# Environment Setup and Verification Script
# SDN Network Telemetry and Traffic Anomaly Detection System
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "=== [1/4] Checking Python Environment ==="
PYTHON_BIN="$(which python3 || echo "")"
if [ -z "${PYTHON_BIN}" ]; then
    echo "[ERROR] python3 not found in PATH."
    exit 1
fi
echo "[OK] Found Python: $(${PYTHON_BIN} --version) at ${PYTHON_BIN}"

echo "=== [2/4] Installing / Verifying Python Dependencies ==="
PIP_BIN="$(which pip3 || which pip || echo "/home/zen/.local/bin/pip")"

if [ -f "${PROJECT_ROOT}/requirements.txt" ] && [ -x "${PIP_BIN}" ]; then
    echo "[*] Installing dependencies from ${PROJECT_ROOT}/requirements.txt..."
    "${PIP_BIN}" install --user --break-system-packages -r "${PROJECT_ROOT}/requirements.txt" || \
    "${PIP_BIN}" install --user -r "${PROJECT_ROOT}/requirements.txt" || \
    echo "[!] Notice: Some packages may already be installed or managed externally."
fi

echo "=== [3/4] Verifying Core Python Modules ==="
${PYTHON_BIN} -c "
import sys
modules = ['eventlet', 'yaml', 'sklearn', 'numpy', 'scipy', 'pandas', 'joblib', 'prometheus_client']
missing = []
for m in modules:
    try:
        __import__(m)
        print(f'  [OK] {m}')
    except ImportError:
        missing.append(m)
        print(f'  [FAIL] {m}')

try:
    import os_ken
    print('  [OK] os_ken')
except ImportError:
    try:
        import ryu
        print('  [OK] ryu')
    except ImportError:
        print('  [WARN] Neither os_ken nor ryu installed (fallback mock will be used)')

if missing:
    print(f'[WARN] Missing modules: {missing}')
else:
    print('[SUCCESS] All essential Python modules are present!')
"

echo "=== [4/4] Checking System SDN & Tool Prerequisites ==="
for cmd in mn ovs-vsctl prometheus grafana-server hping3 nmap; do
    if command -v "$cmd" >/dev/null 2>&1; then
        echo "  [OK] $cmd is installed ($(which $cmd))"
    else
        echo "  [INFO] $cmd is not found in system PATH (may be required for full hardware/live emulations)"
    fi
done

echo "=============================================================================="
echo "Environment check and setup complete."
echo "Project Root: ${PROJECT_ROOT}"
echo "=============================================================================="
