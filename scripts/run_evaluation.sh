#!/usr/bin/env bash
# ==============================================================================
# SDN Telemetry & Anomaly Detection: Automated Benchmark Evaluation Driver
#
# Executes the systematic 51-run evaluation matrix across 1s, 2s, and 5s
# polling intervals for normal baseline and attack scenarios (SYN, UDP, Port Scan).
# Generates benchmark_summary.csv and evaluation_report.md in evaluation/results/.
# ==============================================================================

set -euo pipefail

# ANSI color escape codes
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

OUTPUT_DIR="${PROJECT_ROOT}/evaluation/results"
INTERVALS="1 2 5"
QUICK_FLAG=""
MODE="auto"

print_header() {
    echo -e "${BLUE}==============================================================================${NC}"
    echo -e "${BOLD}${CYAN}  SDN Network Telemetry & Traffic Anomaly Detection System${NC}"
    echo -e "${BOLD}  Systematic Benchmark Evaluation Suite (51-Run Matrix)${NC}"
    echo -e "${BLUE}==============================================================================${NC}"
}

usage() {
    echo -e "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --quick               Execute rapid evaluation matrix (for automated testing)"
    echo "  --intervals \"1 2 5\"   Set polling intervals to evaluate (default: 1 2 5)"
    echo "  --output-dir <DIR>    Directory to store evaluation results (default: evaluation/results)"
    echo "  --mode <MODE>         Execution mode: auto, live, simulated (default: auto)"
    echo "  -h, --help            Display this help message"
    echo ""
    exit 0
}

# Parse command line flags
while [[ $# -gt 0 ]]; do
    case "$1" in
        --quick)
            QUICK_FLAG="--quick"
            shift
            ;;
        --intervals)
            INTERVALS="$2"
            shift 2
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --mode)
            MODE="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            usage
            ;;
    esac
done

print_header

echo -e "${BOLD}Configuration:${NC}"
echo -e "  Project Root:       ${CYAN}${PROJECT_ROOT}${NC}"
echo -e "  Output Directory:   ${CYAN}${OUTPUT_DIR}${NC}"
echo -e "  Polling Intervals:  ${CYAN}${INTERVALS}${NC}"
echo -e "  Execution Mode:     ${CYAN}${MODE}${NC}"
if [[ -n "${QUICK_FLAG}" ]]; then
    echo -e "  Evaluation Mode:    ${YELLOW}QUICK (Rapid Validation)${NC}"
else
    echo -e "  Evaluation Mode:    ${GREEN}FULL BENCHMARK${NC}"
fi
echo ""

# Ensure output directory exists
mkdir -p "${OUTPUT_DIR}"

# Check for python3
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}ERROR: python3 could not be found. Please install Python 3.${NC}"
    exit 1
fi

echo -e "${BLUE}[*] Starting Benchmark Runner...${NC}"

# Execute benchmark runner
PYTHONPATH="${PROJECT_ROOT}:${PYTHONPATH:-}" python3 "${PROJECT_ROOT}/evaluation/benchmark_runner.py" \
    --output-dir "${OUTPUT_DIR}" \
    --intervals ${INTERVALS} \
    --mode "${MODE}" \
    ${QUICK_FLAG}

# Verify output artifacts
CSV_FILE="${OUTPUT_DIR}/benchmark_summary.csv"
REPORT_FILE="${OUTPUT_DIR}/evaluation_report.md"

if [[ -f "${CSV_FILE}" && -f "${REPORT_FILE}" ]]; then
    TOTAL_ROWS=$(($(wc -l < "${CSV_FILE}") - 1))
    echo ""
    echo -e "${GREEN}${BOLD}✓ Benchmark evaluation finished successfully!${NC}"
    echo -e "  Total evaluation runs recorded: ${BOLD}${TOTAL_ROWS}${NC}"
    echo -e "  CSV Dataset:  ${CYAN}${CSV_FILE}${NC}"
    echo -e "  Report:       ${CYAN}${REPORT_FILE}${NC}"
    echo ""

    echo -e "${BOLD}${CYAN}--- Benchmark Summary Preview ---${NC}"
    echo -e "${BOLD}Top rows from ${CSV_FILE}:${NC}"
    head -n 6 "${CSV_FILE}" | column -s, -t 2>/dev/null || head -n 6 "${CSV_FILE}"
    echo ""

    echo -e "${BLUE}==============================================================================${NC}"
    echo -e "${GREEN}${BOLD}Evaluation complete. All artifacts ready for viva demonstration and audit.${NC}"
    echo -e "${BLUE}==============================================================================${NC}"
    exit 0
else
    echo -e "${RED}ERROR: Benchmark artifacts were not generated properly.${NC}"
    exit 1
fi
