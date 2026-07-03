#!/usr/bin/env bash
#
# run_sailor_arm.sh -- run the full Sailor-Arm pipeline end to end:
#   1. isla-footprint: sweep every instruction in AARCHMRS/Instructions.json
#      across EL0-EL3 and write raw traces to arm_traces_output/
#   2. parse_arm.py:   parse those traces into footprint/access CSVs
#   3. analyzer_arm.py: classify every ordered EL pair into
#      switch-from-EL{s}-to-EL{t}.csv
#
# Run from the repository root:
#   ./scripts/run_sailor_arm.sh
#
# Options (env vars, all optional):
#   TIMEOUT       per-instruction Isla timeout in seconds   (default: 30)
#   THREADS       isla-footprint worker thread count        (default: 2)
#   TRACES_DIR    where isla-footprint writes raw traces     (default: arm_traces_output)
#                 NOTE: isla-footprint's output directory name is hardcoded to
#                 "arm_traces_output" -- this variable is used to tell parse_arm.py
#                 where to look, not to change where isla-footprint writes.
#   RESULTS_DIR   parse/analyze input+output directory       (default: sailor_artifacts/results)
#   SKIP_TRACES   set to 1 to skip step 1 and reuse existing traces in TRACES_DIR
#   DETAIL        set to 1 to also emit analyzer *-detail.csv files
#
# Examples:
#   ./scripts/run_sailor_arm.sh
#   THREADS=8 TIMEOUT=60 ./scripts/run_sailor_arm.sh
#   SKIP_TRACES=1 ./scripts/run_sailor_arm.sh          # re-run parse+analyze only

set -euo pipefail

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
TIMEOUT="${TIMEOUT:-30}"
THREADS="${THREADS:-2}"
TRACES_DIR="${TRACES_DIR:-arm_traces_output}"
RESULTS_DIR="${RESULTS_DIR:-sailor_artifacts/results}"
SKIP_TRACES="${SKIP_TRACES:-0}"
DETAIL="${DETAIL:-0}"

ISLA_FOOTPRINT="isla/target/release/isla-footprint"
IR_FILE="configs/armv9p4.ir"
MMU_CONFIG="isla/configs/armv9p4_mmu_on.toml"
INSTRUCTIONS_JSON="AARCHMRS/Instructions.json"

# Resolve repo root so the script works from any cwd.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

log() { printf '\n[run_sailor_arm] %s\n' "$1"; }

# ---------------------------------------------------------------------------
# Sanity checks
# ---------------------------------------------------------------------------
if [ "${SKIP_TRACES}" != "1" ]; then
    [ -x "${ISLA_FOOTPRINT}" ] || {
        echo "error: ${ISLA_FOOTPRINT} not found or not executable." >&2
        echo "       build it first, e.g. 'make setup-isla'." >&2
        exit 1
    }
    [ -f "${IR_FILE}" ]            || { echo "error: ${IR_FILE} not found." >&2; exit 1; }
    [ -f "${MMU_CONFIG}" ]         || { echo "error: ${MMU_CONFIG} not found." >&2; exit 1; }
    [ -f "${INSTRUCTIONS_JSON}" ]  || { echo "error: ${INSTRUCTIONS_JSON} not found." >&2; exit 1; }
fi

command -v python3 >/dev/null 2>&1 || { echo "error: python3 not found." >&2; exit 1; }
[ -f "src/parse_arm.py" ]    || { echo "error: src/parse_arm.py not found." >&2; exit 1; }
[ -f "src/analyzer_arm.py" ] || { echo "error: src/analyzer_arm.py not found." >&2; exit 1; }

# ---------------------------------------------------------------------------
# Step 1: generate traces
# ---------------------------------------------------------------------------
if [ "${SKIP_TRACES}" = "1" ]; then
    log "SKIP_TRACES=1 -- reusing traces already in ${TRACES_DIR}/"
    [ -d "${TRACES_DIR}" ] || { echo "error: ${TRACES_DIR} does not exist." >&2; exit 1; }
else
    log "Step 1/3: generating traces (timeout=${TIMEOUT}s, threads=${THREADS})"
    START=$(date +%s)

    "${ISLA_FOOTPRINT}" \
        -A "${IR_FILE}" \
        -C "${MMU_CONFIG}" \
        -i "passcheck" \
        -n "${INSTRUCTIONS_JSON}" \
        --timeout "${TIMEOUT}" \
        -T "${THREADS}" \
        -s \
        --high-va-probe \
        --armv8-page-tables "identity 0x600000;"

    # isla-footprint's output directory name ("arm_traces_output") is hardcoded;
    # if the caller asked for a different TRACES_DIR, move the output there.
    if [ "${TRACES_DIR}" != "arm_traces_output" ]; then
        rm -rf "${TRACES_DIR}"
        mv arm_traces_output "${TRACES_DIR}"
    fi

    END=$(date +%s)
    log "Trace generation done in $((END - START))s -> ${TRACES_DIR}/"
fi

# ---------------------------------------------------------------------------
# Step 2: parse traces
# ---------------------------------------------------------------------------
log "Step 2/3: parsing traces -> ${RESULTS_DIR}/"
mkdir -p "${RESULTS_DIR}"

SAILOR_TRACES_DIR="${TRACES_DIR}" \
SAILOR_OUTPUT_DIR="${RESULTS_DIR}" \
    python3 src/parse_arm.py

# ---------------------------------------------------------------------------
# Step 3: classify every EL pair
# ---------------------------------------------------------------------------
log "Step 3/3: running the analyzer -> ${RESULTS_DIR}/"

ANALYZER_ARGS=(--in "${RESULTS_DIR}" --out "${RESULTS_DIR}")
[ "${DETAIL}" = "1" ] && ANALYZER_ARGS+=(--detail)

python3 src/analyzer_arm.py "${ANALYZER_ARGS[@]}"

log "Done. Sensitivity CSVs for all 16 EL pairs are in ${RESULTS_DIR}/"
