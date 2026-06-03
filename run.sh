#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# run.sh — Full Bug Bounty Pipeline
# Chains Phase 1 (bash recon) → Phase 2 (Qwen analysis) → Phase 3 (report)
#
# Usage: ./run.sh <domain> [scope]
# Example: ./run.sh tesla.com "*.tesla.com"
# ─────────────────────────────────────────────────────────────────

set -euo pipefail

TARGET="${1:-}"
SCOPE="${2:-}"

if [[ -z "$TARGET" ]]; then
  echo ""
  echo "  Usage: ./run.sh <domain> [scope]"
  echo "  Example: ./run.sh example.com '*.example.com'"
  echo ""
  exit 1
fi

if [[ -z "$SCOPE" ]]; then
  SCOPE="*.${TARGET}"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
OUT_DIR="${SCRIPT_DIR}/reports/${TARGET}_${TIMESTAMP}"
mkdir -p "$OUT_DIR"

RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[0;33m'
BLU='\033[0;34m'
BLD='\033[1m'
RST='\033[0m'

banner() {
  echo ""
  echo -e "${BLU}${BLD}╔══════════════════════════════════════════════╗${RST}"
  echo -e "${BLU}${BLD}║   BB-Agent — Qwen 2.5 7B + Bash Pipeline    ║${RST}"
  echo -e "${BLU}${BLD}╚══════════════════════════════════════════════╝${RST}"
  echo ""
  echo -e "  ${BLD}Target${RST} : $TARGET"
  echo -e "  ${BLD}Scope ${RST} : $SCOPE"
  echo -e "  ${BLD}Output${RST} : $OUT_DIR"
  echo ""
}

step() {
  echo ""
  echo -e "${YLW}${BLD}━━━ $* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
}

ok()   { echo -e "  ${GRN}✓${RST} $*"; }
fail() { echo -e "  ${RED}✗${RST} $*"; }

check_deps() {
  step "Checking dependencies"
  local missing=0

  # Required
  for tool in python3; do
    if command -v "$tool" &>/dev/null; then
      ok "$tool found"
    else
      fail "$tool NOT FOUND (required)"
      missing=$((missing + 1))
    fi
  done

  # Check ollama
  if curl -sf http://localhost:11434/api/tags &>/dev/null; then
    ok "ollama running"
    # Check if qwen2.5:7b is available
    if curl -sf http://localhost:11434/api/tags | grep -q "qwen2.5:7b"; then
      ok "qwen2.5:7b model found"
    else
      fail "qwen2.5:7b not pulled — run: ollama pull qwen2.5:7b"
      missing=$((missing + 1))
    fi
  else
    fail "ollama not running — run: ollama serve"
    missing=$((missing + 1))
  fi

  # Check python deps
  if python3 -c "import openai" 2>/dev/null; then
    ok "openai python package found"
  else
    fail "openai not installed — run: pip install openai"
    missing=$((missing + 1))
  fi

  # Optional tools (warn but don't fail)
  echo ""
  for tool in subfinder httpx nuclei ffuf gau katana amass; do
    if command -v "$tool" &>/dev/null; then
      ok "$tool (optional) ✓"
    else
      echo -e "  ${YLW}⚠${RST}  $tool not found (optional — skipped if missing)"
    fi
  done

  if [[ $missing -gt 0 ]]; then
    echo ""
    fail "$missing required dependency/dependencies missing. Fix above errors and retry."
    exit 1
  fi
}

run_phase1() {
  step "Phase 1 — Bash Recon"
  bash "${SCRIPT_DIR}/phase1_recon.sh" "$TARGET" "$OUT_DIR"
}

run_phase2() {
  step "Phase 2 — Qwen 2.5 7B Analysis"
  python3 "${SCRIPT_DIR}/phase2_analyze.py" "$TARGET" "$OUT_DIR"
}

run_phase3() {
  step "Phase 3 — Report Generation"
  python3 "${SCRIPT_DIR}/phase3_report.py" "$TARGET" "$OUT_DIR"
}

final_summary() {
  echo ""
  echo -e "${GRN}${BLD}╔══════════════════════════════════════════════╗${RST}"
  echo -e "${GRN}${BLD}║              Pipeline Complete               ║${RST}"
  echo -e "${GRN}${BLD}╚══════════════════════════════════════════════╝${RST}"
  echo ""
  echo -e "  ${BLD}All outputs in:${RST} $OUT_DIR/"
  echo ""
  echo "  Files generated:"
  ls -lh "$OUT_DIR/" | awk 'NR>1 {printf "    %-40s %s\n", $NF, $5}'
  echo ""
  echo -e "  ${YLW}⚠  Remember: verify ALL findings manually before submitting${RST}"
  echo ""
}

# ── Main ──────────────────────────────────────────────────────────
banner
check_deps

START=$(date +%s)

run_phase1
run_phase2
run_phase3

END=$(date +%s)
ELAPSED=$((END - START))
MINS=$((ELAPSED / 60))
SECS=$((ELAPSED % 60))

final_summary
echo -e "  ${BLD}Total time:${RST} ${MINS}m ${SECS}s"
echo ""
