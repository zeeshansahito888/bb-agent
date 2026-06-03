#!/usr/bin/env bash
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

[[ -z "$SCOPE" ]] && SCOPE="*.${TARGET}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RECON_DIR="${SCRIPT_DIR}/recon/${TARGET}"

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[0;33d'
BLU='\033[0;34m'; BLD='\033[1m'; RST='\033[0m'

banner() {
  echo ""
  echo -e "${BLU}${BLD}╔══════════════════════════════════════════════╗${RST}"
  echo -e "${BLU}${BLD}║   BB-Agent — Qwen 2.5 7B + Bash Pipeline    ║${RST}"
  echo -e "${BLU}${BLD}╚══════════════════════════════════════════════╝${RST}"
  echo ""
  echo -e "  ${BLD}Target${RST} : $TARGET"
  echo -e "  ${BLD}Scope ${RST} : $SCOPE"
  echo -e "  ${BLD}Output${RST} : $RECON_DIR"
  echo ""
}

step() { echo ""; echo -e "${YLW}${BLD}━━━ $* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"; }
ok()   { echo -e "  ${GRN}✓${RST} $*"; }
fail() { echo -e "  ${RED}✗${RST} $*"; }

check_deps() {
  step "Checking dependencies"
  if curl -sf http://localhost:11434/api/tags &>/dev/null; then
    ok "ollama running"
    if curl -sf http://localhost:11434/api/tags | grep -q "qwen2.5:7b"; then
      ok "qwen2.5:7b ready"
    else
      fail "qwen2.5:7b not pulled — run: ollama pull qwen2.5:7b"
      exit 1
    fi
  else
    fail "ollama not running"
    exit 1
  fi

  if python3 -c "import openai" 2>/dev/null; then
    ok "openai python package"
  else
    fail "openai not installed — run: pip install openai --break-system-packages"
    exit 1
  fi

  echo ""
  for tool in subfinder httpx-toolkit dnsx nuclei katana assetfinder waybackurls gf ffuf; do
    command -v "$tool" &>/dev/null \
      && echo -e "  ${GRN}✓${RST} $tool" \
      || echo -e "  ${YLW}⚠${RST}  $tool (optional — run install.sh)"
  done
}

banner
check_deps

START=$(date +%s)

step "Phase 1 — Bash Recon"
bash "${SCRIPT_DIR}/phase1_recon.sh" "$TARGET" "${SCRIPT_DIR}/recon"

step "Phase 2 — Qwen Analysis"
python3 "${SCRIPT_DIR}/phase2_analyze.py" "$TARGET" "$RECON_DIR"

step "Recon Ranker — Attack Surface Ranking"
python3 "${SCRIPT_DIR}/recon_ranker.py" "$TARGET" "$RECON_DIR"

step "Phase 3 — Report Generation"
python3 "${SCRIPT_DIR}/phase3_report.py" "$TARGET" "$RECON_DIR"

END=$(date +%s)
ELAPSED=$((END - START))

echo ""
echo -e "${GRN}${BLD}╔══════════════════════════════════════════════╗${RST}"
echo -e "${GRN}${BLD}║              Pipeline Complete               ║${RST}"
echo -e "${GRN}${BLD}╚══════════════════════════════════════════════╝${RST}"
echo ""
echo -e "  ${BLD}Output:${RST} $RECON_DIR/"
echo ""
echo -e "  ${YLW}⚠  Verify ALL findings manually before submitting${RST}"
echo -e "  ${BLD}Time:${RST} $((ELAPSED/60))m $((ELAPSED%60))s"
echo ""
