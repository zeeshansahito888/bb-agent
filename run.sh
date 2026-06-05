#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# run.sh — Full Bug Bounty Pipeline
# Phase 1 (recon) → Phase 2 (analyze) → Ranker → Phase 3 (report)
# + Auto-mines results into MemPalace
#
# Usage: ./run.sh <domain> [scope]
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

[[ -z "$SCOPE" ]] && SCOPE="*.${TARGET}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RECON_DIR="${SCRIPT_DIR}/recon/${TARGET}"

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[0;33m'
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
warn() { echo -e "  ${YLW}⚠${RST}  $*"; }

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
  for tool in subfinder httpx-toolkit dnsx nuclei katana assetfinder waybackurls gf ffuf mempalace; do
    command -v "$tool" &>/dev/null \
      && echo -e "  ${GRN}✓${RST} $tool" \
      || echo -e "  ${YLW}⚠${RST}  $tool (optional)"
  done
}

mine_mempalace() {
  step "MemPalace — Mining findings into memory"
  if command -v mempalace &>/dev/null; then
    cd "$SCRIPT_DIR"

    # Mine recon output
    echo -e "  Mining recon/${TARGET}/..."
    mempalace mine "${RECON_DIR}" 2>/dev/null \
      && ok "Recon results mined" \
      || warn "Recon mine failed"

    # Mine hunt memory
    echo -e "  Mining hunt-memory/..."
    mempalace mine "${SCRIPT_DIR}/hunt-memory" 2>/dev/null \
      && ok "Hunt memory mined" \
      || warn "Hunt memory mine failed"

    ok "MemPalace updated — future hunts will benefit from these findings"
  else
    warn "mempalace not installed — run: pipx install mempalace"
  fi
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

# Auto-mine into MemPalace
mine_mempalace

END=$(date +%s)
ELAPSED=$((END - START))

echo ""
echo -e "${GRN}${BLD}╔══════════════════════════════════════════════╗${RST}"
echo -e "${GRN}${BLD}║              Pipeline Complete               ║${RST}"
echo -e "${GRN}${BLD}╚══════════════════════════════════════════════╝${RST}"
echo ""
echo -e "  ${BLD}Output:${RST} $RECON_DIR/"
echo ""

# Show output files
echo "  Files generated:"
ls -lh "$RECON_DIR/"*.{txt,md,json} 2>/dev/null \
  | awk '{printf "    %-45s %s\n", $NF, $5}' || true

echo ""
echo -e "  ${YLW}⚠  Verify ALL findings manually before submitting${RST}"
echo -e "  ${BLD}Time:${RST} $((ELAPSED/60))m $((ELAPSED%60))s"
echo ""
echo -e "  ${BLU}Next hunt will remember:${RST}"
echo -e "    mempalace search \"$TARGET findings\""
echo ""
