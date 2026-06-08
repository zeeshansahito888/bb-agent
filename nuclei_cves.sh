#!/usr/bin/env bash
TARGET="${1:-}"
OUTDIR="${2:-recon/$TARGET}"

if [[ -z "$TARGET" ]]; then
  echo "Usage: $0 <domain> <recon_dir>"
  exit 1
fi

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[0;33m'
BLU='\033[0;34m'; RST='\033[0m'

info() { echo -e "[$(date '+%H:%M:%S')] ${BLU}[NCVE]${RST}  $*"; }
ok()   { echo -e "[$(date '+%H:%M:%S')] ${GRN}[OK]${RST}    $*"; }
warn() { echo -e "[$(date '+%H:%M:%S')] ${YLW}[WARN]${RST}  $*"; }

info "=== NUCLEI CVE SCAN + INTERACTSH OOB ==="

touch "$OUTDIR/nuclei_cves.txt"
touch "$OUTDIR/nuclei_oob.txt"

# ── Pass 1: CVE templates ─────────────────────────────────────────
info "Pass 1 — CVE-specific templates..."
if [[ -d ~/nuclei-templates/cves ]]; then
  nuclei -l "$OUTDIR/live-urls.txt" \
         -t ~/nuclei-templates/cves/ \
         -silent -no-color \
         -o "$OUTDIR/nuclei_cves.txt" 2>/dev/null || true
  ok "CVE findings: $(wc -l < "$OUTDIR/nuclei_cves.txt")"
else
  warn "~/nuclei-templates/cves/ not found — run: nuclei -update-templates"
fi

# ── Pass 2: OOB/SSRF templates with interactsh ───────────────────
info "Pass 2 — OOB detection with interactsh..."
if command -v interactsh-client &>/dev/null; then
  # Generate interactsh URL
  IURL=$(interactsh-client \
    -server https://interact.sh \
    -n 1 -json 2>/dev/null \
    | jq -r '.url' 2>/dev/null | head -1)

  if [[ -n "$IURL" ]]; then
    ok "Interactsh URL: $IURL"

    # Run nuclei with interactsh for OOB detection
    nuclei -l "$OUTDIR/live-urls.txt" \
           -tags oob,ssrf,xxe,ssti \
           -iserver "https://interact.sh" \
           -silent -no-color \
           -o "$OUTDIR/nuclei_oob.txt" 2>/dev/null || true

    ok "OOB findings: $(wc -l < "$OUTDIR/nuclei_oob.txt")"
    info "Check https://app.interactsh.com for OOB hits"
  else
    warn "interactsh URL generation failed — skipping OOB scan"
  fi
else
  warn "interactsh-client not installed — skipping OOB scan"
  warn "Install: go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
fi

# ── Pass 3: Exposure templates ────────────────────────────────────
info "Pass 3 — Exposure templates..."
if [[ -d ~/nuclei-templates/exposures ]]; then
  nuclei -l "$OUTDIR/live-urls.txt" \
         -t ~/nuclei-templates/exposures/ \
         -severity critical,high \
         -silent -no-color \
         >> "$OUTDIR/nuclei_cves.txt" 2>/dev/null || true
  ok "Exposure scan done"
fi

echo ""
info "NUCLEI CVE SCAN COMPLETE"
info "CVE findings : $(wc -l < "$OUTDIR/nuclei_cves.txt")"
info "OOB findings : $(wc -l < "$OUTDIR/nuclei_oob.txt")"
