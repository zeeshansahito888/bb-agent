#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# Phase 1 — Pure Bash Recon
# Usage: ./phase1_recon.sh <domain> [out_dir]
# Example: ./phase1_recon.sh tesla.com
# ─────────────────────────────────────────────────────────────────

set -euo pipefail

TARGET="${1:-}"
OUT="${2:-./tmp}"

if [[ -z "$TARGET" ]]; then
  echo "Usage: $0 <domain> [out_dir]"
  exit 1
fi

mkdir -p "$OUT"
LOG="$OUT/recon.log"
exec > >(tee -a "$LOG") 2>&1

ts() { date '+%H:%M:%S'; }
info()  { echo "[$(ts)] [INFO]  $*"; }
ok()    { echo "[$(ts)] [OK]    $*"; }
warn()  { echo "[$(ts)] [WARN]  $*"; }
check() {
  if ! command -v "$1" &>/dev/null; then
    warn "$1 not found — skipping (install: $2)"
    return 1
  fi
  return 0
}

info "Target  : $TARGET"
info "Out dir : $OUT"
echo ""

# ── 1. Subdomain enumeration ──────────────────────────────────────
info "=== SUBFINDER ==="
if check subfinder "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"; then
  subfinder -d "$TARGET" -silent -o "$OUT/subs_subfinder.txt" 2>/dev/null || true
  SUBS_SF=$(wc -l < "$OUT/subs_subfinder.txt" 2>/dev/null || echo 0)
  ok "subfinder found $SUBS_SF subdomains"
else
  touch "$OUT/subs_subfinder.txt"
fi

# ── 2. Additional subdomain enum via amass (passive) ─────────────
info "=== AMASS (passive) ==="
if check amass "https://github.com/owasp-amass/amass"; then
  amass enum -passive -d "$TARGET" -o "$OUT/subs_amass.txt" 2>/dev/null || true
  SUBS_AM=$(wc -l < "$OUT/subs_amass.txt" 2>/dev/null || echo 0)
  ok "amass found $SUBS_AM subdomains"
else
  touch "$OUT/subs_amass.txt"
fi

# ── 3. Merge + deduplicate ────────────────────────────────────────
info "=== MERGING subdomains ==="
cat "$OUT"/subs_*.txt 2>/dev/null | sort -u > "$OUT/subs_all.txt"
TOTAL=$(wc -l < "$OUT/subs_all.txt")
ok "Total unique subdomains: $TOTAL"

# ── 4. Probe live hosts ───────────────────────────────────────────
info "=== HTTPX — probing live hosts ==="
if check httpx "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"; then
  httpx -l "$OUT/subs_all.txt" \
        -silent \
        -title \
        -status-code \
        -tech-detect \
        -mc 200,301,302,403 \
        -o "$OUT/live_hosts.txt" 2>/dev/null || true
  LIVE=$(wc -l < "$OUT/live_hosts.txt" 2>/dev/null || echo 0)
  ok "Live hosts: $LIVE"
  # Extract just the URLs for downstream tools
  awk '{print $1}' "$OUT/live_hosts.txt" > "$OUT/live_urls.txt"
else
  # Fallback: treat all subs as potentially live with https
  awk '{print "https://"$1}' "$OUT/subs_all.txt" > "$OUT/live_urls.txt"
  cp "$OUT/subs_all.txt" "$OUT/live_hosts.txt"
fi

# ── 5. Historical URLs ────────────────────────────────────────────
info "=== GAU — historical URLs ==="
if check gau "go install github.com/lc/gau/v2/cmd/gau@latest"; then
  gau --subs "$TARGET" 2>/dev/null | sort -u > "$OUT/urls_gau.txt" || true
  GAU_COUNT=$(wc -l < "$OUT/urls_gau.txt" 2>/dev/null || echo 0)
  ok "gau found $GAU_COUNT historical URLs"
else
  touch "$OUT/urls_gau.txt"
fi

# ── 6. JS crawl for endpoints ─────────────────────────────────────
info "=== KATANA — JS crawl ==="
KATANA_OUT="$OUT/urls_katana.txt"
if check katana "go install github.com/projectdiscovery/katana/cmd/katana@latest"; then
  # Crawl first 10 live URLs to keep it fast
  head -10 "$OUT/live_urls.txt" | while read -r url; do
    katana -u "$url" -d 3 -silent -jc 2>/dev/null || true
  done > "$KATANA_OUT"
  KAT_COUNT=$(wc -l < "$KATANA_OUT" 2>/dev/null || echo 0)
  ok "katana found $KAT_COUNT endpoints"
else
  touch "$KATANA_OUT"
fi

# ── 7. Nuclei scan ────────────────────────────────────────────────
info "=== NUCLEI — vuln scan ==="
if check nuclei "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"; then
  nuclei -l "$OUT/live_urls.txt" \
         -severity high,critical \
         -silent \
         -no-color \
         -o "$OUT/nuclei_findings.txt" 2>/dev/null || true
  NUC=$(wc -l < "$OUT/nuclei_findings.txt" 2>/dev/null || echo 0)
  ok "nuclei found $NUC potential issues"
else
  touch "$OUT/nuclei_findings.txt"
  warn "Install nuclei for vuln scanning"
fi

# ── 8. Directory fuzzing (top 5 live hosts) ───────────────────────
info "=== FFUF — directory fuzz (top 5 hosts) ==="
FFUF_OUT="$OUT/ffuf_findings.txt"
touch "$FFUF_OUT"
if check ffuf "go install github.com/ffuf/ffuf/v2@latest"; then
  WORDLIST=""
  for wl in \
    /usr/share/seclists/Discovery/Web-Content/common.txt \
    /usr/share/wordlists/dirb/common.txt \
    /opt/SecLists/Discovery/Web-Content/common.txt; do
    if [[ -f "$wl" ]]; then WORDLIST="$wl"; break; fi
  done

  if [[ -n "$WORDLIST" ]]; then
    head -5 "$OUT/live_urls.txt" | while read -r url; do
      ffuf -u "${url}/FUZZ" \
           -w "$WORDLIST" \
           -mc 200,301,302,403 \
           -silent \
           -of json \
           -o "$OUT/ffuf_$(echo "$url" | md5sum | cut -c1-8).json" 2>/dev/null || true
    done
    # Merge all ffuf json → text
    for f in "$OUT"/ffuf_*.json; do
      [[ -f "$f" ]] || continue
      python3 -c "
import json, sys
try:
  d = json.load(open('$f'))
  for r in d.get('results',[]):
    print(f\"{r['status']} {r['url']}\")
except: pass
" >> "$FFUF_OUT" 2>/dev/null || true
    done
    FFUF_COUNT=$(wc -l < "$FFUF_OUT")
    ok "ffuf found $FFUF_COUNT interesting paths"
  else
    warn "No wordlist found. Install SecLists: https://github.com/danielmiessler/SecLists"
  fi
else
  warn "Install ffuf for directory fuzzing"
fi

# ── Summary ───────────────────────────────────────────────────────
echo ""
info "════════════════════════════════════"
info "RECON COMPLETE — Summary"
info "════════════════════════════════════"
info "Subdomains    : $(wc -l < "$OUT/subs_all.txt" 2>/dev/null || echo 0)"
info "Live hosts    : $(wc -l < "$OUT/live_urls.txt" 2>/dev/null || echo 0)"
info "Historical URLs: $(wc -l < "$OUT/urls_gau.txt" 2>/dev/null || echo 0)"
info "Crawled URLs  : $(wc -l < "$KATANA_OUT" 2>/dev/null || echo 0)"
info "Nuclei hits   : $(wc -l < "$OUT/nuclei_findings.txt" 2>/dev/null || echo 0)"
info "Ffuf paths    : $(wc -l < "$FFUF_OUT" 2>/dev/null || echo 0)"
info "Outputs in    : $OUT/"
echo ""
info "Next: python3 phase2_analyze.py $TARGET $OUT"
