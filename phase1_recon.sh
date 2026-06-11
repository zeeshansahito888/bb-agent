#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-}"
OUT="${2:-./recon}"

if [[ -z "$TARGET" ]]; then
  echo "Usage: $0 <domain> [out_dir]"
  exit 1
fi

OUTDIR="$OUT/$TARGET"
mkdir -p "$OUTDIR"
LOG="$OUTDIR/recon.log"
exec > >(tee -a "$LOG") 2>&1

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[0;33m'
BLU='\033[0;34m'; BLD='\033[1m'; RST='\033[0m'

ts()   { date '+%H:%M:%S'; }
info() { echo -e "[$(ts)] ${BLU}[INFO]${RST}  $*"; }
ok()   { echo -e "[$(ts)] ${GRN}[OK]${RST}    $*"; }
warn() { echo -e "[$(ts)] ${YLW}[WARN]${RST}  $*"; }
skip() { echo -e "[$(ts)] ${YLW}[SKIP]${RST}  $* not installed"; }
has()  { command -v "$1" &>/dev/null; }

HTTPX_CMD=""
if has httpx-toolkit; then HTTPX_CMD="httpx-toolkit"
elif has httpx;       then HTTPX_CMD="httpx"
else warn "httpx-toolkit not found — install: apt install httpx-toolkit"
fi

info "Target  : $TARGET"
info "Out dir : $OUTDIR"
echo ""

info "=== STEP 1: SUBDOMAIN ENUMERATION ==="

if [[ -n "${CHAOS_API_KEY:-}" ]]; then
  info "Running Chaos API..."
  curl -s "https://dns.projectdiscovery.io/dns/$TARGET/subdomains" \
    -H "Authorization: $CHAOS_API_KEY" \
    | jq -r '.subdomains[]' 2>/dev/null \
    | sed "s/$/.${TARGET}/" \
    > "$OUTDIR/subs_chaos.txt" || true
  ok "Chaos: $(wc -l < "$OUTDIR/subs_chaos.txt") subdomains"
else
  warn "CHAOS_API_KEY not set — skipping"
  touch "$OUTDIR/subs_chaos.txt"
fi

if has subfinder; then
  info "Running subfinder..."
  subfinder -d "$TARGET" -silent -o "$OUTDIR/subs_subfinder.txt" 2>/dev/null || true
  ok "subfinder: $(wc -l < "$OUTDIR/subs_subfinder.txt") subdomains"
else
  skip subfinder; touch "$OUTDIR/subs_subfinder.txt"
fi

if has assetfinder; then
  info "Running assetfinder..."
  assetfinder --subs-only "$TARGET" > "$OUTDIR/subs_assetfinder.txt" 2>/dev/null || true
  ok "assetfinder: $(wc -l < "$OUTDIR/subs_assetfinder.txt") subdomains"
else
  skip assetfinder; touch "$OUTDIR/subs_assetfinder.txt"
fi

info "Merging subdomains..."
cat "$OUTDIR"/subs_*.txt 2>/dev/null \
  | grep -v "^$" \
  | sort -u > "$OUTDIR/subdomains.txt"
ok "Total unique subdomains: $(wc -l < "$OUTDIR/subdomains.txt")"

info ""
info "=== STEP 2: LIVE HOST DISCOVERY ==="

if [[ -n "$HTTPX_CMD" ]]; then
  if has dnsx; then
    cat "$OUTDIR/subdomains.txt" \
      | dnsx -silent 2>/dev/null \
      | $HTTPX_CMD -silent -status-code -title -tech-detect -mc 200,301,302,403 \
      | tee "$OUTDIR/live-hosts.txt" || true
  else
    awk '{if ($0 !~ /^https?:\/\//) print "https://"$0; else print}' \
      "$OUTDIR/subdomains.txt" \
      | $HTTPX_CMD -silent -status-code -title -tech-detect -mc 200,301,302,403 \
      | tee "$OUTDIR/live-hosts.txt" || true
  fi
  ok "Live hosts: $(wc -l < "$OUTDIR/live-hosts.txt")"
else
  awk '{print "https://"$0}' "$OUTDIR/subdomains.txt" > "$OUTDIR/live-hosts.txt"
fi

awk '{print $1}' "$OUTDIR/live-hosts.txt" > "$OUTDIR/live-urls.txt"
ok "Live URLs: $(wc -l < "$OUTDIR/live-urls.txt")"

info ""
info "=== STEP 3: URL CRAWLING ==="

touch "$OUTDIR/urls.txt"

if has katana; then
  info "Running katana..."
  cat "$OUTDIR/live-urls.txt" \
    | katana -d 3 -jc -kf all -silent 2>/dev/null \
    >> "$OUTDIR/urls.txt" || true
  ok "katana done"
else
  skip katana
fi

if has waybackurls; then
  info "Running waybackurls..."
  echo "$TARGET" | waybackurls 2>/dev/null >> "$OUTDIR/urls.txt" || true
  ok "waybackurls done"
else
  skip waybackurls
fi

sort -u "$OUTDIR/urls.txt" -o "$OUTDIR/urls.txt"
ok "Total unique URLs: $(wc -l < "$OUTDIR/urls.txt")"

info ""
info "=== STEP 4: URL CLASSIFICATION ==="

if has gf; then
  cat "$OUTDIR/urls.txt" | gf idor  > "$OUTDIR/idor-candidates.txt"  2>/dev/null || true
  cat "$OUTDIR/urls.txt" | gf ssrf  > "$OUTDIR/ssrf-candidates.txt"  2>/dev/null || true
  cat "$OUTDIR/urls.txt" | gf xss   > "$OUTDIR/xss-candidates.txt"   2>/dev/null || true
  cat "$OUTDIR/urls.txt" | gf sqli  > "$OUTDIR/sqli-candidates.txt"  2>/dev/null || true
else
  skip gf
  grep -iE "[?&](id|uid|user_id|account|order|invoice|file|path)=[0-9]" \
    "$OUTDIR/urls.txt" > "$OUTDIR/idor-candidates.txt" 2>/dev/null || true
  grep -iE "[?&](url|uri|path|dest|redirect|next|src|target|host)=" \
    "$OUTDIR/urls.txt" > "$OUTDIR/ssrf-candidates.txt" 2>/dev/null || true
  grep -iE "[?&](q|search|query|input|keyword|name|s)=" \
    "$OUTDIR/urls.txt" > "$OUTDIR/xss-candidates.txt" 2>/dev/null || true
  grep -iE "[?&](id|cat|category|item|page|sort|order)=" \
    "$OUTDIR/urls.txt" > "$OUTDIR/sqli-candidates.txt" 2>/dev/null || true
fi

grep -iE "/api/|/v1/|/v2/|/v3/|/graphql|/rest/|/json" \
  "$OUTDIR/urls.txt" | sort -u > "$OUTDIR/api-endpoints.txt" 2>/dev/null || true

grep -iE "/graphql|/subscriptions|ws://|wss://" \
  "$OUTDIR/urls.txt" | sort -u > "$OUTDIR/p1-candidates.txt" 2>/dev/null || true

ok "IDOR candidates : $(wc -l < "$OUTDIR/idor-candidates.txt")"
ok "SSRF candidates : $(wc -l < "$OUTDIR/ssrf-candidates.txt")"
ok "XSS  candidates : $(wc -l < "$OUTDIR/xss-candidates.txt")"
ok "SQLi candidates : $(wc -l < "$OUTDIR/sqli-candidates.txt")"
ok "API endpoints   : $(wc -l < "$OUTDIR/api-endpoints.txt")"
ok "GraphQL/WS (P1) : $(wc -l < "$OUTDIR/p1-candidates.txt")"

info ""
info "=== STEP 5: NUCLEI SCAN ==="

touch "$OUTDIR/nuclei.txt"
if has nuclei; then
  info "Running nuclei..."
  nuclei -l "$OUTDIR/live-urls.txt" \
         -severity critical,high,medium \
         -silent -no-color \
         -o "$OUTDIR/nuclei.txt" 2>/dev/null || true
  ok "Nuclei findings: $(wc -l < "$OUTDIR/nuclei.txt")"
else
  skip nuclei
fi

info ""
info "=== KILL CHECK ==="

LIVE_COUNT=$(wc -l < "$OUTDIR/live-urls.txt"       2>/dev/null || echo 0)
API_COUNT=$(wc -l  < "$OUTDIR/api-endpoints.txt"   2>/dev/null || echo 0)
IDOR_COUNT=$(wc -l < "$OUTDIR/idor-candidates.txt" 2>/dev/null || echo 0)
NUC_COUNT=$(wc -l  < "$OUTDIR/nuclei.txt"          2>/dev/null || echo 0)
P1_COUNT=$(wc -l   < "$OUTDIR/p1-candidates.txt"   2>/dev/null || echo 0)

if [[ $API_COUNT -eq 0 && $IDOR_COUNT -eq 0 && $NUC_COUNT -eq 0 && $P1_COUNT -eq 0 ]]; then
  warn "⚠  KILL CHECK: No APIs, no IDOR candidates, no findings. Consider a different target."
else
  ok "Attack surface found — proceed to ranking"
fi

echo ""
info "════════════════════════════════════════"
info "RECON COMPLETE — $TARGET"
info "════════════════════════════════════════"
info "Subdomains      : $(wc -l < "$OUTDIR/subdomains.txt"      2>/dev/null || echo 0)"
info "Live hosts      : $LIVE_COUNT"
info "Total URLs      : $(wc -l < "$OUTDIR/urls.txt"            2>/dev/null || echo 0)"
info "API endpoints   : $API_COUNT"
info "IDOR candidates : $IDOR_COUNT"
info "GraphQL/WS (P1) : $P1_COUNT"
info "Nuclei findings : $NUC_COUNT"
info "Output          : $OUTDIR/"
echo ""
info "Next: python3 phase2_analyze.py $TARGET"

# ── Shodan + SecurityTrails (runs after subfinder) ────────────────
# Load config
CONFIG="${BASH_SOURCE%/*}/config.env"
[[ -f "$CONFIG" ]] && source "$CONFIG"

# Shodan subdomain enum
if [[ -n "${SHODAN_API_KEY:-}" ]]; then
  info "Running Shodan..."
  curl -s "https://api.shodan.io/dns/domain/${TARGET}?key=${SHODAN_API_KEY}" \
    2>/dev/null \
    | python3 -c "
import sys,json
try:
  d=json.load(sys.stdin)
  for s in d.get('subdomains',[]):
    print(f'{s}.${TARGET}' if not s.endswith('${TARGET}') else s)
except: pass
" >> "$OUTDIR/subdomains.txt" 2>/dev/null || true
  ok "Shodan done"
else
  warn "SHODAN_API_KEY not set in config.env"
fi

# SecurityTrails subdomain enum
if [[ -n "${SECURITYTRAILS_API_KEY:-}" ]]; then
  info "Running SecurityTrails..."
  curl -s "https://api.securitytrails.com/v1/domain/${TARGET}/subdomains?apikey=${SECURITYTRAILS_API_KEY}" \
    2>/dev/null \
    | python3 -c "
import sys,json
try:
  d=json.load(sys.stdin)
  target='${TARGET}'
  for s in d.get('subdomains',[]):
    print(f'{s}.{target}')
except: pass
" >> "$OUTDIR/subdomains.txt" 2>/dev/null || true
  ok "SecurityTrails done"
else
  warn "SECURITYTRAILS_API_KEY not set in config.env"
fi

# Deduplicate after adding new sources
sort -u "$OUTDIR/subdomains.txt" -o "$OUTDIR/subdomains.txt"
ok "Subdomains after Shodan+ST: $(wc -l < "$OUTDIR/subdomains.txt")"
