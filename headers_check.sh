#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-}"
OUTDIR="${2:-recon/$TARGET}"

if [[ -z "$TARGET" ]]; then
  echo "Usage: $0 <domain> <recon_dir>"
  exit 1
fi

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[0;33m'
BLU='\033[0;34m'; BLD='\033[1m'; RST='\033[0m'

ts()   { date '+%H:%M:%S'; }
info() { echo -e "[$(ts)] ${BLU}[HDR]${RST}  $*"; }
ok()   { echo -e "[$(ts)] ${GRN}[OK]${RST}   $*"; }
warn() { echo -e "[$(ts)] ${YLW}[WARN]${RST} $*"; }

info "=== SECURITY HEADERS CHECK ==="

HEADERS_FILE="$OUTDIR/headers_raw.txt"
FINDINGS_FILE="$OUTDIR/headers_findings.txt"
touch "$HEADERS_FILE" "$FINDINGS_FILE"

info "Fetching headers from live hosts..."
COUNT=0
while read -r url && [[ $COUNT -lt 50 ]]; do
  headers=$(curl -skI "$url" --max-time 8 -H "User-Agent: Mozilla/5.0" 2>/dev/null || true)
  if [[ -n "$headers" ]]; then
    echo "=== $url ===" >> "$HEADERS_FILE"
    echo "$headers" >> "$HEADERS_FILE"
    echo "" >> "$HEADERS_FILE"
    COUNT=$((COUNT + 1))
  fi
done < "$OUTDIR/live-urls.txt"
ok "Fetched headers from $COUNT hosts"

info "Checking for missing security headers..."
MISSING=0
current_url=""
current_headers=""

while IFS= read -r line; do
  if [[ "$line" == "=== "* ]]; then
    current_url="${line//=== /}"
    current_url="${current_url// ===/}"
    current_headers=""
  elif [[ -z "$line" && -n "$current_url" ]]; then
    findings=""
    echo "$current_headers" | grep -qi "strict-transport-security" || \
      findings+="MISSING: Strict-Transport-Security (HSTS)\n"
    echo "$current_headers" | grep -qi "content-security-policy" || \
      findings+="MISSING: Content-Security-Policy (CSP)\n"
    echo "$current_headers" | grep -qi "x-frame-options" || \
      findings+="MISSING: X-Frame-Options (Clickjacking)\n"
    echo "$current_headers" | grep -qi "x-content-type-options" || \
      findings+="MISSING: X-Content-Type-Options\n"
    echo "$current_headers" | grep -qi "referrer-policy" || \
      findings+="MISSING: Referrer-Policy\n"
    echo "$current_headers" | grep -qiE "server: apache|server: nginx/[0-9]|x-powered-by|x-aspnet-version" && \
      findings+="INFO LEAK: Server version disclosed\n" || true

    if [[ -n "$findings" ]]; then
      echo "HOST: $current_url" >> "$FINDINGS_FILE"
      echo -e "$findings" >> "$FINDINGS_FILE"
      echo "---" >> "$FINDINGS_FILE"
      MISSING=$((MISSING + 1))
    fi
    current_url=""
  else
    current_headers+="$line"$'\n'
  fi
done < "$HEADERS_FILE"

ok "Found $MISSING hosts with header issues"

echo ""
info "HEADERS CHECK COMPLETE"
info "Hosts checked: $COUNT | Issues: $MISSING"
info "Next: python3 headers_analyzer.py $TARGET $OUTDIR"
