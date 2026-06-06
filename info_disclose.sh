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
info() { echo -e "[$(ts)] ${BLU}[INFO]${RST}  $*"; }
ok()   { echo -e "[$(ts)] ${GRN}[OK]${RST}    $*"; }
warn() { echo -e "[$(ts)] ${YLW}[WARN]${RST}  $*"; }
crit() { echo -e "[$(ts)] ${RED}[CRIT]${RST}  $*"; }

info "=== INFO DISCLOSURE CHECK ==="

RESPONSES_FILE="$OUTDIR/info_responses.txt"
touch "$RESPONSES_FILE"

PATHS=(
  "/nonexistent-page-404"
  "/.env"
  "/.git/config"
  "/.git/HEAD"
  "/config.json"
  "/config.yml"
  "/debug"
  "/debug/info"
  "/info"
  "/health"
  "/healthz"
  "/metrics"
  "/actuator"
  "/actuator/env"
  "/actuator/mappings"
  "/phpinfo.php"
  "/server-status"
  "/robots.txt"
  "/swagger.json"
  "/swagger-ui.html"
  "/api-docs"
  "/api/swagger"
  "/openapi.json"
  "/__debug__"
  "/telescope"
  "/horizon"
  "/.well-known/security.txt"
)

info "Probing ${#PATHS[@]} paths on live hosts..."

COUNT=0
while read -r url && [[ $COUNT -lt 20 ]]; do
  for path in "${PATHS[@]}"; do
    full_url="${url}${path}"
    response=$(curl -sk "$full_url" \
      --max-time 8 \
      -w "\nHTTP_STATUS:%{http_code}" \
      -H "User-Agent: Mozilla/5.0" \
      2>/dev/null || true)

    status=$(echo "$response" | grep "HTTP_STATUS:" | cut -d: -f2)
    body=$(echo "$response" | grep -v "HTTP_STATUS:")

    if [[ "$status" == "200" || "$status" == "500" ]]; then
      if echo "$body" | grep -qiE "error|exception|stack|trace|debug|password|secret|token|key|config|database|sql|php|ruby|python|node|version|internal"; then
        echo "=== URL: $full_url ===" >> "$RESPONSES_FILE"
        echo "STATUS: $status" >> "$RESPONSES_FILE"
        echo "BODY:" >> "$RESPONSES_FILE"
        echo "$body" | head -50 >> "$RESPONSES_FILE"
        echo "---" >> "$RESPONSES_FILE"
      fi
    fi

    # Always save .env and .git hits
    if [[ "$status" == "200" ]] && [[ "$path" == "/.env" || "$path" == "/.git/config" || "$path" == "/.git/HEAD" ]]; then
      crit "CRITICAL HIT: $full_url"
      echo "=== CRITICAL: $full_url ===" >> "$RESPONSES_FILE"
      echo "STATUS: $status" >> "$RESPONSES_FILE"
      echo "$body" | head -30 >> "$RESPONSES_FILE"
      echo "---" >> "$RESPONSES_FILE"
    fi
  done
  COUNT=$((COUNT + 1))
done < "$OUTDIR/live-urls.txt"

ok "Probed $COUNT hosts"

INTERESTING=$(grep -c "^=== URL:" "$RESPONSES_FILE" 2>/dev/null || echo 0)
CRITICAL=$(grep -c "^=== CRITICAL:" "$RESPONSES_FILE" 2>/dev/null || echo 0)

echo ""
info "INFO DISCLOSURE COMPLETE"
info "Hosts: $COUNT | Interesting: $INTERESTING | Critical: $CRITICAL"
[[ $CRITICAL -gt 0 ]] && crit "CRITICAL hits found — check $RESPONSES_FILE"
info "Next: python3 info_analyzer.py $TARGET $OUTDIR"
