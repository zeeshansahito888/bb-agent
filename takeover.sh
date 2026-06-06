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
info() { echo -e "[$(ts)] ${BLU}[TAKE]${RST}  $*"; }
ok()   { echo -e "[$(ts)] ${GRN}[OK]${RST}    $*"; }
warn() { echo -e "[$(ts)] ${YLW}[WARN]${RST}  $*"; }
crit() { echo -e "[$(ts)] ${RED}[CRIT]${RST}  $*"; }

TAKEOVER_FILE="$OUTDIR/takeover_findings.txt"
touch "$TAKEOVER_FILE"

info "=== SUBDOMAIN TAKEOVER CHECK ==="

declare -A FINGERPRINTS
FINGERPRINTS["github.io"]="There isn't a GitHub Pages site here"
FINGERPRINTS["herokuapp.com"]="No such app"
FINGERPRINTS["amazonaws.com"]="NoSuchBucket"
FINGERPRINTS["s3.amazonaws.com"]="NoSuchBucket"
FINGERPRINTS["cloudfront.net"]="Bad request"
FINGERPRINTS["azurewebsites.net"]="404 Web Site not found"
FINGERPRINTS["ghost.io"]="Used at Ghost"
FINGERPRINTS["fastly.net"]="Fastly error"
FINGERPRINTS["helpjuice.com"]="We could not find what"
FINGERPRINTS["shopify.com"]="Sorry, this shop is currently unavailable"
FINGERPRINTS["statuspage.io"]="You are being redirected"
FINGERPRINTS["surge.sh"]="project not found"
FINGERPRINTS["tumblr.com"]="Whatever you were looking for"
FINGERPRINTS["wordpress.com"]="Do you want to register"
FINGERPRINTS["zendesk.com"]="Help Center Closed"
FINGERPRINTS["readme.io"]="Project doesnt exist"
FINGERPRINTS["fly.io"]="404 Not Found"
FINGERPRINTS["netlify.app"]="Not Found"
FINGERPRINTS["vercel.app"]="404: NOT_FOUND"
FINGERPRINTS["webflow.io"]="The page you are looking for"
FINGERPRINTS["strikingly.com"]="page not found"
FINGERPRINTS["uberflip.com"]="Non-existent domain"
FINGERPRINTS["smugmug.com"]="Page Not Found"
FINGERPRINTS["tilda.cc"]="Please renew your subscription"

info "Checking subdomains for dangling CNAMEs..."

TOTAL=0
VULNERABLE=0

while read -r subdomain; do
  TOTAL=$((TOTAL + 1))

  cname=$(dig CNAME "$subdomain" +short 2>/dev/null | head -1 || true)
  [[ -z "$cname" ]] && continue

  for service in "${!FINGERPRINTS[@]}"; do
    if echo "$cname" | grep -qi "$service"; then
      error_string="${FINGERPRINTS[$service]}"
      response=$(curl -sk "http://$subdomain" \
        --max-time 10 \
        -H "Host: $subdomain" \
        2>/dev/null || true)

      if echo "$response" | grep -qi "$error_string"; then
        crit "POTENTIAL TAKEOVER: $subdomain"
        crit "  CNAME   : $cname"
        crit "  Service : $service"

        echo "VULNERABLE: $subdomain" >> "$TAKEOVER_FILE"
        echo "CNAME: $cname" >> "$TAKEOVER_FILE"
        echo "SERVICE: $service" >> "$TAKEOVER_FILE"
        echo "---" >> "$TAKEOVER_FILE"
        VULNERABLE=$((VULNERABLE + 1))
      fi
    fi
  done

done < "$OUTDIR/subdomains.txt"

ok "Checked $TOTAL subdomains"

# Run subjack if available
if command -v subjack &>/dev/null; then
  info "Running subjack..."
  subjack -w "$OUTDIR/subdomains.txt" \
          -t 20 -timeout 30 \
          -o "$OUTDIR/subjack_results.txt" \
          -ssl 2>/dev/null || true
  ok "subjack done: $(wc -l < "$OUTDIR/subjack_results.txt" 2>/dev/null || echo 0) hits"
fi

# Run nuclei takeover templates if available
if command -v nuclei &>/dev/null; then
  info "Running nuclei takeover templates..."
  nuclei -l "$OUTDIR/subdomains.txt" \
         -t ~/nuclei-templates/takeovers/ \
         -silent -no-color \
         -o "$OUTDIR/nuclei_takeovers.txt" 2>/dev/null || true
  ok "nuclei takeover: $(wc -l < "$OUTDIR/nuclei_takeovers.txt" 2>/dev/null || echo 0) hits"
fi

echo ""
info "TAKEOVER CHECK COMPLETE"
info "Subdomains checked : $TOTAL"
info "Vulnerable found   : $VULNERABLE"
[[ $VULNERABLE -gt 0 ]] && crit "TAKEOVER POSSIBLE — check $TAKEOVER_FILE"
