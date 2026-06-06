#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-}"
OUTDIR="${2:-recon/$TARGET}"

if [[ -z "$TARGET" ]]; then
  echo "Usage: $0 <domain> <recon_dir>"
  exit 1
fi

JS_DIR="$OUTDIR/js_files"
mkdir -p "$JS_DIR"

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[0;33m'
BLU='\033[0;34m'; BLD='\033[1m'; RST='\033[0m'

ts()   { date '+%H:%M:%S'; }
info() { echo -e "[$(ts)] ${BLU}[JS]${RST}  $*"; }
ok()   { echo -e "[$(ts)] ${GRN}[OK]${RST}  $*"; }
warn() { echo -e "[$(ts)] ${YLW}[SKIP]${RST} $*"; }

info "=== JS SECRET FINDER ==="
info "Target  : $TARGET"
info "JS dir  : $JS_DIR"

info "Collecting JS URLs from recon..."
touch "$OUTDIR/js_urls.txt"

if [[ -f "$OUTDIR/urls.txt" ]]; then
  grep -iE "\.js(\?|$)" "$OUTDIR/urls.txt" \
    | grep -v "\.json" \
    | sort -u >> "$OUTDIR/js_urls.txt" || true
fi

if [[ -f "$OUTDIR/live-urls.txt" ]]; then
  while read -r url; do
    curl -sk "$url" --max-time 5 2>/dev/null \
      | grep -oiE 'src="[^"]+\.js[^"]*"' \
      | grep -oiE '"[^"]+"' \
      | tr -d '"' \
      | while read -r js; do
          if [[ "$js" == http* ]]; then echo "$js"
          else echo "${url%/}/$js"
          fi
        done
  done < <(head -20 "$OUTDIR/live-urls.txt") >> "$OUTDIR/js_urls.txt" 2>/dev/null || true
fi

sort -u "$OUTDIR/js_urls.txt" -o "$OUTDIR/js_urls.txt"
JS_COUNT=$(wc -l < "$OUTDIR/js_urls.txt")
ok "Found $JS_COUNT JS URLs"

if [[ $JS_COUNT -eq 0 ]]; then
  warn "No JS files found — skipping"
  exit 0
fi

info "Downloading JS files (max 30)..."
DOWNLOADED=0
while read -r url && [[ $DOWNLOADED -lt 30 ]]; do
  filename=$(echo "$url" | md5sum | cut -c1-8).js
  outfile="$JS_DIR/$filename"
  echo "$filename $url" >> "$JS_DIR/url_map.txt"
  curl -sk "$url" --max-time 10 -H "User-Agent: Mozilla/5.0" -o "$outfile" 2>/dev/null || true
  if [[ -s "$outfile" ]]; then
    DOWNLOADED=$((DOWNLOADED + 1))
  else
    rm -f "$outfile"
  fi
done < "$OUTDIR/js_urls.txt"
ok "Downloaded $DOWNLOADED JS files"

info "Quick grep scan for obvious secrets..."
touch "$OUTDIR/js_grep_findings.txt"

PATTERNS=(
  "api[_-]?key\s*[:=]\s*['\"][a-zA-Z0-9]{16,}"
  "secret\s*[:=]\s*['\"][a-zA-Z0-9]{16,}"
  "password\s*[:=]\s*['\"][^'\"]{8,}"
  "token\s*[:=]\s*['\"][a-zA-Z0-9._-]{16,}"
  "AKIA[0-9A-Z]{16}"
  "AIza[0-9A-Za-z_-]{35}"
  "sk-[a-zA-Z0-9]{32,}"
  "ghp_[a-zA-Z0-9]{36}"
  "xox[baprs]-[0-9a-zA-Z]+"
  "-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----"
  "mongodb(\+srv)?://[^'\"\\s]+"
  "postgres://[^'\"\\s]+"
  "mysql://[^'\"\\s]+"
  "redis://[^'\"\\s]+"
  "https?://[^'\"\\s]+@[^'\"\\s]+"
)

for js_file in "$JS_DIR"/*.js; do
  [[ -f "$js_file" ]] || continue
  filename=$(basename "$js_file")
  url=$(grep "^$filename " "$JS_DIR/url_map.txt" 2>/dev/null | awk '{print $2}' || echo "unknown")
  for pattern in "${PATTERNS[@]}"; do
    matches=$(grep -oiE "$pattern" "$js_file" 2>/dev/null | head -3 || true)
    if [[ -n "$matches" ]]; then
      echo "FILE: $url" >> "$OUTDIR/js_grep_findings.txt"
      echo "PATTERN: $pattern" >> "$OUTDIR/js_grep_findings.txt"
      echo "MATCH: $matches" >> "$OUTDIR/js_grep_findings.txt"
      echo "---" >> "$OUTDIR/js_grep_findings.txt"
    fi
  done
done

GREP_COUNT=$(grep -c "^FILE:" "$OUTDIR/js_grep_findings.txt" 2>/dev/null || echo 0)
ok "Grep found $GREP_COUNT potential secrets"

info "Extracting API endpoints from JS..."
touch "$OUTDIR/js_endpoints.txt"
for js_file in "$JS_DIR"/*.js; do
  [[ -f "$js_file" ]] || continue
  grep -oiE '["'"'"'`](/api/[^"'"'"'`\s]{3,}|/v[0-9]+/[^"'"'"'`\s]{3,})["'"'"'`]' \
    "$js_file" 2>/dev/null | tr -d '"'"'"'`' | sort -u >> "$OUTDIR/js_endpoints.txt" || true
done
sort -u "$OUTDIR/js_endpoints.txt" -o "$OUTDIR/js_endpoints.txt"
EP_COUNT=$(wc -l < "$OUTDIR/js_endpoints.txt")
ok "Found $EP_COUNT API endpoints in JS files"

echo ""
info "JS SCAN COMPLETE"
info "JS files: $DOWNLOADED | Secrets: $GREP_COUNT | Endpoints: $EP_COUNT"
info "Next: python3 js_analyzer.py $TARGET $OUTDIR"
