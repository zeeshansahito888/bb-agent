#!/usr/bin/env bash
TARGET="${1:-}"
OUTDIR="${2:-recon/$TARGET}"

if [[ -z "$TARGET" ]]; then
  echo "Usage: $0 <domain> <recon_dir>"
  exit 1
fi

echo "[*] Running nuclei CVE-specific scan..."
if [[ -d ~/nuclei-templates/cves ]]; then
  nuclei -l "$OUTDIR/live-urls.txt" \
         -t ~/nuclei-templates/cves/ \
         -silent -no-color \
         -o "$OUTDIR/nuclei_cves.txt" 2>/dev/null || true
  echo "[OK] CVE findings: $(wc -l < "$OUTDIR/nuclei_cves.txt")"
else
  touch "$OUTDIR/nuclei_cves.txt"
  echo "[WARN] ~/nuclei-templates/cves/ not found — run: nuclei -update-templates"
fi
