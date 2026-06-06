#!/usr/bin/env python3
import sys, json, re
from pathlib import Path
from openai import OpenAI

OLLAMA_URL = "http://localhost:11434/v1"
MODEL      = "qwen2.5:7b"
client     = OpenAI(base_url=OLLAMA_URL, api_key="ollama")

def extract_json(text):
    try: return json.loads(text.strip())
    except: pass
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if m:
        try: return json.loads(m.group(1))
        except: pass
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if m:
        try: return json.loads(m.group(0))
        except: pass
    return None

def ask(prompt, label=""):
    if label: print(f"  [LLM] {label}...")
    r = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.1, max_tokens=1500,
    )
    return r.choices[0].message.content.strip()

def analyze_headers(findings_raw, target):
    prompt = f"""You are a bug bounty researcher reviewing security header findings for {target}.

Raw findings:
{findings_raw[:3000]}

Decide which missing headers are actually reportable on bug bounty programs.

Reportable:
- Missing CSP on pages handling sensitive data = Medium
- Missing HSTS on main domain = Low-Medium
- Server version disclosure = Low-Medium
- X-Frame-Options missing on login/payment pages = Low

NOT reportable on most programs:
- Missing headers on CDN/static asset domains
- Missing Referrer-Policy alone
- Missing Permissions-Policy alone

Reply ONLY with JSON:
{{
  "reportable": [
    {{
      "host": "...",
      "issue": "...",
      "severity": "Medium/Low",
      "reason": "why reportable",
      "affected_pages": "login/payment/admin/etc"
    }}
  ],
  "skip": ["host1", "host2"],
  "skip_reason": "why skipped",
  "notes": "one sentence summary"
}}"""
    raw = ask(prompt, "Analyzing security headers")
    return extract_json(raw) or {"reportable": [], "skip": [], "notes": "Parse error"}

def main():
    target  = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    out_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(f"recon/{target}")

    print(f"\n[*] Headers Analyzer")
    print(f"[*] Target : {target}\n")

    findings_file = out_dir / "headers_findings.txt"
    if not findings_file.exists() or findings_file.stat().st_size == 0:
        print("[!] No header findings — run headers_check.sh first")
        sys.exit(0)

    findings_raw  = findings_file.read_text(errors="ignore")
    host_count    = findings_raw.count("HOST:")
    print(f"[*] Hosts with issues: {host_count}")

    result     = analyze_headers(findings_raw, target)
    reportable = result.get("reportable", [])

    print(f"\n  → Reportable : {len(reportable)}")
    print(f"  → Skipped    : {len(result.get('skip',[]))}")

    out_path = out_dir / "headers_analysis.json"
    out_path.write_text(json.dumps(result, indent=2))

    if reportable:
        print(f"\n  REPORTABLE HEADER ISSUES:")
        for r in reportable:
            print(f"    [{r.get('severity','?')}] {r.get('issue','?')}")
            print(f"    Host : {r.get('host','?')}")
            print(f"    Why  : {r.get('reason','?')}")
            print()

    print(f"[*] Saved : {out_path}")
    print(f"[*] Notes : {result.get('notes','')}")

if __name__ == "__main__":
    main()
