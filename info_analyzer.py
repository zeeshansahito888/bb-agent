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

def analyze_responses(responses_raw, target):
    prompt = f"""You are a bug bounty researcher reviewing HTTP responses from {target} for information disclosure.

Responses:
{responses_raw[:3000]}

Look for REAL sensitive information disclosure only:
- Stack traces with file paths and line numbers
- Database errors (SQL errors, table names)
- Framework version numbers
- Internal IP addresses
- API keys, tokens, passwords in responses
- .env file contents
- .git/config with repo URLs
- Debug endpoints exposing config
- Cloud metadata or credentials

Only flag REAL findings from the actual responses above.
Do NOT invent findings.

Reply ONLY with JSON:
{{
  "findings": [
    {{
      "url": "...",
      "type": "stack_trace/env_file/git_config/version_disclosure/api_key/etc",
      "severity": "Critical/High/Medium/Low",
      "evidence": "exact sensitive data found (first 100 chars)",
      "reportable": true,
      "reason": "why reportable"
    }}
  ],
  "critical_count": 0,
  "notes": "one sentence summary"
}}"""
    raw = ask(prompt, "Analyzing info disclosure responses")
    return extract_json(raw) or {"findings": [], "critical_count": 0, "notes": "Parse error"}

def main():
    target  = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    out_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(f"recon/{target}")

    print(f"\n[*] Info Disclosure Analyzer")
    print(f"[*] Target : {target}\n")

    responses_file = out_dir / "info_responses.txt"
    if not responses_file.exists() or responses_file.stat().st_size == 0:
        print("[!] No responses — run info_disclose.sh first")
        sys.exit(0)

    responses_raw = responses_file.read_text(errors="ignore")
    hit_count     = responses_raw.count("=== URL:")
    print(f"[*] Interesting responses: {hit_count}")

    if hit_count == 0:
        print("[*] Target looks clean")
        sys.exit(0)

    result     = analyze_responses(responses_raw, target)
    findings   = result.get("findings", [])
    reportable = [f for f in findings if f.get("reportable")]

    print(f"\n  → Total findings : {len(findings)}")
    print(f"  → Reportable     : {len(reportable)}")
    print(f"  → Critical       : {result.get('critical_count',0)}")

    out_path = out_dir / "info_analysis.json"
    out_path.write_text(json.dumps(result, indent=2))

    if reportable:
        print(f"\n  REPORTABLE INFO DISCLOSURE:")
        for f in reportable:
            print(f"    [{f.get('severity','?')}] {f.get('type','?')}")
            print(f"    URL      : {f.get('url','?')}")
            print(f"    Evidence : {f.get('evidence','?')[:80]}")
            print(f"    Why      : {f.get('reason','?')}")
            print()

    print(f"[*] Saved : {out_path}")
    print(f"[*] Notes : {result.get('notes','')}")

if __name__ == "__main__":
    main()
