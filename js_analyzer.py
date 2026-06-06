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
        temperature=0.1, max_tokens=1000,
    )
    return r.choices[0].message.content.strip()

def analyze_js_file(content, url, target):
    prompt = f"""You are a security researcher analyzing a JavaScript file from {target}.
Source URL: {url}

JS content:
{content[:3000]}

Look ONLY for real security issues in this actual code above.
Do NOT invent findings. If nothing suspicious return empty lists.

Look for:
1. Hardcoded secrets (API keys, tokens, passwords, AWS keys)
2. Hidden API endpoints not in public docs
3. Internal URLs or IP addresses
4. Debug/admin functionality

Reply ONLY with JSON:
{{
  "secrets": [
    {{"type": "api_key/token/password/aws_key", "value": "first 20 chars only", "line_context": "surrounding code"}}
  ],
  "endpoints": [
    {{"path": "/api/...", "method": "GET/POST", "interesting": "why"}}
  ],
  "other": [
    {{"finding": "...", "severity": "High/Medium/Low", "detail": "..."}}
  ],
  "verdict": "clean/suspicious/critical"
}}"""
    raw = ask(prompt, f"Analyzing {url[-50:]}")
    return extract_json(raw) or {"secrets": [], "endpoints": [], "other": [], "verdict": "parse_error"}

def analyze_grep_findings(grep_raw, target):
    if not grep_raw.strip():
        return {"confirmed": [], "false_positives": 0}
    prompt = f"""You are a security researcher reviewing grep matches from JS files on {target}.

Grep findings:
{grep_raw[:2000]}

For each finding: is this a REAL secret or false positive?
Real: actual API key, real password, valid token format
False positive: example code, placeholder, test value, public key

Reply ONLY with JSON:
{{
  "confirmed": [
    {{"type": "...", "value": "first 15 chars", "url": "...", "severity": "Critical/High/Medium"}}
  ],
  "false_positives": 0
}}"""
    raw = ask(prompt, "Validating grep findings")
    return extract_json(raw) or {"confirmed": [], "false_positives": 0}

def main():
    target  = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    out_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(f"recon/{target}")
    js_dir  = out_dir / "js_files"

    print(f"\n[*] JS Analyzer")
    print(f"[*] Target : {target}\n")

    if not js_dir.exists():
        print("[!] No JS files — run js_secrets.sh first")
        sys.exit(0)

    js_files = list(js_dir.glob("*.js"))
    print(f"[*] JS files: {len(js_files)}")

    url_map = {}
    url_map_file = js_dir / "url_map.txt"
    if url_map_file.exists():
        for line in url_map_file.read_text().splitlines():
            parts = line.split(" ", 1)
            if len(parts) == 2:
                url_map[parts[0]] = parts[1]

    all_findings = {"secrets": [], "endpoints": [], "other": [], "critical_files": []}

    for i, js_file in enumerate(js_files[:15], 1):
        url = url_map.get(js_file.name, js_file.name)
        content = js_file.read_text(errors="ignore")
        if len(content) < 100:
            continue
        print(f"\n  [{i}/{min(len(js_files),15)}] {url[-60:]}")
        result = analyze_js_file(content, url, target)
        verdict = result.get("verdict", "clean")
        print(f"  → {verdict} | secrets: {len(result.get('secrets',[]))} | endpoints: {len(result.get('endpoints',[]))}")
        for s in result.get("secrets", []):
            s["source_url"] = url
            all_findings["secrets"].append(s)
        for e in result.get("endpoints", []):
            e["source_url"] = url
            all_findings["endpoints"].append(e)
        for o in result.get("other", []):
            o["source_url"] = url
            all_findings["other"].append(o)
        if verdict == "critical":
            all_findings["critical_files"].append(url)

    print()
    grep_file = out_dir / "js_grep_findings.txt"
    if grep_file.exists() and grep_file.stat().st_size > 0:
        grep_result = analyze_grep_findings(grep_file.read_text(errors="ignore"), target)
        confirmed = grep_result.get("confirmed", [])
        print(f"  → Grep confirmed: {len(confirmed)} real secrets")
        all_findings["secrets"].extend(confirmed)
    else:
        print("  → No grep findings")

    results_path = out_dir / "js_findings.json"
    results_path.write_text(json.dumps(all_findings, indent=2))

    print(f"\n{'='*50}")
    print(f"JS ANALYSIS COMPLETE")
    print(f"  Secrets   : {len(all_findings['secrets'])}")
    print(f"  Endpoints : {len(all_findings['endpoints'])}")
    print(f"  Other     : {len(all_findings['other'])}")
    print(f"  Saved     : {results_path}")

    if all_findings["secrets"]:
        print(f"\n  SECRETS:")
        for s in all_findings["secrets"][:5]:
            print(f"    [{s.get('severity','?')}] {s.get('type','?')}: {s.get('value','?')}")
            print(f"    From: {s.get('source_url','?')[-60:]}")

if __name__ == "__main__":
    main()
