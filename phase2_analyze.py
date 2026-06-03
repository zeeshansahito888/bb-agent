#!/usr/bin/env python3
import sys, json, re
from pathlib import Path
from openai import OpenAI

OLLAMA_URL = "http://localhost:11434/v1"
MODEL      = "qwen2.5:7b"

client = OpenAI(base_url=OLLAMA_URL, api_key="ollama")

def read_file(path, max_lines=100):
    if not path.exists():
        return ""
    lines = path.read_text(errors="ignore").strip().splitlines()
    if len(lines) > max_lines:
        return "\n".join(lines[:max_lines]) + f"\n... (+{len(lines)-max_lines} more)"
    return "\n".join(lines)

def extract_json(text):
    try:
        return json.loads(text.strip())
    except:
        pass
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
    if label:
        print(f"  [LLM] {label}...")
    r = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.1,
        max_tokens=1500,
    )
    return r.choices[0].message.content.strip()

def analyze_nuclei(nuclei_raw, target):
    if not nuclei_raw.strip():
        return {"confirmed": [], "false_positives": 0, "notes": "No nuclei output"}
    prompt = f"""You are a strict bug bounty validator reviewing nuclei output for {target}.

Nuclei output:
{nuclei_raw}

A finding is VALID only if nuclei matched a vulnerability template with real evidence.
Informational and tech-detection lines are NOT vulnerabilities.

Reply ONLY with JSON:
{{
  "confirmed": [
    {{"template": "...", "url": "...", "severity": "...", "evidence": "one line"}}
  ],
  "false_positives": 0,
  "notes": "one sentence"
}}"""
    raw = ask(prompt, "Analyzing nuclei output")
    return extract_json(raw) or {"confirmed": [], "false_positives": 0, "notes": "Parse error"}

def analyze_idor(idor_raw, target):
    if not idor_raw.strip():
        return {"interesting": [], "notes": "No IDOR candidates"}
    prompt = f"""You are a bug bounty researcher reviewing IDOR candidates for {target}.

URLs with ID parameters:
{idor_raw}

Pick TOP 5 most promising. Prefer numeric IDs, UUID params, /api/ endpoints.

Reply ONLY with JSON:
{{
  "interesting": [
    {{"url": "...", "parameter": "...", "reason": "one line", "test": "change id=X to id=Y"}}
  ],
  "notes": "one sentence"
}}"""
    raw = ask(prompt, "Analyzing IDOR candidates")
    return extract_json(raw) or {"interesting": [], "notes": "Parse error"}

def analyze_api(api_raw, target):
    if not api_raw.strip():
        return {"interesting": [], "notes": "No API endpoints"}
    prompt = f"""You are a bug bounty researcher reviewing API endpoints for {target}.

API endpoints:
{api_raw}

Identify TOP 10 most interesting. Look for user input, admin APIs, file upload, auth endpoints, version numbers.

Reply ONLY with JSON:
{{
  "interesting": [
    {{"endpoint": "...", "reason": "...", "test_for": "IDOR/Auth/XSS/etc"}}
  ],
  "notes": "one sentence"
}}"""
    raw = ask(prompt, "Analyzing API endpoints")
    return extract_json(raw) or {"interesting": [], "notes": "Parse error"}

def analyze_hosts(hosts_raw, target):
    if not hosts_raw.strip():
        return {"priority": [], "notes": "No live hosts"}
    prompt = f"""You are a bug bounty researcher reviewing live hosts for {target}.

Live hosts:
{hosts_raw}

Rank TOP 5 most interesting. Consider admin panels, dev/staging, APIs, old tech, unusual ports.

Reply ONLY with JSON:
{{
  "priority": [
    {{"host": "...", "tech": "...", "why": "one line", "test_first": "what to test"}}
  ],
  "notes": "one sentence"
}}"""
    raw = ask(prompt, "Prioritizing live hosts")
    return extract_json(raw) or {"priority": [], "notes": "Parse error"}

def critic_check(all_findings, target):
    prompt = f"""You are a senior bug bounty triager for {target}.
Review findings and CUT noise. Be skeptical.
A URL with ?id= is NOT a confirmed IDOR — it is just a candidate.

Findings:
{json.dumps(all_findings, indent=2)[:2000]}

Reply ONLY with JSON:
{{
  "validated": [
    {{"type": "...", "url": "...", "severity": "Critical/High/Medium/Low", "confidence": "high/medium/low", "summary": "one line"}}
  ],
  "filtered_count": 0,
  "filter_reason": "brief explanation"
}}"""
    raw = ask(prompt, "Running critic (false-positive filter)")
    return extract_json(raw) or {"validated": [], "filtered_count": 0, "filter_reason": "Parse error"}

def main():
    target  = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    out_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(f"recon/{target}")

    print(f"\n[*] Phase 2 — Analysis")
    print(f"[*] Target  : {target}")
    print(f"[*] Out dir : {out_dir}\n")

    nuclei_raw = read_file(out_dir / "nuclei.txt",           80)
    idor_raw   = read_file(out_dir / "idor-candidates.txt",  50)
    api_raw    = read_file(out_dir / "api-endpoints.txt",    80)
    hosts_raw  = read_file(out_dir / "live-hosts.txt",       50)

    nuclei_result = analyze_nuclei(nuclei_raw, target)
    print(f"  → Nuclei confirmed: {len(nuclei_result.get('confirmed',[]))}")

    idor_result = analyze_idor(idor_raw, target)
    print(f"  → IDOR candidates: {len(idor_result.get('interesting',[]))}")

    api_result = analyze_api(api_raw, target)
    print(f"  → Interesting APIs: {len(api_result.get('interesting',[]))}")

    hosts_result = analyze_hosts(hosts_raw, target)
    print(f"  → Priority hosts: {len(hosts_result.get('priority',[]))}")

    combined = {
        "nuclei": nuclei_result.get("confirmed", []),
        "idor":   idor_result.get("interesting", []),
        "api":    api_result.get("interesting", []),
        "hosts":  hosts_result.get("priority", []),
    }

    print()
    critic_result = critic_check(combined, target)
    print(f"  → Validated: {len(critic_result.get('validated',[]))}, "
          f"filtered: {critic_result.get('filtered_count',0)}")

    analysis = {
        "target":          target,
        "nuclei_analysis": nuclei_result,
        "idor_analysis":   idor_result,
        "api_analysis":    api_result,
        "hosts_analysis":  hosts_result,
        "critic":          critic_result,
    }

    analysis_path = out_dir / "analysis.json"
    analysis_path.write_text(json.dumps(analysis, indent=2))
    print(f"\n[*] Saved: {analysis_path}")

    validated = critic_result.get("validated", [])
    if validated:
        print(f"\n[*] Findings:")
        for f in validated:
            print(f"    [{f.get('severity','?')}] {f.get('type','?')} @ {f.get('url','?')}")
    else:
        print("\n[*] No confirmed findings — check IDOR/API candidates manually")

    print(f"\nNext: python3 recon_ranker.py {target} {out_dir}")

if __name__ == "__main__":
    main()
