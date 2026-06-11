#!/usr/bin/env python3
import sys, json, re
from pathlib import Path
from openai import OpenAI

OLLAMA_URL = "http://localhost:11434/v1"
MODEL      = "qwen2.5:7b"

client = OpenAI(base_url=OLLAMA_URL, api_key="ollama")

SKILLS_DIR = Path(__file__).parent / "skills"

def load_skill(skill_path, max_lines=60):
    path = SKILLS_DIR / skill_path
    if not path.exists(): return ""
    lines = path.read_text(errors="ignore").strip().splitlines()
    start = 0
    if lines and lines[0] == "---":
        for i, l in enumerate(lines[1:], 1):
            if l == "---": start = i + 1; break
    return "\n".join(lines[start:start+max_lines])

def read_file(path, max_lines=100):
    if not Path(path).exists(): return ""
    lines = Path(path).read_text(errors="ignore").strip().splitlines()
    if len(lines) > max_lines:
        return "\n".join(lines[:max_lines]) + f"\n... (+{len(lines)-max_lines} more)"
    return "\n".join(lines)

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

def analyze_nuclei(nuclei_raw, nuclei_cves, nuclei_oob, target):
    combined = "\n".join(filter(None, [nuclei_raw, nuclei_cves, nuclei_oob]))
    if not combined.strip():
        return {"confirmed": [], "false_positives": 0, "notes": "No nuclei output"}
    prompt = f"""You are a strict bug bounty validator reviewing nuclei output for {target}.

Nuclei output:
{combined[:2000]}

VALID: real vulnerability template matches with evidence
INVALID: tech detection, informational, missing headers

Reply ONLY with JSON:
{{
  "confirmed": [
    {{"template": "...", "url": "...", "severity": "...", "evidence": "one line", "oob": true}}
  ],
  "false_positives": 0,
  "notes": "one sentence"
}}"""
    raw = ask(prompt, "Analyzing nuclei output")
    return extract_json(raw) or {"confirmed": [], "false_positives": 0, "notes": "Parse error"}

def analyze_sqli_results(sqli_raw, target):
    if not sqli_raw.strip():
        return {"confirmed": [], "candidates": [], "notes": "No SQLi fuzzer output"}
    confirmed = []
    candidates = []
    for line in sqli_raw.splitlines():
        line = line.strip()
        if line.startswith("SQLI_TIME:"):
            parts = line.replace("SQLI_TIME:", "").strip()
            url_match    = re.search(r"(https?://[^\s|]+)", parts)
            param_match  = re.search(r"param=([^\s|]+)", parts)
            elapsed_match= re.search(r"elapsed=([^\s|]+)", parts)
            confirmed.append({
                "type": "time-based SQLi",
                "url": url_match.group(1) if url_match else parts,
                "parameter": param_match.group(1) if param_match else "unknown",
                "evidence": f"Response delayed {elapsed_match.group(1) if elapsed_match else '5000ms+'} — SLEEP() executed",
                "severity": "High",
                "fuzzer_confirmed": True
            })
        elif line.startswith("SQLI_ERROR:"):
            parts = line.replace("SQLI_ERROR:", "").strip()
            url_match   = re.search(r"(https?://[^\s|]+)", parts)
            param_match = re.search(r"param=([^\s|]+)", parts)
            candidates.append({
                "type": "error-based SQLi candidate",
                "url": url_match.group(1) if url_match else parts,
                "parameter": param_match.group(1) if param_match else "unknown",
                "evidence": "SQL error string in response",
                "severity": "High",
                "fuzzer_confirmed": False,
                "needs_manual_verify": True
            })
    return {
        "confirmed": confirmed,
        "candidates": candidates,
        "notes": f"{len(confirmed)} time-based confirmed, {len(candidates)} error candidates"
    }

def analyze_ssrf_results(ssrf_raw, target):
    if not ssrf_raw.strip():
        return {"tested": [], "notes": "No SSRF fuzzer output"}
    tested = []
    for line in ssrf_raw.splitlines():
        if line.startswith("TESTED:"):
            parts = line.replace("TESTED:", "").strip()
            url_match    = re.search(r"(https?://[^\s\[]+)", parts)
            param_match  = re.search(r"param=([^\s\]]+)", parts)
            status_match = re.search(r"status=(\d+)", parts)
            if url_match:
                tested.append({
                    "url": url_match.group(1),
                    "parameter": param_match.group(1) if param_match else "unknown",
                    "status": status_match.group(1) if status_match else "unknown",
                    "note": "Check OOB collaborator for DNS/HTTP hit to confirm"
                })
    return {
        "tested": tested[:10],
        "notes": f"{len(tested)} URLs tested — check Burp Collaborator/interactsh for OOB hits"
    }

def analyze_xss(xss_raw, target):
    if not xss_raw.strip():
        return {"confirmed": [], "notes": "No XSS fuzzer output"}
    confirmed = []
    for line in xss_raw.splitlines():
        if line.startswith("XSS_REFLECTED:"):
            parts = line.replace("XSS_REFLECTED:", "").strip()
            url_match     = re.search(r"(https?://[^\s|]+)", parts)
            param_match   = re.search(r"param=([^\s|]+)", parts)
            payload_match = re.search(r"payload=(.+)", parts)
            confirmed.append({
                "type": "Reflected XSS",
                "url": url_match.group(1) if url_match else parts,
                "parameter": param_match.group(1) if param_match else "unknown",
                "payload": payload_match.group(1) if payload_match else "unknown",
                "severity": "High",
                "fuzzer_confirmed": True,
                "needs_manual_verify": True
            })
    return {
        "confirmed": confirmed,
        "notes": f"{len(confirmed)} reflected XSS hits — verify in browser"
    }

def analyze_api(api_raw, target):
    if not api_raw.strip():
        return {"interesting": [], "notes": "No API endpoints"}
    prompt = f"""You are a bug bounty researcher reviewing API endpoints for {target}.

API endpoints:
{api_raw[:1500]}

Apply sibling rule: if /api/admin/users has auth, /api/admin/export probably doesn't.
Look for: admin, export, delete, file upload, auth endpoints, old versions.
Only URL containing {target} domain.

Reply ONLY with JSON:
{{
  "interesting": [
    {{"endpoint": "...", "reason": "...", "test_for": "...", "priority": "P1/P2"}}
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
{hosts_raw[:1500]}

Rank TOP 5. Consider: admin panels, dev/staging, APIs, old tech, non-standard ports.
Only include hosts containing {target} domain.

Reply ONLY with JSON:
{{
  "priority": [
    {{"host": "...", "tech": "...", "why": "...", "test_first": "..."}}
  ],
  "notes": "one sentence"
}}"""
    raw = ask(prompt, "Prioritizing live hosts")
    return extract_json(raw) or {"priority": [], "notes": "Parse error"}

def critic_check(all_findings, target):
    triage_ref = load_skill("triage-validation/SKILL.md", max_lines=60)
    prompt = f"""You are a senior bug bounty triager for {target}.

Triage reference:
{triage_ref}

STRICT RULES:
- fuzzer_confirmed: true  → keep if High/Critical
- fuzzer_confirmed: false → only keep with very strong evidence
- REPORT: Critical (RCE, SQLi+data, ATO), High (confirmed SSRF OOB, confirmed XSS, time-based SQLi)
- SKIP: IDOR, missing headers, directory listing, unconfirmed anything, info disclosure without credentials

Findings:
{json.dumps(all_findings, indent=2)[:2500]}

Reply ONLY with JSON:
{{
  "validated": [
    {{
      "type": "...",
      "url": "...",
      "severity": "Critical/High",
      "confidence": "high/medium/low",
      "fuzzer_confirmed": true/false,
      "summary": "one line",
      "needs_manual_verify": true/false
    }}
  ],
  "filtered_count": 0,
  "filter_reason": "brief explanation"
}}"""
    raw = ask(prompt, "Running critic (false-positive filter)")
    return extract_json(raw) or {"validated": [], "filtered_count": 0, "filter_reason": "Parse error"}

def widen_gf_patterns(out_dir, target):
    urls_file = out_dir / "urls.txt"
    if not urls_file.exists(): return
    urls = urls_file.read_text(errors="ignore").splitlines()
    total = len(urls)

    idor_file = out_dir / "idor-candidates.txt"
    ssrf_file = out_dir / "ssrf-candidates.txt"
    idor_count = len(open(idor_file, errors="ignore").readlines()) if idor_file.exists() else 0
    ssrf_count = len(open(ssrf_file, errors="ignore").readlines()) if ssrf_file.exists() else 0

    if idor_count < 5 and total > 100:
        print(f"  [GREP] Widening IDOR patterns ({idor_count} found, {total} URLs)...")
        wider = [u for u in urls if re.search(
            r"[?&](id|uid|user|account|profile|order|invoice|ticket|item|doc|file|"
            r"record|object|uuid|guid|key|ref|token|member|customer|client|pid|rid|eid)[\[=]",
            u, re.I
        )]
        with open(idor_file, "a") as f:
            for u in wider[:200]: f.write(u + "\n")
        print(f"  [GREP] Added {len(wider)} IDOR candidates")

    if ssrf_count < 3 and total > 100:
        print(f"  [GREP] Widening SSRF patterns ({ssrf_count} found)...")
        wider = [u for u in urls if re.search(
            r"[?&](url|uri|path|dest|destination|redirect|next|return|returnurl|callback|"
            r"src|source|target|host|domain|endpoint|api|feed|fetch|load|proxy|request|"
            r"site|link|ref|image|img|pdf|download|file|open|window|data|service|server)=",
            u, re.I
        )]
        with open(ssrf_file, "a") as f:
            for u in wider[:100]: f.write(u + "\n")
        print(f"  [GREP] Added {len(wider)} SSRF candidates")

def main():
    target  = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    out_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(f"recon/{target}")

    print(f"\n[*] Phase 2 — Analysis")
    print(f"[*] Target  : {target}")
    print(f"[*] Out dir : {out_dir}")
    skill_check = load_skill("triage-validation/SKILL.md", 5)
    print(f"[*] Skills  : {'loaded' if skill_check else 'not found'}\n")

    # Widen gf patterns if needed
    widen_gf_patterns(out_dir, target)

    # Load all inputs
    nuclei_raw  = read_file(out_dir / "nuclei.txt",               80)
    nuclei_cves = read_file(out_dir / "nuclei_cves.txt",          80)
    nuclei_oob  = read_file(out_dir / "nuclei_oob.txt",           40)
    api_raw     = read_file(out_dir / "api-endpoints.txt",        80)
    hosts_raw   = read_file(out_dir / "live-hosts.txt",           50)
    sqli_raw    = read_file(out_dir / "sqli_fuzzer_findings.txt", 200)
    ssrf_raw    = read_file(out_dir / "ssrf_fuzzer_findings.txt", 200)
    xss_raw     = read_file(out_dir / "xss_fuzzer_findings.txt",  200)

    # Run analysis
    nuclei_result = analyze_nuclei(nuclei_raw, nuclei_cves, nuclei_oob, target)
    print(f"  → Nuclei confirmed  : {len(nuclei_result.get('confirmed',[]))}")

    sqli_result = analyze_sqli_results(sqli_raw, target)
    print(f"  → SQLi confirmed    : {len(sqli_result.get('confirmed',[]))} time-based, "
          f"{len(sqli_result.get('candidates',[]))} error candidates")

    ssrf_result = analyze_ssrf_results(ssrf_raw, target)
    print(f"  → SSRF tested       : {len(ssrf_result.get('tested',[]))} URLs")

    xss_result = analyze_xss(xss_raw, target)
    print(f"  → XSS reflected     : {len(xss_result.get('confirmed',[]))}")

    api_result = analyze_api(api_raw, target)
    print(f"  → Interesting APIs  : {len(api_result.get('interesting',[]))}")

    hosts_result = analyze_hosts(hosts_raw, target)
    print(f"  → Priority hosts    : {len(hosts_result.get('priority',[]))}")

    # Critic pass
    combined = {
        "nuclei":          nuclei_result.get("confirmed", []),
        "sqli_confirmed":  sqli_result.get("confirmed", []),
        "sqli_candidates": sqli_result.get("candidates", []),
        "ssrf_tested":     ssrf_result.get("tested", []),
        "xss_confirmed":   xss_result.get("confirmed", []),
        "api":             api_result.get("interesting", []),
        "hosts":           hosts_result.get("priority", []),
    }

    print()
    critic_result = critic_check(combined, target)
    validated = critic_result.get("validated", [])
    print(f"  → Validated         : {len(validated)}")
    print(f"  → Filtered          : {critic_result.get('filtered_count',0)}")
    print(f"  → Reason            : {critic_result.get('filter_reason','')}")

    analysis = {
        "target":          target,
        "nuclei_analysis": nuclei_result,
        "sqli_analysis":   sqli_result,
        "ssrf_analysis":   ssrf_result,
        "xss_analysis":    xss_result,
        "api_analysis":    api_result,
        "hosts_analysis":  hosts_result,
        "critic":          critic_result,
    }

    analysis_path = out_dir / "analysis.json"
    analysis_path.write_text(json.dumps(analysis, indent=2))
    print(f"\n[*] Saved: {analysis_path}")

    if validated:
        print(f"\n[*] Findings to report:")
        for f in validated:
            tag = " [FUZZER CONFIRMED]" if f.get("fuzzer_confirmed") else " ⚠ verify manually"
            print(f"    [{f.get('severity','?')}] {f.get('type','?')} @ {f.get('url','?')}{tag}")
    else:
        print("\n[*] No confirmed findings — check SSRF OOB manually")

    print(f"\nNext: python3 recon_ranker.py {target} {out_dir}")

if __name__ == "__main__":
    main()
