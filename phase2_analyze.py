#!/usr/bin/env python3
import sys, json, re
from pathlib import Path
from openai import OpenAI

OLLAMA_URL = "http://localhost:11434/v1"
MODEL      = "qwen2.5:7b"

client = OpenAI(base_url=OLLAMA_URL, api_key="ollama")

SKILLS_DIR = Path(__file__).parent / "skills"

def load_skill(skill_path: str, max_lines: int = 150) -> str:
    path = SKILLS_DIR / skill_path
    if not path.exists():
        return ""
    lines = path.read_text(errors="ignore").strip().splitlines()
    # Skip frontmatter
    start = 0
    if lines and lines[0] == "---":
        for i, l in enumerate(lines[1:], 1):
            if l == "---":
                start = i + 1
                break
    lines = lines[start:]
    if len(lines) > max_lines:
        lines = lines[:max_lines]
    return "\n".join(lines)

def read_file(path, max_lines=100):
    if not Path(path).exists():
        return ""
    lines = Path(path).read_text(errors="ignore").strip().splitlines()
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

    vuln_ref = load_skill("web2-vuln-classes/SKILL.md", max_lines=80)

    prompt = f"""You are a strict bug bounty validator reviewing nuclei output for {target}.

Vuln class reference:
{vuln_ref}

Nuclei output:
{nuclei_raw}

A finding is VALID only if nuclei matched a real vulnerability template with evidence.
Informational and tech-detection lines are NOT vulnerabilities.

Reply ONLY with JSON:
{{
  "confirmed": [
    {{"template": "...", "url": "...", "severity": "...", "evidence": "one line", "vuln_class": "..."}}
  ],
  "false_positives": 0,
  "notes": "one sentence"
}}"""
    raw = ask(prompt, "Analyzing nuclei output")
    return extract_json(raw) or {"confirmed": [], "false_positives": 0, "notes": "Parse error"}

def analyze_idor(idor_raw, target):
    if not idor_raw.strip():
        return {"interesting": [], "notes": "No IDOR candidates"}

    idor_ref = load_skill("web2-vuln-classes/SKILL.md", max_lines=60)

    prompt = f"""You are a bug bounty researcher reviewing IDOR candidates for {target}.

IDOR methodology reference:
{idor_ref}

URLs with ID parameters:
{idor_raw}

Apply the IDOR testing checklist from the reference.
Pick TOP 5 most promising. Prefer:
- Numeric IDs in API endpoints
- UUID parameters
- /api/v1/ endpoints (check if /v2/ has auth that /v1/ lacks)
- GraphQL node queries
- WebSocket messages with client-supplied IDs

Reply ONLY with JSON:
{{
  "interesting": [
    {{
      "url": "...",
      "parameter": "...",
      "idor_variant": "V1/V2/V3/etc",
      "reason": "one line",
      "test": "exact test to perform",
      "chain_potential": "IDOR+Read/IDOR+Write/IDOR+Admin"
    }}
  ],
  "notes": "one sentence"
}}"""
    raw = ask(prompt, "Analyzing IDOR candidates")
    return extract_json(raw) or {"interesting": [], "notes": "Parse error"}

def analyze_api(api_raw, target):
    if not api_raw.strip():
        return {"interesting": [], "notes": "No API endpoints"}

    vuln_ref = load_skill("web2-vuln-classes/SKILL.md", max_lines=60)

    prompt = f"""You are a bug bounty researcher reviewing API endpoints for {target}.

Vuln reference (focus on mass assignment, JWT, CORS, auth bypass):
{vuln_ref}

API endpoints:
{api_raw}

Apply the sibling rule: if 9 endpoints have auth, the 10th probably doesn't.
Look for: admin endpoints, export endpoints, delete endpoints missing auth.

Reply ONLY with JSON:
{{
  "interesting": [
    {{
      "endpoint": "...",
      "reason": "...",
      "test_for": "IDOR/Auth/XSS/SQLi/Mass-Assignment/etc",
      "sibling_rule": true/false,
      "priority": "P1/P2"
    }}
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

Rank TOP 5 most interesting. Consider:
- Admin panels (P1 if unauthed, P2 if authed)
- Dev/staging environments (less hardened)
- APIs with version numbers
- Non-standard ports (8080, 3000, 9200, 8443)
- Old tech stacks

Reply ONLY with JSON:
{{
  "priority": [
    {{"host": "...", "tech": "...", "why": "one line", "test_first": "what to test", "auth_required": true/false}}
  ],
  "notes": "one sentence"
}}"""
    raw = ask(prompt, "Prioritizing live hosts")
    return extract_json(raw) or {"priority": [], "notes": "Parse error"}

def analyze_ssrf(ssrf_raw, target):
    if not ssrf_raw.strip():
        return {"interesting": [], "notes": "No SSRF candidates"}

    prompt = f"""You are a bug bounty researcher reviewing SSRF candidates for {target}.

URLs with URL/redirect parameters:
{ssrf_raw}

Pick TOP 3 most promising SSRF candidates.
SSRF is valuable if it can reach: cloud metadata (169.254.169.254), internal services, or exfil data.

Reply ONLY with JSON:
{{
  "interesting": [
    {{"url": "...", "parameter": "...", "test": "try http://169.254.169.254/latest/meta-data/", "reason": "..."}}
  ],
  "notes": "one sentence"
}}"""
    raw = ask(prompt, "Analyzing SSRF candidates")
    return extract_json(raw) or {"interesting": [], "notes": "Parse error"}

def critic_check(all_findings, target):
    report_ref = load_skill("triage-validation/SKILL.md", max_lines=60)

    prompt = f"""You are a senior bug bounty triager for {target}.
Review findings and CUT noise. Be skeptical.

Triage reference:
{report_ref}

Rules:
- A URL with ?id= is NOT a confirmed IDOR — just a candidate
- Only keep findings with real concrete evidence
- Rate each by confidence

Findings:
{json.dumps(all_findings, indent=2)[:2000]}

Reply ONLY with JSON:
{{
  "validated": [
    {{
      "type": "...",
      "url": "...",
      "severity": "Critical/High/Medium/Low",
      "confidence": "high/medium/low",
      "summary": "one line",
      "needs_manual_verify": true/false
    }}
  ],
  "filtered_count": 0,
  "filter_reason": "brief explanation"
}}"""
    raw = ask(prompt, "Running critic (false-positive filter)")
    return extract_json(raw) or {"validated": [], "filtered_count": 0, "filter_reason": "Parse error"}

def main():
    target  = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    out_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(f"recon/{target}")

    print(f"\n[*] Phase 2 — Analysis (with skill files)")
    print(f"[*] Target  : {target}")
    print(f"[*] Out dir : {out_dir}")

    # Check skills loaded
    vuln_skill = load_skill("web2-vuln-classes/SKILL.md", 10)
    print(f"[*] Skills  : {'loaded' if vuln_skill else 'NOT FOUND — run from ~/bb-agent/'}\n")

    nuclei_raw = read_file(out_dir / "nuclei.txt",           80)
    idor_raw   = read_file(out_dir / "idor-candidates.txt",  50)
    api_raw    = read_file(out_dir / "api-endpoints.txt",    80)
    hosts_raw  = read_file(out_dir / "live-hosts.txt",       50)
    ssrf_raw   = read_file(out_dir / "ssrf-candidates.txt",  30)

    nuclei_result = analyze_nuclei(nuclei_raw, target)
    print(f"  → Nuclei confirmed: {len(nuclei_result.get('confirmed',[]))}")

    idor_result = analyze_idor(idor_raw, target)
    print(f"  → IDOR candidates: {len(idor_result.get('interesting',[]))}")

    api_result = analyze_api(api_raw, target)
    print(f"  → Interesting APIs: {len(api_result.get('interesting',[]))}")

    hosts_result = analyze_hosts(hosts_raw, target)
    print(f"  → Priority hosts: {len(hosts_result.get('priority',[]))}")

    ssrf_result = analyze_ssrf(ssrf_raw, target)
    print(f"  → SSRF candidates: {len(ssrf_result.get('interesting',[]))}")

    combined = {
        "nuclei": nuclei_result.get("confirmed", []),
        "idor":   idor_result.get("interesting", []),
        "api":    api_result.get("interesting", []),
        "hosts":  hosts_result.get("priority", []),
        "ssrf":   ssrf_result.get("interesting", []),
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
        "ssrf_analysis":   ssrf_result,
        "critic":          critic_result,
    }

    analysis_path = out_dir / "analysis.json"
    analysis_path.write_text(json.dumps(analysis, indent=2))
    print(f"\n[*] Saved: {analysis_path}")

    validated = critic_result.get("validated", [])
    if validated:
        print(f"\n[*] Findings:")
        for f in validated:
            manual = " ⚠ verify manually" if f.get("needs_manual_verify") else ""
            print(f"    [{f.get('severity','?')}] {f.get('type','?')} @ {f.get('url','?')}{manual}")
    else:
        print("\n[*] No confirmed findings — check IDOR/API candidates manually")

    print(f"\nNext: python3 recon_ranker.py {target} {out_dir}")

if __name__ == "__main__":
    main()
