#!/usr/bin/env python3
"""
Phase 2 — Qwen 2.5 7B Analysis
Reads bash recon output, filters false positives, flags real findings.

Usage: python3 phase2_analyze.py <domain> [out_dir]
"""

import sys, json, re, os
from pathlib import Path
from openai import OpenAI

# ── Config ────────────────────────────────────────────────────────
OLLAMA_URL = "http://localhost:11434/v1"
MODEL      = "qwen2.5:7b"
MAX_TOKENS = 1500

client = OpenAI(base_url=OLLAMA_URL, api_key="ollama")


# ── Helpers ───────────────────────────────────────────────────────
def read_file(path: Path, max_lines: int = 100) -> str:
    if not path.exists():
        return ""
    lines = path.read_text(errors="ignore").strip().splitlines()
    if len(lines) > max_lines:
        return "\n".join(lines[:max_lines]) + f"\n... (+{len(lines)-max_lines} more lines)"
    return "\n".join(lines)


def extract_json(text: str) -> dict | None:
    # Try direct
    try:
        return json.loads(text.strip())
    except Exception:
        pass
    # Try markdown block
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1))
        except Exception:
            pass
    # Try first { }
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except Exception:
            pass
    return None


def ask(prompt: str, label: str = "") -> str:
    if label:
        print(f"  [LLM] {label}...")
    r = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.1,
        max_tokens=MAX_TOKENS,
    )
    return r.choices[0].message.content.strip()


# ── Analysis tasks ────────────────────────────────────────────────

def analyze_nuclei(nuclei_raw: str, target: str) -> dict:
    if not nuclei_raw.strip():
        return {"confirmed": [], "false_positives": 0, "notes": "No nuclei output"}

    prompt = f"""You are a strict bug bounty validator reviewing nuclei scan output for {target}.

Nuclei output:
{nuclei_raw}

Rules:
- A finding is VALID only if nuclei explicitly matched a template with evidence
- Informational findings are NOT vulnerabilities
- Generic "tech detected" lines are NOT vulnerabilities

Reply ONLY with this JSON (no prose, no markdown):
{{
  "confirmed": [
    {{"template": "...", "url": "...", "severity": "...", "evidence": "one line summary"}}
  ],
  "false_positives": <integer count of items you filtered out>,
  "notes": "one sentence summary"
}}"""

    raw = ask(prompt, "Analyzing nuclei output")
    result = extract_json(raw)
    if not result:
        return {"confirmed": [], "false_positives": 0, "notes": "Parse error", "raw": raw}
    return result


def analyze_urls(gau_raw: str, katana_raw: str, target: str) -> dict:
    combined = gau_raw + "\n" + katana_raw
    if not combined.strip():
        return {"interesting": [], "notes": "No URLs collected"}

    prompt = f"""You are a bug bounty researcher reviewing discovered URLs for {target}.

URLs found:
{combined[:2000]}

Identify URLs that are worth manually testing. Look for:
- API endpoints (/api/, /v1/, /graphql, /rest/)
- Admin or internal paths (/admin, /dashboard, /internal, /debug)
- File upload or export endpoints
- Auth-related endpoints (/login, /oauth, /token, /reset)
- ID parameters suggesting IDOR (?id=, ?user=, ?order=)
- Backup or config files (.env, .bak, .config, .sql)

Reply ONLY with this JSON:
{{
  "interesting": [
    {{"url": "...", "reason": "one line why", "test_for": "IDOR/XSS/LFI/etc"}}
  ],
  "notes": "one sentence summary"
}}"""

    raw = ask(prompt, "Analyzing URLs for interesting endpoints")
    result = extract_json(raw)
    if not result:
        return {"interesting": [], "notes": "Parse error", "raw": raw}
    return result


def analyze_ffuf(ffuf_raw: str, target: str) -> dict:
    if not ffuf_raw.strip():
        return {"interesting_paths": [], "notes": "No ffuf output"}

    prompt = f"""You are a bug bounty researcher reviewing directory fuzzing results for {target}.

ffuf results:
{ffuf_raw[:1500]}

Identify which paths are actually interesting:
- 200 OK paths that expose data or functionality
- 403 Forbidden on sensitive paths (worth bypass testing)
- Ignore generic 301 redirects to login pages
- Flag anything suggesting admin, debug, backup, or API

Reply ONLY with this JSON:
{{
  "interesting_paths": [
    {{"path": "...", "status": 200, "reason": "..."}}
  ],
  "notes": "one sentence"
}}"""

    raw = ask(prompt, "Analyzing ffuf directory results")
    result = extract_json(raw)
    if not result:
        return {"interesting_paths": [], "notes": "Parse error", "raw": raw}
    return result


def critic_check(all_findings: dict, target: str) -> dict:
    """Final false-positive filter — Bronxi's most important lesson."""

    prompt = f"""You are a senior bug bounty triager. Review these preliminary findings for {target}.
Your job is to REDUCE noise, not increase it.

Findings to review:
{json.dumps(all_findings, indent=2)[:2000]}

For each finding ask:
1. Is there actual evidence, or just a guess?
2. Could this be a false positive (word "password" in docs, test data, etc.)?
3. Is the impact real and concrete?

Reply ONLY with this JSON:
{{
  "validated": [
    {{"type": "...", "url": "...", "severity": "Critical/High/Medium/Low", "confidence": "high/medium/low", "summary": "one line"}}
  ],
  "filtered_count": <integer>,
  "filter_reason": "brief explanation of what you removed and why"
}}"""

    raw = ask(prompt, "Running critic validation (false-positive filter)")
    result = extract_json(raw)
    if not result:
        return {"validated": [], "filtered_count": 0, "filter_reason": "Parse error"}
    return result


# ── Main ──────────────────────────────────────────────────────────
def main():
    target  = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    out_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("./tmp")

    print(f"\n[*] Phase 2 — Analysis")
    print(f"[*] Target  : {target}")
    print(f"[*] Out dir : {out_dir}\n")

    # Load bash outputs
    nuclei_raw = read_file(out_dir / "nuclei_findings.txt", max_lines=80)
    gau_raw    = read_file(out_dir / "urls_gau.txt",        max_lines=100)
    katana_raw = read_file(out_dir / "urls_katana.txt",     max_lines=100)
    ffuf_raw   = read_file(out_dir / "ffuf_findings.txt",   max_lines=80)
    live_hosts = read_file(out_dir / "live_hosts.txt",      max_lines=50)

    print(f"  Loaded: nuclei={len(nuclei_raw.splitlines())} lines, "
          f"gau={len(gau_raw.splitlines())} lines, "
          f"katana={len(katana_raw.splitlines())} lines, "
          f"ffuf={len(ffuf_raw.splitlines())} lines\n")

    # Run analysis passes
    nuclei_result = analyze_nuclei(nuclei_raw, target)
    print(f"  → Nuclei confirmed: {len(nuclei_result.get('confirmed', []))}, "
          f"filtered: {nuclei_result.get('false_positives', 0)}")

    urls_result = analyze_urls(gau_raw, katana_raw, target)
    print(f"  → Interesting URLs: {len(urls_result.get('interesting', []))}")

    ffuf_result = analyze_ffuf(ffuf_raw, target)
    print(f"  → Interesting paths: {len(ffuf_result.get('interesting_paths', []))}")

    # Build combined findings for critic
    combined = {
        "nuclei":  nuclei_result.get("confirmed", []),
        "urls":    urls_result.get("interesting", []),
        "paths":   ffuf_result.get("interesting_paths", []),
    }

    print()
    critic_result = critic_check(combined, target)
    print(f"  → Validated findings: {len(critic_result.get('validated', []))}")
    print(f"  → Filtered out: {critic_result.get('filtered_count', 0)} "
          f"({critic_result.get('filter_reason', '')})")

    # Save full analysis
    analysis = {
        "target":         target,
        "nuclei_analysis": nuclei_result,
        "url_analysis":    urls_result,
        "ffuf_analysis":   ffuf_result,
        "critic":          critic_result,
        "live_hosts_raw":  live_hosts,
    }

    analysis_path = out_dir / "analysis.json"
    analysis_path.write_text(json.dumps(analysis, indent=2))
    print(f"\n[*] Analysis saved to {analysis_path}")

    validated = critic_result.get("validated", [])
    if validated:
        print(f"\n[*] Validated findings to report:")
        for f in validated:
            sev = f.get("severity", "?")
            url = f.get("url", "?")
            typ = f.get("type", "?")
            conf = f.get("confidence", "?")
            print(f"    [{sev}] {typ} @ {url} (confidence: {conf})")
    else:
        print("\n[*] No confirmed findings after validation.")
        print("    This is normal — false positives are common with automated tools.")

    print(f"\nNext: python3 phase3_report.py {target} {out_dir}")
    return analysis_path


if __name__ == "__main__":
    main()
