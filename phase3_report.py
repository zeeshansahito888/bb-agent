#!/usr/bin/env python3
import sys, json, re
from pathlib import Path
from datetime import datetime
from openai import OpenAI

OLLAMA_URL = "http://localhost:11434/v1"
MODEL      = "qwen2.5:7b"

client = OpenAI(base_url=OLLAMA_URL, api_key="ollama")

def extract_text(response):
    return response.choices[0].message.content.strip()

def count_lines(path):
    p = Path(path)
    if not p.exists(): return 0
    return len(p.read_text(errors="ignore").strip().splitlines())

def write_finding_report(finding, target):
    prompt = f"""Write a professional HackerOne bug bounty report for this finding.

Target: {target}
Finding: {json.dumps(finding, indent=2)}

Use EXACTLY this format:

## [Vuln Type] in [endpoint] allows [attacker] to [impact]

### Summary
[2-3 sentences: what, where, what attacker gains]

### Vulnerability Details
- **Type**: [e.g. IDOR / XSS / SSRF]
- **Severity**: [Critical / High / Medium / Low]
- **CVSS Score**: [estimate]
- **Endpoint**: [URL or parameter]

### Steps to Reproduce
1. [step]
2. [step]
3. Observe: [impact]

### Impact
[Specific harm: data exfil, ATO, RCE etc]

### Remediation
[One specific fix]

Rules:
- Under 350 words
- Factual, no hype
- If evidence limited, note manual verification required
- Write like a human researcher"""

    r = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.2,
        max_tokens=800,
    )
    return extract_text(r)

def write_summary(validated, target, stats):
    prompt = f"""Write a short executive summary for a bug bounty report on {target}.

Stats:
- Subdomains: {stats.get('subdomains',0)}
- Live hosts: {stats.get('live_hosts',0)}
- Validated findings: {len(validated)}
- Severity breakdown: {stats.get('severity_breakdown',{})}

Findings: {json.dumps(validated, indent=2)[:1000]}

Write 3-4 sentences max. Factual and professional. Plain prose only, no bullets."""

    r = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.2,
        max_tokens=300,
    )
    return extract_text(r)

def main():
    target  = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    out_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(f"recon/{target}")

    print(f"\n[*] Phase 3 — Report Generation")
    print(f"[*] Target  : {target}\n")

    analysis_path = out_dir / "analysis.json"
    if not analysis_path.exists():
        print(f"[!] analysis.json not found — run phase2_analyze.py first")
        sys.exit(1)

    analysis  = json.loads(analysis_path.read_text())
    validated = analysis.get("critic", {}).get("validated", [])

    stats = {
        "subdomains": count_lines(out_dir / "subdomains.txt"),
        "live_hosts": count_lines(out_dir / "live-urls.txt"),
        "severity_breakdown": {}
    }
    for f in validated:
        sev = f.get("severity", "Unknown")
        stats["severity_breakdown"][sev] = stats["severity_breakdown"].get(sev, 0) + 1

    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    lines = []
    lines.append(f"# Bug Bounty Report — {target}")
    lines.append(f"**Date:** {now}  ")
    lines.append(f"**Target:** {target}  ")
    lines.append(f"**Tool:** Qwen 2.5 7B + bash recon\n")

    lines.append("## Findings Overview\n")
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    for sev in ["Critical", "High", "Medium", "Low"]:
        lines.append(f"| {sev} | {stats['severity_breakdown'].get(sev,0)} |")
    lines.append("")

    lines.append("## Recon Coverage\n")
    lines.append(f"- Subdomains enumerated: **{stats['subdomains']}**")
    lines.append(f"- Live hosts confirmed: **{stats['live_hosts']}**")
    lines.append(f"- Validated findings: **{len(validated)}**\n")

    if validated:
        print("  [LLM] Writing executive summary...")
        summary = write_summary(validated, target, stats)
        lines.append("## Executive Summary\n")
        lines.append(summary + "\n")
        lines.append("---\n")
        lines.append("## Findings\n")
        for i, finding in enumerate(validated, 1):
            print(f"  [LLM] Writing finding {i}/{len(validated)}: "
                  f"{finding.get('type','?')}...")
            report = write_finding_report(finding, target)
            lines.append(report)
            lines.append("\n---\n")
    else:
        lines.append("## Results\n")
        lines.append(
            "No confirmed vulnerabilities found in automated scan. "
            "Manual testing recommended.\n"
        )
        lines.append("### Interesting Endpoints for Manual Review\n")
        interesting = analysis.get("url_analysis", {}).get("interesting", [])
        for item in interesting[:10]:
            lines.append(
                f"- `{item.get('url','')}` — {item.get('reason','')} "
                f"*(test: {item.get('test_for','')})*"
            )

    lines.append("---\n")
    lines.append("## Methodology\n")
    lines.append("1. Subdomain Enumeration — subfinder, assetfinder, Chaos API")
    lines.append("2. Live Host Probing — httpx-toolkit + dnsx")
    lines.append("3. URL Collection — waybackurls, katana")
    lines.append("4. Classification — gf patterns (IDOR/SSRF/XSS/SQLi)")
    lines.append("5. Vuln Scanning — nuclei (critical/high/medium)")
    lines.append("6. AI Analysis — Qwen 2.5 7B false-positive filtering")
    lines.append("7. Attack Surface Ranking — recon_ranker.py\n")
    lines.append("> ⚠️ All findings require manual verification before submission.\n")

    report_text = "\n".join(lines)
    ts = datetime.now().strftime("%Y%m%d_%H%M")
    report_path = out_dir / f"report_{target}_{ts}.md"
    report_path.write_text(report_text)

    print(f"\n{'='*50}")
    print(f"REPORT: {report_path}")
    print(f"{'='*50}")
    for sev, count in stats["severity_breakdown"].items():
        print(f"  {sev:10}: {count}")
    print()

if __name__ == "__main__":
    main()
