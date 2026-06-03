#!/usr/bin/env python3
"""
Phase 3 — Qwen 2.5 7B Report Writer
Reads analysis.json and generates a HackerOne-ready markdown report.

Usage: python3 phase3_report.py <domain> [out_dir]
"""

import sys, json, re
from pathlib import Path
from datetime import datetime
from openai import OpenAI

OLLAMA_URL = "http://localhost:11434/v1"
MODEL      = "qwen2.5:7b"

client = OpenAI(base_url=OLLAMA_URL, api_key="ollama")


def extract_text(response) -> str:
    return response.choices[0].message.content.strip()


def write_finding_report(finding: dict, target: str) -> str:
    """Generate a single HackerOne-style report for one finding."""

    prompt = f"""Write a professional HackerOne bug bounty report for this finding.

Target: {target}
Finding data: {json.dumps(finding, indent=2)}

Use EXACTLY this format — fill in the blanks based on the finding data:

## [Vuln Type] in [endpoint] allows [attacker role] to [impact]

### Summary
[2-3 sentences: what it is, where it is, what attacker gains]

### Vulnerability Details
- **Type**: [e.g. IDOR / XSS / SSRF]
- **Severity**: [Critical / High / Medium / Low]
- **CVSS Score**: [estimate, e.g. 7.5 (High)]
- **Endpoint**: [URL or parameter]

### Steps to Reproduce
1. [Concrete step]
2. [Concrete step]
3. Observe: [exact impact]

### Impact
[What can attacker do? Be specific: data exfil, ATO, RCE, etc.]

### Remediation
[One specific fix]

Rules:
- Keep it under 350 words
- Be factual, no hype
- If evidence is limited, note "Manual verification required"
- Write like a human researcher, not AI"""

    r = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.2,
        max_tokens=800,
    )
    return extract_text(r)


def write_executive_summary(validated: list, target: str, stats: dict) -> str:
    prompt = f"""Write a short executive summary for a bug bounty report on {target}.

Stats:
- Subdomains found: {stats.get('subdomains', 0)}
- Live hosts: {stats.get('live_hosts', 0)}
- Findings after validation: {len(validated)}
- Severity breakdown: {stats.get('severity_breakdown', {})}

Validated findings: {json.dumps(validated, indent=2)[:1000]}

Write 3-4 sentences max. Be factual and professional.
Do NOT use bullet points. Plain prose only."""

    r = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.2,
        max_tokens=300,
    )
    return extract_text(r)


def count_lines(path: Path) -> int:
    if not path.exists():
        return 0
    return len(path.read_text(errors="ignore").strip().splitlines())


def main():
    target  = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    out_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("./tmp")

    print(f"\n[*] Phase 3 — Report Generation")
    print(f"[*] Target  : {target}\n")

    analysis_path = out_dir / "analysis.json"
    if not analysis_path.exists():
        print(f"[!] analysis.json not found at {analysis_path}")
        print("    Run phase2_analyze.py first.")
        sys.exit(1)

    analysis = json.loads(analysis_path.read_text())
    validated = analysis.get("critic", {}).get("validated", [])

    # Stats for summary
    stats = {
        "subdomains":  count_lines(out_dir / "subs_all.txt"),
        "live_hosts":  count_lines(out_dir / "live_urls.txt"),
        "severity_breakdown": {}
    }
    for f in validated:
        sev = f.get("severity", "Unknown")
        stats["severity_breakdown"][sev] = stats["severity_breakdown"].get(sev, 0) + 1

    # Build report
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    report_lines = []

    report_lines.append(f"# Bug Bounty Report — {target}")
    report_lines.append(f"**Date:** {now}  ")
    report_lines.append(f"**Target:** {target}  ")
    report_lines.append(f"**Tool:** Qwen 2.5 7B + bash recon  \n")

    # Severity table
    report_lines.append("## Findings Overview\n")
    report_lines.append("| Severity | Count |")
    report_lines.append("|---|---|")
    for sev in ["Critical", "High", "Medium", "Low"]:
        count = stats["severity_breakdown"].get(sev, 0)
        report_lines.append(f"| {sev} | {count} |")
    report_lines.append("")

    # Recon stats
    report_lines.append("## Recon Coverage\n")
    report_lines.append(f"- Subdomains enumerated: **{stats['subdomains']}**")
    report_lines.append(f"- Live hosts confirmed: **{stats['live_hosts']}**")
    report_lines.append(f"- Validated findings: **{len(validated)}**\n")

    # Executive summary
    if validated:
        print("  [LLM] Writing executive summary...")
        summary = write_executive_summary(validated, target, stats)
        report_lines.append("## Executive Summary\n")
        report_lines.append(summary + "\n")

        # Individual finding reports
        report_lines.append("---\n")
        report_lines.append("## Findings\n")
        for i, finding in enumerate(validated, 1):
            print(f"  [LLM] Writing report for finding {i}/{len(validated)}: "
                  f"{finding.get('type','?')}...")
            finding_report = write_finding_report(finding, target)
            report_lines.append(finding_report)
            report_lines.append("\n---\n")
    else:
        report_lines.append("## Results\n")
        report_lines.append(
            "No confirmed vulnerabilities found in this automated scan. "
            "This does not mean the target is secure — automated tools miss "
            "business logic flaws, IDOR chains, and many other vulnerability classes. "
            "Manual testing is recommended.\n"
        )
        report_lines.append("### Interesting Endpoints for Manual Review\n")
        interesting = analysis.get("url_analysis", {}).get("interesting", [])
        for item in interesting[:10]:
            url    = item.get("url", "")
            reason = item.get("reason", "")
            test   = item.get("test_for", "")
            report_lines.append(f"- `{url}` — {reason} *(test for: {test})*")
        report_lines.append("")

    # Methodology
    report_lines.append("---\n")
    report_lines.append("## Methodology\n")
    report_lines.append("1. **Subdomain Enumeration** — subfinder, amass (passive)")
    report_lines.append("2. **Live Host Probing** — httpx (status codes, tech stack)")
    report_lines.append("3. **Historical URL Collection** — gau, Wayback Machine")
    report_lines.append("4. **JS Crawling** — katana (depth 3, JS parsing)")
    report_lines.append("5. **Vulnerability Scanning** — nuclei (high/critical templates)")
    report_lines.append("6. **Directory Fuzzing** — ffuf (SecLists common.txt)")
    report_lines.append("7. **AI Analysis** — Qwen 2.5 7B (false-positive filtering)")
    report_lines.append("8. **AI Validation** — Critic pass to reduce noise\n")
    report_lines.append(
        "> ⚠️ All findings require manual verification before submission. "
        "AI analysis reduces false positives but does not eliminate them.\n"
    )

    # Save report
    report_text = "\n".join(report_lines)
    report_path = out_dir / f"report_{target}_{datetime.now().strftime('%Y%m%d_%H%M')}.md"
    report_path.write_text(report_text)

    print(f"\n{'='*60}")
    print(f"REPORT SAVED: {report_path}")
    print(f"{'='*60}")
    print(f"  Findings : {len(validated)}")
    for sev, count in stats["severity_breakdown"].items():
        print(f"  {sev:10}: {count}")
    print()

    return report_path


if __name__ == "__main__":
    main()
