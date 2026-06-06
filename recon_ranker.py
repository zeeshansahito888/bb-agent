#!/usr/bin/env python3
import sys, json, re
from pathlib import Path
from datetime import datetime, timedelta
from openai import OpenAI

OLLAMA_URL = "http://localhost:11434/v1"
MODEL      = "qwen2.5:7b"

client = OpenAI(base_url=OLLAMA_URL, api_key="ollama")

TECH_VULN_MAP = {
    "laravel":       ["sqli", "xss", "mass-assignment", "idor"],
    "django":        ["idor", "ssrf", "xss"],
    "rails":         ["mass-assignment", "idor", "xss"],
    "wordpress":     ["sqli", "xss", "file-upload", "rce"],
    "drupal":        ["rce", "sqli", "xss"],
    "joomla":        ["sqli", "xss", "rce"],
    "nginx":         ["path-traversal", "ssrf"],
    "apache":        ["path-traversal", "rce"],
    "tomcat":        ["rce", "deserialization"],
    "spring":        ["ssrf", "rce", "actuator-exposure"],
    "express":       ["xss", "nosqli", "idor"],
    "next.js":       ["xss", "ssrf", "idor"],
    "graphql":       ["introspection", "idor", "sqli", "dos"],
    "elasticsearch": ["unauth-access", "data-exposure"],
    "jenkins":       ["rce", "unauth-access"],
    "jira":          ["ssrf", "xss", "idor"],
    "confluence":    ["rce", "xss", "ssrf"],
    "php":           ["sqli", "xss", "lfi", "rce", "file-upload"],
    "asp.net":       ["sqli", "xss", "idor", "deserialization"],
    "jquery":        ["xss", "prototype-pollution"],
    "react":         ["xss", "idor"],
    "angular":       ["xss", "open-redirect"],
    "s3":            ["unauth-access", "bucket-takeover"],
    "cloudfront":    ["cache-poisoning", "ssrf"],
}

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
        max_tokens=2000,
    )
    return r.choices[0].message.content.strip()
def search_mempalace(query, top=3):
    import subprocess
    try:
        r = subprocess.run(
            ["mempalace", "search", query, "--results", str(top)],
            capture_output=True, text=True,
            cwd="/root/bb-agent", timeout=10
        )
        return r.stdout.strip()[:800] if r.stdout.strip() else ""
    except:
        return ""

def load_hunt_memory(target):
    memory = {"patterns": [], "previous_tests": [], "successful_techs": []}

    contexts = []
    for query in [
        f"IDOR vulnerability API {target}",
        "bug bounty high severity findings",
        "SQL injection SSRF bypass",
    ]:
        result = search_mempalace(query)
        if result:
            contexts.append(result)

    if contexts:
        print(f"  Memory: MemPalace {len(contexts)} contexts loaded")
        memory["patterns"] = [{"pattern": "mempalace", "context": c} for c in contexts]
        return memory

    # JSON fallback
    print("  Memory: using JSON fallback")
    memory_dir = Path("hunt-memory")
    patterns_file = memory_dir / "patterns.jsonl"
    if patterns_file.exists():
        for line in patterns_file.read_text().strip().splitlines():
            try: memory["patterns"].append(json.loads(line))
            except: pass
    target_file = memory_dir / "targets" / f"{target}.json"
    if target_file.exists():
        try:
            data = json.loads(target_file.read_text())
            memory["previous_tests"] = data.get("tested_endpoints", [])
            memory["successful_techs"] = data.get("successful_techs", [])
        except: pass
    return memory

def save_hunt_memory(target, ranking_result):
    memory_dir = Path("hunt-memory/targets")
    memory_dir.mkdir(parents=True, exist_ok=True)
    target_file = memory_dir / f"{target}.json"
    existing = {}
    if target_file.exists():
        try: existing = json.loads(target_file.read_text())
        except: pass
    existing["last_ranked"] = datetime.now().isoformat()
    existing["p1_count"]    = len(ranking_result.get("p1", []))
    existing["p2_count"]    = len(ranking_result.get("p2", []))
    target_file.write_text(json.dumps(existing, indent=2))

def get_tech_vulns(tech_line):
    tech_lower = tech_line.lower()
    vulns = []
    for tech, classes in TECH_VULN_MAP.items():
        if tech in tech_lower:
            vulns.extend(classes)
    return list(set(vulns))

def rank_surface(recon_data, memory, target):
    tech_vuln_context = []
    for host_line in recon_data.get("live_hosts", "").splitlines()[:20]:
        vulns = get_tech_vulns(host_line)
        if vulns:
            tech_vuln_context.append(
                f"{host_line.split()[0]} → likely: {', '.join(vulns[:3])}"
            )

    memory_context = ""
    if memory["patterns"]:
        memory_context = "Past successful patterns:\n"
        for p in memory["patterns"][:5]:
            memory_context += f"- {p.get('pattern','?')} on {p.get('tech','?')} → {p.get('result','?')}\n"

    # Auto P1 — GraphQL/WebSocket always P1
    p1_auto = []
    for line in recon_data.get("p1_candidates", "").splitlines()[:10]:
        if line.strip():
            p1_auto.append({
                "target": line.strip(),
                "reason": "GraphQL/WebSocket — always P1",
                "suggested_test": "test introspection, IDOR via queries",
                "vuln_class": "graphql/websocket",
                "auto": True
            })

    prompt = f"""You are an attack surface analyst for bug bounty target: {target}

Live hosts with tech:
{recon_data.get('live_hosts','none')[:1500]}

Tech → likely vulns:
{chr(10).join(tech_vuln_context) or 'none detected'}

IDOR candidates:
{recon_data.get('idor_candidates','none')[:800]}

API endpoints:
{recon_data.get('api_endpoints','none')[:800]}

SSRF candidates:
{recon_data.get('ssrf_candidates','none')[:400]}

Nuclei findings:
{recon_data.get('nuclei','none')[:600]}

{memory_context}

Ranking rules:
- P1: IDOR candidates, API with ID params, unauthenticated admin, nuclei critical/high
- P2: Admin behind auth, interesting endpoints without ID params, nuclei medium
- Kill list: CDN hosts, static pages, third-party domains

Reply ONLY with JSON:
{{
  "p1": [
    {{"target":"...","reason":"...","tech":"...","suggested_test":"...","vuln_class":"..."}}
  ],
  "p2": [
    {{"target":"...","reason":"...","suggested_test":"..."}}
  ],
  "kill_list": [
    {{"target":"...","reason":"..."}}
  ],
  "recommended_first": "one sentence: where to start and why"
}}"""

    raw = ask(prompt, "Ranking attack surface")
    result = extract_json(raw)
    if not result:
        return {"p1": p1_auto, "p2": [], "kill_list": [],
                "recommended_first": "Parse error — check recon output"}

    if p1_auto:
        result["p1"] = p1_auto + result.get("p1", [])
    return result

def write_report(target, ranking, memory, stats):
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    lines = []
    lines.append(f"# Attack Surface Ranking: {target}")
    lines.append(f"**Generated:** {now}\n")
    lines.append("## Stats")
    lines.append(f"- Subdomains   : {stats.get('subdomains',0)}")
    lines.append(f"- Live hosts   : {stats.get('live_hosts',0)}")
    lines.append(f"- Total URLs   : {stats.get('urls',0)}")
    lines.append(f"- P1 targets   : {len(ranking.get('p1',[]))}")
    lines.append(f"- P2 targets   : {len(ranking.get('p2',[]))}")
    lines.append(f"- Kill list    : {len(ranking.get('kill_list',[]))}")
    lines.append(f"- Prev tested  : {len(memory.get('previous_tests',[]))}\n")

    if ranking.get("recommended_first"):
        lines.append("## Start Here")
        lines.append(f"> {ranking['recommended_first']}\n")

    lines.append("## Priority 1 (start here)")
    for i, item in enumerate(ranking.get("p1",[]), 1):
        lines.append(f"\n{i}. **{item.get('target','?')}**")
        lines.append(f"   - Why   : {item.get('reason','?')}")
        if item.get('tech'): lines.append(f"   - Tech  : {item.get('tech')}")
        lines.append(f"   - Test  : {item.get('suggested_test','?')}")
        if item.get('vuln_class'): lines.append(f"   - Class : {item.get('vuln_class')}")

    lines.append("\n## Priority 2 (after P1)")
    for i, item in enumerate(ranking.get("p2",[]), 1):
        lines.append(f"\n{i}. **{item.get('target','?')}**")
        lines.append(f"   - Why  : {item.get('reason','?')}")
        lines.append(f"   - Test : {item.get('suggested_test','?')}")

    lines.append("\n## Kill List (skip)")
    for item in ranking.get("kill_list",[]):
        lines.append(f"- `{item.get('target','?')}` — {item.get('reason','?')}")

    lines.append("\n## Memory Context")
    for p in memory.get("patterns",[])[:3]:
        ctx = p.get("context","")
        if ctx:
            preview = "\n  ".join(ctx.splitlines()[:2])
            lines.append(f"- {preview}")
        else:
            lines.append(f"- {p.get('pattern','?')} on {p.get('tech','?')} → {p.get('result','?')}")
    if not memory.get("patterns"):
        lines.append("No hunt memory yet.")

    return "\n".join(lines)

def count_lines(path):
    p = Path(path)
    if not p.exists(): return 0
    return len(p.read_text(errors="ignore").strip().splitlines())

def main():
    target    = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    recon_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(f"recon/{target}")

    print(f"\n[*] Recon Ranker")
    print(f"[*] Target  : {target}")
    print(f"[*] Dir     : {recon_dir}\n")

    if not recon_dir.exists():
        print(f"[!] Not found: {recon_dir} — run phase1_recon.sh first")
        sys.exit(1)

    recon_data = {
        "live_hosts":      read_file(recon_dir / "live-hosts.txt",      50),
        "idor_candidates": read_file(recon_dir / "idor-candidates.txt", 50),
        "ssrf_candidates": read_file(recon_dir / "ssrf-candidates.txt", 30),
        "api_endpoints":   read_file(recon_dir / "api-endpoints.txt",   50),
        "p1_candidates":   read_file(recon_dir / "p1-candidates.txt",   20),
        "nuclei":          read_file(recon_dir / "nuclei.txt",          30),
    }

    stats = {
        "subdomains": count_lines(recon_dir / "subdomains.txt"),
        "live_hosts": count_lines(recon_dir / "live-urls.txt"),
        "urls":       count_lines(recon_dir / "urls.txt"),
    }

    memory  = load_hunt_memory(target)
    print(f"  Memory: {len(memory['patterns'])} patterns, "
          f"{len(memory['previous_tests'])} prev tested")

    ranking = rank_surface(recon_data, memory, target)

    print(f"\n  P1: {len(ranking.get('p1',[]))}  "
          f"P2: {len(ranking.get('p2',[]))}  "
          f"Kill: {len(ranking.get('kill_list',[]))}")

    if ranking.get("recommended_first"):
        print(f"\n  START → {ranking['recommended_first']}")

    report = write_report(target, ranking, memory, stats)
    (recon_dir / "ranking.md").write_text(report)
    (recon_dir / "ranking.json").write_text(json.dumps(ranking, indent=2))
    save_hunt_memory(target, ranking)

    print(f"\n[*] ranking.md  saved")
    print(f"[*] ranking.json saved")
    print(f"\nNext: python3 phase3_report.py {target} {recon_dir}")

if __name__ == "__main__":
    main()
