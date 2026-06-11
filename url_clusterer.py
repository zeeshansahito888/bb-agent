#!/usr/bin/env python3
"""
url_clusterer.py — Cluster, Rank, Flag discovered URLs
Inspired by: "cluster, rank, flag" recon workflow

Step 1: Cluster URLs into buckets (admin, API, upload, debug, etc.)
Step 2: Rank buckets by testing priority
Step 3: Flag anomalies (backup paths, old API versions, robots.txt paths, no-auth patterns)

Usage: python3 url_clusterer.py <domain> [recon_dir]
"""

import sys, json, re
from pathlib import Path
from collections import defaultdict
from openai import OpenAI

OLLAMA_URL = "http://localhost:11434/v1"
MODEL      = "qwen2.5:7b"

client = OpenAI(base_url=OLLAMA_URL, api_key="ollama")


def read_file(path, max_lines=500):
    if not Path(path).exists():
        return []
    lines = Path(path).read_text(errors="ignore").strip().splitlines()
    return [l.strip() for l in lines if l.strip()]


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
    if label:
        print(f"  [LLM] {label}...")
    r = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.1,
        max_tokens=2000,
    )
    return r.choices[0].message.content.strip()


# ── Step 1: Cluster URLs (bash logic, no LLM needed) ─────────────

CLUSTER_RULES = {
    "admin":        [r"/admin", r"/administrator", r"/manage", r"/dashboard", r"/control", r"/panel", r"/backend", r"/cms"],
    "api":          [r"/api/", r"/v1/", r"/v2/", r"/v3/", r"/v4/", r"/rest/", r"/graphql", r"/rpc"],
    "auth":         [r"/login", r"/signin", r"/signup", r"/register", r"/auth/", r"/oauth", r"/sso", r"/saml", r"/token", r"/password", r"/reset"],
    "upload_export":[r"/upload", r"/import", r"/export", r"/download", r"/file", r"/attachment", r"/media", r"/document"],
    "debug":        [r"/debug", r"/test", r"/dev", r"/console", r"/trace", r"/log", r"/info", r"/status", r"/health", r"/actuator", r"/metrics"],
    "user_data":    [r"/user", r"/account", r"/profile", r"/member", r"/customer", r"/client", r"/order", r"/invoice", r"/payment"],
    "config":       [r"\.env", r"\.git", r"\.config", r"\.yaml", r"\.yml", r"\.json", r"backup", r"\.bak", r"\.old", r"\.sql", r"\.dump"],
    "staging":      [r"staging", r"stage", r"uat", r"dev\.", r"test\.", r"preprod", r"sandbox", r"demo", r"beta"],
    "static_noise": [r"\.css", r"\.ico", r"\.png", r"\.jpg", r"\.gif", r"\.woff", r"\.ttf", r"\.svg", r"cdn\."],
}

def cluster_urls(urls: list) -> dict:
    """Bucket URLs into clusters using regex rules."""
    clusters = defaultdict(list)
    unclustered = []

    for url in urls:
        url_lower = url.lower()
        matched = False
        for cluster_name, patterns in CLUSTER_RULES.items():
            if any(re.search(p, url_lower) for p in patterns):
                clusters[cluster_name].append(url)
                matched = True
                break
        if not matched:
            unclustered.append(url)

    clusters["other"] = unclustered[:50]  # cap other bucket

    return dict(clusters)


# ── Step 2: Rank clusters ─────────────────────────────────────────

CLUSTER_PRIORITY = {
    "admin":         1,  # P1 — highest value
    "auth":          1,  # P1
    "debug":         1,  # P1
    "config":        1,  # P1 — .env, .git
    "api":           2,  # P2
    "upload_export": 2,  # P2
    "user_data":     2,  # P2
    "staging":       2,  # P2
    "other":         3,  # P3
    "static_noise":  4,  # deprioritize
}

def rank_clusters(clusters: dict) -> list:
    """Sort clusters by priority."""
    ranked = []
    for cluster_name, urls in clusters.items():
        if not urls:
            continue
        priority = CLUSTER_PRIORITY.get(cluster_name, 3)
        ranked.append({
            "cluster": cluster_name,
            "priority": priority,
            "count": len(urls),
            "sample": urls[:5]
        })
    return sorted(ranked, key=lambda x: x["priority"])


# ── Step 3: Flag anomalies ────────────────────────────────────────

def flag_anomalies(urls: list, robots_txt: str = "", target: str = "") -> list:
    """Flag things that look 'off' — no LLM needed for most."""
    flags = []
    url_set = set(u.lower() for u in urls)

    # Flag 1: Old API version alongside new
    has_v1 = any("/v1/" in u.lower() for u in urls)
    has_v2 = any("/v2/" in u.lower() for u in urls)
    has_v3 = any("/v3/" in u.lower() for u in urls)
    if has_v1 and (has_v2 or has_v3):
        old_apis = [u for u in urls if "/v1/" in u.lower()][:3]
        flags.append({
            "type": "old_api_version",
            "severity": "High",
            "description": "Old API v1 endpoints exist alongside newer versions — v1 may lack auth that v2 has",
            "examples": old_apis,
            "test": "Test v1 endpoints without auth token"
        })

    # Flag 2: Backup/config files accessible
    backup_patterns = [r"\.bak$", r"\.old$", r"\.backup$", r"\.sql$", r"\.dump$", r"~$", r"\.swp$"]
    backup_urls = [u for u in urls if any(re.search(p, u.lower()) for p in backup_patterns)]
    if backup_urls:
        flags.append({
            "type": "backup_files",
            "severity": "Critical",
            "description": "Backup/dump files discovered — may contain source code, credentials, or database dumps",
            "examples": backup_urls[:5],
            "test": "Download and inspect each file"
        })

    # Flag 3: Disallowed in robots.txt but reachable
    if robots_txt:
        disallowed = re.findall(r"Disallow:\s*(.+)", robots_txt)
        for path in disallowed:
            path = path.strip()
            if path and path != "/":
                matching = [u for u in urls if path.lower() in u.lower()]
                if matching:
                    flags.append({
                        "type": "robots_disallowed_but_reachable",
                        "severity": "Medium",
                        "description": f"Path '{path}' is disallowed in robots.txt but was found in crawl",
                        "examples": matching[:3],
                        "test": "Access directly and check for sensitive data"
                    })

    # Flag 4: Debug/staging endpoints live in production
    debug_live = [u for u in urls if re.search(r"/(debug|test|dev|console|trace)(/|$|\?)", u.lower())]
    if debug_live:
        flags.append({
            "type": "debug_endpoints_live",
            "severity": "High",
            "description": "Debug/development endpoints accessible in what appears to be production",
            "examples": debug_live[:5],
            "test": "Access each endpoint, check for stack traces, config dump, code execution"
        })

    # Flag 5: Admin paths without obvious auth pattern
    admin_paths = [u for u in urls if re.search(r"/admin|/manage|/dashboard", u.lower())]
    if admin_paths:
        flags.append({
            "type": "admin_surface",
            "severity": "High",
            "description": f"{len(admin_paths)} admin/management paths discovered",
            "examples": admin_paths[:5],
            "test": "Test access without auth, test with low-priv account"
        })

    # Flag 6: JWT/token in URL (security anti-pattern)
    token_in_url = [u for u in urls if re.search(r"[?&](token|jwt|auth|access_token|api_key)=", u.lower())]
    if token_in_url:
        flags.append({
            "type": "token_in_url",
            "severity": "Medium",
            "description": "Auth tokens/JWTs passed as URL parameters — leaked in logs, referrer headers",
            "examples": token_in_url[:3],
            "test": "Check if tokens are valid, check token scope"
        })

    # Flag 7: Export endpoints (often IDOR goldmine)
    export_paths = [u for u in urls if re.search(r"/(export|download|report|generate|extract)", u.lower())]
    if export_paths:
        flags.append({
            "type": "export_endpoints",
            "severity": "Medium",
            "description": f"{len(export_paths)} export/download endpoints — common IDOR vectors",
            "examples": export_paths[:5],
            "test": "Test with another user's ID, check if auth required"
        })

    return flags


# ── LLM pass: Qwen reviews top clusters for extra signals ─────────

def llm_review_top_clusters(ranked: list, target: str) -> dict:
    """Ask Qwen to review only the P1 clusters for extra anomalies."""
    p1_clusters = [c for c in ranked if c["priority"] == 1]
    if not p1_clusters:
        return {"extra_flags": [], "notes": "No P1 clusters to review"}

    cluster_summary = json.dumps([{
        "cluster": c["cluster"],
        "count": c["count"],
        "sample": c["sample"]
    } for c in p1_clusters], indent=2)

    prompt = f"""You are a bug bounty researcher reviewing URL clusters for {target}.

P1 clusters (highest priority):
{cluster_summary}

Look for additional anomalies not caught by basic pattern matching:
- Unusual parameter names suggesting privilege escalation
- Endpoints that mix admin/user context unexpectedly
- API versioning inconsistencies
- Paths that suggest internal tooling exposed externally
- Any other "this doesn't look normal" signals

Only flag REAL anomalies from the actual URLs above.
If nothing extra found, return empty list.

Reply ONLY with JSON:
{{
  "extra_flags": [
    {{
      "type": "...",
      "severity": "High/Medium",
      "description": "...",
      "example_url": "...",
      "test": "what to do"
    }}
  ],
  "notes": "one sentence"
}}"""

    raw = ask(prompt, "LLM reviewing P1 clusters for anomalies")
    return extract_json(raw) or {"extra_flags": [], "notes": "Parse error"}


# ── Write report ──────────────────────────────────────────────────

def write_cluster_report(target: str, ranked: list, flags: list, extra_flags: list, stats: dict) -> str:
    from datetime import datetime
    lines = []
    lines.append(f"# URL Cluster Report: {target}")
    lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")

    lines.append("## Stats")
    lines.append(f"- Total URLs analyzed : {stats['total']}")
    lines.append(f"- Clusters found      : {stats['clusters']}")
    lines.append(f"- Flags raised        : {len(flags) + len(extra_flags)}")
    lines.append(f"- P1 clusters         : {stats['p1_count']}")
    lines.append(f"- Noise filtered      : {stats['noise_count']}\n")

    # P1 clusters
    lines.append("## Priority 1 — Test First")
    p1 = [c for c in ranked if c["priority"] == 1]
    if p1:
        for c in p1:
            lines.append(f"\n### {c['cluster'].upper()} ({c['count']} URLs)")
            for url in c["sample"][:5]:
                lines.append(f"- `{url}`")
    else:
        lines.append("No P1 clusters found.")

    # P2 clusters
    lines.append("\n## Priority 2 — Test After P1")
    p2 = [c for c in ranked if c["priority"] == 2]
    if p2:
        for c in p2:
            lines.append(f"\n### {c['cluster'].upper()} ({c['count']} URLs)")
            for url in c["sample"][:3]:
                lines.append(f"- `{url}`")

    # Flags
    lines.append("\n## Flags — Anomalies to Investigate")
    all_flags = flags + extra_flags
    if all_flags:
        for f in all_flags:
            lines.append(f"\n### [{f.get('severity','?')}] {f.get('type','?')}")
            lines.append(f"**Description:** {f.get('description','?')}")
            if f.get("examples") or f.get("example_url"):
                examples = f.get("examples", [f.get("example_url","")]) 
                for ex in examples[:3]:
                    lines.append(f"- `{ex}`")
            lines.append(f"**Test:** {f.get('test','?')}")
    else:
        lines.append("No anomalies flagged.")

    # Noise
    lines.append("\n## Deprioritized (Noise)")
    noise = [c for c in ranked if c["priority"] == 4]
    for c in noise:
        lines.append(f"- {c['cluster']}: {c['count']} URLs (skip)")

    return "\n".join(lines)


# ── Main ──────────────────────────────────────────────────────────

def main():
    target  = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    out_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(f"recon/{target}")

    print(f"\n[*] URL Clusterer — Cluster, Rank, Flag")
    print(f"[*] Target  : {target}")
    print(f"[*] Out dir : {out_dir}\n")

    # Load URLs
    urls = read_file(out_dir / "urls.txt", max_lines=5000)
    # Also add API endpoints and IDOR candidates
    urls += read_file(out_dir / "api-endpoints.txt", max_lines=500)
    urls += read_file(out_dir / "idor-candidates.txt", max_lines=500)
    urls = list(set(urls))  # deduplicate

    print(f"[*] Total URLs loaded: {len(urls)}")

    if len(urls) < 10:
        print("[!] Too few URLs — run phase1_recon.sh first")
        sys.exit(0)

    # Load robots.txt if available
    robots_txt = ""
    robots_file = out_dir / "robots.txt"
    if robots_file.exists():
        robots_txt = robots_file.read_text(errors="ignore")

    # Step 1: Cluster
    print("[*] Step 1 — Clustering URLs...")
    clusters = cluster_urls(urls)
    for name, bucket in clusters.items():
        if bucket:
            print(f"  {name:20} : {len(bucket)} URLs")

    # Step 2: Rank
    print("\n[*] Step 2 — Ranking clusters...")
    ranked = rank_clusters(clusters)

    # Step 3: Flag
    print("\n[*] Step 3 — Flagging anomalies...")
    flags = flag_anomalies(urls, robots_txt, target)
    for f in flags:
        print(f"  [{f['severity']}] {f['type']}")

    # LLM pass on P1 clusters
    print()
    llm_result = llm_review_top_clusters(ranked, target)
    extra_flags = llm_result.get("extra_flags", [])
    if extra_flags:
        print(f"  [LLM] Found {len(extra_flags)} additional flags")
        for f in extra_flags:
            print(f"    [{f.get('severity','?')}] {f.get('type','?')}")

    # Stats
    stats = {
        "total":       len(urls),
        "clusters":    len([c for c in ranked if c["count"] > 0]),
        "p1_count":    len([c for c in ranked if c["priority"] == 1]),
        "noise_count": sum(c["count"] for c in ranked if c["priority"] == 4),
    }

    # Write report
    report = write_cluster_report(target, ranked, flags, extra_flags, stats)
    report_path = out_dir / "cluster_report.md"
    report_path.write_text(report)

    # Save JSON
    result = {
        "target":      target,
        "stats":       stats,
        "ranked":      ranked,
        "flags":       flags,
        "extra_flags": extra_flags,
    }
    json_path = out_dir / "cluster_report.json"
    json_path.write_text(json.dumps(result, indent=2))

    print(f"\n{'='*50}")
    print(f"CLUSTER REPORT COMPLETE")
    print(f"  P1 clusters : {stats['p1_count']}")
    print(f"  Total flags : {len(flags) + len(extra_flags)}")
    print(f"  Noise URLs  : {stats['noise_count']} (skipped)")
    print(f"  Report      : {report_path}")
    print(f"{'='*50}")

    # Print flags summary
    all_flags = flags + extra_flags
    if all_flags:
        print(f"\n  FLAGS TO INVESTIGATE:")
        for f in all_flags:
            print(f"    [{f.get('severity','?')}] {f.get('type','?')}")
            print(f"    → {f.get('description','?')[:80]}")
            if f.get("examples"):
                print(f"    → Example: {f['examples'][0]}")
            print()


if __name__ == "__main__":
    main()
