# BB-Agent — Bug Bounty Pipeline
### Qwen 2.5 7B + Bash | Inspired by Bronxi's lessons on Bugcrowd

---

## Philosophy

> *"AI in bug bounty is an amplifier of proven personal skills — not a substitute."*
> — Bronxi, Bugcrowd (2026)

This pipeline follows Bronxi's hard-won lesson:
- **Bash does the scanning** (fast, reliable, proven tools)
- **Qwen analyzes the output** (reading, pattern matching, filtering)
- **Critic step filters false positives** (the #1 problem with AI agents)
- **You verify before submitting** (always)

---

## Structure

```
bb-agent/
├── run.sh              ← Start here (runs all 3 phases)
├── phase1_recon.sh     ← Pure bash: subfinder, httpx, nuclei, ffuf, gau
├── phase2_analyze.py   ← Qwen analysis + false-positive filtering
├── phase3_report.py    ← Qwen writes HackerOne-ready markdown report
├── reports/            ← All output goes here (one folder per run)
└── README.md
```

---

## Quick Start

### 1. Prerequisites

**Required:**
```bash
# Ollama running with qwen2.5:7b
ollama serve
ollama pull qwen2.5:7b

# Python openai package
pip install openai
```

**Recommended (install as many as you have):**
```bash
# Go tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/ffuf/ffuf/v2@latest

# Wordlists
git clone https://github.com/danielmiessler/SecLists /usr/share/seclists
```

The pipeline skips any tool that isn't installed — no crashes.

### 2. Run

```bash
chmod +x run.sh phase1_recon.sh
./run.sh example.com "*.example.com"
```

That's it. The pipeline:
1. Runs bash recon (subfinder → httpx → nuclei → ffuf → gau)
2. Qwen analyzes output, filters false positives
3. Qwen writes the markdown report

Report is saved to `reports/<domain>_<timestamp>/`

---

## Running Phases Individually

```bash
# Phase 1 only (recon)
bash phase1_recon.sh example.com ./tmp

# Phase 2 only (analyze existing recon output)
python3 phase2_analyze.py example.com ./tmp

# Phase 3 only (generate report from existing analysis)
python3 phase3_report.py example.com ./tmp
```

Useful if a phase fails or you want to re-run just the AI analysis.

---

## Output Files

Each run creates a timestamped folder in `reports/`:

| File | Contents |
|---|---|
| `subs_all.txt` | All unique subdomains found |
| `live_urls.txt` | Confirmed live HTTP endpoints |
| `live_hosts.txt` | Live hosts with status/title/tech |
| `nuclei_findings.txt` | Raw nuclei output |
| `ffuf_findings.txt` | Directory fuzzing results |
| `urls_gau.txt` | Historical URLs (gau) |
| `urls_katana.txt` | Crawled JS endpoints |
| `analysis.json` | Full Qwen analysis (machine-readable) |
| `report_*.md` | HackerOne-ready markdown report |
| `recon.log` | Full phase 1 log |

---

## What Qwen Does (and Doesn't Do)

**Qwen 2.5 7B is your analyst, not your hacker.**

| Task | Who Does It |
|---|---|
| Subdomain enumeration | subfinder / amass (bash) |
| Probing live hosts | httpx (bash) |
| Vuln template scanning | nuclei (bash) |
| Directory fuzzing | ffuf (bash) |
| **Reading nuclei output** | **Qwen** |
| **Filtering false positives** | **Qwen (critic step)** |
| **Finding interesting URLs** | **Qwen** |
| **Writing the report** | **Qwen** |
| **Manual verification** | **You** |

---

## False Positive Strategy

Bronxi's biggest lesson: agents produce tons of false positives.

This pipeline fights that with a **3-layer filter**:

1. **Analysis pass** — Qwen reads each tool's output and flags candidates
2. **Critic pass** — A second Qwen prompt reviews candidates and cuts noise
3. **Manual gate** — You verify before submitting (non-negotiable)

The critic prompt is specifically designed to be skeptical:
- A file containing the word "password" is NOT a finding
- Tech detection is NOT a vulnerability
- DNS-only SSRF without internal access proof is NOT reportable

---

## Tips for Qwen 2.5 7B

- Keep tool outputs truncated (already done in code — 80-100 lines max)
- One task per prompt (the code does this)
- Temperature 0.1 for analysis, 0.2 for report writing
- If JSON parsing fails, the code retries with a simpler prompt
- 7B models drift on long contexts — split phases help a lot

---

## Legal

Only use against targets you have **explicit permission** to test.
This tool is for authorized bug bounty programs only.
