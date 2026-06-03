# Hunt Memory

Stores successful patterns across hunts to inform future rankings.

## patterns.jsonl
Add a line after each successful finding:
```bash
cat >> hunt-memory/patterns.jsonl << EOF
{"pattern": "what you found", "tech": "tech stack", "result": "vuln", "date": "2026-01-01"}
EOF
```

## targets/
Auto-generated per target by recon_ranker.py.
Stores last ranked date and P1/P2 counts.
