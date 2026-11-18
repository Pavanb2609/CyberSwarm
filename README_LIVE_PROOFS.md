# CyberSwarm Live Attack Proofs

## Running
```bash
python scripts/generate_live_proofs.py
```

Proofs are written to `results/proofs/<timestamp>/` with summary.json, proof_trail.md, and artifacts/.

## What constitutes "live proof"
- Browser-executed XSS proof (Playwright captures actual JS execution via non-spoofable proof variable)
- Concrete payload bundles with categories and truth markers
- HTTP probe delivery with classification and criteria-based filtering

These demonstrate the tool performs attack generation, delivery, and proof capture.
