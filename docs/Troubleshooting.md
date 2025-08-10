## Troubleshooting
If it can fail, it will — here’s how to win anyway.

### ModuleNotFoundError: sentinelscope
Use the same interpreter you installed into:
```bash
python3.11 -m pip install -e . -r requirements-dev.txt
python3.11 -m pytest -q
```

### TLS errors or timeouts
- Ensure domain resolves publicly
- Some hosts block TLS handshake from scanners; proceed with headers or port-only scans

### No subdomains found
- CT logs may be sparse for new domains
- Add more wordlist entries in `sentinelscope/scanning/subdomains.py`

### DNS/DMARC/SPF missing
- Some providers publish records at subdomains (e.g., `_dmarc.example.com`); ensure delegation is correct
- Check with authoritative DNS or dig as a cross-check

### Takeover false positives
- Heuristics are best-effort. Manually verify flagged hosts before actionable remediation
- Add or tune signatures in `sentinelscope/scanning/takeover.py`

### HTML report missing
Ensure templates packaged:
```bash
pip install -e .
```

### Slow scans
See Performance Tuning. Consider reducing wordlist and ports profile.

