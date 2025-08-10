## Troubleshooting

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

### HTML report missing
Ensure templates packaged:
```bash
pip install -e .
```

### Slow scans
See Performance Tuning. Consider reducing wordlist and ports profile.

