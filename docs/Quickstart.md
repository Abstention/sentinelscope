## Quickstart

This guide gets you from zero to running scans and producing reports in minutes.

### Prerequisites
- Python 3.11+
- macOS/Linux/WSL recommended

### Install
```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e . -r requirements-dev.txt
```

### Verify
```bash
pytest -q
```
Expected: `3 passed`

### First scan (domain)
```bash
sscan domain example.com --json out/example.json --html out/example.html
open out/example.html  # macOS (use xdg-open on Linux)
```

What happens:
- Subdomains enumerated via crt.sh + lightweight DNS wordlist
- Common ports scanned asynchronously
- HTTPS security headers analyzed and graded
- TLS certificate parsed and expiry checked

### Targeted scans
```bash
# Headers only
sscan headers https://example.com --json out/headers.json

# TLS only
sscan tls example.com --json out/tls.json

# Ports only (top 100 profile)
sscan ports example.com --ports top100 --json out/ports.json

# Custom port list
sscan ports example.com --ports custom --custom-ports "22,80,443,8443"
```

### Run the API
```bash
uvicorn sentinelscope.api:app --host 0.0.0.0 --port 8000
```
Open API docs in your browser: `http://localhost:8000/docs`

Trigger a scan via API:
```bash
curl -sX POST http://localhost:8000/scan/domain \
  -H 'Content-Type: application/json' \
  -d '{"domain":"example.com","scan_ports":true,"scan_subdomains":true,"analyze_headers":true,"analyze_tls":true}' \
  | jq .
```

### Safety
- For authorized targets only. Always obtain explicit permission.
- Keep concurrency modest on fragile networks. SentinelScope uses safe defaults.

