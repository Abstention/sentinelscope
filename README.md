## SentinelScope
> Created by Josh Arbourne. Coffee optional; curiosity mandatory.

A modern, plain‑English security checkup for websites and domains. Finds subdomains, scans common ports, reviews HTTPS and DNS posture, checks headers, cookies and CORS, flags possible subdomain takeovers, and produces clean reports people actually read.

### Highlights
- **Async recon pipeline**: subdomains, ports, TLS, HTTP headers, DNS, web preview
- **Takeover heuristics**: flags potential subdomain takeovers (best-effort)
- **Actionable reporting**: clean HTML report with charts + machine-readable JSON
- **Modern stack**: Python 3.11+, FastAPI, Typer, Pydantic v2, Jinja2, Rich
- **Secure defaults**: timeouts, safe parsing, input validation
- **DX**: pre-commit (ruff, black), GitHub Actions CI, typed codebase
 - Optional Rust acceleration for port scanning (via maturin)

### Install
- macOS / Linux
  ```bash
  python3.11 -m venv .venv && source .venv/bin/activate
  pip install -U pip
  pip install -r requirements.txt
  pip install -e .  # optional for editable install
  ```
- Windows (PowerShell)
  ```powershell
  py -3.11 -m venv .venv
  .\.venv\Scripts\Activate.ps1
  python -m pip install -U pip
  pip install -r requirements.txt
  pip install -e .  # optional for editable install
  ```

### Quickstart (pick your path)
- UI (no terminal needed)
```bash
uvicorn sentinelscope.api:app --host 0.0.0.0 --port 8000
# Open http://127.0.0.1:8000/ and click Scan
```
- CLI → HTML report
```bash
sscan domain example.com --html out/report.html
# macOS: open out/report.html   Linux: xdg-open out/report.html   Windows: start out\report.html
```

Call the API (macOS/Linux):
```bash
curl -X POST 'http://localhost:8000/scan/domain' \
  -H 'Content-Type: application/json' \
  -d '{"domain":"example.com","scan_ports":true,"scan_subdomains":true,"analyze_headers":true,"analyze_tls":true}'
```
On Windows (PowerShell):
```powershell
Invoke-RestMethod -Method POST -Uri http://localhost:8000/scan/domain -ContentType 'application/json' -Body '{"domain":"example.com","scan_ports":true,"scan_subdomains":true,"analyze_headers":true,"analyze_tls":true}'
```

### Everyday usage (clean, memorable)
```bash
# Full scan, richer port profile + both outputs
sscan domain example.com --ports top100 --html out/report.html --json out/report.json

# Faster scan (skip subdomains, cookies)
sscan domain example.com --no-scan-subdomains --no-analyze-cookies --html out/quick.html

# Custom ports
sscan domain example.com --ports custom --custom-ports "22,80,443,8443"

# Focused checks
sscan headers https://example.com --json out/headers.json
sscan tls example.com --json out/tls.json
sscan ports example.com --ports top100 --json out/ports.json
sscan cors https://example.com --json out/cors.json
sscan cookies https://example.com --json out/cookies.json
sscan fingerprint https://example.com --json out/fp.json
sscan axfr example.com --json out/axfr.json
```

### Show it to a layperson (GitHub Pages demo)
Create and publish a static demo page from your latest report:
```bash
# 1) Generate a fresh HTML report
sscan domain example.com --html out/example.html

# 2) Use the richer demo template (optional) or your own report
#    a) Use curated demo page
cp docs/index.html docs/index.html  # already present (custom demo)
#    b) Or publish a live report you generated
# cp out/example.html docs/index.html

# 3) Commit and push
git add docs/index.html
git commit -m "docs: publish demo report"
git push

# 4) In GitHub → Settings → Pages → Build and deployment
#    Source: Deploy from branch
#    Branch: main /docs
# Your live report will be available at: https://<username>.github.io/<repo>/
```

Tip: Use a domain you own or a known-public domain like `example.com` for demos.

### What gets checked
- **Subdomains**: CT log enumeration via crt.sh + lightweight wordlist DNS resolution
- **Ports**: Async TCP connect scan against curated common ports
- **TLS**: Certificate subject/issuer, SANs, expiry, validity window, protocol used
- **HTTP Security Headers**: Presence/quality of CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy (graded)
- **DNS**: A/AAAA/MX/TXT posture, SPF/DMARC (with suggestions)
- **AXFR**: DNS zone transfer open? (quick check)
- **Web preview**: HTTP status/title/server/type
- **CORS**: allow‑origin/credentials risks
- **Cookies**: Secure/HttpOnly/SameSite issues
- **WAF/CDN**: light fingerprint (server/vendor hints)
- **Takeover**: common dangling signatures (best‑effort)

### Project Structure
```
sentinelscope/
  api.py           # FastAPI app
  cli.py           # Typer CLI
  models.py        # Pydantic models (v2)
  reporting/       # HTML report generator + templates
  scanning/        # Recon modules: ports, tls, http_headers, subdomains
  utils/           # Shared helpers
tests/
.github/workflows/ci.yml
docs/
  Quickstart.md
  CLI-Guide.md
  API-Guide.md
  Reports.md
  Use-Cases.md
  Performance-Tuning.md
  Troubleshooting.md
  Operational-Safety.md
  Examples.md
```

### Development
```bash
pip install -r requirements-dev.txt
pre-commit install
pytest -q
```
On Windows (PowerShell), replace `source .venv/bin/activate` with `.\.venv\Scripts\Activate.ps1`.

### Optional: Build Rust native extension
```bash
pip install maturin
maturin develop  # builds and installs the sentinelscope_rs extension for the active env
```

### Documentation
- Quickstart: docs/Quickstart.md
- CLI Guide: docs/CLI-Guide.md
- API Guide: docs/API-Guide.md
- Reports: docs/Reports.md
- Use Cases: docs/Use-Cases.md
- Performance Tuning: docs/Performance-Tuning.md
- Troubleshooting: docs/Troubleshooting.md
- Operational Safety: docs/Operational-Safety.md
- Examples: docs/Examples.md

### Security and Legal
- For authorized testing only. Always obtain permission before scanning domains you don’t own.
- MIT License. See `LICENSE`.

### Roadmap Ideas
- DNS zone transfer checks, CNAME takeovers
- Screenshots of web targets, WAF/CDN detection
- SBOM ingestion and OSV integration
- Container and IaC policy scanning

