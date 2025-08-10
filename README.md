## SentinelScope
> Created by Josh Arbourne. Coffee optional; curiosity mandatory.

Advanced attack surface recon and security reporting toolkit. It discovers subdomains, scans common ports, reviews HTTPS and DNS posture, and produces a polished HTML report anyone can read. Built with a CLI, REST API, tests, and CI. It’s the neat, friendly report you show your boss — without the panic.

### Highlights
- **Async recon pipeline**: subdomains, ports, TLS, HTTP headers, DNS, web preview
- **Takeover heuristics**: flags potential subdomain takeovers (best-effort)
- **Actionable reporting**: clean HTML report with charts + machine-readable JSON
- **Modern stack**: Python 3.11+, FastAPI, Typer, Pydantic v2, Jinja2, Rich
- **Secure defaults**: timeouts, safe parsing, input validation
- **DX**: pre-commit (ruff, black), GitHub Actions CI, typed codebase
 - Optional Rust acceleration for port scanning (via maturin)

### Install
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install -e .  # optional for editable install
```

### Quickstart
Generate a one-page HTML report:
```bash
sscan domain example.com --html out/example.html
open out/example.html  # macOS
```

Run the API server:
```bash
uvicorn sentinelscope.api:app --host 0.0.0.0 --port 8000
```

Call the API:
```bash
curl -X POST 'http://localhost:8000/scan/domain' \
  -H 'Content-Type: application/json' \
  -d '{"domain":"example.com","scan_ports":true,"scan_subdomains":true,"analyze_headers":true,"analyze_tls":true}'
```

### CLI Usage
```bash
sscan --help

sscan domain DOMAIN [--ports top100|top30|custom --custom-ports "80,443,8080" \
                     --json out.json --html out.html]

sscan headers URL [--json out.json]
sscan tls DOMAIN [--json out.json]
sscan ports HOST [--ports top100|top30|custom --custom-ports "22,80,443" --json out.json]
```

### Show it to a layperson (GitHub Pages demo)
Create and publish a static demo page from your latest report:
```bash
# 1) Generate a fresh HTML report
sscan domain example.com --html out/example.html

# 2) Copy to docs/ and push
mkdir -p docs
cp out/example.html docs/index.html
git add docs/index.html
git commit -m "docs: publish demo report"
git push

# 3) In GitHub → Settings → Pages → Build and deployment
#    Source: Deploy from branch
#    Branch: main /docs
# Your live report will be available at: https://<username>.github.io/<repo>/
```

Tip: Use a domain you own or a known-public domain like `example.com` for demos.

### What gets checked
- **Subdomains**: CT log enumeration via crt.sh + lightweight wordlist DNS resolution
- **Ports**: Async TCP connect scan against curated common ports
- **TLS**: Certificate subject/issuer, SANs, expiry, validity window, protocol used
- **HTTP Security Headers**: Presence/quality of CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, etc., with a letter grade
- **DNS**: A/AAAA/MX/TXT posture, SPF/DMARC presence and recommendations
- **Web Preview**: HTTP status, title, server, content-type
- **Takeover**: Heuristic signatures for common providers

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

