# SentinelScope
> A fast, plain‑English security checkup for websites and domains. Focused, readable, safe by default.

SentinelScope runs a practical security health check against a target domain. It looks for the things people most often miss: weak HTTP security headers, soon‑to‑expire TLS certs, risky cookies and CORS, loose DNS posture (SPF/DMARC), open common ports, and potential subdomain takeover signals. Results are easy to read, ship well in PRs, and can be handed to non‑security teammates without translation.

Think of it as a thoughtful safety checklist, not a noisy scanner.

---

## Who this is for
- Maintainers who want a quick “Are we OK?” before shipping
- SREs/Platform teams doing hygiene checks on services and vanity domains
- Security engineers automating baseline controls
- Product teams who need a shareable report for stakeholders

If you own a domain or service and want an honest, actionable assessment in minutes, this is for you.

---

## What SentinelScope checks
- Subdomains: Certificate Transparency (crt.sh) + small DNS wordlist probe
- Ports: Async TCP connect scan against curated common ports
- TLS: Protocol, issuer/subject, SANs, validity window, expiry warnings
- HTTP Security Headers: Presence and quality (graded score + recommendations)
- DNS posture: A/AAAA/MX/TXT, SPF/DMARC detection and suggestions
- AXFR: Zone transfer exposure on authoritative nameservers
- Web preview: Status, title, server banner, content type
- CORS: allow‑origin + credentials risks
- Cookies: Secure/HttpOnly/SameSite flags and issues
- WAF/CDN: Lightweight fingerprint from response headers

Output formats:
- HTML report people will actually read
- JSON for pipelines and storage
- FastAPI endpoint for programmatic use

---

## Install
Requires Python 3.11+ on macOS, Linux, or Windows.

```bash
python3.11 -m venv .venv && source .venv/bin/activate
python -m pip install -U pip
pip install -r requirements.txt
pip install -e .   # optional editable install for development
```

Windows (PowerShell):
```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip
pip install -r requirements.txt
pip install -e .
```

Optional native acceleration (Rust) for port scanning:
```bash
pip install maturin
maturin develop  # builds and installs sentinelscope_rs for the active env
```

---

## Quickstart
### Run the web UI (no terminal expertise needed)
```bash
uvicorn sentinelscope.api:app --host 0.0.0.0 --port 8000
# Open http://127.0.0.1:8000/
# Interactive API docs are at http://127.0.0.1:8000/docs
```

### One‑liner report from the CLI
```bash
sscan domain example.com --html out/report.html --json out/report.json
# macOS: open out/report.html   Linux: xdg-open out/report.html   Windows: start out\report.html
```

---

## CLI usage you’ll actually remember
Global:
```bash
sscan --help
sscan --version
```

Full domain scan (sensible defaults):
```bash
sscan domain example.com
```

Faster scan (skip subdomains/cookies):
```bash
sscan domain example.com --no-scan-subdomains --no-analyze-cookies
```

Custom ports and richer profile:
```bash
sscan domain example.com --ports top100
sscan domain example.com --ports custom --custom-ports "22,80,443,8443"
```

Tune timeouts and concurrency:
```bash
# HTTP timeouts (headers, cookies, cors, fingerprint, preview, security.txt)
sscan domain example.com --timeout 8

# DNS resolution timeout for subdomain enumeration
sscan domain example.com --dns-timeout 3

# TCP connect concurrency for port scan (higher is faster; be respectful)
sscan domain example.com --concurrency 500
```

Targeted checks:
```bash
sscan headers https://example.com --json out/headers.json
sscan tls example.com --json out/tls.json
sscan ports example.com --ports top100 --json out/ports.json
sscan cors https://example.com --json out/cors.json
sscan cookies https://example.com --json out/cookies.json
sscan fingerprint https://example.com --json out/fp.json
sscan axfr example.com --json out/axfr.json
```

---

## API usage (FastAPI)
Start the API:
```bash
uvicorn sentinelscope.api:app --reload
```

Health and docs:
- GET /health → `{ "status": "ok" }`
- Swagger UI: `/docs`

Example scan request:
```bash
curl -sS -X POST http://127.0.0.1:8000/scan/domain \
  -H 'Content-Type: application/json' \
  -d '{
        "domain":"example.com",
        "scan_ports":true,
        "scan_subdomains":true,
        "analyze_headers":true,
        "analyze_tls":true,
        "analyze_dns":true,
        "web_preview":true,
        "analyze_cors":true,
        "analyze_cookies":true,
        "fingerprint_web":true,
        "check_security_txt":true,
        "check_mixed_content":true,
        "check_dnssec_caa":true,
        "port_profile":"top30"
      }'
```

---

## How it works (design notes)
- Async first: HTTP checks run concurrently; DNS and ports are bounded by semaphores for stability
- Safe network defaults: conservative timeouts; graceful error handling returns neutral results instead of crashing
- Clear models (Pydantic v2): strongly typed results ready for JSON and templating
- Readable reports: a single HTML file with a compact summary, actionable hints, and supporting detail
- Optional Rust: if available, port scanning uses the native extension for speed

---

## What “good” looks like
- Headers: CSP, HSTS (includeSubDomains; preload), X‑Content‑Type‑Options, X‑Frame‑Options, Referrer‑Policy, Permissions‑Policy → A/A+ grade
- TLS: modern protocol, issuer you expect, expiry > 30 days, SANs cover your hostnames
- DNS: SPF present with `-all` or `~all`; DMARC policy `quarantine`/`reject`
- Ports: only what you really need (typically 80/443 for websites)
- CORS: no wildcard with credentials; tight origins if needed at all
- Cookies: Secure + HttpOnly + SameSite

The report highlights gaps and includes plain‑English recommendations.

---

## Performance tuning (responsibly)
- Increase `--concurrency` for faster port scans (default 200). Observe rate limits; don’t scan networks you don’t own.
- Use `--timeout` and `--dns-timeout` to adapt to slower networks.
- Prefer `--ports top100` only when you need deeper coverage.
- Build the Rust extension (`maturin develop`) for the fastest port checks.

See also: `docs/Performance-Tuning.md` and `docs/Operational-Safety.md`.

---

## Safety, scope, and consent
SentinelScope is intended for authorized testing of domains and services you own or explicitly control. Obtain permission before scanning. Respect terms of service and laws in your jurisdiction. The tool is designed to be gentle, but any network scanner can cause load. Use sane timeouts, limit concurrency, and be a good neighbor.

See: `docs/Operational-Safety.md` and `docs/Troubleshooting.md`.

---

## Outputs
- HTML: polished, dark‑mode friendly report at `out/report.html`
- JSON: structured output for automation

Tip: pipe JSON to other tools
```bash
sscan domain example.com --json - | jq '.ports.open_ports'
```

---

## Development
```bash
pip install -r requirements-dev.txt
pre-commit install
pytest -q
```
Coding standards:
- Type hints everywhere; avoid mutable default arguments
- Prefer small, testable functions
- Handle errors explicitly and return neutral results on network errors

Project structure:
```
sentinelscope/
  api.py           # FastAPI app (web UI + API)
  cli.py           # Typer CLI (sscan)
  models.py        # Pydantic v2 models
  reporting/       # Jinja2 HTML templates
  scanning/        # Ports, TLS, headers, DNS, subdomains, etc.
  web/             # Minimal single-page UI
```

---

## Versioning and license
- Version: `sscan --version`
- License: MIT (see `LICENSE`)

## Credits
Created by Josh Arbourne. Contributions welcome.

If this helped you catch something before it reached prod, that was the point.
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

### CLI flags you’ll use often
```bash
# Tune network timeouts for HTTP requests and DNS
sscan domain example.com --timeout 8 --dns-timeout 3

# Increase TCP connect concurrency for port scanning
sscan domain example.com --concurrency 500

# Quickly check the version
sscan --version
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

