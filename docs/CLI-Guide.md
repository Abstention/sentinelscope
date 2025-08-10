## CLI Guide
We love CLIs because buttons are shy.

SentinelScope ships with a Typer-based CLI `sscan`.

### Help
If you’re lost, `--help` is your compass.
```bash
sscan --help
```

### Full domain scan
```bash
sscan domain example.com \
  --ports top30 \
  --timeout 6 \
  --dns-timeout 2 \
  --concurrency 200 \
  --json out/example.json \
  --html out/example.html
```

Options:
- `--ports`: `top30`, `top100`, or `custom`
- `--custom-ports`: CSV list, e.g., `"22,80,443,8443"` (required when `--ports custom`)
- `--timeout`: HTTP request timeout in seconds (affects headers, cookies, cors, fingerprint, preview, security.txt)
- `--dns-timeout`: DNS lookup timeout in seconds (affects subdomain enumeration)
- `--concurrency`: Max concurrent TCP connects for port scanning

Outputs include:
- DNS: A/AAAA/MX/TXT, SPF/DMARC posture
- Web Preview: status code, title, server, content-type
- Takeover: flagged subdomains with provider signatures

### Individual commands
```bash
# Security headers
sscan headers https://shop.example.com --json out/headers.json

# TLS
sscan tls shop.example.com --json out/tls.json

# Ports
sscan ports shop.example.com --ports top100 --json out/ports.json
```

### Version
```bash
sscan --version
```

### Exit codes
- `0`: success
- `1`: unexpected error

### Tips
- Use `python3.11 -m sentinelscope.cli ...` if your shell cannot find `sscan`
- Pipe JSON to tools:
  ```bash
  sscan domain example.com --json - | jq '.ports.open_ports'
  ```

