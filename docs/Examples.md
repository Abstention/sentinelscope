## Examples
Copy, paste, impress.

### 1) Baseline a marketing site
```bash
sscan domain www.brand.example --json out/brand.json --html out/brand.html
jq '.headers.grade, .ports.open_ports' out/brand.json
```

### 2) Find weak headers across multiple hosts
```bash
for url in https://app.example https://admin.example https://api.example; do
  sscan headers "$url" --json - | jq -r "\(.url) -> \(.grade)"
done
```

### 3) TLS expiry watch
```bash
for d in example.com shop.example.com api.example.com; do
  sscan tls "$d" --json - | jq -r '"\(.domain) -> \(.days_until_expiry // "n/a") days"'
done
```

### 4) CI pipeline snippet (GitHub Actions)
```yaml
jobs:
  recon:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.11' }
      - run: |
          pip install -e .
          sscan domain example.com --json out/report.json --html out/report.html
      - uses: actions/upload-artifact@v4
        with:
          name: sscope-report
          path: out/
```

### 5) Mail posture snapshot
```bash
sscan domain example.com --json out/mail.json
jq '{spf_present: .dns.spf_present, spf_policy: .dns.spf_policy, dmarc: .dns.dmarc_policy}' out/mail.json
```

### 6) Takeover signatures to CSV
```bash
sscan domain example.com --json - | jq -r '.takeover.flagged[] | "\(.subdomain),\(.reason)"' > flagged.csv
```

