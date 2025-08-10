## Reports

SentinelScope produces both JSON and polished HTML reports.

### JSON
```bash
sscan domain example.com --json out/example.json
jq '.headers.grade, .ports.open_ports' out/example.json
```

### HTML
```bash
sscan domain example.com --html out/example.html
open out/example.html
```

HTML includes:
- Summary banner with timestamps
- Security headers table + grade + score donut chart
- TLS details and warnings (e.g., impending expiry)
- Open ports table (or “none found” badge)
- Subdomain list with source counts

### Embedding in pipelines
- Store JSON artifacts for machine processing
- Publish HTML to a static site or artifact store for stakeholders

