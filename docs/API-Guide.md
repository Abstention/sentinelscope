## API Guide

The FastAPI app exposes a REST endpoint to kick off scans.

### Start server
```bash
uvicorn sentinelscope.api:app --host 0.0.0.0 --port 8000
```

### OpenAPI docs
Visit `http://localhost:8000/docs` to explore and try requests.

### Endpoints
- `GET /health`: Health check
- `POST /scan/domain`: Run a domain scan

### Domain scan request
```json
{
  "domain": "example.com",
  "scan_ports": true,
  "scan_subdomains": true,
  "analyze_headers": true,
  "analyze_tls": true,
  "analyze_dns": true,
  "web_preview": true,
  "port_profile": "top30",
  "custom_ports": null
}
```

Example cURL:
```bash
curl -sX POST http://localhost:8000/scan/domain \
  -H 'Content-Type: application/json' \
  -d '{"domain":"example.com","scan_ports":true,"scan_subdomains":true,"analyze_headers":true,"analyze_tls":true}' \
  | jq '.headers.grade, .ports.open_ports'
```

### Response
Returns `DomainScanResult` with:
- `subdomains`, `ports`, `tls`, `headers`
- `dns` (SPF/DMARC, A/AAAA/MX/TXT)
- `preview` (status/title/server/content-type)
- `takeover` (flagged subdomains)

