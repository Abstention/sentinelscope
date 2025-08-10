## Real-world Use Cases

### 1) Attack surface recon for a new acquisition
Goal: get a quick snapshot of public exposure.
```bash
sscan domain acquired-corp.com --ports top100 --json out/acquired.json --html out/acquired.html
```
Actions:
- Review open ports for risky services (e.g., RDP, databases)
- Check TLS expiry for soon-to-expire certs
- Scan discovered subdomains individually if needed

### 2) Continuous monitoring in CI/CD
Run a nightly job and compare results.
```bash
sscan domain product.example --json out/nightly.json
jq '.ports.open_ports, .headers.grade, .tls.days_until_expiry' out/nightly.json
```
Alert when:
- New open ports appear
- Headers grade drops
- TLS expiry < 30 days

### 3) Hardening a web application
```bash
sscan headers https://shop.example.com --json out/headers.json
jq '.findings[] | select(.recommendation != null)' out/headers.json
```
Implement recommendations, then re-run.

### 4) Perimeter changes validation
After firewall or CDN updates:
```bash
sscan ports edge.example.com --ports custom --custom-ports "80,443,8443,9000"
```
Validate only intended ports are exposed.

