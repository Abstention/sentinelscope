## Performance Tuning

The defaults are conservative. You can increase speed safely with care.

### Ports scan
- Current defaults: concurrency ~200, timeout 1s
- For fast networks: raise concurrency to 500–1000 and lower timeout to 0.5s in code if required

### Subdomains
- DNS resolution concurrency ~50; increase to 100–200 with reliable DNS
- Add more wordlist entries for depth (at cost of time)

### HTTP headers
- Already fast; consider batching multiple URLs via shell loops

### API workers
Use uvicorn workers for parallel scans:
```bash
uvicorn sentinelscope.api:app --host 0.0.0.0 --port 8000 --workers 4
```

### Resource considerations
- Avoid overloading targets; throttle in sensitive environments
- In CI, shard targets across jobs

