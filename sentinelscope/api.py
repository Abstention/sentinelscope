from __future__ import annotations

import asyncio
from datetime import datetime

from fastapi import FastAPI

from sentinelscope.models import DomainScanRequest, DomainScanResult
from sentinelscope.scanning.http_headers import analyze_security_headers
from sentinelscope.scanning.ports import TOP_30_PORTS, scan_ports
from sentinelscope.scanning.subdomains import enumerate_subdomains
from sentinelscope.scanning.tls import get_tls_info
from sentinelscope.scanning.dns_records import assess_dns
from sentinelscope.scanning.web_preview import fetch_preview
from sentinelscope.scanning.takeover import check_takeover_candidates


app = FastAPI(title="SentinelScope API", version="0.1.0")


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/scan/domain", response_model=DomainScanResult)
async def scan_domain(req: DomainScanRequest) -> DomainScanResult:
    started = datetime.utcnow()
    ports_list = TOP_30_PORTS
    if req.port_profile == "top100":
        # Keep in sync with CLI; basic extension
        ports_list = sorted(set(TOP_30_PORTS + [
            19, 37, 49, 88, 161, 162, 389, 636, 873, 1025,
            1433, 1521, 2049, 2082, 2083, 2086, 2087, 2483, 2484, 3268,
            3269, 4444, 5000, 5001, 5060, 5222, 5900, 5985, 5986, 8081,
            9000, 9090, 9200, 9300, 11211, 27017, 27018, 27019, 6379, 6380,
        ]))
    elif req.port_profile == "custom" and req.custom_ports:
        ports_list = sorted(set(req.custom_ports))

    subdomains_task = enumerate_subdomains(req.domain) if req.scan_subdomains else None
    ports_task = scan_ports(req.domain, ports_list) if req.scan_ports else None
    headers_task = analyze_security_headers(f"https://{req.domain}") if req.analyze_headers else None
    tls_info = get_tls_info(req.domain) if req.analyze_tls else None
    dns_info = assess_dns(req.domain) if req.analyze_dns else None
    preview_task = fetch_preview(f"https://{req.domain}") if req.web_preview else None

    subdomains_res = await subdomains_task if subdomains_task else None
    ports_res = await ports_task if ports_task else None
    headers_res = await headers_task if headers_task else None
    preview_res = await preview_task if preview_task else None
    takeover_res = None
    if subdomains_res:
        try:
            takeover_res = await check_takeover_candidates(subdomains_res.discovered)
        except Exception:
            takeover_res = None

    finished = datetime.utcnow()
    return DomainScanResult(
        domain=req.domain,
        started_at=started,
        finished_at=finished,
        subdomains=subdomains_res,
        ports=ports_res,
        tls=tls_info,
        headers=headers_res,
        dns=dns_info,
        preview=preview_res,
        takeover=takeover_res,
    )

