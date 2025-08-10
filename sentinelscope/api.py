from __future__ import annotations

import asyncio
from datetime import datetime

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pathlib import Path

from sentinelscope.models import DomainScanRequest, DomainScanResult
from sentinelscope.scanning.http_headers import analyze_security_headers
from sentinelscope.scanning.ports import TOP_30_PORTS, scan_ports
from sentinelscope.scanning.subdomains import enumerate_subdomains
from sentinelscope.scanning.tls import get_tls_info
from sentinelscope.scanning.dns_records import assess_dns
from sentinelscope.scanning.web_preview import fetch_preview
from sentinelscope.scanning.takeover import check_takeover_candidates
from sentinelscope.scanning.cors import analyze_cors
from sentinelscope.scanning.cookies import analyze_cookies
from sentinelscope.scanning.fingerprint import fingerprint_web
from sentinelscope.scanning.dns_axfr import check_dns_axfr
from sentinelscope.scanning.security_txt import fetch_security_txt
from sentinelscope.scanning.mixed_content import check_mixed_content
from sentinelscope.scanning.dns_extras import gather_dns_extras


app = FastAPI(title="SentinelScope API", version="0.1.0")


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
async def ui_root():
    index = Path(__file__).parent / "web" / "index.html"
    if index.exists():
        return index.read_text(encoding="utf-8")
    return HTMLResponse("<h1>SentinelScope</h1><p>UI not built. Use /docs for API or the CLI.</p>")


@app.post("/scan/domain", response_model=DomainScanResult)
async def scan_domain(req: DomainScanRequest) -> DomainScanResult:
    started = datetime.utcnow()
    # Normalize input: accept either bare domain or full URL
    raw = req.domain.strip()
    host = raw
    if raw.startswith("http://") or raw.startswith("https://"):
        try:
            from urllib.parse import urlparse

            parsed = urlparse(raw)
            host = (parsed.hostname or raw).strip('/')
        except Exception:
            host = raw.replace("https://", "").replace("http://", "").strip('/')
    else:
        host = raw.strip('/')
    # Preserve scheme if provided; otherwise choose a sensible default
    scheme = "https"
    if raw.startswith("http://") or raw.startswith("https://"):
        try:
            from urllib.parse import urlparse

            parsed = urlparse(raw)
            if parsed.scheme in ("http", "https"):
                scheme = parsed.scheme
        except Exception:
            pass
    else:
        if host in {"localhost", "127.0.0.1", "::1"}:
            scheme = "http"
    base_url = f"{scheme}://{host}"
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

    # Schedule async tasks
    subdomains_task = asyncio.create_task(enumerate_subdomains(host)) if req.scan_subdomains else None
    ports_task = asyncio.create_task(scan_ports(host, ports_list)) if req.scan_ports else None
    headers_task = asyncio.create_task(analyze_security_headers(base_url)) if req.analyze_headers else None
    preview_task = asyncio.create_task(fetch_preview(base_url)) if req.web_preview else None
    cors_task = asyncio.create_task(analyze_cors(base_url)) if req.analyze_cors else None
    cookies_task = asyncio.create_task(analyze_cookies(base_url)) if req.analyze_cookies else None
    fp_task = asyncio.create_task(fingerprint_web(base_url)) if req.fingerprint_web else None
    sec_txt_task = asyncio.create_task(fetch_security_txt(host)) if req.check_security_txt else None
    mixed_task = asyncio.create_task(check_mixed_content(base_url)) if req.check_mixed_content else None

    # Offload blocking calls to threads
    tls_future = asyncio.to_thread(get_tls_info, host) if req.analyze_tls else None
    dns_future = asyncio.to_thread(assess_dns, host) if req.analyze_dns else None
    axfr_future = asyncio.to_thread(check_dns_axfr, host)
    dns_extra_future = asyncio.to_thread(gather_dns_extras, host) if req.check_dnssec_caa else None

    subdomains_res = await subdomains_task if subdomains_task else None
    ports_res = await ports_task if ports_task else None
    headers_res = await headers_task if headers_task else None
    preview_res = await preview_task if preview_task else None
    cors_res = await cors_task if cors_task else None
    cookies_res = await cookies_task if cookies_task else None
    fp_res = await fp_task if fp_task else None
    sec_txt_res = await sec_txt_task if sec_txt_task else None
    mixed_res = await mixed_task if mixed_task else None
    tls_info = await tls_future if tls_future else None
    dns_info = await dns_future if dns_future else None
    axfr_res = await axfr_future
    dns_extra_res = await dns_extra_future if dns_extra_future else None
    takeover_res = None
    if subdomains_res and subdomains_res.discovered:
        try:
            takeover_res = await check_takeover_candidates(subdomains_res.discovered)
        except Exception:
            takeover_res = None

    finished = datetime.utcnow()
    return DomainScanResult(
        domain=host,
        started_at=started,
        finished_at=finished,
        subdomains=subdomains_res,
        ports=ports_res,
        tls=tls_info,
        headers=headers_res,
        dns=dns_info,
        preview=preview_res,
        takeover=takeover_res,
        cors=cors_res,
        cookies=cookies_res,
        web_fingerprint=fp_res,
        dns_axfr=axfr_res,
        security_txt=sec_txt_res,
        mixed_content=mixed_res,
        dns_extras=dns_extra_res,
    )

