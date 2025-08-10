from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from sentinelscope.models import DomainScanResult
from sentinelscope.reporting.html import write_html_report
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
from datetime import datetime


app = typer.Typer(
    add_completion=False,
    help=(
        "SentinelScope – run fast, readable security checkups. "
        "Full scans (domain) or targeted checks (headers/tls/ports)."
    ),
)
console = Console()


def _resolve_ports(profile: str, custom: Optional[str]) -> list[int]:
    if profile == "top30":
        return TOP_30_PORTS
    if profile == "top100":
        # Basic extension of common ports
        extra = [
            19, 37, 49, 88, 161, 162, 389, 636, 873, 1025,
            1433, 1521, 2049, 2082, 2083, 2086, 2087, 2483, 2484, 3268,
            3269, 4444, 5000, 5001, 5060, 5222, 5900, 5985, 5986, 8081,
            9000, 9090, 9200, 9300, 11211, 27017, 27018, 27019, 6379, 6380,
        ]
        return sorted(set(TOP_30_PORTS + extra))
    if profile == "custom":
        if not custom:
            raise typer.BadParameter("--custom-ports must be provided when --ports=custom")
        return [int(x.strip()) for x in custom.split(",") if x.strip()]
    raise typer.BadParameter("--ports must be one of: top30, top100, custom")


@app.command()
def domain(
    domain: str = typer.Argument(..., help="Domain to scan, e.g., example.com"),
    ports: str = typer.Option(
        "top30", "--ports", help="Port profile: top30, top100, custom"
    ),
    custom_ports: Optional[str] = typer.Option(None, "--custom-ports", help="CSV of ports"),
    json_out: Optional[Path] = typer.Option(None, "--json", help="Write JSON to path"),
    html_out: Optional[Path] = typer.Option(None, "--html", help="Write HTML report to path"),
    scan_subdomains: bool = typer.Option(True, "--scan-subdomains/--no-scan-subdomains", help="Enumerate subdomains (CT + DNS)", show_default=True),
    scan_ports: bool = typer.Option(True, "--scan-ports/--no-scan-ports", help="Scan common ports", show_default=True),
    analyze_headers: bool = typer.Option(True, "--analyze-headers/--no-analyze-headers", help="Analyze HTTP security headers", show_default=True),
    analyze_tls: bool = typer.Option(True, "--analyze-tls/--no-analyze-tls", help="Collect TLS info", show_default=True),
    analyze_dns: bool = typer.Option(True, "--analyze-dns/--no-analyze-dns", help="Assess DNS + SPF/DMARC", show_default=True),
    web_preview: bool = typer.Option(True, "--web-preview/--no-web-preview", help="Fetch basic web preview", show_default=True),
    analyze_cors_opt: bool = typer.Option(True, "--analyze-cors/--no-analyze-cors", help="Assess CORS policy", show_default=True),
    analyze_cookies_opt: bool = typer.Option(True, "--analyze-cookies/--no-analyze-cookies", help="Check cookie security flags", show_default=True),
    fingerprint_web_opt: bool = typer.Option(True, "--fingerprint-web/--no-fingerprint-web", help="Detect WAF/CDN and server", show_default=True),
):
    """Run a full domain scan and optionally emit JSON/HTML reports.

    Examples:
      - Full scan (HTML + JSON):
        sscan domain example.com --ports top100 --html out/report.html --json out/report.json

      - Disable subdomains and cookies to go faster:
        sscan domain example.com --no-scan-subdomains --no-analyze-cookies --html out/quick.html

      - Use a custom port set:
        sscan domain example.com --ports custom --custom-ports "22,80,443,8443"
    """
    async def _run():
        started = datetime.utcnow()
        ports_list = _resolve_ports(ports, custom_ports)

        console.rule(f"[bold]Scanning {domain}")

        subdomains_task = enumerate_subdomains(domain) if scan_subdomains else None
        ports_task = scan_ports(domain, ports_list) if scan_ports else None
        tls_info = get_tls_info(domain) if analyze_tls else None
        headers_task = analyze_security_headers(f"https://{domain}") if analyze_headers else None
        dns_info = assess_dns(domain) if analyze_dns else None
        preview_task = fetch_preview(f"https://{domain}") if web_preview else None

        subdomains = await subdomains_task if subdomains_task else None
        ports_res = await ports_task if ports_task else None
        headers = await headers_task if headers_task else None
        preview = await preview_task if preview_task else None

        takeover = None
        try:
            takeover = await check_takeover_candidates(subdomains.discovered)
        except Exception:
            takeover = None

        cors_res = await analyze_cors(f"https://{domain}") if analyze_cors_opt else None
        cookies_res = await analyze_cookies(f"https://{domain}") if analyze_cookies_opt else None
        fp = await fingerprint_web(f"https://{domain}") if fingerprint_web_opt else None
        axfr = check_dns_axfr(domain)

        finished = datetime.utcnow()
        result = DomainScanResult(
            domain=domain,
            started_at=started,
            finished_at=finished,
            subdomains=subdomains,
            ports=ports_res,
            tls=tls_info,
            headers=headers,
            dns=dns_info,
            preview=preview,
            takeover=takeover,
            cors=cors_res,
            cookies=cookies_res,
            web_fingerprint=fp,
            dns_axfr=axfr,
        )

        # Console summary
        table = Table(title=f"Summary for {domain}")
        table.add_column("Item")
        table.add_column("Value")
        table.add_row("Open ports", str(len(result.ports.open_ports) if result.ports else 0))
        table.add_row("Subdomains", str(len(result.subdomains.discovered) if result.subdomains else 0))
        table.add_row("TLS protocol", result.tls.protocol if result.tls and result.tls.protocol else "n/a")
        table.add_row("Headers grade", result.headers.grade if result.headers else "n/a")
        table.add_row("SPF present", str(result.dns.spf_present if result.dns else False))
        table.add_row("DMARC policy", result.dns.dmarc_policy if result.dns else "n/a")
        table.add_row("AXFR open NS", str(len(result.dns_axfr.axfr_allowed_on) if result.dns_axfr else 0))
        table.add_row("CORS allow-origin", result.cors.allow_origin if result.cors else "n/a")
        console.print(table)

        if json_out:
            json_out.parent.mkdir(parents=True, exist_ok=True)
            json_out.write_text(result.model_dump_json(indent=2))
            console.print(f"[green]Wrote JSON[/green] {json_out}")
        if html_out:
            write_html_report(result, html_out)
            console.print(f"[green]Wrote HTML[/green] {html_out}")

    asyncio.run(_run())


@app.command()
def headers(url: str, json_out: Optional[Path] = typer.Option(None, "--json")):
    """Analyze HTTP security headers and output a grade and recommendations.

    Example:
      sscan headers https://example.com --json out/headers.json
    """
    async def _run():
        res = await analyze_security_headers(url)
        console.print(res)
        if json_out:
            json_out.parent.mkdir(parents=True, exist_ok=True)
            json_out.write_text(res.model_dump_json(indent=2))
    asyncio.run(_run())


@app.command()
def tls(domain: str, json_out: Optional[Path] = typer.Option(None, "--json")):
    """Inspect TLS certificate validity, issuer/subject, SANs, and protocol.

    Example:
      sscan tls example.com --json out/tls.json
    """
    info = get_tls_info(domain)
    console.print(info)
    if json_out:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(info.model_dump_json(indent=2))


@app.command()
def ports(
    host: str,
    ports: str = typer.Option("top30", "--ports"),
    custom_ports: Optional[str] = typer.Option(None, "--custom-ports"),
    json_out: Optional[Path] = typer.Option(None, "--json"),
):
    """Scan common TCP ports using async connect checks.

    Examples:
      - Top 100:
        sscan ports example.com --ports top100
      - Custom list:
        sscan ports example.com --ports custom --custom-ports "22,80,443"
    """
    async def _run():
        plist = _resolve_ports(ports, custom_ports)
        res = await scan_ports(host, plist)
        console.print(res)
        if json_out:
            json_out.parent.mkdir(parents=True, exist_ok=True)
            json_out.write_text(res.model_dump_json(indent=2))
    asyncio.run(_run())


@app.command()
def cors(url: str, json_out: Optional[Path] = typer.Option(None, "--json")):
    """Check CORS policy for a URL (allow-origin/credentials, common risks).

    Example:
      sscan cors https://example.com --json out/cors.json
    """
    async def _run():
        res = await analyze_cors(url)
        console.print(res)
        if json_out:
            json_out.parent.mkdir(parents=True, exist_ok=True)
            json_out.write_text(res.model_dump_json(indent=2))
    asyncio.run(_run())


@app.command()
def cookies(url: str, json_out: Optional[Path] = typer.Option(None, "--json")):
    """Inspect Set-Cookie flags (Secure/HttpOnly/SameSite) and highlight issues.

    Example:
      sscan cookies https://example.com --json out/cookies.json
    """
    async def _run():
        res = await analyze_cookies(url)
        console.print(res)
        if json_out:
            json_out.parent.mkdir(parents=True, exist_ok=True)
            json_out.write_text(res.model_dump_json(indent=2))
    asyncio.run(_run())


@app.command()
def fingerprint(url: str, json_out: Optional[Path] = typer.Option(None, "--json")):
    """Detect server banner and common WAF/CDN fingerprints.

    Example:
      sscan fingerprint https://example.com --json out/fingerprint.json
    """
    async def _run():
        res = await fingerprint_web(url)
        console.print(res)
        if json_out:
            json_out.parent.mkdir(parents=True, exist_ok=True)
            json_out.write_text(res.model_dump_json(indent=2))
    asyncio.run(_run())


@app.command()
def axfr(domain: str, json_out: Optional[Path] = typer.Option(None, "--json")):
    """Check if DNS zone transfer (AXFR) is allowed on any authoritative nameserver.

    Example:
      sscan axfr example.com --json out/axfr.json
    """
    res = check_dns_axfr(domain)
    console.print(res)
    if json_out:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(res.model_dump_json(indent=2))


def main():  # entrypoint
    app()


if __name__ == "__main__":
    main()

