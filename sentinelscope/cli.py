from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from sentinelscope.models import DomainScanResult
from sentinelscope import __version__
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
from sentinelscope.scanning.security_txt import fetch_security_txt
from sentinelscope.scanning.mixed_content import check_mixed_content
from sentinelscope.scanning.dns_extras import gather_dns_extras
from datetime import datetime


app = typer.Typer(
    add_completion=False,
    help=(
        "SentinelScope – run fast, readable security checkups. "
        "Full scans (domain) or targeted checks (headers/tls/ports)."
    ),
)
console = Console()


def _version_callback(value: bool):
    if value:
        typer.echo(f"SentinelScope {__version__}")
        raise typer.Exit()


@app.callback()
def _main_callback(
    version: bool = typer.Option(  # type: ignore[assignment]
        False,
        "--version",
        help="Show version and exit",
        is_eager=True,
        callback=_version_callback,
    ),
):
    return


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
    do_scan_subdomains: bool = typer.Option(True, "--scan-subdomains/--no-scan-subdomains", help="Enumerate subdomains (CT + DNS)", show_default=True),
    do_scan_ports: bool = typer.Option(True, "--scan-ports/--no-scan-ports", help="Scan common ports", show_default=True),
    analyze_headers: bool = typer.Option(True, "--analyze-headers/--no-analyze-headers", help="Analyze HTTP security headers", show_default=True),
    analyze_tls: bool = typer.Option(True, "--analyze-tls/--no-analyze-tls", help="Collect TLS info", show_default=True),
    analyze_dns: bool = typer.Option(True, "--analyze-dns/--no-analyze-dns", help="Assess DNS + SPF/DMARC", show_default=True),
    web_preview: bool = typer.Option(True, "--web-preview/--no-web-preview", help="Fetch basic web preview", show_default=True),
    analyze_cors_opt: bool = typer.Option(True, "--analyze-cors/--no-analyze-cors", help="Assess CORS policy", show_default=True),
    analyze_cookies_opt: bool = typer.Option(True, "--analyze-cookies/--no-analyze-cookies", help="Check cookie security flags", show_default=True),
    fingerprint_web_opt: bool = typer.Option(True, "--fingerprint-web/--no-fingerprint-web", help="Detect WAF/CDN and server", show_default=True),
    check_security_txt_opt: bool = typer.Option(True, "--check-security-txt/--no-check-security-txt", help="Look for security.txt", show_default=True),
    check_mixed_content_opt: bool = typer.Option(True, "--check-mixed-content/--no-check-mixed-content", help="Scan for insecure http references", show_default=True),
    check_dnssec_caa_opt: bool = typer.Option(True, "--check-dnssec-caa/--no-check-dnssec-caa", help="Query DNSSEC and CAA records", show_default=True),
    concurrency: int = typer.Option(200, "--concurrency", min=1, help="Max concurrent port connections"),
    timeout: float = typer.Option(6.0, "--timeout", min=0.1, help="Network timeout (seconds) for HTTP checks"),
    dns_timeout: float = typer.Option(2.0, "--dns-timeout", min=0.1, help="DNS resolution timeout (seconds)"),
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
        # Normalize input: accept either bare domain or full URL
        raw = domain.strip()
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
        # Preserve scheme if provided; default to https
        scheme = "https"
        if raw.startswith("http://") or raw.startswith("https://"):
            try:
                from urllib.parse import urlparse

                parsed = urlparse(raw)
                if parsed.scheme in ("http", "https"):
                    scheme = parsed.scheme
            except Exception:
                pass
        base_url = f"{scheme}://{host}"
        ports_list = _resolve_ports(ports, custom_ports)

        console.rule(f"[bold]Scanning {host}")

        # Schedule async tasks where possible
        subdomains_task = enumerate_subdomains(host, dns_timeout=dns_timeout, http_timeout=timeout) if do_scan_subdomains else None
        ports_task = scan_ports(host, ports_list, concurrency=concurrency, timeout=1.0) if do_scan_ports else None
        headers_task = analyze_security_headers(base_url, timeout=timeout) if analyze_headers else None
        preview_task = fetch_preview(base_url, timeout=timeout) if web_preview else None

        subdomains = await subdomains_task if subdomains_task else None
        ports_res = await ports_task if ports_task else None
        headers = await headers_task if headers_task else None
        preview = await preview_task if preview_task else None

        takeover = None
        if subdomains and subdomains.discovered:
            try:
                takeover = await check_takeover_candidates(subdomains.discovered)
            except Exception:
                takeover = None

        cors_res = await analyze_cors(base_url, timeout=timeout) if analyze_cors_opt else None
        cookies_res = await analyze_cookies(base_url, timeout=timeout) if analyze_cookies_opt else None
        fp = await fingerprint_web(base_url, timeout=timeout) if fingerprint_web_opt else None
        axfr = check_dns_axfr(host)
        sec_txt = await fetch_security_txt(host, timeout=timeout) if check_security_txt_opt else None
        mixed = await check_mixed_content(base_url, timeout=timeout) if check_mixed_content_opt else None
        dns_extra = gather_dns_extras(host) if check_dnssec_caa_opt else None

        finished = datetime.utcnow()
        result = DomainScanResult(
            domain=host,
            started_at=started,
            finished_at=finished,
            subdomains=subdomains,
            ports=ports_res,
            tls=get_tls_info(host, timeout=timeout) if analyze_tls else None,
            headers=headers,
            dns=assess_dns(host) if analyze_dns else None,
            preview=preview,
            takeover=takeover,
            cors=cors_res,
            cookies=cookies_res,
            web_fingerprint=fp,
            dns_axfr=axfr,
            security_txt=sec_txt,
            mixed_content=mixed,
            dns_extras=dns_extra,
        )

        # Console summary
        table = Table(title=f"Summary for {domain}")
        table.add_column("Item")
        table.add_column("Value")
        table.add_row("Open ports", str(len(result.ports.open_ports) if result.ports else 0))
        table.add_row("Subdomains", str(len(result.subdomains.discovered) if result.subdomains else 0))
        table.add_row("TLS protocol", result.tls.protocol if result.tls and result.tls.protocol else "n/a")
        table.add_row("Headers grade", result.headers.grade if (result.headers and result.headers.grade) else "n/a")
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
def interactive():
    """Guide you through an interactive scan setup and run it."""
    # Inputs
    domain_in = typer.prompt("Domain (e.g., example.com or https://...)", type=str)
    ports_choice = typer.prompt("Port profile [top30/top100/custom]", default="top30")
    if ports_choice not in {"top30", "top100", "custom"}:
        raise typer.BadParameter("ports must be one of: top30, top100, custom")
    custom_ports = None
    if ports_choice == "custom":
        custom_ports = typer.prompt("Custom ports CSV (e.g., 22,80,443)", default="22,80,443")

    do_scan_subdomains = typer.confirm("Scan subdomains?", default=True)
    do_scan_ports = typer.confirm("Scan ports?", default=True)
    analyze_headers = typer.confirm("Analyze HTTP security headers?", default=True)
    analyze_tls = typer.confirm("Analyze TLS?", default=True)
    analyze_dns = typer.confirm("Analyze DNS (SPF/DMARC)?", default=True)
    web_preview = typer.confirm("Fetch web preview?", default=True)

    analyze_cors_opt = typer.confirm("Analyze CORS?", default=True)
    analyze_cookies_opt = typer.confirm("Analyze cookies?", default=True)
    fingerprint_web_opt = typer.confirm("Fingerprint web (server/WAF)?", default=True)
    check_security_txt_opt = typer.confirm("Check security.txt?", default=True)
    check_mixed_content_opt = typer.confirm("Check mixed content?", default=True)
    check_dnssec_caa_opt = typer.confirm("Check DNSSEC/CAA?", default=True)

    concurrency = typer.prompt("Port scan concurrency", default=200, type=int)
    timeout = typer.prompt("HTTP timeout (seconds)", default=6.0, type=float)
    dns_timeout = typer.prompt("DNS timeout (seconds)", default=2.0, type=float)

    write_html = typer.confirm("Write HTML report?", default=True)
    html_out: Path | None = None
    if write_html:
        html_out_default = Path("out/report.html")
        html_out = Path(typer.prompt("HTML output path", default=str(html_out_default)))

    write_json = typer.confirm("Write JSON output?", default=False)
    json_out: Path | None = None
    if write_json:
        json_out_default = Path("out/report.json")
        json_out = Path(typer.prompt("JSON output path", default=str(json_out_default)))

    # Run using the same implementation as the domain command
    domain(
        domain=domain_in,
        ports=ports_choice,
        custom_ports=custom_ports,
        json_out=json_out,
        html_out=html_out,
        do_scan_subdomains=do_scan_subdomains,
        do_scan_ports=do_scan_ports,
        analyze_headers=analyze_headers,
        analyze_tls=analyze_tls,
        analyze_dns=analyze_dns,
        web_preview=web_preview,
        analyze_cors_opt=analyze_cors_opt,
        analyze_cookies_opt=analyze_cookies_opt,
        fingerprint_web_opt=fingerprint_web_opt,
        check_security_txt_opt=check_security_txt_opt,
        check_mixed_content_opt=check_mixed_content_opt,
        check_dnssec_caa_opt=check_dnssec_caa_opt,
        concurrency=concurrency,
        timeout=timeout,
        dns_timeout=dns_timeout,
    )


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

