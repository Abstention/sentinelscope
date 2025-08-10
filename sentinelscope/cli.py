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
from datetime import datetime


app = typer.Typer(add_completion=False, help="SentinelScope CLI")
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
):
    """Run a full domain scan and optionally emit JSON/HTML reports."""
    async def _run():
        started = datetime.utcnow()
        ports_list = _resolve_ports(ports, custom_ports)

        console.rule(f"[bold]Scanning {domain}")

        subdomains_task = enumerate_subdomains(domain)
        ports_task = scan_ports(domain, ports_list)
        tls_info = get_tls_info(domain)
        headers_task = analyze_security_headers(f"https://{domain}")

        subdomains, ports_res, headers = await asyncio.gather(
            subdomains_task, ports_task, headers_task
        )

        finished = datetime.utcnow()
        result = DomainScanResult(
            domain=domain,
            started_at=started,
            finished_at=finished,
            subdomains=subdomains,
            ports=ports_res,
            tls=tls_info,
            headers=headers,
        )

        # Console summary
        table = Table(title=f"Summary for {domain}")
        table.add_column("Item")
        table.add_column("Value")
        table.add_row("Open ports", str(len(result.ports.open_ports) if result.ports else 0))
        table.add_row("Subdomains", str(len(result.subdomains.discovered) if result.subdomains else 0))
        table.add_row("TLS protocol", result.tls.protocol if result.tls and result.tls.protocol else "n/a")
        table.add_row("Headers grade", result.headers.grade if result.headers else "n/a")
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
    async def _run():
        res = await analyze_security_headers(url)
        console.print(res)
        if json_out:
            json_out.parent.mkdir(parents=True, exist_ok=True)
            json_out.write_text(res.model_dump_json(indent=2))
    asyncio.run(_run())


@app.command()
def tls(domain: str, json_out: Optional[Path] = typer.Option(None, "--json")):
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
    async def _run():
        plist = _resolve_ports(ports, custom_ports)
        res = await scan_ports(host, plist)
        console.print(res)
        if json_out:
            json_out.parent.mkdir(parents=True, exist_ok=True)
            json_out.write_text(res.model_dump_json(indent=2))
    asyncio.run(_run())


def main():  # entrypoint
    app()


if __name__ == "__main__":
    main()

