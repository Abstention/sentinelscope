from __future__ import annotations

from pathlib import Path
from typing import Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

from sentinelscope.models import DomainScanResult


def render_html_report(result: DomainScanResult) -> str:
    templates_dir = Path(__file__).parent / "templates"
    env = Environment(
        loader=FileSystemLoader(str(templates_dir)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template("report.html")
    # Ensure grade/score are shown consistently: render as-is from result
    return template.render(result=result)


def write_html_report(result: DomainScanResult, output_path: str | Path) -> Path:
    html = render_html_report(result)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")
    return output_path

