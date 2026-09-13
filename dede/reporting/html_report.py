"""HTML report generation with embedded CSS/JS (offline)."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from dede.models import ScanResult
from dede.reporting.context import build_report_context


def write_html_report(result: ScanResult, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    reporting_dir = Path(__file__).parent
    template_dir = reporting_dir / "templates"
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=True,
    )
    template = env.get_template("report.html.j2")
    html = template.render(**build_report_context(result, pdf=False))
    path = output_dir / "report.html"
    path.write_text(html, encoding="utf-8")
    return path
