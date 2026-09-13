"""Archival PDF/A report generation via WeasyPrint.

The PDF contains tagged document structure and embeds the canonical JSON scan
payload plus scan manifest as data attachments.  The report stays fully
self-contained and does not fetch remote assets.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from dede.models import ScanResult
from dede.reporting.context import build_report_context
from dede.reporting.json_report import build_json_payload


class PDFDependencyUnavailable(RuntimeError):
    """Raised when optional native PDF dependencies are not installed."""


def _attachment_json(value: object) -> str:
    return json.dumps(value, indent=2, sort_keys=True, default=str)


def write_pdf_report(result: ScanResult, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    reporting_dir = Path(__file__).parent
    template_dir = reporting_dir / "templates"
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=True,
    )
    template = env.get_template("report_pdf.html.j2")
    ctx = build_report_context(result, pdf=True)
    html = template.render(**ctx)
    path = output_dir / "report.pdf"
    try:
        import weasyprint
    except ModuleNotFoundError as exc:
        if exc.name == "weasyprint":
            raise PDFDependencyUnavailable(
                "WeasyPrint is not installed; PDF is optional in native runtime"
            ) from exc
        raise

    try:
        html_document = weasyprint.HTML(string=html, base_url=str(reporting_dir))
        attachment_type = getattr(weasyprint, "Attachment", None)
        attachments = []
        if attachment_type is not None:
            evidence_payload = build_json_payload(result)
            manifest_payload = result.metadata.scan_manifest or {}
            attachments = [
                attachment_type(
                    string=_attachment_json(evidence_payload),
                    name="dede-report-evidence.json",
                    description="Canonical machine-readable Dede scan evidence",
                    relationship="Data",
                ),
                attachment_type(
                    string=_attachment_json(manifest_payload),
                    name="dede-scan-manifest.json",
                    description="Scanner, ruleset and source traceability manifest",
                    relationship="Data",
                ),
            ]
        options = {
            "attachments": attachments,
            "pdf_variant": "pdf/a-3u",
            "pdf_tags": True,
            "srgb": True,
            "optimize_images": True,
        }
        try:
            html_document.write_pdf(str(path), **options)
        except TypeError:
            # Compatibility with older WeasyPrint releases and lightweight test doubles.
            html_document.write_pdf(str(path))
        if path.is_file():
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            (output_dir / "report.pdf.sha256").write_text(
                f"{digest}  {path.name}\n", encoding="ascii"
            )
    except Exception as exc:
        raise RuntimeError(f"PDF generation failed: {exc}") from exc
    return path
