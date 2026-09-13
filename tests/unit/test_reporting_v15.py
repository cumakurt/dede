from __future__ import annotations

import sys
from datetime import datetime, timezone
from types import SimpleNamespace

from dede.models import (
    AnalyzerResult,
    Category,
    Confidence,
    DataflowStep,
    Evidence,
    Finding,
    LanguageStats,
    RiskScore,
    ScanMetadata,
    ScanResult,
    Severity,
    ToolStatus,
)
from dede.reporting.context import build_report_context
from dede.reporting.html_report import write_html_report
from dede.reporting.pdf_report import write_pdf_report


def _result() -> ScanResult:
    finding = Finding(
        id="SRM-REPORT-001",
        tool="dede-semantic-python",
        detected_by=["dede-semantic-python", "semgrep"],
        rule_id="DEDE-SQLI",
        category=Category.SECURITY,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        cwe=["CWE-89"],
        file="app/repo.py",
        start_line=42,
        message="HTTP input reaches SQL execution",
        code_snippet="42 cursor.execute(query)",
        source_kind="http.query",
        sink_kind="cursor.execute",
        reachable=True,
        exploitability_score=95,
        endpoint="/users/{id}",
        http_method="GET",
        authentication_required=False,
        internet_exposed=True,
        lifecycle_status="NEW",
        query_matches=["builtin.internet-sql"],
        attack_path=["GET /users/{id}", "service.lookup", "cursor.execute"],
        dataflow=[
            DataflowStep(
                kind="SINK",
                file="app/repo.py",
                start_line=42,
                end_line=42,
                content="cursor.execute(query)",
            )
        ],
        evidence=[Evidence(kind="route", value="GET /users/{id}")],
        correlation_score=0.91,
    )
    metadata = ScanMetadata(
        scanner_version="1.5.0",
        scan_started=datetime(2026, 9, 13, tzinfo=timezone.utc),
        duration_seconds=3.2,
        target="/tmp/app",
        files_scanned=10,
        lines_scanned=500,
        lifecycle={
            "counts": {"NEW": 1, "EXISTING": 0, "REOPENED": 0, "RESOLVED": 2},
            "current_total": 1,
        },
        policy_violations=[
            {
                "policy": "public-critical",
                "finding_id": finding.id,
                "severity": "CRITICAL",
                "file": finding.file,
            }
        ],
        profile={"discovery": 0.2, "analyzers": 2.5},
        incremental={"changed_files": ["app/repo.py"], "affected_files": ["app/repo.py"]},
        scan_manifest={"scanner": "1.5.0", "rules": "test"},
        ruleset_versions={"dede-engine": "test"},
    )
    return ScanResult(
        metadata=metadata,
        languages=LanguageStats(languages={"Python": 100.0}, files_scanned=10, lines_scanned=500),
        findings=[finding],
        tool_statuses=[
            AnalyzerResult(
                tool="dede-semantic-python",
                status=ToolStatus.SUCCESS,
                version="1.5.0",
                duration_seconds=2.5,
                findings=[finding],
            )
        ],
        risk=RiskScore(
            score=80,
            category="HIGH",
            algorithm="test",
            raw_weighted=10,
            weights={"CRITICAL": 10},
        ),
        severity_counts={"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
    )


def test_operational_report_metrics_are_evidence_backed():
    ctx = build_report_context(_result(), pdf=False)
    assert ctx["lifecycle_metrics"]["counts"]["NEW"] == 1
    assert ctx["lifecycle_metrics"]["counts"]["RESOLVED"] == 2
    assert ctx["attack_metrics"]["internet_exposed"] == 1
    assert ctx["attack_metrics"]["unauthenticated_exposed"] == 1
    assert ctx["attack_metrics"]["high_exploitability"] == 1
    assert ctx["governance_metrics"]["policy_gate"] == "BLOCKED"
    assert ctx["analyzer_metrics"]["completion_pct"] == 100
    assert ctx["finding_quality_metrics"]["multi_engine"] == 1
    assert ctx["performance_metrics"]["incremental"]["changed_files"] == 1
    assert ctx["governance_metrics"]["manifest_digest_short"] != "n/a"


def test_html_report_has_offline_interactive_reporting_controls(tmp_path):
    html = write_html_report(_result(), tmp_path).read_text(encoding="utf-8")
    for marker in (
        'class="html-toolbar"',
        'class="report-nav"',
        'id="filter-lifecycle"',
        'id="filter-reachability"',
        'id="theme-toggle"',
        'id="security-operations"',
        'class="attack-flow"',
        'class="copy-link"',
        'data-reachable="true"',
        'data-exposed="true"',
        "Multi-engine corroboration",
        "Structured Evidence",
    ):
        assert marker in html
    assert "https://cdn" not in html.lower()
    assert "unpkg.com" not in html.lower()


def test_pdf_writer_requests_archival_tagged_pdf_and_embeds_evidence(tmp_path, monkeypatch):
    calls: dict[str, object] = {"attachments": []}

    class Attachment:
        def __init__(self, **kwargs):
            calls["attachments"].append(kwargs)

    class HTML:
        def __init__(self, string, base_url):
            calls["html"] = string
            calls["base_url"] = base_url

        def write_pdf(self, path, **kwargs):
            calls["options"] = kwargs
            with open(path, "wb") as handle:
                handle.write(b"%PDF-1.7\nreport")

    monkeypatch.setitem(sys.modules, "weasyprint", SimpleNamespace(HTML=HTML, Attachment=Attachment))
    path = write_pdf_report(_result(), tmp_path)
    assert path.read_bytes().startswith(b"%PDF-")
    assert (tmp_path / "report.pdf.sha256").is_file()
    assert calls["options"]["pdf_variant"] == "pdf/a-3u"
    assert calls["options"]["pdf_tags"] is True
    assert calls["options"]["srgb"] is True
    names = {item["name"] for item in calls["attachments"]}
    assert names == {"dede-report-evidence.json", "dede-scan-manifest.json"}
    assert "Report navigation" in calls["html"]
    assert "Report Integrity & Portability" in calls["html"]
