"""Unit tests for premium report context aggregations."""

from __future__ import annotations

from datetime import datetime, timezone

from dede.models import (
    AnalyzerResult,
    Category,
    Confidence,
    Finding,
    LanguageStats,
    RiskScore,
    ScanMetadata,
    ScanResult,
    Severity,
    ToolStatus,
)
from dede.reporting.context import (
    build_report_context,
    logo_assets,
    parse_code_lines,
    security_class_for_finding,
    security_score_label,
)
from dede.reporting.html_report import write_html_report


def _meta(**kwargs) -> ScanMetadata:
    base = dict(
        scanner_version="0.1.0",
        scan_started=datetime(2026, 9, 8, 12, 0, tzinfo=timezone.utc),
        scan_finished=datetime(2026, 9, 8, 12, 1, tzinfo=timezone.utc),
        duration_seconds=1.5,
        files_scanned=3,
        lines_scanned=40,
        target="/tmp/demo-app",
    )
    base.update(kwargs)
    return ScanMetadata(**base)


def _finding(**kwargs) -> Finding:
    base = dict(
        id="SRM-2026-000001",
        tool="bandit",
        rule_id="B608",
        category=Category.SECURITY,
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        cwe=["CWE-89"],
        file="app/db.py",
        start_line=10,
        end_line=10,
        message="Possible SQL injection",
        code_snippet="9  query = base\n10 cursor.execute('SELECT ' + user)\n11 return\n",
    )
    base.update(kwargs)
    return Finding(**base)


def test_logo_assets_available():
    logos = logo_assets()
    assert logos["has_logo"] is True
    assert logos["logo_data_uri"].startswith("data:image/png;base64,")
    assert logos["logo_src"] == "assets/dede.png" or logos["logo_path"].endswith("dede.png")


def test_security_score_inversion_and_label():
    result = ScanResult(
        metadata=_meta(),
        languages=LanguageStats(files_scanned=3, lines_scanned=40, languages={"Python": 100.0}),
        findings=[_finding()],
        tool_statuses=[
            AnalyzerResult(tool="gitleaks", status=ToolStatus.SUCCESS, version="8.0"),
            AnalyzerResult(tool="bandit", status=ToolStatus.SUCCESS, version="1.0"),
        ],
        risk=RiskScore(
            score=35,
            category="MODERATE",
            algorithm="test",
            raw_weighted=7,
            weights={"HIGH": 7},
        ),
        severity_counts={"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0},
    )
    ctx = build_report_context(result, pdf=False)
    assert ctx["security_score"] == 65
    assert ctx["security_score_label"] == security_score_label(65)
    assert ctx["security_score_label"] == "Elevated Risk"
    assert ctx["overall_risk_label"].startswith("MODERATE")
    assert ctx["project_name"] == "demo-app"
    assert ctx["analysis_id"].startswith("SRM-")
    assert ctx["engine_label"].startswith("Dede SAST")
    assert ctx["primary_risk"] is not None
    assert ctx["primary_risk"]["id"] == "SRM-2026-000001"
    assert "Block release" not in ctx["release_decision"]  # high but not critical
    assert "High findings" in ctx["release_decision"]
    assert ctx["has_logo"] is True
    assert ctx["findings_by_category"][0]["name"] == "Injection"
    factor_names = {f["name"] for f in ctx["contributing_factors"]}
    assert "Severity burden" in factor_names
    assert "Exploitability" not in factor_names
    assert "Reachability" not in factor_names


def test_missing_risk_does_not_invent_score():
    result = ScanResult(
        metadata=_meta(),
        languages=LanguageStats(),
        findings=[],
        risk=None,
    )
    ctx = build_report_context(result, pdf=True)
    assert ctx["security_score"] is None
    assert ctx["security_score_label"] == "n/a"
    assert ctx["primary_risk"] is None
    assert ctx["hotspot_folders"] == []
    assert ctx["cwe_distribution"] == []
    assert ctx["has_secrets"] is False


def test_parse_code_lines_highlights_vulnerable_line():
    lines = parse_code_lines(
        "11     # comment\n12     os.system(user_input)\n13 \n",
        12,
    )
    assert len(lines) == 3
    assert lines[1]["number"] == 12
    assert lines[1]["vulnerable"] is True


def test_secrets_section_and_remediation_groups():
    secret = _finding(
        id="SRM-2026-000002",
        tool="gitleaks",
        rule_id="aws-access-key",
        category=Category.SECRET,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        cwe=["CWE-798"],
        file="config.env",
        start_line=2,
        message="AWS key detected",
        recommendation="Rotate and remove the credential.",
    )
    result = ScanResult(
        metadata=_meta(repository="git@example.com:acme/app.git", branch="main", commit="abc123def"),
        languages=LanguageStats(languages={"Python": 100.0}),
        findings=[secret, _finding(severity=Severity.LOW, confidence=Confidence.LOW, cwe=[])],
        tool_statuses=[AnalyzerResult(tool="gitleaks", status=ToolStatus.SUCCESS)],
        risk=RiskScore(score=80, category="CRITICAL", algorithm="t", raw_weighted=11, weights={}),
        severity_counts={"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 1, "INFO": 0},
    )
    ctx = build_report_context(result, pdf=False)
    assert ctx["has_secrets"] is True
    assert ctx["branch_commit_display"] == "main / abc123d"
    assert "Block release" in ctx["release_decision"]
    assert ctx["primary_risk"]["severity"] == "CRITICAL"
    assert security_class_for_finding(secret) == "Secrets"
    assert ctx["security_score"] == 20


def test_collapse_redaction_and_pdf_omits_html_chrome():
    from pathlib import Path

    from jinja2 import Environment, FileSystemLoader, select_autoescape

    from dede.reporting.context import _collapse_redaction

    assert _collapse_redaction("secret " + ("*" * 80)) == "secret ************"
    result = ScanResult(
        metadata=_meta(),
        languages=LanguageStats(languages={"Python": 100.0}),
        findings=[_finding()],
        tool_statuses=[AnalyzerResult(tool="bandit", status=ToolStatus.SUCCESS)],
        risk=RiskScore(score=10, category="LOW", algorithm="t", raw_weighted=1, weights={}),
        severity_counts={"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0},
    )
    env = Environment(
        loader=FileSystemLoader(str(Path("dede/reporting/templates"))),
        autoescape=select_autoescape(["html", "xml"]),
    )
    pdf_html = env.get_template("report_pdf.html.j2").render(
        **build_report_context(result, pdf=True)
    )
    assert "page-chrome" not in pdf_html
    assert "UTC" in build_report_context(result, pdf=True)["analysis_date"]


def test_html_report_matches_template_structure(tmp_path):
    result = ScanResult(
        metadata=_meta(),
        languages=LanguageStats(
            files_scanned=2,
            lines_scanned=20,
            languages={"Python": 100.0},
            frameworks=["flask"],
        ),
        findings=[_finding()],
        tool_statuses=[
            AnalyzerResult(tool="bandit", status=ToolStatus.SUCCESS, version="1.9"),
            AnalyzerResult(tool="gitleaks", status=ToolStatus.SUCCESS, version="8.21"),
        ],
        risk=RiskScore(
            score=35,
            category="MODERATE",
            algorithm="test",
            raw_weighted=7,
            weights={"HIGH": 7},
        ),
        severity_counts={"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0},
    )
    path = write_html_report(result, tmp_path)
    html = path.read_text(encoding="utf-8")
    assert "data:image/png;base64," in html
    assert "Application Security Analysis Report" in html
    assert "CONFIDENTIAL" in html.upper() or "Confidential" in html
    assert "01 / Executive Summary" in html
    assert "02 / Findings Overview" in html
    assert "03 / Security Score" in html
    assert "04 / Top Security Risks" in html
    assert "05 / Finding Detail" in html
    assert "08 / Hotspots" in html
    assert "10 / Remediation Roadmap" in html
    assert "11 / Analysis Coverage" in html
    assert "13 / Methodology" in html
    assert "OF 100" in html
    assert "Source-to-Sink" not in html
    assert "Dependency Security" not in html
    assert "Immediate action" in html
    assert "Needs Review" in html
