"""Standard mappings remain static evidence and never turn into compliance claims."""

import json

from dede.analyzers.semgrep import _standards
from dede.models import Finding, LanguageStats, ScanMetadata, ScanResult, Severity, utc_now
from dede.normalization.deduplicate import deduplicate_findings
from dede.reporting.html_report import write_html_report
from dede.reporting.json_report import write_json_report
from dede.reporting.standards import standards_assessment


def finding(**kwargs):
    defaults = {
        "tool": "semgrep",
        "rule_id": "sql",
        "file": "app.cs",
        "cwe": ["CWE-89"],
        "owasp": ["A05:2025"],
    }
    defaults.update(kwargs)
    return Finding(**defaults)


def test_mapping_normalization_handles_external_metadata():
    assert _standards(None) == {}
    assert _standards(["not a mapping"]) == {}
    assert _standards({"a": "control", "b": ["one", "one", None, 1, {}]}) == {"b": ["one"]}


def test_duplicate_findings_preserve_all_control_mappings():
    first = finding(standards={"ASVS": ["1.2.4"]}, severity=Severity.MEDIUM)
    second = finding(standards={"ASVS": ["1.2.4"], "Microsoft": ["CA3001"]}, severity=Severity.HIGH)
    merged = deduplicate_findings([first, second])
    assert len(merged) == 1
    assert merged[0].standards == {"ASVS": ["1.2.4"], "Microsoft": ["CA3001"]}


def test_report_excludes_suppressed_and_ai_findings_from_standard_evidence():
    assessment = standards_assessment([
        finding(standards={"ASVS": ["1.2.4", "1.2.4"]}),
        finding(standards={"ASVS": ["hidden"]}, suppressed=True),
        finding(standards={"ASVS": ["invented"]}, ai_generated=True),
    ])
    assert {row["control"] for row in assessment["controls"]} == {"1.2.4", "CWE-89", "A05:2025"}
    assert all(row["finding_count"] == 1 for row in assessment["controls"])
    assert all(row["status"] == "REVIEW_REQUIRED" for row in assessment["controls"])


def test_empty_report_never_claims_standard_compliance(tmp_path):
    scan = ScanResult(
        metadata=ScanMetadata(scanner_version="test", scan_started=utc_now()),
        languages=LanguageStats(),
    )
    report = json.loads(write_json_report(scan, tmp_path).read_text())
    assert report["standards_assessment"]["controls"] == []
    html = write_html_report(scan, tmp_path).read_text()
    assert "Controls remain unverified" in html


def test_standard_labels_are_escaped_in_html(tmp_path):
    scan = ScanResult(
        metadata=ScanMetadata(scanner_version="test", scan_started=utc_now()),
        languages=LanguageStats(),
        findings=[finding(standards={"<script>standard</script>": ["<script>control</script>"]})],
    )
    html = write_html_report(scan, tmp_path).read_text()
    assert "<script>standard</script>" not in html
    assert "&lt;script&gt;standard&lt;/script&gt;" in html
    assert "<script>control</script>" not in html


def test_html_coverage_table_includes_contributing_rule_ids(tmp_path):
    scan = ScanResult(
        metadata=ScanMetadata(scanner_version="test", scan_started=utc_now()),
        languages=LanguageStats(),
        findings=[finding(rule_id="dede.csharp.advanced.sql-injection", standards={"ASVS": ["1.2.4"]})],
    )
    html = write_html_report(scan, tmp_path).read_text()
    assert "<th>Rules</th>" in html
    assert "dede.csharp.advanced.sql-injection" in html
