"""Coverage, privacy and SARIF source-to-sink exports remain consistent."""

import json
from pathlib import Path

import pytest

from dede.config import AppConfig
from dede.engine.analyzer import DedeEngineAnalyzer
from dede.engine.matcher import SourceFile, match_rule
from dede.engine.rules import load_rules_dir
from dede.models import (
    AnalyzerResult,
    DataflowStep,
    Finding,
    LanguageStats,
    ScanMetadata,
    ScanResult,
    ToolStatus,
    utc_now,
)
from dede.reporting.context import build_report_context
from dede.reporting.html_report import write_html_report
from dede.reporting.json_report import write_json_report
from dede.reporting.sarif_report import build_sarif_log
from dede.utils.redact import redact_text, sanitize_finding_fields

ROOT = Path(__file__).resolve().parents[2]
RULES = {r.id: r for f in load_rules_dir(ROOT / "rules/dede-engine") for r in f.rules}


@pytest.mark.parametrize(
    "rule_id,filename,unsafe,unrelated_safe",
    [
        ("dede.py.cmd.eval-exec", "app.py", "eval(value)", "ast.literal_eval(other)"),
        (
            "dede.py.deserialize.unsafe-pickle-load",
            "app.py",
            "pickle.load(stream)",
            "json.load(other)",
        ),
        (
            "dede.java.jdbc.raw-concat-query",
            "App.java",
            'stmt.executeQuery("SELECT * FROM users WHERE name=" + name);',
            'PreparedStatement safe = connection.prepareStatement("SELECT 1");',
        ),
        (
            "dede.js.dom.innerHTML-assignment",
            "app.js",
            "node.innerHTML = value;",
            "other.textContent = safe;",
        ),
    ],
)
def test_unrelated_safe_code_does_not_suppress_unsafe_line(
    rule_id, filename, unsafe, unrelated_safe
):
    rule = RULES[rule_id]
    source = SourceFile.from_text(filename, unsafe + "\n" + unrelated_safe)
    assert match_rule(rule, source, rule.languages[0])


def test_unrelated_environment_lookup_does_not_hide_provider_token():
    token = "ghp_" + "x" * 36  # Synthetic format sample, not a credential.
    source = SourceFile.from_text("app.py", f'value = "{token}"\nother = os.environ["OTHER"]')
    matches = match_rule(RULES["dede.any.secrets.github-token"], source, "python")
    assert matches and matches[0].snippet == "***REDACTED***"
    assert token not in redact_text("unlabeled: " + token)


def test_trace_redaction_applies_to_all_engines():
    token = "ghp_" + "x" * 36
    finding = Finding(
        tool="custom",
        rule_id="custom.rule",
        file="a.cs",
        dataflow=[
            DataflowStep(kind="source", file="a.cs", start_line=1, end_line=1, content=token)
        ],
    )
    sanitize_finding_fields(finding)
    assert token not in finding.dataflow[0].content


def result(tmp_path, statuses, findings=None):
    return ScanResult(
        metadata=ScanMetadata(
            scanner_version="1.0.0", scan_started=utc_now(), target=str(tmp_path)
        ),
        languages=LanguageStats(),
        tool_statuses=statuses,
        findings=findings or [],
    )


def test_skipped_analyzer_is_partial_coverage(tmp_path):
    report = result(
        tmp_path,
        [
            AnalyzerResult(tool="native", status=ToolStatus.SUCCESS),
            AnalyzerResult(tool="semgrep", status=ToolStatus.SKIPPED_OFFLINE_DEPENDENCY),
        ],
    )
    context = build_report_context(report, pdf=False)
    assert context["scan_coverage"] == "Partial"
    assert context["coverage_pct"] == 50


def test_native_flow_round_trip_json_html_sarif_and_escaped_paths(tmp_path):
    path = tmp_path / "Controller #1.cs"
    path.write_text('var query = Request.Query["q"];\ndb.FromSqlRaw(query);')
    from dede.models import ProjectContext

    engine = DedeEngineAnalyzer(rules_dir=ROOT / "rules/dede-engine")
    analyzed = engine.analyze(
        ProjectContext(root=str(tmp_path), files=[str(path)]), AppConfig(), tmp_path / "raw"
    )
    assert analyzed.status == ToolStatus.SUCCESS, analyzed.message
    report = result(tmp_path, [analyzed], analyzed.findings)
    data = json.loads(write_json_report(report, tmp_path).read_text())
    finding = next(f for f in data["findings"] if f["analysis_kind"] == "taint")
    assert finding["dataflow"][0]["start_line"] == 1
    assert finding["dataflow"][-1]["start_line"] == 2
    assert finding["standards"]["microsoft-dotnet"] == ["CA3001"]
    html = write_html_report(report, tmp_path).read_text()
    assert "Native Engine Coverage" in html
    assert "Source Distribution by Language" in html
    assert "Data Flow Evidence" in html
    sarif = build_sarif_log(report)
    item = next(
        f for f in sarif["runs"][0]["results"] if f["properties"]["analysisKind"] == "taint"
    )
    assert (
        item["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        == "Controller%20%231.cs"
    )
    steps = item["codeFlows"][0]["threadFlows"][0]["locations"]
    assert steps[0]["kinds"] == ["source"] and steps[-1]["kinds"] == ["sink"]
    assert sarif["runs"][0]["properties"]["nativeCoverage"]["files_scanned"] == 1


def test_sarif_handles_default_target_and_failed_execution(tmp_path):
    report = result(tmp_path, [AnalyzerResult(tool="native", status=ToolStatus.FAILED)])
    report.metadata.target = ""
    sarif = build_sarif_log(report)
    assert sarif["runs"][0]["originalUriBaseIds"]["%SRCROOT%"]["uri"].startswith("file:///")
    assert not sarif["runs"][0]["invocations"][0]["executionSuccessful"]
