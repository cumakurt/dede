"""Run the offline rule corpus against unsafe code and safe counterexamples."""

import json
import shutil
from pathlib import Path

import pytest
import yaml

from dede.analyzers.semgrep import SemgrepAnalyzer
from dede.config import AppConfig, SemgrepConfig
from dede.discovery.languages import detect_languages
from dede.models import ProjectContext, ScanMetadata, ScanResult, ToolStatus, utc_now
from dede.reporting.html_report import write_html_report
from dede.reporting.json_report import write_json_report

ROOT = Path(__file__).resolve().parents[2]
CASES = json.loads((ROOT / "tests/rule_samples/advanced_cases.json").read_text())
RULES = {
    rule["id"]: rule
    for path in (ROOT / "rules/semgrep/custom").glob("*advanced-security*.yml")
    for rule in yaml.safe_load(path.read_text())["rules"]
}
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(shutil.which("semgrep") is None, reason="Semgrep is not installed"),
]


def test_advanced_rules_through_application_and_reports(tmp_path):
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    expected = set()
    safe = set()
    files = []
    for index, case in enumerate(CASES):
        for kind in ("unsafe", "safe"):
            source = source_dir / f"case_{index}_{kind}.{case['extension']}"
            source.write_text(case[kind])
            files.append(source)
            (expected if kind == "unsafe" else safe).add((source.name, case["rule_id"]))
    project = ProjectContext(
        root=str(source_dir),
        files=[str(path) for path in files],
        languages=detect_languages(files, source_dir),
    )
    config = AppConfig(semgrep=SemgrepConfig(profile="custom-only"))
    output = SemgrepAnalyzer().analyze(project, config, tmp_path)
    assert output.status == ToolStatus.SUCCESS, output.message
    findings = [finding for finding in output.findings if finding.rule_id in RULES]
    actual = {(Path(finding.file).name, finding.rule_id) for finding in findings}
    assert not actual & safe
    assert actual == expected
    assert {finding.rule_id for finding in findings} == set(RULES)
    for finding in findings:
        rule = RULES[finding.rule_id]
        assert finding.standards == rule["metadata"]["standards"]
        assert finding.owasp == rule["metadata"]["owasp"]
        assert finding.analysis_kind == rule["metadata"].get("analysis", "pattern")
        assert finding.recommendation == rule["metadata"]["recommendation"]
        assert finding.ai_generated is False
    scan = ScanResult(
        metadata=ScanMetadata(scanner_version="test", scan_started=utc_now()),
        languages=project.languages,
        findings=findings,
        tool_statuses=[output],
    )
    report = json.loads(write_json_report(scan, tmp_path).read_text())
    assert "standards" in report["field_origins"]["Static analysis"]
    controls = report["standards_assessment"]["controls"]
    assert controls and all(row["status"] == "REVIEW_REQUIRED" for row in controls)
    html = write_html_report(scan, tmp_path).read_text()
    assert "owasp-asvs-5.0.0" in html
    assert "CA3001" in html
    assert "does not mean a control passed" in html


def test_csharp_legacy_audit_is_precise_and_binaryformatter_instances_are_detected(tmp_path):
    safe = tmp_path / "safe.cs"
    safe.write_text(
        'using System.Diagnostics;\nclass Safe { void Run() { Process.Start("/usr/bin/date"); } }'
    )
    unsafe = tmp_path / "unsafe.cs"
    unsafe.write_text(
        "using System.Runtime.Serialization.Formatters.Binary;\n"
        "class Unsafe { void Run() { var formatter = new BinaryFormatter();\n"
        "var value = formatter.Deserialize(stream); } }"
    )
    output = SemgrepAnalyzer().analyze(
        ProjectContext(root=str(tmp_path), files=[str(safe), str(unsafe)]),
        AppConfig(semgrep=SemgrepConfig(profile="custom-only")),
        tmp_path,
    )
    assert output.status == ToolStatus.SUCCESS, output.message
    assert not any(Path(finding.file).name == "safe.cs" for finding in output.findings)
    assert any(
        finding.rule_id == "dede.csharp.security.insecure-deserial-binaryformatter"
        for finding in output.findings
    )
