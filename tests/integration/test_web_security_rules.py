"""Verify security rule matches and safe boundaries with the real Semgrep engine."""

import json
import shutil
from pathlib import Path

import pytest
import yaml

from dede.analyzers.semgrep import SemgrepAnalyzer
from dede.config import AppConfig, SemgrepConfig
from dede.models import ProjectContext, ScanMetadata, ScanResult, ToolStatus, utc_now
from dede.reporting.json_report import write_json_report
from dede.utils.process import run_command

ROOT = Path(__file__).resolve().parents[2]
SAMPLES = ROOT / "tests/rule_samples"
pytestmark = pytest.mark.integration


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="Semgrep is not installed")
@pytest.mark.parametrize(
    "language,filename",
    [
        ("python", "python_web.py"),
        ("javascript", "javascript_web.js"),
        ("javascript", "typescript_web.ts"),
        ("java", "JavaWeb.java"),
        ("go", "go_web.go"),
        ("php", "php_web.php"),
    ],
)
def test_web_rules_detect_unsafe_and_accept_safe_code(language, filename, tmp_path):
    source = SAMPLES / filename
    if filename == "typescript_web.ts":
        source = tmp_path / filename
        source.write_text((SAMPLES / "javascript_web.js").read_text())
    result = run_command(
        [
            "semgrep",
            "scan",
            "--json",
            "--quiet",
            "--metrics",
            "off",
            "--disable-version-check",
            "--no-rewrite-rule-ids",
            "--config",
            str(ROOT / f"rules/semgrep/custom/{language}-web-security.yml"),
            str(source),
        ],
        timeout=60,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    payload = json.loads(result.stdout)
    assert not payload["errors"]
    expected, safe = set(), set()
    for number, line in enumerate(source.read_text().splitlines(), 1):
        if "ruleid: " in line:
            expected.add((line.split("ruleid: ", 1)[1].strip(), number + 1))
        if "ok: " in line:
            safe.add((line.split("ok: ", 1)[1].strip(), number + 1))
    actual = {(item["check_id"], item["start"]["line"]) for item in payload["results"]}
    assert expected and safe
    assert not actual & safe
    assert actual == expected


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="Semgrep is not installed")
def test_application_preserves_new_rule_evidence_and_static_origins(tmp_path):
    project = ProjectContext(
        root=str(SAMPLES),
        files=[
            str(SAMPLES / name)
            for name in [
                "python_web.py",
                "javascript_web.js",
                "JavaWeb.java",
                "go_web.go",
                "php_web.php",
            ]
        ],
    )
    config = AppConfig(semgrep=SemgrepConfig(profile="custom-only"))
    output = SemgrepAnalyzer().analyze(project, config, tmp_path)
    assert output.status == ToolStatus.SUCCESS, output.message
    rules = {
        rule["id"]: rule
        for path in (ROOT / "rules/semgrep/custom").glob("*-web-security.yml")
        for rule in yaml.safe_load(path.read_text())["rules"]
    }
    findings = [finding for finding in output.findings if finding.rule_id in rules]
    assert {finding.rule_id for finding in findings} == set(rules)
    scan = ScanResult(
        metadata=ScanMetadata(scanner_version="test", scan_started=utc_now()),
        languages=project.languages,
        findings=findings,
        tool_statuses=[output],
    )
    report = json.loads(write_json_report(scan, tmp_path).read_text())
    assert "rule_id" in report["field_origins"]["Static analysis"]
    assert "summary" in report["field_origins"]["AI"]
    for finding in report["findings"]:
        rule = rules[finding["rule_id"]]
        metadata = rule["metadata"]
        assert finding["cwe"] == metadata["cwe"]
        assert finding["confidence"] == metadata["confidence"]
        assert finding["recommendation"] == metadata["recommendation"]
        assert finding["references"] == metadata["references"]
        assert finding["analysis_kind"] == rule.get("mode", "pattern")
        assert finding["ai_generated"] is False
