"""Regression coverage for native rule validation and incomplete execution."""

import json
from pathlib import Path

import pytest

from dede.config import AppConfig
from dede.engine.analyzer import DedeEngineAnalyzer
from dede.engine.rules import RuleSchemaError, load_rule_file, parse_rule_document
from dede.models import ProjectContext, ToolStatus


def rule(**overrides):
    return {
        "id": "dede.test.rule",
        "message": "Test rule",
        "languages": ["python"],
        "when": [{"pattern": "unsafe"}],
        **overrides,
    }


@pytest.mark.parametrize("field", ["if", "if_not", "references", "cwe", "owasp", "asvs"])
@pytest.mark.parametrize("value", [False, 0, "", {}])
def test_false_valued_invalid_lists_are_rejected(field, value):
    with pytest.raises(RuleSchemaError):
        parse_rule_document(rule(**{field: value}), "test")


@pytest.mark.parametrize("field", ["contains_any", "contains_all"])
@pytest.mark.parametrize("value", [False, 0, "", {}])
def test_false_valued_file_condition_lists_are_rejected(field, value):
    with pytest.raises(RuleSchemaError):
        parse_rule_document(rule(**{"if": [{"path": "*.py", field: value}]}), "test")


@pytest.mark.parametrize("schema", [True, 1.0, "1", 2])
def test_schema_requires_exact_integer(schema):
    with pytest.raises(RuleSchemaError):
        parse_rule_document({"schema": schema, "rules": [rule()]}, "test")


@pytest.mark.parametrize(
    "name,content",
    [("bad.yml", "rules: ["), ("bad.json", "{"), ("bad.json", '{"rules": [], "rules": []}')],
)
def test_invalid_documents_have_consistent_errors(tmp_path, name, content):
    path = tmp_path / name
    path.write_text(content)
    with pytest.raises(RuleSchemaError):
        load_rule_file(path)


def test_missing_rule_file_has_consistent_error(tmp_path):
    with pytest.raises(RuleSchemaError):
        load_rule_file(tmp_path / "missing.json")


def test_rule_limit_is_rejected_instead_of_silently_truncating():
    with pytest.raises(RuleSchemaError, match="500"):
        parse_rule_document({"rules": [rule(id=f"dede.test.r{i}") for i in range(501)]}, "test")


def analyze(tmp_path, files, *, custom_rule=None, timeout=10, max_bytes=None):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir(exist_ok=True)
    (rules_dir / "test.json").write_text(json.dumps(custom_rule or rule()))
    analyzer = DedeEngineAnalyzer(rules_dir=rules_dir)
    config = AppConfig()
    config.scan.analyzer_timeout_seconds = timeout
    project = ProjectContext(root=str(tmp_path), files=[str(tmp_path / name) for name in files])
    return analyzer.analyze(project, config, tmp_path / "raw", max_file_bytes=max_bytes)


def test_unreadable_file_preserves_findings_and_fails_coverage(tmp_path):
    (tmp_path / "ok.py").write_text("unsafe()\n")
    result = analyze(tmp_path, ["ok.py", "missing.py"])
    assert result.status == ToolStatus.FAILED
    assert len(result.findings) == 1
    assert result.coverage["files_scanned"] == 1
    assert result.coverage["files_failed"] == 1


def test_oversize_file_is_not_counted_as_scanned(tmp_path):
    (tmp_path / "big.py").write_text("unsafe()" * 50)
    result = analyze(tmp_path, ["big.py"], max_bytes=10)
    assert result.status == ToolStatus.FAILED
    assert not result.findings
    assert result.coverage["files_scanned"] == 0


def test_path_outside_root_is_not_read(tmp_path):
    result = analyze(tmp_path, ["../outside.py"])
    assert result.status == ToolStatus.FAILED
    assert not result.findings


def test_native_timeout_bounds_catastrophic_regex_and_retains_completed_files(tmp_path):
    (tmp_path / "ok.py").write_text("a")
    (tmp_path / "slow.py").write_text("a" * 100 + "!")
    result = analyze(
        tmp_path, ["ok.py", "slow.py"], timeout=2, custom_rule=rule(when=[{"regex": "^(a+)+$"}])
    )
    assert result.status == ToolStatus.FAILED
    assert "timeout" in result.message.lower()
    assert len(result.findings) == 1
    assert result.coverage["files_scanned"] == 1
    assert result.duration_seconds < 10


def test_invalid_rules_remain_applicable_so_pipeline_reports_failure(tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "bad.yml").write_text("rules: [")
    analyzer = DedeEngineAnalyzer(rules_dir=rules)
    project = ProjectContext(root=str(tmp_path), files=[str(tmp_path / "a.py")])
    assert analyzer.supports(project)
    assert analyzer.analyze(project, AppConfig(), tmp_path / "raw").status == ToolStatus.FAILED


def test_native_diagnostics_and_raw_output_do_not_include_source(tmp_path):
    (tmp_path / "ok.py").write_text('unsafe(password="<example-credential>")\n')
    result = analyze(tmp_path, ["ok.py"])
    assert result.status == ToolStatus.SUCCESS
    assert "<example-credential>" not in Path(result.raw_path).read_text()
    assert result.coverage["rule_digests"]


def test_worker_never_imports_a_target_dede_package_or_pythonpath(tmp_path, monkeypatch):
    malicious = tmp_path / "dede"
    malicious.mkdir()
    (malicious / "__init__.py").write_text('raise RuntimeError("TARGET_CODE_EXECUTED")')
    (tmp_path / "sitecustomize.py").write_text('raise RuntimeError("TARGET_HOOK_EXECUTED")')
    (tmp_path / "ok.py").write_text("unsafe()")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    result = analyze(tmp_path, ["ok.py"])
    assert result.status == ToolStatus.SUCCESS, result.message
    assert len(result.findings) == 1


def test_rule_snapshot_change_cannot_mix_detection_and_metadata(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    definition = rules_dir / "rule.json"
    definition.write_text(json.dumps(rule()))
    analyzer = DedeEngineAnalyzer(rules_dir=rules_dir)
    assert analyzer.rule_count() == 1
    definition.write_text(json.dumps(rule(when=[{"pattern": "different"}])))
    source = tmp_path / "a.py"
    source.write_text("different()")
    result = analyzer.analyze(
        ProjectContext(root=str(tmp_path), files=[str(source)]), AppConfig(), tmp_path / "raw"
    )
    assert result.status == ToolStatus.FAILED
    assert "rules changed" in result.message
    assert not result.findings


@pytest.mark.parametrize("per_file,total", [(2, 100), (100, 2)])
def test_finding_limits_are_explicit_failures(tmp_path, per_file, total):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "rule.json").write_text(json.dumps(rule()))
    source = tmp_path / "a.py"
    source.write_text("unsafe()\n" * 5)
    config = AppConfig()
    config.engine.max_findings_per_file = per_file
    config.engine.max_findings = total
    analyzed = DedeEngineAnalyzer(rules_dir=rules_dir).analyze(
        ProjectContext(root=str(tmp_path), files=[str(source)]), config, tmp_path / "raw"
    )
    assert analyzed.status == ToolStatus.FAILED
    assert len(analyzed.findings) == 2
    assert analyzed.coverage["files_truncated"] == 1


def test_exact_finding_limit_does_not_claim_truncation(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "rule.json").write_text(json.dumps(rule()))
    source = tmp_path / "a.py"
    source.write_text("unsafe()\n" * 2)
    config = AppConfig()
    config.engine.max_findings = 2
    analyzed = DedeEngineAnalyzer(rules_dir=rules_dir).analyze(
        ProjectContext(root=str(tmp_path), files=[str(source)]), config, tmp_path / "raw"
    )
    assert analyzed.status == ToolStatus.SUCCESS
    assert len(analyzed.findings) == 2
