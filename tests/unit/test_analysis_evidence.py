"""Engine evidence, diagnostics and deduplication must survive normalization."""

import json
from datetime import datetime, timezone

import pytest

from dede.analyzers.semgrep import SemgrepAnalyzer, _parse_dataflow
from dede.config import AppConfig
from dede.models import (
    AnalyzerResult,
    Confidence,
    DataflowStep,
    Finding,
    LanguageStats,
    ProjectContext,
    ScanMetadata,
    ScanResult,
    Severity,
    ToolStatus,
)
from dede.normalization.deduplicate import deduplicate_findings
from dede.reporting.context import build_report_context
from dede.reporting.html_report import write_html_report
from dede.utils.process import CommandResult


def _location(file="app.py", line=1):
    return {"path": file, "start": {"line": line}, "end": {"line": line}}


def test_dataflow_retains_order_and_rejects_external_paths(tmp_path):
    trace = {
        "taint_source": ["CliLoc", [_location(line=2), "request.args['q']"]],
        "intermediate_vars": [
            {"location": _location(line=3), "content": "query"},
            {"location": _location(file="../outside.py"), "content": "outside"},
        ],
        "taint_sink": ["CliLoc", [_location(line=5), "query"]],
    }
    steps = _parse_dataflow(trace, tmp_path)
    assert [step.kind for step in steps] == ["source", "propagation", "sink"]
    assert [step.start_line for step in steps] == [2, 3, 5]
    assert all(step.file == "app.py" for step in steps)


@pytest.mark.parametrize(
    "trace",
    [None, [], "requires login", {"taint_source": []}, {"taint_sink": ["CliLoc", [None, "x"]]}],
)
def test_missing_trace_is_not_invented(tmp_path, trace):
    assert _parse_dataflow(trace, tmp_path) == []


def test_dataflow_redacts_values(tmp_path):
    trace = {"taint_source": ["CliLoc", [_location(), "password=<placeholder>"]]}
    assert "<placeholder>" not in _parse_dataflow(trace, tmp_path)[0].content


def test_semgrep_preserves_findings_and_exposes_engine_errors(tmp_path, monkeypatch):
    (tmp_path / "rules.yml").write_text("rules:\n  - id: r\n    languages: [python]\n")
    monkeypatch.setattr("dede.analyzers.semgrep.which", lambda _: "/tool")
    monkeypatch.setattr(SemgrepAnalyzer, "version", lambda _: "test")
    monkeypatch.setattr(
        "dede.analyzers.semgrep.resolve_semgrep_configs",
        lambda *a, **kw: [tmp_path / "rules.yml"],
    )
    payload = {
        "results": [
            {
                "check_id": "r",
                "path": "app.py",
                "extra": {
                    "lines": "requires login",
                    "metadata": {
                        "confidence": "LOW",
                        "analysis": "taint",
                        "recommendation": "Bind parameters",
                    },
                },
            }
        ],
        "errors": [{"type": "PartialParsing"}],
    }
    monkeypatch.setattr(
        "dede.analyzers.semgrep.run_command",
        lambda *a, **kw: CommandResult(0, json.dumps(payload), ""),
    )
    project = ProjectContext(root=str(tmp_path), files=[str(tmp_path / "app.py")])
    result = SemgrepAnalyzer().analyze(project, AppConfig(), tmp_path)
    assert result.status == ToolStatus.FAILED
    assert "incomplete coverage" in result.message
    assert result.findings[0].confidence == Confidence.LOW
    assert result.findings[0].analysis_kind == "taint"
    assert result.findings[0].recommendation == "Bind parameters"
    assert not result.findings[0].code_snippet


def test_dedup_preserves_richer_evidence_when_severity_increases():
    step = DataflowStep(
        kind="source", file="app.py", start_line=1, end_line=1, content="request.args"
    )
    first = Finding(
        tool="one",
        rule_id="r",
        file="app.py",
        normalized_type="sql",
        severity=Severity.MEDIUM,
        dataflow=[step],
        recommendation="Bind parameters",
        references=["https://example.invalid/rule"],
        detected_by=["one", "two"],
        analysis_kind="taint",
    )
    second = Finding(
        tool="three", rule_id="r", file="app.py", normalized_type="sql", severity=Severity.HIGH
    )
    result = deduplicate_findings([first, second])[0]
    assert result.severity == Severity.HIGH
    assert result.dataflow == [step]
    assert result.recommendation == "Bind parameters"
    assert result.references == ["https://example.invalid/rule"]
    assert result.detected_by == ["one", "two", "three"]


def test_report_renders_trace_as_text_and_only_claims_used_methods(tmp_path):
    finding = Finding(
        tool="semgrep",
        rule_id="r",
        file="app.py",
        analysis_kind="taint",
        dataflow=[
            DataflowStep(
                kind="source",
                file="app.py",
                start_line=1,
                end_line=1,
                content="<script>trace_marker()</script>",
            )
        ],
    )
    result = ScanResult(
        metadata=ScanMetadata(
            scanner_version="test", scan_started=datetime(2026, 1, 1, tzinfo=timezone.utc)
        ),
        languages=LanguageStats(),
        findings=[finding],
        tool_statuses=[
            AnalyzerResult(tool="semgrep", status=ToolStatus.SUCCESS, findings=[finding])
        ],
    )
    html = write_html_report(result, tmp_path).read_text()
    assert "Data Flow Evidence" in html
    assert "&lt;script&gt;trace_marker()&lt;/script&gt;" in html
    assert "<script>trace_marker()</script>" not in html
    methodologies = build_report_context(result, pdf=False)["methodologies"]
    assert any("taint" in method for method in methodologies)
    assert not any("Gitleaks" in method or "gosec" in method for method in methodologies)
