"""Pipeline scope, suppression and report failure regression tests."""

import json

import pytest

from dede.config import AppConfig
from dede.models import AnalyzerResult, Finding, ToolStatus
from dede.normalization.findings import compute_fingerprint
from dede.pipeline import run_scan


@pytest.fixture
def scan_setup(tmp_path, monkeypatch):
    root = tmp_path / "project"
    root.mkdir()
    (root / "keep.py").write_text("print(1)\n")
    findings = [Finding(tool="test", rule_id="r", file="keep.py")]

    class Analyzer:
        name = "test"

        def supports(self, project):
            return True

        def analyze(self, *args):
            return AnalyzerResult(tool="test", status=ToolStatus.SUCCESS, findings=findings)

    monkeypatch.setattr("dede.pipeline.get_analyzers", lambda: [Analyzer()])
    monkeypatch.setattr("dede.pipeline.collect_git_metadata", lambda root: {})
    cfg = AppConfig()
    cfg.ai.enabled = False
    cfg.reports.output = str(tmp_path / "reports")
    cfg.reports.formats = ["json"]
    return root, cfg, findings


def test_scan_filters_findings_to_discovered_files(scan_setup):
    root, cfg, findings = scan_setup
    (root / "excluded.py").write_text("print(2)")
    cfg.scan.exclude.append("excluded.py")
    findings.extend(
        [
            Finding(tool="test", rule_id="r", file="excluded.py"),
            Finding(tool="test", rule_id="r", file="../outside.py"),
        ]
    )
    result, code = run_scan(root, cfg, progress=False)
    assert code == 0
    assert [finding.file for finding in result.findings] == ["keep.py"]
    assert [finding.file for finding in result.tool_statuses[0].findings] == ["keep.py"]


def test_suppressed_finding_is_not_resolved(scan_setup, tmp_path):
    root, cfg, findings = scan_setup
    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        json.dumps({"findings": [{"fingerprint": compute_fingerprint(findings[0])}]})
    )
    cfg.suppress.rules = ["r"]
    result, code = run_scan(root, cfg, baseline=baseline, progress=False)
    assert code == 0
    assert not result.resolved_findings
    assert len(result.suppressed_findings) == 1


def test_partial_report_failure_returns_error(scan_setup, monkeypatch):
    root, cfg, _ = scan_setup
    cfg.reports.formats = ["json", "html"]

    def fail(*args):
        raise OSError("cannot write HTML")

    monkeypatch.setattr("dede.pipeline.write_html_report", fail)
    _, code = run_scan(root, cfg, progress=False)
    assert code == 4
    assert (root.parent / "reports" / "report.json").is_file()


@pytest.mark.parametrize(
    "status,expected_code",
    [
        (ToolStatus.FAILED, 3),
        (ToolStatus.SKIPPED_OFFLINE_DEPENDENCY, 0),
    ],
)
def test_partial_analyzer_failure_preserves_report_and_signals_incomplete_coverage(
    scan_setup, monkeypatch, status, expected_code
):
    root, cfg, findings = scan_setup

    class Analyzer:
        def __init__(self, name, result_status):
            self.name = name
            self.status = result_status

        def supports(self, project):
            return True

        def analyze(self, *args):
            return AnalyzerResult(
                tool=self.name,
                status=self.status,
                findings=findings if self.status == ToolStatus.SUCCESS else [],
            )

    monkeypatch.setattr(
        "dede.pipeline.get_analyzers",
        lambda: [Analyzer("semgrep", status), Analyzer("ruff", ToolStatus.SUCCESS)],
    )
    result, code = run_scan(root, cfg, progress=False)
    assert code == expected_code
    assert len(result.findings) == 1
    report = json.loads((root.parent / "reports" / "report.json").read_text())
    assert report["tool_statuses"][0]["status"] == status.value
    assert len(report["findings"]) == 1


def test_no_findings_does_not_request_model_installation(scan_setup, monkeypatch):
    root, cfg, findings = scan_setup
    cfg.ai.enabled = True
    cfg.ai.hunt_enabled = False
    findings.clear()

    def unexpected(*args, **kwargs):
        pytest.fail("No findings should not trigger model setup or an LLM request")

    monkeypatch.setattr("dede.llm.ensure.ensure_model_installed", unexpected)
    monkeypatch.setattr("dede.llm.client.OllamaClient.is_reachable", unexpected)
    _, code = run_scan(root, cfg, progress=False)
    assert code == 0


def test_ai_hunt_runs_without_existing_static_findings(scan_setup, monkeypatch):
    root, cfg, findings = scan_setup
    findings.clear()
    cfg.ai.enabled = True
    cfg.ai.hunt_enabled = True
    cfg.reports.formats = ["json"]
    called = []
    monkeypatch.setattr(
        "dede.llm.ensure.ensure_model_installed", lambda *args, **kwargs: (True, "ready")
    )

    def hunt(*args, **kwargs):
        called.append(True)
        return (
            [
                Finding(
                    tool="llm",
                    rule_id="AI-HUNT",
                    file="keep.py",
                    severity="HIGH",
                    analysis_kind="ai-hunt",
                    ai_generated=True,
                    ai_status="hunt",
                    ai_model_digest="digest",
                )
            ],
            "ai-hunt: 1 candidate(s)",
        )

    monkeypatch.setattr("dede.llm.hunt.run_vulnerability_hunt", hunt)
    result, code = run_scan(root, cfg, progress=False)
    assert called and code == 0
    assert result.metadata.ai_enabled is True
    assert result.findings[0].analysis_kind == "ai-hunt"


def test_ai_hunt_candidate_does_not_trigger_ci_gate(scan_setup, monkeypatch):
    root, cfg, findings = scan_setup
    findings.clear()
    cfg.ai.enabled = True
    cfg.ai.hunt_enabled = True
    cfg.severity.fail_on = "HIGH"
    monkeypatch.setattr(
        "dede.llm.ensure.ensure_model_installed", lambda *args, **kwargs: (True, "ready")
    )
    monkeypatch.setattr(
        "dede.llm.hunt.run_vulnerability_hunt",
        lambda *args, **kwargs: (
            [
                Finding(
                    tool="llm",
                    rule_id="AI-HUNT",
                    file="keep.py",
                    severity="HIGH",
                    analysis_kind="ai-hunt",
                    ai_generated=True,
                    ai_status="hunt",
                )
            ],
            "ai-hunt: 1 candidate(s)",
        ),
    )
    result, code = run_scan(root, cfg, progress=False)
    assert code == 0
    assert result.risk.raw_weighted == 0


def test_unavailable_ai_status_is_persisted_without_hiding_findings(scan_setup, monkeypatch):
    root, cfg, _ = scan_setup
    cfg.ai.enabled = True
    monkeypatch.setattr(
        "dede.llm.ensure.ensure_model_installed",
        lambda *args, **kwargs: (False, "Ollama is not reachable"),
    )
    result, code = run_scan(root, cfg, progress=False)
    assert code == 0 and len(result.findings) == 1
    assert "review=Ollama is not reachable" in result.metadata.ai_status
    assert "hunt=Ollama is not reachable" in result.metadata.ai_status
    assert result.metadata.ai_review_counts == {"unavailable": 1}
    assert not result.metadata.ai_enabled
    payload = json.loads((root.parent / "reports" / "report.json").read_text())
    assert payload["metadata"]["ai_review_counts"] == {"unavailable": 1}


def test_ai_false_positive_verdict_does_not_change_ci_decision(scan_setup, monkeypatch):
    from dede.models import Severity

    root, cfg, findings = scan_setup
    cfg.ai.enabled = True
    cfg.severity.fail_on = "HIGH"
    findings[0].severity = Severity.HIGH
    monkeypatch.setattr(
        "dede.llm.ensure.ensure_model_installed", lambda *args, **kwargs: (True, "ready")
    )

    def enrich(items, *args, **kwargs):
        items[0].ai_generated = True
        items[0].ai_verdict = "LIKELY_FALSE_POSITIVE"
        items[0].ai_status = "reviewed"
        return items, True, "test-digest", "enabled: enriched=1/1"

    monkeypatch.setattr("dede.pipeline.enrich_findings", enrich)
    result, code = run_scan(root, cfg, progress=False)
    assert code == 1
    assert result.severity_counts["HIGH"] == 1
    assert result.metadata.ai_review_counts == {"reviewed": 1}
    assert not result.findings[0].suppressed


def test_verifier_failure_keeps_scan_and_reports_available(scan_setup, monkeypatch):
    root, cfg, _ = scan_setup
    cfg.ai.enabled = True
    monkeypatch.setattr(
        "dede.llm.ensure.ensure_model_installed", lambda *args, **kwargs: (True, "ready")
    )

    def enrich(items, *args, **kwargs):
        items[0].ai_generated = True
        items[0].ai_status = "reviewed"
        return items, True, "test-digest", "enabled: enriched=1/1"

    def broken(*args):
        raise OSError("controlled verification failure")

    monkeypatch.setattr("dede.pipeline.enrich_findings", enrich)
    monkeypatch.setattr("dede.pipeline.verify_ai_reviews", broken)
    result, code = run_scan(root, cfg, progress=False)
    assert code == 0 and len(result.findings) == 1
    assert result.metadata.ai_validation_counts == {"ERROR": 1}
    assert result.metadata.ai_fix_counts == {"ERROR": 1}
    assert (root.parent / "reports" / "report.json").is_file()


def test_no_ai_pipeline_never_calls_llm_wrappers(scan_setup, monkeypatch):
    root, cfg, _ = scan_setup
    cfg.ai.enabled = False

    def unexpected(*args, **kwargs):
        pytest.fail("--no-ai must not enter enrichment or verification code")

    monkeypatch.setattr("dede.pipeline.enrich_findings", unexpected)
    monkeypatch.setattr("dede.pipeline.verify_ai_reviews", unexpected)
    result, code = run_scan(root, cfg, progress=False)
    assert code == 0
    assert result.metadata.ai_enabled is False
    assert "hard-disabled" in result.metadata.ai_status


def test_not_applicable_analyzer_does_not_probe_version(scan_setup, monkeypatch):
    root, cfg, _ = scan_setup

    class NotApplicable:
        name = "foreign-tool"

        def supports(self, project):
            return False

        def version(self):
            pytest.fail("not-applicable analyzer version must not spawn a subprocess")

    monkeypatch.setattr("dede.pipeline.get_analyzers", lambda: [NotApplicable()])
    result, code = run_scan(root, cfg, progress=False)
    assert code == 0
    assert result.tool_statuses[0].status == ToolStatus.NOT_APPLICABLE
    assert result.tool_statuses[0].version == "not-run"


def test_native_runtime_skips_missing_optional_pdf_dependency(scan_setup, monkeypatch):
    from dede.reporting.pdf_report import PDFDependencyUnavailable

    root, cfg, _ = scan_setup
    cfg.reports.formats = ["json", "pdf"]
    monkeypatch.setenv("DEDE_NATIVE_RUNTIME", "1")
    monkeypatch.setattr(
        "dede.pipeline.write_pdf_report",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            PDFDependencyUnavailable("WeasyPrint not installed")
        ),
    )
    result, code = run_scan(root, cfg, progress=False)
    assert code == 0
    assert result.metadata.files_scanned == 1
    assert (root.parent / "reports" / "report.json").is_file()
