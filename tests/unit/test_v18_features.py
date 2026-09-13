from __future__ import annotations

import json
from pathlib import Path

from dede.config import AppConfig
from dede.feedback import apply_feedback, record_feedback
from dede.fix_verification import verify_reports
from dede.models import Finding, ProjectContext, Severity
from dede.precision_lab import run_precision_corpus
from dede.sca import DependencyReachabilityAnalyzer
from dede.semantic.model_packs import sign_pack, verify_pack
from dede.semantic.polyglot import PolyglotSemanticAnalyzer


def _project(root: Path, files: list[Path], **flags: bool) -> ProjectContext:
    return ProjectContext(root=str(root), files=[str(p) for p in files], **flags)


def test_polyglot_js_requires_proven_source_to_known_sink(tmp_path: Path) -> None:
    good = tmp_path / "app.js"
    good.write_text("function x(req, db) {\n const q = req.query.q;\n return db.query('select '+q);\n}\n", encoding="utf-8")
    project = _project(tmp_path, [good], has_javascript=True)
    result = PolyglotSemanticAnalyzer().analyze(project, AppConfig(), tmp_path / "raw")
    assert any("CWE-89" in f.cwe for f in result.findings)

    safe = tmp_path / "safe.js"
    safe.write_text("function x(req, executor) {\n const q = req.query.q;\n return executor.execute(q);\n}\n", encoding="utf-8")
    project = _project(tmp_path, [safe], has_javascript=True)
    result = PolyglotSemanticAnalyzer().analyze(project, AppConfig(), tmp_path / "raw2")
    assert result.findings == []


def test_sca_exact_version_and_reachability(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("demo-lib==1.2.0\n", encoding="utf-8")
    source = tmp_path / "app.py"
    source.write_text("import demo_lib\nprint(demo_lib)\n", encoding="utf-8")
    advisory = tmp_path / "advisories.json"
    advisory.write_text(json.dumps({"advisories": [{
        "id": "TEST-2026-1", "ecosystem": "PyPI", "package": "demo-lib",
        "introduced": "1.0.0", "fixed": "1.3.0", "severity": "HIGH", "cwe": ["CWE-20"]
    }]}), encoding="utf-8")
    cfg = AppConfig()
    cfg.sca.advisory_paths = [str(advisory)]
    project = _project(tmp_path, [source, tmp_path / "requirements.txt"], has_python=True)
    result = DependencyReachabilityAnalyzer().analyze(project, cfg, tmp_path / "raw")
    assert len(result.findings) == 1
    assert result.findings[0].reachable is True
    assert result.findings[0].severity == Severity.HIGH


def test_model_pack_hmac_signature(tmp_path: Path) -> None:
    pack = tmp_path / "pack.json"
    pack.write_text(json.dumps({
        "schema_version": 1, "name": "corp", "version": "1.0",
        "models": {"python": {"sources": [{"call": "corp.input", "kind": "http.custom"}]}}
    }), encoding="utf-8")
    digest = sign_pack(pack, "secret-key")
    loaded = verify_pack(pack, secret="secret-key", require_signature=True)
    assert loaded.verified is True
    assert loaded.digest == digest


def test_feedback_is_advisory_by_default(tmp_path: Path) -> None:
    cfg = AppConfig()
    cfg.feedback.path = str(tmp_path / "feedback.json")
    f = Finding(tool="x", rule_id="r", file="a.py", severity=Severity.HIGH, semantic_fingerprint="sem-1", sink_kind="sql")
    record_feedback(Path(cfg.feedback.path), semantic_fingerprint="sem-1", verdict="false-positive", reason="validated wrapper", rule_id="r", sink_kind="sql")
    counts = apply_feedback([f], cfg, tmp_path)
    assert counts["exact"] == 1
    assert f.feedback_verdict == "false-positive"
    assert f.suppressed is False


def test_precision_lab_builtin_corpus() -> None:
    corpus = Path(__file__).resolve().parents[2] / "dede" / "benchmarks" / "precision-corpus.json"
    metrics, detail = run_precision_corpus(corpus)
    assert metrics.precision >= 0.99
    assert metrics.recall >= 0.99
    assert all(case["passed"] for case in detail["cases"])


def test_verify_fix_detects_removed_finding(tmp_path: Path) -> None:
    before = tmp_path / "before.json"; after = tmp_path / "after.json"
    before.write_text(json.dumps({"findings": [{"semantic_fingerprint": "abc", "severity": "HIGH"}]}), encoding="utf-8")
    after.write_text(json.dumps({"findings": []}), encoding="utf-8")
    result = verify_reports(before, after)
    assert result.status == "VERIFIED_BY_RESCAN"


def test_installer_defaults_are_yes() -> None:
    text = (Path(__file__).resolve().parents[2] / "install.sh").read_text(encoding="utf-8")
    assert '[default=yes]' in text
    assert '""|y|Y|yes|YES)' in text
    assert '"$WITH_REPORTING" -eq 1 || "$ASSUME_YES" -eq 1' in text
    assert '"$WITH_DOCKER" -eq 1 || "$ASSUME_YES" -eq 1' in text
    assert '"$PULL_MODEL" -eq 1 || "$ASSUME_YES" -eq 1' in text


def test_agent_security_only_flags_explicit_dangerous_permissions(tmp_path: Path) -> None:
    from dede.agent_security import AgentSecurityAnalyzer
    cfg_file = tmp_path / "mcp.json"
    cfg_file.write_text(json.dumps({"servers": {"x": {"sandbox": False}}}), encoding="utf-8")
    project = _project(tmp_path, [cfg_file])
    result = AgentSecurityAnalyzer().analyze(project, AppConfig(), tmp_path / "raw-agent")
    assert len(result.findings) == 1
    assert result.findings[0].precision.value == "VERY_HIGH"


def test_experimental_authorization_is_off_by_default_and_opt_in(tmp_path: Path) -> None:
    from dede.authorization import ExperimentalAuthorizationAnalyzer
    source = tmp_path / "app.py"
    source.write_text("@app.get('/users/{id}')\ndef user(id):\n    return db.users.get(id)\n", encoding="utf-8")
    project = _project(tmp_path, [source], has_python=True)
    analyzer = ExperimentalAuthorizationAnalyzer()
    assert analyzer.analyze(project, AppConfig(), tmp_path / "raw-off").findings == []
    cfg = AppConfig(); cfg.experimental.authorization_analysis = True
    result = analyzer.analyze(project, cfg, tmp_path / "raw-on")
    assert len(result.findings) == 1
    assert result.findings[0].precision.value == "EXPERIMENTAL"


def test_mcp_report_query_is_read_only_and_searchable() -> None:
    from dede.mcp_server import _call
    report = {"findings": [{"id": "D1", "severity": "HIGH", "rule_id": "sql", "file": "app.py", "message": "SQL injection", "cwe": ["CWE-89"]}]}
    summary = _call(report, "findings_summary", {})
    assert summary["findings"] == 1
    assert _call(report, "findings_search", {"query": "CWE-89"})[0]["id"] == "D1"


def test_external_pack_signature_policy_does_not_reject_bundled_packs(tmp_path: Path, monkeypatch) -> None:
    from dede.semantic.model_packs import load_model_packs
    pack = tmp_path / "external.json"
    pack.write_text(json.dumps({"schema_version": 1, "name": "external", "version": "1", "models": {}}), encoding="utf-8")
    cfg = AppConfig(); cfg.model_packs.paths = [str(pack)]; cfg.model_packs.require_signature = True
    monkeypatch.setenv("DEDE_MODEL_PACK_KEY", "key")
    try:
        load_model_packs(cfg, tmp_path)
    except ValueError as exc:
        assert "Unsigned model pack" in str(exc)
    else:
        raise AssertionError("unsigned external pack should be rejected")
