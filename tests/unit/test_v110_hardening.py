from __future__ import annotations

import json
from pathlib import Path

from dede.authorization import ExperimentalAuthorizationAnalyzer
from dede.config import AppConfig
from dede.models import Confidence, Finding, LanguageStats, Precision, ProjectContext
from dede.normalization.precision import apply_precision_gate
from dede.precision_lab import run_hardening_corpus
from dede.security_hardening import SecurityHardeningAnalyzer
from dede.semantic.model_packs import verify_pack
from dede.semantic.polyglot import PolyglotSemanticAnalyzer
from dede.semantic.python_ast import PythonSemanticAnalyzer


def _project(tmp_path: Path, filename: str, source: str) -> ProjectContext:
    path = tmp_path / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    suffix = path.suffix.lower()
    return ProjectContext(
        root=str(tmp_path),
        files=[str(path)],
        languages=LanguageStats(languages={"Test": 100.0}),
        has_python=suffix == ".py",
        has_javascript=suffix in {".js", ".jsx", ".mjs", ".cjs"},
        has_typescript=suffix in {".ts", ".tsx"},
        has_java=suffix == ".java",
        has_csharp=suffix == ".cs",
        has_go=suffix == ".go",
        has_php=suffix == ".php",
    )


def _finding(*, precision: Precision, confidence: Confidence = Confidence.HIGH, detected_by: list[str] | None = None) -> Finding:
    return Finding(
        tool="dede-engine",
        rule_id="dede.test.profile",
        file="app.py",
        start_line=1,
        end_line=1,
        precision=precision,
        confidence=confidence,
        detected_by=detected_by or ["dede-engine"],
    )


def test_hardening_detects_explicit_tls_bypass(tmp_path: Path) -> None:
    project = _project(tmp_path, "app.py", 'import requests\nrequests.get("https://example.test", verify=False)\n')
    result = SecurityHardeningAnalyzer().analyze(project, AppConfig(), tmp_path / "raw")
    assert any(f.rule_id == "dede.hardening.python.tls-verify-false" for f in result.findings)
    assert all(f.precision in {Precision.VERY_HIGH, Precision.HIGH} for f in result.findings)


def test_hardening_does_not_flag_logging_literal_secret_word(tmp_path: Path) -> None:
    project = _project(tmp_path, "app.py", 'import logging\nlogging.info("password reset requested")\n')
    result = SecurityHardeningAnalyzer().analyze(project, AppConfig(), tmp_path / "raw")
    assert not any(f.rule_id == "dede.hardening.sensitive-data.logging" for f in result.findings)


def test_hardening_flags_secret_variable_logging(tmp_path: Path) -> None:
    project = _project(tmp_path, "app.py", 'import logging\napi_token = "x"\nlogging.info("token=%s", api_token)\n')
    result = SecurityHardeningAnalyzer().analyze(project, AppConfig(), tmp_path / "raw")
    assert any(f.rule_id == "dede.hardening.sensitive-data.logging" for f in result.findings)


def test_hardening_precision_corpus_meets_perfect_regression_baseline() -> None:
    corpus = Path(__file__).parents[2] / "dede" / "benchmarks" / "hardening-corpus.json"
    metrics, payload = run_hardening_corpus(corpus)
    assert metrics.false_positive == 0
    assert metrics.false_negative == 0
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0
    assert all(case["passed"] for case in payload["cases"])


def test_security_profiles_keep_experimental_out_of_production_defaults() -> None:
    candidate = _finding(precision=Precision.EXPERIMENTAL, confidence=Confidence.LOW)
    cfg = AppConfig()
    assert apply_precision_gate([candidate], cfg) == ([], 1)

    cfg.engine.profile = "audit"
    assert apply_precision_gate([candidate], cfg) == ([], 1)

    cfg.engine.profile = "experimental"
    assert apply_precision_gate([candidate], cfg) == ([candidate], 0)


def test_strict_profile_requires_very_high_or_corroborated_high() -> None:
    cfg = AppConfig()
    cfg.engine.profile = "strict"
    high = _finding(precision=Precision.HIGH, confidence=Confidence.HIGH)
    very_high = _finding(precision=Precision.VERY_HIGH)
    corroborated = _finding(precision=Precision.HIGH, confidence=Confidence.HIGH, detected_by=["dede-engine", "semgrep"])
    kept, filtered = apply_precision_gate([high, very_high, corroborated], cfg)
    assert kept == [very_high, corroborated]
    assert filtered == 1


def test_python_semantic_secret_environment_to_log(tmp_path: Path) -> None:
    project = _project(
        tmp_path,
        "app.py",
        'import os, logging\n\ndef h():\n    api_token = os.getenv("API_TOKEN")\n    logging.info("token=%s", api_token)\n',
    )
    result = PythonSemanticAnalyzer().analyze(project, AppConfig(), tmp_path / "raw")
    assert any("CWE-532" in f.cwe and f.source_kind == "secret.environment" for f in result.findings)


def test_python_semantic_ldap_and_unsafe_deserialization(tmp_path: Path) -> None:
    project = _project(
        tmp_path,
        "app.py",
        'from flask import request\nimport pickle\n\ndef h(ldap_conn):\n    q=request.args.get("q")\n    ldap_conn.search("dc=example", q)\n    pickle.loads(q)\n',
    )
    result = PythonSemanticAnalyzer().analyze(project, AppConfig(), tmp_path / "raw")
    cwes = {cwe for finding in result.findings for cwe in finding.cwe}
    assert "CWE-90" in cwes
    assert "CWE-502" in cwes


def test_polyglot_nosql_and_secret_logging(tmp_path: Path) -> None:
    project = _project(
        tmp_path,
        "app.js",
        'function h(req){\n  const q=req.query.q;\n  collection.find(q);\n  const apiSecret=process.env.API_SECRET;\n  console.log(apiSecret);\n}\n',
    )
    result = PolyglotSemanticAnalyzer().analyze(project, AppConfig(), tmp_path / "raw")
    cwes = {cwe for finding in result.findings for cwe in finding.cwe}
    assert "CWE-943" in cwes
    assert "CWE-532" in cwes


def test_authorization_and_business_logic_are_opt_in(tmp_path: Path) -> None:
    source = '''\nfrom flask import Flask, request\napp=Flask(__name__)\n@app.get("/admin/users/{id}")\ndef admin_user(id):\n    return users.get(id)\n@app.post("/charge")\ndef charge():\n    amount=request.json["amount"]\n    account.balance -= amount\n    return "ok"\n'''
    project = _project(tmp_path, "app.py", source)
    analyzer = ExperimentalAuthorizationAnalyzer()
    disabled = analyzer.analyze(project, AppConfig(), tmp_path / "raw-disabled")
    assert disabled.findings == []

    cfg = AppConfig()
    cfg.experimental.authorization_analysis = True
    cfg.experimental.business_logic_analysis = True
    enabled = analyzer.analyze(project, cfg, tmp_path / "raw-enabled")
    rules = {f.rule_id for f in enabled.findings}
    assert "dede.experimental.privileged-route-missing-auth" in rules
    assert "dede.experimental.possible-idor" in rules
    assert "dede.experimental.unvalidated-financial-value" in rules
    assert all(f.precision == Precision.EXPERIMENTAL for f in enabled.findings)


def test_new_framework_packs_have_valid_integrity() -> None:
    root = Path(__file__).parents[2] / "dede" / "semantic" / "packs"
    for name in ("laravel.json", "nestjs.json", "go-web.json", "rails.json", "vapor.json"):
        pack = verify_pack(root / name)
        assert pack.verified
        assert pack.models


def test_hardening_raw_report_contains_check_count(tmp_path: Path) -> None:
    project = _project(tmp_path, "app.go", 'package main\nvar c=&tls.Config{InsecureSkipVerify:true}\n')
    result = SecurityHardeningAnalyzer().analyze(project, AppConfig(), tmp_path / "raw")
    payload = json.loads(Path(result.raw_path).read_text(encoding="utf-8"))
    assert payload["checks"] >= 20 if "checks" in payload else payload["rule_count"] >= 20
    assert payload["hits"] >= 1


def test_exact_location_same_cwe_correlates_duplicate_rule_labels() -> None:
    from dede.models import Category, Severity
    from dede.normalization.deduplicate import deduplicate_findings

    a = Finding(
        tool="dede-engine", rule_id="dede.a", category=Category.SECURITY,
        severity=Severity.HIGH, confidence=Confidence.HIGH, precision=Precision.HIGH,
        cwe=["CWE-295"], file="app.py", start_line=7, end_line=7,
        normalized_type="tls-verification-disabled", detected_by=["dede-engine"],
    )
    b = Finding(
        tool="dede-hardening", rule_id="dede.b", category=Category.SECURITY,
        severity=Severity.HIGH, confidence=Confidence.HIGH, precision=Precision.VERY_HIGH,
        cwe=["CWE-295"], file="app.py", start_line=7, end_line=7,
        normalized_type="verify-disabled", detected_by=["dede-hardening"],
    )
    merged = deduplicate_findings([a, b])
    assert len(merged) == 1
    assert set(merged[0].detected_by) == {"dede-engine", "dede-hardening"}
    assert merged[0].correlation_score >= 0.96
