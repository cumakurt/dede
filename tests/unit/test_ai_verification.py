"""Model opinions cannot approve a dismissal or a fix without deterministic checks."""

import pytest

from dede.config import AppConfig
from dede.llm.verification import verify_ai_reviews
from dede.models import AnalyzerResult, Finding, Severity, ToolStatus
from dede.reporting.context import build_finding_view, finding_title
from dede.utils.hashes import sha256_text


@pytest.fixture
def reviewed(tmp_path):
    source = 'def query(cursor, value):\n    cursor.execute("SELECT " + value)\n'
    (tmp_path / "app.py").write_text(source)
    return Finding(
        tool="semgrep",
        rule_id="sql",
        file="app.py",
        start_line=2,
        end_line=2,
        severity=Severity.HIGH,
        message="Static engine warning",
        recommendation="Engine fix",
        ai_generated=True,
        ai_status="reviewed",
        ai_verdict="LIKELY_VALID",
        ai_source_digest=sha256_text(source.rstrip("\n")),
        summary="AI summary",
        recommended_fix="AI fix",
        ai_confidence=1.0,
    )


def repeated(finding, **updates):
    values = dict(tool="semgrep", status=ToolStatus.SUCCESS, findings=[finding.model_copy()])
    values.update(updates)
    return AnalyzerResult(**values)


def check(tmp_path, finding):
    verify_ai_reviews([finding], tmp_path, AppConfig(), tmp_path / "verification")


@pytest.mark.parametrize(
    "verdict,expected",
    [
        ("LIKELY_FALSE_POSITIVE", "CONFLICT"),
        ("LIKELY_VALID", "CORROBORATED"),
        ("NEEDS_CONTEXT", "UNVERIFIED"),
    ],
)
def test_reproduced_warning_is_not_dismissed(tmp_path, reviewed, monkeypatch, verdict, expected):
    reviewed.ai_verdict = verdict
    monkeypatch.setattr("dede.llm.verification._analyze", lambda *args: [repeated(reviewed)])
    check(tmp_path, reviewed)
    assert reviewed.ai_validation_status == expected
    assert reviewed.severity == Severity.HIGH and not reviewed.suppressed
    assert reviewed.ai_verdict == verdict  # Preserve the raw opinion for auditability.
    assert "Reproduced by" in reviewed.ai_validation_notes[0]


@pytest.mark.parametrize(
    "status,expected",
    [
        (ToolStatus.SUCCESS, "UNVERIFIED"),
        (ToolStatus.FAILED, "ERROR"),
        (ToolStatus.NOT_APPLICABLE, "UNVERIFIED"),
    ],
)
def test_missing_match_is_never_proof_of_safety(tmp_path, reviewed, monkeypatch, status, expected):
    reviewed.ai_verdict = "LIKELY_FALSE_POSITIVE"
    monkeypatch.setattr(
        "dede.llm.verification._analyze",
        lambda *args: [repeated(reviewed, status=status, findings=[])],
    )
    check(tmp_path, reviewed)
    assert reviewed.ai_validation_status == expected
    assert reviewed.ai_validation_status != "CORROBORATED"


def test_failed_partial_engine_output_cannot_corroborate(tmp_path, reviewed, monkeypatch):
    monkeypatch.setattr(
        "dede.llm.verification._analyze",
        lambda *args: [repeated(reviewed, status=ToolStatus.FAILED)],
    )
    check(tmp_path, reviewed)
    assert reviewed.ai_validation_status == "ERROR"


@pytest.mark.parametrize(
    "updates",
    [
        {"file": "other.py"},
        {"rule_id": "other-rule"},
        {"start_line": 50, "end_line": 50},
    ],
)
def test_nearby_unrelated_warning_does_not_verify_the_claim(
    tmp_path, reviewed, monkeypatch, updates
):
    other = reviewed.model_copy(update=updates)
    monkeypatch.setattr("dede.llm.verification._analyze", lambda *args: [repeated(other)])
    check(tmp_path, reviewed)
    assert reviewed.ai_validation_status == "UNVERIFIED"


def test_changed_source_is_not_verified(tmp_path, reviewed, monkeypatch):
    (tmp_path / "app.py").write_text("# changed after model request\n")
    files_checked = []

    def analyze(root, files, *args):
        files_checked.extend(files)
        return []

    monkeypatch.setattr("dede.llm.verification._analyze", analyze)
    check(tmp_path, reviewed)
    assert reviewed.ai_validation_status == "SOURCE_CHANGED" and not files_checked


def test_source_changed_during_recheck_is_not_verified(tmp_path, reviewed, monkeypatch):
    def analyze(*args):
        (tmp_path / "app.py").write_text("# changed during verification\n")
        return [repeated(reviewed)]

    monkeypatch.setattr("dede.llm.verification._analyze", analyze)
    check(tmp_path, reviewed)
    assert reviewed.ai_validation_status == "SOURCE_CHANGED"


@pytest.mark.parametrize(
    "example,status",
    [
        ("", "NOT_PROVIDED"),
        ("def broken(:", "SYNTAX_ERROR"),
        ("```python\npass\n```\n```python\npass\n```", "UNSUPPORTED"),
    ],
)
def test_incomplete_examples_are_not_approved(tmp_path, reviewed, monkeypatch, example, status):
    reviewed.secure_code_example = example
    monkeypatch.setattr("dede.llm.verification._analyze", lambda *args: [])
    check(tmp_path, reviewed)
    assert reviewed.ai_fix_status == status


@pytest.mark.parametrize(
    "issues,engine_status,expected",
    [
        (False, ToolStatus.SUCCESS, "CHECKS_PASSED"),
        (True, ToolStatus.SUCCESS, "ISSUES_FOUND"),
        (False, ToolStatus.FAILED, "ERROR"),
        (False, ToolStatus.NOT_APPLICABLE, "ERROR"),
    ],
)
def test_example_results_remain_scoped_to_static_checks(
    tmp_path, reviewed, monkeypatch, issues, engine_status, expected
):
    reviewed.secure_code_example = "```python\nprint(1)\n```"

    def analyze(root, files, cfg, output):
        assert cfg.scan.analyzer_timeout_seconds == cfg.ai.verification_timeout_seconds
        if output.name == "source":
            return [repeated(reviewed)]
        assert len(files) == 1 and files[0].read_text() == "print(1)"
        found = [Finding(tool="ruff", rule_id="F821", file=str(files[0]))] if issues else []
        return [AnalyzerResult(tool="ruff", status=engine_status, findings=found)]

    monkeypatch.setattr("dede.llm.verification._analyze", analyze)
    check(tmp_path, reviewed)
    assert reviewed.ai_fix_status == expected
    if expected == "CHECKS_PASSED":
        assert "Not a validated patch" in reviewed.ai_fix_notes[0]


def test_candidate_source_is_not_rewritten(tmp_path, reviewed, monkeypatch):
    reviewed.secure_code_example = 'eval("nosemgrep")  # noqa: S307\n# nosemgrep\n'

    def analyze(root, files, cfg, output):
        if output.name == "examples":
            content = files[0].read_text()
            assert content == reviewed.secure_code_example.strip()
        return []

    monkeypatch.setattr("dede.llm.verification._analyze", analyze)
    check(tmp_path, reviewed)
    assert reviewed.ai_fix_status == "ERROR"


def test_cached_review_is_rechecked(tmp_path, reviewed, monkeypatch):
    reviewed.ai_status = "cached"
    reviewed.ai_validation_status = "CORROBORATED"
    reviewed.ai_verdict = "LIKELY_FALSE_POSITIVE"
    monkeypatch.setattr("dede.llm.verification._analyze", lambda *args: [repeated(reviewed)])
    check(tmp_path, reviewed)
    assert reviewed.ai_validation_status == "CONFLICT"


@pytest.mark.parametrize("status", ["UNVERIFIED", "CONFLICT", "ERROR", "SOURCE_CHANGED"])
def test_ai_text_is_visible_with_origin_even_when_verification_disagrees(reviewed, status):
    reviewed.ai_validation_status = status
    view = build_finding_view(reviewed)
    assert view["risk_text"] == "AI summary"
    assert view["remediation_text"] == "AI fix"
    assert view["risk_origin"] == view["remediation_origin"] == "AI"
    assert finding_title(reviewed) == "AI summary"
    assert reviewed.message == "Static engine warning"
    assert reviewed.ai_validation_status == status


def test_flagged_example_remains_visible_as_ai_proposal(reviewed):
    reviewed.ai_validation_status = "CORROBORATED"
    reviewed.ai_fix_status = "ISSUES_FOUND"
    reviewed.secure_code_example = "eval(value)"
    view = build_finding_view(reviewed)
    assert view["secure_example"] == "eval(value)"
    assert view["secure_example_is_ai"]
    assert view["remediation_text"] == "AI fix"
    assert reviewed.ai_fix_status == "ISSUES_FOUND"


def test_corroborated_model_prose_retains_ai_origin(reviewed):
    reviewed.ai_validation_status = "CORROBORATED"
    reviewed.ai_fix_status = "CHECKS_PASSED"
    reviewed.technical_explanation = "Unsupported model claim"
    reviewed.ai_impact = "Unsupported model impact"
    view = build_finding_view(reviewed)
    assert view["risk_text"] == "AI summary"
    assert view["technical_text"] == "Unsupported model claim"
    assert view["impact_text"] == "Unsupported model impact"
    assert view["remediation_text"] == "AI fix"
    for key in ("risk_origin", "technical_origin", "impact_origin", "remediation_origin"):
        assert view[key] == "AI"
