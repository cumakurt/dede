"""Unit tests for redaction and fingerprinting."""

from dede.models import Category, Finding, Severity
from dede.normalization.deduplicate import deduplicate_findings
from dede.normalization.findings import compute_fingerprint
from dede.normalization.risk import compute_risk_score
from dede.utils.redact import mask_secret, redact_text


def test_mask_secret():
    assert mask_secret("ABCDEFGH") == "AB****GH"
    assert "*" in mask_secret("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")


def test_redact_text_password():
    text = "password=SuperSecretValue123"
    redacted = redact_text(text)
    assert "SuperSecretValue123" not in redacted
    assert "password=" in redacted


def test_fingerprint_stable():
    a = Finding(
        tool="semgrep",
        rule_id="python.lang.security.audit.exec-detected",
        category=Category.SECURITY,
        severity=Severity.HIGH,
        cwe=["CWE-78"],
        file="src/a.py",
        start_line=10,
        end_line=10,
        normalized_type="python.lang.security.audit.exec-detected",
    )
    b = Finding(
        tool="bandit",
        rule_id="B605",
        category=Category.SECURITY,
        severity=Severity.HIGH,
        cwe=["CWE-78"],
        file="src/a.py",
        start_line=10,
        end_line=10,
        normalized_type="python.lang.security.audit.exec-detected",
    )
    assert compute_fingerprint(a) == compute_fingerprint(b)


def test_dedup_merges_tools():
    a = Finding(
        tool="semgrep",
        rule_id="r1",
        cwe=["CWE-78"],
        file="a.py",
        start_line=1,
        end_line=1,
        severity=Severity.HIGH,
        normalized_type="exec",
        message="a",
    )
    b = Finding(
        tool="bandit",
        rule_id="r2",
        cwe=["CWE-78"],
        file="a.py",
        start_line=1,
        end_line=1,
        severity=Severity.HIGH,
        normalized_type="exec",
        message="b",
    )
    merged = deduplicate_findings([a, b])
    assert len(merged) == 1
    assert set(merged[0].detected_by) == {"semgrep", "bandit"}


def test_risk_score_bounds():
    findings = [
        Finding(
            tool="t",
            rule_id="r",
            file="f.py",
            severity=Severity.CRITICAL,
            message="x",
        )
        for _ in range(50)
    ]
    risk = compute_risk_score(findings)
    assert 0 <= risk.score <= 100
    assert risk.category in {"LOW", "MODERATE", "HIGH", "CRITICAL"}


def test_quality_findings_do_not_inflate_security_risk():
    security = Finding(tool="test", rule_id="security", file="a.py", severity=Severity.HIGH)
    quality = [
        Finding(
            tool="test",
            rule_id=category.value,
            category=category,
            file="a.py",
            severity=Severity.HIGH,
        )
        for category in (
            Category.CODE_SMELL,
            Category.DUPLICATE,
            Category.COMPLEXITY,
            Category.QUALITY,
            Category.MAINTAINABILITY,
            Category.BUG,
        )
    ]
    assert compute_risk_score(quality).score == 0
    assert compute_risk_score([security, *quality]) == compute_risk_score([security])
