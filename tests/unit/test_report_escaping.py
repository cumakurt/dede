"""Source and analyzer text must remain text in both report formats."""

import sys
import json
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from dede.models import Finding, LanguageStats, ScanMetadata, ScanResult
from dede.reporting.html_report import write_html_report
from dede.reporting.pdf_report import write_pdf_report
from dede.reporting.json_report import write_json_report
from dede.reporting.context import build_finding_view


def _result():
    return ScanResult(
        metadata=ScanMetadata(
            scanner_version="test", scan_started=datetime(2026, 1, 1, tzinfo=timezone.utc)
        ),
        languages=LanguageStats(),
        findings=[
            Finding(
                tool="test",
                rule_id="r",
                file="source.py",
                id="test-finding",
                message="<script>report_marker()</script>",
                code_snippet='<img src="file:///untrusted-local-file">',
            )
        ],
    )


def _assert_escaped(html):
    assert "<script>report_marker()</script>" not in html
    assert "&lt;script&gt;report_marker()&lt;/script&gt;" in html
    assert '<img src="file:///untrusted-local-file">' not in html
    assert "&lt;img" in html


def test_html_escapes_source_and_messages(tmp_path):
    html = write_html_report(_result(), tmp_path).read_text()
    _assert_escaped(html)


def test_pdf_escapes_content_before_rendering(tmp_path, monkeypatch):
    captured = []

    class HTML:
        def __init__(self, string, base_url):
            captured.append(string)

        def write_pdf(self, path):
            pass

    monkeypatch.setitem(sys.modules, "weasyprint", SimpleNamespace(HTML=HTML))
    write_pdf_report(_result(), tmp_path)
    _assert_escaped(captured[0])


def test_ai_assessment_is_advisory_and_escaped(tmp_path):
    result = _result()
    finding = result.findings[0]
    finding.ai_generated = True
    finding.ai_verdict = "NEEDS_CONTEXT"
    finding.ai_rationale = "<script>ai_marker()</script>"
    finding.ai_verification = "Test with an untrusted input."
    finding.ai_model = "example:small"
    finding.ai_confidence = 0.0
    result.metadata.ai_status = "enabled: enriched=1/1"
    html = write_html_report(result, tmp_path).read_text()
    assert "AI Review — Advisory" in html and "NEEDS_CONTEXT" in html
    assert "<script>ai_marker()</script>" not in html
    assert "&lt;script&gt;ai_marker()&lt;/script&gt;" in html
    assert "0% (not calibrated)" in html
    assert "AI-suggested regression test" in html
    assert "enabled: enriched=1/1" in html


@pytest.mark.parametrize("format", ["html", "pdf"])
def test_model_content_and_origins_are_visible_despite_static_conflict(
    tmp_path, monkeypatch, format
):
    result = _result()
    finding = result.findings[0]
    finding.ai_generated = True
    finding.summary = "MODEL_SUMMARY"
    finding.technical_explanation = "MODEL_EXPLANATION"
    finding.recommended_fix = "MODEL_FIX"
    finding.recommendation = "ENGINE_FIX"
    finding.impact = "ENGINE_IMPACT"
    finding.secure_code_example = "eval(user_input)"
    finding.ai_validation_status = "CONFLICT"
    finding.ai_fix_status = "ISSUES_FOUND"
    if format == "html":
        html = write_html_report(result, tmp_path).read_text()
    else:
        captured = []

        class HTML:
            def __init__(self, string, base_url):
                captured.append(string)

            def write_pdf(self, path):
                pass

        monkeypatch.setitem(sys.modules, "weasyprint", SimpleNamespace(HTML=HTML))
        write_pdf_report(result, tmp_path)
        html = captured[0]
    assert 'data-origin="AI"' in html and 'data-origin="Static analysis"' in html
    assert 'Risk <span class="source-tag source-ai"' in html
    assert 'Impact <span class="source-tag source-static"' in html
    for text in (
        "MODEL_SUMMARY",
        "MODEL_EXPLANATION",
        "MODEL_FIX",
        "ENGINE_FIX",
        "ENGINE_IMPACT",
        "eval(user_input)",
    ):
        assert text in html
    assert "CONFLICT" in html and "ISSUES_FOUND" in html
    assert "not an approved fix" in html
    assert "Unverified model proposal" not in html  # No collapsed-only proposal.
    _assert_escaped(html)


def test_missing_model_fields_use_static_origin():
    finding = _result().findings[0]
    finding.ai_generated = True
    finding.summary = "AI title"
    finding.explanation = "Engine explanation"
    view = build_finding_view(finding)
    assert view["title_origin"] == view["risk_origin"] == "AI"
    assert view["technical_origin"] == view["impact_origin"] == "Static analysis"
    assert view["technical_text"] == "Engine explanation"


def test_json_declares_model_engine_and_verification_field_origins(tmp_path):
    result = _result()
    result.findings[0].summary = "AI title"
    payload = json.loads(write_json_report(result, tmp_path).read_text())
    assert "summary" in payload["field_origins"]["AI"]
    assert "message" in payload["field_origins"]["Static analysis"]
    assert "ai_validation_status" in payload["field_origins"]["Static verification"]
    assert payload["findings"][0]["summary"] == "AI title"
