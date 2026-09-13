from __future__ import annotations

from dede.config import AppConfig
from dede.models import Confidence, Finding
from dede.normalization.precision import apply_precision_gate


def _finding(*, confidence: Confidence, detected_by: list[str] | None = None) -> Finding:
    return Finding(
        tool="dede-engine",
        rule_id="dede.test.low",
        confidence=confidence,
        file="app.py",
        start_line=1,
        end_line=1,
        detected_by=detected_by or ["dede-engine"],
    )


def test_uncorroborated_low_native_finding_is_filtered_by_default() -> None:
    kept, count = apply_precision_gate([_finding(confidence=Confidence.LOW)], AppConfig())
    assert kept == []
    assert count == 1


def test_low_native_finding_is_kept_when_another_engine_confirms_it() -> None:
    finding = _finding(confidence=Confidence.LOW, detected_by=["dede-engine", "semgrep"])
    kept, count = apply_precision_gate([finding], AppConfig())
    assert kept == [finding]
    assert count == 0


def test_user_can_request_low_confidence_native_findings() -> None:
    cfg = AppConfig()
    cfg.engine.report_low_confidence = True
    finding = _finding(confidence=Confidence.LOW)
    kept, count = apply_precision_gate([finding], cfg)
    assert kept == [finding]
    assert count == 0
