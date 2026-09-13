"""Risk score calculation with evidence-aware deterministic weighting."""

from __future__ import annotations

import math

from dede.models import Category, Confidence, Finding, RiskScore, Severity

WEIGHTS = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 7,
    Severity.MEDIUM: 4,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

K = 40.0
_CONFIDENCE = {Confidence.HIGH: 1.0, Confidence.MEDIUM: 0.85, Confidence.LOW: 0.65}


def _finding_multiplier(finding: Finding) -> float:
    """Deterministic multiplier; absence of metadata remains backwards compatible."""
    confidence = finding.confidence_score
    if confidence is None:
        confidence = _CONFIDENCE.get(finding.confidence, 0.85)
    # Explicitly unreachable findings remain visible but contribute less to
    # current exploit risk. Unknown reachability is neutral.
    reachability = 0.35 if finding.reachable is False else 1.0
    exploitability = 1.0
    if finding.exploitability_score is not None:
        exploitability = 0.5 + (finding.exploitability_score / 200.0)
    consensus = 1.0 + min(0.25, 0.08 * max(0, len(set(finding.detected_by)) - 1))
    return max(0.1, min(1.5, confidence * reachability * exploitability * consensus))


def compute_risk_score(findings: list[Finding]) -> RiskScore:
    raw = 0.0
    for finding in findings:
        if finding.suppressed or finding.analysis_kind == "ai-hunt":
            continue
        if finding.category not in {Category.SECURITY, Category.SECRET}:
            continue
        weight = WEIGHTS.get(finding.severity, 0)
        if weight:
            raw += weight * _finding_multiplier(finding)

    score = int(round(100 * (1 - math.exp(-raw / K))))
    score = max(0, min(100, score))
    if score <= 19:
        category = "LOW"
    elif score <= 39:
        category = "MODERATE"
    elif score <= 69:
        category = "HIGH"
    else:
        category = "CRITICAL"

    algorithm = (
        "evidence_weighted_severity_exp_normalize_v2: severity weight × deterministic "
        "confidence × reachability × exploitability × multi-engine consensus; "
        "score = 100 * (1 - exp(-raw/40)); AI-hunt/quality/suppressed findings excluded"
    )
    return RiskScore(
        score=score,
        category=category,
        algorithm=algorithm,
        raw_weighted=round(raw, 4),
        weights={k.value: v for k, v in WEIGHTS.items()},
    )
