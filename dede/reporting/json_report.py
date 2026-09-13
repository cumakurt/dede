"""JSON report writer and machine-readable report payload builder."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from dede.models import ScanResult
from dede.normalization.maintainability import maintainability_breakdown
from dede.reporting.standards import standards_assessment


def build_json_payload(result: ScanResult) -> dict[str, Any]:
    """Build the canonical machine-readable report payload.

    PDF reporting embeds this payload as an attachment, so keeping the builder
    separate prevents the human and machine-readable reports from drifting.
    """
    payload = result.model_dump(mode="json")
    payload["standards_assessment"] = standards_assessment(result.findings)
    payload["maintainability"] = {
        "rating": result.maintainability_rating,
        "debt_minutes": result.maintainability_debt_minutes,
        "debt_ratio": result.maintainability_debt_ratio,
        "smell_breakdown": maintainability_breakdown(result.findings),
    }
    payload["field_origins"] = {
        "AI": [
            "summary",
            "technical_explanation",
            "ai_impact",
            "exploitability",
            "false_positive_probability",
            "recommended_fix",
            "secure_code_example",
            "ai_confidence",
            "ai_verdict",
            "ai_rationale",
            "ai_assumptions",
            "ai_verification",
        ],
        "Static analysis": [
            "tool",
            "rule_id",
            "severity",
            "confidence",
            "message",
            "code_snippet",
            "explanation",
            "impact",
            "attack_scenario",
            "recommendation",
            "secure_example",
            "cwe",
            "owasp",
            "standards",
            "dataflow",
            "semantic_fingerprint",
            "symbol",
            "function",
            "source_kind",
            "sink_kind",
            "reachable",
            "exploitability_score",
            "confidence_score",
            "precision",
            "evidence",
            "correlation_score",
            "ast_fingerprint",
            "endpoint",
            "http_method",
            "authentication_required",
            "internet_exposed",
            "attack_surface",
            "attack_path",
            "query_matches",
            "lifecycle_status",
        ],
        "Static verification": [
            "ai_validation_status",
            "ai_validation_notes",
            "ai_fix_status",
            "ai_fix_notes",
        ],
    }
    return payload


def write_json_report(result: ScanResult, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "report.json"
    path.write_text(
        json.dumps(build_json_payload(result), indent=2, default=str),
        encoding="utf-8",
    )
    return path
