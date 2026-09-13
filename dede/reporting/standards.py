"""Summarize explicit static rule mappings, never infer a compliance pass."""

from __future__ import annotations

from dede.models import Finding

ASSESSMENT_SCOPE = (
    "Partial static assessment of mapped controls. Findings require review; an absent finding "
    "does not mean a control passed. Runtime behavior, business authorization, dependency CVEs "
    "and organizational practices require separate verification. NIST SSDF PW.7 source review "
    "can use this evidence; this report does not certify SSDF or ASVS compliance."
)


def standards_assessment(findings: list[Finding]) -> dict:
    grouped: dict[tuple[str, str], dict] = {}
    for finding in findings:
        if finding.suppressed or finding.ai_generated:
            continue
        mappings = {**finding.standards, "OWASP Top 10": finding.owasp, "CWE": finding.cwe}
        for standard, controls in mappings.items():
            for control in set(controls):
                row = grouped.setdefault(
                    (standard, control),
                    {
                        "standard": standard,
                        "control": control,
                        "status": "REVIEW_REQUIRED",
                        "finding_count": 0,
                        "rule_ids": set(),
                    },
                )
                row["finding_count"] += 1
                row["rule_ids"].add(finding.rule_id)
    return {
        "scope": ASSESSMENT_SCOPE,
        "controls": [
            {**row, "rule_ids": sorted(row["rule_ids"])} for _, row in sorted(grouped.items())
        ],
    }
