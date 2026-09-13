"""Maintainability rating and technical debt estimation.

Produces a SonarQube-style maintainability rating (A/B/C/D/E) and an
estimated technical debt in minutes for the scanned codebase. The rating
is derived from the distribution of code_smell, complexity, quality, and
duplicate findings, weighted by estimated remediation effort.
"""

from __future__ import annotations

from dede.models import Category, Finding, Severity

# Sonar-style maintainability ratings mapped from a debt ratio.
# Debt ratio = estimated_debt_minutes / (100 * estimated_clean_minutes).
# Clean minutes are a heuristic based on lines scanned.
RATING_BREAKS = [
    (0.05, "A"),  # Outstanding
    (0.10, "B"),  # Good
    (0.20, "C"),  # Technical debt present
    (0.30, "D"),  # Significant debt
    (0.40, "E"),  # Critical debt
]

# Estimated remediation minutes per finding type, by category and severity.
DEBT_MINUTES = {
    (Category.DUPLICATE, Severity.HIGH): 60,
    (Category.DUPLICATE, Severity.MEDIUM): 30,
    (Category.DUPLICATE, Severity.LOW): 15,
    (Category.CODE_SMELL, Severity.HIGH): 45,
    (Category.CODE_SMELL, Severity.MEDIUM): 20,
    (Category.CODE_SMELL, Severity.LOW): 8,
    (Category.COMPLEXITY, Severity.HIGH): 45,
    (Category.COMPLEXITY, Severity.MEDIUM): 20,
    (Category.COMPLEXITY, Severity.LOW): 8,
    (Category.QUALITY, Severity.HIGH): 30,
    (Category.QUALITY, Severity.MEDIUM): 15,
    (Category.QUALITY, Severity.LOW): 5,
    (Category.BUG, Severity.HIGH): 45,
    (Category.BUG, Severity.MEDIUM): 20,
    (Category.BUG, Severity.LOW): 8,
}

# Clean-code baseline: 1 minute of "good code" per 10 lines scanned.
CLEAN_MINUTES_PER_LINE = 1.0 / 10.0


def maintainability_rating(findings: list[Finding], lines_scanned: int) -> tuple[str, int, float]:
    """Return (rating, total_debt_minutes, debt_ratio).

    Unsuppressed deterministic findings contribute to debt. Advisory AI output
    never changes a deterministic quality metric.
    """
    debt = 0.0
    for f in findings:
        if f.suppressed:
            continue
        if f.analysis_kind == "ai-hunt":
            continue
        minutes = _debt_for(f)
        if minutes:
            debt += minutes

    clean_minutes = max(1.0, lines_scanned * CLEAN_MINUTES_PER_LINE)
    ratio = debt / clean_minutes
    rating = _rating_for(ratio)
    return rating, int(round(debt)), ratio


def _debt_for(f: Finding) -> float | None:
    key = (f.category, f.severity)
    return DEBT_MINUTES.get(key)


def _rating_for(ratio: float) -> str:
    for break_point, letter in RATING_BREAKS:
        if ratio < break_point:
            return letter
    return "E"


def maintainability_breakdown(findings: list[Finding]) -> dict[str, int]:
    """Count findings per smell/quality subcategory for reporting."""
    counts: dict[str, int] = {}
    for f in findings:
        if f.suppressed:
            continue
        if f.category in {
            Category.DUPLICATE,
            Category.CODE_SMELL,
            Category.COMPLEXITY,
            Category.QUALITY,
        }:
            key = f"{f.category}:{f.rule_id}"
            counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: -kv[1]))
