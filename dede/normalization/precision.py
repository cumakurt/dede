"""Precision-first post-correlation filtering and scan profiles.

The gate runs after cross-tool correlation.  That ordering is deliberate: a
medium-confidence rule can become highly actionable when a second independent
engine reports the same weakness at the same semantic location.
"""
from __future__ import annotations

from dede.config import AppConfig
from dede.models import Confidence, Finding, Precision


def _corroborated(finding: Finding) -> bool:
    return len(set(finding.detected_by or [finding.tool])) >= 2 or finding.correlation_score >= 0.85


def apply_precision_gate(findings: list[Finding], config: AppConfig) -> tuple[list[Finding], int]:
    """Apply the configured precision profile and return (kept, filtered)."""
    profile = config.engine.profile
    if config.engine.report_low_confidence and profile == "smart":
        # Historical behavior: the explicit flag means ``audit`` breadth.
        profile = "audit"

    retained: list[Finding] = []
    filtered = 0
    for finding in findings:
        corroborated = _corroborated(finding)
        keep = True

        if profile == "experimental":
            keep = True
        elif profile == "audit":
            keep = finding.precision != Precision.EXPERIMENTAL or corroborated
        elif profile == "strict":
            keep = (
                finding.precision == Precision.VERY_HIGH
                or (
                    corroborated
                    and finding.confidence == Confidence.HIGH
                    and finding.precision in {Precision.HIGH, Precision.VERY_HIGH}
                )
            )
        else:  # smart
            low_native_only = (
                finding.tool == "dede-engine"
                and finding.confidence == Confidence.LOW
                and not corroborated
            )
            experimental_only = finding.precision == Precision.EXPERIMENTAL and not corroborated
            keep = not low_native_only and not experimental_only

        if keep:
            retained.append(finding)
        else:
            filtered += 1
    return retained, filtered
