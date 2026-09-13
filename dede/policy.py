"""Deterministic finding policy evaluation."""

from __future__ import annotations

from fnmatch import fnmatch

from dede.config import AppConfig
from dede.models import Finding

_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def evaluate_policy(findings: list[Finding], config: AppConfig) -> list[dict[str, str]]:
    if not config.policy.enabled:
        return []
    violations: list[dict[str, str]] = []
    for policy in config.policy.rules:
        threshold = _RANK[policy.deny_severity]
        categories = set(policy.categories)
        for finding in findings:
            if finding.suppressed or finding.analysis_kind == "ai-hunt":
                continue
            if finding.category.value not in categories:
                continue
            if not fnmatch(finding.file.replace("\\", "/"), policy.path):
                continue
            if _RANK[finding.severity.value] < threshold:
                continue
            violations.append(
                {
                    "policy": policy.name,
                    "finding": finding.id or finding.semantic_fingerprint or finding.fingerprint,
                    "rule_id": finding.rule_id,
                    "file": finding.file,
                    "severity": finding.severity.value,
                }
            )
    return violations
