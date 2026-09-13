"""Finding suppression with scoped, expiring policy entries."""

from __future__ import annotations

from datetime import UTC, date, datetime
from fnmatch import fnmatch

from dede.config import AppConfig
from dede.models import Finding


def _entry_matches(finding: Finding, entry: object) -> bool:
    rule = getattr(entry, "rule", "")
    fp = str(getattr(entry, "fingerprint", "")).removeprefix("sha256:")
    path = getattr(entry, "path", "**") or "**"
    if rule and rule != finding.rule_id:
        return False
    if fp and fp not in {
        finding.fingerprint.removeprefix("sha256:"),
        finding.semantic_fingerprint.removeprefix("sha256:"),
    }:
        return False
    if not fnmatch(finding.file.replace("\\", "/"), path):
        return False
    expires = getattr(entry, "expires", None)
    if expires and date.fromisoformat(expires) < datetime.now(UTC).date():
        return False
    return bool(rule or fp)


def apply_suppressions(
    findings: list[Finding], config: AppConfig
) -> tuple[list[Finding], list[Finding]]:
    fp_set = {f.removeprefix("sha256:") for f in config.suppress.fingerprints}
    rule_set = set(config.suppress.rules)
    active: list[Finding] = []
    suppressed: list[Finding] = []
    for finding in findings:
        identities = {
            finding.fingerprint.removeprefix("sha256:"),
            finding.semantic_fingerprint.removeprefix("sha256:"),
        }
        if identities & fp_set:
            finding.suppressed = True
            finding.suppress_reason = "fingerprint"
            suppressed.append(finding)
            continue
        if finding.rule_id in rule_set:
            finding.suppressed = True
            finding.suppress_reason = "rule"
            suppressed.append(finding)
            continue
        matched = next((entry for entry in config.suppress.entries if _entry_matches(finding, entry)), None)
        if matched is not None:
            finding.suppressed = True
            reason = getattr(matched, "reason", "") or "scoped suppression"
            approved = getattr(matched, "approved_by", "")
            finding.suppress_reason = f"{reason}" + (f" (approved by {approved})" if approved else "")
            suppressed.append(finding)
            continue
        active.append(finding)
    return active, suppressed
