"""Baseline / delta scan support with v1 and semantic-v2 identity."""

from __future__ import annotations

import json
from pathlib import Path

from dede.models import BaselineStatus, Finding


def _load_baseline_items(path: Path) -> list[dict[str, object]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    findings = data.get("findings") if isinstance(data, dict) else data
    if not isinstance(findings, list) or any(not isinstance(item, dict) for item in findings):
        raise ValueError(f"Invalid baseline: expected a report or finding list in {path}")
    return findings


def load_baseline_fingerprints(path: Path) -> set[str]:
    """Return legacy fingerprints; retained as a public compatibility helper."""
    return {
        str(item["fingerprint"])
        for item in _load_baseline_items(path)
        if item.get("fingerprint")
    }


def apply_baseline(
    findings: list[Finding], baseline_path: Path | None
) -> tuple[list[Finding], list[Finding]]:
    if baseline_path is None:
        for finding in findings:
            finding.baseline_status = BaselineStatus.NONE
        return findings, []

    items = _load_baseline_items(baseline_path)
    previous_v1 = {str(item["fingerprint"]) for item in items if item.get("fingerprint")}
    previous_v2 = {
        str(item["semantic_fingerprint"])
        for item in items
        if item.get("semantic_fingerprint")
    }
    current_v1 = {f.fingerprint for f in findings if f.fingerprint}
    current_v2 = {f.semantic_fingerprint for f in findings if f.semantic_fingerprint}

    for finding in findings:
        if finding.fingerprint in previous_v1 or (
            finding.semantic_fingerprint and finding.semantic_fingerprint in previous_v2
        ):
            finding.baseline_status = BaselineStatus.EXISTING
        else:
            finding.baseline_status = BaselineStatus.NEW

    # Prefer semantic identity when present. Old baseline reports continue to
    # produce legacy resolved records exactly as before.
    resolved: list[Finding] = []
    for item in items:
        fp = str(item.get("fingerprint") or "")
        semantic = str(item.get("semantic_fingerprint") or "")
        still_present = (semantic and semantic in current_v2) or (fp and fp in current_v1)
        if still_present:
            continue
        resolved.append(
            Finding(
                tool="baseline",
                rule_id="resolved",
                file=str(item.get("file") or ""),
                fingerprint=fp,
                semantic_fingerprint=semantic,
                message="Finding resolved since baseline",
                baseline_status=BaselineStatus.RESOLVED,
            )
        )
    return findings, resolved
