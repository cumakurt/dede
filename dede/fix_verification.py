"""Deterministic remediation verification from before/after scan reports."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class FixVerification:
    status: str
    removed: list[str]
    persisted: list[str]
    new_high_or_critical: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {"status": self.status, "removed": self.removed, "persisted": self.persisted, "new_high_or_critical": self.new_high_or_critical}


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _identity(f: dict[str, Any]) -> str:
    return str(f.get("semantic_fingerprint") or f.get("fingerprint") or f.get("id") or "")


def verify_reports(before: Path, after: Path, *, finding_id: str | None = None) -> FixVerification:
    b = _load(before).get("findings", [])
    a = _load(after).get("findings", [])
    before_map = {_identity(f): f for f in b if _identity(f)}
    after_map = {_identity(f): f for f in a if _identity(f)}
    targets = {finding_id} if finding_id else set(before_map)
    removed = sorted(x for x in targets if x and x in before_map and x not in after_map)
    persisted = sorted(x for x in targets if x and x in before_map and x in after_map)
    new_severe = sorted(
        ident for ident, f in after_map.items()
        if ident not in before_map and str(f.get("severity", "")).upper() in {"HIGH", "CRITICAL"}
    )
    if persisted:
        status = "NOT_FIXED"
    elif new_severe:
        status = "REGRESSION_DETECTED"
    elif removed:
        status = "VERIFIED_BY_RESCAN"
    else:
        status = "NO_MATCHING_FINDING"
    return FixVerification(status, removed, persisted, new_severe)
