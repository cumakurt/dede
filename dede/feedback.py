"""Local organization feedback for finding triage.

Feedback is deliberately advisory: it annotates exact or similar findings but
does not create suppressions unless an administrator explicitly enables that
policy. This avoids feedback loops that silently hide security issues.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from dede.config import AppConfig
from dede.models import Finding
from dede.utils.hashes import sha256_text

_ALLOWED = {"false-positive", "accepted-risk", "mitigated", "confirmed", "wont-fix"}


def feedback_path(config: AppConfig, root: Path) -> Path:
    if config.feedback.path:
        value = Path(config.feedback.path).expanduser()
        return value if value.is_absolute() else root / value
    return root / ".dede" / "feedback.json"


def load_feedback(config: AppConfig, root: Path) -> list[dict[str, Any]]:
    if not config.feedback.enabled:
        return []
    path = feedback_path(config, root)
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    items = data.get("entries", []) if isinstance(data, dict) else []
    return [x for x in items if isinstance(x, dict) and x.get("verdict") in _ALLOWED]


def record_feedback(
    path: Path,
    *,
    semantic_fingerprint: str,
    verdict: str,
    reason: str,
    rule_id: str = "",
    sink_kind: str = "",
    ast_fingerprint: str = "",
    author: str = "",
) -> dict[str, Any]:
    verdict = verdict.strip().lower()
    if verdict not in _ALLOWED:
        raise ValueError(f"Feedback verdict must be one of: {', '.join(sorted(_ALLOWED))}")
    if not semantic_fingerprint:
        raise ValueError("semantic_fingerprint is required")
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        current = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
    except json.JSONDecodeError:
        current = {}
    entries = current.get("entries", []) if isinstance(current, dict) else []
    if not isinstance(entries, list):
        entries = []
    entry = {
        "id": sha256_text(f"{semantic_fingerprint}|{verdict}|{reason}")[:16],
        "semantic_fingerprint": semantic_fingerprint,
        "verdict": verdict,
        "reason": reason.strip(),
        "rule_id": rule_id,
        "sink_kind": sink_kind,
        "ast_fingerprint": ast_fingerprint,
        "author": author.strip(),
        "created_at": datetime.now(UTC).isoformat(),
    }
    # Same exact identity receives one active verdict; newer feedback replaces it.
    entries = [x for x in entries if x.get("semantic_fingerprint") != semantic_fingerprint]
    entries.append(entry)
    payload = {"schema_version": 1, "entries": entries}
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return entry


def apply_feedback(findings: list[Finding], config: AppConfig, root: Path) -> dict[str, int]:
    entries = load_feedback(config, root)
    exact = {str(x.get("semantic_fingerprint")): x for x in entries if x.get("semantic_fingerprint")}
    counts = {"exact": 0, "similar": 0, "auto_suppressed": 0}
    for finding in findings:
        identity = finding.semantic_fingerprint or finding.fingerprint
        entry = exact.get(identity)
        similarity = 1.0 if entry else 0.0
        if entry is None and config.feedback.annotate_similar:
            candidates = [
                x for x in entries
                if x.get("rule_id") and x.get("rule_id") == finding.rule_id
                and (not x.get("sink_kind") or x.get("sink_kind") == finding.sink_kind)
            ]
            if finding.ast_fingerprint:
                ast_match = next((x for x in candidates if x.get("ast_fingerprint") == finding.ast_fingerprint), None)
                if ast_match:
                    entry, similarity = ast_match, 0.95
            if entry is None and candidates:
                entry, similarity = candidates[-1], 0.70
        if entry is None:
            continue
        finding.feedback_verdict = str(entry.get("verdict", ""))
        finding.feedback_reason = str(entry.get("reason", ""))
        finding.feedback_similarity = similarity
        finding.feedback_id = str(entry.get("id", ""))
        if similarity == 1.0:
            counts["exact"] += 1
        else:
            counts["similar"] += 1
        if (
            similarity == 1.0
            and config.feedback.auto_suppress_false_positive
            and finding.feedback_verdict == "false-positive"
        ):
            finding.suppressed = True
            finding.suppress_reason = f"organization feedback: {finding.feedback_reason or 'false-positive'}"
            counts["auto_suppressed"] += 1
    return counts
