"""Persistent semantic finding cache used by dependency-aware incremental scans."""

from __future__ import annotations

import json
from pathlib import Path

from dede.models import Finding
from dede.utils.hashes import sha256_text


def semantic_signature(config_dump: dict, *, analyzer_version: str) -> str:
    payload = json.dumps(
        {"version": analyzer_version, "semantic": config_dump},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return sha256_text(payload)


def load_cache(path: Path, signature: str) -> list[Finding] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return None
    if payload.get("signature") != signature or payload.get("version") != 1:
        return None
    try:
        return [Finding.model_validate(item) for item in payload.get("findings", [])]
    except (ValueError, TypeError):
        return None


def save_cache(path: Path, signature: str, findings: list[Finding]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    payload = {
        "version": 1,
        "signature": signature,
        "findings": [finding.model_dump(mode="json") for finding in findings],
    }
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    tmp.replace(path)


def unaffected_cached_findings(findings: list[Finding], affected_files: set[str]) -> list[Finding]:
    kept: list[Finding] = []
    for finding in findings:
        touched = {finding.file, *(step.file for step in finding.dataflow)}
        if touched.isdisjoint(affected_files):
            kept.append(finding)
    return kept
