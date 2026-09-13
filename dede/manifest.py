"""Reproducible scan manifest helpers."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from dede.config import AppConfig


def _digest_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def digest_tree(path: Path) -> str:
    digest = hashlib.sha256()
    if not path.exists():
        return ""
    for file in sorted(p for p in path.rglob("*") if p.is_file()):
        digest.update(file.relative_to(path).as_posix().encode())
        digest.update(b"\0")
        digest.update(file.read_bytes())
        digest.update(b"\0")
    return "sha256:" + digest.hexdigest()


def build_scan_manifest(
    config: AppConfig,
    *,
    scanner_version: str,
    rulesets: dict[str, str],
    rules_dirs: list[Path],
    commit: str,
) -> dict[str, Any]:
    config_json = json.dumps(config.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return {
        "schema": "dede.scan-manifest/v1",
        "scanner_version": scanner_version,
        "source_commit": commit,
        "config_digest": _digest_bytes(config_json.encode()),
        "ruleset_versions": rulesets,
        "rules_digest": _digest_bytes("|".join(digest_tree(p) for p in rules_dirs).encode()),
    }
