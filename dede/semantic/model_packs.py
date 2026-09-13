"""Offline semantic model packs with deterministic integrity verification.

Packs extend framework/library source, sink and sanitizer knowledge without
changing Dede itself.  They are plain JSON, can be carried into air-gapped
environments, and optionally use HMAC-SHA256 signatures with an organization
secret stored outside the repository.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from dede.config import AppConfig


@dataclass(frozen=True)
class PackModel:
    language: str
    sources: tuple[dict[str, Any], ...] = ()
    sinks: tuple[dict[str, Any], ...] = ()
    sanitizers: tuple[str, ...] = ()


@dataclass(frozen=True)
class LoadedModelPack:
    name: str
    version: str
    path: str
    verified: bool
    digest: str
    models: tuple[PackModel, ...] = ()
    warnings: tuple[str, ...] = ()


def _canonical_payload(data: dict[str, Any]) -> bytes:
    clean = {k: v for k, v in data.items() if k != "integrity"}
    return json.dumps(clean, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def verify_pack(path: Path, *, secret: str | None = None, require_signature: bool = False) -> LoadedModelPack:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or int(data.get("schema_version", 0)) != 1:
        raise ValueError(f"Unsupported model-pack schema: {path}")
    name = str(data.get("name", "")).strip()
    version = str(data.get("version", "")).strip()
    if not name or not version:
        raise ValueError(f"Model pack requires name and version: {path}")
    payload = _canonical_payload(data)
    digest = hashlib.sha256(payload).hexdigest()
    integrity = data.get("integrity") or {}
    expected_digest = str(integrity.get("sha256", "")).lower()
    signature = str(integrity.get("hmac_sha256", "")).lower()
    warnings: list[str] = []
    verified = False
    if expected_digest and not hmac.compare_digest(expected_digest, digest):
        raise ValueError(f"Model pack SHA-256 mismatch: {path}")
    if signature:
        if not secret:
            if require_signature:
                raise ValueError(f"Model pack is signed but {path} cannot be verified without the configured key")
            warnings.append("signature-present-but-key-unavailable")
        else:
            expected = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(signature, expected):
                raise ValueError(f"Model pack signature verification failed: {path}")
            verified = True
    elif require_signature:
        raise ValueError(f"Unsigned model pack rejected by policy: {path}")
    elif expected_digest:
        verified = True

    raw_models = data.get("models") or {}
    models: list[PackModel] = []
    if not isinstance(raw_models, dict):
        raise ValueError(f"Model pack models must be an object: {path}")
    for language, model in sorted(raw_models.items()):
        if not isinstance(model, dict):
            continue
        sources = tuple(x for x in model.get("sources", []) if isinstance(x, dict) and x.get("call"))
        sinks = tuple(x for x in model.get("sinks", []) if isinstance(x, dict) and x.get("call"))
        sanitizers = tuple(str(x) for x in model.get("sanitizers", []) if str(x).strip())
        models.append(PackModel(str(language).lower(), sources, sinks, sanitizers))
    return LoadedModelPack(name, version, str(path), verified, digest, tuple(models), tuple(warnings))


def load_model_packs(config: AppConfig, root: Path) -> list[LoadedModelPack]:
    if not config.model_packs.enabled:
        return []
    key = os.getenv(config.model_packs.hmac_key_env, "") or None
    paths: list[Path] = []
    if config.semantic.framework_models:
        bundled = Path(__file__).resolve().parent / "packs"
        if bundled.is_dir():
            paths.extend(sorted(bundled.glob("*.json")))
    for raw in config.model_packs.paths:
        path = Path(raw).expanduser()
        if not path.is_absolute():
            path = root / path
        if path.is_dir():
            paths.extend(sorted(path.glob("*.json")))
        elif path.is_file():
            paths.append(path)
    # Conventional repository-local directory, intentionally opt-in by presence.
    local = root / ".dede" / "model-packs"
    if local.is_dir():
        paths.extend(sorted(local.glob("*.json")))
    unique = {p.resolve(): p for p in paths}
    bundled_root = (Path(__file__).resolve().parent / "packs").resolve()
    loaded: list[LoadedModelPack] = []
    for p in unique.values():
        resolved = p.resolve()
        is_bundled = resolved.is_relative_to(bundled_root)
        loaded.append(
            verify_pack(
                p,
                secret=key,
                require_signature=(config.model_packs.require_signature and not is_bundled),
            )
        )
    return loaded


def language_models(packs: list[LoadedModelPack], language: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    sources: list[dict[str, Any]] = []
    sinks: list[dict[str, Any]] = []
    sanitizers: list[str] = []
    aliases = {language.lower()}
    if language.lower() in {"javascript", "typescript"}:
        aliases |= {"javascript", "typescript", "js", "ts"}
    if language.lower() in {"csharp", "c#"}:
        aliases |= {"csharp", "c#", "dotnet"}
    for pack in packs:
        for model in pack.models:
            if model.language in aliases or model.language == "*":
                sources.extend(model.sources)
                sinks.extend(model.sinks)
                sanitizers.extend(model.sanitizers)
    return sources, sinks, list(dict.fromkeys(sanitizers))


def sign_pack(path: Path, secret: str) -> str:
    """Write canonical SHA-256 + HMAC signature back to a pack file."""
    data = json.loads(path.read_text(encoding="utf-8"))
    payload = _canonical_payload(data)
    digest = hashlib.sha256(payload).hexdigest()
    signature = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    data["integrity"] = {"sha256": digest, "hmac_sha256": signature}
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return digest
