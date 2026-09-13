"""User settings persistence (~/.config/dede/settings.yml)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


def settings_path() -> Path:
    return Path.home() / ".config" / "dede" / "settings.yml"


def load_user_settings() -> dict[str, Any]:
    path = settings_path()
    if not path.is_file():
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return {}
    return data if isinstance(data, dict) else {}


def save_user_settings(data: dict[str, Any]) -> Path:
    path = settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return path


def get_preferred_model() -> str | None:
    data = load_user_settings()
    ai = data.get("ai") if isinstance(data.get("ai"), dict) else {}
    model = ai.get("model") if isinstance(ai, dict) else None
    return str(model) if model else None


def set_preferred_model(model: str) -> Path:
    data = load_user_settings()
    ai = data.get("ai") if isinstance(data.get("ai"), dict) else {}
    if not isinstance(ai, dict):
        ai = {}
    ai["model"] = model
    data["ai"] = ai
    return save_user_settings(data)
