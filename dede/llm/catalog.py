"""Curated Ollama model catalog with resource estimates."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class ModelSpec:
    name: str
    display_name: str
    size_gb: float
    # Recommended minimums for usable performance
    min_ram_gb: float
    min_vram_gb: float  # 0 = CPU-only OK
    notes: str = ""
    coding: bool = True


# Conservative estimates for common coding / general models available on Ollama.
# size_gb ≈ download size; min_ram_gb includes OS + KV cache headroom on CPU.
CATALOG: dict[str, ModelSpec] = {
    "qwen2.5-coder:1.5b": ModelSpec(
        "qwen2.5-coder:1.5b",
        "Qwen2.5 Coder 1.5B",
        size_gb=1.0,
        min_ram_gb=4.0,
        min_vram_gb=0.0,
        notes="Lightweight; good for low-RAM hosts",
    ),
    "qwen2.5-coder:3b": ModelSpec(
        "qwen2.5-coder:3b",
        "Qwen2.5 Coder 3B",
        size_gb=1.9,
        min_ram_gb=6.0,
        min_vram_gb=0.0,
        notes="Small coding model",
    ),
    "qwen2.5-coder:7b": ModelSpec(
        "qwen2.5-coder:7b",
        "Qwen2.5 Coder 7B",
        size_gb=4.7,
        min_ram_gb=10.0,
        min_vram_gb=6.0,
        notes="Balanced quality/speed for most laptops",
    ),
    "qwen2.5-coder:14b": ModelSpec(
        "qwen2.5-coder:14b",
        "Qwen2.5 Coder 14B",
        size_gb=9.0,
        min_ram_gb=18.0,
        min_vram_gb=12.0,
        notes="Higher quality; needs ample RAM/VRAM",
    ),
    "qwen2.5-coder:32b": ModelSpec(
        "qwen2.5-coder:32b",
        "Qwen2.5 Coder 32B",
        size_gb=20.0,
        min_ram_gb=36.0,
        min_vram_gb=20.0,
        notes="Heavy; workstation / high-RAM hosts",
    ),
    "qwen3-coder:30b": ModelSpec(
        "qwen3-coder:30b",
        "Qwen3 Coder 30B-A3B",
        size_gb=19.0,
        min_ram_gb=28.0,
        min_vram_gb=16.0,
        notes="Default Dede model (MoE, ~19GB Q4)",
    ),
    "codellama:7b": ModelSpec(
        "codellama:7b",
        "Code Llama 7B",
        size_gb=3.8,
        min_ram_gb=10.0,
        min_vram_gb=6.0,
    ),
    "codellama:13b": ModelSpec(
        "codellama:13b",
        "Code Llama 13B",
        size_gb=7.4,
        min_ram_gb=16.0,
        min_vram_gb=10.0,
    ),
    "deepseek-coder:6.7b": ModelSpec(
        "deepseek-coder:6.7b",
        "DeepSeek Coder 6.7B",
        size_gb=3.8,
        min_ram_gb=10.0,
        min_vram_gb=6.0,
    ),
    "llama3.2:3b": ModelSpec(
        "llama3.2:3b",
        "Llama 3.2 3B",
        size_gb=2.0,
        min_ram_gb=6.0,
        min_vram_gb=0.0,
        coding=False,
        notes="General model; usable for enrichment",
    ),
    "gemma2:9b": ModelSpec(
        "gemma2:9b",
        "Gemma 2 9B",
        size_gb=5.4,
        min_ram_gb=12.0,
        min_vram_gb=8.0,
        coding=False,
    ),
    "mistral:7b": ModelSpec(
        "mistral:7b",
        "Mistral 7B",
        size_gb=4.1,
        min_ram_gb=10.0,
        min_vram_gb=6.0,
        coding=False,
    ),
}


_PARAM_RE = re.compile(r"(?i)(\d+(?:\.\d+)?)[bB]\b")


def estimate_unknown_model(name: str) -> ModelSpec:
    """Heuristic estimates when the model is not in the curated catalog."""
    match = _PARAM_RE.search(name.replace("-", " "))
    params = float(match.group(1)) if match else 7.0
    # Rough Q4 size ≈ 0.55 GB per billion params (MoE models may be smaller)
    size_gb = max(0.5, round(params * 0.55, 1))
    if "a3b" in name.lower() or "moe" in name.lower():
        size_gb = max(0.5, round(params * 0.35, 1))
    min_ram = max(4.0, round(size_gb * 1.4 + 4.0, 1))
    min_vram = 0.0 if size_gb < 3 else round(size_gb * 0.9, 1)
    return ModelSpec(
        name=name,
        display_name=name,
        size_gb=size_gb,
        min_ram_gb=min_ram,
        min_vram_gb=min_vram,
        notes="Estimated (not in curated catalog) — verify before large downloads",
        coding=True,
    )


def resolve_model_spec(name: str) -> ModelSpec:
    key = name.strip()
    if key in CATALOG:
        return CATALOG[key]
    # Try without tag → prefer smallest coding variant if base known
    base = key.split(":", 1)[0]
    candidates = [spec for n, spec in CATALOG.items() if n.startswith(base + ":")]
    if candidates and ":" not in key:
        # default tag often :latest ≈ mid size; pick first coding
        return sorted(candidates, key=lambda s: s.size_gb)[len(candidates) // 2]
    if key + ":latest" in CATALOG:
        return CATALOG[key + ":latest"]
    # Partial match
    for n, spec in CATALOG.items():
        if n == key or n.startswith(key + ":") or key.startswith(n.split(":")[0]):
            if n.split(":")[0] == key.split(":")[0] and (":" not in key or n == key):
                return spec
    return estimate_unknown_model(key)


def list_catalog(*, coding_only: bool = False) -> list[ModelSpec]:
    specs = list(CATALOG.values())
    if coding_only:
        specs = [s for s in specs if s.coding]
    return sorted(specs, key=lambda s: (s.size_gb, s.name))
