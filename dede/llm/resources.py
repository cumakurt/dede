"""Host resource probing and model compatibility checks."""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from dede.llm.catalog import ModelSpec, resolve_model_spec
from dede.utils.process import run_command


class Compatibility(str, Enum):
    COMPATIBLE = "COMPATIBLE"
    MARGINAL = "MARGINAL"
    INCOMPATIBLE = "INCOMPATIBLE"


@dataclass
class HostResources:
    ram_total_gb: float
    ram_available_gb: float
    disk_free_gb: float
    vram_total_gb: float
    has_nvidia: bool
    device_preference: str = "auto"  # auto|cpu|cuda


@dataclass
class CompatibilityReport:
    model: str
    spec: ModelSpec
    host: HostResources
    level: Compatibility
    reasons: list[str]
    recommendations: list[str]

    @property
    def ok_to_download(self) -> bool:
        return self.level != Compatibility.INCOMPATIBLE


def _read_meminfo() -> tuple[float, float]:
    total_kb = 0.0
    avail_kb = 0.0
    try:
        text = Path("/proc/meminfo").read_text(encoding="utf-8")
    except OSError:
        return 0.0, 0.0
    for line in text.splitlines():
        if line.startswith("MemTotal:"):
            total_kb = float(line.split()[1])
        elif line.startswith("MemAvailable:"):
            avail_kb = float(line.split()[1])
    return total_kb / (1024 * 1024), avail_kb / (1024 * 1024)


def _disk_free_gb(path: str = "/tmp") -> float:
    try:
        usage = shutil.disk_usage(path)
        # Prefer home / var for ollama models if present
        for candidate in ("/var/lib/docker", str(Path.home()), "/"):
            try:
                u = shutil.disk_usage(candidate)
                if u.free > usage.free:
                    usage = u
            except OSError:
                continue
        return usage.free / (1024**3)
    except OSError:
        return 0.0


def _nvidia_vram_gb() -> tuple[bool, float]:
    result = run_command(
        [
            "nvidia-smi",
            "--query-gpu=memory.total",
            "--format=csv,noheader,nounits",
        ],
        timeout=10,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return False, 0.0
    total_mib = 0.0
    for line in result.stdout.splitlines():
        try:
            total_mib += float(line.strip().split()[0])
        except ValueError:
            continue
    if total_mib <= 0:
        return False, 0.0
    return True, round(total_mib / 1024.0, 1)


def probe_host(device_preference: str = "auto") -> HostResources:
    ram_total, ram_avail = _read_meminfo()
    has_nvidia, vram = _nvidia_vram_gb()
    return HostResources(
        ram_total_gb=round(ram_total, 1),
        ram_available_gb=round(ram_avail, 1),
        disk_free_gb=round(_disk_free_gb(), 1),
        vram_total_gb=vram,
        has_nvidia=has_nvidia,
        device_preference=device_preference,
    )


def check_model_compatibility(
    model_name: str,
    *,
    device_preference: str = "auto",
    host: HostResources | None = None,
) -> CompatibilityReport:
    spec = resolve_model_spec(model_name)
    host = host or probe_host(device_preference)
    reasons: list[str] = []
    recommendations: list[str] = []
    level = Compatibility.COMPATIBLE

    disk_need = spec.size_gb + 2.0
    if host.disk_free_gb < disk_need:
        level = Compatibility.INCOMPATIBLE
        reasons.append(
            f"Insufficient disk space: need ~{disk_need:.1f}GB free, have {host.disk_free_gb:.1f}GB"
        )
        recommendations.append("Free disk space or choose a smaller model")

    use_cuda = host.device_preference == "cuda" or (
        host.device_preference == "auto" and host.has_nvidia and host.vram_total_gb > 0
    )
    if host.device_preference == "cpu":
        use_cuda = False

    if use_cuda and spec.min_vram_gb > 0:
        if host.vram_total_gb < spec.min_vram_gb:
            if host.ram_total_gb >= spec.min_ram_gb:
                if level == Compatibility.COMPATIBLE:
                    level = Compatibility.MARGINAL
                reasons.append(
                    f"GPU VRAM {host.vram_total_gb:.1f}GB < recommended {spec.min_vram_gb:.1f}GB; "
                    "Ollama may offload to system RAM (very slow)"
                )
                recommendations.append("Prefer a smaller model, or set DEDE_DEVICE=cpu explicitly")
            else:
                level = Compatibility.INCOMPATIBLE
                reasons.append(
                    f"GPU VRAM {host.vram_total_gb:.1f}GB < {spec.min_vram_gb:.1f}GB and "
                    f"RAM {host.ram_total_gb:.1f}GB < {spec.min_ram_gb:.1f}GB"
                )
    else:
        # CPU path
        if host.ram_total_gb < spec.min_ram_gb:
            level = Compatibility.INCOMPATIBLE
            reasons.append(
                f"System RAM {host.ram_total_gb:.1f}GB < required ~{spec.min_ram_gb:.1f}GB for {spec.name}"
            )
            recommendations.append("Choose a smaller model (see: dede model recommend)")
        elif host.ram_available_gb < spec.min_ram_gb * 0.7:
            if level == Compatibility.COMPATIBLE:
                level = Compatibility.MARGINAL
            reasons.append(
                f"Available RAM {host.ram_available_gb:.1f}GB is tight "
                f"(want ~{spec.min_ram_gb:.1f}GB free headroom)"
            )
            recommendations.append("Close other applications before pulling/running the model")

    if not reasons:
        reasons.append("Host resources look sufficient for this model")

    if level != Compatibility.COMPATIBLE and not any(
        "smaller model" in r.lower() for r in recommendations
    ):
        recommendations.append("Run: dede model recommend")

    return CompatibilityReport(
        model=model_name,
        spec=spec,
        host=host,
        level=level,
        reasons=reasons,
        recommendations=recommendations,
    )


def recommend_models(
    *,
    device_preference: str = "auto",
    coding_only: bool = True,
    limit: int = 5,
) -> list[tuple[ModelSpec, CompatibilityReport]]:
    from dede.llm.catalog import list_catalog

    host = probe_host(device_preference)
    scored: list[tuple[ModelSpec, CompatibilityReport]] = []
    for spec in list_catalog(coding_only=coding_only):
        report = check_model_compatibility(
            spec.name, device_preference=device_preference, host=host
        )
        if report.level == Compatibility.INCOMPATIBLE:
            continue
        scored.append((spec, report))
    # Prefer larger compatible models first among COMPATIBLE, then MARGINAL
    scored.sort(
        key=lambda item: (
            0 if item[1].level == Compatibility.COMPATIBLE else 1,
            -item[0].size_gb,
        )
    )
    return scored[:limit]
