"""Tests for model catalog and resource compatibility checks."""

from dede.llm.catalog import estimate_unknown_model, resolve_model_spec
from dede.llm.resources import Compatibility, HostResources, check_model_compatibility


def test_resolve_known_model():
    spec = resolve_model_spec("qwen3-coder:30b")
    assert spec.size_gb >= 18
    assert spec.min_ram_gb >= 20


def test_estimate_unknown_7b():
    spec = estimate_unknown_model("acme-coder:7b")
    assert 3.0 <= spec.size_gb <= 6.0


def test_incompatible_low_ram():
    host = HostResources(
        ram_total_gb=8.0,
        ram_available_gb=4.0,
        disk_free_gb=100.0,
        vram_total_gb=0.0,
        has_nvidia=False,
        device_preference="cpu",
    )
    report = check_model_compatibility(
        "qwen3-coder:30b", device_preference="cpu", host=host
    )
    assert report.level == Compatibility.INCOMPATIBLE
    assert not report.ok_to_download


def test_compatible_small_model():
    host = HostResources(
        ram_total_gb=16.0,
        ram_available_gb=12.0,
        disk_free_gb=100.0,
        vram_total_gb=0.0,
        has_nvidia=False,
        device_preference="cpu",
    )
    report = check_model_compatibility(
        "qwen2.5-coder:7b", device_preference="cpu", host=host
    )
    assert report.level in {Compatibility.COMPATIBLE, Compatibility.MARGINAL}
    assert report.ok_to_download


def test_disk_blocks_download():
    host = HostResources(
        ram_total_gb=64.0,
        ram_available_gb=40.0,
        disk_free_gb=5.0,
        vram_total_gb=24.0,
        has_nvidia=True,
        device_preference="cuda",
    )
    report = check_model_compatibility(
        "qwen3-coder:30b", device_preference="cuda", host=host
    )
    assert report.level == Compatibility.INCOMPATIBLE
