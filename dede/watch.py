"""Incremental developer watch loop built on Dede's persistent index/cache."""
from __future__ import annotations

import time
from pathlib import Path

from dede.config import AppConfig
from dede.discovery.files import discover_files
from dede.pipeline import run_scan


def _snapshot(root: Path, config: AppConfig) -> dict[str, tuple[int, int]]:
    snap: dict[str, tuple[int, int]] = {}
    for path in discover_files(root, config):
        try:
            stat = path.stat(); rel = path.resolve().relative_to(root.resolve()).as_posix()
        except (OSError, ValueError):
            continue
        snap[rel] = (stat.st_mtime_ns, stat.st_size)
    return snap


def watch(root: Path, config: AppConfig, *, interval: float = 1.0, once: bool = False) -> int:
    root = root.resolve()
    previous: dict[str, tuple[int, int]] | None = None
    exit_code = 0
    while True:
        current = _snapshot(root, config)
        if previous is None or current != previous:
            if previous is not None:
                changed = sorted({*current, *previous} - {k for k in current.keys() & previous.keys() if current[k] == previous[k]})
                print(f"Change detected: {len(changed)} file(s) -> {', '.join(changed[:8])}{' ...' if len(changed) > 8 else ''}")
            _, exit_code = run_scan(root, config, progress=True)
            previous = current
            if once:
                return exit_code
        time.sleep(max(0.25, interval))
