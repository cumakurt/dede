"""Low-noise live progress reporting for long-running scan operations."""

from __future__ import annotations

import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator

from rich.console import Console


@dataclass(slots=True)
class OperationResult:
    label: str
    elapsed_seconds: float


class LiveProgress:
    """Emit deterministic stage updates plus periodic heartbeats.

    Rich spinners look good in a TTY but disappear from CI/container logs.  Dede
    instead emits a compact heartbeat after ``interval_seconds`` so the user can
    always tell that a blocking external analyzer is still alive.
    """

    def __init__(
        self,
        console: Console,
        *,
        enabled: bool = True,
        interval_seconds: float = 5.0,
    ) -> None:
        self.console = console
        self.enabled = enabled
        self.interval_seconds = max(1.0, float(interval_seconds))

    def info(self, message: str) -> None:
        if self.enabled:
            self.console.print(message)

    @contextmanager
    def operation(self, label: str, *, detail: str = "") -> Iterator[OperationResult]:
        started = time.monotonic()
        result = OperationResult(label=label, elapsed_seconds=0.0)
        if not self.enabled:
            try:
                yield result
            finally:
                result.elapsed_seconds = time.monotonic() - started
            return

        suffix = f" — {detail}" if detail else ""
        self.console.print(f"  → {label}{suffix}")
        stop = threading.Event()

        def heartbeat() -> None:
            # Do not print immediately: fast analyzers should remain one-line.
            while not stop.wait(self.interval_seconds):
                elapsed = time.monotonic() - started
                self.console.print(f"    … {label} still running ({elapsed:.0f}s)")

        thread = threading.Thread(target=heartbeat, name=f"dede-progress-{label}", daemon=True)
        thread.start()
        try:
            yield result
        finally:
            stop.set()
            thread.join(timeout=0.2)
            result.elapsed_seconds = time.monotonic() - started

    def done(
        self,
        result: OperationResult,
        *,
        status: str = "OK",
        findings: int | None = None,
        extra: str = "",
    ) -> None:
        if not self.enabled:
            return
        bits = [status, f"{result.elapsed_seconds:.1f}s"]
        if findings is not None:
            bits.append(f"{findings} findings")
        if extra:
            bits.append(extra)
        marker = "✓" if status in {"OK", "SUCCESS"} else "•"
        self.console.print(f"    {marker} {result.label}: " + " | ".join(bits))
