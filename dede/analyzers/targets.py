"""Run file-based analyzers with bounded command size and a shared time budget."""

from __future__ import annotations

import json
import os
import time
from collections.abc import Callable, Iterator

from dede.utils.process import CommandResult, run_command


def target_batches(
    args: list[str], files: list[str], max_bytes: int = 48 * 1024
) -> Iterator[list[str]]:
    base_size = sum(len(os.fsencode(arg)) + 1 for arg in args) + 3
    batch: list[str] = []
    size = base_size
    for file in files:
        length = len(os.fsencode(file)) + 1
        if base_size + length > max_bytes:
            raise ValueError("Analyzer command exceeds the argument size budget")
        if size + length > max_bytes:
            yield batch
            batch, size = [], base_size
        batch.append(file)
        size += length
    if batch:
        yield batch


def run_json_targets(
    args: list[str],
    files: list[str],
    *,
    key: str | None,
    timeout: int,
    cwd: str,
    env: dict[str, str] | None = None,
    runner: Callable = run_command,
) -> CommandResult:
    """Merge finding arrays, preserving partial findings and engine diagnostics."""
    deadline = time.monotonic() + timeout
    findings: list = []
    errors: list = []
    scanned: list = []
    stderr: list[str] = []
    returncode = 0
    timed_out = False
    batches = 0
    for batch in target_batches(args, files):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            returncode, timed_out = 124, True
            stderr.append("Analyzer time budget exhausted before all files were scanned")
            break
        result = runner([*args, "--", *batch], timeout=remaining, cwd=cwd, env=env)
        batches += 1
        if result.stderr:
            stderr.append(result.stderr)
        try:
            payload = json.loads(result.stdout)
            rows = payload.get(key) if key and isinstance(payload, dict) else payload
            if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
                raise ValueError("Expected a JSON array of findings")
            findings.extend(rows)
            if isinstance(payload, dict):
                errors.extend(payload.get("errors") or [])
                scanned.extend((payload.get("paths") or {}).get("scanned") or [])
        except (ValueError, TypeError, AttributeError):
            returncode = 2
            stderr.append("Invalid analyzer JSON output")
        if result.returncode not in (0, 1):
            returncode = result.returncode
        if result.timed_out:
            returncode, timed_out = 124, True
            break
    merged = (
        findings
        if key is None
        else {
            key: findings,
            "errors": errors,
            "paths": {"scanned": scanned},
            "batches": batches,
        }
    )
    return CommandResult(returncode, json.dumps(merged), "\n".join(stderr), timed_out)
