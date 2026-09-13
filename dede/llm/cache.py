"""Fingerprint-based AI enrichment cache with thread-safe L1 in-memory layer."""

from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
from pathlib import Path
from typing import Any

from dede.utils.hashes import sha256_text

logger = logging.getLogger(__name__)


class AICache:
    """Two-level cache: L1 in-memory dict (thread-safe) + L2 disk JSON files.

    L1 is populated on every cache hit or successful write so repeated
    accesses within a single enrichment run never touch the filesystem.
    The lock protects L1 only; disk writes use atomic os.replace() so
    concurrent processes remain safe without holding the lock during I/O.

    If a disk write fails the L1 entry is NOT updated — the previously
    persisted value remains the authoritative source and subsequent get()
    calls will read it from disk (and repopulate L1).
    """

    def __init__(self, root: Path) -> None:
        self.root = root
        self.enabled = True
        self._lock = threading.Lock()
        self._l1: dict[str, dict[str, Any]] = {}
        try:
            self.root.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            self.enabled = False
            logger.warning("AI cache unavailable at %s: %s", self.root, exc)

    def _path(self, fingerprint: str, context_hash: str) -> Path:
        key = sha256_text(f"{fingerprint}:{context_hash}")
        return self.root / f"{key}.json"

    def _l1_key(self, fingerprint: str, context_hash: str) -> str:
        return sha256_text(f"{fingerprint}:{context_hash}")

    def get(self, fingerprint: str, context_hash: str) -> dict[str, Any] | None:
        if not self.enabled:
            return None
        key = self._l1_key(fingerprint, context_hash)

        # L1 fast path — no I/O under lock
        with self._lock:
            if key in self._l1:
                return self._l1[key]

        # L2 disk read — outside lock so other threads aren't blocked
        path = self._path(fingerprint, context_hash)
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(value, dict):
                return None
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as exc:
            logger.warning("Cannot read AI cache entry %s: %s", path, exc)
            return None

        # Populate L1 so the next access is instant
        with self._lock:
            self._l1[key] = value
        return value

    def set(self, fingerprint: str, context_hash: str, value: dict[str, Any]) -> None:
        if not self.enabled:
            return
        path = self._path(fingerprint, context_hash)
        key = self._l1_key(fingerprint, context_hash)
        temporary: Path | None = None
        disk_ok = False
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=self.root, delete=False
            ) as handle:
                temporary = Path(handle.name)
                json.dump(value, handle)
            os.replace(temporary, path)
            disk_ok = True
        except OSError as exc:
            logger.warning("Cannot write AI cache entry %s: %s", path, exc)
        finally:
            if temporary is not None:
                try:
                    temporary.unlink(missing_ok=True)
                except OSError as exc:
                    logger.warning("Cannot remove temporary AI cache entry %s: %s", temporary, exc)

        # Update L1 only when the disk write succeeded — keeps L1 consistent
        # with what is persisted so a restart sees the same value.
        if disk_ok:
            with self._lock:
                self._l1[key] = value
