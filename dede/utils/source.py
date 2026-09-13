"""Bounded source reads confined to the scan target."""

from __future__ import annotations

import stat
from pathlib import Path


def decode_source(content: bytes) -> str:
    """Decode supported source encodings without silently losing evidence."""
    if content.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
        return content.decode("utf-32")
    if content.startswith((b"\xff\xfe", b"\xfe\xff")):
        return content.decode("utf-16")
    return content.decode("utf-8-sig")


def read_source_lines(root: Path, file: str, max_bytes: int) -> list[str]:
    """Return no context for external paths, special files or oversized sources."""
    try:
        root = root.resolve()
        path = (root / file).resolve()
        if not path.is_relative_to(root):
            return []
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > max_bytes:
            return []
        with path.open("rb") as handle:
            content = handle.read(max_bytes + 1)
        if len(content) > max_bytes:
            return []
        text = decode_source(content)
        return [] if "\x00" in text else text.splitlines()
    except (OSError, RuntimeError, ValueError):
        return []
