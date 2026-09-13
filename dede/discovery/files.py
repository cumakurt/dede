"""File discovery with ignore rules, binary/minified detection, symlink protection."""

from __future__ import annotations

import codecs
import os
import stat
from pathlib import Path

import pathspec

from dede.config import AppConfig

BINARY_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".ico",
    ".pdf",
    ".zip",
    ".gz",
    ".tar",
    ".bz2",
    ".xz",
    ".7z",
    ".rar",
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".class",
    ".jar",
    ".war",
    ".o",
    ".a",
    ".pyc",
    ".pyo",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".mp3",
    ".mp4",
    ".avi",
    ".mov",
    ".wasm",
    ".bin",
    ".dat",
    ".sqlite",
    ".db",
}


def _compile_gitignore(lines: list[str]) -> pathspec.PathSpec:
    """Compile gitignore-style patterns without relying on deprecated factories."""
    gitignore_spec = getattr(pathspec, "GitIgnoreSpec", None)
    if gitignore_spec is not None:
        return gitignore_spec.from_lines(lines)
    # Compatibility with older pathspec releases supported by Dede.
    return pathspec.PathSpec.from_lines("gitwildmatch", lines)


def _load_ignore_spec(root: Path, filenames: list[str]) -> pathspec.PathSpec | None:
    lines: list[str] = []
    for name in filenames:
        path = root / name
        if path.is_file():
            lines.extend(path.read_text(encoding="utf-8", errors="ignore").splitlines())
    if not lines:
        return None
    return _compile_gitignore(lines)


def _is_binary(path: Path) -> bool:
    if path.suffix.lower() in BINARY_EXTENSIONS:
        return True
    try:
        with path.open("rb") as handle:
            chunk = handle.read(8192)
        if chunk.startswith((b"\xff\xfe", b"\xfe\xff", b"\x00\x00\xfe\xff")):
            # An incremental decoder tolerates a cut code point at the sample
            # boundary. Native matching validates the full bounded source.
            encoding = (
                "utf-32"
                if chunk.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff"))
                else "utf-16"
            )
            return "\x00" in codecs.getincrementaldecoder(encoding)().decode(chunk, final=False)
        if b"\x00" in chunk:
            return True
    except (OSError, UnicodeError):
        return True
    return False


def _is_minified_js(path: Path) -> bool:
    name = path.name.lower()
    if name.endswith(".min.js") or name.endswith(".min.css"):
        return True
    if path.suffix.lower() not in {".js", ".mjs", ".cjs"}:
        return False
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return True
    if not text:
        return False
    lines = text.splitlines()
    if len(lines) <= 3 and len(text) > 5000:
        return True
    avg = len(text) / max(1, len(lines))
    return avg > 300 and len(text) > 10_000


def discover_files(root: Path, config: AppConfig) -> list[Path]:
    root = root.resolve()
    max_bytes = int(config.scan.max_file_size_mb * 1024 * 1024)
    exclude_spec = _compile_gitignore(config.scan.exclude)
    output_dir = Path(config.reports.output).resolve() if config.reports.output else None

    ignore_files = [".dedeignore"]
    if config.scan.respect_gitignore:
        ignore_files.insert(0, ".gitignore")
    ignore_spec = _load_ignore_spec(root, ignore_files)

    results: list[Path] = []
    seen_inodes: set[tuple[int, int]] = set()

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)

        # Prune excluded directories
        pruned: list[str] = []
        for name in sorted(dirnames):
            child = current / name
            rel = str(child.relative_to(root)).replace("\\", "/")
            if exclude_spec.match_file(rel + "/") or child == output_dir:
                continue
            if ignore_spec and ignore_spec.match_file(rel + "/"):
                continue
            # Symlink directories: do not follow
            if child.is_symlink():
                continue
            pruned.append(name)
        dirnames[:] = pruned

        for filename in sorted(filenames):
            path = current / filename
            rel = path.relative_to(root).as_posix()
            if exclude_spec.match_file(rel) or (ignore_spec and ignore_spec.match_file(rel)):
                continue
            if path.is_symlink():
                # Analyze symlink target only if inside root and not looping
                try:
                    target = path.resolve()
                except (OSError, RuntimeError):
                    continue
                if root not in target.parents and target != root:
                    continue
                path = target

            rel = str(path.relative_to(root)).replace("\\", "/")
            if ignore_spec and ignore_spec.match_file(rel):
                continue
            if exclude_spec.match_file(rel):
                continue
            if output_dir and output_dir != root and path.is_relative_to(output_dir):
                continue
            try:
                st = path.stat()
            except OSError:
                continue
            key = (st.st_dev, st.st_ino)
            if not stat.S_ISREG(st.st_mode) or st.st_size > max_bytes or key in seen_inodes:
                continue
            if _is_binary(path):
                continue
            if _is_minified_js(path):
                continue
            seen_inodes.add(key)
            results.append(path)
            if len(results) >= config.scan.max_files:
                return results

    return results
