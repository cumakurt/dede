"""Duplicate code detection analyzer (hash-based similarity finder).

Detects copy-paste code and near-duplicate blocks using token-based hashing
and a sliding Rice-Rolling hash window. Produces findings in the duplicate
category that appear in all report formats alongside other analyzers.
"""

from __future__ import annotations

import hashlib
import re
import time
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from dede.analyzers.base import Analyzer
from dede.config import AppConfig
from dede.models import (
    AnalyzerResult,
    Category,
    Confidence,
    Finding,
    ProjectContext,
    Severity,
    ToolStatus,
)

# Minimum shared lines to consider a block a "duplicate" candidate.
MIN_DUPLICATE_LINES = 6
# Maximum block size in lines for the rolling hash window.
MAX_BLOCK_LINES = 60
# Similarity threshold: fraction of overlapping token hashes to count as
# a duplicate pair. 0.7 = 70% token overlap.
DUPLICATE_SIMILARITY = 0.70
# Cap reported duplicate groups to keep reports tractable.
MAX_DUPLICATE_GROUPS = 200
# Cap source lines examined per file for the O(n^2) pairwise step.
MAX_FILE_LINES = 4000
# Ignore ubiquitous single-line tokens when building near-duplicate candidate
# pairs. Exact block hashes are still handled independently.
MAX_TOKEN_POSTINGS = 200
# Hard bounds protect scans of generated/monorepo sources from exhausting RAM.
MAX_TOTAL_BLOCKS = 100_000
MAX_CANDIDATE_PAIRS = 500_000


@dataclass(frozen=True)
class TokenizedLine:
    """A single source line represented as a normalized token tuple."""

    line_no: int
    token_hash: str
    raw: str


@dataclass(frozen=True)
class DuplicateBlock:
    """A contiguous region of source lines with stable hash identity."""

    file: str
    start_line: int
    end_line: int
    block_hash: str
    snippet: str
    token_hashes: tuple[str, ...]


def _tokenize_line(line: str) -> tuple[str, ...]:
    """Normalize a line into a stable token sequence for hashing.

    Strips string/char literals and comments so that cosmetic differences
    (different messages, different variable names inside strings) do not
    hide structural duplication.
    """
    text = line
    # Remove single-line comments (naive but stable across languages).
    text = re.sub(r"//.*$|#.*$|--.*$|;.*$", "", text, flags=re.MULTILINE)
    # Collapse string/char literals to a placeholder.
    text = re.sub(r'"(?:\\.|[^"\\])*"', '""', text)
    text = re.sub(r"'(?:\\\.|[^'\\])*'", "''", text)
    text = re.sub(r"`.*`", "``", text)
    # Normalize whitespace.
    text = re.sub(r"\s+", " ", text).strip()
    if not text:
        return ()
    return tuple(text.split())


def _token_hash(tokens: tuple[str, ...]) -> str:
    """Stable SHA-256 over a normalized token tuple."""
    if not tokens:
        return ""
    canonical = " ".join(tokens)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def _rolling_hash(token_hashes: Sequence[str]) -> list[str]:
    """Rice-Rolling hash over a sequence of per-line token hashes.

    Returns one fingerprint per line that incorporates the preceding window
    so that identical adjacent blocks produce identical rolling fingerprints.
    """
    if not token_hashes:
        return []
    window: list[str] = []
    out: list[str] = []
    for h in token_hashes:
        window.append(h)
        if len(window) > MAX_BLOCK_LINES:
            window.pop(0)
        combined = "|".join(window)
        out.append(hashlib.sha256(combined.encode("utf-8")).hexdigest()[:16])
    return out


def _overlap(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / max(len(a), len(b))


def _read_lines(path: Path) -> list[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


class DuplicateAnalyzer(Analyzer):
    name = "duplicate"

    def supports(self, project: ProjectContext) -> bool:
        return bool(project.files)

    def version(self) -> str:
        return "1.0.0"

    def analyze(
        self,
        project: ProjectContext,
        config: AppConfig,
        raw_dir: Path,
    ) -> AnalyzerResult:
        started = time.monotonic()
        files = [Path(f) for f in project.files if Path(f).suffix in _SOURCE_SUFFIXES]
        if not files:
            return AnalyzerResult(
                tool=self.name,
                status=ToolStatus.NOT_APPLICABLE,
                version=self.version(),
                message="No source files to analyze for duplication",
                duration_seconds=time.monotonic() - started,
            )

        raw_path = raw_dir / "duplicate.json"
        blocks: list[DuplicateBlock] = []
        files_scanned = 0
        total_lines = 0
        block_limit_reached = False

        for path in files:
            try:
                too_large = path.stat().st_size > int(config.scan.max_file_size_mb * 1024 * 1024)
            except OSError:
                continue
            if too_large:
                continue
            lines = _read_lines(path)
            if len(lines) > MAX_FILE_LINES:
                lines = lines[:MAX_FILE_LINES]
            if not lines:
                continue
            total_lines += len(lines)
            files_scanned += 1
            try:
                rel = path.resolve().relative_to(Path(project.root).resolve()).as_posix()
            except (OSError, ValueError):
                rel = path.as_posix()
            remaining = MAX_TOTAL_BLOCKS - len(blocks)
            if remaining <= 0:
                block_limit_reached = True
                break
            extracted = _extract_blocks(path, lines, rel)
            blocks.extend(extracted[:remaining])
            if len(extracted) > remaining:
                block_limit_reached = True
                break

        raw_path.write_text(
            _raw_summary(blocks, files_scanned, total_lines, self.version()),
            encoding="utf-8",
        )

        groups = _find_duplicate_groups(blocks)
        findings: list[Finding] = []
        for group in groups[:MAX_DUPLICATE_GROUPS]:
            findings.extend(_group_to_findings(group))
        findings = _merge_overlapping_findings(findings)

        message = (
            f"{files_scanned} files / {total_lines} lines; "
            f"{len(groups)} duplicate groups, {len(findings)} findings"
        )
        if block_limit_reached:
            message += f" (analysis capped at {MAX_TOTAL_BLOCKS} windows)"
        return AnalyzerResult(
            tool=self.name,
            status=ToolStatus.SUCCESS,
            version=self.version(),
            message=message,
            findings=findings,
            raw_path=str(raw_path),
            duration_seconds=time.monotonic() - started,
        )


def _extract_blocks(path: Path, lines: list[str], rel: str) -> list[DuplicateBlock]:
    """Extract every fixed-size normalized code window.

    The previous implementation compared adjacent cumulative rolling hashes for
    equality. Those hashes necessarily change as each new line enters the
    window, so real copy/paste blocks were almost never emitted.
    """
    tokenized: list[TokenizedLine] = []
    for i, line in enumerate(lines, start=1):
        tokens = _tokenize_line(line)
        if not tokens:
            continue
        tokenized.append(TokenizedLine(line_no=i, token_hash=_token_hash(tokens), raw=line))

    if len(tokenized) < MIN_DUPLICATE_LINES:
        return []

    blocks: list[DuplicateBlock] = []
    for start in range(len(tokenized) - MIN_DUPLICATE_LINES + 1):
        block_lines = tokenized[start : start + MIN_DUPLICATE_LINES]
        # Do not call six sparse statements separated by a large comment/data
        # region a contiguous duplicate block.
        if block_lines[-1].line_no - block_lines[0].line_no > MIN_DUPLICATE_LINES * 3:
            continue
        token_hashes = tuple(item.token_hash for item in block_lines)
        block_hash = hashlib.sha256("|".join(token_hashes).encode("utf-8")).hexdigest()[:16]
        snippet = "\n".join(f"{item.line_no}: {item.raw}" for item in block_lines)
        blocks.append(
            DuplicateBlock(
                file=rel,
                start_line=block_lines[0].line_no,
                end_line=block_lines[-1].line_no,
                block_hash=block_hash,
                snippet=snippet[:600],
                token_hashes=token_hashes,
            )
        )

    return blocks


def _find_duplicate_groups(blocks: list[DuplicateBlock]) -> list[list[DuplicateBlock]]:
    """Group blocks with overlapping token hashes across files/regions.

    Uses a lightest-first union-find over overlapping pairs to keep the
    reported groups coherent and reduce O(n^2) blowup.
    """
    if len(blocks) < 2:
        return []

    pairs: list[tuple[int, int, float]] = []
    seen: set[tuple[int, int]] = set()

    def consider(i: int, j: int) -> None:
        if i == j:
            return
        key = (min(i, j), max(i, j))
        if key in seen:
            return
        seen.add(key)
        left, right = blocks[key[0]], blocks[key[1]]
        if (
            left.file == right.file
            and left.start_line <= right.end_line
            and right.start_line <= left.end_line
        ):
            return
        a = set(blocks[i].token_hashes)
        b = set(blocks[j].token_hashes)
        sim = _overlap(a, b)
        if sim >= DUPLICATE_SIMILARITY:
            pairs.append((i, j, sim))

    # Exact windows are cheap and must never be lost because a line is common.
    exact: dict[str, list[int]] = defaultdict(list)
    postings: dict[str, list[int]] = defaultdict(list)
    for index, block in enumerate(blocks):
        exact[block.block_hash].append(index)
        for token_hash in sorted(set(block.token_hashes)):
            postings[token_hash].append(index)
    for indices in exact.values():
        # Exact equality is transitive, so connecting every item to one
        # representative gives the same component without quadratic pairs.
        if len(indices) > 1:
            representative = indices[0]
            for right in indices[1:]:
                consider(representative, right)

    # Near-duplicate comparisons are generated only for blocks sharing tokens,
    # avoiding the previous O(number_of_blocks²) all-pairs scan.
    candidates: set[tuple[int, int]] = set()
    candidate_limit_reached = False
    for indices in postings.values():
        if len(indices) > MAX_TOKEN_POSTINGS:
            continue
        for offset, left in enumerate(indices):
            for right in indices[offset + 1 :]:
                candidates.add((left, right))
                if len(candidates) >= MAX_CANDIDATE_PAIRS:
                    candidate_limit_reached = True
                    break
            if candidate_limit_reached:
                break
        if candidate_limit_reached:
            break
    for left, right in sorted(candidates):
        consider(left, right)

    if not pairs:
        return []

    # Sort pairs by similarity descending, then greedily build groups.
    pairs.sort(key=lambda p: -p[2])
    parent: dict[int, int] = {}

    def find(x: int) -> int:
        root = x
        while parent.get(root, root) != root:
            root = parent.get(root, root)
        while parent.get(x, x) != root:
            nxt = parent.get(x, x)
            parent[x] = root
            x = nxt
        return root

    def union(x: int, y: int) -> None:
        rx, ry = find(x), find(y)
        if rx != ry:
            parent[rx] = ry

    for i, j, _ in pairs:
        union(i, j)

    groups: dict[int, list[DuplicateBlock]] = {}
    for idx, b in enumerate(blocks):
        root = find(idx)
        groups.setdefault(root, []).append(b)

    # Unique windows must not consume the report's duplicate-group limit.
    return [sorted(g, key=lambda b: (b.file, b.start_line)) for g in groups.values() if len(g) > 1]


def _group_to_findings(group: list[DuplicateBlock]) -> list[Finding]:
    """Turn a duplicate group into findings (one per non-primary occurrence)."""
    if len(group) < 2:
        return []

    # First occurrence is the "original"; rest are duplicates.
    primary = group[0]
    findings: list[Finding] = []
    for dup in group[1:]:
        findings.append(
            Finding(
                tool="duplicate",
                rule_id="duplicate.code",
                category=Category.DUPLICATE,
                severity=_severity_for_group(group),
                confidence=Confidence.HIGH,
                file=dup.file,
                start_line=dup.start_line,
                end_line=dup.end_line,
                message=(
                    f"Duplicate code block ({len(group)} occurrences total): "
                    f"this copy appears in {dup.file}:{dup.start_line}. "
                    f"Primary location: {primary.file}:{primary.start_line}"
                ),
                code_snippet=dup.snippet,
                recommendation=(
                    "Extract the shared logic into a reusable function/component "
                    "and reference it from both locations to reduce maintenance burden."
                ),
                normalized_type="duplicate:code",
                source_tool_severity=str(len(group)),
            )
        )
    return findings


def _merge_overlapping_findings(findings: list[Finding]) -> list[Finding]:
    """Collapse overlapping sliding-window reports into useful duplicate regions."""
    merged: list[Finding] = []
    for finding in sorted(findings, key=lambda item: (item.file, item.start_line, item.end_line)):
        previous = merged[-1] if merged else None
        if (
            previous is not None
            and previous.file == finding.file
            and finding.start_line <= previous.end_line + 1
        ):
            previous.end_line = max(previous.end_line, finding.end_line)
            if len(finding.code_snippet) > len(previous.code_snippet):
                previous.code_snippet = finding.code_snippet
            continue
        merged.append(finding)
    return merged


def _severity_for_group(group: list[DuplicateBlock]) -> Severity:
    n = len(group)
    total_lines = sum(b.end_line - b.start_line + 1 for b in group)
    if n >= 5 or total_lines >= 80:
        return Severity.HIGH
    if n >= 3 or total_lines >= 40:
        return Severity.MEDIUM
    return Severity.LOW


def _source_suffixes() -> set[str]:
    return {
        ".py",
        ".pyw",
        ".pyi",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".mjs",
        ".cjs",
        ".go",
        ".java",
        ".kt",
        ".kts",
        ".rb",
        ".php",
        ".cs",
        ".vb",
        ".fs",
        ".fsx",
        ".cpp",
        ".cc",
        ".cxx",
        ".c",
        ".h",
        ".hpp",
        ".swift",
        ".scala",
        ".rs",
        ".sol",
        ".cls",
        ".sh",
        ".bash",
        ".zsh",
        ".ps1",
        ".psm1",
        ".pl",
        ".pm",
        ".sql",
        ".ex",
        ".exs",
        ".clj",
        ".dart",
        ".lua",
        ".ml",
        ".mli",
    }


def _source_suffixes_cached() -> set[str]:
    return _SOURCE_SUFFIXES


_SOURCE_SUFFIXES = _source_suffixes()


def _raw_summary(
    blocks: list[DuplicateBlock],
    files_scanned: int,
    total_lines: int,
    version: str,
) -> str:
    import json

    groups = _find_duplicate_groups(blocks)
    return json.dumps(
        {
            "analyzer": "duplicate",
            "version": version,
            "files_scanned": files_scanned,
            "lines_considered": total_lines,
            "blocks_extracted": len(blocks),
            "duplicate_groups": len(groups),
            "duplicate_findings": sum(len(_group_to_findings(g)) for g in groups),
        },
        indent=2,
    )
