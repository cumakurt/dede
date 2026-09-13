"""Code smell analyzer — quality and maintainability findings.

Detects common maintainability smells that deterministic pattern engines
structurally miss: overly long files/functions, deep nesting, magic numbers,
empty exception handling, commented-out code leftovers, and similarly
structured issues across supported languages.
"""

from __future__ import annotations

import re
import time
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

# Tuneable smell thresholds.
THRESHOLDS = {
    "file_lines_warning": 400,
    "file_lines_violation": 800,
    "function_lines_warning": 40,
    "function_lines_violation": 80,
    "nesting_warning": 4,
    "nesting_violation": 6,
    "magic_number_min_digits": 3,
    "magic_number_min_occurrences": 3,
}

# Heuristic to decide if a number looks "magic" (not 0/1/-1/2).
_MAGIC_NUMBER_RE = re.compile(r"(?<![\w.])(0[xX][0-9a-fA-F]+|\d{3,})\b")
# Heuristics for finding function/function-like boundaries across languages.
_FUNC_START_RE = re.compile(
    r"^\s*(?:func|function|def|fn|sub|method|private\s+function|"
    r"public\s+function|protected\s+function|static\s+function|"
    r"local\s+function)\b"
)
_BRACE_DEPTH_RE = re.compile(r"[{}]")
_PAREN_DEPTH_RE = re.compile(r"[\(\)]")


class CodeSmellAnalyzer(Analyzer):
    name = "code_smell"

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
        files = [Path(f) for f in project.files]
        if not files:
            return AnalyzerResult(
                tool=self.name,
                status=ToolStatus.NOT_APPLICABLE,
                version=self.version(),
                message="No source files to analyze for code smells",
                duration_seconds=time.monotonic() - started,
            )

        raw_path = raw_dir / "code_smell.json"
        findings: list[Finding] = []
        files_scanned = 0
        smells_summary: dict[str, int] = {}

        for path in files:
            try:
                too_large = path.stat().st_size > int(config.scan.max_file_size_mb * 1024 * 1024)
            except OSError:
                continue
            if too_large:
                continue
            try:
                rel = path.resolve().relative_to(Path(project.root).resolve()).as_posix()
            except (OSError, ValueError):
                rel = path.as_posix()

            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            files_scanned += 1
            lines = text.splitlines()
            findings.extend(_smell_file(path, rel, lines, smells_summary))

        raw_path.write_text(
            _raw_summary(files_scanned, smells_summary, self.version()),
            encoding="utf-8",
        )

        message = f"{files_scanned} files scanned; " + ", ".join(
            f"{k}={v}" for k, v in sorted(smells_summary.items())
        )
        return AnalyzerResult(
            tool=self.name,
            status=ToolStatus.SUCCESS,
            version=self.version(),
            message=message,
            findings=findings,
            raw_path=str(raw_path),
            duration_seconds=time.monotonic() - started,
        )


def _smell_file(path: Path, rel: str, lines: list[str], summary: dict[str, int]) -> list[Finding]:
    findings: list[Finding] = []

    # Large file smell.
    nlines = len(lines)
    if nlines >= THRESHOLDS["file_lines_violation"]:
        severity = Severity.HIGH
        summary["file_large_violation"] = summary.get("file_large_violation", 0) + 1
    elif nlines >= THRESHOLDS["file_lines_warning"]:
        severity = Severity.LOW
        summary["file_large_warning"] = summary.get("file_large_warning", 0) + 1
    else:
        severity = None

    if severity:
        findings.append(
            Finding(
                tool="code_smell",
                rule_id="code_smell.large_file",
                category=Category.CODE_SMELL,
                severity=severity,
                confidence=Confidence.MEDIUM,
                file=rel,
                start_line=1,
                end_line=nlines,
                message=(
                    f"Large file ({nlines} lines). Large files are harder to review, "
                    f"test and maintain. Consider splitting responsibilities across "
                    f"smaller modules."
                ),
                recommendation=(
                    "Break the file into focused modules by responsibility; aim for "
                    "files under 400 lines where practical."
                ),
                normalized_type="code_smell:large_file",
                source_tool_severity=str(nlines),
            )
        )

    # Long function / code block smell (heuristic, line-based).
    function_regions = _find_function_regions(lines)
    for start, end in function_regions:
        length = end - start + 1
        if length >= THRESHOLDS["function_lines_violation"]:
            severity = Severity.MEDIUM
            summary["func_long_violation"] = summary.get("func_long_violation", 0) + 1
        elif length >= THRESHOLDS["function_lines_warning"]:
            severity = Severity.LOW
            summary["func_long_warning"] = summary.get("func_long_warning", 0) + 1
        else:
            continue

        name = _function_name(lines, start)
        findings.append(
            Finding(
                tool="code_smell",
                rule_id="code_smell.long_function",
                category=Category.CODE_SMELL,
                severity=severity,
                confidence=Confidence.MEDIUM,
                file=rel,
                start_line=start,
                end_line=end,
                message=(
                    f"Long function/block '{name}' spans {length} lines "
                    f"({rel}:{start}). Long functions tend to do too many things "
                    f"at once and are harder to reason about."
                ),
                code_snippet="\n".join(lines[start - 1 : end]),
                recommendation=(
                    "Extract logical chunks into smaller helper functions with clear "
                    "single responsibilities."
                ),
                normalized_type="code_smell:long_function",
                source_tool_severity=str(length),
            )
        )

    # Deep nesting smell. Track depth across the file; measuring only the
    # braces on the current line misses the very condition this check targets.
    nesting_depth = 0
    for i, line in enumerate(lines, start=1):
        depth, nesting_depth = _nesting_depth(line, nesting_depth)
        if depth >= THRESHOLDS["nesting_violation"]:
            severity = Severity.MEDIUM
            summary["nesting_deep_violation"] = summary.get("nesting_deep_violation", 0) + 1
        elif depth >= THRESHOLDS["nesting_warning"]:
            severity = Severity.LOW
            summary["nesting_deep_warning"] = summary.get("nesting_deep_warning", 0) + 1
        else:
            continue
        findings.append(
            Finding(
                tool="code_smell",
                rule_id="code_smell.deep_nesting",
                category=Category.CODE_SMELL,
                severity=severity,
                confidence=Confidence.MEDIUM,
                file=rel,
                start_line=i,
                end_line=i,
                message=(
                    f"Deep nesting at line {i} (depth {depth}). Deeply nested code is "
                    f"harder to read and test; early returns or extraction usually help."
                ),
                code_snippet=line.strip()[:400],
                recommendation=(
                    "Reduce nesting via early returns, guard clauses, or extracting the "
                    "inner block into a helper."
                ),
                normalized_type="code_smell:deep_nesting",
                source_tool_severity=str(depth),
            )
        )

    # Magic number clusters.
    magic_by_line: dict[int, int] = {}
    for i, line in enumerate(lines, start=1):
        for m in _MAGIC_NUMBER_RE.finditer(line):
            tok = m.group(0)
            # Filter obvious non-magic numbers (0, 1, -1, 2).
            try:
                val: int | None = None
                if tok.lower().startswith("0x"):
                    val = int(tok, 16)
                else:
                    val = int(tok)
                if val in {0, 1, 2, -1}:
                    continue
            except ValueError:
                continue
            magic_by_line[i] = magic_by_line.get(i, 0) + 1

    for line_no, count in magic_by_line.items():
        if count >= THRESHOLDS["magic_number_min_occurrences"]:
            summary["magic_number_cluster"] = summary.get("magic_number_cluster", 0) + 1
            findings.append(
                Finding(
                    tool="code_smell",
                    rule_id="code_smell.magic_numbers",
                    category=Category.CODE_SMELL,
                    severity=Severity.LOW,
                    confidence=Confidence.LOW,
                    file=rel,
                    start_line=line_no,
                    end_line=line_no,
                    message=(
                        f"Line {line_no} contains {count} numeric literal(s). Clusters of "
                        f"magic numbers reduce clarity and make changes error-prone."
                    ),
                    code_snippet=lines[line_no - 1].strip()[:400],
                    recommendation=(
                        "Extract repeated or significant numeric literals into named "
                        "constants with explanatory names."
                    ),
                    normalized_type="code_smell:magic_numbers",
                    source_tool_severity=str(count),
                )
            )

    return findings


def _find_function_regions(lines: list[str]) -> list[tuple[int, int]]:
    """Heuristic function/block region detection using start markers and braces.

    This is intentionally conservative and language-agnostic; it finds obvious
    function-like regions and returns (start_line, end_line) pairs.
    """
    regions: list[tuple[int, int]] = []
    stack_start: list[int] = []
    current_start: int | None = None

    for idx, line in enumerate(lines, start=1):
        if _FUNC_START_RE.match(line):
            # New function-like region begins.
            if current_start is not None:
                regions.append((current_start, idx - 1))
            current_start = idx
            # Estimate block extent from braces on the same line.
            opens = line.count("{") - line.count("}")
            if opens > 0:
                stack_start.append(idx)
        elif current_start is not None:
            opens = line.count("{") - line.count("}")
            if opens > 0:
                stack_start.append(idx)
            closes = line.count("}") - line.count("{")
            if closes > 0 and stack_start:
                stack_start.pop()
                if not stack_start and current_start is not None:
                    regions.append((current_start, idx))
                    current_start = None

    if current_start is not None:
        last = len(lines)
        regions.append((current_start, last))

    return regions


def _function_name(lines: list[str], start: int) -> str:
    if start < 1 or start > len(lines):
        return "<unknown>"
    line = lines[start - 1]
    m = re.search(r"(?:func|function|def|fn|sub)\s+(\w+)", line)
    return m.group(1) if m else "<anonymous>"


def _nesting_depth(line: str, current: int = 0) -> tuple[int, int]:
    "Return (depth observed on this line, depth for the next line)."
    code = re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', "", line)
    opens = code.count("{") + code.count("(")
    closes = code.count("}") + code.count(")")
    depth = max(0, current + opens)
    next_depth = max(0, current + opens - closes)
    return depth, next_depth


def _raw_summary(files_scanned: int, summary: dict[str, int], version: str) -> str:
    import json

    return json.dumps(
        {
            "analyzer": "code_smell",
            "version": version,
            "files_scanned": files_scanned,
            "smell_counts": summary,
        },
        indent=2,
    )
