"""Deterministic checks of AI-reviewed locations and proposed code, never execution."""

from __future__ import annotations

import ast
import re
from pathlib import Path
from tempfile import TemporaryDirectory

from dede.analyzers.ruff import RuffAnalyzer
from dede.analyzers.semgrep import SemgrepAnalyzer
from dede.config import AppConfig
from dede.models import AnalyzerResult, Finding, ProjectContext, ToolStatus
from dede.utils.hashes import sha256_text
from dede.utils.redact import redact_text
from dede.utils.source import read_source_lines

SUPPORTED_SUFFIXES = {".py", ".pyi", ".pyw", ".js", ".jsx", ".ts", ".tsx"}


def _analyze(
    root: Path, files: list[Path], config: AppConfig, output: Path
) -> list[AnalyzerResult]:
    """Two bounded batches; no shell, generated tests, imports or project code run."""
    output.mkdir(parents=True, exist_ok=True)
    project = ProjectContext(
        root=str(root),
        files=[str(file) for file in files],
        has_python=any(file.suffix in {".py", ".pyi", ".pyw"} for file in files),
    )
    results = []
    for analyzer in (
        SemgrepAnalyzer(ignore_suppressions=True),
        RuffAnalyzer(ignore_suppressions=True),
    ):
        if not files or not analyzer.supports(project):
            continue
        try:
            results.append(analyzer.analyze(project, config, output))
        except Exception as exc:  # noqa: BLE001
            results.append(
                AnalyzerResult(
                    tool=analyzer.name,
                    status=ToolStatus.FAILED,
                    message=f"Static verification failed: {type(exc).__name__}",
                )
            )
    return results


def _path(root: Path, file: str) -> Path | None:
    try:
        path = (root / file).resolve()
        return path if path.is_relative_to(root.resolve()) else None
    except (OSError, RuntimeError, ValueError):
        return None


def _matches(original: Finding, repeated: Finding, root: Path) -> bool:
    # Reproduce the same rule at the same location, not just another issue nearby.
    return (
        original.rule_id == repeated.rule_id
        and _path(root, original.file) == _path(root, repeated.file)
        and original.start_line <= repeated.end_line
        and repeated.start_line <= max(original.start_line, original.end_line)
    )


def _example(text: str) -> str | None:
    text = text.strip()
    if "```" not in text:
        return text
    match = re.fullmatch(r"```[\w+-]*\s*\n(.*?)\n```", text, re.DOTALL)
    return match.group(1) if match and "```" not in match.group(1) else None


def _digest(root: Path, file: str, max_bytes: int) -> str:
    lines = read_source_lines(root, file, max_bytes)
    return sha256_text("\n".join(lines)) if lines else ""


def verify_ai_reviews(
    findings: list[Finding],
    root: Path,
    config: AppConfig,
    output: Path,
) -> None:
    """Always recheck cached reviews too. No AI verdict can establish a clean scan."""
    targets = [
        f
        for f in findings
        if f.ai_generated and f.ai_status in {"reviewed", "cached"} and not f.suppressed
    ]
    if not targets:
        return
    root = root.resolve()
    checks = config.model_copy(deep=True)
    checks.scan.analyzer_timeout_seconds = config.ai.verification_timeout_seconds
    checks.scan.respect_gitignore = False
    # Check generated fragments for bugs and dangerous APIs even with narrow scan lint settings.
    checks.ruff.select = list(dict.fromkeys([*config.ruff.select, "F", "E9", "S", "B"]))
    max_bytes = int(config.scan.max_file_size_mb * 1024 * 1024)
    paths = {f.file: _path(root, f.file) for f in targets}

    # --- Compute source digests in parallel ---------------------------------
    # For large projects with many reviewed findings this avoids sequential
    # disk reads before the verification loop starts.
    from concurrent.futures import ThreadPoolExecutor as _TPE

    unique_files = list(dict.fromkeys(f.file for f in targets))

    def _digest_file(file: str) -> tuple[str, str]:
        return file, _digest(root, file, max_bytes)

    with _TPE(max_workers=min(len(unique_files), 8)) as pool:
        initial = dict(pool.map(_digest_file, unique_files))

    eligible = []
    for finding in targets:
        finding.ai_validation_status = "UNVERIFIED"
        finding.ai_validation_notes = []
        if not finding.ai_source_digest or not initial[finding.file]:
            finding.ai_validation_notes = [
                "Source snapshot is unavailable; the AI interpretation is not verified."
            ]
        elif finding.ai_source_digest != initial[finding.file]:
            finding.ai_validation_status = "SOURCE_CHANGED"
            finding.ai_validation_notes = [
                "Source changed after review began; rescan before using the AI interpretation."
            ]
        else:
            eligible.append(finding)
    files = sorted({path for f in eligible if (path := paths[f.file]) is not None})
    results = _analyze(root, files, checks, output / "source")

    # Re-compute digests after analysis to detect concurrent writes — also parallel.
    with _TPE(max_workers=min(len(unique_files), 8)) as pool:
        after = dict(pool.map(_digest_file, unique_files))

    for finding in eligible:
        if after[finding.file] != initial[finding.file]:
            finding.ai_validation_status = "SOURCE_CHANGED"
            finding.ai_validation_notes = [
                "Source changed during static verification; rescan required."
            ]
            continue
        matches = [
            repeated
            for result in results
            if result.status == ToolStatus.SUCCESS
            for repeated in result.findings
            if _matches(finding, repeated, root)
        ]
        finding.ai_validation_notes = [
            f"Reproduced by {item.tool}: {item.rule_id} at line {item.start_line}."
            for item in matches[:10]
        ]
        if matches:
            if (
                finding.ai_verdict == "LIKELY_FALSE_POSITIVE"
                or finding.false_positive_probability == "HIGH"
            ):
                finding.ai_validation_status = "CONFLICT"
                finding.ai_validation_notes.append(
                    "AI dismissal conflicts with a reproduced static warning; dismissal is not accepted."
                )
            elif finding.ai_verdict == "LIKELY_VALID":
                finding.ai_validation_status = "CORROBORATED"
            finding.ai_validation_notes.append(
                "This reproduces a static warning, not runtime exploitability or the AI narrative's correctness."
            )
        else:
            finding.ai_validation_status = (
                "ERROR" if any(r.status == ToolStatus.FAILED for r in results) else "UNVERIFIED"
            )
            finding.ai_validation_notes.append(
                "No matching successful recheck. Absence of a match does not establish safety or a false positive."
            )
        finding.ai_validation_notes.extend(
            f"{r.tool}: {r.status.value}; verification coverage is incomplete."
            for r in results
            if r.status != ToolStatus.SUCCESS
        )
    _verify_examples(targets, checks, output / "examples")


def _verify_examples(targets: list[Finding], config: AppConfig, output: Path) -> None:
    with TemporaryDirectory(prefix="dede-ai-static-") as directory:
        root = Path(directory)
        candidates: dict[Path, Finding] = {}
        for index, finding in enumerate(targets):
            finding.ai_fix_notes = []
            if not finding.secure_code_example.strip():
                finding.ai_fix_status = "NOT_PROVIDED"
                continue
            suffix = Path(finding.file).suffix.lower()
            code = _example(finding.secure_code_example)
            if suffix not in SUPPORTED_SUFFIXES or not code or len(code.encode()) > 32_000:
                finding.ai_fix_status = "UNSUPPORTED"
                finding.ai_fix_notes = [
                    "Expected one bounded Python/JavaScript/TypeScript code fragment; not verified."
                ]
                continue
            if suffix in {".py", ".pyi", ".pyw"}:
                try:
                    ast.parse(code)
                except (SyntaxError, ValueError, RecursionError) as exc:
                    finding.ai_fix_status = "SYNTAX_ERROR"
                    finding.ai_fix_notes = [
                        f"Python parse failed ({type(exc).__name__}); example rejected."
                    ]
                    continue
            path = root / f"example_{index}{suffix}"
            path.write_text(code, encoding="utf-8")
            candidates[path] = finding
        results = _analyze(root, list(candidates), config, output)
        for path, finding in candidates.items():
            applicable = [
                r for r in results if r.tool == "semgrep" or path.suffix in {".py", ".pyi", ".pyw"}
            ]
            issues = [
                item
                for result in applicable
                for item in result.findings
                if _path(root, item.file) == path
            ]
            if issues:
                finding.ai_fix_status = "ISSUES_FOUND"
                finding.ai_fix_notes = [
                    redact_text(
                        f"{item.tool}:{item.rule_id} at line {item.start_line}: {item.message}"
                    )[:500]
                    for item in issues[:20]
                ]
            elif not applicable or any(
                result.status != ToolStatus.SUCCESS for result in applicable
            ):
                finding.ai_fix_status = "ERROR"
                finding.ai_fix_notes = [
                    "Static checks were unavailable or incomplete; example is not verified."
                ]
            else:
                finding.ai_fix_status = "CHECKS_PASSED"
                finding.ai_fix_notes = [
                    "No warnings in this isolated fragment under the selected rules. Not a validated patch; integration and runtime behavior remain untested."
                ]
