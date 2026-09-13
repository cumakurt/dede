"""Finding fingerprinting, ID assignment, and snippet enrichment."""

from __future__ import annotations

from pathlib import Path
import re

from dede.config import AppConfig
from dede.models import Category, Finding
from dede.utils.hashes import sha256_text
from dede.utils.redact import (
    redact_snippet_for_secret_finding,
    redact_source_lines,
    redact_text,
    sanitize_finding_fields,
)
from dede.utils.source import read_source_lines


def normalized_problem_type(finding: Finding) -> str:
    if finding.normalized_type:
        return finding.normalized_type
    if finding.cwe:
        return ",".join(sorted(finding.cwe))
    return finding.rule_id.rsplit(".", 1)[-1].lower()


def compute_fingerprint(finding: Finding) -> str:
    """Legacy v1 fingerprint retained for baseline compatibility."""
    cwe = ",".join(sorted(finding.cwe))
    key = "|".join(
        [
            finding.file.replace("\\", "/"),
            str(finding.start_line),
            str(finding.end_line),
            cwe,
            normalized_problem_type(finding),
        ]
    )
    return sha256_text(key)


def _normalized_code_identity(snippet: str) -> str:
    """Return a location-independent representation suitable for identity.

    Snippet line-number prefixes, comments and repeated whitespace are ignored.
    Literal values are retained because they can materially distinguish two
    nearby security findings.
    """
    lines: list[str] = []
    for raw in snippet.splitlines():
        line = re.sub(r"^\s*\d+\s*:\s?", "", raw)
        line = re.sub(r"\s+", " ", line).strip()
        if line:
            lines.append(line)
    return "\n".join(lines[:24])


def compute_semantic_fingerprint(finding: Finding) -> str:
    """Stable v2 identity resilient to pure line-number shifts."""
    identity = [
        "dede-fingerprint-v2",
        finding.file.replace("\\", "/"),
        normalized_problem_type(finding),
        ",".join(sorted(finding.cwe)),
        finding.symbol or finding.function,
        finding.source_kind,
        finding.sink_kind,
        finding.ast_fingerprint,
        _normalized_code_identity(finding.code_snippet),
    ]
    # If no semantic/contextual material exists, include the old location to
    # avoid collapsing unrelated findings in the same file.
    if not any(identity[4:]):
        identity.extend([str(finding.start_line), str(finding.end_line)])
    return sha256_text("|".join(identity))


def assign_ids(findings: list[Finding], year: int = 2026) -> list[Finding]:
    for index, finding in enumerate(findings, start=1):
        finding.id = f"SRM-{year}-{index:06d}"
        if not finding.fingerprint:
            finding.fingerprint = compute_fingerprint(finding)
        if not finding.semantic_fingerprint:
            finding.semantic_fingerprint = compute_semantic_fingerprint(finding)
        if not finding.detected_by:
            finding.detected_by = [finding.tool]
    return findings


def attach_snippets(findings: list[Finding], root: Path, config: AppConfig) -> list[Finding]:
    ctx = config.scan.snippet_context_lines
    by_file: dict[str, list[Finding]] = {}
    for finding in findings:
        if finding.category == Category.SECRET:
            finding.code_snippet = redact_snippet_for_secret_finding(finding.code_snippet)
            continue
        if finding.code_snippet:
            finding.code_snippet = redact_text(finding.code_snippet)
            continue
        by_file.setdefault(finding.file, []).append(finding)
    max_bytes = int(config.scan.max_file_size_mb * 1024 * 1024)
    for file, group in by_file.items():
        lines = redact_source_lines(read_source_lines(root, file, max_bytes))
        for finding in group:
            start = max(1, finding.start_line - ctx)
            end = min(len(lines), max(finding.start_line, finding.end_line) + ctx)
            finding.code_snippet = "\n".join(f"{i}: {lines[i - 1]}" for i in range(start, end + 1))
    for finding in findings:
        sanitize_finding_fields(finding)
    return findings
