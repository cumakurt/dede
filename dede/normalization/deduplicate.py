"""Deduplicate and correlate findings across tools.

Correlation is indexed by stable identities and compact location buckets. This
avoids the O(n²) all-pairs behavior that becomes expensive on large monorepos
while retaining conservative fuzzy correlation for nearby cross-tool reports.
"""

from __future__ import annotations

from dede.models import Finding
from dede.normalization.correlation import should_merge
from dede.normalization.findings import (
    compute_fingerprint,
    compute_semantic_fingerprint,
    normalized_problem_type,
)

SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_BUCKET_SIZE = 4


def _merge(existing: Finding, incoming: Finding, score: float) -> Finding:
    winner, other = existing, incoming
    if SEVERITY_RANK[incoming.severity.value] > SEVERITY_RANK[existing.severity.value]:
        winner, other = incoming, existing
    winner.detected_by = list(dict.fromkeys([*existing.detected_by, *incoming.detected_by]))
    winner.references = list(dict.fromkeys([*existing.references, *incoming.references]))
    winner.owasp = list(dict.fromkeys([*existing.owasp, *incoming.owasp]))
    winner.cwe = list(dict.fromkeys([*existing.cwe, *incoming.cwe]))
    winner.sanitizers = list(dict.fromkeys([*existing.sanitizers, *incoming.sanitizers]))
    winner.call_path = list(dict.fromkeys([*existing.call_path, *incoming.call_path]))
    winner.control_flow = list(dict.fromkeys([*existing.control_flow, *incoming.control_flow]))
    winner.attack_surface = list(dict.fromkeys([*existing.attack_surface, *incoming.attack_surface]))
    winner.evidence = [
        *existing.evidence,
        *[item for item in incoming.evidence if item not in existing.evidence],
    ]
    winner.standards = {
        name: list(
            dict.fromkeys([*existing.standards.get(name, []), *incoming.standards.get(name, [])])
        )
        for name in existing.standards.keys() | incoming.standards.keys()
    }
    for field in (
        "code_snippet",
        "recommendation",
        "explanation",
        "impact",
        "dataflow",
        "analysis_kind",
        "symbol",
        "function",
        "class_name",
        "module",
        "package",
        "source_kind",
        "sink_kind",
        "rule_version",
        "engine_version",
        "ast_fingerprint",
        "endpoint",
        "http_method",
    ):
        if not getattr(winner, field):
            setattr(winner, field, getattr(other, field))
    if winner.reachable is None:
        winner.reachable = other.reachable
    if winner.authentication_required is None:
        winner.authentication_required = other.authentication_required
    if winner.internet_exposed is None:
        winner.internet_exposed = other.internet_exposed
    values = [
        value
        for value in (existing.exploitability_score, incoming.exploitability_score)
        if value is not None
    ]
    winner.exploitability_score = max(values) if values else None
    values = [
        value
        for value in (existing.confidence_score, incoming.confidence_score)
        if value is not None
    ]
    winner.confidence_score = max(values) if values else None
    winner.correlation_score = max(existing.correlation_score, incoming.correlation_score, score)
    if len(other.message) > len(winner.message):
        winner.message = other.message
    # Keep identity deterministic regardless of which engine had greater severity.
    winner.fingerprint = existing.fingerprint or incoming.fingerprint
    winner.semantic_fingerprint = existing.semantic_fingerprint or incoming.semantic_fingerprint
    return winner


def _path(finding: Finding) -> str:
    return finding.file.replace("\\", "/").lower()


def _buckets(finding: Finding) -> set[int]:
    start = max(1, finding.start_line) // _BUCKET_SIZE
    end = max(finding.start_line, finding.end_line, 1) // _BUCKET_SIZE
    if end - start > 32:
        core = {start, end}
    else:
        core = set(range(start, end + 1))
    return {max(0, value + delta) for value in core for delta in (-1, 0, 1)}


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    groups: list[Finding] = []
    by_v1: dict[str, int] = {}
    by_semantic: dict[str, int] = {}
    by_location: dict[tuple[str, int], set[int]] = {}

    def index_group(index: int, finding: Finding) -> None:
        if finding.fingerprint:
            by_v1[finding.fingerprint] = index
        if finding.semantic_fingerprint:
            by_semantic[finding.semantic_fingerprint] = index
        path = _path(finding)
        for bucket in _buckets(finding):
            by_location.setdefault((path, bucket), set()).add(index)

    for finding in findings:
        finding.normalized_type = normalized_problem_type(finding)
        finding.fingerprint = finding.fingerprint or compute_fingerprint(finding)
        finding.semantic_fingerprint = finding.semantic_fingerprint or compute_semantic_fingerprint(finding)
        finding.detected_by = list(dict.fromkeys(finding.detected_by or [finding.tool]))

        exact_index = by_v1.get(finding.fingerprint)
        if exact_index is None:
            exact_index = by_semantic.get(finding.semantic_fingerprint)
        if exact_index is not None:
            groups[exact_index] = _merge(groups[exact_index], finding, 1.0)
            index_group(exact_index, groups[exact_index])
            continue

        candidate_indexes: set[int] = set()
        path = _path(finding)
        for bucket in _buckets(finding):
            candidate_indexes.update(by_location.get((path, bucket), set()))

        merged_index: int | None = None
        merged_score = 0.0
        for index in sorted(candidate_indexes):
            should, score = should_merge(groups[index], finding)
            if should and score > merged_score:
                merged_index = index
                merged_score = score
        if merged_index is not None:
            groups[merged_index] = _merge(groups[merged_index], finding, merged_score)
            index_group(merged_index, groups[merged_index])
            continue

        groups.append(finding)
        index_group(len(groups) - 1, finding)
    return groups
