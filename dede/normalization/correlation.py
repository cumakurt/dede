"""Semantic cross-tool finding correlation.

The correlator intentionally uses conservative signals. It may merge findings
only when their source location/problem identity substantially overlap, while
preserving every contributing engine in ``detected_by`` and the strongest
available evidence.
"""

from __future__ import annotations

from difflib import SequenceMatcher
from pathlib import PurePosixPath

from dede.models import Finding


def _norm_path(value: str) -> str:
    return PurePosixPath(value.replace("\\", "/")).as_posix().lower()


def _line_overlap(a: Finding, b: Finding) -> float:
    a0, a1 = max(1, a.start_line), max(a.start_line, a.end_line)
    b0, b1 = max(1, b.start_line), max(b.start_line, b.end_line)
    overlap = max(0, min(a1, b1) - max(a0, b0) + 1)
    union = max(a1, b1) - min(a0, b0) + 1
    if overlap:
        return overlap / union
    # Nearby reports from different engines frequently disagree by one line.
    distance = min(abs(a0 - b1), abs(b0 - a1))
    return 0.5 if distance <= 2 else 0.0


def _set_similarity(left: list[str], right: list[str]) -> float:
    a, b = set(left), set(right)
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def correlation_score(a: Finding, b: Finding) -> float:
    """Return a conservative 0..1 semantic similarity score."""
    if _norm_path(a.file) != _norm_path(b.file):
        return 0.0

    score = 0.0
    score += 0.28 * _line_overlap(a, b)
    score += 0.22 * _set_similarity(a.cwe, b.cwe)
    if a.normalized_type and b.normalized_type:
        score += 0.22 * SequenceMatcher(None, a.normalized_type, b.normalized_type).ratio()
    if a.source_kind and a.source_kind == b.source_kind:
        score += 0.08
    if a.sink_kind and a.sink_kind == b.sink_kind:
        score += 0.08
    if a.symbol and a.symbol == b.symbol:
        score += 0.06
    if a.function and a.function == b.function:
        score += 0.06
    return min(1.0, score)


def should_merge(a: Finding, b: Finding, *, threshold: float = 0.72) -> tuple[bool, float]:
    # Semantic fingerprints are the strongest line-shift-stable identity.
    if a.semantic_fingerprint and a.semantic_fingerprint == b.semantic_fingerprint:
        return True, 1.0

    # Two engines/rules reporting the same CWE on the exact same source span
    # almost always describe the same defect.  Treat this as a strong identity
    # signal even when their normalized labels differ (for example
    # ``tls-verification-disabled`` vs ``verify-disabled``).  This removes
    # duplicate alert noise without broadening fuzzy nearby-line correlation.
    if (
        _norm_path(a.file) == _norm_path(b.file)
        and a.start_line == b.start_line
        and a.end_line == b.end_line
        and bool(set(a.cwe) & set(b.cwe))
        and a.category == b.category
    ):
        return True, 0.96

    score = correlation_score(a, b)
    return score >= threshold, score
