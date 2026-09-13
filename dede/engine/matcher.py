"""Line-based matching core for the Dede engine.

The engine is a small, deterministic, dependency-free weakness matcher:
rules express line conditions (combined with AND) plus optional whole-file
conditions. Nothing is inferred beyond what the rule and the source say —
findings always point at the exact matched line.
"""

from __future__ import annotations

import fnmatch
import re
from bisect import bisect_left, bisect_right
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path

from dede.engine.rules import DedRule, FileCondition, WhenCondition
from dede.engine.source import compiled_regex, mask_comments, tokens
from dede.utils.redact import redact_source_lines
from dede.utils.source import decode_source


@dataclass(frozen=True)
class SourceFile:
    """A file prepared for matching: original lines plus a lowercase copy."""

    relative_path: str
    lines: tuple[str, ...]
    lower_lines: tuple[str, ...]
    text_lower: str
    lexical_language: str = ""

    @cached_property
    def text(self) -> str:
        return "\n".join(self.lines)

    @cached_property
    def redacted_lines(self) -> tuple[str, ...]:
        return tuple(redact_source_lines(list(self.lines)))

    @cached_property
    def line_offsets(self) -> tuple[int, ...]:
        return (0, *(i + 1 for i, char in enumerate(self.text) if char == "\n"))

    def line_at(self, offset: int) -> int:
        return bisect_right(self.line_offsets, offset)

    @cached_property
    def literal_spans(self) -> tuple[tuple[int, ...], tuple[int, ...]]:
        literals = [
            (t.start, t.end) for t in tokens(self.text, self.lexical_language) if t.kind == "string"
        ]
        return tuple(start for start, _ in literals), tuple(end for _, end in literals)

    def without_comments(self, language: str) -> SourceFile:
        return self.from_text(self.relative_path, mask_comments(self.text, language), language)

    @classmethod
    def from_text(cls, relative_path: str, text: str, language: str = "") -> SourceFile:
        lines = tuple(text.splitlines())
        return cls(
            relative_path, lines, tuple(line.lower() for line in lines), text.lower(), language
        )

    @classmethod
    def load(cls, path: Path, relative_path: str, max_bytes: int | None = None) -> SourceFile:
        with path.open("rb") as handle:
            raw = handle.read(max_bytes + 1) if max_bytes is not None else handle.read()
        if max_bytes is not None and len(raw) > max_bytes:
            raise ValueError("File exceeds native engine byte limit")
        # BOM-aware decoding supports Windows .NET sources without treating
        # UTF-16 text as binary or silently replacing invalid input.
        return cls.from_text(relative_path, decode_source(raw))


@dataclass(frozen=True)
class Match:
    rule_id: str
    file: str
    start_line: int
    end_line: int
    snippet: str
    dataflow: tuple[dict, ...] = ()


def _iter_pattern_lines(source: SourceFile, pattern: str) -> list[int]:
    needle = pattern.lower()
    return [i for i, line in enumerate(source.lower_lines) if needle in line]


def _iter_regex_lines(source: SourceFile, regex: str) -> list[int]:
    try:
        compiled = compiled_regex(regex)
    except re.error:
        return []
    return [i for i, line in enumerate(source.lines) if compiled.search(line)]


def _iter_when_lines(source: SourceFile, when: WhenCondition) -> list[int]:
    if when.pattern:
        lines = _iter_pattern_lines(source, when.pattern)
    else:
        lines = _iter_regex_lines(source, when.regex)
    if when.not_pattern:
        banned = when.not_pattern.lower()
        lines = [i for i in lines if banned not in source.lower_lines[i]]
    if when.not_regex:
        try:
            compiled = compiled_regex(when.not_regex)
        except re.error:
            return []
        lines = [i for i in lines if not compiled.search(source.lines[i])]
    if when.line_min_length is not None:
        lines = [i for i in lines if len(source.lines[i]) >= when.line_min_length]
    if when.line_max_length is not None:
        lines = [i for i in lines if len(source.lines[i]) <= when.line_max_length]
    return lines


def evaluate_when(source: SourceFile, when: tuple[WhenCondition, ...]) -> list[int]:
    """Evaluate AND-combined line conditions; returns 0-based match lines.

    ``same_line`` on each subsequent condition constrains it to a reachable
    previous line. Otherwise any candidate at or after a reachable previous
    line is eligible. Ordered text matches do not bind variables or prove flow.
    """
    if not when:
        return []
    first = _iter_when_lines(source, when[0])
    if all(c.same_line for c in when):
        common = set(first)
        for condition in when[1:]:
            common &= set(_iter_when_lines(source, condition))
        return sorted(common)

    anchors = first
    for condition in when[1:]:
        candidates = _iter_when_lines(source, condition)
        if not anchors:
            break
        anchors = (
            sorted(set(anchors) & set(candidates))
            if condition.same_line
            else candidates[bisect_left(candidates, anchors[0]) :]
        )
    return sorted(set(anchors))


def evaluate_file_condition(source: SourceFile, condition: FileCondition) -> bool:
    """All declared matchers AND together (empty matchers are ignored)."""
    if condition.path and not fnmatch.fnmatch(source.relative_path, condition.path):
        return False
    if condition.contains and not all(
        item.lower() in source.text_lower for item in condition.contains
    ):
        return False
    if condition.contains_any and not any(
        item.lower() in source.text_lower for item in condition.contains_any
    ):
        return False
    if condition.contains_all and not all(
        item.lower() in source.text_lower for item in condition.contains_all
    ):
        return False
    if condition.not_regex:
        try:
            compiled = compiled_regex(condition.not_regex)
        except re.error:
            return True
        # Absence of the (safe) pattern is what satisfies this condition.
        if any(compiled.search(line) for line in source.lines):
            return False
    if condition.min_count_pattern is not None and condition.min_count is not None:
        if source.text_lower.count(condition.min_count_pattern.lower()) < condition.min_count:
            return False
    return True


def rule_applies(rule: DedRule, language: str) -> bool:
    return language.lower() in rule.languages or "*" in rule.languages


def match_rule(
    rule: DedRule,
    source: SourceFile,
    language: str,
    *,
    prepared: SourceFile | None = None,
    max_matches: int = 1001,
) -> list[Match]:
    """Match one rule against one file. Returns zero or more matches."""
    if not rule_applies(rule, language):
        return []
    view = (prepared or source.without_comments(language)) if rule.exclude_comments else source
    if any(evaluate_file_condition(view, c) for c in rule.if_not_conditions):
        return []
    if rule.if_conditions and not all(evaluate_file_condition(view, c) for c in rule.if_conditions):
        return []

    if rule.mode == "document":
        return _match_document(rule, source, view, language, max_matches)
    lines = evaluate_when(view, rule.when)
    matches: list[Match] = []
    for line_index in lines[:max_matches]:
        snippet = (
            "***REDACTED***" if rule.category == "secret" else source.redacted_lines[line_index]
        )
        matches.append(
            Match(
                rule_id=rule.id,
                file=source.relative_path,
                start_line=line_index + 1,
                end_line=line_index + 1,
                snippet=snippet[:400],
            )
        )
    return matches


def _match_document(
    rule: DedRule, source: SourceFile, view: SourceFile, language: str, limit: int
) -> list[Match]:
    condition = rule.when[0]
    results: list[Match] = []
    code_languages = {
        "c#",
        "java",
        "kotlin",
        "scala",
        "groovy",
        "visual basic",
        "f#",
        "rust",
        "swift",
        "dart",
        "python",
        "javascript",
        "typescript",
        "c",
        "c++",
        "objective-c",
        "objective-c++",
        "julia",
        "elixir",
        "r",
        "perl",
        "lua",
        "zig",
    }
    literal_starts, literal_ends = (
        view.literal_spans
        if rule.exclude_comments
        and not rule.match_in_strings
        and language.lower() in code_languages
        else ((), ())
    )
    for match in compiled_regex(condition.regex).finditer(view.text):
        if match.start() == match.end():
            continue
        literal_index = bisect_right(literal_starts, match.start()) - 1
        if literal_index >= 0 and match.start() < literal_ends[literal_index]:
            continue
        start = source.line_at(match.start())
        end = source.line_at(match.end() - 1)
        if end - start + 1 > rule.max_span_lines:
            continue
        span = match.group()
        if condition.not_pattern and condition.not_pattern.lower() in span.lower():
            continue
        if condition.not_regex and compiled_regex(condition.not_regex).search(span):
            continue
        if condition.line_min_length is not None and len(span) < condition.line_min_length:
            continue
        if condition.line_max_length is not None and len(span) > condition.line_max_length:
            continue
        snippet = (
            "***REDACTED***"
            if rule.category == "secret"
            else "\n".join(source.redacted_lines[start - 1 : end])[:400]
        )
        results.append(Match(rule.id, source.relative_path, start, end, snippet))
        if len(results) >= limit:
            break
    return results


def rule_digests(rules_dir: Path) -> dict[str, str]:
    """Per-file SHA-256 digests for reporting rule provenance."""
    import hashlib

    digests: dict[str, str] = {}
    if not rules_dir.is_dir():
        return digests
    for path in sorted((*rules_dir.glob("*.json"), *rules_dir.glob("*.y*ml"))):
        if path.name == "MANIFEST.yml":
            continue
        try:
            digests[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            continue
    return digests
