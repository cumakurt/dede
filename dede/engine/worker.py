"""Isolated native execution. JSON lines preserve completed files on timeout.

Only scanner code runs here: source projects are read as text and never
imported, built, restored or executed. The parent enforces a hard process limit.
"""

from __future__ import annotations

import json
import stat
import sys
from collections import Counter
from dataclasses import asdict
from pathlib import Path

from dede.discovery.languages import detect_file_language
from dede.engine.dotnet import analyze_local_flow
from dede.engine.matcher import Match, SourceFile, match_rule, rule_applies
from dede.engine.rules import DedRule, load_rules_dir


def _emit(payload: dict) -> None:
    print(json.dumps(payload, ensure_ascii=True), flush=True)


def scan(request: dict) -> None:
    root = Path(request["root"]).resolve()
    rule_files = load_rules_dir(Path(request["rules_dir"]))
    rules = tuple(rule for bundle in rule_files for rule in bundle.rules)
    _emit(
        {
            "event": "start",
            "rule_digests": {bundle.path.name: bundle.digest for bundle in rule_files},
        }
    )
    by_language: dict[str, tuple[DedRule, ...]] = {}
    total = 0
    for entry in request["files"]:
        path = Path(entry)
        relative = ""
        try:
            resolved = path.resolve()
            relative = resolved.relative_to(root).as_posix()
            if not stat.S_ISREG(resolved.stat().st_mode):
                raise ValueError("Source is not a regular file")
            source = SourceFile.load(resolved, relative, request["max_bytes"])
        except (OSError, ValueError, RuntimeError) as exc:
            _emit({"event": "error", "file": relative, "reason": type(exc).__name__})
            continue
        language = detect_file_language(path) or "unknown"
        if language not in by_language:
            by_language[language] = tuple(rule for rule in rules if rule_applies(rule, language))
        applicable = by_language[language]
        prepared = (
            source.without_comments(language)
            if any(r.exclude_comments for r in applicable)
            else None
        )
        matches: list[Match] = []
        limit = min(request["max_per_file"], request["max_findings"] - total)
        for rule in applicable:
            if rule.mode == "taint":
                continue
            matches.extend(
                match_rule(
                    rule, source, language, prepared=prepared, max_matches=limit + 1 - len(matches)
                )
            )
            if len(matches) > limit:
                break
        flow_rules = tuple(rule for rule in applicable if rule.mode == "taint")
        if flow_rules and len(matches) <= limit:
            try:
                matches.extend(analyze_local_flow(source, flow_rules, limit + 1 - len(matches)))
            except ValueError:
                _emit(
                    {"event": "error", "file": relative, "reason": "Native flow complexity limit"}
                )
                continue
        truncated = len(matches) > limit
        matches = matches[:limit]
        total += len(matches)
        kinds = Counter(rule.kind for rule in applicable if "*" not in rule.languages)
        _emit(
            {
                "event": "file",
                "file": relative,
                "language": language,
                "rules": len(applicable),
                "language_rules": sum(kinds.values()),
                "rule_kinds": dict(kinds),
                "truncated": truncated,
                "matches": [asdict(match) for match in matches],
            }
        )
        if truncated and total >= request["max_findings"]:
            _emit({"event": "limit", "reason": "Native finding limit reached"})
            return
    _emit({"event": "complete"})


def main() -> None:
    try:
        scan(json.load(sys.stdin))
    except Exception as exc:
        # Error types provide diagnosis without copying rule/source text.
        _emit({"event": "fatal", "reason": type(exc).__name__})
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
