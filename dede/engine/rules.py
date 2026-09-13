"""Loaders for the Dede rule schema.

Dede's rule files are JSON documents under ``rules/dede-engine``. Each file is
either a rule or a bundle: ``{"schema": 1, "rules": [...]}``. Rules declare
weaknesses with:

- ``when``: line-based conditions combined with AND (``id``, ``pattern``,
  ``not_pattern``, ``regex``, ``line_min_length``, ``line_max_length``,
  ``same_line``)
- ``if``: per-file conditions evaluated before matching lines (``id``,
  ``contains_any``, ``contains_all``, ``path``, ``min_count``, ``min_count_pattern``)
- ``if_not``: same shape as ``if``; file is skipped when any condition matches

Literal matching is case-insensitive; regex uses Python's ``re`` module.
Condition IDs are descriptive labels, not variable bindings. Document mode
matches a bounded multiline span and keeps original source locations.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

MAX_RULES_PER_FILE = 500
MAX_RULE_FILE_BYTES = 4 * 1024 * 1024
MAX_CONDITIONS = 32
MAX_PATTERN_LENGTH = 8192


class RuleSchemaError(ValueError):
    """Raised when a rule file does not conform to the Dede rule schema."""


def _require_list(value: object, where: str) -> list:
    if not isinstance(value, list):
        raise RuleSchemaError(f"{where} must be a list")
    return value


def _require_str(value: object, where: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RuleSchemaError(f"{where} must be a non-empty string")
    return value


def _opt_str(value: object, where: str) -> str:
    if value is None:
        return ""
    return _require_str(value, where)


def _opt_int(value: object, where: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise RuleSchemaError(f"{where} must be an integer")
    return int(value)


def _optional_list(raw: dict, key: str, where: str) -> list:
    value = raw.get(key, [])
    return _require_list(value, f"{where}.{key}")


def _validate_regex(value: str, where: str) -> None:
    if len(value) > MAX_PATTERN_LENGTH:
        raise RuleSchemaError(f"{where}: pattern exceeds {MAX_PATTERN_LENGTH} characters")
    try:
        re.compile(value)
    except (re.error, RecursionError, OverflowError) as exc:
        raise RuleSchemaError(f"{where}: invalid regex ({exc})") from exc


@dataclass(frozen=True)
class WhenCondition:
    """A line matcher. ``pattern`` matches by case-insensitive substring."""

    id: str = ""
    pattern: str = ""
    regex: str = ""
    not_pattern: str = ""
    not_regex: str = ""
    line_min_length: int | None = None
    line_max_length: int | None = None
    same_line: bool = False


@dataclass(frozen=True)
class FileCondition:
    """A whole-file condition used in ``if`` / ``if_not`` blocks.

    ``not_regex`` means NO line in the file may match the expression (the
    condition holds when the pattern is absent). It combines with the other
    matchers by AND, so ``contains_any`` + ``not_regex`` expresses
    "file mentions X but never shows the safe form".
    """

    id: str = ""
    contains_any: tuple[str, ...] = ()
    contains_all: tuple[str, ...] = ()
    contains: tuple[str, ...] = ()
    not_regex: str = ""
    path: str = ""
    min_count: int | None = None
    min_count_pattern: str = ""


@dataclass(frozen=True)
class DedRule:
    """A weakness rule: line conditions (AND) + optional file conditions."""

    id: str
    message: str
    severity: str
    category: str
    languages: tuple[str, ...]
    when: tuple[WhenCondition, ...]
    if_conditions: tuple[FileCondition, ...] = ()
    if_not_conditions: tuple[FileCondition, ...] = ()
    confidence: str = "HIGH"
    cwe: tuple[str, ...] = ()
    owasp: tuple[str, ...] = ()
    asvs: tuple[str, ...] = ()
    recommendation: str = ""
    references: tuple[str, ...] = ()
    source: str = ""
    debt_minutes: int | None = None
    mode: str = "line"
    exclude_comments: bool = False
    max_span_lines: int = 30
    taint_sink: str = ""
    standards: dict[str, tuple[str, ...]] = field(default_factory=dict)
    match_in_strings: bool = False

    @property
    def kind(self) -> str:
        return (
            "taint"
            if self.mode == "taint"
            else "regex"
            if any(c.regex for c in self.when)
            else "pattern"
        )


@dataclass(frozen=True)
class RuleFile:
    path: Path
    rules: tuple[DedRule, ...]
    digest: str = ""


def _parse_when(raw: object, where: str) -> WhenCondition:
    if not isinstance(raw, dict):
        raise RuleSchemaError(f"{where} must be an object")
    if any(not isinstance(key, str) for key in raw):
        raise RuleSchemaError(f"{where} keys must be strings")
    unknown = set(raw) - {
        "id",
        "pattern",
        "regex",
        "not_pattern",
        "not_regex",
        "line_min_length",
        "line_max_length",
        "same_line",
    }
    if unknown:
        raise RuleSchemaError(f"{where}: unknown keys {sorted(unknown)}")
    pattern = _opt_str(raw.get("pattern"), f"{where}.pattern")
    regex = _opt_str(raw.get("regex"), f"{where}.regex")
    if bool(pattern) == bool(regex):
        raise RuleSchemaError(f"{where}: exactly one of pattern/regex is required")
    if regex:
        _validate_regex(regex, f"{where}.regex")
    not_regex = _opt_str(raw.get("not_regex"), f"{where}.not_regex")
    if not_regex:
        _validate_regex(not_regex, f"{where}.not_regex")
    same_line = raw.get("same_line", False)
    if not isinstance(same_line, bool):
        raise RuleSchemaError(f"{where}.same_line must be a boolean")
    line_min = _opt_int(raw.get("line_min_length"), f"{where}.line_min_length")
    line_max = _opt_int(raw.get("line_max_length"), f"{where}.line_max_length")
    if line_min is not None and line_min < 0:
        raise RuleSchemaError(f"{where}.line_min_length must be non-negative")
    if line_max is not None and line_max < 0:
        raise RuleSchemaError(f"{where}.line_max_length must be non-negative")
    if line_min is not None and line_max is not None and line_min > line_max:
        raise RuleSchemaError(f"{where}: line_min_length cannot exceed line_max_length")
    return WhenCondition(
        id=_opt_str(raw.get("id"), f"{where}.id"),
        pattern=pattern,
        regex=regex,
        not_pattern=_opt_str(raw.get("not_pattern"), f"{where}.not_pattern"),
        not_regex=not_regex,
        line_min_length=line_min,
        line_max_length=line_max,
        same_line=same_line,
    )


def _parse_file_condition(raw: object, where: str) -> FileCondition:
    if not isinstance(raw, dict):
        raise RuleSchemaError(f"{where} must be an object")
    if any(not isinstance(key, str) for key in raw):
        raise RuleSchemaError(f"{where} keys must be strings")
    unknown = set(raw) - {
        "id",
        "contains",
        "contains_any",
        "contains_all",
        "not_regex",
        "path",
        "min_count",
        "min_count_pattern",
    }
    if unknown:
        raise RuleSchemaError(f"{where}: unknown keys {sorted(unknown)}")
    contains = _opt_str(raw.get("contains"), f"{where}.contains")
    not_regex = _opt_str(raw.get("not_regex"), f"{where}.not_regex")
    if not_regex:
        _validate_regex(not_regex, f"{where}.not_regex")
    any_list = tuple(
        _require_str(item, f"{where}.contains_any[]")
        for item in _optional_list(raw, "contains_any", where)
    )
    all_list = tuple(
        _require_str(item, f"{where}.contains_all[]")
        for item in _optional_list(raw, "contains_all", where)
    )
    singletons = [item for item in (contains,) if item]
    if len(any_list) == 1:
        singletons.append(any_list[0])
        any_list = ()
    if len(all_list) == 1:
        singletons.append(all_list[0])
        all_list = ()
    if len(singletons) > 1 or (singletons and (any_list or all_list)):
        raise RuleSchemaError(f"{where}: only one of contains/contains_any/contains_all")
    path = _opt_str(raw.get("path"), f"{where}.path")
    has_matcher = bool(singletons or any_list or all_list or not_regex or path)
    min_count = _opt_int(raw.get("min_count"), f"{where}.min_count")
    min_count_pattern = _opt_str(raw.get("min_count_pattern"), f"{where}.min_count_pattern")
    if min_count is not None or min_count_pattern:
        if not min_count_pattern or min_count is None:
            raise RuleSchemaError(f"{where}: min_count and min_count_pattern must be set together")
        if min_count < 1:
            raise RuleSchemaError(f"{where}.min_count must be positive")
    elif not has_matcher:
        raise RuleSchemaError(f"{where}: at least one matcher is required")
    return FileCondition(
        id=_opt_str(raw.get("id"), f"{where}.id"),
        contains=tuple(singletons),
        contains_any=any_list,
        contains_all=all_list,
        not_regex=not_regex,
        path=path,
        min_count=min_count,
        min_count_pattern=min_count_pattern,
    )


def _parse_str_list(value: object, where: str) -> tuple[str, ...]:
    return tuple(_require_str(item, f"{where}[]") for item in _require_list(value, where))


VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
VALID_CATEGORIES = {
    "security",
    "bug",
    "quality",
    "secret",
    "complexity",
    "duplicate",
    "code_smell",
    "maintainability",
}


def _parse_rule(raw: object, where: str) -> DedRule:
    if not isinstance(raw, dict):
        raise RuleSchemaError(f"{where} must be an object")
    if any(not isinstance(key, str) for key in raw):
        raise RuleSchemaError(f"{where} keys must be strings")
    allowed = {
        "id",
        "message",
        "severity",
        "category",
        "languages",
        "when",
        "if",
        "if_not",
        "confidence",
        "cwe",
        "owasp",
        "asvs",
        "recommendation",
        "references",
        "source",
        "debt_minutes",
        "mode",
        "exclude_comments",
        "max_span_lines",
        "taint_sink",
        "standards",
        "match_in_strings",
    }
    unknown = set(raw) - allowed
    if unknown:
        raise RuleSchemaError(f"{where}: unknown keys {sorted(unknown)}")
    rule_id = _require_str(raw.get("id"), f"{where}.id")
    if not rule_id.startswith("dede."):
        raise RuleSchemaError(f"{where}.id must start with 'dede.'")
    severity = str(raw.get("severity", "MEDIUM")).upper()
    if severity not in VALID_SEVERITIES:
        raise RuleSchemaError(f"{where}.severity must be one of {sorted(VALID_SEVERITIES)}")
    category = str(raw.get("category", "security")).lower()
    if category not in VALID_CATEGORIES:
        raise RuleSchemaError(f"{where}.category must be one of {sorted(VALID_CATEGORIES)}")
    languages = tuple(
        lang.lower() for lang in _parse_str_list(raw.get("languages"), f"{where}.languages")
    )
    if not languages:
        raise RuleSchemaError(f"{where}.languages must be a non-empty list")
    when = tuple(
        _parse_when(item, f"{where}.when[{index}]")
        for index, item in enumerate(_require_list(raw.get("when"), f"{where}.when"))
    )
    if not when:
        raise RuleSchemaError(f"{where}.when must be a non-empty list")
    if len(when) > MAX_CONDITIONS:
        raise RuleSchemaError(f"{where}.when may contain at most {MAX_CONDITIONS} conditions")
    if_conf = tuple(
        _parse_file_condition(item, f"{where}.if[{index}]")
        for index, item in enumerate(_optional_list(raw, "if", where))
    )
    if_not_conf = tuple(
        _parse_file_condition(item, f"{where}.if_not[{index}]")
        for index, item in enumerate(_optional_list(raw, "if_not", where))
    )
    if max(len(if_conf), len(if_not_conf)) > MAX_CONDITIONS:
        raise RuleSchemaError(f"{where}: at most {MAX_CONDITIONS} file conditions are supported")
    confidence = str(raw.get("confidence", "HIGH")).upper()
    if confidence not in {"HIGH", "MEDIUM", "LOW"}:
        raise RuleSchemaError(f"{where}.confidence must be HIGH, MEDIUM or LOW")
    references = tuple(
        _require_str(item, f"{where}.references[]")
        for item in _optional_list(raw, "references", where)
    )
    for ref in references:
        if not ref.startswith(("http://", "https://")):
            raise RuleSchemaError(f"{where}.references[] must be http(s) URLs")
    debt_minutes = _opt_int(raw.get("debt_minutes"), f"{where}.debt_minutes")
    if debt_minutes is not None and debt_minutes < 0:
        raise RuleSchemaError(f"{where}.debt_minutes must be non-negative")
    mode = raw.get("mode", "line")
    if mode not in ("line", "document", "taint"):
        raise RuleSchemaError(f"{where}.mode must be line, document or taint")
    exclude_comments = raw.get("exclude_comments", False)
    if not isinstance(exclude_comments, bool):
        raise RuleSchemaError(f"{where}.exclude_comments must be a boolean")
    max_span = _opt_int(raw.get("max_span_lines", 30), f"{where}.max_span_lines")
    if max_span is None or not 1 <= max_span <= 200:
        raise RuleSchemaError(f"{where}.max_span_lines must be between 1 and 200")
    if mode in {"document", "taint"} and (len(when) != 1 or not when[0].regex):
        raise RuleSchemaError(f"{where}: {mode} mode requires exactly one regex condition")
    taint_sink = _opt_str(raw.get("taint_sink"), f"{where}.taint_sink")
    if mode == "taint":
        if taint_sink not in {
            "sql",
            "command",
            "arguments",
            "path",
            "ssrf",
            "xss",
            "redirect",
            "xpath",
            "regex",
            "ldap",
            "code",
        }:
            raise RuleSchemaError(f"{where}.taint_sink is not supported")
        if set(languages) - {"c#", "razor"}:
            raise RuleSchemaError(
                f"{where}: native taint currently supports C# and Razor code only"
            )
        if if_conf or if_not_conf:
            raise RuleSchemaError(f"{where}: native taint does not support file-wide guards")
    elif taint_sink:
        raise RuleSchemaError(f"{where}: taint_sink requires taint mode")
    raw_standards = raw.get("standards", {})
    if not isinstance(raw_standards, dict):
        raise RuleSchemaError(f"{where}.standards must be an object")
    standards = {
        _require_str(name, f"{where}.standards key"): _parse_str_list(
            controls, f"{where}.standards.{name}"
        )
        for name, controls in raw_standards.items()
    }
    match_in_strings = raw.get("match_in_strings", False)
    if not isinstance(match_in_strings, bool):
        raise RuleSchemaError(f"{where}.match_in_strings must be a boolean")
    return DedRule(
        id=rule_id,
        message=_require_str(raw.get("message"), f"{where}.message"),
        severity=severity,
        category=category,
        languages=languages,
        when=when,
        if_conditions=if_conf,
        if_not_conditions=if_not_conf,
        confidence=confidence,
        cwe=_parse_str_list(raw.get("cwe", []), f"{where}.cwe"),
        owasp=_parse_str_list(raw.get("owasp", []), f"{where}.owasp"),
        asvs=_parse_str_list(raw.get("asvs", []), f"{where}.asvs"),
        recommendation=_opt_str(raw.get("recommendation"), f"{where}.recommendation"),
        references=references,
        source=_opt_str(raw.get("source"), f"{where}.source"),
        debt_minutes=debt_minutes,
        mode=mode,
        exclude_comments=exclude_comments,
        max_span_lines=max_span,
        taint_sink=taint_sink,
        standards=standards,
        match_in_strings=match_in_strings,
    )


def parse_rule_document(payload: object, source: str) -> tuple[DedRule, ...]:
    """Parse one rule document (a single rule object or ``{"rules": [...]}``)."""
    if isinstance(payload, dict) and any(not isinstance(key, str) for key in payload):
        raise RuleSchemaError(f"{source}: document keys must be strings")
    if isinstance(payload, dict) and isinstance(payload.get("rules"), list):
        unknown = set(payload) - {"schema", "rules"}
        if unknown:
            raise RuleSchemaError(f"{source}: unknown document keys {sorted(unknown)}")
        schema = payload.get("schema", 1)
        if type(schema) is not int or schema != 1:
            raise RuleSchemaError(f"{source}.schema must be 1")
        if len(payload["rules"]) > MAX_RULES_PER_FILE:
            raise RuleSchemaError(f"{source}: at most {MAX_RULES_PER_FILE} rules are allowed")
        return tuple(
            _parse_rule(item, f"{source}.rules[{index}]")
            for index, item in enumerate(payload["rules"])
        )
    return (_parse_rule(payload, source),)


def load_rule_file(path: Path) -> RuleFile:
    """Load ``.json`` or ``.yml``/.yaml`` rule files from the engine rules dir."""
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_RULE_FILE_BYTES + 1)
        if len(raw) > MAX_RULE_FILE_BYTES:
            raise RuleSchemaError(f"{path}: rule file exceeds {MAX_RULE_FILE_BYTES} bytes")
        text = raw.decode("utf-8-sig")
    except (OSError, UnicodeError) as exc:
        raise RuleSchemaError(f"{path}: cannot read rule file ({type(exc).__name__})") from exc
    suffix = path.suffix.lower()
    try:
        if suffix in {".yml", ".yaml"}:
            payload = yaml.load(text, Loader=_UniqueSafeLoader)
        else:
            payload = json.loads(text, object_pairs_hook=_unique_pairs)
    except (ValueError, yaml.YAMLError, RecursionError) as exc:
        raise RuleSchemaError(f"{path}: invalid rule document ({type(exc).__name__})") from exc
    if payload is None:
        return RuleFile(path=path, rules=())
    try:
        rules = parse_rule_document(payload, str(path))
    except RecursionError as exc:
        raise RuleSchemaError(f"{path}: recursive rule document") from exc
    import hashlib

    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return RuleFile(path=path, rules=rules, digest=digest)


def _unique_pairs(pairs: list[tuple]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise RuleSchemaError("Duplicate document key")
        result[key] = value
    return result


class _UniqueSafeLoader(yaml.SafeLoader):
    """Reject ambiguous duplicate keys without changing PyYAML global behavior."""

    def construct_mapping(self, node, deep=False):
        self.flatten_mapping(node)
        pairs = self.construct_pairs(node, deep=deep)
        try:
            return _unique_pairs(pairs)
        except TypeError as exc:
            raise RuleSchemaError("Rule mapping keys must be scalar") from exc


def load_rules_dir(rules_dir: Path) -> tuple[RuleFile, ...]:
    """Load every rule file in the directory (non-recursive)."""
    if not rules_dir.is_dir():
        return ()
    files = sorted(
        p for p in rules_dir.glob("*.json") if p.name != "MANIFEST.json"
    ) + sorted(p for p in rules_dir.glob("*.y*ml") if p.name != "MANIFEST.yml")
    loaded = tuple(load_rule_file(path) for path in files)
    seen: dict[str, Path] = {}
    for rule_file in loaded:
        for rule in rule_file.rules:
            if rule.id in seen:
                raise RuleSchemaError(
                    f"duplicate rule id {rule.id!r} in {seen[rule.id]} and {rule_file.path}"
                )
            seen[rule.id] = rule_file.path
    return loaded
