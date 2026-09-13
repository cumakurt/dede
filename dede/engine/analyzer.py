"""The Dede engine — Dede's own static analysis analyzer.

Runs the vendored, standalone rule set under ``rules/dede-engine`` over
every discovered source file. Deterministic and offline: a bounded Python worker never executes target code
and never touches the network, so it always works even when external tools
are missing.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

from dede.analyzers.base import Analyzer
from dede.config import AppConfig
from dede.engine import matcher
from dede.engine.rules import DedRule, RuleSchemaError, load_rules_dir
from dede.models import (
    AnalyzerResult,
    Category,
    Confidence,
    DataflowStep,
    Finding,
    ProjectContext,
    Precision,
    Severity,
    ToolStatus,
)
from dede.utils.process import run_command
from dede.utils.redact import redact_text

CATEGORY_MAP = {
    "security": Category.SECURITY,
    "bug": Category.BUG,
    "quality": Category.QUALITY,
    "secret": Category.SECRET,
    "complexity": Category.COMPLEXITY,
    "duplicate": Category.DUPLICATE,
    "code_smell": Category.CODE_SMELL,
    "maintainability": Category.MAINTAINABILITY,
}


def default_engine_rules_dir() -> Path:
    candidates = [
        Path("/rules/dede-engine"),
        Path(__file__).resolve().parents[2] / "rules" / "dede-engine",
        Path(__file__).resolve().parents[3] / "rules" / "dede-engine",
        Path(__file__).resolve().parents[1] / "bundled_rules" / "dede-engine",
    ]
    for path in candidates:
        try:
            if path.is_dir() and (any(path.glob("*.json")) or any(path.glob("*.y*ml"))):
                return path
        except OSError:
            continue
    return candidates[0]


class DedeEngineAnalyzer(Analyzer):
    """Dede's native weakness-detection engine (no external binary)."""

    name = "dede-engine"

    def __init__(self, *, rules_dir: Path | None = None) -> None:
        self._rules_dir_override = rules_dir
        self._rules: tuple[DedRule, ...] | None = None
        self._rule_files: int = 0
        self._load_error: str = ""
        self._rule_digests: dict[str, str] = {}

    # -- rule loading -------------------------------------------------------

    def _rules_dir(self) -> Path:
        return self._rules_dir_override or default_engine_rules_dir()

    def _ensure_rules(self) -> tuple[DedRule, ...]:
        if self._rules is not None:
            return self._rules
        rules_dir = self._rules_dir()
        try:
            rule_files = load_rules_dir(rules_dir)
        except RuleSchemaError as exc:
            self._load_error = str(exc)
            self._rules = ()
            return self._rules
        self._rule_files = len(rule_files)
        self._rule_digests = {bundle.path.name: bundle.digest for bundle in rule_files}
        self._rules = tuple(rule for rule_file in rule_files for rule in rule_file.rules)
        return self._rules

    def rule_count(self) -> int:
        return len(self._ensure_rules())

    @property
    def load_error(self) -> str:
        """Non-empty when the vendored rules failed schema validation."""
        self._ensure_rules()
        return self._load_error

    # -- Analyzer interface -------------------------------------------------

    def supports(self, project: ProjectContext) -> bool:
        return bool(project.files)

    def version(self) -> str:
        try:
            return (self._rules_dir() / "VERSION").read_text(encoding="utf-8").strip() or "bundled"
        except (OSError, UnicodeError):
            return "bundled" if self.rule_count() else "no-rules"

    def analyze(
        self,
        project: ProjectContext,
        config: AppConfig,
        raw_dir: Path,
        *,
        max_file_bytes: int | None = None,
    ) -> AnalyzerResult:
        started = time.monotonic()
        rules = self._ensure_rules()
        if self._load_error:
            return AnalyzerResult(
                tool=self.name,
                status=ToolStatus.FAILED,
                version=self.version(),
                message=f"Invalid engine rules: {self._load_error[:400]}",
                duration_seconds=time.monotonic() - started,
            )
        if not rules:
            return AnalyzerResult(
                tool=self.name,
                status=ToolStatus.FAILED,
                version=self.version(),
                message=f"Dede engine rules not found under {self._rules_dir()}",
                duration_seconds=time.monotonic() - started,
            )

        limit = (
            max_file_bytes
            if max_file_bytes is not None
            else int(config.scan.max_file_size_mb * 1024 * 1024)
        )
        if limit < 1:
            raise ValueError("max_file_bytes must be positive")
        request = {
            "root": str(Path(project.root).resolve()),
            "files": project.files,
            "rules_dir": str(self._rules_dir().resolve()),
            "max_bytes": limit,
            "max_findings": config.engine.max_findings,
            "max_per_file": config.engine.max_findings_per_file,
        }
        command = run_command(
            # -I excludes the target cwd, PYTHONPATH and user-site hooks. The
            # worker must import this scanner installation, never a package
            # called 'dede' supplied by the project being inspected.
            [
                sys.executable,
                "-I",
                "-c",
                "import sys; sys.path.insert(0, sys.argv[1]); from dede.engine.worker import main; main()",
                str(Path(__file__).resolve().parents[2]),
            ],
            cwd=Path(__file__).resolve().parents[2],
            input_text=json.dumps(request),
            timeout=config.scan.analyzer_timeout_seconds,
        )
        findings, coverage, errors = self._read_worker_output(
            command.stdout, rules, len(project.files)
        )
        if command.timed_out:
            errors.append("Native analyzer timeout; completed file results retained")
        elif command.returncode:
            errors.append(f"Native worker exited with code {command.returncode}")
        raw_dir.mkdir(parents=True, exist_ok=True)
        raw_path = raw_dir / "dede-engine.json"
        raw_path.write_text(
            json.dumps(
                {
                    "engine": self.name,
                    "version": self.version(),
                    "rules": len(rules),
                    "rule_ids": sorted(rule.id for rule in rules),
                    "hits": len(findings),
                    **coverage,
                    "diagnostics": errors[:100],
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        message = f"{len(rules)} rules / {coverage['files_scanned']} files ({len(findings)} hits)"
        if errors:
            message += "; " + "; ".join(errors[:3])
        return AnalyzerResult(
            tool=self.name,
            status=ToolStatus.FAILED if errors else ToolStatus.SUCCESS,
            version=self.version(),
            message=redact_text(message),
            findings=findings,
            raw_path=str(raw_path),
            coverage=coverage,
            duration_seconds=time.monotonic() - started,
        )

    def _read_worker_output(
        self,
        output: str,
        rules: tuple[DedRule, ...],
        requested: int,
    ) -> tuple[list[Finding], dict, list[str]]:
        rule_by_id = {rule.id: rule for rule in rules}
        findings: list[Finding] = []
        coverage: dict = {
            "files_requested": requested,
            "files_scanned": 0,
            "files_failed": 0,
            "files_truncated": 0,
            "languages": {},
            "rule_digests": {},
        }
        errors: list[str] = []
        completed = False
        for line in output.splitlines():
            try:
                packet = json.loads(line)
                event = packet["event"]
                if event == "start":
                    coverage["rule_digests"] = packet["rule_digests"]
                    if coverage["rule_digests"] != self._rule_digests:
                        coverage["files_unprocessed"] = requested
                        return (
                            [],
                            coverage,
                            ["Native rules changed after validation; rescan with a fresh analyzer"],
                        )
                elif event == "file":
                    for item in packet["matches"]:
                        match = matcher.Match(**item)
                        findings.append(self._to_finding(rule_by_id[match.rule_id], match))
                    language = coverage["languages"].setdefault(
                        packet["language"],
                        {
                            "files_scanned": 0,
                            "rules": packet["rules"],
                            "language_rules": packet["language_rules"],
                            "rule_kinds": packet["rule_kinds"],
                        },
                    )
                    language["files_scanned"] += 1
                    coverage["files_scanned"] += 1
                    if packet["truncated"]:
                        coverage["files_truncated"] += 1
                        errors.append("Per-file native finding limit reached")
                elif event == "error":
                    coverage["files_failed"] += 1
                    errors.append(f"Cannot scan {packet['file'] or 'source'} ({packet['reason']})")
                elif event in {"fatal", "limit"}:
                    errors.append(packet["reason"])
                elif event == "complete":
                    completed = True
                else:
                    errors.append("Unknown native worker event")
            except (ValueError, KeyError, TypeError):
                errors.append("Invalid native worker output")
        if not completed:
            errors.append("Native analysis incomplete")
        coverage["files_unprocessed"] = max(
            0, requested - coverage["files_scanned"] - coverage["files_failed"]
        )
        return findings, coverage, errors

    def _to_finding(self, rule: DedRule, match: matcher.Match) -> Finding:
        try:
            confidence = Confidence(rule.confidence)
        except ValueError:
            confidence = Confidence.MEDIUM
        try:
            severity = Severity(rule.severity)
        except ValueError:
            severity = Severity.INFO
        references = [ref for ref in rule.references if ref.startswith("http")]
        standards: dict[str, list[str]] = {
            name: list(controls) for name, controls in rule.standards.items()
        }
        if rule.asvs:
            standards["owasp-asvs-5.0.0"] = list(rule.asvs)
        precision = {
            Confidence.HIGH: Precision.HIGH,
            Confidence.MEDIUM: Precision.MEDIUM,
            Confidence.LOW: Precision.EXPERIMENTAL,
        }.get(confidence, Precision.MEDIUM)
        confidence_score = {
            Confidence.HIGH: 0.90,
            Confidence.MEDIUM: 0.75,
            Confidence.LOW: 0.55,
        }.get(confidence, 0.75)
        return Finding(
            tool=self.name,
            rule_id=rule.id,
            category=CATEGORY_MAP.get(rule.category, Category.OTHER),
            severity=severity,
            confidence=confidence,
            confidence_score=confidence_score,
            precision=precision,
            cwe=list(rule.cwe),
            owasp=list(rule.owasp),
            standards=standards,
            file=match.file,
            start_line=match.start_line,
            end_line=match.end_line,
            message=redact_text(rule.message),
            code_snippet=match.snippet,
            recommendation=redact_text(rule.recommendation),
            analysis_kind=rule.kind,
            dataflow=[DataflowStep.model_validate(step) for step in match.dataflow],
            source_tool_severity=rule.severity,
            normalized_type=rule.id,
            references=references,
            explanation=(
                rule.debt_minutes and f"Estimated remediation: ~{rule.debt_minutes} min" or ""
            ),
        )
