"""Ruff linter analyzer for Python quality/bugs."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from dede.analyzers.base import Analyzer
from dede.analyzers.targets import run_json_targets
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
from dede.utils.process import run_command, which
from dede.utils.redact import redact_text

_SECURITY_PREFIXES = ("S",)
_BUG_PREFIXES = ("B", "F", "E9")


class RuffAnalyzer(Analyzer):
    name = "ruff"

    def __init__(self, *, ignore_suppressions: bool = False) -> None:
        self.ignore_suppressions = ignore_suppressions

    def supports(self, project: ProjectContext) -> bool:
        return project.has_python

    def version(self) -> str:
        result = run_command(["ruff", "--version"], timeout=30)
        if result.returncode == 0:
            return (result.stdout or result.stderr).strip()
        return "unavailable"

    def analyze(
        self,
        project: ProjectContext,
        config: AppConfig,
        raw_dir: Path,
    ) -> AnalyzerResult:
        started = time.monotonic()
        if which("ruff") is None:
            return AnalyzerResult(
                tool=self.name,
                status=ToolStatus.SKIPPED_OFFLINE_DEPENDENCY,
                version="unavailable",
                message="ruff not installed; optional in native runtime",
                duration_seconds=time.monotonic() - started,
            )

        raw_path = raw_dir / "ruff.json"
        args = [
            "ruff",
            "check",
            "--isolated",
            "--select",
            ",".join(config.ruff.select),
            "--no-fix",
            "--output-format",
            "json",
            "--exit-zero",
            "--no-cache",
        ]
        if self.ignore_suppressions:
            args.append("--ignore-noqa")
        if not config.scan.respect_gitignore:
            args.append("--no-respect-gitignore")
        env = {
            **os.environ,
            "RUFF_CACHE_DIR": "/tmp/ruff_cache",
        }
        files = [
            file for file in project.files if Path(file).suffix.lower() in {".py", ".pyi", ".pyw"}
        ]
        result = run_json_targets(
            args,
            files,
            key=None,
            timeout=config.scan.analyzer_timeout_seconds,
            cwd=project.root,
            env=env,
            runner=run_command,
        )
        raw_path.write_text(result.stdout or "[]", encoding="utf-8")

        findings: list[Finding] = []
        try:
            payload = json.loads(result.stdout or "[]")
        except json.JSONDecodeError:
            return AnalyzerResult(
                tool=self.name,
                status=ToolStatus.FAILED,
                version=self.version(),
                message="Invalid Ruff JSON",
                raw_path=str(raw_path),
                duration_seconds=time.monotonic() - started,
            )

        for item in payload if isinstance(payload, list) else []:
            code = str(item.get("code") or "ruff")
            if code.startswith(_SECURITY_PREFIXES):
                category = Category.SECURITY
                severity = Severity.MEDIUM
                if code in {"S102", "S307", "S506", "S602", "S605", "S608"}:
                    severity = Severity.HIGH
                elif code in {"S101", "S311"} or code.startswith("S4"):
                    severity = Severity.LOW
            elif code.startswith((*_BUG_PREFIXES, "ASYNC")):
                category = Category.BUG
                severity = Severity.MEDIUM
            else:
                category = Category.QUALITY
                severity = Severity.LOW
            loc = item.get("location") or {}
            end = item.get("end_location") or {}
            findings.append(
                Finding(
                    tool=self.name,
                    rule_id=code,
                    category=category,
                    severity=severity,
                    confidence=Confidence.MEDIUM,
                    file=str(item.get("filename") or ""),
                    start_line=int(loc.get("row") or 1),
                    start_column=int(loc.get("column") or 0),
                    end_line=int(end.get("row") or loc.get("row") or 1),
                    end_column=int(end.get("column") or 0),
                    message=redact_text(str(item.get("message") or "")),
                    source_tool_severity=code,
                    normalized_type=f"ruff:{code}",
                    references=[item["url"]] if isinstance(item.get("url"), str) else [],
                )
            )

        status = ToolStatus.SUCCESS if result.returncode in (0, 1) else ToolStatus.FAILED
        return AnalyzerResult(
            tool=self.name,
            status=status,
            version=self.version(),
            message=result.stderr.strip()[:500] if status == ToolStatus.FAILED else "",
            findings=findings,
            raw_path=str(raw_path),
            duration_seconds=time.monotonic() - started,
        )
