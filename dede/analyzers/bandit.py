"""Bandit Python security analyzer."""

from __future__ import annotations

import json
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
    ToolStatus,
)
from dede.normalization.severity import map_bandit_severity
from dede.utils.process import run_command, which
from dede.utils.redact import redact_text


class BanditAnalyzer(Analyzer):
    name = "bandit"

    def supports(self, project: ProjectContext) -> bool:
        return project.has_python

    def version(self) -> str:
        result = run_command(["bandit", "--version"], timeout=30)
        if result.returncode == 0:
            return (result.stdout or result.stderr).strip().splitlines()[0]
        return "unavailable"

    def analyze(
        self,
        project: ProjectContext,
        config: AppConfig,
        raw_dir: Path,
    ) -> AnalyzerResult:
        started = time.monotonic()
        if which("bandit") is None:
            return AnalyzerResult(
                tool=self.name,
                status=ToolStatus.SKIPPED_OFFLINE_DEPENDENCY,
                version="unavailable",
                message="bandit not installed; optional in native runtime",
                duration_seconds=time.monotonic() - started,
            )

        raw_path = raw_dir / "bandit.json"
        args = [
            "bandit",
            "-f",
            "json",
            "-q",
        ]
        files = [file for file in project.files if Path(file).suffix.lower() in {".py", ".pyw"}]
        result = run_json_targets(
            args,
            files,
            key="results",
            timeout=config.scan.analyzer_timeout_seconds,
            cwd=project.root,
            runner=run_command,
        )
        raw_path.write_text(result.stdout or "{}", encoding="utf-8")

        findings: list[Finding] = []
        try:
            payload = json.loads(result.stdout or "{}")
        except json.JSONDecodeError:
            return AnalyzerResult(
                tool=self.name,
                status=ToolStatus.FAILED,
                version=self.version(),
                message="Invalid Bandit JSON",
                raw_path=str(raw_path),
                duration_seconds=time.monotonic() - started,
            )

        for item in payload.get("results", []):
            cwe_id = ""
            issue_cwe = item.get("issue_cwe") or {}
            if isinstance(issue_cwe, dict):
                cwe_id = str(issue_cwe.get("id") or "")
            cwe = [f"CWE-{cwe_id}"] if cwe_id else []
            findings.append(
                Finding(
                    tool=self.name,
                    rule_id=str(item.get("test_id") or "bandit"),
                    category=Category.SECURITY,
                    severity=map_bandit_severity(str(item.get("issue_severity", "LOW"))),
                    confidence=Confidence(str(item.get("issue_confidence") or "MEDIUM").upper()),
                    cwe=cwe,
                    file=str(item.get("filename") or ""),
                    start_line=int(item.get("line_number") or 1),
                    end_line=int((item.get("line_range") or [item.get("line_number") or 1])[-1]),
                    message=redact_text(str(item.get("issue_text") or "")),
                    code_snippet=redact_text(str(item.get("code") or "")),
                    source_tool_severity=str(item.get("issue_severity") or ""),
                    normalized_type=str(item.get("test_id") or "bandit"),
                )
            )

        status = (
            ToolStatus.SUCCESS
            if result.returncode in (0, 1) and not payload.get("errors")
            else ToolStatus.FAILED
        )
        return AnalyzerResult(
            tool=self.name,
            status=status,
            version=self.version(),
            message=(result.stderr.strip()[:500] or "Bandit reported incomplete file coverage")
            if status == ToolStatus.FAILED
            else "",
            findings=findings,
            raw_path=str(raw_path),
            duration_seconds=time.monotonic() - started,
        )
