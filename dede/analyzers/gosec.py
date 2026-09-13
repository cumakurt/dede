"""gosec analyzer (offline; skip if module download required)."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from dede.analyzers.base import Analyzer
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

_SEV = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
}


class GosecAnalyzer(Analyzer):
    name = "gosec"

    def supports(self, project: ProjectContext) -> bool:
        return project.has_go

    def version(self) -> str:
        result = run_command(["gosec", "-version"], timeout=30)
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
        if which("gosec") is None:
            return AnalyzerResult(
                tool=self.name,
                status=ToolStatus.SKIPPED_OFFLINE_DEPENDENCY,
                version=self.version(),
                message="gosec not installed",
                duration_seconds=time.monotonic() - started,
            )
        if not (Path(project.root) / "go.mod").is_file():
            # gosec ./... only works inside a module; without go.mod it cannot
            # resolve packages and would report a spurious failure.
            return AnalyzerResult(
                tool=self.name,
                status=ToolStatus.NOT_APPLICABLE,
                version=self.version(),
                message="No go.mod at project root; gosec requires a Go module",
                duration_seconds=time.monotonic() - started,
            )

        raw_path = raw_dir / "gosec.json"
        raw_path.write_text("", encoding="utf-8")
        env = {
            **os.environ,
            "GOFLAGS": "-mod=readonly",
            "GO111MODULE": "on",
            "GOPROXY": "off",
            "GOCACHE": os.environ.get("GOCACHE") or "/tmp/dede-go-build",
            "GOMODCACHE": os.environ.get("GOMODCACHE") or "/tmp/dede-go-mod",
        }
        args = [
            "gosec",
            "-fmt=json",
            "-out",
            str(raw_path),
            "./...",
        ]
        result = run_command(
            args,
            cwd=project.root,
            timeout=config.scan.analyzer_timeout_seconds,
            env=env,
        )

        combined = (result.stdout + result.stderr).lower()
        if (
            "cannot find module" in combined
            or "does not contain main module" in combined
            or "no packages found" in combined
            or result.returncode == 127
        ):
            return AnalyzerResult(
                tool=self.name,
                status=ToolStatus.SKIPPED_OFFLINE_DEPENDENCY,
                version=self.version(),
                message="gosec unavailable offline or missing modules",
                duration_seconds=time.monotonic() - started,
            )

        findings: list[Finding] = []
        payload = {}
        parse_error = ""
        if raw_path.is_file():
            try:
                payload = json.loads(raw_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                parse_error = "Invalid gosec JSON report"
                payload = {}
        elif result.returncode == 0:
            # gosec can omit the output file when a clean package has no
            # issues. A successful exit is authoritative in that case.
            payload = {"Issues": []}

        if not isinstance(payload, dict):
            parse_error = "Invalid gosec JSON report"
            payload = {}
        issues = payload.get("Issues") or []
        if not isinstance(issues, list) or any(not isinstance(item, dict) for item in issues):
            parse_error = "Invalid gosec JSON issues"
            issues = []

        for item in issues:
            cwe = []
            cwe_raw = item.get("cwe") or {}
            if isinstance(cwe_raw, dict) and cwe_raw.get("ID"):
                cwe = [f"CWE-{cwe_raw['ID']}"]
            sev = _SEV.get(str(item.get("severity", "LOW")).upper(), Severity.LOW)
            findings.append(
                Finding(
                    tool=self.name,
                    rule_id=str(item.get("rule_id") or "gosec"),
                    category=Category.SECURITY,
                    severity=sev,
                    confidence=Confidence.MEDIUM,
                    cwe=cwe,
                    file=str(item.get("file") or ""),
                    start_line=int(item.get("line") or 1)
                    if str(item.get("line", "1")).isdigit()
                    else 1,
                    end_line=int(item.get("line") or 1)
                    if str(item.get("line", "1")).isdigit()
                    else 1,
                    message=redact_text(str(item.get("details") or "")),
                    code_snippet=redact_text(str(item.get("code") or "")),
                    source_tool_severity=str(item.get("severity") or ""),
                    normalized_type=str(item.get("rule_id") or "gosec"),
                )
            )

        failed = (
            result.timed_out
            or result.returncode not in (0, 1)
            or (result.returncode == 1 and not findings)
            or bool(parse_error)
        )
        return AnalyzerResult(
            tool=self.name,
            status=ToolStatus.FAILED if failed else ToolStatus.SUCCESS,
            version=self.version(),
            message=(
                parse_error
                or redact_text(result.stderr.strip())[:500]
                or f"gosec exited with code {result.returncode}"
            )
            if failed
            else "",
            findings=findings,
            raw_path=str(raw_path) if raw_path.is_file() else None,
            duration_seconds=time.monotonic() - started,
        )
