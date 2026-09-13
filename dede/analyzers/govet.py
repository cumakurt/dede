"""go vet analyzer (offline; no module download)."""

from __future__ import annotations

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


class GoVetAnalyzer(Analyzer):
    name = "go_vet"

    def supports(self, project: ProjectContext) -> bool:
        return project.has_go

    def version(self) -> str:
        result = run_command(["go", "version"], timeout=30)
        if result.returncode == 0:
            return (result.stdout or "").strip()
        return "unavailable"

    def analyze(
        self,
        project: ProjectContext,
        config: AppConfig,
        raw_dir: Path,
    ) -> AnalyzerResult:
        started = time.monotonic()
        if which("go") is None:
            return AnalyzerResult(
                tool=self.name,
                status=ToolStatus.SKIPPED_OFFLINE_DEPENDENCY,
                version=self.version(),
                message="go toolchain not installed",
                duration_seconds=time.monotonic() - started,
            )
        if not (Path(project.root) / "go.mod").is_file():
            # go vet ./... only works inside a module; Go files without one
            # (snippets, vendored samples) are not analyzable by design.
            return AnalyzerResult(
                tool=self.name,
                status=ToolStatus.NOT_APPLICABLE,
                version=self.version(),
                message="No go.mod at project root; go vet requires a Go module",
                duration_seconds=time.monotonic() - started,
            )

        raw_path = raw_dir / "go_vet.txt"
        env = {
            **os.environ,
            "GOFLAGS": "-mod=readonly",
            "GOPROXY": "off",
            "GO111MODULE": "on",
            "GOCACHE": os.environ.get("GOCACHE") or "/tmp/dede-go-build",
            "GOMODCACHE": os.environ.get("GOMODCACHE") or "/tmp/dede-go-mod",
        }
        result = run_command(
            ["go", "vet", "./..."],
            cwd=project.root,
            timeout=config.scan.analyzer_timeout_seconds,
            env=env,
        )
        raw_path.write_text(result.stdout + "\n" + result.stderr, encoding="utf-8")

        # Module download required?
        combined = (result.stdout + result.stderr).lower()
        if (
            "cannot find module" in combined
            or "missing go.sum" in combined
            or "does not contain main module" in combined
        ):
            if result.returncode != 0 and "vet:" not in combined:
                return AnalyzerResult(
                    tool=self.name,
                    status=ToolStatus.SKIPPED_OFFLINE_DEPENDENCY,
                    version=self.version(),
                    message="Go modules unavailable offline",
                    raw_path=str(raw_path),
                    duration_seconds=time.monotonic() - started,
                )

        findings: list[Finding] = []
        for line in (result.stderr or result.stdout).splitlines():
            # format: file:line:col: message
            if ":" not in line:
                continue
            parts = line.split(":", 3)
            if len(parts) < 4:
                continue
            file_path, line_no, _col, message = parts[0], parts[1], parts[2], parts[3]
            try:
                lineno = int(line_no)
            except ValueError:
                continue
            findings.append(
                Finding(
                    tool=self.name,
                    rule_id="go.vet",
                    category=Category.BUG,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    file=file_path,
                    start_line=lineno,
                    end_line=lineno,
                    message=redact_text(message.strip()),
                    source_tool_severity="warning",
                    normalized_type="go:vet",
                )
            )

        failed = (
            result.timed_out
            or result.returncode not in (0, 1)
            or (result.returncode == 1 and not findings)
        )
        return AnalyzerResult(
            tool=self.name,
            status=ToolStatus.FAILED if failed else ToolStatus.SUCCESS,
            version=self.version(),
            message=(
                redact_text(result.stderr.strip())[:500]
                or f"go vet exited with code {result.returncode}"
            )
            if failed
            else "",
            findings=findings,
            raw_path=str(raw_path),
            duration_seconds=time.monotonic() - started,
        )
