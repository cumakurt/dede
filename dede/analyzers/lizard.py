"""Lizard complexity analyzer."""

from __future__ import annotations

import json
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

# Skipped runs must not surface as FAILED to the pipeline; a missing optional
# complexity module is an offline dependency gap, same as a missing gosec binary.
from dede.utils.process import run_command


class LizardAnalyzer(Analyzer):
    name = "lizard"

    def supports(self, project: ProjectContext) -> bool:
        return bool(project.files)

    def version(self) -> str:
        result = run_command(["lizard", "--version"], timeout=30)
        if result.returncode == 0 and (result.stdout or result.stderr).strip():
            return (result.stdout or result.stderr).strip()
        result = run_command(
            [
                "python",
                "-c",
                "import importlib.metadata as m; print(m.version('lizard'))",
            ],
            timeout=30,
        )
        if result.returncode == 0:
            return result.stdout.strip()
        return "installed"

    def analyze(
        self,
        project: ProjectContext,
        config: AppConfig,
        raw_dir: Path,
    ) -> AnalyzerResult:
        started = time.monotonic()
        try:
            import lizard as lizard_mod
        except ImportError:
            return AnalyzerResult(
                tool=self.name,
                status=ToolStatus.SKIPPED_OFFLINE_DEPENDENCY,
                version=self.version(),
                message="lizard python module not installed",
                duration_seconds=time.monotonic() - started,
            )

        raw_path = raw_dir / "lizard.json"

        try:
            analysis = lizard_mod.analyze(project.files)
            findings: list[Finding] = []
            rows = []
            for file_info in analysis:
                for func in file_info.function_list:
                    rows.append(
                        {
                            "file": file_info.filename,
                            "name": func.name,
                            "ccn": func.cyclomatic_complexity,
                            "nloc": func.nloc,
                            "start_line": func.start_line,
                            "end_line": func.end_line,
                        }
                    )
                    if func.cyclomatic_complexity >= 15:
                        severity = (
                            Severity.INFO if func.cyclomatic_complexity < 30 else Severity.LOW
                        )
                        findings.append(
                            Finding(
                                tool=self.name,
                                rule_id="complexity.high-ccn",
                                category=Category.COMPLEXITY,
                                severity=severity,
                                confidence=Confidence.HIGH,
                                file=file_info.filename,
                                start_line=int(func.start_line),
                                end_line=int(func.end_line),
                                message=(
                                    f"High cyclomatic complexity ({func.cyclomatic_complexity}) "
                                    f"in {func.name}"
                                ),
                                source_tool_severity=str(func.cyclomatic_complexity),
                                normalized_type="complexity:ccn",
                                recommendation="Refactor into smaller functions to reduce complexity.",
                            )
                        )
            raw_path.write_text(json.dumps(rows, indent=2), encoding="utf-8")
            return AnalyzerResult(
                tool=self.name,
                status=ToolStatus.SUCCESS,
                version=self.version(),
                findings=findings,
                raw_path=str(raw_path),
                duration_seconds=time.monotonic() - started,
            )
        except Exception as exc:  # noqa: BLE001
            return AnalyzerResult(
                tool=self.name,
                status=ToolStatus.FAILED,
                version=self.version(),
                message=str(exc)[:500],
                duration_seconds=time.monotonic() - started,
            )
