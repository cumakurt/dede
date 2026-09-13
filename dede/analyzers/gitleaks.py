"""Gitleaks offline secret scanner."""

from __future__ import annotations

import json
import time
import hashlib
import os
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
from dede.utils.redact import mask_secret, redact_snippet_for_secret_finding, redact_text


class GitleaksAnalyzer(Analyzer):
    name = "gitleaks"

    def supports(self, project: ProjectContext) -> bool:
        return bool(project.files)

    def version(self) -> str:
        result = run_command(["gitleaks", "version"], timeout=30)
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
        if which("gitleaks") is None:
            return AnalyzerResult(
                tool=self.name,
                status=ToolStatus.SKIPPED_OFFLINE_DEPENDENCY,
                version="unavailable",
                message="gitleaks binary not found — install gitleaks for secret scanning",
                duration_seconds=time.monotonic() - started,
            )

        raw_path = raw_dir / "gitleaks.json"
        # A failed invocation must never reuse findings from an earlier scan.
        raw_path.write_text("[]", encoding="utf-8")
        args = [
            "gitleaks",
            "dir",
            project.root,
            "--no-banner",
            "--redact=100",
            "--report-format",
            "json",
            "--report-path",
            str(raw_path),
            "--exit-code",
            "0",
        ]
        result = run_command(args, timeout=config.scan.analyzer_timeout_seconds)

        findings: list[Finding] = []
        payload: list = []
        parse_error = ""
        if raw_path.is_file():
            try:
                payload = json.loads(raw_path.read_text(encoding="utf-8") or "[]")
            except (OSError, ValueError):
                parse_error = "Invalid Gitleaks JSON report"
                payload = []
        if not isinstance(payload, list) or any(not isinstance(item, dict) for item in payload):
            parse_error = "Invalid Gitleaks JSON report"
            payload = []

        cluster_key = os.urandom(32)
        clustered: list[tuple[Finding, str]] = []
        for item in payload:
            secret = str(item.get("Secret") or item.get("Match") or "")
            redacted = mask_secret(secret) if secret else "***REDACTED***"
            file_path = str(item.get("File") or "")
            line = int(item.get("StartLine") or item.get("Line") or 1)
            rule = str(item.get("RuleID") or item.get("Description") or "secret")
            finding = Finding(
                    tool=self.name,
                    rule_id=rule,
                    category=Category.SECRET,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    cwe=["CWE-798"],
                    owasp=["A07:2021"],
                    file=file_path,
                    start_line=line,
                    end_line=int(item.get("EndLine") or line),
                    message=redact_text(f"Potential secret detected ({rule}): {redacted}"),
                    code_snippet=redact_snippet_for_secret_finding(
                        str(item.get("Match") or redacted)
                    ),
                    source_tool_severity="critical",
                    normalized_type=f"secret:{rule}",
                    recommendation="Remove the secret from source control and rotate credentials.",
                )
            findings.append(finding)
            if secret:
                cluster = hashlib.blake2b(secret.encode("utf-8", errors="replace"), key=cluster_key, digest_size=16).hexdigest()
                clustered.append((finding, cluster))

        # Correlate repeated credentials in-memory without persisting the raw
        # secret or a stable cross-scan hash that could aid offline guessing.
        cluster_locations: dict[str, list[str]] = {}
        for finding, cluster in clustered:
            cluster_locations.setdefault(cluster, []).append(f"{finding.file}:{finding.start_line}")
        for finding, cluster in clustered:
            locations = cluster_locations.get(cluster, [])
            finding.secret_occurrence_count = len(locations)
            finding.secret_related_locations = locations[:20]

        status = ToolStatus.SUCCESS
        if result.timed_out or result.returncode != 0 or parse_error:
            status = ToolStatus.FAILED

        return AnalyzerResult(
            tool=self.name,
            status=status,
            version=self.version(),
            message=(
                parse_error
                or redact_text(result.stderr.strip())[:500]
                or f"Gitleaks exited with code {result.returncode}"
            )
            if status == ToolStatus.FAILED
            else "",
            findings=findings,
            raw_path=str(raw_path),
            duration_seconds=time.monotonic() - started,
        )
