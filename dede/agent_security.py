"""High-precision security checks for AI-agent / MCP configuration.

Only explicit dangerous configuration is reported; Dede does not infer intent
from natural-language prompts. This keeps the feature useful without turning
agent-security scanning into a speculative warning generator.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from dede.analyzers.base import Analyzer
from dede.config import AppConfig
from dede.models import AnalyzerResult, Category, Confidence, Evidence, Finding, Precision, ProjectContext, Severity, ToolStatus
from dede.utils.hashes import sha256_text


_SUSPICIOUS_NAMES = {"mcp.json", "mcp_config.json", "claude_desktop_config.json", "agent.json", "agents.json", "settings.json"}


def _walk(value: Any, path: tuple[str, ...] = ()):  # type: ignore[no-untyped-def]
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _walk(child, (*path, str(key)))
    elif isinstance(value, list):
        for idx, child in enumerate(value):
            yield from _walk(child, (*path, str(idx)))
    else:
        yield path, value


class AgentSecurityAnalyzer(Analyzer):
    name = "dede-agent-security"
    def supports(self, project: ProjectContext) -> bool:
        return any(Path(f).suffix.lower() == ".json" and (Path(f).name.lower() in _SUSPICIOUS_NAMES or any(x in Path(f).as_posix().lower() for x in ("/.cursor/", "/.claude/", "/mcp/", "/agent"))) for f in project.files)
    def version(self) -> str: return "1.0.0"
    def analyze(self, project: ProjectContext, config: AppConfig, raw_dir: Path) -> AnalyzerResult:
        started = time.perf_counter()
        if not config.experimental.agent_security:
            return AnalyzerResult(tool=self.name, status=ToolStatus.SKIPPED, version=self.version(), message="agent security disabled")
        root = Path(project.root).resolve()
        findings: list[Finding] = []
        checked = 0
        for value in project.files:
            path = Path(value)
            relish = path.as_posix().lower()
            if path.suffix.lower() != ".json" or not (path.name.lower() in _SUSPICIOUS_NAMES or any(x in relish for x in ("/.cursor/", "/.claude/", "/mcp/", "/agent"))):
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                rel = path.resolve().relative_to(root).as_posix()
            except (OSError, json.JSONDecodeError, ValueError):
                continue
            checked += 1
            for keys, leaf in _walk(data):
                key = keys[-1].lower() if keys else ""
                danger = ""
                severity = Severity.MEDIUM
                if key in {"dangerouslydisablesandbox", "allowshell", "unsafemode"} and leaf is True:
                    danger = f"{'.'.join(keys)} explicitly enables an unsafe agent capability"
                    severity = Severity.HIGH
                elif key == "sandbox" and leaf is False:
                    danger = f"{'.'.join(keys)} explicitly disables the agent sandbox"
                    severity = Severity.HIGH
                elif key in {"autoapprove", "alwaysallow", "allowedtools"} and isinstance(leaf, str) and leaf.strip().lower() in {"*", "all"}:
                    danger = f"{'.'.join(keys)} grants wildcard tool approval"
                    severity = Severity.HIGH
                if not danger:
                    continue
                identity = sha256_text(f"agent|{rel}|{'.'.join(keys)}|{leaf}")
                findings.append(Finding(
                    tool=self.name, rule_id="dede.agent.explicit-dangerous-permission",
                    category=Category.SECURITY, severity=severity, confidence=Confidence.HIGH,
                    confidence_score=0.99, precision=Precision.VERY_HIGH, cwe=["CWE-284"],
                    file=rel, start_line=1, end_line=1, message=danger,
                    recommendation="Replace wildcard/unsafe agent permissions with explicit least-privilege tool grants and sandboxing.",
                    normalized_type="agent-permission", analysis_kind="agent-security",
                    semantic_fingerprint=identity, source_kind="agent-configuration", sink_kind="privileged-agent-tooling",
                    reachable=True, exploitability_score=80.0,
                    evidence=[Evidence(kind="agent-config", value=f"{'.'.join(keys)}={leaf!r}", confidence=1.0)],
                ))
        return AnalyzerResult(tool=self.name, status=ToolStatus.SUCCESS, version=self.version(), findings=findings, duration_seconds=time.perf_counter()-started, coverage={"agent_config_files": checked, "explicit_risks": len(findings)})
