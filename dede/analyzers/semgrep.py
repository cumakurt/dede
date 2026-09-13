"""Semgrep Community Edition analyzer (offline vendored rules only)."""

from __future__ import annotations

import json
import os
import time
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory

from dede.analyzers.base import Analyzer
from dede.analyzers.ruleset import (
    append_config_args,
    default_rules_dir,
    prepare_project_configs,
    resolve_semgrep_configs,
)
from dede.analyzers.targets import run_json_targets
from dede.config import AppConfig
from dede.models import (
    AnalyzerResult,
    Category,
    Confidence,
    DataflowStep,
    Finding,
    ProjectContext,
    ToolStatus,
)
from dede.normalization.severity import map_semgrep_severity
from dede.utils.process import run_command, which
from dede.utils.redact import redact_text

# Re-export for CLI / doctor imports
__all__ = ["SemgrepAnalyzer", "default_rules_dir", "resolve_semgrep_configs"]


class SemgrepAnalyzer(Analyzer):
    name = "semgrep"

    def __init__(self, *, ignore_suppressions: bool = False) -> None:
        self.ignore_suppressions = ignore_suppressions

    def supports(self, project: ProjectContext) -> bool:
        return bool(project.files)

    def version(self) -> str:
        with _offline_environment() as env:
            result = run_command(
                ["semgrep", "--version", "--disable-version-check"], timeout=30, env=env
            )
        if result.returncode != 0:
            return "unavailable"
        text = (result.stdout or result.stderr or "").strip()
        if text:
            return text.splitlines()[0]
        return "unavailable"

    def analyze(
        self,
        project: ProjectContext,
        config: AppConfig,
        raw_dir: Path,
    ) -> AnalyzerResult:
        started = time.monotonic()
        if which("semgrep") is None:
            # Not an incomplete scan: Semgrep is an optional host dependency
            # (bundled in the Docker image); dede-engine still covers the run.
            return AnalyzerResult(
                tool=self.name,
                status=ToolStatus.SKIPPED_OFFLINE_DEPENDENCY,
                version=self.version(),
                message="semgrep not installed on host (bundled in Docker image)",
                duration_seconds=time.monotonic() - started,
            )

        rules_dir = default_rules_dir()
        configs = resolve_semgrep_configs(project, config, rules_dir=rules_dir)
        if not configs:
            return AnalyzerResult(
                tool=self.name,
                status=ToolStatus.FAILED,
                version=self.version(),
                message=f"Semgrep rules not found under {rules_dir}",
                duration_seconds=time.monotonic() - started,
            )

        raw_path = raw_dir / "semgrep.json"
        args = [
            "semgrep",
            "scan",
            "--json",
            "--quiet",
            "--no-rewrite-rule-ids",
            "--disable-version-check",
            "--metrics",
            "off",
            "--timeout",
            str(max(30, config.scan.analyzer_timeout_seconds // 2)),
            "--max-target-bytes",
            str(int(config.scan.max_file_size_mb * 1024 * 1024)),
        ]
        if self.ignore_suppressions:
            args.append("--disable-nosem")
        if not config.scan.respect_gitignore:
            args.append("--no-git-ignore")
        with _offline_environment() as env:
            configs = prepare_project_configs(
                configs, project, Path(env["SEMGREP_SETTINGS_FILE"]).parent
            )
            if not configs:
                return AnalyzerResult(
                    tool=self.name,
                    status=ToolStatus.NOT_APPLICABLE,
                    version=self.version(),
                    message="No selected rules apply to the discovered languages",
                    duration_seconds=time.monotonic() - started,
                )
            append_config_args(args, configs)
            result = run_json_targets(
                args,
                project.files,
                key="results",
                timeout=config.scan.analyzer_timeout_seconds,
                cwd=project.root,
                env=env,
                runner=run_command,
            )
            # semgrep-core intermittently fails to start (io_uring allocation
            # under memory pressure); instances linger briefly in the kernel.
            # A short backoff with bounded retries turns the flake into a delay.
            for retry in range(2):
                if not _is_transient_core_failure(result):
                    break
                time.sleep(0.5 * (retry + 1))
                result = run_json_targets(
                    args,
                    project.files,
                    key="results",
                    timeout=config.scan.analyzer_timeout_seconds,
                    cwd=project.root,
                    env=env,
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
                message=f"Invalid Semgrep JSON: {result.stderr[:500]}",
                raw_path=str(raw_path),
                duration_seconds=time.monotonic() - started,
            )

        for item in payload.get("results", []):
            extra = item.get("extra", {})
            metadata = extra.get("metadata", {}) or {}
            cwe = metadata.get("cwe") or []
            if isinstance(cwe, str):
                cwe = [cwe]
            owasp = metadata.get("owasp") or []
            if isinstance(owasp, str):
                owasp = [owasp]
            path = item.get("path", "")
            start = item.get("start", {})
            end = item.get("end", {})
            message = redact_text(extra.get("message") or item.get("check_id", ""))
            severity = map_semgrep_severity(str(extra.get("severity", "INFO")))
            findings.append(
                Finding(
                    tool=self.name,
                    rule_id=item.get("check_id", "unknown"),
                    category=Category.SECURITY,
                    severity=severity,
                    confidence=_confidence(metadata.get("confidence")),
                    cwe=[str(c) for c in cwe],
                    owasp=[str(o) for o in owasp],
                    standards=_standards(metadata.get("standards")),
                    file=path,
                    start_line=int(start.get("line", 1)),
                    start_column=int(start.get("col", 0)),
                    end_line=int(end.get("line", start.get("line", 1))),
                    end_column=int(end.get("col", 0)),
                    message=message,
                    code_snippet=redact_text(extra.get("lines") or "")
                    if extra.get("lines") != "requires login"
                    else "",
                    recommendation=redact_text(str(metadata.get("recommendation") or "")),
                    analysis_kind=(
                        str(metadata.get("analysis"))
                        if metadata.get("analysis") in {"taint", "regex"}
                        else "pattern"
                    ),
                    dataflow=_parse_dataflow(extra.get("dataflow_trace"), Path(project.root)),
                    source_tool_severity=str(extra.get("severity", "")),
                    normalized_type=item.get("check_id", "semgrep"),
                    references=list(metadata.get("references") or [])
                    if isinstance(metadata.get("references"), list)
                    else [],
                )
            )

        status = ToolStatus.SUCCESS
        if result.timed_out or result.returncode not in (0, 1):
            status = ToolStatus.FAILED

        engine_errors = payload.get("errors") or []
        if engine_errors:
            status = ToolStatus.FAILED
        config_note = f"{len(configs)} configs ({config.semgrep.profile})"
        if engine_errors:
            config_note += f"; incomplete coverage: {len(engine_errors)} engine error(s)"
        fail_msg = redact_text(result.stderr.strip())[-500:] if status == ToolStatus.FAILED else ""
        return AnalyzerResult(
            tool=self.name,
            status=status,
            version=self.version(),
            message=fail_msg or config_note,
            findings=findings,
            raw_path=str(raw_path),
            duration_seconds=time.monotonic() - started,
        )


def _is_transient_core_failure(result: object) -> bool:
    """Detect flaky semgrep-core startup crashes worth one retry."""
    try:
        payload = json.loads(getattr(result, "stdout", "") or "{}")
    except json.JSONDecodeError:
        return False
    errors = payload.get("errors") if isinstance(payload, dict) else None
    if not errors:
        return False
    text = " ".join(str(error.get("message", "")) for error in errors if isinstance(error, dict))
    return "io_uring_queue_init" in text or "Cannot allocate memory" in text


@contextmanager
def _offline_environment():
    # Semgrep otherwise writes logs/settings under the read-only auditor home.
    with TemporaryDirectory(prefix="dede-semgrep-") as temporary:
        yield {
            **os.environ,
            "SEMGREP_SEND_METRICS": "off",
            "SEMGREP_ENABLE_VERSION_CHECK": "0",
            "SEMGREP_USER_AGENT_APPEND": "dede-offline",
            "SEMGREP_SETTINGS_FILE": str(Path(temporary) / "settings.yml"),
            "SEMGREP_LOG_FILE": os.devnull,
            # semgrep-core 1.65+ uses OCaml Eio with io_uring; ring allocation
            # fails intermittently under memlock pressure ("Cannot allocate
            # memory io_uring_queue_init"). The posix backend avoids io_uring.
            "EIO_URING": "posix",
        }


def _confidence(value: object) -> Confidence:
    try:
        return Confidence(str(value).upper())
    except ValueError:
        return Confidence.MEDIUM


def _standards(value: object) -> dict[str, list[str]]:
    """Accept explicit rule mappings without inventing compliance evidence."""
    if not isinstance(value, dict):
        return {}
    return {
        str(name): list(dict.fromkeys(item for item in controls if isinstance(item, str) and item))
        for name, controls in value.items()
        if isinstance(controls, list) and controls
    }


def _parse_dataflow(trace: object, root: Path) -> list[DataflowStep]:
    """Keep only engine-provided local trace locations; never infer missing steps."""
    if not isinstance(trace, dict):
        return []
    steps: list[DataflowStep] = []

    def add(kind: str, location: object, content: object) -> None:
        if not isinstance(location, dict):
            return
        try:
            file = (root / location["path"]).resolve().relative_to(root.resolve()).as_posix()
            start = int(location["start"]["line"])
            end = int(location["end"]["line"])
            if start < 1 or end < start:
                return
        except (KeyError, TypeError, ValueError, OSError, RuntimeError):
            return
        steps.append(
            DataflowStep(
                kind=kind,
                file=file,
                start_line=start,
                end_line=end,
                content=redact_text(str(content or ""))[:500],
            )
        )

    def add_endpoint(kind: str, endpoint: object) -> None:
        if (
            isinstance(endpoint, list)
            and len(endpoint) == 2
            and endpoint[0] == "CliLoc"
            and isinstance(endpoint[1], list)
            and len(endpoint[1]) == 2
        ):
            add(kind, endpoint[1][0], endpoint[1][1])

    add_endpoint("source", trace.get("taint_source"))
    intermediates = trace.get("intermediate_vars")
    if isinstance(intermediates, list):
        for item in intermediates[:50]:
            if isinstance(item, dict):
                add("propagation", item.get("location"), item.get("content"))
    add_endpoint("sink", trace.get("taint_sink"))
    return steps
