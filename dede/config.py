"""Configuration loading with CLI > env > yaml > defaults precedence."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_EXCLUDE_DIRS = [
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "coverage",
    ".next",
    ".nuxt",
    "target",
    "bin",
    "obj",
    ".venv",
    ".venv-backup.*",
    "venv",
    "__pycache__",
    ".idea",
    ".vscode",
    ".cache",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".nox",
    ".hypothesis",
]


class ScanConfig(BaseModel):
    respect_gitignore: bool = False
    max_file_size_mb: float = Field(default=5.0, gt=0, le=100, allow_inf_nan=False)
    max_files: int = Field(default=50_000, gt=0, le=1_000_000)
    analyzer_timeout_seconds: int = Field(default=300, gt=0, le=3600)
    snippet_context_lines: int = Field(default=10, ge=0, le=500)
    progress_interval_seconds: float = Field(default=5.0, ge=1.0, le=60.0, allow_inf_nan=False)
    exclude: list[str] = Field(default_factory=lambda: list(DEFAULT_EXCLUDE_DIRS))


class SeverityConfig(BaseModel):
    fail_on: str | None = None

    @field_validator("fail_on")
    @classmethod
    def validate_fail_on(cls, value: str | None) -> str | None:
        from dede.normalization.severity import parse_fail_on

        parse_fail_on(value)
        return value.upper() if value else None


class AIConfig(BaseModel):
    enabled: bool = True
    model: str = "qwen3-coder:30b"
    max_context: int = Field(default=32_768, ge=512, le=262_144)
    max_findings: int = Field(default=200, ge=0, le=5_000)
    # Project-wide AI vulnerability hunt (finds issues engines miss)
    hunt_enabled: bool = True
    max_hunt_findings: int = Field(default=10, ge=0, le=100)
    hunt_max_files: int = Field(default=24, gt=0, le=200)
    concurrency: int = Field(default=4, gt=0, le=16)
    ollama_host: str = "http://127.0.0.1:11434"
    device: str = "auto"
    context_lines: int = Field(default=30, ge=0, le=500)
    request_timeout_seconds: float = Field(default=120.0, gt=0, le=3600, allow_inf_nan=False)
    max_output_tokens: int = Field(default=2048, ge=128, le=32_768)
    verification_timeout_seconds: int = Field(default=60, gt=0, le=600)

    @field_validator("ollama_host")
    @classmethod
    def validate_local_ollama_host(cls, value: str) -> str:
        """Prevent project configuration from exfiltrating source to a remote LLM."""
        parsed = urlsplit(value)
        if (
            parsed.scheme != "http"
            or parsed.hostname not in {"127.0.0.1", "localhost", "::1", "ollama"}
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError(
                "ai.ollama_host must be a local HTTP endpoint (localhost, loopback, or ollama)"
            )
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("ai.ollama_host contains an invalid port") from exc
        if port is not None and not 1 <= port <= 65535:
            raise ValueError("ai.ollama_host port must be between 1 and 65535")
        return value.rstrip("/")

    @field_validator("device")
    @classmethod
    def validate_device(cls, value: str) -> str:
        normalized = value.lower()
        if normalized not in {"auto", "cpu", "cuda"}:
            raise ValueError("ai.device must be auto, cpu or cuda")
        return normalized


class ReportsConfig(BaseModel):
    formats: list[str] = Field(default_factory=lambda: ["json", "html", "pdf"])
    # Empty means "derive /tmp/<project-dir-name> at scan time"
    output: str = ""

    @field_validator("formats")
    @classmethod
    def validate_formats(cls, values: list[str]) -> list[str]:
        formats = list(dict.fromkeys(value.lower() for value in values))
        if not formats or any(value not in {"json", "html", "pdf", "sarif"} for value in formats):
            raise ValueError("Report formats must contain json, html, pdf or sarif")
        return formats




class SuppressionRule(BaseModel):
    rule: str = ""
    fingerprint: str = ""
    path: str = "**"
    reason: str = ""
    expires: str | None = None
    approved_by: str = ""

    @field_validator("expires")
    @classmethod
    def validate_expiry(cls, value: str | None) -> str | None:
        if value is None:
            return None
        from datetime import date

        try:
            date.fromisoformat(value)
        except ValueError as exc:
            raise ValueError("suppression expires must be YYYY-MM-DD") from exc
        return value


class PolicyRule(BaseModel):
    name: str
    path: str = "**"
    deny_severity: str = "CRITICAL"
    categories: list[str] = Field(default_factory=lambda: ["security", "secret"])

    @field_validator("deny_severity")
    @classmethod
    def validate_deny_severity(cls, value: str) -> str:
        value = value.upper()
        if value not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
            raise ValueError("policy deny_severity must be CRITICAL, HIGH, MEDIUM, LOW or INFO")
        return value


class PolicyConfig(BaseModel):
    enabled: bool = False
    rules: list[PolicyRule] = Field(default_factory=list)


class SemanticSourceModel(BaseModel):
    call: str
    kind: str = "untrusted"


class SemanticSinkModel(BaseModel):
    call: str
    kind: str
    cwe: str
    severity: str = "HIGH"
    argument: int = Field(default=0, ge=0, le=32)
    require_shell_true: bool = False

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, value: str) -> str:
        value = value.upper()
        if value not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
            raise ValueError("semantic sink severity is invalid")
        return value


class SemanticFlowQuery(BaseModel):
    id: str
    description: str = ""
    source: str = "*"
    sink: str = "*"
    cwe: list[str] = Field(default_factory=list)
    endpoint: str = "*"
    authentication_required: bool | None = None
    internet_exposed: bool | None = None
    min_exploitability: float = Field(default=0.0, ge=0.0, le=100.0)

    @field_validator("id")
    @classmethod
    def validate_query_id(cls, value: str) -> str:
        value = value.strip()
        if not value or not re.fullmatch(r"[A-Za-z0-9_.-]+", value):
            raise ValueError("semantic query id may contain only letters, digits, ., _ and -")
        return value


class SemanticConfig(BaseModel):
    enabled: bool = True
    max_call_depth: int = Field(default=12, ge=1, le=64)
    max_contexts: int = Field(default=10_000, ge=100, le=100_000)
    framework_models: bool = True
    endpoint_parameters_as_sources: bool = True
    builtin_flow_queries: bool = True
    sources: list[SemanticSourceModel] = Field(default_factory=list)
    sinks: list[SemanticSinkModel] = Field(default_factory=list)
    sanitizers: list[str] = Field(default_factory=list)
    queries: list[SemanticFlowQuery] = Field(default_factory=list)




class ModelPackConfig(BaseModel):
    """Offline semantic model-pack loading and signature policy."""

    enabled: bool = True
    paths: list[str] = Field(default_factory=list)
    require_signature: bool = False
    hmac_key_env: str = "DEDE_MODEL_PACK_KEY"


class SCAConfig(BaseModel):
    """Offline dependency vulnerability and source reachability analysis."""

    enabled: bool = True
    builtin_advisories: bool = True
    advisory_paths: list[str] = Field(default_factory=list)
    report_unreachable: bool = True
    require_exact_version: bool = True


class FeedbackConfig(BaseModel):
    """Local organization verdicts; never auto-suppress by default."""

    enabled: bool = True
    path: str = ""
    annotate_similar: bool = True
    auto_suppress_false_positive: bool = False


class PrecisionLabConfig(BaseModel):
    enabled: bool = True
    minimum_precision: float = Field(default=0.90, ge=0.0, le=1.0)
    minimum_recall: float = Field(default=0.75, ge=0.0, le=1.0)


class ExperimentalConfig(BaseModel):
    # Heuristic business-logic analyzers remain opt-in because their precision
    # depends on application semantics that static analysis cannot always prove.
    authorization_analysis: bool = False
    business_logic_analysis: bool = False
    agent_security: bool = True


class PerformanceConfig(BaseModel):
    persistent_index: bool = True
    profile: bool = True
    index_path: str = ""
    dependency_aware: bool = True
    semantic_cache: bool = True


class SuppressConfig(BaseModel):
    fingerprints: list[str] = Field(default_factory=list)
    rules: list[str] = Field(default_factory=list)
    entries: list[SuppressionRule] = Field(default_factory=list)


class SemgrepConfig(BaseModel):
    """Offline Semgrep ruleset selection."""

    # smart is the precision-first default; full remains available for breadth.
    profile: str = "smart"  # full | smart | custom-only
    extra_packs: list[str] = Field(default_factory=list)
    disable_packs: list[str] = Field(default_factory=list)

    @field_validator("extra_packs", "disable_packs")
    @classmethod
    def validate_pack_names(cls, values: list[str]) -> list[str]:
        normalized = list(dict.fromkeys(value.strip().lower() for value in values))
        if any(not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", value) for value in normalized):
            raise ValueError("Semgrep pack names may contain only letters, digits, _ and -")
        return normalized

    @field_validator("profile")
    @classmethod
    def validate_profile(cls, value: str) -> str:
        value = value.lower()
        if value not in {"full", "smart", "custom-only"}:
            raise ValueError("Semgrep profile must be full, smart or custom-only")
        return value


class RuffConfig(BaseModel):
    select: list[str] = Field(default_factory=lambda: ["F", "E9", "B", "S", "SIM", "ASYNC", "PERF"])

    @field_validator("select")
    @classmethod
    def validate_select(cls, values: list[str]) -> list[str]:
        if not values or any(not re.fullmatch(r"[A-Z]+[0-9]*", value) for value in values):
            raise ValueError("Ruff select must contain rule codes or prefixes")
        return list(dict.fromkeys(values))


class EngineConfig(BaseModel):
    """Native engine resource ceilings and precision/profile controls."""

    max_findings: int = Field(default=20_000, ge=1, le=100_000)
    max_findings_per_file: int = Field(default=1_000, ge=1, le=10_000)
    # Precision-first scan profile. ``smart`` is the production default.
    # strict: VERY_HIGH or independently corroborated HIGH findings only.
    # smart: suppress uncorroborated LOW and EXPERIMENTAL findings.
    # audit: include MEDIUM/LOW evidence but still suppress EXPERIMENTAL.
    # experimental: expose every finding for security research/rule tuning.
    profile: str = "smart"
    # Backward-compatible escape hatch used by existing projects/tests.
    report_low_confidence: bool = False

    @field_validator("profile")
    @classmethod
    def validate_profile(cls, value: str) -> str:
        value = value.strip().lower()
        if value not in {"strict", "smart", "audit", "experimental"}:
            raise ValueError("Engine profile must be strict, smart, audit or experimental")
        return value


class AppConfig(BaseModel):
    # Explicit offline mode disables every attempt to pull a missing model or
    # reach a remote service.  The scanner runtime is network-isolated by
    # default; this flag also makes the model-availability policy explicit.
    offline: bool = False
    scan: ScanConfig = Field(default_factory=ScanConfig)
    severity: SeverityConfig = Field(default_factory=SeverityConfig)
    ai: AIConfig = Field(default_factory=AIConfig)
    reports: ReportsConfig = Field(default_factory=ReportsConfig)
    suppress: SuppressConfig = Field(default_factory=SuppressConfig)
    semgrep: SemgrepConfig = Field(default_factory=SemgrepConfig)
    ruff: RuffConfig = Field(default_factory=RuffConfig)
    engine: EngineConfig = Field(default_factory=EngineConfig)
    policy: PolicyConfig = Field(default_factory=PolicyConfig)
    performance: PerformanceConfig = Field(default_factory=PerformanceConfig)
    semantic: SemanticConfig = Field(default_factory=SemanticConfig)
    model_packs: ModelPackConfig = Field(default_factory=ModelPackConfig)
    sca: SCAConfig = Field(default_factory=SCAConfig)
    feedback: FeedbackConfig = Field(default_factory=FeedbackConfig)
    precision_lab: PrecisionLabConfig = Field(default_factory=PrecisionLabConfig)
    experimental: ExperimentalConfig = Field(default_factory=ExperimentalConfig)
    exclude: list[str] = Field(default_factory=list)


class EnvSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="DEDE_", extra="ignore")

    model: str | None = None
    device: str | None = None
    max_file_size_mb: float | None = None
    llm_max_context: int | None = None
    ollama_host: str | None = None
    offline: bool | None = None


def sanitize_project_dirname(name: str) -> str:
    cleaned = re.sub(r"[^\w.\-]+", "_", name.strip()) or "project"
    if cleaned in {".", ".."}:
        return "project"
    return cleaned[:120]


def default_report_dir(target: Path) -> Path:
    """Use a private per-user fallback when the traditional path is occupied."""
    override = os.getenv("DEDE_PROJECT_NAME")
    if override:
        project_name = sanitize_project_dirname(override)
    else:
        project_name = sanitize_project_dirname(target.resolve().name)
    candidate = Path("/tmp") / project_name
    if candidate.is_symlink() or (candidate.exists() and candidate.stat().st_uid != os.getuid()):
        return Path("/tmp") / f"{project_name}-{os.getuid()}"
    return candidate


def find_project_config(start: Path) -> Path | None:
    for name in (".dede.yml", ".dede.yaml"):
        candidate = start / name
        if candidate.is_file():
            return candidate
    return None


def load_yaml_config(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"Configuration file not found: {path}")
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML config file: {path}") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError(f"Invalid config file: {path}")
    return data


def _env_first(*keys: str) -> str | None:
    for key in keys:
        value = os.getenv(key)
        if value:
            return value
    return None


def build_config(
    target: Path,
    *,
    cli_overrides: dict[str, Any] | None = None,
    config_path: Path | None = None,
) -> AppConfig:
    """Build configuration with precedence: CLI > env > yaml > defaults."""
    target = target.resolve()
    yaml_path = config_path or find_project_config(target)
    yaml_data = load_yaml_config(yaml_path) if yaml_path else {}

    config = AppConfig.model_validate(yaml_data if yaml_data else {})

    if "exclude" in yaml_data and isinstance(yaml_data["exclude"], list):
        merged = list(dict.fromkeys([*config.scan.exclude, *yaml_data["exclude"]]))
        config.scan.exclude = merged

    env = EnvSettings()

    # A saved preference supplies the default, but never overrides project YAML.
    from dede.llm.settings import get_preferred_model

    preferred = get_preferred_model()
    if preferred and "model" not in yaml_data.get("ai", {}):
        config.ai.model = preferred

    if env.model:
        config.ai.model = env.model
    if env.device:
        config.ai.device = env.device
    if env.max_file_size_mb is not None:
        config.scan.max_file_size_mb = env.max_file_size_mb
    if env.llm_max_context is not None:
        config.ai.max_context = env.llm_max_context
    if env.ollama_host:
        config.ai.ollama_host = env.ollama_host
    if env.offline is not None:
        config.offline = env.offline
    # Hard runtime kill-switch used by the host wrapper for --no-ai.  Unlike
    # project YAML this cannot be accidentally re-enabled later by a model preference.
    if os.getenv("DEDE_AI_DISABLED", "").strip().lower() in {"1", "true", "yes", "on"}:
        config.ai.enabled = False
        config.ai.hunt_enabled = False

    if os.getenv("ANALYZER_TIMEOUT_SECONDS"):
        config.scan.analyzer_timeout_seconds = int(os.environ["ANALYZER_TIMEOUT_SECONDS"])
    if os.getenv("MAX_FILES"):
        config.scan.max_files = int(os.environ["MAX_FILES"])
    if os.getenv("MAX_LLM_FINDINGS"):
        config.ai.max_findings = int(os.environ["MAX_LLM_FINDINGS"])
    if os.getenv("LLM_CONCURRENCY"):
        config.ai.concurrency = int(os.environ["LLM_CONCURRENCY"])

    overrides = cli_overrides or {}
    if "respect_gitignore" in overrides and overrides["respect_gitignore"] is not None:
        config.scan.respect_gitignore = bool(overrides["respect_gitignore"])
    if "max_file_size_mb" in overrides and overrides["max_file_size_mb"] is not None:
        config.scan.max_file_size_mb = float(overrides["max_file_size_mb"])
    if overrides.get("formats"):
        config.reports.formats = list(overrides["formats"])
    if overrides.get("output"):
        config.reports.output = str(overrides["output"])
    if overrides.get("no_ai"):
        config.ai.enabled = False
    if "offline" in overrides and overrides["offline"] is not None:
        config.offline = bool(overrides["offline"])
    if "ai_hunt" in overrides and overrides["ai_hunt"] is not None:
        config.ai.hunt_enabled = bool(overrides["ai_hunt"])
    if overrides.get("fail_on"):
        config.severity.fail_on = str(overrides["fail_on"]).upper()
    if overrides.get("exclude"):
        config.scan.exclude = list(dict.fromkeys([*config.scan.exclude, *overrides["exclude"]]))
    if overrides.get("model"):
        config.ai.model = str(overrides["model"])
    if overrides.get("security_profile"):
        config.engine.profile = str(overrides["security_profile"]).lower()
    if "ai_enabled" in overrides and overrides["ai_enabled"] is not None:
        config.ai.enabled = bool(overrides["ai_enabled"])

    # Always default reports to /tmp/<project-dir-name> unless explicitly set
    if not config.reports.output:
        config.reports.output = str(default_report_dir(target))

    # Environment and CLI assignments must satisfy the same rules as YAML.
    return AppConfig.model_validate(config.model_dump())
