"""Shared enums and finding / scan result models."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Precision(str, Enum):
    VERY_HIGH = "VERY_HIGH"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    EXPERIMENTAL = "EXPERIMENTAL"


class Category(str, Enum):
    SECURITY = "security"
    QUALITY = "quality"
    BUG = "bug"
    SECRET = "secret"
    COMPLEXITY = "complexity"
    MAINTAINABILITY = "maintainability"
    DUPLICATE = "duplicate"
    CODE_SMELL = "code_smell"
    OTHER = "other"


class ToolStatus(str, Enum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    SKIPPED_OFFLINE_DEPENDENCY = "SKIPPED_OFFLINE_DEPENDENCY"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class BaselineStatus(str, Enum):
    NEW = "NEW"
    EXISTING = "EXISTING"
    RESOLVED = "RESOLVED"
    NONE = "NONE"


class AnalyzerResult(BaseModel):
    tool: str
    status: ToolStatus
    version: str = ""
    message: str = ""
    findings: list[Finding] = Field(default_factory=list)
    raw_path: str | None = None
    duration_seconds: float = 0.0
    coverage: dict[str, Any] = Field(default_factory=dict)
    # Internal dependency graph used by the persistent incremental index. It is
    # excluded from serialized scan results to avoid bloating public reports.
    dependency_graph: dict[str, list[str]] = Field(default_factory=dict, exclude=True)


class DataflowStep(BaseModel):
    kind: str
    file: str
    start_line: int
    end_line: int
    content: str = ""
    symbol: str = ""


class Evidence(BaseModel):
    kind: str
    value: str
    source: str = "static"
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)


class Finding(BaseModel):
    id: str = ""
    fingerprint: str = ""
    tool: str
    rule_id: str
    category: Category = Category.OTHER
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.MEDIUM
    cwe: list[str] = Field(default_factory=list)
    owasp: list[str] = Field(default_factory=list)
    standards: dict[str, list[str]] = Field(default_factory=dict)
    file: str
    start_line: int = 1
    start_column: int = 0
    end_line: int = 1
    end_column: int = 0
    message: str = ""
    code_snippet: str = ""
    explanation: str = ""
    impact: str = ""
    attack_scenario: str = ""
    recommendation: str = ""
    secure_example: str = ""
    references: list[str] = Field(default_factory=list)
    ai_generated: bool = False
    source_tool_severity: str = ""
    detected_by: list[str] = Field(default_factory=list)
    suppressed: bool = False
    suppress_reason: str = ""
    baseline_status: BaselineStatus = BaselineStatus.NONE
    # AI enrichment fields
    summary: str = ""
    technical_explanation: str = ""
    exploitability: str = ""
    false_positive_probability: str = ""
    recommended_fix: str = ""
    secure_code_example: str = ""
    ai_confidence: float | None = None
    ai_verdict: str = ""
    ai_rationale: str = ""
    ai_assumptions: str = ""
    ai_verification: str = ""
    ai_impact: str = ""
    ai_model: str = ""
    ai_model_digest: str = ""
    ai_status: str = ""
    ai_source_digest: str = ""
    ai_validation_status: str = "UNVERIFIED"
    ai_validation_notes: list[str] = Field(default_factory=list)
    ai_fix_status: str = "UNVERIFIED"
    ai_fix_notes: list[str] = Field(default_factory=list)
    normalized_type: str = ""
    analysis_kind: str = ""
    dataflow: list[DataflowStep] = Field(default_factory=list)
    # Semantic-analysis and lifecycle metadata. These fields are optional so
    # reports produced by older analyzers remain valid.
    semantic_fingerprint: str = ""
    symbol: str = ""
    function: str = ""
    class_name: str = ""
    module: str = ""
    package: str = ""
    source_kind: str = ""
    sink_kind: str = ""
    sanitizers: list[str] = Field(default_factory=list)
    call_path: list[str] = Field(default_factory=list)
    control_flow: list[str] = Field(default_factory=list)
    reachable: bool | None = None
    exploitability_score: float | None = Field(default=None, ge=0.0, le=100.0)
    confidence_score: float | None = Field(default=None, ge=0.0, le=1.0)
    precision: Precision = Precision.HIGH
    rule_version: str = ""
    engine_version: str = ""
    evidence: list[Evidence] = Field(default_factory=list)
    correlation_score: float = Field(default=0.0, ge=0.0, le=1.0)
    ast_fingerprint: str = ""
    endpoint: str = ""
    http_method: str = ""
    authentication_required: bool | None = None
    internet_exposed: bool | None = None
    attack_surface: list[str] = Field(default_factory=list)
    attack_path: list[str] = Field(default_factory=list)
    query_matches: list[str] = Field(default_factory=list)
    lifecycle_status: str = ""
    feedback_verdict: str = ""
    feedback_reason: str = ""
    feedback_similarity: float = Field(default=0.0, ge=0.0, le=1.0)
    feedback_id: str = ""
    secret_occurrence_count: int = Field(default=0, ge=0)
    secret_related_locations: list[str] = Field(default_factory=list)

    def model_post_init(self, __context: Any) -> None:
        if not self.detected_by:
            self.detected_by = [self.tool]


class LanguageStats(BaseModel):
    languages: dict[str, float] = Field(default_factory=dict)
    frameworks: list[str] = Field(default_factory=list)
    project_types: list[str] = Field(default_factory=list)
    files_scanned: int = 0
    lines_scanned: int = 0


class RiskScore(BaseModel):
    score: int
    category: str
    algorithm: str
    raw_weighted: float
    weights: dict[str, int]


class ScanMetadata(BaseModel):
    scanner_version: str
    scan_started: datetime
    scan_finished: datetime | None = None
    duration_seconds: float = 0.0
    offline_mode: bool = True
    ai_enabled: bool = False
    ai_status: str = ""
    ai_review_counts: dict[str, int] = Field(default_factory=dict)
    ai_validation_counts: dict[str, int] = Field(default_factory=dict)
    ai_fix_counts: dict[str, int] = Field(default_factory=dict)
    model: str = ""
    model_digest: str = ""
    analyzers: dict[str, dict[str, Any]] = Field(default_factory=dict)
    ruleset_versions: dict[str, str] = Field(default_factory=dict)
    files_scanned: int = 0
    lines_scanned: int = 0
    target: str = ""
    fail_on: str | None = None
    security_profile: str = "smart"
    repository: str = ""
    branch: str = ""
    commit: str = ""
    scan_manifest: dict[str, Any] = Field(default_factory=dict)
    profile: dict[str, float] = Field(default_factory=dict)
    incremental: dict[str, Any] = Field(default_factory=dict)
    policy_violations: list[dict[str, str]] = Field(default_factory=list)
    lifecycle: dict[str, Any] = Field(default_factory=dict)
    feedback: dict[str, Any] = Field(default_factory=dict)


class ScanResult(BaseModel):
    metadata: ScanMetadata
    languages: LanguageStats
    findings: list[Finding] = Field(default_factory=list)
    suppressed_findings: list[Finding] = Field(default_factory=list)
    resolved_findings: list[Finding] = Field(default_factory=list)
    tool_statuses: list[AnalyzerResult] = Field(default_factory=list)
    risk: RiskScore | None = None
    maintainability_rating: str = "N/A"
    maintainability_debt_minutes: int = 0
    maintainability_debt_ratio: float = 0.0
    severity_counts: dict[str, int] = Field(default_factory=dict)

    def compute_severity_counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for finding in self.findings:
            if not finding.suppressed:
                counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
        self.severity_counts = counts
        return counts


class ProjectContext(BaseModel):
    root: str
    files: list[str] = Field(default_factory=list)
    languages: LanguageStats = Field(default_factory=LanguageStats)
    has_python: bool = False
    has_javascript: bool = False
    has_typescript: bool = False
    has_go: bool = False
    has_java: bool = False
    has_rust: bool = False
    has_docker: bool = False
    has_csharp: bool = False
    has_php: bool = False
    has_ruby: bool = False
    changed_files: list[str] = Field(default_factory=list)
    affected_files: list[str] = Field(default_factory=list)


def utc_now() -> datetime:
    return datetime.now(UTC)
