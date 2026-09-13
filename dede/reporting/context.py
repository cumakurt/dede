"""Shared report template context for HTML and PDF."""

from __future__ import annotations

import base64
import hashlib
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from dede.models import (
    Category,
    Confidence,
    Finding,
    ScanResult,
    Severity,
    ToolStatus,
)
from dede.normalization.maintainability import maintainability_breakdown
from dede.normalization.risk import WEIGHTS
from dede.reporting.analytics import build_operational_metrics
from dede.reporting.standards import standards_assessment

_ASSETS_DIR = Path(__file__).resolve().parent / "assets"
_LOGO_FILE = _ASSETS_DIR / "dede.png"
_ROOT_LOGO = Path(__file__).resolve().parents[2] / "dede.png"

DEVELOPER_NAME = "Cuma KURT"
DEVELOPER_EMAIL = "cumakurt@gmail.com"
DEVELOPER_LINKEDIN = "https://www.linkedin.com/in/cuma-kurt-34414917/"
DEVELOPER_GITHUB = "https://github.com/cumakurt/dede"

SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

CONFIDENCE_ORDER = {
    Confidence.HIGH: 0,
    Confidence.MEDIUM: 1,
    Confidence.LOW: 2,
}

# Map CWE identifiers to AppSec report categories (honest, coarse).
_CWE_SECURITY_CLASS: dict[str, str] = {
    "78": "Injection",
    "89": "Injection",
    "77": "Injection",
    "90": "Injection",
    "94": "Injection",
    "95": "Injection",
    "79": "Injection",
    "80": "Injection",
    "22": "Path Traversal",
    "23": "Path Traversal",
    "36": "Path Traversal",
    "73": "Path Traversal",
    "798": "Secrets",
    "259": "Secrets",
    "321": "Secrets",
    "256": "Secrets",
    "287": "Authentication",
    "306": "Authentication",
    "307": "Authentication",
    "384": "Authentication",
    "862": "Authorization",
    "863": "Authorization",
    "284": "Authorization",
    "285": "Authorization",
    "327": "Cryptography",
    "328": "Cryptography",
    "326": "Cryptography",
    "330": "Cryptography",
    "338": "Cryptography",
    "502": "Deserialization",
    "200": "Data Exposure",
    "209": "Data Exposure",
    "312": "Data Exposure",
    "359": "Data Exposure",
    "20": "Input Validation",
    "116": "Input Validation",
    "400": "Resource Management",
    "770": "Resource Management",
    "918": "Configuration",
    "611": "Configuration",
    "776": "Configuration",
}

_LINE_PREFIX_RE = re.compile(r"^(\d+)([:|\s].*)$")
_CWE_NUM_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)


def resolve_logo_path() -> Path | None:
    """Prefer packaged report dede.png; fall back to repository root copy."""
    if _LOGO_FILE.is_file():
        return _LOGO_FILE
    if _ROOT_LOGO.is_file():
        return _ROOT_LOGO
    return None


def logo_assets() -> dict[str, str | bool]:
    path = resolve_logo_path()
    if path is None:
        return {"logo_path": "", "logo_src": "", "logo_data_uri": "", "has_logo": False}
    raw = path.read_bytes()
    data_uri = "data:image/png;base64," + base64.b64encode(raw).decode("ascii")
    # Relative to reporting/ for WeasyPrint base_url
    rel = f"assets/{path.name}" if path.parent == _ASSETS_DIR else path.as_uri()
    return {
        "logo_path": str(path),
        "logo_src": rel,
        "logo_data_uri": data_uri,
        "has_logo": True,
    }


def _risk_card(finding: Finding | None) -> dict[str, str] | None:
    if finding is None:
        return None
    return {
        "id": finding.id,
        "title": finding_title(finding),
        "title_origin": "AI" if finding.summary else "Static analysis",
        "severity": finding.severity.value,
        "class": security_class_for_finding(finding),
        "file": f"{finding.file}:{finding.start_line}",
        "summary": _clip(finding.message or "", 160),
    }


def _release_decision(*, critical: int, high: int, top_ids: list[str]) -> str:
    if critical > 0:
        ids = ", ".join(top_ids[:3]) if top_ids else "Critical findings"
        return (
            f"Block release until Critical findings are remediated and verified"
            f"{f' (priority: {ids})' if top_ids else ''}."
        )
    if high > 0:
        return (
            "Do not treat this as production-ready until High findings are remediated "
            "or explicitly accepted with compensating controls."
        )
    if high == 0 and critical == 0:
        return (
            "No Critical or High findings were reported; proceed with Medium/Low remediation "
            "on the planned backlog and re-scan before major releases."
        )
    return "Review analyzer coverage and findings before making a release decision."


def _coverage_pct(result: ScanResult) -> int | None:
    tools = result.tool_statuses
    if not tools:
        return None
    applicable = [t for t in tools if t.status != ToolStatus.NOT_APPLICABLE]
    if not applicable:
        return None
    ok = sum(1 for t in applicable if t.status == ToolStatus.SUCCESS)
    return int(round(100 * ok / len(applicable)))


def _trend_narrative(
    *,
    total: int,
    hotspot_folders: list[dict[str, Any]],
    critical_high: int,
) -> str:
    if total == 0:
        return "No findings were reported by the executed analyzers for this scan."
    if hotspot_folders and critical_high > 0:
        top = hotspot_folders[0]
        share = int(round(100 * top["count"] / total)) if total else 0
        return (
            f"Risk is concentrated: {top['path']} accounts for {top['count']} finding(s) "
            f"({share}% of the total). Targeted remediation in concentrated modules is more "
            f"efficient than broad refactoring."
        )
    return (
        f"The scan reported {total} finding(s), including {critical_high} Critical/High. "
        f"Prioritize by severity and confidence before broad cleanup work."
    )


def security_score_label(score: int) -> str:
    if score <= 39:
        return "Critical Risk"
    if score <= 59:
        return "High Risk"
    if score <= 74:
        return "Elevated Risk"
    if score <= 89:
        return "Moderate / Good"
    return "Strong"


def _cwe_number(cwe: str) -> str | None:
    match = _CWE_NUM_RE.search(cwe)
    if match:
        return match.group(1)
    if cwe.isdigit():
        return cwe
    return None


def security_class_for_finding(finding: Finding) -> str:
    if finding.category == Category.SECRET:
        return "Secrets"
    if finding.category == Category.COMPLEXITY:
        return "Resource Management"
    if finding.category == Category.QUALITY:
        return "Configuration"
    if finding.category == Category.BUG:
        return "Business Logic"
    if finding.category == Category.MAINTAINABILITY:
        return "Configuration"
    for cwe in finding.cwe:
        num = _cwe_number(cwe)
        if num and num in _CWE_SECURITY_CLASS:
            return _CWE_SECURITY_CLASS[num]
    if finding.category == Category.SECURITY:
        return "Input Validation"
    return "Configuration"


def _ai_text(finding: Finding, field: str) -> str:
    """Retain model content regardless of verification; report its origin separately."""
    return getattr(finding, field)


def finding_display_status(finding: Finding) -> str:
    if finding.suppressed:
        return "Suppressed"
    if finding.confidence == Confidence.LOW:
        return "Potential Finding"
    if finding.baseline_status and finding.baseline_status.value not in ("NONE",):
        return finding.baseline_status.value.title()
    has_narrative = bool(
        finding.explanation
        or _ai_text(finding, "technical_explanation")
        or finding.attack_scenario
        or finding.recommendation
        or _ai_text(finding, "recommended_fix")
    )
    if not has_narrative and finding.confidence != Confidence.HIGH:
        return "Needs Review"
    if not has_narrative:
        return "Needs Review"
    return "Open"


def _collapse_redaction(text: str, *, max_run: int = 12) -> str:
    """Collapse long mask/asterisk runs that break PDF/HTML layout."""
    if not text:
        return ""
    text = re.sub(r"\*{6,}", "*" * max_run, text)
    text = re.sub(r"•{6,}", "••••", text)
    text = re.sub(r"X{8,}", "XXXXXXXX", text, flags=re.IGNORECASE)
    return text


def _clip(text: str, limit: int) -> str:
    text = _collapse_redaction((text or "").strip())
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)].rstrip() + "..."


def finding_title(finding: Finding) -> str:
    if _ai_text(finding, "summary"):
        return _clip(_ai_text(finding, "summary"), 100)
    msg = finding.message or finding.rule_id or "Finding"
    return _clip(msg, 100)


def parse_code_lines(
    snippet: str,
    vulnerable_line: int,
    *,
    max_lines: int = 18,
    max_width: int = 110,
) -> list[dict[str, Any]]:
    """Parse a code snippet into numbered lines with vulnerable highlight."""
    if not snippet:
        return []
    lines: list[dict[str, Any]] = []
    raw_lines = snippet.replace("\r\n", "\n").split("\n")
    if raw_lines and raw_lines[-1] == "":
        raw_lines = raw_lines[:-1]

    numbered = 0
    for raw in raw_lines:
        match = _LINE_PREFIX_RE.match(raw)
        if match:
            number = int(match.group(1))
            text = match.group(2)
            if text.startswith(":") or text.startswith("|"):
                text = text[1:]
            text = text.removeprefix(" ")
            numbered += 1
        else:
            number = vulnerable_line - (len(raw_lines) // 2) + len(lines)
            if number < 1:
                number = len(lines) + 1
            text = raw
        text = _collapse_redaction(text)
        if len(text) > max_width:
            text = text[: max_width - 1] + "…"
        lines.append(
            {
                "number": number,
                "text": text,
                "vulnerable": number == vulnerable_line,
            }
        )

    if numbered == 0 and vulnerable_line > 0 and lines:
        mid = min(len(lines) - 1, max(0, len(lines) // 2))
        for idx, row in enumerate(lines):
            row["vulnerable"] = idx == mid
            row["number"] = vulnerable_line - mid + idx

    if len(lines) > max_lines:
        # Prefer keeping the vulnerable line in view
        vuln_idx = next((i for i, row in enumerate(lines) if row["vulnerable"]), 0)
        start = max(0, vuln_idx - max_lines // 3)
        end = min(len(lines), start + max_lines)
        start = max(0, end - max_lines)
        lines = lines[start:end]

    return lines


def build_finding_view(finding: Finding, *, max_code_lines: int = 18) -> dict[str, Any]:
    remediation = _ai_text(finding, "recommended_fix") or finding.recommendation or ""
    technical = _ai_text(finding, "technical_explanation") or finding.explanation or ""
    why = _ai_text(finding, "exploitability") or finding.attack_scenario or ""
    secure = _ai_text(finding, "secure_code_example") or finding.secure_example or ""
    risk_text = _ai_text(finding, "summary") or ""
    if not risk_text and technical:
        risk_text = technical
    if not risk_text:
        risk_text = finding.message
    risk_text = _clip(risk_text, 420)

    status = finding_display_status(finding)
    dom_seed = finding.id or finding.semantic_fingerprint or finding.fingerprint or finding.rule_id
    dom_id = "finding-" + re.sub(r"[^A-Za-z0-9_-]+", "-", dom_seed).strip("-")[:96]
    return {
        "finding": finding,
        "dom_id": dom_id,
        "title": finding_title(finding),
        "title_origin": "AI" if finding.summary else "Static analysis",
        "risk_origin": "AI"
        if finding.summary or finding.technical_explanation
        else "Static analysis",
        "technical_origin": "AI" if finding.technical_explanation else "Static analysis",
        "why_origin": "AI" if finding.exploitability else "Static analysis",
        "impact_origin": "AI" if finding.ai_impact else "Static analysis",
        "remediation_origin": "AI" if finding.recommended_fix else "Static analysis",
        "status": status,
        "needs_review": status in ("Needs Review", "Potential Finding"),
        "security_class": security_class_for_finding(finding),
        "code_lines": parse_code_lines(
            finding.code_snippet, finding.start_line, max_lines=max_code_lines
        ),
        "secure_lines": parse_code_lines(secure, 0, max_lines=max_code_lines) if secure else [],
        "risk_text": risk_text,
        "why_text": _clip(why, 420),
        "technical_text": _clip(technical, 600),
        "impact_text": _clip(_ai_text(finding, "ai_impact") or finding.impact or "", 320),
        "remediation_text": _clip(remediation, 420),
        "secure_example": secure,
        "secure_example_is_ai": bool(finding.secure_code_example),
        "has_remediation": bool(remediation),
        "has_why": bool(why),
        "has_technical": bool(technical and technical != finding.message),
        "has_impact": bool(_ai_text(finding, "ai_impact") or finding.impact),
        "cwe_display": ", ".join(finding.cwe) if finding.cwe else "n/a",
        "owasp_display": ", ".join(finding.owasp) if finding.owasp else "n/a",
        "function_name": finding.function or finding.symbol or "",
        "attack_path": list(finding.attack_path or []),
        "dataflow_steps": list(finding.dataflow or []),
        "evidence_items": list(finding.evidence or []),
        "references": list(finding.references or []),
    }


def _sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (
            SEVERITY_ORDER.get(f.severity, 99),
            CONFIDENCE_ORDER.get(f.confidence, 99),
            f.file,
            f.start_line,
        ),
    )


def _active_findings(result: ScanResult) -> list[Finding]:
    return [f for f in result.findings if not f.suppressed]


def _cwe_distribution(findings: list[Finding]) -> list[dict[str, Any]]:
    counter: Counter[str] = Counter()
    for finding in findings:
        for cwe in finding.cwe:
            label = cwe.strip()
            if not label:
                continue
            if not label.upper().startswith("CWE-"):
                num = _cwe_number(label)
                label = f"CWE-{num}" if num else label
            counter[label] += 1
    total = sum(counter.values()) or 1
    rows = [
        {"id": cwe, "count": count, "pct": round(100 * count / total, 1)}
        for cwe, count in counter.most_common(15)
    ]
    return rows


def _owasp_distribution(findings: list[Finding]) -> list[dict[str, Any]]:
    counter: Counter[str] = Counter()
    for finding in findings:
        for item in finding.owasp:
            label = item.strip()
            if label:
                counter[label] += 1
    total = sum(counter.values()) or 1
    return [
        {"id": owasp, "count": count, "pct": round(100 * count / total, 1)}
        for owasp, count in counter.most_common(15)
    ]


def _category_distribution(findings: list[Finding]) -> list[dict[str, Any]]:
    counter: Counter[str] = Counter()
    for finding in findings:
        counter[security_class_for_finding(finding)] += 1
    total = sum(counter.values()) or 1
    return [
        {
            "name": name,
            "count": count,
            "pct": round(100 * count / total, 1),
            "bar": min(100, round(100 * count / total)),
        }
        for name, count in counter.most_common()
    ]


def _hotspots(
    findings: list[Finding], *, limit: int = 10
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    dir_weights: dict[str, float] = defaultdict(float)
    dir_counts: dict[str, int] = defaultdict(int)
    file_weights: dict[str, float] = defaultdict(float)
    file_counts: dict[str, int] = defaultdict(int)
    dir_max_sev: dict[str, int] = defaultdict(lambda: 99)

    for finding in findings:
        weight = float(WEIGHTS.get(finding.severity, 0))
        path = finding.file.replace("\\", "/")
        parts = path.split("/")
        folder = parts[0] + "/" if len(parts) > 1 else "(root)/"
        dir_weights[folder] += weight
        dir_counts[folder] += 1
        dir_max_sev[folder] = min(dir_max_sev[folder], SEVERITY_ORDER.get(finding.severity, 99))
        file_weights[path] += weight
        file_counts[path] += 1

    max_w = max(dir_weights.values()) if dir_weights else 1.0
    severity_name = {0: "CRITICAL", 1: "HIGH", 2: "MEDIUM", 3: "LOW", 4: "INFO"}

    folders: list[dict[str, Any]] = []
    for folder, weight in sorted(dir_weights.items(), key=lambda x: (-x[1], x[0]))[:limit]:
        folders.append(
            {
                "path": folder,
                "count": dir_counts[folder],
                "weight": weight,
                "bar": int(round(100 * weight / max_w)) if max_w else 0,
                "max_severity": severity_name.get(dir_max_sev[folder], "INFO"),
            }
        )

    max_fw = max(file_weights.values()) if file_weights else 1.0
    files: list[dict[str, Any]] = []
    for path, weight in sorted(file_weights.items(), key=lambda x: (-x[1], x[0]))[:limit]:
        files.append(
            {
                "path": path,
                "count": file_counts[path],
                "weight": weight,
                "bar": int(round(100 * weight / max_fw)) if max_fw else 0,
            }
        )
    return folders, files


def _remediation_groups(findings: list[Finding]) -> dict[str, list[dict[str, Any]]]:
    immediate: list[dict[str, Any]] = []
    short_term: list[dict[str, Any]] = []
    planned: list[dict[str, Any]] = []

    for finding in _sort_findings(findings):
        action = _ai_text(finding, "recommended_fix") or finding.recommendation or finding.message
        complexity = "Medium"
        if finding.category == Category.SECRET:
            complexity = "Low"
        elif finding.severity in (Severity.CRITICAL, Severity.HIGH):
            complexity = "High" if finding.confidence == Confidence.HIGH else "Medium"
        elif finding.severity in (Severity.LOW, Severity.INFO):
            complexity = "Low"

        row = {
            "id": finding.id,
            "finding": finding_title(finding),
            "title_origin": "AI" if finding.summary else "Static analysis",
            "severity": finding.severity.value,
            "priority": finding.severity.value,
            "complexity": complexity,
            "action": action,
            "action_origin": "AI" if finding.recommended_fix else "Static analysis",
            "file": finding.file,
        }

        if finding.severity == Severity.CRITICAL or (
            finding.severity == Severity.HIGH and finding.confidence == Confidence.HIGH
        ):
            immediate.append(row)
        elif finding.severity in (Severity.HIGH, Severity.MEDIUM):
            short_term.append(row)
        else:
            planned.append(row)

    return {"immediate": immediate, "short_term": short_term, "planned": planned}


def _quick_wins(findings: list[Finding]) -> list[dict[str, Any]]:
    wins: list[dict[str, Any]] = []
    for finding in _sort_findings(findings):
        action = ""
        action_origin = "Static analysis"
        if finding.category == Category.SECRET:
            action = "Remove committed credential and rotate the exposed secret."
        elif finding.rule_id in {"B105", "B106", "B107"} or any(
            _cwe_number(c) in {"798", "259"} for c in finding.cwe
        ):
            action = "Remove hard-coded credential and load secrets from a secure secret store."
        elif _ai_text(finding, "recommended_fix") or finding.recommendation:
            action_origin = "AI" if finding.recommended_fix else "Static analysis"
            # Only treat short, concrete remediation as a quick win
            text = _ai_text(finding, "recommended_fix") or finding.recommendation
            if len(text) <= 200 and finding.severity in (
                Severity.CRITICAL,
                Severity.HIGH,
                Severity.MEDIUM,
            ):
                action = text
        if not action:
            continue
        wins.append(
            {
                "id": finding.id,
                "action": action,
                "action_origin": action_origin,
                "file": f"{finding.file}:{finding.start_line}",
                "severity": finding.severity.value,
            }
        )
        if len(wins) >= 8:
            break
    return wins


def _security_strengths(result: ScanResult, findings: list[Finding]) -> list[str]:
    strengths: list[str] = []
    secret_count = sum(1 for f in findings if f.category == Category.SECRET)
    gitleaks = next((t for t in result.tool_statuses if t.tool == "gitleaks"), None)
    if gitleaks and gitleaks.status == ToolStatus.SUCCESS and secret_count == 0:
        strengths.append("No exposed credentials detected by secret scanning")

    analyzers_ok = [
        t
        for t in result.tool_statuses
        if t.status in (ToolStatus.SUCCESS, ToolStatus.NOT_APPLICABLE)
    ]
    if analyzers_ok and len(analyzers_ok) == len(result.tool_statuses) and result.tool_statuses:
        strengths.append("All applicable analyzers completed successfully")

    if result.metadata.offline_mode:
        strengths.append("Scan executed in offline mode with local deterministic analyzers")

    if not findings:
        strengths.append("No findings reported by executed analyzers")

    return strengths


def _executive_narrative(
    *,
    critical: int,
    high: int,
    medium: int,
    security_score: int | None,
    security_label: str,
    top_class: str | None,
    files_scanned: int,
) -> list[str]:
    sentences: list[str] = []
    if security_score is None:
        sentences.append(
            "A security score was not available for this analysis; review finding counts and analyzer status directly."
        )
    else:
        sentences.append(
            f"The overall security posture is assessed as {security_label} "
            f"(Security Score {security_score}/100) based on weighted finding severity."
        )

    if critical > 0:
        sentences.append(
            f"{critical} Critical finding(s) require remediation before production release."
        )
    elif high > 0:
        sentences.append(
            f"{high} High severity finding(s) should be addressed as a release gate priority."
        )
    elif medium > 0:
        sentences.append(
            f"No Critical or High findings were reported; {medium} Medium finding(s) remain for planned remediation."
        )
    else:
        sentences.append(
            "No Critical, High, or Medium findings were reported by the completed analyzers."
        )

    if top_class:
        sentences.append(f"The primary risk concentration is in the {top_class} category.")

    sentences.append(
        "Exploitation likelihood depends on deployment context; static analysis does not prove runtime exploitability."
    )
    sentences.append(
        f"Analysis covered {files_scanned} file(s); validate coverage and suppressed findings before acceptance."
    )
    return sentences[:6]


def _analysis_id(result: ScanResult) -> str:
    meta = result.metadata
    seed = "|".join(
        [
            meta.scanner_version or "",
            meta.target or "",
            meta.scan_started.isoformat() if meta.scan_started else "",
            str(meta.files_scanned),
            str(len(result.findings)),
        ]
    )
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:12].upper()
    return f"SRM-{digest}"


def _donut_segments(counts: dict[str, int]) -> list[dict[str, Any]]:
    """Build SVG donut stroke-dasharray segments for severity counts."""
    order = [
        ("CRITICAL", "#8b1e1e"),
        ("HIGH", "#e04545"),
        ("MEDIUM", "#d4a017"),
        ("LOW", "#3b82c4"),
        ("INFO", "#8a939e"),
    ]
    total = sum(counts.get(name, 0) for name, _color in order) or 1
    circumference = 2 * 3.1415926535 * 42  # r=42
    offset = 0.0
    segments = []
    for name, color in order:
        value = counts.get(name, 0)
        length = circumference * (value / total)
        segments.append(
            {
                "name": name,
                "count": value,
                "color": color,
                "dash": f"{length:.2f} {circumference - length:.2f}",
                "offset": f"{-offset:.2f}",
            }
        )
        offset += length
    return segments


def build_report_context(result: ScanResult, *, pdf: bool) -> dict[str, Any]:
    """Derived fields shared by HTML and PDF Jinja templates."""
    counts = result.severity_counts or result.compute_severity_counts()
    critical = counts.get(Severity.CRITICAL.value, 0)
    high = counts.get(Severity.HIGH.value, 0)
    medium = counts.get(Severity.MEDIUM.value, 0)
    low = counts.get(Severity.LOW.value, 0)
    info = counts.get(Severity.INFO.value, 0)
    active = _active_findings(result)
    total = len(active)

    security_score: int | None = None
    security_label = "n/a"
    overall_risk_label = "n/a"
    risk_line = "n/a"
    if result.risk:
        risk_line = f"{result.risk.score}/100 — {result.risk.category}"
        overall_risk_label = f"{result.risk.category} ({result.risk.score}/100)"
        security_score = max(0, min(100, 100 - result.risk.score))
        security_label = security_score_label(security_score)

    category_dist = _category_distribution(active)
    top_class = category_dist[0]["name"] if category_dist else None
    hotspot_folders, hotspot_files = _hotspots(active)

    top_risks = _sort_findings(active)[:10]
    max_code = 12 if pdf else 18
    # PDF: keep report printable; HTML keeps the full finding list.
    detailed_source = _sort_findings(result.findings)
    detailed_limit = 40 if pdf else len(detailed_source)
    detailed_findings = detailed_source[:detailed_limit]
    omitted_findings = max(0, len(detailed_source) - len(detailed_findings))
    top_risk_views = [build_finding_view(f, max_code_lines=max_code) for f in top_risks]
    finding_views = [build_finding_view(f, max_code_lines=max_code) for f in detailed_findings]
    secrets = [
        build_finding_view(f, max_code_lines=max_code)
        for f in active
        if f.category == Category.SECRET
    ]

    languages_list: list[dict[str, str | float]] = [
        {"name": name, "pct": pct}
        for name, pct in sorted(
            (result.languages.languages or {}).items(),
            key=lambda x: (-x[1], x[0]),
        )
    ]

    project_name = Path(result.metadata.target or "project").name or "project"
    repository = result.metadata.repository or "n/a"
    branch = result.metadata.branch or "n/a"
    commit = result.metadata.commit or "n/a"

    ai_label = "ON" if result.metadata.ai_enabled else "OFF"
    if result.metadata.ai_enabled and result.metadata.model:
        ai_label = f"ON ({result.metadata.model})"

    scan_coverage = "Partial"
    success_tools = [t for t in result.tool_statuses if t.status == ToolStatus.SUCCESS]
    failed_tools = [t for t in result.tool_statuses if t.status == ToolStatus.FAILED]
    skipped_tools = [
        t
        for t in result.tool_statuses
        if t.status in {ToolStatus.SKIPPED, ToolStatus.SKIPPED_OFFLINE_DEPENDENCY}
    ]
    if success_tools and not failed_tools and not skipped_tools:
        scan_coverage = "Complete (applicable analyzers executed)"
    elif failed_tools:
        scan_coverage = "Degraded (analyzer failures)"

    confidence_summary = "Mixed"
    if active:
        conf_counts = Counter(f.confidence for f in active)
        if conf_counts.get(Confidence.HIGH, 0) == len(active):
            confidence_summary = "HIGH"
        elif conf_counts.get(Confidence.LOW, 0) == len(active):
            confidence_summary = "LOW"
        else:
            confidence_summary = "MEDIUM"

    rules_triggered = sorted({f.rule_id for f in active if f.rule_id})
    used_tools = {
        tool.tool
        for tool in result.tool_statuses
        if tool.status == ToolStatus.SUCCESS or tool.findings
    }
    methodologies = []
    pattern_tools = sorted(used_tools & {"semgrep", "bandit", "ruff", "gosec"})
    if pattern_tools:
        methodologies.append(f"AST / pattern matching ({', '.join(pattern_tools)})")
    if any(f.analysis_kind == "taint" for f in active):
        methodologies.append(
            "Intraprocedural taint analysis (untrusted input to sensitive operations)"
        )
    for tool, description in (
        ("gitleaks", "Secret detection (Gitleaks)"),
        ("lizard", "Complexity heuristics (Lizard)"),
        ("go_vet", "Go static checks (go vet)"),
    ):
        if tool in used_tools:
            methodologies.append(description)
    if result.metadata.ai_enabled:
        methodologies.append("Optional local LLM enrichment (explanations only)")

    high_conf = sum(1 for f in active if f.confidence == Confidence.HIGH)
    fix_available = sum(1 for f in active if (_ai_text(f, "recommended_fix") or f.recommendation))
    coverage_pct = _coverage_pct(result)
    primary = _risk_card(top_risks[0] if top_risks else None)
    secondary = _risk_card(top_risks[1] if len(top_risks) > 1 else None)
    critical_ids = [f.id for f in top_risks if f.severity == Severity.CRITICAL]
    if not critical_ids:
        critical_ids = [f.id for f in top_risks if f.severity == Severity.HIGH][:3]

    commit_short = commit[:7] if commit and commit != "n/a" and len(commit) >= 7 else commit
    branch_commit_display = f"{branch} / {commit_short}"
    engine_label = f"Dede SAST {result.metadata.scanner_version}"
    primary_lang = languages_list[0]["name"] if languages_list else "n/a"
    primary_lang_pct = languages_list[0]["pct"] if languages_list else None

    # Contributing factors: only engine-backed metrics (no inventable exploitability/reachability)
    contributing_factors: list[dict[str, Any]] = []
    if result.risk is not None:
        contributing_factors.append(
            {"name": "Severity burden", "value": result.risk.score, "note": "Engine risk score"}
        )
    if active:
        contributing_factors.append(
            {
                "name": "Confidence",
                "value": int(round(100 * high_conf / total)) if total else 0,
                "note": f"{high_conf}/{total} high-confidence",
            }
        )
    if coverage_pct is not None:
        contributing_factors.append(
            {
                "name": "Coverage",
                "value": coverage_pct,
                "note": "Successful analyzers / applicable",
            }
        )

    logos = logo_assets()
    files_scanned = result.metadata.files_scanned or result.languages.files_scanned
    lines_scanned = result.metadata.lines_scanned or result.languages.lines_scanned

    raw_date = result.metadata.scan_started
    if hasattr(raw_date, "strftime"):
        analysis_date_display = raw_date.strftime("%d %b %Y — %H:%M UTC")
    else:
        analysis_date_display = str(raw_date)

    return {
        "result": result,
        "pdf": pdf,
        "severity_counts": counts,
        "total_findings": total,
        "critical_count": critical,
        "high_count": high,
        "medium_count": medium,
        "low_count": low,
        "info_count": info,
        "critical_high_count": critical + high,
        "top_findings": top_risks,
        "top_risk_views": top_risk_views,
        "finding_views": finding_views,
        "risk_line": risk_line,
        "overall_risk_label": overall_risk_label,
        "security_score": security_score,
        "security_score_label": security_label,
        "ai_label": ai_label,
        "bar_total": total if total > 0 else 1,
        "findings_by_category": category_dist,
        "cwe_distribution": _cwe_distribution(active),
        "owasp_distribution": _owasp_distribution(active),
        "standards_assessment": standards_assessment(active),
        "hotspot_folders": hotspot_folders,
        "hotspot_files": hotspot_files,
        "secrets_findings": secrets,
        "has_secrets": bool(secrets),
        "remediation_groups": _remediation_groups(active),
        "quick_wins": _quick_wins(active),
        "security_strengths": _security_strengths(result, active),
        "executive_narrative": _executive_narrative(
            critical=critical,
            high=high,
            medium=medium,
            security_score=security_score,
            security_label=security_label,
            top_class=top_class,
            files_scanned=files_scanned,
        ),
        "trend_narrative": _trend_narrative(
            total=total,
            hotspot_folders=hotspot_folders,
            critical_high=critical + high,
        ),
        "analysis_id": _analysis_id(result),
        "project_name": project_name,
        "repository": repository,
        "branch": branch,
        "commit": commit,
        "commit_short": commit_short,
        "branch_commit_display": branch_commit_display,
        "engine_label": engine_label,
        "languages_list": languages_list,
        "languages_display": ", ".join(str(language["name"]) for language in languages_list)
        or "n/a",
        "frameworks_display": ", ".join(result.languages.frameworks) or "n/a",
        "primary_language": primary_lang,
        "primary_language_pct": primary_lang_pct,
        "donut_segments": _donut_segments(counts),
        "scan_coverage": scan_coverage,
        "native_coverage": next(
            (t.coverage for t in result.tool_statuses if t.tool == "dede-engine"), {}
        ),
        "coverage_pct": coverage_pct,
        "confidence_summary": confidence_summary,
        "high_confidence_count": high_conf,
        "high_confidence_pct": int(round(100 * high_conf / total)) if total else 0,
        "fix_available_count": fix_available,
        "primary_risk": primary,
        "secondary_risk": secondary,
        "release_decision": _release_decision(critical=critical, high=high, top_ids=critical_ids),
        "contributing_factors": contributing_factors,
        "rules_triggered": rules_triggered,
        "rules_triggered_count": len(rules_triggered),
        "methodologies": methodologies,
        "analysis_date": analysis_date_display,
        "analysis_date_raw": raw_date,
        "files_scanned": files_scanned,
        "lines_scanned": lines_scanned,
        "suppressed_count": len(result.suppressed_findings),
        "resolved_count": len(result.resolved_findings),
        "maintainability_rating": result.maintainability_rating,
        "maintainability_debt_minutes": result.maintainability_debt_minutes,
        "maintainability_debt_ratio": result.maintainability_debt_ratio,
        "smell_breakdown": maintainability_breakdown(result.findings),
        "omitted_findings_count": omitted_findings,
        "detailed_findings_limit": detailed_limit,
        "reporting_dir": str(Path(__file__).resolve().parent),
        "developer_name": DEVELOPER_NAME,
        "developer_email": DEVELOPER_EMAIL,
        "developer_linkedin": DEVELOPER_LINKEDIN,
        "developer_github": DEVELOPER_GITHUB,
        **build_operational_metrics(result),
        **logos,
    }
