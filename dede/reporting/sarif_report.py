"""SARIF 2.1.0 export for IDE and CI integrations.

Emits a static, offline SARIF log so tools such as the VS Code SARIF Viewer,
GitHub code scanning or other SARIF consumers can display Dede findings in
place. Exported findings are the same normalized findings as every other
report: advisory review fields remain advisory and nothing here changes
severity, fingerprints or CI gates.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import quote

from dede import __version__
from dede.models import ScanResult
from dede.utils.redact import redact_text

# Severity → SARIF level. INFO has no native level; "note" is the convention.
_LEVELS = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}

_RULE_URI = "https://github.com/cumakurt/dede"


def _rule_metadata(finding: Any) -> dict[str, Any]:
    """Rule descriptor from finding metadata; no invented content."""
    # Build a stable helpUri: CWE link when available, else project info page.
    cwe_list = finding.cwe or []
    if cwe_list:
        first_cwe = str(cwe_list[0])
        import re as _re

        m = _re.search(r"\d+", first_cwe)
        help_uri = f"https://cwe.mitre.org/data/definitions/{m.group()}.html" if m else _RULE_URI
    else:
        help_uri = _RULE_URI

    rule: dict[str, Any] = {
        "id": finding.rule_id,
        "name": finding.normalized_type or finding.rule_id,
        "shortDescription": {"text": (finding.message or finding.rule_id)[:1000]},
        "helpUri": help_uri,
        "defaultConfiguration": {"level": _LEVELS.get(finding.severity.value, "note")},
        "properties": {
            "category": finding.category.value,
            "confidence": finding.confidence.value,
            "tags": [finding.tool, *(finding.cwe or [])],
        },
    }
    if finding.recommendation:
        rule["help"] = {"text": finding.recommendation[:4000]}
    if cwe_list:
        rule["properties"]["cwe"] = list(cwe_list)
    if finding.owasp:
        rule["properties"]["owasp"] = list(finding.owasp)
    if finding.standards:
        rule["properties"]["standards"] = finding.standards
    return rule


def build_sarif_log(result: ScanResult) -> dict[str, Any]:
    """Build a SARIF 2.1.0 log object from a scan result."""
    rules: list[dict[str, Any]] = []
    rule_index: dict[str, int] = {}
    results: list[dict[str, Any]] = []

    for finding in result.findings:
        if finding.suppressed:
            continue
        if finding.rule_id not in rule_index:
            rule_index[finding.rule_id] = len(rules)
            rules.append(_rule_metadata(finding))
        location: dict[str, Any] = {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": quote(Path(finding.file).as_posix(), safe="/"),
                    "uriBaseId": "%SRCROOT%",
                },
                "region": {
                    "startLine": max(1, finding.start_line),
                    "endLine": max(1, max(finding.start_line, finding.end_line)),
                },
            }
        }
        if finding.start_column:
            location["physicalLocation"]["region"]["startColumn"] = max(1, finding.start_column)
        message_text = finding.message or finding.rule_id
        if finding.ai_generated:
            message_text += " [AI advisory — requires human verification]"
        result_entry: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "ruleIndex": rule_index[finding.rule_id],
            "level": _LEVELS.get(finding.severity.value, "note"),
            "message": {"text": message_text[:4000]},
            "locations": [location],
            "fingerprints": {
                "dede/v1": finding.fingerprint or finding.id,
                **({"dede/semantic-v2": finding.semantic_fingerprint} if finding.semantic_fingerprint else {}),
            },
            "properties": {
                "tool": finding.tool,
                "severity": finding.severity.value,
                "aiGenerated": finding.ai_generated,
                "aiValidationStatus": finding.ai_validation_status,
                "analysisKind": finding.analysis_kind,
                "precision": finding.precision.value,
                "confidenceScore": finding.confidence_score,
                "exploitabilityScore": finding.exploitability_score,
                "reachable": finding.reachable,
                "sourceKind": finding.source_kind,
                "sinkKind": finding.sink_kind,
                "detectedBy": finding.detected_by,
                "correlationScore": finding.correlation_score,
                "astFingerprint": finding.ast_fingerprint,
                "endpoint": finding.endpoint,
                "httpMethod": finding.http_method,
                "authenticationRequired": finding.authentication_required,
                "internetExposed": finding.internet_exposed,
                "attackSurface": finding.attack_surface,
                "attackPath": finding.attack_path,
                "queryMatches": finding.query_matches,
                "lifecycleStatus": finding.lifecycle_status,
            },
        }
        if finding.dataflow:
            result_entry["codeFlows"] = [
                {
                    "threadFlows": [
                        {
                            "locations": [
                                {
                                    "location": {
                                        "physicalLocation": {
                                            "artifactLocation": {
                                                "uri": quote(Path(step.file).as_posix(), safe="/"),
                                                "uriBaseId": "%SRCROOT%",
                                            },
                                            "region": {
                                                "startLine": max(1, step.start_line),
                                                "endLine": max(1, step.start_line, step.end_line),
                                            },
                                        },
                                        "message": {"text": redact_text(step.content)},
                                    },
                                    "kinds": [step.kind],
                                }
                                for step in finding.dataflow
                            ]
                        }
                    ]
                }
            ]
        results.append(result_entry)

    root_uri = Path(result.metadata.target or ".").resolve().as_uri()
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Dede",
                        "version": __version__,
                        "informationUri": _RULE_URI,
                        "semanticVersion": __version__,
                        "rules": rules,
                    }
                },
                "originalUriBaseIds": {
                    "%SRCROOT%": {"uri": root_uri if root_uri.endswith("/") else root_uri + "/"}
                },
                "invocations": [
                    {
                        "executionSuccessful": not any(
                            t.status.value == "FAILED" for t in result.tool_statuses
                        )
                    }
                ],
                "properties": {
                    "aiEnabled": result.metadata.ai_enabled,
                    "riskScore": result.risk.score if result.risk else None,
                    "coverage": {
                        name: status.get("status")
                        for name, status in result.metadata.analyzers.items()
                    },
                    "nativeCoverage": next(
                        (t.coverage for t in result.tool_statuses if t.tool == "dede-engine"), {}
                    ),
                },
                "results": results,
            }
        ],
    }


def write_sarif_report(result: ScanResult, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "report.sarif"
    path.write_text(json.dumps(build_sarif_log(result), indent=2), encoding="utf-8")
    return path
