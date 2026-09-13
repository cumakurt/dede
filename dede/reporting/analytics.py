"""Derived operational metrics for human-readable reports.

All values in this module are computed from ScanResult evidence.  The report
layer must not invent reachability, exploitability, lifecycle, or policy state
that the scanners did not provide.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from typing import Any

from dede.models import Finding, ScanResult, ToolStatus


def _pct(part: int, total: int) -> int:
    return int(round(100 * part / total)) if total else 0


def _active(result: ScanResult) -> list[Finding]:
    return [finding for finding in result.findings if not finding.suppressed]


def lifecycle_metrics(result: ScanResult) -> dict[str, Any]:
    active = _active(result)
    raw = result.metadata.lifecycle if isinstance(result.metadata.lifecycle, dict) else {}
    counts = raw.get("counts") if isinstance(raw.get("counts"), dict) else {}
    if not counts:
        counts = Counter(f.lifecycle_status for f in active if f.lifecycle_status)
    normalized = {name: int(counts.get(name, 0) or 0) for name in ("NEW", "EXISTING", "REOPENED", "RESOLVED")}
    status = str(raw.get("status") or ("available" if counts else "unavailable"))
    return {
        "status": status,
        "counts": normalized,
        "current_total": int(raw.get("current_total", len(active)) or 0),
        "resolved": list(raw.get("resolved") or [])[:25],
        "has_history": bool(counts or raw.get("resolved")),
    }


def analyzer_metrics(result: ScanResult) -> dict[str, Any]:
    applicable = [t for t in result.tool_statuses if t.status != ToolStatus.NOT_APPLICABLE]
    success = [t for t in applicable if t.status == ToolStatus.SUCCESS]
    failed = [t for t in applicable if t.status == ToolStatus.FAILED]
    skipped = [
        t
        for t in applicable
        if t.status in {ToolStatus.SKIPPED, ToolStatus.SKIPPED_OFFLINE_DEPENDENCY}
    ]
    slowest = sorted(
        (
            {
                "tool": t.tool,
                "seconds": round(float(t.duration_seconds or 0.0), 3),
                "status": t.status.value,
                "findings": len(t.findings),
            }
            for t in applicable
        ),
        key=lambda row: (-row["seconds"], row["tool"]),
    )[:8]
    return {
        "applicable": len(applicable),
        "success": len(success),
        "failed": len(failed),
        "skipped": len(skipped),
        "completion_pct": _pct(len(success), len(applicable)),
        "slowest": slowest,
        "coverage_degraded": bool(failed or skipped),
    }


def attack_surface_metrics(result: ScanResult) -> dict[str, Any]:
    active = _active(result)
    reachable = [f for f in active if f.reachable is True]
    internet = [f for f in active if f.internet_exposed is True]
    unauthenticated = [
        f for f in internet if f.authentication_required is False and bool(f.endpoint)
    ]
    high_exploitability = [
        f for f in active if f.exploitability_score is not None and f.exploitability_score >= 80
    ]
    with_flow = [f for f in active if f.dataflow or f.attack_path]
    with_evidence = [f for f in active if f.evidence or f.dataflow or f.code_snippet]
    endpoints: dict[tuple[str, str], list[Finding]] = defaultdict(list)
    for finding in active:
        if finding.endpoint:
            endpoints[(finding.http_method or "ANY", finding.endpoint)].append(finding)
    endpoint_rows = []
    for (method, endpoint), findings in endpoints.items():
        severities = Counter(f.severity.value for f in findings)
        endpoint_rows.append(
            {
                "method": method,
                "endpoint": endpoint,
                "findings": len(findings),
                "critical_high": severities.get("CRITICAL", 0) + severities.get("HIGH", 0),
                "internet_exposed": any(f.internet_exposed is True for f in findings),
                "authentication_required": (
                    True
                    if all(f.authentication_required is True for f in findings)
                    else False
                    if any(f.authentication_required is False for f in findings)
                    else None
                ),
                "max_exploitability": max(
                    (float(f.exploitability_score) for f in findings if f.exploitability_score is not None),
                    default=None,
                ),
            }
        )
    endpoint_rows.sort(
        key=lambda row: (
            -row["critical_high"],
            -(row["max_exploitability"] or -1),
            -row["findings"],
            row["endpoint"],
        )
    )
    query_counter = Counter(match for f in active for match in f.query_matches)
    source_counter = Counter(f.source_kind for f in active if f.source_kind)
    sink_counter = Counter(f.sink_kind for f in active if f.sink_kind)
    return {
        "reachable": len(reachable),
        "internet_exposed": len(internet),
        "unauthenticated_exposed": len(unauthenticated),
        "high_exploitability": len(high_exploitability),
        "with_flow": len(with_flow),
        "flow_coverage_pct": _pct(len(with_flow), len(active)),
        "evidence_coverage_pct": _pct(len(with_evidence), len(active)),
        "endpoints": endpoint_rows[:20],
        "endpoint_count": len(endpoint_rows),
        "query_matches": [{"id": key, "count": value} for key, value in query_counter.most_common(15)],
        "source_kinds": [{"name": key, "count": value} for key, value in source_counter.most_common(10)],
        "sink_kinds": [{"name": key, "count": value} for key, value in sink_counter.most_common(10)],
    }


def finding_quality_metrics(result: ScanResult) -> dict[str, Any]:
    active = _active(result)
    precision = Counter(f.precision.value for f in active)
    tools = Counter(tool for f in active for tool in (f.detected_by or [f.tool]))
    multi_engine = sum(1 for f in active if len(set(f.detected_by or [f.tool])) > 1)
    return {
        "precision": [{"name": key, "count": value} for key, value in precision.most_common()],
        "tools": [{"name": key, "count": value} for key, value in tools.most_common(12)],
        "multi_engine": multi_engine,
        "multi_engine_pct": _pct(multi_engine, len(active)),
    }


def performance_metrics(result: ScanResult) -> dict[str, Any]:
    profile = result.metadata.profile if isinstance(result.metadata.profile, dict) else {}
    phases = [
        {"name": str(name).replace("_", " ").title(), "seconds": round(float(value), 3)}
        for name, value in profile.items()
        if isinstance(value, (int, float))
    ]
    phases.sort(key=lambda row: (-row["seconds"], row["name"]))
    maximum = max((row["seconds"] for row in phases), default=0.0) or 1.0
    for row in phases:
        row["bar"] = round(100 * row["seconds"] / maximum, 1)

    incremental = result.metadata.incremental if isinstance(result.metadata.incremental, dict) else {}
    changed = list(incremental.get("changed_files") or [])
    affected = list(incremental.get("affected_files") or [])
    return {
        "phases": phases,
        "incremental": {
            "changed_files": len(changed),
            "affected_files": len(affected),
            "removed_files": len(list(incremental.get("removed_files") or [])),
            "unchanged_files": int(incremental.get("unchanged_files", 0) or 0),
            "dependency_edges_cached": int(incremental.get("dependency_edges_cached", 0) or 0),
            "dependency_edges_current": int(incremental.get("dependency_edges_current", 0) or 0),
            "cache_hit_ratio": incremental.get("cache_hit_ratio"),
            "status": incremental.get("status", "available" if incremental else "unavailable"),
        },
    }


def governance_metrics(result: ScanResult) -> dict[str, Any]:
    violations = list(result.metadata.policy_violations or [])
    manifest = result.metadata.scan_manifest if isinstance(result.metadata.scan_manifest, dict) else {}
    digest = hashlib.sha256(
        json.dumps(manifest, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
    ).hexdigest() if manifest else ""
    rulesets = result.metadata.ruleset_versions or {}
    return {
        "policy_violations": violations[:50],
        "policy_violation_count": len(violations),
        "policy_gate": "BLOCKED" if violations else "PASS",
        "manifest_digest": digest,
        "manifest_digest_short": digest[:16] if digest else "n/a",
        "rulesets": [{"name": name, "version": version} for name, version in sorted(rulesets.items())],
        "offline_mode": bool(result.metadata.offline_mode),
    }


def remediation_sla() -> list[dict[str, str]]:
    """Default report guidance, explicitly labelled as suggested targets."""
    return [
        {"severity": "CRITICAL", "target": "24 hours", "action": "Block release / emergency remediation"},
        {"severity": "HIGH", "target": "7 days", "action": "Release-gate priority"},
        {"severity": "MEDIUM", "target": "30 days", "action": "Planned sprint remediation"},
        {"severity": "LOW", "target": "90 days", "action": "Hardening backlog"},
    ]


def build_operational_metrics(result: ScanResult) -> dict[str, Any]:
    return {
        "lifecycle_metrics": lifecycle_metrics(result),
        "analyzer_metrics": analyzer_metrics(result),
        "attack_metrics": attack_surface_metrics(result),
        "finding_quality_metrics": finding_quality_metrics(result),
        "performance_metrics": performance_metrics(result),
        "governance_metrics": governance_metrics(result),
        "remediation_sla": remediation_sla(),
    }
