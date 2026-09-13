"""Attack-graph export derived from deterministic semantic IR and findings."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from dede.models import Finding
from dede.semantic.ir import SecurityIR


def build_attack_graph(ir: SecurityIR, findings: list[Finding]) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: set[tuple[str, str, str]] = set()

    for endpoint in ir.endpoints:
        eid = f"endpoint:{endpoint.function}:{endpoint.path}"
        nodes[eid] = {
            "id": eid,
            "kind": "endpoint",
            "label": f"{'/'.join(endpoint.methods) or 'HTTP'} {endpoint.path}",
            "file": endpoint.file,
            "line": endpoint.line,
            "authentication_required": endpoint.authentication_required,
        }
        fid = f"function:{endpoint.function}"
        nodes.setdefault(fid, {"id": fid, "kind": "function", "label": endpoint.function})
        edges.add((eid, fid, "enters"))

    for call in ir.calls:
        caller = f"function:{call.caller}"
        callee = f"function:{call.callee}"
        nodes.setdefault(caller, {"id": caller, "kind": "function", "label": call.caller})
        nodes.setdefault(callee, {"id": callee, "kind": "function", "label": call.callee})
        edges.add((caller, callee, "calls"))

    paths: list[dict[str, Any]] = []
    for finding in findings:
        if not (finding.analysis_kind.startswith("semantic-") or finding.analysis_kind == "sca-reachability"):
            continue
        sink_id = f"sink:{finding.semantic_fingerprint or finding.rule_id}:{finding.file}:{finding.start_line}"
        nodes[sink_id] = {
            "id": sink_id,
            "kind": "sink",
            "label": finding.sink_kind,
            "file": finding.file,
            "line": finding.start_line,
            "cwe": finding.cwe,
            "severity": finding.severity.value,
            "exploitability_score": finding.exploitability_score,
        }
        if finding.call_path:
            last = f"function:{finding.call_path[-1]}"
            nodes.setdefault(last, {"id": last, "kind": "function", "label": finding.call_path[-1]})
            edges.add((last, sink_id, "reaches"))
        path = [*(finding.attack_surface or []), *finding.call_path, finding.sink_kind]
        paths.append(
            {
                "finding": finding.semantic_fingerprint or finding.fingerprint,
                "path": path,
                "severity": finding.severity.value,
                "exploitability_score": finding.exploitability_score,
                "query_matches": finding.query_matches,
            }
        )

    ranked = sorted(paths, key=lambda p: (p["exploitability_score"] or 0.0), reverse=True)
    # Dependency vulnerabilities become first-class graph nodes when SCA
    # evidence is available, allowing application and supply-chain risk to be
    # ranked in the same deterministic graph.
    for finding in findings:
        if finding.analysis_kind != "sca-reachability":
            continue
        dep_id = f"dependency:{finding.semantic_fingerprint or finding.rule_id}"
        nodes[dep_id] = {"id": dep_id, "kind": "dependency", "label": finding.message, "file": finding.file, "line": finding.start_line, "reachable": finding.reachable, "severity": finding.severity.value}
        for step in finding.dataflow:
            source_id = f"source:{step.file}:{step.start_line}"
            nodes[source_id] = {"id": source_id, "kind": "source-reference", "label": step.symbol or step.file, "file": step.file, "line": step.start_line}
            edges.add((source_id, dep_id, "uses"))

    return {
        "version": "2",
        "nodes": sorted(nodes.values(), key=lambda item: item["id"]),
        "edges": [
            {"source": source, "target": target, "kind": kind}
            for source, target, kind in sorted(edges)
        ],
        "attack_paths": ranked,
        "stats": {
            "nodes": len(nodes),
            "edges": len(edges),
            "attack_paths": len(paths),
            "internet_exposed_paths": sum(1 for f in findings if f.internet_exposed),
        },
    }


def write_attack_graph(ir: SecurityIR, findings: list[Finding], raw_dir: Path) -> tuple[Path, Path]:
    graph = build_attack_graph(ir, findings)
    json_path = raw_dir / "semantic-python-attack-graph.json"
    json_path.write_text(json.dumps(graph, indent=2, sort_keys=True), encoding="utf-8")

    dot_path = raw_dir / "semantic-python-attack-graph.dot"
    lines = ["digraph dede_attack_graph {", "  rankdir=LR;"]
    for node in graph["nodes"]:
        label = str(node.get("label", node["id"])).replace('"', r'\"')
        lines.append(f'  "{node["id"]}" [label="{label}"];')
    for edge in graph["edges"]:
        lines.append(
            f'  "{edge["source"]}" -> "{edge["target"]}" [label="{edge["kind"]}"];'
        )
    lines.append("}")
    dot_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return json_path, dot_path


def write_unified_finding_graph(findings: list[Finding], raw_dir: Path) -> Path:
    """Write a report-level attack graph across semantic, SCA and agent findings.

    This graph does not invent edges.  It only joins explicit ``attack_path``
    steps and structured source/sink/dependency evidence already attached to a
    finding, making it safe to consume for triage and local MCP/API queries.
    """
    nodes: dict[str, dict[str, Any]] = {}
    edges: set[tuple[str, str, str]] = set()
    paths: list[dict[str, Any]] = []
    for finding in findings:
        if not (
            finding.analysis_kind.startswith("semantic-")
            or finding.analysis_kind in {"sca-reachability", "agent-security", "business-logic-experimental"}
        ):
            continue
        raw_steps = list(finding.attack_path)
        if not raw_steps:
            if finding.source_kind:
                raw_steps.append(finding.source_kind)
            if finding.function:
                raw_steps.append(finding.function)
            if finding.sink_kind:
                raw_steps.append(finding.sink_kind)
        if not raw_steps:
            continue
        node_ids: list[str] = []
        for idx, label in enumerate(raw_steps):
            node_id = f"path:{finding.semantic_fingerprint or finding.fingerprint}:{idx}"
            kind = "source" if idx == 0 else ("sink" if idx == len(raw_steps)-1 else "hop")
            nodes[node_id] = {"id": node_id, "kind": kind, "label": label, "file": finding.file, "line": finding.start_line}
            node_ids.append(node_id)
        for left, right in zip(node_ids, node_ids[1:]):
            edges.add((left, right, "flows-to"))
        paths.append({
            "finding": finding.semantic_fingerprint or finding.fingerprint,
            "rule_id": finding.rule_id,
            "analysis_kind": finding.analysis_kind,
            "path": raw_steps,
            "severity": finding.severity.value,
            "reachable": finding.reachable,
            "exploitability_score": finding.exploitability_score,
        })
    payload = {
        "version": "2",
        "nodes": sorted(nodes.values(), key=lambda x: x["id"]),
        "edges": [{"source": a, "target": b, "kind": kind} for a,b,kind in sorted(edges)],
        "attack_paths": sorted(paths, key=lambda x: x.get("exploitability_score") or 0.0, reverse=True),
        "stats": {"nodes": len(nodes), "edges": len(edges), "attack_paths": len(paths)},
    }
    raw_dir.mkdir(parents=True, exist_ok=True)
    path = raw_dir / "attack-graph-v2.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return path
