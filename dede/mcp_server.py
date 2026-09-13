"""Minimal offline MCP stdio server for querying an existing Dede report.

The server is intentionally read-only. It never executes project code, never
opens network sockets, and only exposes normalized scan results from report.json.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def _load_report(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _tools() -> list[dict[str, Any]]:
    return [
        {"name": "findings_summary", "description": "Return severity and lifecycle counts from a Dede report.", "inputSchema": {"type": "object", "properties": {}}},
        {"name": "findings_search", "description": "Search findings by text, severity, CWE, rule, file, endpoint or lifecycle.", "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}, "severity": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 100}}, "required": ["query"]}},
        {"name": "finding_get", "description": "Return one finding by id, fingerprint or semantic fingerprint.", "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}, "required": ["id"]}},
    ]


def _call(report: dict[str, Any], name: str, args: dict[str, Any]) -> Any:
    findings = report.get("findings", []) if isinstance(report, dict) else []
    if name == "findings_summary":
        severity: dict[str, int] = {}
        lifecycle: dict[str, int] = {}
        reachable = 0
        for f in findings:
            severity[str(f.get("severity", "UNKNOWN"))] = severity.get(str(f.get("severity", "UNKNOWN")), 0) + 1
            status = str(f.get("lifecycle_status", "")) or "UNSET"
            lifecycle[status] = lifecycle.get(status, 0) + 1
            if f.get("reachable") is True: reachable += 1
        return {"findings": len(findings), "severity": severity, "lifecycle": lifecycle, "reachable": reachable, "risk": report.get("risk")}
    if name == "findings_search":
        query = str(args.get("query", "")).lower()
        severity_filter = str(args.get("severity", "")).upper()
        limit = max(1, min(100, int(args.get("limit", 20))))
        out = []
        for f in findings:
            if severity_filter and str(f.get("severity", "")).upper() != severity_filter: continue
            haystack = " ".join(str(f.get(k, "")) for k in ("id","rule_id","file","message","endpoint","lifecycle_status","source_kind","sink_kind")) + " " + " ".join(f.get("cwe", []) or [])
            if query in haystack.lower(): out.append(f)
            if len(out) >= limit: break
        return out
    if name == "finding_get":
        wanted = str(args.get("id", ""))
        for f in findings:
            if wanted in {str(f.get("id", "")), str(f.get("fingerprint", "")), str(f.get("semantic_fingerprint", ""))}:
                return f
        return None
    raise ValueError(f"Unknown MCP tool: {name}")


def serve_stdio(report_path: Path) -> int:
    report = _load_report(report_path)
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw: continue
        try:
            req = json.loads(raw)
            rid = req.get("id")
            method = req.get("method")
            if method == "initialize":
                result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}, "serverInfo": {"name": "dede-mcp", "version": "1.0"}}
            elif method == "tools/list":
                result = {"tools": _tools()}
            elif method == "tools/call":
                params = req.get("params") or {}
                value = _call(report, str(params.get("name", "")), params.get("arguments") or {})
                result = {"content": [{"type": "text", "text": json.dumps(value, ensure_ascii=False, indent=2)}], "isError": False}
            elif method == "notifications/initialized":
                continue
            else:
                raise ValueError(f"Unsupported MCP method: {method}")
            print(json.dumps({"jsonrpc": "2.0", "id": rid, "result": result}, ensure_ascii=False), flush=True)
        except Exception as exc:  # noqa: BLE001
            rid = None
            try: rid = json.loads(raw).get("id")
            except Exception: pass
            print(json.dumps({"jsonrpc": "2.0", "id": rid, "error": {"code": -32000, "message": str(exc)}}), flush=True)
    return 0
