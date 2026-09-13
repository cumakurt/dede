"""Local read-only HTTP dashboard/API for an existing Dede report directory.

This is a privacy-first team/server foundation.  It binds to loopback only and
serves already-generated artifacts; it does not upload source code or execute
project content.
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


def _summary(report: dict) -> dict:
    findings = report.get("findings", []) if isinstance(report, dict) else []
    sev: dict[str, int] = {}
    for finding in findings:
        key = str(finding.get("severity", "UNKNOWN"))
        sev[key] = sev.get(key, 0) + 1
    return {
        "scanner_version": (report.get("metadata") or {}).get("scanner_version"),
        "findings": len(findings),
        "severity": sev,
        "risk": report.get("risk"),
        "lifecycle": (report.get("metadata") or {}).get("lifecycle", {}),
        "feedback": (report.get("metadata") or {}).get("feedback", {}),
    }


def serve(report_dir: Path, *, port: int = 8765) -> int:
    report_dir = report_dir.resolve()
    report_path = report_dir / "report.json"
    if not report_path.is_file():
        raise FileNotFoundError(f"report.json not found in {report_dir}")

    class Handler(BaseHTTPRequestHandler):
        server_version = "DedeLocal/1.0"
        def _send_json(self, obj, status=200):
            payload = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self.send_response(status); self.send_header("Content-Type", "application/json; charset=utf-8"); self.send_header("Content-Length", str(len(payload))); self.send_header("Cache-Control", "no-store"); self.end_headers(); self.wfile.write(payload)
        def do_GET(self):  # noqa: N802
            parsed = urlparse(self.path)
            try:
                report = json.loads(report_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                self._send_json({"error": str(exc)}, 500); return
            if parsed.path == "/api/summary":
                self._send_json(_summary(report)); return
            if parsed.path == "/api/findings":
                query = parse_qs(parsed.query)
                severity = (query.get("severity") or [""])[0].upper()
                text = (query.get("q") or [""])[0].lower()
                out = []
                for finding in report.get("findings", []):
                    if severity and str(finding.get("severity", "")).upper() != severity: continue
                    haystack = " ".join(str(finding.get(k, "")) for k in ("id","rule_id","file","message","endpoint","source_kind","sink_kind"))
                    if text and text not in haystack.lower(): continue
                    out.append(finding)
                self._send_json(out); return
            if parsed.path in {"/", "/report.html"}:
                path = report_dir / "report.html"
                if not path.is_file(): self._send_json({"error": "report.html not found"}, 404); return
                payload = path.read_bytes(); self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8"); self.send_header("Content-Length", str(len(payload))); self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'"); self.end_headers(); self.wfile.write(payload); return
            self._send_json({"error": "not found"}, 404)
        def log_message(self, fmt, *args):
            return

    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"Dede local report server: http://127.0.0.1:{port}")
    print("Read-only loopback service; press Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0
