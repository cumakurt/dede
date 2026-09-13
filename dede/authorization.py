"""Opt-in authorization and business-logic analysis.

The analyzer intentionally remains outside the default precision profile.  It
requires multiple structural signals before emitting a candidate and labels all
results EXPERIMENTAL so teams can evaluate them with Dede's Precision Lab and
organization feedback before promoting them into policy.
"""
from __future__ import annotations

import ast
import re
import time
from pathlib import Path

from dede.analyzers.base import Analyzer
from dede.config import AppConfig
from dede.models import AnalyzerResult, Category, Confidence, Evidence, Finding, Precision, ProjectContext, Severity, ToolStatus
from dede.utils.hashes import sha256_text

_ROUTE_DECORATOR = {"get", "post", "put", "patch", "delete", "route"}
_GUARD_WORDS = {"current_user", "owner", "ownership", "authorize", "permission", "principal", "tenant", "user_id", "account_id", "organization_id", "org_id", "role", "is_admin"}
_PRIVILEGED_ROUTE = re.compile(r"/(?:admin|manage|management|staff|internal|root)(?:/|$)", re.I)
_LOOKUP = r"\.(?:get|find|find_by_id|filter|filter_by|first|one)\s*\([^\n)]*\b{ident}\b"
_SENSITIVE_WRITE = re.compile(r"\.(?:delete|update|save|commit|remove|destroy)\s*\(|\b(?:delete|update)\s+", re.I)
_GUARD_CALL = re.compile(r"\b(?:authorize|check_permission|has_permission|is_owner|ensure_owner|require_role|require_admin)\s*\(", re.I)
_MONEY_NAMES = re.compile(r"(?i)^(?:amount|price|quantity|qty|discount|total|credit|debit)$")
_STATE_NAMES = re.compile(r"(?i)^(?:status|state|phase)$")


def _name(node: ast.AST | None) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        left = _name(node.value)
        return f"{left}.{node.attr}" if left else node.attr
    return ""


def _route(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[str, tuple[str, ...], bool]:
    path = ""
    methods: list[str] = []
    authenticated = False
    for deco in fn.decorator_list:
        call = deco if isinstance(deco, ast.Call) else None
        name = _name(call.func if call else deco).lower()
        tail = name.rsplit(".", 1)[-1]
        if any(word in name for word in ("auth", "login", "permission", "jwt", "role")):
            authenticated = True
        if call and tail in _ROUTE_DECORATOR and call.args and isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str):
            path = call.args[0].value
            if tail != "route":
                methods.append(tail.upper())
            for kw in call.keywords:
                if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                    methods.extend(
                        str(item.value).upper() for item in kw.value.elts
                        if isinstance(item, ast.Constant) and isinstance(item.value, str)
                    )
    for default in [*fn.args.defaults, *fn.args.kw_defaults]:
        if isinstance(default, ast.Call) and _name(default.func).rsplit(".", 1)[-1] in {"Depends", "Security"}:
            dep = _name(default.args[0]).lower() if default.args else ""
            if any(word in dep for word in ("auth", "user", "principal", "permission", "jwt", "role")):
                authenticated = True
    return path, tuple(dict.fromkeys(methods)), authenticated


def _finding(*, rule_id: str, rel: str, line: int, route: str, message: str, recommendation: str, cwe: str, evidence: str, normalized_type: str, exploitability: float = 60.0) -> Finding:
    semantic = sha256_text(f"{rule_id}|{rel}|{route}|{line}|{evidence}")
    return Finding(
        tool="dede-authz-experimental", rule_id=rule_id, category=Category.SECURITY,
        severity=Severity.MEDIUM, confidence=Confidence.LOW, confidence_score=0.58,
        precision=Precision.EXPERIMENTAL, cwe=[cwe], file=rel, start_line=line, end_line=line,
        message=message, recommendation=recommendation, normalized_type=normalized_type,
        analysis_kind="business-logic-experimental", semantic_fingerprint=semantic,
        endpoint=route, internet_exposed=True, reachable=True, exploitability_score=exploitability,
        evidence=[Evidence(kind="experimental-business-logic", value=evidence, confidence=0.58)],
    )


class ExperimentalAuthorizationAnalyzer(Analyzer):
    name = "dede-authz-experimental"

    def supports(self, project: ProjectContext) -> bool:
        return project.has_python

    def version(self) -> str:
        return "0.2.0"

    def analyze(self, project: ProjectContext, config: AppConfig, raw_dir: Path) -> AnalyzerResult:
        authz = config.experimental.authorization_analysis
        logic = config.experimental.business_logic_analysis
        if not authz and not logic:
            return AnalyzerResult(
                tool=self.name, status=ToolStatus.NOT_APPLICABLE, version=self.version(),
                message="experimental authorization/business-logic analysis disabled",
            )
        started = time.perf_counter()
        root = Path(project.root).resolve()
        findings: list[Finding] = []
        functions_scanned = 0
        for file_value in project.files:
            path = Path(file_value)
            if path.suffix.lower() != ".py":
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(text)
                rel = path.resolve().relative_to(root).as_posix()
            except (OSError, SyntaxError, ValueError):
                continue
            lines = text.splitlines()
            for fn in [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
                route, methods, authenticated = _route(fn)
                if not route:
                    continue
                functions_scanned += 1
                body_lines = lines[max(0, fn.lineno - 1): getattr(fn, "end_lineno", fn.lineno)]
                body_text = "\n".join(body_lines)
                lower = body_text.lower()
                visible_guard = authenticated or any(word in lower for word in _GUARD_WORDS) or bool(_GUARD_CALL.search(body_text))

                if authz:
                    # 1) Privileged management surfaces without a visible auth boundary.
                    if _PRIVILEGED_ROUTE.search(route) and not visible_guard:
                        findings.append(_finding(
                            rule_id="dede.experimental.privileged-route-missing-auth",
                            rel=rel, line=fn.lineno, route=route, cwe="CWE-862",
                            message=f"Privileged route {route} has no visible authentication/authorization guard.",
                            recommendation="Require authentication and an explicit role/permission check before executing privileged actions.",
                            evidence="privileged route marker + no visible auth/role guard",
                            normalized_type="authorization-missing-guard", exploitability=72.0,
                        ))

                    # 2) BOLA/IDOR: path identifier directly drives object lookup with no ownership/tenant guard.
                    ids = set(re.findall(r"\{([A-Za-z_]\w*)\}|<(?:(?:int|uuid|string):)?([A-Za-z_]\w*)>", route))
                    route_ids = {a or b for a, b in ids if a or b}
                    if route_ids and not visible_guard:
                        for ident in sorted(route_ids):
                            lookup = re.search(_LOOKUP.format(ident=re.escape(ident)), body_text)
                            if not lookup:
                                continue
                            line = fn.lineno + body_text[:lookup.start()].count("\n")
                            cwe = "CWE-639"
                            detail = f"route-id={ident}; direct object lookup; no visible ownership/tenant guard"
                            if ident.lower() in {"tenant_id", "account_id", "org_id", "organization_id"}:
                                detail += "; tenant-scoped identifier"
                            findings.append(_finding(
                                rule_id="dede.experimental.possible-idor",
                                rel=rel, line=line, route=route, cwe=cwe,
                                message=f"Route {route} directly looks up object identifier '{ident}' without a visible ownership/tenant guard.",
                                recommendation="Require authentication and verify resource ownership/tenant membership before returning or mutating the object.",
                                evidence=detail, normalized_type="authorization-idor", exploitability=68.0,
                            ))
                            break

                    # 3) Sensitive write happens before a guard later in the same handler.
                    write = _SENSITIVE_WRITE.search(body_text)
                    guard = _GUARD_CALL.search(body_text)
                    if write and guard and write.start() < guard.start():
                        line = fn.lineno + body_text[:write.start()].count("\n")
                        findings.append(_finding(
                            rule_id="dede.experimental.authorization-after-write",
                            rel=rel, line=line, route=route, cwe="CWE-862",
                            message=f"Route {route} appears to perform a state-changing operation before its visible authorization check.",
                            recommendation="Perform authentication/authorization before any sensitive read, write, delete, commit, or external side effect.",
                            evidence="state-changing operation precedes authorization helper",
                            normalized_type="authorization-ordering", exploitability=70.0,
                        ))

                if logic:
                    # 4) Money/quantity values from HTTP input used in financial-looking operations without a visible range check.
                    tainted_names: set[str] = set()
                    for node in ast.walk(fn):
                        if isinstance(node, (ast.Assign, ast.AnnAssign)):
                            target = node.targets[0] if isinstance(node, ast.Assign) and node.targets else node.target if isinstance(node, ast.AnnAssign) else None
                            value = node.value
                            name = target.id if isinstance(target, ast.Name) else ""
                            if name and _MONEY_NAMES.match(name) and isinstance(value, (ast.Call, ast.Subscript, ast.Attribute)):
                                rendered = ast.unparse(value).lower() if hasattr(ast, "unparse") else ""
                                if any(marker in rendered for marker in ("request", "params", "query", "form", "json", "data")):
                                    tainted_names.add(name)
                    for name in sorted(tainted_names):
                        validation = re.search(rf"\b{re.escape(name)}\b\s*(?:<=|<|>=|>)\s*-?\d|(?:<=|<|>=|>)\s*\b{re.escape(name)}\b", body_text)
                        use = re.search(rf"(?:charge|debit|credit|balance|total|price|amount|quantity|qty)[^\n]*\b{re.escape(name)}\b|\b{re.escape(name)}\b[^\n]*(?:charge|debit|credit|balance|total|price)", body_text, re.I)
                        if use and not validation:
                            line = fn.lineno + body_text[:use.start()].count("\n")
                            findings.append(_finding(
                                rule_id="dede.experimental.unvalidated-financial-value",
                                rel=rel, line=line, route=route, cwe="CWE-20",
                                message=f"HTTP-controlled financial/quantity value '{name}' is used without a visible numeric range validation.",
                                recommendation="Validate sign, range, precision, currency/unit and business invariants before financial/state-changing operations.",
                                evidence=f"http-derived value={name}; financial-looking use; no visible range check",
                                normalized_type="business-logic-financial-validation", exploitability=55.0,
                            ))

                    # 5) HTTP-controlled state/status assigned directly without an allow-list/enum validation.
                    for node in ast.walk(fn):
                        if not isinstance(node, ast.Assign) or not node.targets:
                            continue
                        target = node.targets[0]
                        if not isinstance(target, ast.Name) or not _STATE_NAMES.match(target.id):
                            continue
                        rendered = ast.unparse(node.value).lower() if hasattr(ast, "unparse") else ""
                        if not any(marker in rendered for marker in ("request", "params", "query", "form", "json", "data")):
                            continue
                        name = target.id
                        if re.search(rf"\b{name}\b\s+in\s+[\[\(\{{]|Enum\b|allowed_(?:states|statuses)", body_text, re.I):
                            continue
                        assignment = re.search(rf"\.\s*(?:status|state)\s*=\s*{re.escape(name)}\b", body_text, re.I)
                        if assignment:
                            line = fn.lineno + body_text[:assignment.start()].count("\n")
                            findings.append(_finding(
                                rule_id="dede.experimental.unvalidated-state-transition",
                                rel=rel, line=line, route=route, cwe="CWE-841",
                                message=f"HTTP-controlled state value '{name}' is assigned directly without a visible transition allow-list.",
                                recommendation="Map external state requests to an explicit transition table and enforce current-state, role, and invariant checks.",
                                evidence=f"http-derived state={name}; direct state assignment; no visible allow-list",
                                normalized_type="business-logic-state-transition", exploitability=58.0,
                            ))
        # Stable identity de-duplication.
        unique: dict[tuple[str, str, int, str], Finding] = {}
        for finding in findings:
            unique.setdefault((finding.rule_id, finding.file, finding.start_line, finding.endpoint), finding)
        findings = list(unique.values())
        return AnalyzerResult(
            tool=self.name, status=ToolStatus.SUCCESS, version=self.version(), findings=findings,
            duration_seconds=time.perf_counter() - started,
            message=f"{len(findings)} experimental authorization/business-logic candidate(s)",
            coverage={"experimental": True, "functions_scanned": functions_scanned, "candidates": len(findings)},
        )
