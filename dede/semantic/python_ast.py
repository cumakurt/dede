"""Project-wide Python semantic analysis.

The frontend builds a language-neutral Security IR, a static call graph and
lightweight CFG edges, then performs bounded context-sensitive taint analysis
across files.  It deliberately favors deterministic, explainable evidence over
broad speculative matches.
"""

from __future__ import annotations

import ast
import json
import re
from urllib.parse import urlsplit
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

from dede.analyzers.base import Analyzer
from dede.config import AppConfig
from dede.models import (
    AnalyzerResult,
    Category,
    Confidence,
    DataflowStep,
    Evidence,
    Finding,
    LanguageStats,
    Precision,
    ProjectContext,
    Severity,
    ToolStatus,
)
from dede.semantic.ir import (
    IRCFGEdge,
    IRCallEdge,
    IREndpoint,
    IRFunction,
    IRSecurityFlow,
    SecurityIR,
)
from dede.semantic.attack_graph import write_attack_graph
from dede.semantic.cache import load_cache, save_cache, semantic_signature, unaffected_cached_findings
from dede.semantic.query import apply_flow_queries
from dede.semantic.model_packs import load_model_packs, language_models
from dede.utils.hashes import sha256_text


@dataclass
class FunctionSummary:
    returns_source: bool = False
    passthrough_params: set[int] = field(default_factory=set)
    source_kinds: set[str] = field(default_factory=set)


@dataclass(frozen=True)
class SinkSpec:
    kind: str
    cwe: str
    severity: Severity
    argument: int = 0
    require_shell_true: bool = False


@dataclass(frozen=True)
class EndpointInfo:
    path: str
    methods: tuple[str, ...] = ()
    authentication_required: bool | None = None

    @property
    def labels(self) -> list[str]:
        methods = self.methods or ("HTTP",)
        return [f"{method} {self.path}" for method in methods]


@dataclass
class FunctionInfo:
    key: str
    module: str
    file: str
    name: str
    qualname: str
    node: ast.FunctionDef | ast.AsyncFunctionDef | ast.Module
    params: tuple[str, ...]
    aliases: dict[str, str]
    class_name: str = ""
    endpoint: EndpointInfo | None = None


@dataclass
class PythonProjectModel:
    root: Path
    trees: dict[str, ast.Module]
    sources: dict[str, list[str]]
    modules: dict[str, str]
    files_by_module: dict[str, str]
    aliases: dict[str, dict[str, str]]
    functions: dict[str, FunctionInfo]
    dependencies: dict[str, list[str]]
    parse_errors: int = 0


@dataclass(frozen=True)
class SymbolicValue:
    params: frozenset[int] = frozenset()
    sources: frozenset[str] = frozenset()

    @property
    def tainted(self) -> bool:
        return bool(self.params or self.sources)

    def merge(self, other: "SymbolicValue") -> "SymbolicValue":
        return SymbolicValue(self.params | other.params, self.sources | other.sources)


@dataclass(frozen=True)
class TaintValue:
    kinds: frozenset[str]
    trace: tuple[DataflowStep, ...]
    sanitized_for: frozenset[str] = frozenset()

    @property
    def tainted(self) -> bool:
        return bool(self.kinds)

    def with_step(self, step: DataflowStep) -> "TaintValue":
        trace = (*self.trace, step)
        return TaintValue(self.kinds, trace[-24:], self.sanitized_for)

    def sanitized(self, sink_kinds: set[str] | frozenset[str], step: DataflowStep) -> "TaintValue":
        if not self.tainted:
            return self
        trace = (*self.trace, step)
        return TaintValue(self.kinds, trace[-24:], self.sanitized_for | frozenset(sink_kinds))

    def merge(self, other: "TaintValue") -> "TaintValue":
        if not self.tainted:
            return other
        if not other.tainted:
            return self
        # A sink is considered sanitized only when every merged taint path is
        # sanitized for that sink class. This avoids false negatives when one
        # branch is clean and another branch remains dangerous.
        trace = self.trace if len(self.trace) <= len(other.trace) else other.trace
        return TaintValue(
            self.kinds | other.kinds,
            trace,
            self.sanitized_for & other.sanitized_for,
        )


@dataclass
class FlowState:
    values: dict[str, TaintValue] = field(default_factory=dict)
    terminated: bool = False

    def clone(self) -> "FlowState":
        return FlowState(dict(self.values), self.terminated)


@dataclass
class AnalysisContext:
    function_key: str
    params: dict[int, TaintValue]
    call_path: tuple[str, ...]
    endpoint: EndpointInfo | None
    depth: int


_BUILTIN_SOURCES = {
    "input": "stdin",
    # Flask / Werkzeug
    "request.args.get": "http.query",
    "request.form.get": "http.form",
    "request.json.get": "http.json",
    "request.get_json": "http.json",
    # Django / DRF
    "request.GET.get": "http.query",
    "request.POST.get": "http.form",
    "request.data.get": "http.body",
    "request.query_params.get": "http.query",
    # Starlette / FastAPI Request objects
    "request.path_params.get": "http.path",
    "request.cookies.get": "http.cookie",
    "request.headers.get": "http.header",
}
_BUILTIN_SANITIZERS = {
    # Numeric coercion removes the grammar characters needed by the built-in
    # injection/path/URL sinks. Custom sanitizers remain universal for
    # backwards compatibility with existing .dede.yml files.
    "int",
    "float",
}
_CONTEXT_SANITIZERS: dict[str, frozenset[str]] = {
    # Context-specific sanitizers must not erase taint globally. For example,
    # shlex.quote protects a shell argument but does not make the value safe
    # for SQL, filesystem paths, URLs, templates or deserialization.
    "shlex.quote": frozenset({"command-execution"}),
    "werkzeug.utils.secure_filename": frozenset({"path-traversal"}),
    "secure_filename": frozenset({"path-traversal"}),
    "os.path.basename": frozenset({"path-traversal"}),
}
_BUILTIN_SINKS = {
    "eval": SinkSpec("code-execution", "CWE-95", Severity.CRITICAL),
    "exec": SinkSpec("code-execution", "CWE-95", Severity.CRITICAL),
    "os.system": SinkSpec("command-execution", "CWE-78", Severity.CRITICAL),
    "os.popen": SinkSpec("command-execution", "CWE-78", Severity.HIGH),
    "subprocess.call": SinkSpec(
        "command-execution", "CWE-78", Severity.HIGH, require_shell_true=True
    ),
    "subprocess.run": SinkSpec(
        "command-execution", "CWE-78", Severity.HIGH, require_shell_true=True
    ),
    "subprocess.Popen": SinkSpec(
        "command-execution", "CWE-78", Severity.HIGH, require_shell_true=True
    ),
    "cursor.execute": SinkSpec("sql-execution", "CWE-89", Severity.HIGH),
    "cursor.executemany": SinkSpec("sql-execution", "CWE-89", Severity.HIGH),
    "db.execute": SinkSpec("sql-execution", "CWE-89", Severity.HIGH),
    "db.executemany": SinkSpec("sql-execution", "CWE-89", Severity.HIGH),
    "connection.execute": SinkSpec("sql-execution", "CWE-89", Severity.HIGH),
    "connection.executemany": SinkSpec("sql-execution", "CWE-89", Severity.HIGH),
    "session.execute": SinkSpec("sql-execution", "CWE-89", Severity.HIGH),
    "engine.execute": SinkSpec("sql-execution", "CWE-89", Severity.HIGH),
    "requests.get": SinkSpec("ssrf", "CWE-918", Severity.HIGH),
    "requests.post": SinkSpec("ssrf", "CWE-918", Severity.HIGH),
    "requests.put": SinkSpec("ssrf", "CWE-918", Severity.HIGH),
    "requests.patch": SinkSpec("ssrf", "CWE-918", Severity.HIGH),
    "requests.delete": SinkSpec("ssrf", "CWE-918", Severity.HIGH),
    "requests.head": SinkSpec("ssrf", "CWE-918", Severity.HIGH),
    "requests.request": SinkSpec("ssrf", "CWE-918", Severity.HIGH, argument=1),
    "httpx.get": SinkSpec("ssrf", "CWE-918", Severity.HIGH),
    "httpx.post": SinkSpec("ssrf", "CWE-918", Severity.HIGH),
    "httpx.put": SinkSpec("ssrf", "CWE-918", Severity.HIGH),
    "httpx.patch": SinkSpec("ssrf", "CWE-918", Severity.HIGH),
    "httpx.delete": SinkSpec("ssrf", "CWE-918", Severity.HIGH),
    "httpx.request": SinkSpec("ssrf", "CWE-918", Severity.HIGH, argument=1),
    "urllib.request.urlopen": SinkSpec("ssrf", "CWE-918", Severity.HIGH),
    "open": SinkSpec("path-traversal", "CWE-22", Severity.HIGH),
    "os.remove": SinkSpec("path-traversal", "CWE-22", Severity.HIGH),
    "os.unlink": SinkSpec("path-traversal", "CWE-22", Severity.HIGH),
    "os.rename": SinkSpec("path-traversal", "CWE-22", Severity.HIGH),
    "shutil.copy": SinkSpec("path-traversal", "CWE-22", Severity.HIGH),
    "shutil.move": SinkSpec("path-traversal", "CWE-22", Severity.HIGH),
    "flask.send_file": SinkSpec("path-traversal", "CWE-22", Severity.HIGH),
    "send_file": SinkSpec("path-traversal", "CWE-22", Severity.HIGH),
    "pickle.loads": SinkSpec("unsafe-deserialization", "CWE-502", Severity.CRITICAL),
    "pickle.load": SinkSpec("unsafe-deserialization", "CWE-502", Severity.CRITICAL),
    "dill.loads": SinkSpec("unsafe-deserialization", "CWE-502", Severity.CRITICAL),
    "dill.load": SinkSpec("unsafe-deserialization", "CWE-502", Severity.CRITICAL),
    "joblib.load": SinkSpec("unsafe-deserialization", "CWE-502", Severity.HIGH),
    "marshal.loads": SinkSpec("unsafe-deserialization", "CWE-502", Severity.HIGH),
    "yaml.load": SinkSpec("unsafe-deserialization", "CWE-502", Severity.HIGH),
    "yaml.unsafe_load": SinkSpec("unsafe-deserialization", "CWE-502", Severity.CRITICAL),
    "render_template_string": SinkSpec("template-injection", "CWE-1336", Severity.HIGH),
    "jinja2.Template": SinkSpec("template-injection", "CWE-1336", Severity.HIGH),
    "Template": SinkSpec("template-injection", "CWE-1336", Severity.HIGH),
    "ldap3.Connection.search": SinkSpec("ldap-injection", "CWE-90", Severity.HIGH, argument=1),
    "lxml.etree.XPath": SinkSpec("xpath-injection", "CWE-643", Severity.HIGH),
    "pymongo.collection.Collection.find": SinkSpec("nosql-injection", "CWE-943", Severity.HIGH),
    "pymongo.collection.Collection.find_one": SinkSpec("nosql-injection", "CWE-943", Severity.HIGH),
    "collection.find": SinkSpec("nosql-injection", "CWE-943", Severity.HIGH),
    "collection.find_one": SinkSpec("nosql-injection", "CWE-943", Severity.HIGH),
    "ldap.search": SinkSpec("ldap-injection", "CWE-90", Severity.HIGH, argument=1),
    "ldap_conn.search": SinkSpec("ldap-injection", "CWE-90", Severity.HIGH, argument=1),
    "tree.xpath": SinkSpec("xpath-injection", "CWE-643", Severity.HIGH),
    "doc.xpath": SinkSpec("xpath-injection", "CWE-643", Severity.HIGH),
    "flask.redirect": SinkSpec("open-redirect", "CWE-601", Severity.MEDIUM),
    "redirect": SinkSpec("open-redirect", "CWE-601", Severity.MEDIUM),
    "logging.debug": SinkSpec("sensitive-data-log", "CWE-532", Severity.HIGH),
    "logging.info": SinkSpec("sensitive-data-log", "CWE-532", Severity.HIGH),
    "logging.warning": SinkSpec("sensitive-data-log", "CWE-532", Severity.HIGH),
    "logging.error": SinkSpec("sensitive-data-log", "CWE-532", Severity.HIGH),
    "logger.debug": SinkSpec("sensitive-data-log", "CWE-532", Severity.HIGH),
    "logger.info": SinkSpec("sensitive-data-log", "CWE-532", Severity.HIGH),
    "logger.warning": SinkSpec("sensitive-data-log", "CWE-532", Severity.HIGH),
    "logger.error": SinkSpec("sensitive-data-log", "CWE-532", Severity.HIGH),
}
_PROPAGATING_CALLS = {
    "str",
    "repr",
    "bytes",
    "format",
}
_PROPAGATING_METHODS = {
    "strip",
    "lstrip",
    "rstrip",
    "lower",
    "upper",
    "replace",
    "join",
    "format",
    "encode",
    "decode",
}
_SECRET_KEY_RE = re.compile(r"(?i)(?:password|passwd|secret|api[_-]?key|(?:api|access|refresh|reset)?[_-]?token|authorization|private[_-]?key|session[_-]?id)")

_AUTH_DECORATOR_MARKERS = {
    "login_required",
    "requires_auth",
    "require_auth",
    "authenticated",
    "permission_required",
    "jwt_required",
}


def _name(node: ast.AST | None) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        left = _name(node.value)
        return f"{left}.{node.attr}" if left else node.attr
    return ""


def _module_name(path: str) -> str:
    value = path.replace("\\", "/")
    if value.endswith("/__init__.py"):
        value = value[: -len("/__init__.py")]
    elif value.endswith(".py"):
        value = value[:-3]
    return value.replace("/", ".").strip(".") or "__root__"


def _relative_import(module: str, imported: str | None, level: int) -> str:
    if not level:
        return imported or ""
    parts = module.split(".")[:-1]
    trim = max(0, level - 1)
    if trim:
        parts = parts[: max(0, len(parts) - trim)]
    if imported:
        parts.extend(imported.split("."))
    return ".".join(part for part in parts if part)


def _literal_string(node: ast.AST) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return ""


def _literal_methods(node: ast.Call, decorator_name: str) -> tuple[str, ...]:
    method = decorator_name.rsplit(".", 1)[-1].upper()
    if method in {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}:
        return (method,)
    for kw in node.keywords:
        if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple, ast.Set)):
            values = tuple(
                value.upper()
                for item in kw.value.elts
                if (value := _literal_string(item))
            )
            if values:
                return values
    return ()


def _endpoint_for(node: ast.FunctionDef | ast.AsyncFunctionDef) -> EndpointInfo | None:
    endpoint: EndpointInfo | None = None
    auth = False
    # FastAPI commonly expresses authentication/authorization as Depends(...)
    # defaults rather than decorators. Treat obvious auth/user/permission
    # dependency names as an authentication boundary without executing code.
    defaults = [*node.args.defaults, *node.args.kw_defaults]
    for default in defaults:
        if not isinstance(default, ast.Call):
            continue
        if _name(default.func).rsplit(".", 1)[-1] != "Depends" or not default.args:
            continue
        dependency = _name(default.args[0]).lower()
        if any(marker in dependency for marker in ("auth", "current_user", "permission", "jwt", "principal")):
            auth = True
    for decorator in node.decorator_list:
        call = decorator if isinstance(decorator, ast.Call) else None
        name = _name(call.func if call else decorator)
        tail = name.rsplit(".", 1)[-1].lower()
        if tail in _AUTH_DECORATOR_MARKERS or any(marker in tail for marker in ("auth", "permission")):
            auth = True
        if not call or not call.args:
            continue
        if tail not in {"route", "get", "post", "put", "patch", "delete", "options", "head"}:
            continue
        path = _literal_string(call.args[0])
        if not path:
            continue
        endpoint = EndpointInfo(
            path=path,
            methods=_literal_methods(call, name),
            authentication_required=auth,
        )
    if endpoint and auth and endpoint.authentication_required is not True:
        endpoint = EndpointInfo(endpoint.path, endpoint.methods, True)
    return endpoint


def _collect_aliases(tree: ast.Module, module: str) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for item in node.names:
                aliases[item.asname or item.name.split(".")[0]] = item.name
        elif isinstance(node, ast.ImportFrom):
            base = _relative_import(module, node.module, node.level)
            for item in node.names:
                if item.name == "*":
                    continue
                target = f"{base}.{item.name}" if base else item.name
                aliases[item.asname or item.name] = target
    return aliases


def _target_names(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, ast.Attribute):
        name = _name(node)
        return [name] if name else []
    if isinstance(node, (ast.Tuple, ast.List)):
        result: list[str] = []
        for item in node.elts:
            result.extend(_target_names(item))
        return result
    return []


def _function_key(module: str, name: str, class_name: str = "") -> str:
    return f"{module}.{class_name + '.' if class_name else ''}{name}"


def _discover_functions(
    tree: ast.Module,
    module: str,
    file: str,
    aliases: dict[str, str],
) -> dict[str, FunctionInfo]:
    result: dict[str, FunctionInfo] = {}
    module_key = f"{module}::<module>"
    result[module_key] = FunctionInfo(
        key=module_key,
        module=module,
        file=file,
        name="<module>",
        qualname="<module>",
        node=tree,
        params=(),
        aliases=aliases,
    )
    for item in tree.body:
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            key = _function_key(module, item.name)
            result[key] = FunctionInfo(
                key=key,
                module=module,
                file=file,
                name=item.name,
                qualname=item.name,
                node=item,
                params=tuple(arg.arg for arg in (*item.args.posonlyargs, *item.args.args, *item.args.kwonlyargs)),
                aliases=aliases,
                endpoint=_endpoint_for(item),
            )
        elif isinstance(item, ast.ClassDef):
            for child in item.body:
                if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                key = _function_key(module, child.name, item.name)
                result[key] = FunctionInfo(
                    key=key,
                    module=module,
                    file=file,
                    name=child.name,
                    qualname=f"{item.name}.{child.name}",
                    node=child,
                    params=tuple(arg.arg for arg in (*child.args.posonlyargs, *child.args.args, *child.args.kwonlyargs)),
                    aliases=aliases,
                    class_name=item.name,
                    endpoint=_endpoint_for(child),
                )
    return result


def _expand_alias(raw: str, info: FunctionInfo) -> str:
    """Expand the first segment of an imported external symbol deterministically."""
    if not raw:
        return raw
    first, *rest = raw.split(".")
    mapped = info.aliases.get(first)
    if not mapped:
        return raw
    return ".".join([mapped, *rest]) if rest else mapped


def _resolve_call(raw: str, info: FunctionInfo, project: PythonProjectModel) -> str:
    if not raw:
        return ""
    candidates: list[str] = []
    if raw.startswith("self.") and info.class_name:
        candidates.append(_function_key(info.module, raw.split(".", 1)[1], info.class_name))
    first, *rest = raw.split(".")
    if first in info.aliases:
        mapped = info.aliases[first]
        candidates.append(".".join([mapped, *rest]) if rest else mapped)
    if "." not in raw:
        if info.class_name:
            candidates.append(_function_key(info.module, raw, info.class_name))
        candidates.append(_function_key(info.module, raw))
    candidates.append(raw)
    for candidate in candidates:
        if candidate in project.functions:
            return candidate
    # A from-import alias may already be a fully qualified function.
    for candidate in candidates:
        matches = [key for key in project.functions if key == candidate or key.endswith(f".{candidate}")]
        if len(matches) == 1:
            return matches[0]
    return ""


def _dependency_graph(
    aliases: dict[str, dict[str, str]],
    files_by_module: dict[str, str],
) -> dict[str, list[str]]:
    graph: dict[str, set[str]] = {}
    module_by_file = {file: module for module, file in files_by_module.items()}
    for file, module in module_by_file.items():
        deps: set[str] = set()
        for target in aliases.get(file, {}).values():
            parts = target.split(".")
            for end in range(len(parts), 0, -1):
                candidate = ".".join(parts[:end])
                if candidate in files_by_module and files_by_module[candidate] != file:
                    deps.add(files_by_module[candidate])
                    break
        graph[file] = deps
    return {file: sorted(values) for file, values in graph.items()}


def build_python_project(project: ProjectContext) -> PythonProjectModel:
    root = Path(project.root)
    trees: dict[str, ast.Module] = {}
    sources: dict[str, list[str]] = {}
    modules: dict[str, str] = {}
    files_by_module: dict[str, str] = {}
    parse_errors = 0
    for value in project.files:
        path = Path(value)
        if path.suffix.lower() != ".py":
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            rel = path.resolve().relative_to(root.resolve()).as_posix()
            tree = ast.parse(text, filename=rel)
        except (OSError, SyntaxError, ValueError):
            parse_errors += 1
            continue
        module = _module_name(rel)
        trees[rel] = tree
        sources[rel] = text.splitlines()
        modules[rel] = module
        files_by_module[module] = rel
    aliases = {file: _collect_aliases(tree, modules[file]) for file, tree in trees.items()}
    functions: dict[str, FunctionInfo] = {}
    for file, tree in trees.items():
        functions.update(_discover_functions(tree, modules[file], file, aliases[file]))
    return PythonProjectModel(
        root=root,
        trees=trees,
        sources=sources,
        modules=modules,
        files_by_module=files_by_module,
        aliases=aliases,
        functions=functions,
        dependencies=_dependency_graph(aliases, files_by_module),
        parse_errors=parse_errors,
    )


def _source_kind(expr: ast.AST, sources: dict[str, str]) -> str:
    if isinstance(expr, ast.Call):
        call = _name(expr.func)
        if call in sources:
            return sources[call]
        if call in {"os.getenv", "os.environ.get"} and expr.args:
            key = _literal_string(expr.args[0])
            if key and _SECRET_KEY_RE.search(key):
                return "secret.environment"
    if isinstance(expr, ast.Subscript):
        base = _name(expr.value)
        if base == "os.environ":
            key = _literal_string(expr.slice)
            if key and _SECRET_KEY_RE.search(key):
                return "secret.environment"
        if base in {
            "request.args", "request.form", "request.GET", "request.POST",
            "request.query_params", "request.path_params", "request.headers",
            "request.cookies", "sys.argv",
        }:
            if base == "request.query_params":
                return "http.query"
            if base == "request.path_params":
                return "http.path"
            if base == "request.headers":
                return "http.header"
            if base == "request.cookies":
                return "http.cookie"
            return "http.input" if base.startswith("request.") else "process.argv"
    return ""


def _symbolic_expr(
    expr: ast.AST,
    state: dict[str, SymbolicValue],
    info: FunctionInfo,
    project: PythonProjectModel,
    summaries: dict[str, FunctionSummary],
    sources: dict[str, str],
    sanitizers: set[str],
) -> SymbolicValue:
    source = _source_kind(expr, sources)
    if source:
        return SymbolicValue(sources=frozenset({source}))
    if isinstance(expr, ast.Name):
        return state.get(expr.id, SymbolicValue())
    if isinstance(expr, ast.Attribute):
        return state.get(_name(expr), _symbolic_expr(expr.value, state, info, project, summaries, sources, sanitizers))
    if isinstance(expr, ast.Constant):
        return SymbolicValue()
    if isinstance(expr, ast.Call):
        raw = _name(expr.func)
        if raw in sanitizers:
            return SymbolicValue()
        callee = _resolve_call(raw, info, project)
        summary = summaries.get(callee)
        result = SymbolicValue()
        if summary:
            result = SymbolicValue(sources=frozenset(summary.source_kinds))
            for index in summary.passthrough_params:
                if index < len(expr.args):
                    result = result.merge(
                        _symbolic_expr(expr.args[index], state, info, project, summaries, sources, sanitizers)
                    )
            return result
        receiver = _symbolic_expr(expr.func.value, state, info, project, summaries, sources, sanitizers) if isinstance(expr.func, ast.Attribute) else SymbolicValue()
        if raw in _PROPAGATING_CALLS or raw.rsplit(".", 1)[-1] in _PROPAGATING_METHODS:
            result = receiver
            for arg in expr.args:
                result = result.merge(_symbolic_expr(arg, state, info, project, summaries, sources, sanitizers))
            return result
        return SymbolicValue()
    result = SymbolicValue()
    for child in ast.iter_child_nodes(expr):
        result = result.merge(_symbolic_expr(child, state, info, project, summaries, sources, sanitizers))
    return result


def _summary_for(
    info: FunctionInfo,
    project: PythonProjectModel,
    summaries: dict[str, FunctionSummary],
    sources: dict[str, str],
    sanitizers: set[str],
) -> FunctionSummary:
    if isinstance(info.node, ast.Module):
        return FunctionSummary()
    state = {name: SymbolicValue(params=frozenset({index})) for index, name in enumerate(info.params)}
    returns = SymbolicValue()

    def process(statements: Iterable[ast.stmt], local: dict[str, SymbolicValue]) -> dict[str, SymbolicValue]:
        nonlocal returns
        for stmt in statements:
            if isinstance(stmt, ast.Assign):
                value = _symbolic_expr(stmt.value, local, info, project, summaries, sources, sanitizers)
                for target in stmt.targets:
                    for name in _target_names(target):
                        local[name] = value
            elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
                value = _symbolic_expr(stmt.value, local, info, project, summaries, sources, sanitizers)
                for name in _target_names(stmt.target):
                    local[name] = value
            elif isinstance(stmt, ast.Return) and stmt.value is not None:
                returns = returns.merge(
                    _symbolic_expr(stmt.value, local, info, project, summaries, sources, sanitizers)
                )
            elif isinstance(stmt, ast.If):
                left = process(stmt.body, dict(local))
                right = process(stmt.orelse, dict(local))
                for name in set(left) | set(right):
                    local[name] = left.get(name, SymbolicValue()).merge(right.get(name, SymbolicValue()))
            elif isinstance(stmt, (ast.For, ast.While)):
                branch = process(stmt.body, dict(local))
                for name, value in branch.items():
                    local[name] = local.get(name, SymbolicValue()).merge(value)
            elif isinstance(stmt, ast.Try):
                branches = [process(stmt.body, dict(local))]
                branches.extend(process(handler.body, dict(local)) for handler in stmt.handlers)
                for branch in branches:
                    for name, value in branch.items():
                        local[name] = local.get(name, SymbolicValue()).merge(value)
        return local

    process(info.node.body, state)
    return FunctionSummary(
        returns_source=bool(returns.sources),
        passthrough_params=set(returns.params),
        source_kinds=set(returns.sources),
    )


def _summaries(
    project: PythonProjectModel,
    sources: dict[str, str] | None = None,
    sanitizers: set[str] | None = None,
) -> dict[str, FunctionSummary]:
    source_models = sources or dict(_BUILTIN_SOURCES)
    sanitizer_models = sanitizers or set(_BUILTIN_SANITIZERS)
    result = {key: FunctionSummary() for key in project.functions}
    for _ in range(12):
        changed = False
        for key, info in project.functions.items():
            summary = _summary_for(info, project, result, source_models, sanitizer_models)
            if summary != result[key]:
                result[key] = summary
                changed = True
        if not changed:
            break
    return result


def _statement_id(info: FunctionInfo, stmt: ast.stmt, suffix: str = "") -> str:
    return f"{info.key}:{getattr(stmt, 'lineno', 1)}:{type(stmt).__name__}{suffix}"


def _cfg_edges(info: FunctionInfo) -> list[IRCFGEdge]:
    if isinstance(info.node, ast.Module):
        statements = info.node.body
    else:
        statements = info.node.body
    edges: list[IRCFGEdge] = []

    def sequence(items: list[ast.stmt]) -> tuple[str, list[str]]:
        first = ""
        exits: list[str] = []
        previous: list[str] = []
        for stmt in items:
            node_id = _statement_id(info, stmt)
            if not first:
                first = node_id
            for src in previous:
                edges.append(IRCFGEdge(info.key, src, node_id, "next"))
            if isinstance(stmt, ast.If):
                body_first, body_exits = sequence(stmt.body)
                else_first, else_exits = sequence(stmt.orelse)
                if body_first:
                    edges.append(IRCFGEdge(info.key, node_id, body_first, "true"))
                if else_first:
                    edges.append(IRCFGEdge(info.key, node_id, else_first, "false"))
                previous = [*(body_exits or [node_id]), *(else_exits or ([node_id] if not stmt.orelse else []))]
            elif isinstance(stmt, (ast.For, ast.While)):
                body_first, body_exits = sequence(stmt.body)
                if body_first:
                    edges.append(IRCFGEdge(info.key, node_id, body_first, "loop"))
                    for src in body_exits:
                        edges.append(IRCFGEdge(info.key, src, node_id, "back"))
                previous = [node_id]
            elif isinstance(stmt, (ast.Return, ast.Raise)):
                previous = []
            else:
                previous = [node_id]
        exits.extend(previous)
        return first, exits

    sequence(statements)
    return edges


class _CallCollector(ast.NodeVisitor):
    def __init__(self) -> None:
        self.calls: list[ast.Call] = []

    def visit_Call(self, node: ast.Call) -> None:
        self.calls.append(node)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        return


def _function_calls(info: FunctionInfo, project: PythonProjectModel) -> list[IRCallEdge]:
    collector = _CallCollector()
    body = info.node.body if not isinstance(info.node, ast.Module) else info.node.body
    for stmt in body:
        collector.visit(stmt)
    result: list[IRCallEdge] = []
    for call in collector.calls:
        raw = _name(call.func)
        resolved = _resolve_call(raw, info, project)
        result.append(
            IRCallEdge(
                caller=info.key,
                callee=resolved or raw,
                file=info.file,
                line=getattr(call, "lineno", 1),
                resolved=bool(resolved),
            )
        )
    return result


def _build_ir(project: PythonProjectModel, summaries: dict[str, FunctionSummary]) -> SecurityIR:
    functions: list[IRFunction] = []
    endpoints: list[IREndpoint] = []
    calls: list[IRCallEdge] = []
    cfg: list[IRCFGEdge] = []
    for key in sorted(project.functions):
        info = project.functions[key]
        summary = summaries.get(key, FunctionSummary())
        node = info.node
        functions.append(
            IRFunction(
                id=key,
                language="Python",
                module=info.module,
                file=info.file,
                name=info.name,
                qualified_name=info.qualname,
                parameters=info.params,
                class_name=info.class_name,
                start_line=getattr(node, "lineno", 1),
                end_line=getattr(node, "end_lineno", getattr(node, "lineno", 1)),
                return_source_kinds=tuple(sorted(summary.source_kinds)),
                passthrough_params=tuple(sorted(summary.passthrough_params)),
                endpoint=info.endpoint.path if info.endpoint else "",
                http_methods=info.endpoint.methods if info.endpoint else (),
                authentication_required=(info.endpoint.authentication_required if info.endpoint else None),
            )
        )
        if info.endpoint:
            endpoints.append(
                IREndpoint(
                    function=key,
                    file=info.file,
                    line=getattr(node, "lineno", 1),
                    path=info.endpoint.path,
                    methods=info.endpoint.methods,
                    authentication_required=info.endpoint.authentication_required,
                )
            )
        calls.extend(_function_calls(info, project))
        cfg.extend(_cfg_edges(info))
    return SecurityIR(
        language="Python",
        functions=functions,
        calls=calls,
        cfg_edges=cfg,
        endpoints=endpoints,
        dependencies=project.dependencies,
        stats={
            "modules": len(project.trees),
            "functions": len(functions),
            "call_edges": len(calls),
            "resolved_call_edges": sum(1 for call in calls if call.resolved),
            "cfg_edges": len(cfg),
            "endpoints": len(endpoints),
        },
    )


def _empty_taint() -> TaintValue:
    return TaintValue(frozenset(), ())


def _endpoint_param_taint(info: FunctionInfo) -> dict[int, TaintValue]:
    """Seed actual endpoint input parameters while excluding injected objects.

    FastAPI/Django endpoints frequently mix attacker-controlled path/query/body
    values with dependency-injected database sessions, principals and framework
    objects. Treating every parameter as HTTP input caused noisy flows such as
    ``Session.execute`` where the *session object* itself was marked tainted.
    We now use defaults and annotations to separate injected infrastructure from
    request data without relying on fragile parameter names like ``user``.
    """
    result: dict[int, TaintValue] = {}
    if not info.endpoint or isinstance(info.node, ast.Module):
        return result

    node = info.node
    positional = [*node.args.posonlyargs, *node.args.args]
    defaults: dict[str, ast.AST | None] = {arg.arg: None for arg in positional}
    if node.args.defaults:
        for arg, default in zip(positional[-len(node.args.defaults):], node.args.defaults):
            defaults[arg.arg] = default
    for arg, default in zip(node.args.kwonlyargs, node.args.kw_defaults):
        defaults[arg.arg] = default

    annotations: dict[str, str] = {}
    for arg in [*positional, *node.args.kwonlyargs]:
        annotations[arg.arg] = _name(arg.annotation) if arg.annotation is not None else ""

    framework_types = {
        "Request", "Response", "Session", "AsyncSession", "BackgroundTasks",
        "WebSocket", "UploadFile", "HTTPConnection", "SecurityScopes",
    }
    line = getattr(node, "lineno", 1)
    for index, name in enumerate(info.params):
        lowered = name.lower()
        if lowered in {"self", "cls"}:
            continue
        default = defaults.get(name)
        if isinstance(default, ast.Call) and _name(default.func).rsplit(".", 1)[-1] in {"Depends", "Security"}:
            continue
        annotation = annotations.get(name, "").rsplit(".", 1)[-1]
        if annotation in framework_types:
            continue
        # Request objects are modeled through request.args/query_params/etc.,
        # not as a scalar tainted value. This preserves field-sensitive traces.
        if lowered in {"request", "response", "websocket"}:
            continue
        step = DataflowStep(
            kind="source",
            file=info.file,
            start_line=line,
            end_line=line,
            content="",
            symbol=f"endpoint-parameter:{name}",
        )
        result[index] = TaintValue(frozenset({"http.parameter"}), (step,))
    return result


def _merge_states(states: list[FlowState]) -> FlowState:
    alive = [state for state in states if not state.terminated]
    if not alive:
        return FlowState(terminated=True)
    merged: dict[str, TaintValue] = {}
    for state in alive:
        for name, value in state.values.items():
            merged[name] = merged.get(name, _empty_taint()).merge(value)
    return FlowState(merged, False)


def _guard_clean_variables(expr: ast.AST) -> tuple[set[str], set[str]]:
    """Return variables clean on (true branch, false branch)."""
    if isinstance(expr, ast.UnaryOp) and isinstance(expr.op, ast.Not):
        false_clean, true_clean = _guard_clean_variables(expr.operand)
        return true_clean, false_clean
    if isinstance(expr, ast.Call):
        raw = _name(expr.func)
        if isinstance(expr.func, ast.Attribute) and expr.func.attr in {"isdigit", "isnumeric", "isdecimal"}:
            receiver = _name(expr.func.value)
            return ({receiver} if receiver else set(), set())
        if raw == "isinstance" and expr.args:
            variable = _name(expr.args[0])
            if variable:
                return {variable}, set()
    return set(), set()


class _ContextAnalyzer:
    def __init__(
        self,
        project: PythonProjectModel,
        summaries: dict[str, FunctionSummary],
        sources: dict[str, str],
        sanitizers: set[str],
        sinks: dict[str, SinkSpec],
        enqueue: Callable[[AnalysisContext], None],
        max_depth: int,
    ) -> None:
        self.project = project
        self.summaries = summaries
        self.sources = sources
        self.sanitizers = sanitizers
        self.sinks = sinks
        self.enqueue = enqueue
        self.max_depth = max_depth
        self.findings: list[Finding] = []

    def _line(self, info: FunctionInfo, node: ast.AST) -> str:
        line = getattr(node, "lineno", 1)
        source = self.project.sources.get(info.file, [])
        if 1 <= line <= len(source):
            return source[line - 1].strip()
        return ""

    def _step(self, kind: str, info: FunctionInfo, node: ast.AST, symbol: str = "") -> DataflowStep:
        return DataflowStep(
            kind=kind,
            file=info.file,
            start_line=getattr(node, "lineno", 1),
            end_line=getattr(node, "end_lineno", getattr(node, "lineno", 1)),
            content=self._line(info, node),
            symbol=symbol,
        )

    def _source(self, info: FunctionInfo, expr: ast.AST) -> TaintValue:
        kind = _source_kind(expr, self.sources)
        if not kind and isinstance(expr, ast.Call):
            kind = self.sources.get(_expand_alias(_name(expr.func), info), "")
        if not kind:
            return _empty_taint()
        return TaintValue(frozenset({kind}), (self._step("source", info, expr, kind),))

    def _sink_match(self, raw: str) -> tuple[SinkSpec | None, bool]:
        """Resolve a sink and report whether the match is exact.

        Earlier versions treated every ``*.execute`` method as SQL. That was
        convenient but noisy (thread pools, task executors, RPC clients, etc.
        also expose ``execute``). Receiver-agnostic matching is now restricted
        to conventional database receiver names; unusual project APIs should
        be modeled explicitly in ``semantic.sinks``.
        """
        if raw in self.sinks:
            return self.sinks[raw], True
        method = raw.rsplit(".", 1)[-1]
        if method not in {"execute", "executemany"} or "." not in raw:
            return None, False
        receiver = raw.rsplit(".", 1)[0].rsplit(".", 1)[-1].lower()
        database_receivers = {
            "cursor", "cur", "db", "database", "conn", "connection",
            "session", "engine", "sql", "sql_db", "sqldb",
        }
        if receiver not in database_receivers:
            return None, False
        for name, spec in self.sinks.items():
            if spec.kind == "sql-execution" and name.rsplit(".", 1)[-1] == method:
                return spec, False
        return None, False

    @staticmethod
    def _fixed_url_origin(expr: ast.AST) -> bool:
        """Return True when an HTTP(S) URL has a statically fixed authority.

        Taint in a path/query below a constant origin is not SSRF. This small
        structural proof removes a common SAST false positive while remaining
        conservative: if the host can be formatted or concatenated from input,
        the function returns False.
        """
        def fixed(prefix: str) -> bool:
            try:
                parsed = urlsplit(prefix)
            except ValueError:
                return False
            return parsed.scheme in {"http", "https"} and bool(parsed.netloc)

        if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
            return fixed(expr.value)
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
            # A fixed absolute URL on the left locks the authority before any
            # later concatenated user-controlled path/query component.
            return _ContextAnalyzer._fixed_url_origin(expr.left)
        if isinstance(expr, ast.JoinedStr):
            prefix = ""
            for value in expr.values:
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    prefix += value.value
                    if fixed(prefix):
                        return True
                    continue
                # Dynamic content before a proven authority can control host.
                break
            return fixed(prefix)
        if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) and expr.func.attr == "format":
            template = expr.func.value
            if isinstance(template, ast.Constant) and isinstance(template.value, str):
                prefix = template.value.split("{", 1)[0]
                return fixed(prefix)
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Mod):
            if isinstance(expr.left, ast.Constant) and isinstance(expr.left.value, str):
                prefix = expr.left.value.split("%", 1)[0]
                return fixed(prefix)
        return False

    @staticmethod
    def _safe_yaml_loader(expr: ast.Call, raw: str) -> bool:
        if raw != "yaml.load":
            return False
        safe_names = {"yaml.SafeLoader", "yaml.CSafeLoader", "SafeLoader", "CSafeLoader"}
        if len(expr.args) > 1 and _name(expr.args[1]) in safe_names:
            return True
        return any(kw.arg == "Loader" and _name(kw.value) in safe_names for kw in expr.keywords)

    def _eval(
        self,
        expr: ast.AST,
        state: FlowState,
        info: FunctionInfo,
        context: AnalysisContext,
    ) -> TaintValue:
        direct = self._source(info, expr)
        if direct.tainted:
            return direct
        if isinstance(expr, ast.Name):
            return state.values.get(expr.id, _empty_taint())
        if isinstance(expr, ast.Attribute):
            exact = state.values.get(_name(expr))
            return exact or self._eval(expr.value, state, info, context)
        if isinstance(expr, ast.Constant):
            return _empty_taint()
        if isinstance(expr, ast.Subscript):
            return self._source(info, expr).merge(self._eval(expr.value, state, info, context))
        if isinstance(expr, ast.Call):
            raw = _name(expr.func)
            modeled_raw = _expand_alias(raw, info)
            universal_sanitizer = raw in self.sanitizers or modeled_raw in self.sanitizers
            args = [self._eval(arg, state, info, context) for arg in expr.args]
            keyword_values = {
                kw.arg: self._eval(kw.value, state, info, context)
                for kw in expr.keywords
                if kw.arg is not None
            }
            modeled_sink, modeled_exact = self._sink_match(modeled_raw)
            raw_sink, raw_exact = self._sink_match(raw)
            sink_name = modeled_raw if modeled_sink else raw
            sink = modeled_sink or raw_sink
            sink_exact = modeled_exact if modeled_sink else raw_exact
            if sink and sink.argument < len(args):
                shell_enabled = any(
                    kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                    for kw in expr.keywords
                )
                if (not sink.require_shell_true or shell_enabled) and not self._safe_yaml_loader(expr, sink_name):
                    value = args[sink.argument]
                    if sink.kind == "sensitive-data-log":
                        value = _empty_taint()
                        for candidate in args:
                            value = value.merge(candidate)
                    if value.tainted and sink.kind not in value.sanitized_for:
                        # A fixed HTTP(S) authority means only path/query data
                        # is attacker controlled, so this is not an SSRF flow.
                        if sink.kind != "ssrf" or not self._fixed_url_origin(expr.args[sink.argument]):
                            self._finding(
                                info, context, expr, sink_name, sink, value, exact_sink=sink_exact
                            )
            sanitizer_name = modeled_raw if modeled_raw in _CONTEXT_SANITIZERS else raw
            if universal_sanitizer:
                return _empty_taint()
            if sanitizer_name in _CONTEXT_SANITIZERS:
                result = _empty_taint()
                for value in args:
                    result = result.merge(value)
                if result.tainted:
                    return result.sanitized(
                        set(_CONTEXT_SANITIZERS[sanitizer_name]),
                        self._step("sanitizer", info, expr, sanitizer_name),
                    )
                return result

            callee = _resolve_call(raw, info, self.project)
            if callee:
                callee_info = self.project.functions[callee]
                tainted_params = {
                    index: value
                    for index, value in enumerate(args)
                    if value.tainted and index < len(callee_info.params)
                }
                for name, value in keyword_values.items():
                    if value.tainted and name in callee_info.params:
                        tainted_params[callee_info.params.index(name)] = value
                if tainted_params and context.depth < self.max_depth and callee not in context.call_path:
                    call_step = self._step("call", info, expr, callee)
                    propagated = {
                        index: value.with_step(call_step) for index, value in tainted_params.items()
                    }
                    self.enqueue(
                        AnalysisContext(
                            function_key=callee,
                            params=propagated,
                            call_path=(*context.call_path, callee),
                            endpoint=context.endpoint or callee_info.endpoint,
                            depth=context.depth + 1,
                        )
                    )
                summary = self.summaries.get(callee, FunctionSummary())
                result = _empty_taint()
                for source_kind in sorted(summary.source_kinds):
                    source_node = callee_info.node
                    source_line = getattr(source_node, "lineno", 1)
                    source_lines = self.project.sources.get(callee_info.file, [])
                    content = (
                        source_lines[source_line - 1].strip()
                        if 1 <= source_line <= len(source_lines)
                        else ""
                    )
                    source_step = DataflowStep(
                        kind="source",
                        file=callee_info.file,
                        start_line=source_line,
                        end_line=getattr(source_node, "end_lineno", source_line),
                        content=content,
                        symbol=f"{callee}:return:{source_kind}",
                    )
                    return_step = self._step("return", info, expr, callee)
                    result = result.merge(
                        TaintValue(
                            frozenset({source_kind}),
                            (source_step, return_step),
                        )
                    )
                for index in summary.passthrough_params:
                    value = _empty_taint()
                    if index < len(args):
                        value = args[index]
                    elif index < len(callee_info.params):
                        value = keyword_values.get(callee_info.params[index], _empty_taint())
                    if value.tainted:
                        result = result.merge(value.with_step(self._step("return", info, expr, callee)))
                return result
            receiver = self._eval(expr.func.value, state, info, context) if isinstance(expr.func, ast.Attribute) else _empty_taint()
            if raw in _PROPAGATING_CALLS or raw.rsplit(".", 1)[-1] in _PROPAGATING_METHODS:
                result = receiver
                for value in args:
                    result = result.merge(value)
                return result
            return _empty_taint()
        result = _empty_taint()
        for child in ast.iter_child_nodes(expr):
            result = result.merge(self._eval(child, state, info, context))
        return result

    def _finding(
        self,
        info: FunctionInfo,
        context: AnalysisContext,
        node: ast.Call,
        raw: str,
        sink: SinkSpec,
        value: TaintValue,
        *,
        exact_sink: bool = True,
    ) -> None:
        endpoint = context.endpoint or info.endpoint
        score = 90.0
        if endpoint:
            score += 6.0
            if endpoint.authentication_required is False:
                score += 4.0
            elif endpoint.authentication_required is True:
                score -= 4.0
        score = max(0.0, min(100.0, score))
        sink_step = self._step("sink", info, node, raw)
        ast_identity = sha256_text(ast.dump(node, include_attributes=False))
        methods = endpoint.methods if endpoint else ()
        primary_method = methods[0] if methods else ""
        confidence_score = 0.98 if exact_sink else 0.93
        precision = Precision.VERY_HIGH if exact_sink else Precision.HIGH
        self.findings.append(
            Finding(
                tool="dede-semantic-python",
                rule_id=f"dede.semantic.python.taint.{sink.kind}",
                category=Category.SECURITY,
                severity=sink.severity,
                confidence=Confidence.HIGH,
                confidence_score=confidence_score,
                precision=precision,
                cwe=[sink.cwe],
                file=info.file,
                start_line=getattr(node, "lineno", 1),
                end_line=getattr(node, "end_lineno", getattr(node, "lineno", 1)),
                message=f"Untrusted data reaches {raw}",
                recommendation="Validate input and use a structured/parameterized API instead of dynamic execution.",
                normalized_type=sink.kind,
                analysis_kind="semantic-taint",
                engine_version="semantic-python-v3",
                function=info.qualname,
                module=info.module,
                class_name=info.class_name,
                symbol=raw,
                source_kind=",".join(sorted(value.kinds)),
                sink_kind=raw,
                reachable=True,
                exploitability_score=score,
                dataflow=[*value.trace, sink_step][-32:],
                call_path=list(context.call_path),
                control_flow=[f"cfg:{info.key}"],
                evidence=[
                    Evidence(kind="ast", value="project-wide source-to-sink dataflow", confidence=0.97),
                    Evidence(kind="call-graph", value=" -> ".join(context.call_path), confidence=0.95),
                    Evidence(kind="sink", value=raw, confidence=1.0 if exact_sink else 0.93),
                    Evidence(
                        kind="sink-resolution",
                        value="exact model" if exact_sink else "restricted database receiver heuristic",
                        confidence=1.0 if exact_sink else 0.93,
                    ),
                ],
                ast_fingerprint=ast_identity,
                endpoint=endpoint.path if endpoint else "",
                http_method=primary_method,
                authentication_required=(endpoint.authentication_required if endpoint else None),
                internet_exposed=bool(endpoint),
                attack_surface=endpoint.labels if endpoint else [],
                attack_path=[*(endpoint.labels if endpoint else []), *context.call_path, raw],
            )
        )

    def _assign(
        self,
        target: ast.AST,
        value_node: ast.AST,
        state: FlowState,
        info: FunctionInfo,
        context: AnalysisContext,
    ) -> None:
        value = self._eval(value_node, state, info, context)
        if value.tainted:
            value = value.with_step(self._step("propagation", info, value_node, "assignment"))
        for name in _target_names(target):
            if value.tainted:
                state.values[name] = value
            else:
                state.values.pop(name, None)

    def _block(
        self,
        statements: Iterable[ast.stmt],
        state: FlowState,
        info: FunctionInfo,
        context: AnalysisContext,
    ) -> FlowState:
        for stmt in statements:
            if state.terminated:
                break
            if isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    self._assign(target, stmt.value, state, info, context)
            elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
                self._assign(stmt.target, stmt.value, state, info, context)
            elif isinstance(stmt, ast.AugAssign):
                synthetic = ast.BinOp(left=stmt.target, op=stmt.op, right=stmt.value)
                ast.copy_location(synthetic, stmt)
                self._assign(stmt.target, synthetic, state, info, context)
            elif isinstance(stmt, ast.Expr):
                self._eval(stmt.value, state, info, context)
            elif isinstance(stmt, ast.Return):
                if stmt.value is not None:
                    self._eval(stmt.value, state, info, context)
                state.terminated = True
            elif isinstance(stmt, ast.Raise):
                state.terminated = True
            elif isinstance(stmt, ast.If):
                self._eval(stmt.test, state, info, context)
                true_state = state.clone()
                false_state = state.clone()
                true_clean, false_clean = _guard_clean_variables(stmt.test)
                for name in true_clean:
                    true_state.values.pop(name, None)
                for name in false_clean:
                    false_state.values.pop(name, None)
                true_state = self._block(stmt.body, true_state, info, context)
                false_state = self._block(stmt.orelse, false_state, info, context)
                merged = _merge_states([true_state, false_state])
                state.values, state.terminated = merged.values, merged.terminated
            elif isinstance(stmt, (ast.For, ast.AsyncFor)):
                self._eval(stmt.iter, state, info, context)
                body = self._block(stmt.body, state.clone(), info, context)
                merged = _merge_states([state, body])
                state.values, state.terminated = merged.values, merged.terminated
            elif isinstance(stmt, ast.While):
                self._eval(stmt.test, state, info, context)
                body = self._block(stmt.body, state.clone(), info, context)
                merged = _merge_states([state, body])
                state.values, state.terminated = merged.values, merged.terminated
            elif isinstance(stmt, ast.Try):
                branches = [self._block(stmt.body, state.clone(), info, context)]
                branches.extend(self._block(handler.body, state.clone(), info, context) for handler in stmt.handlers)
                merged = _merge_states(branches)
                if stmt.finalbody:
                    merged = self._block(stmt.finalbody, merged, info, context)
                state.values, state.terminated = merged.values, merged.terminated
            elif isinstance(stmt, (ast.With, ast.AsyncWith)):
                for item in stmt.items:
                    self._eval(item.context_expr, state, info, context)
                state = self._block(stmt.body, state, info, context)
            elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            else:
                for child in ast.iter_child_nodes(stmt):
                    if isinstance(child, ast.expr):
                        self._eval(child, state, info, context)
        return state

    def analyze(self, context: AnalysisContext) -> None:
        info = self.project.functions[context.function_key]
        state = FlowState()
        for index, value in context.params.items():
            if index < len(info.params):
                state.values[info.params[index]] = value
        body = info.node.body if isinstance(info.node, ast.Module) else info.node.body
        self._block(body, state, info, context)


def _models(config: AppConfig, root: Path) -> tuple[dict[str, str], set[str], dict[str, SinkSpec]]:
    sources = dict(_BUILTIN_SOURCES)
    sanitizers = set(_BUILTIN_SANITIZERS)
    sinks = dict(_BUILTIN_SINKS)
    for source in config.semantic.sources:
        sources[source.call] = source.kind
    sanitizers.update(config.semantic.sanitizers)
    for sink in config.semantic.sinks:
        sinks[sink.call] = SinkSpec(
            kind=sink.kind,
            cwe=sink.cwe,
            severity=Severity(sink.severity),
            argument=sink.argument,
            require_shell_true=sink.require_shell_true,
        )
    packs = load_model_packs(config, root)
    pack_sources, pack_sinks, pack_sanitizers = language_models(packs, "python")
    for source in pack_sources:
        sources[str(source["call"])] = str(source.get("kind", "untrusted"))
    sanitizers.update(pack_sanitizers)
    for sink in pack_sinks:
        sinks[str(sink["call"])] = SinkSpec(
            kind=str(sink.get("kind", "custom-sink")),
            cwe=str(sink.get("cwe", "CWE-20")),
            severity=Severity(str(sink.get("severity", "HIGH")).upper()),
            argument=int(sink.get("argument", 0)),
            require_shell_true=bool(sink.get("require_shell_true", False)),
        )
    return sources, sanitizers, sinks


def analyze_python_project(
    project: PythonProjectModel,
    config: AppConfig,
    *,
    entry_files: set[str] | None = None,
) -> tuple[list[Finding], SecurityIR, int]:
    sources, sanitizers, sinks = _models(config, project.root)
    summaries = _summaries(project, sources, sanitizers)
    ir = _build_ir(project, summaries)
    queue: deque[AnalysisContext] = deque()
    for key, info in sorted(project.functions.items()):
        if entry_files is not None and info.file not in entry_files:
            continue
        params = (
            _endpoint_param_taint(info)
            if config.semantic.endpoint_parameters_as_sources and info.endpoint
            else {}
        )
        queue.append(
            AnalysisContext(
                function_key=key,
                params=params,
                call_path=(key,),
                endpoint=info.endpoint,
                depth=0,
            )
        )
    visited: set[tuple[str, tuple[int, ...], str]] = set()
    queued_contexts = 0

    def enqueue(context: AnalysisContext) -> None:
        nonlocal queued_contexts
        if len(visited) + len(queue) >= config.semantic.max_contexts:
            return
        queue.append(context)
        queued_contexts += 1

    runner = _ContextAnalyzer(
        project,
        summaries,
        sources,
        sanitizers,
        sinks,
        enqueue,
        config.semantic.max_call_depth,
    )
    while queue and len(visited) < config.semantic.max_contexts:
        context = queue.popleft()
        signature = (
            context.function_key,
            tuple(
                sorted(
                    (index, tuple(sorted(value.kinds)))
                    for index, value in context.params.items()
                )
            ),
            context.endpoint.path if context.endpoint else "",
        )
        if signature in visited:
            continue
        visited.add(signature)
        runner.analyze(context)
    findings = apply_flow_queries(runner.findings, config)
    ir.security_flows = [
        IRSecurityFlow(
            id=f.semantic_fingerprint or f.ast_fingerprint or f"{f.file}:{f.start_line}:{f.rule_id}",
            rule_id=f.rule_id,
            cwe=tuple(f.cwe),
            severity=f.severity.value,
            source_kind=f.source_kind,
            sink_kind=f.sink_kind,
            sink_file=f.file,
            sink_line=f.start_line,
            function=f.function,
            endpoint=f.endpoint,
            http_method=f.http_method,
            authentication_required=f.authentication_required,
            internet_exposed=f.internet_exposed,
            exploitability_score=f.exploitability_score,
            call_path=tuple(f.call_path),
            files=tuple(dict.fromkeys(step.file for step in f.dataflow)),
            query_matches=tuple(f.query_matches),
        )
        for f in findings
    ]
    ir.stats["security_flows"] = len(ir.security_flows)
    ir.stats["dedeql_matches"] = sum(len(f.query_matches) for f in findings)
    return findings, ir, len(visited)


class PythonSemanticAnalyzer(Analyzer):
    name = "dede-semantic-python"

    def supports(self, project: ProjectContext) -> bool:
        return project.has_python

    def version(self) -> str:
        return "3"

    def analyze(self, project: ProjectContext, config: AppConfig, raw_dir: Path) -> AnalyzerResult:
        if not config.semantic.enabled:
            return AnalyzerResult(
                tool=self.name,
                status=ToolStatus.SKIPPED,
                version=self.version(),
                message="Semantic analysis disabled by configuration",
            )
        model = build_python_project(project)
        raw_dir.mkdir(parents=True, exist_ok=True)
        project_cache_id = sha256_text(str(Path(project.root).resolve()))[:16]
        cache_path = raw_dir.parent / ".dede" / f"semantic-python-{project_cache_id}.json"
        signature = semantic_signature(
            {
                "project": str(Path(project.root).resolve()),
                "config": config.semantic.model_dump(mode="json"),
            },
            analyzer_version=self.version(),
        )
        cached = load_cache(cache_path, signature) if config.performance.semantic_cache else None
        affected = set(project.affected_files) & set(model.trees)
        use_incremental = cached is not None and bool(project.affected_files)
        cache_only = cached is not None and not project.changed_files and not project.affected_files

        if cache_only:
            findings = cached
            summaries = _summaries(model, *_models(config, model.root)[:2])
            ir = _build_ir(model, summaries)
            contexts = 0
            incremental_reused = len(cached)
        else:
            entry_files = affected if use_incremental else None
            fresh, ir, contexts = analyze_python_project(model, config, entry_files=entry_files)
            preserved = unaffected_cached_findings(cached or [], affected) if use_incremental else []
            findings = apply_flow_queries([*preserved, *fresh], config)
            # Rebuild exported flow records after cached/fresh merge.
            ir.security_flows = [
                IRSecurityFlow(
                    id=f.semantic_fingerprint or f.ast_fingerprint or f"{f.file}:{f.start_line}:{f.rule_id}",
                    rule_id=f.rule_id, cwe=tuple(f.cwe), severity=f.severity.value,
                    source_kind=f.source_kind, sink_kind=f.sink_kind, sink_file=f.file,
                    sink_line=f.start_line, function=f.function, endpoint=f.endpoint,
                    http_method=f.http_method, authentication_required=f.authentication_required,
                    internet_exposed=f.internet_exposed, exploitability_score=f.exploitability_score,
                    call_path=tuple(f.call_path), files=tuple(dict.fromkeys(step.file for step in f.dataflow)),
                    query_matches=tuple(f.query_matches),
                ) for f in findings
            ]
            ir.stats["security_flows"] = len(ir.security_flows)
            ir.stats["dedeql_matches"] = sum(len(f.query_matches) for f in findings)
            incremental_reused = len(preserved)

        # Always export complete flow records, including cache-only scans.
        ir.security_flows = [
            IRSecurityFlow(
                id=f.semantic_fingerprint or f.ast_fingerprint or f"{f.file}:{f.start_line}:{f.rule_id}",
                rule_id=f.rule_id, cwe=tuple(f.cwe), severity=f.severity.value,
                source_kind=f.source_kind, sink_kind=f.sink_kind, sink_file=f.file,
                sink_line=f.start_line, function=f.function, endpoint=f.endpoint,
                http_method=f.http_method, authentication_required=f.authentication_required,
                internet_exposed=f.internet_exposed, exploitability_score=f.exploitability_score,
                call_path=tuple(f.call_path), files=tuple(dict.fromkeys(step.file for step in f.dataflow)),
                query_matches=tuple(f.query_matches),
            ) for f in findings
        ]
        ir.stats["security_flows"] = len(ir.security_flows)
        ir.stats["dedeql_matches"] = sum(len(f.query_matches) for f in findings)
        if config.performance.semantic_cache:
            save_cache(cache_path, signature, findings)
        ir_path = raw_dir / "semantic-python-ir.json"
        ir_path.write_text(json.dumps(ir.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
        attack_json, attack_dot = write_attack_graph(ir, findings, raw_dir)
        status = ToolStatus.SUCCESS if model.parse_errors == 0 else ToolStatus.FAILED
        return AnalyzerResult(
            tool=self.name,
            status=status,
            version=self.version(),
            findings=findings,
            raw_path=str(ir_path),
            message=(
                f"Parsed {len(model.trees)} Python files; parse errors={model.parse_errors}; "
                f"functions={len(model.functions)}; contexts={contexts}; call_edges={ir.stats.get('call_edges', 0)}; "
                f"incremental_reused={incremental_reused}"
            ),
            coverage={
                "parsed_files": len(model.trees),
                "parse_errors": model.parse_errors,
                "functions": len(model.functions),
                "contexts": contexts,
                "call_edges": ir.stats.get("call_edges", 0),
                "resolved_call_edges": ir.stats.get("resolved_call_edges", 0),
                "cfg_edges": ir.stats.get("cfg_edges", 0),
                "endpoints": ir.stats.get("endpoints", 0),
                "dependency_edges": sum(len(values) for values in model.dependencies.values()),
                "security_flows": ir.stats.get("security_flows", 0),
                "dedeql_matches": ir.stats.get("dedeql_matches", 0),
                "incremental_reused_findings": incremental_reused,
                "incremental_entry_files": len(affected) if use_incremental else len(model.trees),
                "attack_graph_json": str(attack_json),
                "attack_graph_dot": str(attack_dot),
                "ir_version": ir.version,
            },
            dependency_graph=model.dependencies,
        )


# Backwards-compatible helper used by external callers/tests that imported the
# v1 summary API directly.
def legacy_project(root: Path, source: str) -> ProjectContext:
    path = root / "app.py"
    path.write_text(source, encoding="utf-8")
    return ProjectContext(
        root=str(root),
        files=[str(path)],
        languages=LanguageStats(languages={"Python": 100.0}),
        has_python=True,
    )
