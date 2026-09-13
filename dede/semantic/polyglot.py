"""Project-wide semantic frontend for non-Python application languages.

The frontend intentionally stays self-contained/offline.  It builds a structural
project graph (functions, imports, calls, CFG edges and endpoints), computes
fixed-point function summaries, and propagates taint across files and calls.
It is not a compiler/type-checker; ambiguous dynamic dispatch is resolved only
when a target is conservative (same file, explicit import/alias, class/static
receiver, or a globally unique function name).  That precision-first rule is
important: unresolved calls do not become speculative vulnerabilities.
"""
from __future__ import annotations

import json
import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from dede.analyzers.base import Analyzer
from dede.config import AppConfig
from dede.models import (
    AnalyzerResult,
    Category,
    Confidence,
    DataflowStep,
    Evidence,
    Finding,
    Precision,
    ProjectContext,
    Severity,
    ToolStatus,
)
from dede.semantic.ir import IRCFGEdge, IRCallEdge, IREndpoint, IRFunction, IRSecurityFlow, SecurityIR
from dede.semantic.model_packs import language_models, load_model_packs
from dede.semantic.query import apply_flow_queries
from dede.utils.hashes import sha256_text


@dataclass(frozen=True)
class SinkSpec:
    callee: str
    kind: str
    cwe: str
    severity: Severity
    argument: int = 0
    precision: Precision = Precision.HIGH
    # Optional line-level proof that must accompany the call.
    guard: str = ""


@dataclass(frozen=True)
class SanitizerSpec:
    pattern: str
    safe_for: tuple[str, ...] = ("sql-execution", "command-execution", "path-traversal", "code-execution")


@dataclass(frozen=True)
class LanguageProfile:
    name: str
    extensions: tuple[str, ...]
    source_patterns: tuple[tuple[str, str], ...]
    sinks: tuple[SinkSpec, ...]
    sanitizers: tuple[SanitizerSpec, ...] = ()
    endpoint_param_sources: bool = False


# The built-ins are deliberately API-specific.  Generic ``execute``/``query``
# receivers are not sinks unless the receiver family is a known DB API.
_PROFILES: tuple[LanguageProfile, ...] = (
    LanguageProfile(
        "javascript", (".js", ".jsx", ".mjs", ".cjs"),
        (
            (r"\b(?:req|request)\.(?:query|body|params|headers|cookies)\b", "http.request"),
            (r"\b(?:req|request)\.get\s*\(", "http.header"),
            (r"(?i)\bprocess\.env\.[A-Za-z_$][\w$]*(?:(?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|authorization|private[_-]?key|session[_-]?id))[A-Za-z_$\w]*", "secret.environment"),
        ),
        (
            SinkSpec(r"(?:db|pool|connection|client|knex|sequelize)\.(?:query|raw|execute)$", "sql-execution", "CWE-89", Severity.HIGH),
            SinkSpec(r"(?:child_process\.)?(?:exec|execSync)$", "command-execution", "CWE-78", Severity.CRITICAL),
            SinkSpec(r"(?:fetch|axios\.(?:get|post|put|patch|delete)|https?\.request)$", "ssrf", "CWE-918", Severity.HIGH),
            SinkSpec(r"(?:eval|Function)$", "code-execution", "CWE-95", Severity.CRITICAL),
            SinkSpec(r"(?:fs\.)?(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream)$", "path-traversal", "CWE-22", Severity.HIGH),
            SinkSpec(r"(?:res|response)\.redirect$", "open-redirect", "CWE-601", Severity.MEDIUM),
            SinkSpec(r"(?:collection|mongo|mongodb|mongoose)\.(?:find|findOne|aggregate|where)$", "nosql-injection", "CWE-943", Severity.HIGH),
            SinkSpec(r"(?:xpath|xpathjs)\.(?:select|evaluate)$", "xpath-injection", "CWE-643", Severity.HIGH),
            SinkSpec(r"(?:ejs\.render|Handlebars\.compile|_\.template)$", "template-injection", "CWE-1336", Severity.HIGH),
            SinkSpec(r"(?:console|logger|log)\.(?:log|debug|info|warn|error)$", "sensitive-data-log", "CWE-532", Severity.HIGH),
        ),
        (SanitizerSpec(r"\b(?:Number|parseInt|parseFloat)\s*\("),),
    ),
    LanguageProfile(
        "typescript", (".ts", ".tsx", ".mts", ".cts"),
        (
            (r"\b(?:req|request)\.(?:query|body|params|headers|cookies)\b", "http.request"),
            (r"\b(?:req|request)\.get\s*\(", "http.header"),
            (r"(?i)\bprocess\.env\.[A-Za-z_$][\w$]*(?:(?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|authorization|private[_-]?key|session[_-]?id))[A-Za-z_$\w]*", "secret.environment"),
        ),
        (
            SinkSpec(r"(?:db|pool|connection|client|knex|sequelize)\.(?:query|raw|execute)$", "sql-execution", "CWE-89", Severity.HIGH),
            SinkSpec(r"(?:child_process\.)?(?:exec|execSync)$", "command-execution", "CWE-78", Severity.CRITICAL),
            SinkSpec(r"(?:fetch|axios\.(?:get|post|put|patch|delete)|https?\.request)$", "ssrf", "CWE-918", Severity.HIGH),
            SinkSpec(r"(?:eval|Function)$", "code-execution", "CWE-95", Severity.CRITICAL),
            SinkSpec(r"(?:fs\.)?(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream)$", "path-traversal", "CWE-22", Severity.HIGH),
            SinkSpec(r"(?:res|response)\.redirect$", "open-redirect", "CWE-601", Severity.MEDIUM),
            SinkSpec(r"(?:collection|mongo|mongodb|mongoose)\.(?:find|findOne|aggregate|where)$", "nosql-injection", "CWE-943", Severity.HIGH),
            SinkSpec(r"(?:xpath|xpathjs)\.(?:select|evaluate)$", "xpath-injection", "CWE-643", Severity.HIGH),
            SinkSpec(r"(?:ejs\.render|Handlebars\.compile|_\.template)$", "template-injection", "CWE-1336", Severity.HIGH),
            SinkSpec(r"(?:console|logger|log)\.(?:log|debug|info|warn|error)$", "sensitive-data-log", "CWE-532", Severity.HIGH),
        ),
        (SanitizerSpec(r"\b(?:Number|parseInt|parseFloat)\s*\("),),
    ),
    LanguageProfile(
        "java", (".java",),
        (
            (r"\b(?:request|req)\.getParameter(?:Values)?\s*\(", "http.parameter"),
            (r"\b(?:request|req)\.getHeader\s*\(", "http.header"),
            (r"(?i)\bSystem\.getenv\s*\(\s*[\"'][^\"']*(?:(?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|authorization|private[_-]?key|session[_-]?id))[^\"']*[\"']", "secret.environment"),
        ),
        (
            SinkSpec(r"(?:statement|stmt|connection|jdbcTemplate)\.(?:execute|executeQuery|executeUpdate|query|update)$", "sql-execution", "CWE-89", Severity.HIGH),
            SinkSpec(r"exec$", "command-execution", "CWE-78", Severity.CRITICAL, guard=r"Runtime\.getRuntime"),
            SinkSpec(r"ProcessBuilder$", "command-execution", "CWE-78", Severity.HIGH),
            SinkSpec(r"(?:URI\.create|URL)$", "ssrf", "CWE-918", Severity.HIGH),
            SinkSpec(r"(?:ScriptEngine\.)?eval$", "code-execution", "CWE-95", Severity.CRITICAL),
            SinkSpec(r"(?:Paths\.get|Path\.of|Files\.(?:readAllBytes|readString|write|newInputStream|newOutputStream))$", "path-traversal", "CWE-22", Severity.HIGH),
            SinkSpec(r"ObjectInputStream\.readObject$", "unsafe-deserialization", "CWE-502", Severity.CRITICAL),
            SinkSpec(r"(?:response\.)?sendRedirect$", "open-redirect", "CWE-601", Severity.MEDIUM),
            SinkSpec(r"(?:XPath|XPathExpression)\.(?:evaluate|compile)$", "xpath-injection", "CWE-643", Severity.HIGH),
            SinkSpec(r"(?:SpelExpressionParser\.)?parseExpression$", "expression-injection", "CWE-917", Severity.HIGH),
            SinkSpec(r"(?:Yaml|YAML)\.load$", "unsafe-deserialization", "CWE-502", Severity.HIGH),
            SinkSpec(r"XMLDecoder\.readObject$", "unsafe-deserialization", "CWE-502", Severity.CRITICAL),
            SinkSpec(r"(?:log|logger)\.(?:trace|debug|info|warn|error)$", "sensitive-data-log", "CWE-532", Severity.HIGH),
        ),
        (SanitizerSpec(r"\b(?:Integer|Long|Double|Float)\.parse(?:Int|Long|Double|Float)\s*\("),),
        endpoint_param_sources=True,
    ),
    LanguageProfile(
        "kotlin", (".kt", ".kts"),
        (
            (r"\b(?:call|request)\.parameters\b", "http.parameter"),
            (r"\b(?:call|request)\.request\.headers\b", "http.header"),
            (r"(?i)\bSystem\.getenv\s*\(\s*[\"'][^\"']*(?:(?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|authorization|private[_-]?key|session[_-]?id))[^\"']*[\"']", "secret.environment"),
        ),
        (
            SinkSpec(r"(?:statement|stmt|connection|jdbcTemplate)\.(?:execute|executeQuery|executeUpdate|query|update)$", "sql-execution", "CWE-89", Severity.HIGH),
            SinkSpec(r"exec$", "command-execution", "CWE-78", Severity.CRITICAL, guard=r"Runtime\.getRuntime"),
            SinkSpec(r"ProcessBuilder$", "command-execution", "CWE-78", Severity.HIGH),
            SinkSpec(r"(?:URI\.create|URL)$", "ssrf", "CWE-918", Severity.HIGH),
            SinkSpec(r"(?:Paths\.get|Path\.of|Files\.(?:readAllBytes|readString|write))$", "path-traversal", "CWE-22", Severity.HIGH),
            SinkSpec(r"(?:log|logger)\.(?:trace|debug|info|warn|error)$", "sensitive-data-log", "CWE-532", Severity.HIGH),
        ),
        (SanitizerSpec(r"\.(?:toInt|toLong|toDouble)OrNull\s*\("),),
        endpoint_param_sources=True,
    ),
    LanguageProfile(
        "csharp", (".cs", ".csx"),
        (
            (r"\bRequest\.(?:Query|Form|Headers|Cookies|RouteValues)\b", "http.request"),
            (r"\bHttpContext\.Request\.(?:Query|Form|Headers)\b", "http.request"),
            (r"(?i)\bEnvironment\.GetEnvironmentVariable\s*\(\s*[\"'][^\"']*(?:(?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|authorization|private[_-]?key|session[_-]?id))[^\"']*[\"']", "secret.environment"),
        ),
        (
            SinkSpec(r"(?:Database\.)?ExecuteSqlRaw(?:Async)?$", "sql-execution", "CWE-89", Severity.HIGH),
            SinkSpec(r"(?:SqlCommand|NpgsqlCommand)$", "sql-execution", "CWE-89", Severity.HIGH),
            SinkSpec(r"Process\.Start$", "command-execution", "CWE-78", Severity.HIGH),
            SinkSpec(r"(?:HttpClient\.)?(?:GetAsync|PostAsync|PutAsync|SendAsync|GetStringAsync)$", "ssrf", "CWE-918", Severity.HIGH),
            SinkSpec(r"(?:File\.)?(?:ReadAllText|ReadAllBytes|WriteAllText|OpenRead|OpenWrite)$", "path-traversal", "CWE-22", Severity.HIGH),
            SinkSpec(r"BinaryFormatter\.Deserialize$", "unsafe-deserialization", "CWE-502", Severity.CRITICAL),
            SinkSpec(r"(?:Response\.)?Redirect$", "open-redirect", "CWE-601", Severity.MEDIUM),
            SinkSpec(r"(?:XPathNavigator|XPathDocument)\.(?:Select|Evaluate)$", "xpath-injection", "CWE-643", Severity.HIGH),
            SinkSpec(r"LosFormatter\.Deserialize$", "unsafe-deserialization", "CWE-502", Severity.CRITICAL),
            SinkSpec(r"(?:logger|_logger)\.(?:LogTrace|LogDebug|LogInformation|LogWarning|LogError|LogCritical)$", "sensitive-data-log", "CWE-532", Severity.HIGH),
        ),
        (SanitizerSpec(r"\b(?:int|long|double|decimal|Guid)\.Parse\s*\("),),
        endpoint_param_sources=True,
    ),
    LanguageProfile(
        "go", (".go",),
        (
            (r"\.URL\.Query\(\)\.Get\s*\(", "http.query"),
            (r"\b(?:c|ctx)\.(?:Query|Param|PostForm|GetHeader)\s*\(", "http.request"),
            (r"\b(?:r|req)\.FormValue\s*\(", "http.form"),
            (r"\b(?:r|req)\.Header\.Get\s*\(", "http.header"),
            (r"(?i)\bos\.Getenv\s*\(\s*[\"'][^\"']*(?:(?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|authorization|private[_-]?key|session[_-]?id))[^\"']*[\"']", "secret.environment"),
        ),
        (
            SinkSpec(r"(?:db|tx)\.(?:Query|QueryContext|Exec|ExecContext)$", "sql-execution", "CWE-89", Severity.HIGH),
            SinkSpec(r"exec\.Command(?:Context)?$", "command-execution", "CWE-78", Severity.HIGH),
            SinkSpec(r"http\.(?:Get|Post|PostForm)$", "ssrf", "CWE-918", Severity.HIGH),
            SinkSpec(r"(?:os|ioutil)\.(?:Open|ReadFile|WriteFile|Create|Remove|Rename)$", "path-traversal", "CWE-22", Severity.HIGH),
            SinkSpec(r"(?:template|tmpl|tpl)\.Parse$", "template-injection", "CWE-1336", Severity.HIGH),
            SinkSpec(r"(?:log|logger)\.(?:Print|Printf|Println|Debug|Info|Warn|Error)$", "sensitive-data-log", "CWE-532", Severity.HIGH),
        ),
        (SanitizerSpec(r"\bstrconv\.(?:Atoi|ParseInt|ParseUint|ParseFloat)\s*\("),),
    ),
    LanguageProfile(
        "php", (".php",),
        (
            (r"\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b", "http.request"),
            (r"\$request->(?:input|query|get|post|header|route)\s*\(", "http.request"),
            (r"(?i)\bgetenv\s*\(\s*[\"'][^\"']*(?:(?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|authorization|private[_-]?key|session[_-]?id))[^\"']*[\"']", "secret.environment"),
        ),
        (
            SinkSpec(r"(?:mysqli_query|mysql_query)$", "sql-execution", "CWE-89", Severity.HIGH, 1),
            SinkSpec(r"(?:pdo|db|conn|connection)\.(?:query|exec)$", "sql-execution", "CWE-89", Severity.HIGH),
            SinkSpec(r"(?:system|shell_exec|passthru|exec|popen)$", "command-execution", "CWE-78", Severity.CRITICAL),
            SinkSpec(r"eval$", "code-execution", "CWE-95", Severity.CRITICAL),
            SinkSpec(r"(?:file_get_contents|fopen|readfile|include|require|include_once|require_once)$", "path-traversal", "CWE-22", Severity.HIGH),
            SinkSpec(r"unserialize$", "unsafe-deserialization", "CWE-502", Severity.CRITICAL),
            SinkSpec(r"curl_setopt$", "ssrf", "CWE-918", Severity.HIGH, 2, guard=r"CURLOPT_URL"),
            SinkSpec(r"header$", "open-redirect", "CWE-601", Severity.MEDIUM, guard=r"Location\s*:"),
            SinkSpec(r"(?:collection|mongo|mongodb)\.(?:find|findOne|aggregate)$", "nosql-injection", "CWE-943", Severity.HIGH),
            SinkSpec(r"(?:DOMXPath|XPath)\.(?:query|evaluate)$", "xpath-injection", "CWE-643", Severity.HIGH),
            SinkSpec(r"ldap_search$", "ldap-injection", "CWE-90", Severity.HIGH, 2),
            SinkSpec(r"(?:error_log|logger\.(?:debug|info|warning|error))$", "sensitive-data-log", "CWE-532", Severity.HIGH),
        ),
        (SanitizerSpec(r"\b(?:intval|floatval)\s*\("),),
    ),
    LanguageProfile(
        "ruby", (".rb",),
        (
            (r"\bparams\s*\[", "http.parameter"),
            (r"\brequest\.(?:params|headers|cookies)\b", "http.request"),
            (r"(?i)\bENV\s*\[\s*[\"'][^\"']*(?:(?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|authorization|private[_-]?key|session[_-]?id))[^\"']*[\"']\s*\]", "secret.environment"),
        ),
        (
            SinkSpec(r"(?:connection|ActiveRecord::Base\.connection)\.(?:execute|select_all|select_rows)$", "sql-execution", "CWE-89", Severity.HIGH),
            SinkSpec(r"(?:system|exec|spawn|IO\.popen|Open3\.(?:capture2|capture3|popen3))$", "command-execution", "CWE-78", Severity.CRITICAL),
            SinkSpec(r"(?:URI\.open|OpenURI\.open_uri|Net::HTTP\.get|Net::HTTP\.get_response)$", "ssrf", "CWE-918", Severity.HIGH),
            SinkSpec(r"(?:File|IO)\.(?:read|write|open|binread|binwrite)$", "path-traversal", "CWE-22", Severity.HIGH),
            SinkSpec(r"(?:Marshal|YAML)\.load$", "unsafe-deserialization", "CWE-502", Severity.CRITICAL),
            SinkSpec(r"redirect_to$", "open-redirect", "CWE-601", Severity.MEDIUM),
            SinkSpec(r"(?:ERB|Erubi)\.new$", "template-injection", "CWE-1336", Severity.HIGH),
            SinkSpec(r"(?:Nokogiri::XML::XPath|xpath)$", "xpath-injection", "CWE-643", Severity.HIGH),
            SinkSpec(r"(?:logger|Rails\.logger)\.(?:debug|info|warn|error|fatal)$", "sensitive-data-log", "CWE-532", Severity.HIGH),
        ),
        (SanitizerSpec(r"\b(?:Integer|Float)\s*\("),),
        endpoint_param_sources=False,
    ),
    LanguageProfile(
        "rust", (".rs",),
        (
            (r"\b(?:Query|Path|Form)\s*\(", "http.request"),
            (r"\breq\.(?:uri|headers)\(\)", "http.request"),
        ),
        (
            SinkSpec(r"(?:sqlx::query|diesel::sql_query)$", "sql-execution", "CWE-89", Severity.HIGH),
            SinkSpec(r"(?:reqwest::get|Client\.(?:get|post|request))$", "ssrf", "CWE-918", Severity.HIGH),
            SinkSpec(r"(?:std::fs::|fs::)(?:read|read_to_string|write|File::open)$", "path-traversal", "CWE-22", Severity.HIGH),
            # Command::new is safe with separated args, so only shell interpreters are guarded sinks.
            SinkSpec(r"Command::new$", "command-execution", "CWE-78", Severity.HIGH, guard=r"(?:sh|bash|cmd|powershell|pwsh)"),
        ),
        (SanitizerSpec(r"\.parse::<(?:i|u)(?:8|16|32|64|128|size)>\s*\("),),
    ),
    LanguageProfile(
        "c", (".c", ".h"),
        (
            (r"\bargv\s*\[", "process.argument"),
            (r"(?i)\bgetenv\s*\(", "environment"),
        ),
        (
            SinkSpec(r"(?:system|popen)$", "command-execution", "CWE-78", Severity.CRITICAL),
            SinkSpec(r"(?:sqlite3_exec|mysql_query|PQexec)$", "sql-execution", "CWE-89", Severity.HIGH),
            SinkSpec(r"(?:fopen|open|freopen)$", "path-traversal", "CWE-22", Severity.HIGH),
        ),
    ),
    LanguageProfile(
        "cpp", (".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx"),
        (
            (r"\bargv\s*\[", "process.argument"),
            (r"(?i)\bgetenv\s*\(", "environment"),
        ),
        (
            SinkSpec(r"(?:std::system|system|popen)$", "command-execution", "CWE-78", Severity.CRITICAL),
            SinkSpec(r"(?:sqlite3_exec|mysql_query|PQexec)$", "sql-execution", "CWE-89", Severity.HIGH),
            SinkSpec(r"(?:fopen|open|std::fstream|std::ifstream|std::ofstream)$", "path-traversal", "CWE-22", Severity.HIGH),
        ),
    ),
    LanguageProfile(
        "scala", (".scala",),
        (
            (r"\b(?:request|req)\.(?:getQueryString|body|headers|queryString)\b", "http.request"),
            (r"\bparams\s*\(", "http.parameter"),
        ),
        (
            SinkSpec(r"(?:statement|stmt|connection)\.(?:execute|executeQuery|executeUpdate)$", "sql-execution", "CWE-89", Severity.HIGH),
            SinkSpec(r"exec$", "command-execution", "CWE-78", Severity.CRITICAL, guard=r"Runtime\.getRuntime"),
            SinkSpec(r"(?:Source\.fromURL|Http\(\))$", "ssrf", "CWE-918", Severity.HIGH),
            SinkSpec(r"(?:Files\.|Paths\.get)(?:readAllBytes|readString|write)?$", "path-traversal", "CWE-22", Severity.HIGH),
        ),
        (SanitizerSpec(r"\.(?:toInt|toLong|toDouble)Option\b"),),
        endpoint_param_sources=True,
    ),
    LanguageProfile(
        "dart", (".dart",),
        (
            (r"\brequest\.uri\.queryParameters\b", "http.query"),
            (r"\brequest\.headers\b", "http.header"),
        ),
        (
            SinkSpec(r"(?:http\.)?(?:get|post|put|patch|delete)$", "ssrf", "CWE-918", Severity.HIGH),
            SinkSpec(r"HttpClient\.(?:getUrl|postUrl|openUrl)$", "ssrf", "CWE-918", Severity.HIGH),
            SinkSpec(r"File$", "path-traversal", "CWE-22", Severity.HIGH),
            SinkSpec(r"Process\.(?:run|start)$", "command-execution", "CWE-78", Severity.HIGH),
        ),
        (SanitizerSpec(r"\b(?:int|double)\.parse\s*\("),),
    ),
    LanguageProfile(
        "swift", (".swift",),
        (
            (r"\brequest\.(?:query|headers|parameters|content)\b", "http.request"),
            (r"\breq\.(?:query|headers|content)\b", "http.request"),
        ),
        (
            SinkSpec(r"(?:URLSession\.shared\.)?(?:data|dataTask)$", "ssrf", "CWE-918", Severity.HIGH),
            SinkSpec(r"(?:FileManager\.default\.)?(?:contents|createFile|removeItem)$", "path-traversal", "CWE-22", Severity.HIGH),
            SinkSpec(r"Process\.run$", "command-execution", "CWE-78", Severity.HIGH),
        ),
    ),
)


@dataclass(frozen=True)
class ImportBinding:
    alias: str
    target: str
    symbol: str = ""


@dataclass
class FunctionInfo:
    id: str
    language: str
    file: str
    module: str
    name: str
    qualified_name: str
    parameters: tuple[str, ...]
    start: int
    end: int
    class_name: str = ""
    endpoint: str = ""
    methods: tuple[str, ...] = ()
    auth_required: bool | None = None
    return_params: set[int] = field(default_factory=set)
    return_sources: set[str] = field(default_factory=set)
    return_sanitized_for: set[str] = field(default_factory=set)


@dataclass
class FileInfo:
    path: Path
    rel: str
    profile: LanguageProfile
    lines: list[str]
    module: str
    package: str = ""
    imports: dict[str, ImportBinding] = field(default_factory=dict)
    functions: list[FunctionInfo] = field(default_factory=list)


@dataclass(frozen=True)
class Taint:
    source_kind: str
    file: str
    line: int
    symbol: str
    path: tuple[str, ...] = ()
    sanitized_for: frozenset[str] = frozenset()

    def through(self, node: str) -> "Taint":
        return Taint(self.source_kind, self.file, self.line, self.symbol, (*self.path, node), self.sanitized_for)

    def sanitized(self, kinds: Iterable[str]) -> "Taint":
        return Taint(self.source_kind, self.file, self.line, self.symbol, self.path, self.sanitized_for | frozenset(kinds))


@dataclass(frozen=True)
class Call:
    callee: str
    args: tuple[str, ...]
    start: int
    end: int


@dataclass(frozen=True)
class Context:
    function_id: str
    tainted_params: tuple[tuple[int, Taint], ...]
    call_path: tuple[str, ...]
    endpoint: str = ""
    method: str = ""
    auth_required: bool | None = None


def _profile(path: Path) -> LanguageProfile | None:
    suffix = path.suffix.lower()
    for profile in _PROFILES:
        if suffix in profile.extensions:
            return profile
    return None


def _syntax_language(language: str) -> str:
    return "javascript" if language == "typescript" else language


def _strip_strings_and_comments(line: str, language: str) -> str:
    language = _syntax_language(language)
    # Preserve call/identifier structure while preventing braces inside common strings/comments
    # from corrupting structural scope detection.
    text = re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', '""', line)
    if language in {"javascript", "java", "kotlin", "csharp", "go", "rust", "c", "cpp", "swift"}:
        text = re.sub(r"//.*$", "", text)
    if language in {"ruby"}:
        text = re.sub(r"#.*$", "", text)
    return text


def _split_params(raw: str, language: str = "") -> tuple[str, ...]:
    if not raw.strip():
        return ()
    parts = _split_arguments(raw)
    names: list[str] = []
    for part in parts:
        text = part.strip()
        text = re.sub(r"\[[^\]]+\]\s*", "", text)  # C# attributes
        text = re.sub(r"@[A-Za-z_][\w.]*(?:\([^)]*\))?\s*", "", text)  # Java annotations
        # JS/TS destructuring is intentionally not treated as a stable parameter identity.
        if text.startswith(("{", "[")):
            continue
        # PHP/Ruby/JS variable, Go/C/Java/C#/Kotlin/Swift typed parameter.
        candidates = re.findall(r"\$?[A-Za-z_][\w$]*", text)
        if not candidates:
            continue
        # Remove common modifiers/types by taking the identifier next to default/type delimiter.
        if ":" in text and not text.lstrip().startswith("::"):
            before = text.split(":", 1)[0].strip()
            cand = re.findall(r"\$?[A-Za-z_][\w$]*", before)
            name = cand[-1] if cand else candidates[-1]
        elif "=" in text:
            before = text.split("=", 1)[0].strip()
            cand = re.findall(r"\$?[A-Za-z_][\w$]*", before)
            name = cand[-1] if cand else candidates[-1]
        elif text.startswith("$"):
            name = candidates[0]
        elif language == "go":
            # Go parameters are ``name type`` rather than ``type name``.
            name = candidates[0]
        else:
            name = candidates[-1]
        names.append(name)
    return tuple(names)


def _function_starts(lines: list[str], language: str) -> list[tuple[int, str, tuple[str, ...], str]]:
    language = _syntax_language(language)
    out: list[tuple[int, str, tuple[str, ...], str]] = []
    patterns: dict[str, tuple[re.Pattern[str], ...]] = {
        "javascript": (
            re.compile(r"\bfunction\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)"),
            re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>"),
            re.compile(r"\b(?:async\s+)?([A-Za-z_$][\w$]*)\s*\(([^;{}]*)\)\s*\{"),
        ),
        "java": (re.compile(r"(?:^|[{};])\s*(?:(?:public|private|protected|static|final|synchronized|native|abstract|default)\s+)*(?:<[^>]+>\s+)?[\w<>,\[\]? .]+\s+([A-Za-z_$][\w$]*)\s*\(([^;{}]*)\)\s*(?:throws[^\{]+)?\{"),),
        "kotlin": (re.compile(r"\bfun\s+([A-Za-z_][\w]*)\s*\(([^)]*)\)"),),
        "csharp": (re.compile(r"(?:^|[{};])\s*(?:(?:public|private|protected|internal|static|async|virtual|override|sealed|partial)\s+)*[\w<>,\[\]? .]+\s+([A-Za-z_][\w]*)\s*\(([^;{}]*)\)\s*(?:=>|\{)"),),
        "go": (re.compile(r"^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_][\w]*)\s*\(([^)]*)\)"),),
        "php": (re.compile(r"\bfunction\s+([A-Za-z_][\w]*)\s*\(([^)]*)\)"),),
        "ruby": (re.compile(r"^\s*def\s+(?:self\.)?([A-Za-z_][\w!?=]*)\s*(?:\(([^)]*)\)|\s+([^#]+))?"),),
        "rust": (re.compile(r"\bfn\s+([A-Za-z_][\w]*)\s*\(([^)]*)\)"),),
        "c": (re.compile(r"^\s*(?:[A-Za-z_][\w\s*]+)\s+([A-Za-z_][\w]*)\s*\(([^;]*)\)\s*\{"),),
        "cpp": (re.compile(r"^\s*(?:[A-Za-z_:<>~][\w:\s<>,*&~]+)\s+([A-Za-z_~][\w:]*)\s*\(([^;]*)\)\s*(?:const\s*)?\{"),),
        "scala": (re.compile(r"\bdef\s+([A-Za-z_][\w]*)\s*\(([^)]*)\)"),),
        "dart": (re.compile(r"^\s*(?:(?:Future|FutureOr|Stream|void|String|int|double|bool|dynamic|Object)(?:<[^>]+>)?\s+)?([A-Za-z_][\w]*)\s*\(([^;{}]*)\)\s*(?:async\s*)?\{"),),
        "swift": (re.compile(r"\bfunc\s+([A-Za-z_][\w]*)\s*\(([^)]*)\)"),),
    }
    class_name = ""
    for idx, line in enumerate(lines, 1):
        cm = re.search(r"\b(?:class|struct|interface|enum|actor)\s+([A-Za-z_][\w]*)", line)
        if cm:
            class_name = cm.group(1)
        for pat in patterns.get(language, ()):
            m = pat.search(line)
            if not m:
                continue
            name = m.group(1)
            raw = next((g for g in m.groups()[1:] if g is not None), "")
            # Skip control-flow constructs that resemble JS methods.
            if name in {"if", "for", "while", "switch", "catch", "with"}:
                continue
            out.append((idx, name.split("::")[-1], _split_params(raw, language), class_name))
            break
        # Anonymous framework route callbacks are real function scopes too.
        if language == "javascript":
            rm = re.search(r"\b(?:app|router)\.(?:get|post|put|patch|delete)\s*\([^,]+,\s*(?:async\s*)?\(([^)]*)\)\s*=>\s*\{", line, re.I)
            if rm:
                out.append((idx, f"<route@{idx}>", _split_params(rm.group(1), language), class_name))
        elif language == "php":
            rm = re.search(r"Route::(?:get|post|put|patch|delete)\s*\([^,]+,\s*function\s*\(([^)]*)\)", line, re.I)
            if rm:
                out.append((idx, f"<route@{idx}>", _split_params(rm.group(1), language), class_name))
        elif language == "swift":
            rm = re.search(r"\bapp\.(?:get|post|put|patch|delete)\s*\([^)]*\)\s*\{\s*([A-Za-z_][\w]*)", line, re.I)
            if rm:
                out.append((idx, f"<route@{idx}>", (rm.group(1),), class_name))
    # A named parser and a route-callback parser can identify the same line; keep one stable record.
    unique: list[tuple[int, str, tuple[str, ...], str]] = []
    seen: set[tuple[int, str]] = set()
    for item in out:
        key = (item[0], item[1])
        if key not in seen:
            seen.add(key); unique.append(item)
    return unique


def _scope_end(lines: list[str], start: int, language: str) -> int:
    if language == "ruby":
        depth = 0
        for idx in range(start - 1, len(lines)):
            text = _strip_strings_and_comments(lines[idx], language).strip()
            if re.match(r"^(?:def|class|module|if|unless|case|begin|while|until|for)\b", text) or re.search(r"\bdo\s*(?:\|[^|]*\|)?\s*$", text):
                depth += 1
            if text == "end" or text.startswith("end #"):
                depth -= 1
                if depth <= 0 and idx + 1 > start:
                    return idx + 1
        return len(lines)
    depth = 0
    seen = False
    for idx in range(start - 1, len(lines)):
        text = _strip_strings_and_comments(lines[idx], language)
        opens, closes = text.count("{"), text.count("}")
        if opens:
            seen = True
        depth += opens - closes
        if seen and depth <= 0 and idx + 1 > start:
            return idx + 1
    return len(lines)


def _module_name(rel: str, language: str, lines: list[str]) -> tuple[str, str]:
    rel_no_ext = str(Path(rel).with_suffix("")).replace("/", ".")
    if language in {"java", "kotlin"}:
        for line in lines[:80]:
            m = re.search(r"^\s*package\s+([\w.]+)", line)
            if m:
                return f"{m.group(1)}.{Path(rel).stem}", m.group(1)
    if language == "csharp":
        for line in lines[:100]:
            m = re.search(r"^\s*namespace\s+([\w.]+)", line)
            if m:
                return f"{m.group(1)}.{Path(rel).stem}", m.group(1)
    if language == "go":
        for line in lines[:40]:
            m = re.search(r"^\s*package\s+([A-Za-z_][\w]*)", line)
            if m:
                return m.group(1), m.group(1)
    return rel_no_ext, str(Path(rel).parent).replace("/", ".")


def _parse_imports(info: FileInfo) -> dict[str, ImportBinding]:
    imports: dict[str, ImportBinding] = {}
    lang, rel = _syntax_language(info.profile.name), info.rel
    for line in info.lines:
        if lang == "javascript":
            m = re.search(r"\bimport\s+(.+?)\s+from\s+['\"]([^'\"]+)['\"]", line)
            if m:
                spec, target = m.groups()
                if spec.startswith("{"):
                    for item in spec.strip("{} ").split(","):
                        bits = re.split(r"\s+as\s+", item.strip())
                        original, alias = bits[0].strip(), bits[-1].strip()
                        if alias:
                            imports[alias] = ImportBinding(alias, target, original)
                elif spec.startswith("*"):
                    am = re.search(r"\bas\s+([\w$]+)", spec)
                    if am:
                        imports[am.group(1)] = ImportBinding(am.group(1), target, "*")
                else:
                    alias = spec.split(",", 1)[0].strip()
                    if alias:
                        imports[alias] = ImportBinding(alias, target, "default")
            for m in re.finditer(r"(?:const|let|var)\s+([\w$]+)\s*=\s*require\(['\"]([^'\"]+)['\"]\)", line):
                imports[m.group(1)] = ImportBinding(m.group(1), m.group(2), "*")
            m = re.search(r"(?:const|let|var)\s*\{([^}]+)\}\s*=\s*require\(['\"]([^'\"]+)['\"]\)", line)
            if m:
                for item in m.group(1).split(","):
                    bits = item.strip().split(":", 1)
                    original, alias = bits[0].strip(), bits[-1].strip()
                    imports[alias] = ImportBinding(alias, m.group(2), original)
        elif lang in {"java", "kotlin"}:
            m = re.search(r"^\s*import\s+(?:static\s+)?([\w.*]+)(?:\s+as\s+(\w+))?", line)
            if m:
                target, alias = m.group(1), m.group(2) or m.group(1).split(".")[-1]
                imports[alias] = ImportBinding(alias, target, m.group(1).split(".")[-1])
        elif lang == "csharp":
            m = re.search(r"^\s*using\s+(?:(\w+)\s*=\s*)?([\w.]+)\s*;", line)
            if m:
                alias = m.group(1) or m.group(2).split(".")[-1]
                imports[alias] = ImportBinding(alias, m.group(2), "*")
        elif lang == "go":
            m = re.search(r"^\s*(?:(\w+)\s+)?\"([^\"]+)\"", line)
            if m:
                target = m.group(2)
                alias = m.group(1) or target.rsplit("/", 1)[-1]
                imports[alias] = ImportBinding(alias, target, "*")
        elif lang == "php":
            m = re.search(r"\b(?:require|require_once|include|include_once)\s*\(?\s*['\"]([^'\"]+)['\"]", line)
            if m:
                target = m.group(1)
                imports[Path(target).stem] = ImportBinding(Path(target).stem, target, "*")
            m = re.search(r"^\s*use\s+([\\\w]+)(?:\s+as\s+(\w+))?", line)
            if m:
                alias = m.group(2) or m.group(1).split("\\")[-1]
                imports[alias] = ImportBinding(alias, m.group(1).replace("\\", "."), "*")
        elif lang == "ruby":
            m = re.search(r"\brequire_relative\s+['\"]([^'\"]+)['\"]", line)
            if m:
                target = m.group(1)
                imports[Path(target).stem] = ImportBinding(Path(target).stem, target, "*")
        elif lang == "rust":
            m = re.search(r"^\s*(?:use|mod)\s+([\w:]+)", line)
            if m:
                target = m.group(1)
                imports[target.split("::")[-1]] = ImportBinding(target.split("::")[-1], target, "*")
        elif lang in {"c", "cpp"}:
            m = re.search(r"^\s*#\s*include\s*[\"<]([^\">]+)[\">]", line)
            if m:
                imports[Path(m.group(1)).stem] = ImportBinding(Path(m.group(1)).stem, m.group(1), "*")
        elif lang == "swift":
            m = re.search(r"^\s*import\s+([A-Za-z_][\w]*)", line)
            if m:
                imports[m.group(1)] = ImportBinding(m.group(1), m.group(1), "*")
    return imports


def _endpoint_for(fn: FunctionInfo, info: FileInfo) -> tuple[str, tuple[str, ...], bool | None]:
    start = max(0, fn.start - 8)
    end = min(len(info.lines), fn.start + 2)
    window = "\n".join(info.lines[start:end])
    lang = _syntax_language(info.profile.name)
    auth: bool | None = None
    path = ""
    methods: tuple[str, ...] = ()
    if lang == "javascript":
        m = re.search(r"\b(?:app|router)\.(get|post|put|patch|delete)\s*\(\s*['\"]([^'\"]+)", window, re.I)
        if m:
            methods, path = (m.group(1).upper(),), m.group(2)
        if re.search(r"\b(?:auth|authenticate|requireAuth|isAuthenticated)\b", window, re.I):
            auth = True
    elif lang in {"java", "kotlin"}:
        m = re.search(r"@(Get|Post|Put|Patch|Delete|Request)Mapping\s*(?:\(\s*(?:value\s*=\s*)?['\"]([^'\"]*)['\"])?", window)
        if m:
            method = m.group(1).replace("Request", "").upper() or "ANY"
            methods, path = (method,), (m.group(2) or "")
        if re.search(r"@(?:PreAuthorize|Secured|RolesAllowed|Authenticated)", window):
            auth = True
    elif lang == "csharp":
        m = re.search(r"\[Http(Get|Post|Put|Patch|Delete)(?:\(\s*['\"]([^'\"]*)['\"]\s*\))?\]", window, re.I)
        if m:
            methods, path = (m.group(1).upper(),), (m.group(2) or "")
        route = re.search(r"\[Route\(\s*['\"]([^'\"]+)['\"]", window)
        if route and not path:
            path = route.group(1)
        if re.search(r"\[Authorize(?:\([^]]*\))?\]", window):
            auth = True
        if re.search(r"\[AllowAnonymous\]", window):
            auth = False
    elif lang == "php":
        m = re.search(r"Route::(get|post|put|patch|delete)\s*\(\s*['\"]([^'\"]+)", window, re.I)
        if m:
            methods, path = (m.group(1).upper(),), m.group(2)
        if re.search(r"middleware\s*\(\s*['\"]auth", window):
            auth = True
    elif lang == "ruby":
        m = re.search(r"^\s*(get|post|put|patch|delete)\s+['\"]([^'\"]+)", window, re.I | re.M)
        if m:
            methods, path = (m.group(1).upper(),), m.group(2)
        if re.search(r"before_action\s+:authenticate|authenticate_user!", window):
            auth = True
    elif lang == "go":
        # Router registration commonly lives outside handler functions; attach if nearby.
        m = re.search(r"\.(GET|POST|PUT|PATCH|DELETE|HandleFunc)\s*\(\s*['\"]([^'\"]+)", window)
        if m:
            methods, path = ((m.group(1) if m.group(1) != "HandleFunc" else "ANY"),), m.group(2)
    elif lang == "rust":
        m = re.search(r"\b(?:get|post|put|patch|delete)\s*\(\s*([A-Za-z_][\w]*)\s*\)", window)
        if m:
            methods = ("ANY",)
    elif lang == "swift":
        m = re.search(r"\bapp\.(get|post|put|patch|delete)\s*\(\s*['\"]([^'\"]+)", window, re.I)
        if m:
            methods, path = (m.group(1).upper(),), m.group(2)
    return path, methods, auth


def _build_index(root: Path, files: Iterable[str]) -> tuple[dict[str, FileInfo], dict[str, FunctionInfo], dict[str, list[str]]]:
    file_infos: dict[str, FileInfo] = {}
    functions: dict[str, FunctionInfo] = {}
    by_name: dict[str, list[str]] = defaultdict(list)
    for value in files:
        path = Path(value)
        profile = _profile(path)
        if profile is None:
            continue
        try:
            resolved = path.resolve()
            rel = resolved.relative_to(root).as_posix()
            lines = resolved.read_text(encoding="utf-8", errors="replace").splitlines()
        except (OSError, ValueError):
            continue
        module, package = _module_name(rel, profile.name, lines)
        info = FileInfo(resolved, rel, profile, lines, module, package)
        for start, name, params, class_name in _function_starts(lines, profile.name):
            end = _scope_end(lines, start, profile.name)
            qualified = ".".join(x for x in (module, class_name, name) if x)
            fid = f"{profile.name}:{rel}:{class_name}:{name}:{start}"
            fn = FunctionInfo(fid, profile.name, rel, module, name, qualified, params, start, end, class_name)
            path_value, methods, auth = _endpoint_for(fn, info)
            fn.endpoint, fn.methods, fn.auth_required = path_value, methods, auth
            info.functions.append(fn)
            functions[fid] = fn
            by_name[name].append(fid)
            if class_name:
                by_name[f"{class_name}.{name}"].append(fid)
            by_name[qualified].append(fid)
        if not info.functions and lines:
            fid = f"{profile.name}:{rel}:<module>:1"
            fn = FunctionInfo(fid, profile.name, rel, module, "<module>", f"{module}.<module>", (), 1, len(lines))
            info.functions.append(fn); functions[fid] = fn; by_name["<module>"].append(fid)
        info.imports = _parse_imports(info)
        file_infos[rel] = info
    return file_infos, functions, by_name


def _resolve_relative_target(info: FileInfo, target: str, file_infos: dict[str, FileInfo]) -> set[str]:
    candidates: set[str] = set()
    if target.startswith("."):
        base = (Path(info.rel).parent / target).as_posix()
        for rel in file_infos:
            stem = str(Path(rel).with_suffix(""))
            if stem == base or stem.endswith(base.lstrip("./")):
                candidates.add(rel)
    else:
        normalized = target.replace("\\", "/").replace("::", "/").replace(".", "/")
        for rel, other in file_infos.items():
            module_slash = other.module.replace(".", "/")
            if module_slash.endswith(normalized) or normalized.endswith(module_slash) or Path(rel).stem == target.rsplit("/", 1)[-1].rsplit(".", 1)[-1]:
                candidates.add(rel)
    return candidates


def _resolve_call(callee: str, current: FunctionInfo, file_infos: dict[str, FileInfo], functions: dict[str, FunctionInfo], by_name: dict[str, list[str]]) -> str | None:
    clean = callee.replace("->", ".").replace("::", ".")
    clean = re.sub(r"^\$", "", clean)
    parts = [p.lstrip("$") for p in clean.split(".") if p]
    name = parts[-1] if parts else clean
    # Same file wins and is unambiguous.
    same = [fid for fid in by_name.get(name, []) if functions[fid].file == current.file]
    if len(same) == 1:
        return same[0]
    info = file_infos[current.file]
    if len(parts) >= 2:
        receiver = parts[-2]
        binding = info.imports.get(receiver)
        if binding:
            target_files = _resolve_relative_target(info, binding.target, file_infos)
            matched = [fid for fid in by_name.get(name, []) if functions[fid].file in target_files]
            if len(matched) == 1:
                return matched[0]
        class_matches = by_name.get(f"{receiver}.{name}", [])
        if len(class_matches) == 1:
            return class_matches[0]
    # Named import e.g. import {search} ...; search(...)
    binding = info.imports.get(name)
    if binding:
        target_files = _resolve_relative_target(info, binding.target, file_infos)
        symbol = binding.symbol if binding.symbol not in {"", "*", "default"} else name
        matched = [fid for fid in by_name.get(symbol, []) if functions[fid].file in target_files]
        if len(matched) == 1:
            return matched[0]
    # Conservative project-global fallback only for a unique symbol.
    candidates = by_name.get(name, [])
    return candidates[0] if len(candidates) == 1 else None


def _split_arguments(raw: str) -> tuple[str, ...]:
    args: list[str] = []
    start, depth = 0, 0
    quote = ""
    escape = False
    pairs = {"(": ")", "[": "]", "{": "}"}
    stack: list[str] = []
    for i, ch in enumerate(raw):
        if quote:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = ""
            continue
        if ch in {'"', "'", "`"}:
            quote = ch
            continue
        if ch in pairs:
            stack.append(pairs[ch]); depth += 1
        elif stack and ch == stack[-1]:
            stack.pop(); depth -= 1
        elif ch == "," and depth == 0:
            args.append(raw[start:i].strip()); start = i + 1
    tail = raw[start:].strip()
    if tail or raw.strip():
        args.append(tail)
    return tuple(args)


def _extract_calls(text: str) -> list[Call]:
    calls: list[Call] = []
    # Exclude language keywords and declarations.
    keywords = {"if", "for", "while", "switch", "catch", "return", "sizeof", "typeof", "new", "function", "func", "fn", "def"}
    head_re = re.compile(r"(?<![\w$])([\$A-Za-z_][\w$]*(?:(?:\.|::|->)[\$A-Za-z_][\w$]*|\.getRuntime\(\))*)\s*\(")
    for m in head_re.finditer(text):
        callee = m.group(1)
        if callee in keywords:
            continue
        open_idx = text.find("(", m.start(1) + len(callee))
        if open_idx < 0:
            continue
        depth, quote, escape = 1, "", False
        i = open_idx + 1
        while i < len(text) and depth:
            ch = text[i]
            if quote:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == quote:
                    quote = ""
            elif ch in {'"', "'", "`"}:
                quote = ch
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            i += 1
        if depth == 0:
            raw = text[open_idx + 1:i - 1]
            calls.append(Call(callee, _split_arguments(raw), m.start(1), i))
    return calls


def _assignment(line: str, language: str) -> tuple[str, str] | None:
    language = _syntax_language(language)
    patterns = {
        "javascript": r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(.+)",
        "java": r"\b(?:final\s+)?(?:[A-Za-z_$][\w$<>?,.\[\]]*\s+)?([A-Za-z_$][\w$]*)\s*=\s*(.+)",
        "kotlin": r"\b(?:val|var)\s+([A-Za-z_][\w]*)\s*(?::[^=]+)?=\s*(.+)",
        "csharp": r"\b(?:var|[A-Za-z_][\w<>,.?\[\]]*)\s+([A-Za-z_][\w]*)\s*=\s*(.+)",
        "go": r"\b([A-Za-z_][\w]*)\s*(?::=|=)\s*(.+)",
        "php": r"(\$[A-Za-z_][\w]*)\s*=\s*(.+)",
        "ruby": r"\b([A-Za-z_][\w]*)\s*=\s*(.+)",
        "rust": r"\b(?:let\s+(?:mut\s+)?)?([A-Za-z_][\w]*)\s*=\s*(.+)",
        "c": r"\b(?:[A-Za-z_][\w\s*]+\s+)?([A-Za-z_][\w]*)\s*=\s*(.+)",
        "cpp": r"\b(?:[A-Za-z_:][\w:<>,*&\s]+\s+)?([A-Za-z_][\w]*)\s*=\s*(.+)",
        "scala": r"\b(?:val|var)\s+([A-Za-z_][\w]*)\s*(?::[^=]+)?=\s*(.+)",
        "dart": r"\b(?:var|final|late|String|int|double|bool|dynamic)?\s*([A-Za-z_][\w]*)\s*=\s*(.+)",
        "swift": r"\b(?:let|var)\s+([A-Za-z_][\w]*)\s*(?::[^=]+)?=\s*(.+)",
    }
    m = re.search(patterns.get(language, r"$^"), line)
    return (m.group(1), m.group(2)) if m else None


def _return_expr(line: str, language: str) -> str:
    if language == "ruby":
        m = re.match(r"\s*return\s+(.+)", line)
        return m.group(1) if m else ""
    m = re.search(r"\breturn\s+(.+?)(?:;\s*)?$", line)
    return m.group(1) if m else ""


def _contains_var(text: str, var: str) -> bool:
    # Preserve explicit interpolation but do not treat an identifier printed
    # inside a constant string (e.g. SQL column ``q``) as a dataflow reference.
    if var.startswith("$"):
        return var in text
    if re.search(rf"\$\{{\s*{re.escape(var)}(?:\b|\s*\}})", text):
        return True
    masked = re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|`(?:\\.|[^`\\])*`', '""', text)
    return re.search(rf"(?<![\w$]){re.escape(var)}(?![\w$])", masked) is not None


def _source_in_expr(expr: str, profile: LanguageProfile) -> tuple[str, int] | None:
    for pattern, kind in profile.source_patterns:
        m = re.search(pattern, expr)
        if m:
            return kind, m.start()
    return None


def _sanitizers(profile: LanguageProfile, config: AppConfig, root: Path) -> tuple[list[SanitizerSpec], list[dict[str, object]], list[tuple[str, str]], list[SinkSpec]]:
    specs = list(profile.sanitizers)
    source_models: list[tuple[str, str]] = list(profile.source_patterns)
    sinks = list(profile.sinks)
    packs = load_model_packs(config, root)
    extra_sources, extra_sinks, extra_sanitizers = language_models(packs, profile.name)
    for item in extra_sources:
        call = str(item.get("call", "")).strip()
        if call:
            source_models.append((rf"(?<![\w$]){re.escape(call)}\s*\(", str(item.get("kind", "untrusted"))))
    for item in extra_sinks:
        call = str(item.get("call", "")).strip()
        if call:
            sinks.append(SinkSpec(
                rf"{re.escape(call)}$", str(item.get("kind", "custom-sink")), str(item.get("cwe", "CWE-20")),
                Severity(str(item.get("severity", "HIGH")).upper()), int(item.get("argument", 0) or 0),
            ))
    for call in extra_sanitizers:
        specs.append(SanitizerSpec(rf"(?<![\w$]){re.escape(call)}\s*\("))
    meta = [{"name": p.name, "version": p.version, "verified": p.verified, "digest": p.digest} for p in packs]
    # User-configured models are language-neutral custom escape hatches.
    for item in config.semantic.sources:
        source_models.append((rf"(?<![\w$]){re.escape(item.call)}\s*\(", item.kind))
    for item in config.semantic.sinks:
        sinks.append(SinkSpec(rf"{re.escape(item.call)}$", item.kind, item.cwe, Severity(item.severity), item.argument))
    for call in config.semantic.sanitizers:
        specs.append(SanitizerSpec(rf"(?<![\w$]){re.escape(call)}\s*\("))
    return specs, meta, source_models, sinks


def _sanitized_for(expr: str, specs: Iterable[SanitizerSpec]) -> set[str]:
    out: set[str] = set()
    for spec in specs:
        if re.search(spec.pattern, expr):
            out.update(spec.safe_for)
    return out


def _sink_for_call(call: Call, line: str, sinks: Iterable[SinkSpec]) -> SinkSpec | None:
    normalized = call.callee.replace("->", ".")
    for sink in sinks:
        if re.search(sink.callee, normalized) and (not sink.guard or re.search(sink.guard, line, re.I)):
            return sink
    return None


def _expr_taint(expr: str, env: dict[str, Taint], profile: LanguageProfile, source_models: Iterable[tuple[str, str]], sanitizers: Iterable[SanitizerSpec], resolve_return) -> Taint | None:
    src = next(((kind, m.start()) for pattern, kind in source_models if (m := re.search(pattern, expr))), None)
    if src:
        taint = Taint(src[0], "", 0, "direct-source")
    else:
        taint = next((value for name, value in env.items() if _contains_var(expr, name)), None)
    for call in _extract_calls(expr):
        returned = resolve_return(call)
        if returned:
            taint = returned
            break
    if taint:
        safe_for = _sanitized_for(expr, sanitizers)
        if safe_for:
            taint = taint.sanitized(safe_for)
    return taint


def _build_summaries(file_infos: dict[str, FileInfo], functions: dict[str, FunctionInfo], by_name: dict[str, list[str]], config: AppConfig, root: Path) -> None:
    """Compute fixed-point symbolic return summaries across project calls."""
    models: dict[str, tuple[list[SanitizerSpec], list[tuple[str, str]]]] = {}
    for lang in {i.profile.name for i in file_infos.values()}:
        profile = next(p for p in _PROFILES if p.name == lang)
        sanitizers, _, sources, _ = _sanitizers(profile, config, root)
        models[lang] = (sanitizers, sources)
    for _ in range(16):
        changed = False
        for fn in functions.values():
            info = file_infos[fn.file]
            sanitizers, source_models = models[fn.language]
            symbolic: dict[str, set[tuple[str, str]]] = {p: {("param", str(i))} for i, p in enumerate(fn.parameters)}
            symbolic_safe: dict[str, set[str]] = {p: set() for p in fn.parameters}
            for lineno in range(fn.start, min(fn.end, len(info.lines)) + 1):
                line = info.lines[lineno - 1]
                assignment = _assignment(line, fn.language)
                if assignment:
                    name, expr = assignment
                    tags: set[tuple[str, str]] = set()
                    src = _source_in_expr(expr, LanguageProfile(fn.language, (), tuple(source_models), ()))
                    if src:
                        tags.add(("source", src[0]))
                    for var, values in symbolic.items():
                        if _contains_var(expr, var):
                            tags.update(values)
                    for call in _extract_calls(expr):
                        callee_id = _resolve_call(call.callee, fn, file_infos, functions, by_name)
                        if not callee_id:
                            continue
                        callee = functions[callee_id]
                        for idx in callee.return_params:
                            if idx < len(call.args):
                                arg = call.args[idx]
                                for var, values in symbolic.items():
                                    if _contains_var(arg, var):
                                        tags.update(values)
                        tags.update(("source", s) for s in callee.return_sources)
                    safe = _sanitized_for(expr, sanitizers)
                    for call in _extract_calls(expr):
                        callee_id = _resolve_call(call.callee, fn, file_infos, functions, by_name)
                        if callee_id:
                            safe.update(functions[callee_id].return_sanitized_for)
                    if tags:
                        symbolic[name] = tags
                        symbolic_safe[name] = set(safe)
                ret = _return_expr(line, fn.language)
                if ret:
                    before_params, before_sources, before_safe = set(fn.return_params), set(fn.return_sources), set(fn.return_sanitized_for)
                    fn.return_sanitized_for.update(_sanitized_for(ret, sanitizers))
                    for var, tags in symbolic.items():
                        if _contains_var(ret, var):
                            fn.return_sanitized_for.update(symbolic_safe.get(var, set()))
                            for kind, value in tags:
                                if kind == "param": fn.return_params.add(int(value))
                                elif kind == "source": fn.return_sources.add(value)
                    src = _source_in_expr(ret, LanguageProfile(fn.language, (), tuple(source_models), ()))
                    if src:
                        fn.return_sources.add(src[0])
                    for call in _extract_calls(ret):
                        callee_id = _resolve_call(call.callee, fn, file_infos, functions, by_name)
                        if not callee_id:
                            continue
                        callee = functions[callee_id]
                        fn.return_sources.update(callee.return_sources)
                        fn.return_sanitized_for.update(callee.return_sanitized_for)
                        for idx in callee.return_params:
                            if idx < len(call.args):
                                arg = call.args[idx]
                                for pidx, p in enumerate(fn.parameters):
                                    if _contains_var(arg, p):
                                        fn.return_params.add(pidx)
                    if before_params != fn.return_params or before_sources != fn.return_sources or before_safe != fn.return_sanitized_for:
                        changed = True
        if not changed:
            break


def _parameter_scalar_safe_for(fn: FunctionInfo, info: FileInfo, index: int) -> set[str]:
    if index >= len(fn.parameters):
        return set()
    param = re.escape(fn.parameters[index].lstrip("$"))
    signature = "\n".join(info.lines[max(0, fn.start - 2): min(len(info.lines), fn.start + 1)])
    patterns = {
        "java": rf"\b(?:byte|short|int|long|float|double|boolean|Byte|Short|Integer|Long|Float|Double|Boolean|UUID|BigInteger|BigDecimal)\s+{param}\b",
        "kotlin": rf"\b{param}\s*:\s*(?:Byte|Short|Int|Long|Float|Double|Boolean|UInt|ULong|UUID)\b",
        "csharp": rf"\b(?:byte|short|int|long|float|double|decimal|bool|Guid|uint|ulong)\s+{param}\b",
        "scala": rf"\b{param}\s*:\s*(?:Byte|Short|Int|Long|Float|Double|Boolean|BigInt|BigDecimal|UUID)\b",
        "swift": rf"\b{param}\s*:\s*(?:Int|Int32|Int64|UInt|UInt32|UInt64|Float|Double|Bool|UUID)\b",
        "dart": rf"\b(?:int|double|bool)\s+{param}\b",
    }
    pattern = patterns.get(fn.language)
    if pattern and re.search(pattern, signature):
        return {"sql-execution", "command-execution", "path-traversal", "code-execution"}
    return set()


def _parameter_source_indices(fn: FunctionInfo, info: FileInfo) -> set[int]:
    if not fn.endpoint or not info.profile.endpoint_param_sources:
        return set()
    # Framework parameter annotations are the strongest evidence.
    signature = "\n".join(info.lines[max(0, fn.start - 2): min(len(info.lines), fn.start + 1)])
    marked: set[int] = set()
    for idx, param in enumerate(fn.parameters):
        if re.search(rf"(?:@(?:RequestParam|PathVariable|RequestBody|RequestHeader)[^\n]*\b{re.escape(param)}\b|\[(?:FromQuery|FromBody|FromRoute|FromHeader)[^\]]*\][^\n]*\b{re.escape(param)}\b)", signature):
            marked.add(idx)
    # ASP.NET controller actions and Spring/Ktor mapped methods routinely model-bind
    # scalar parameters.  Restrict this to actual endpoints, not arbitrary methods.
    if fn.language in {"java", "kotlin", "csharp"} and fn.endpoint:
        marked.update(range(len(fn.parameters)))
    return marked


def _line_cfg(ir: SecurityIR, fn: FunctionInfo, info: FileInfo) -> None:
    previous = ""
    for line in range(fn.start, min(fn.end, len(info.lines)) + 1):
        text = info.lines[line - 1].strip()
        if not text:
            continue
        node = f"{fn.id}:{line}"
        if not previous:
            ir.cfg_edges.append(IRCFGEdge(fn.id, f"{fn.id}:entry", node, "entry"))
        else:
            kind = "branch" if re.search(r"\b(?:if|else|switch|when|match|case|guard)\b", text) else "next"
            ir.cfg_edges.append(IRCFGEdge(fn.id, previous, node, kind))
        previous = node


def _dependency_graph(file_infos: dict[str, FileInfo]) -> dict[str, list[str]]:
    graph: dict[str, list[str]] = {}
    for rel, info in file_infos.items():
        deps: set[str] = set()
        for binding in info.imports.values():
            deps.update(_resolve_relative_target(info, binding.target, file_infos))
        deps.discard(rel)
        graph[rel] = sorted(deps)
    return graph


def _ssrf_authority_can_be_tainted(expr: str) -> bool:
    """Return False when a proven static absolute origin fixes the authority."""
    text = expr.strip()
    m = re.match(r"(?:[rubfRUBF]*)([\"'`])https?://([^/\"'`]+)(/[^\"'`]*)\1", text)
    if m and m.group(3).startswith("/"):
        return False
    if re.match(r"`https?://[^/`]+/[^`]*\$\{", text):
        return False
    return True


def _analyze_project(project: ProjectContext, config: AppConfig, raw_dir: Path) -> tuple[list[Finding], SecurityIR, dict[str, object]]:
    root = Path(project.root).resolve()
    file_infos, functions, by_name = _build_index(root, project.files)
    _build_summaries(file_infos, functions, by_name, config, root)
    ir = SecurityIR(version="4", language="polyglot")
    ir.dependencies = _dependency_graph(file_infos)
    pack_metadata: dict[str, dict[str, object]] = {}
    model_cache: dict[str, tuple[list[SanitizerSpec], list[tuple[str, str]], list[SinkSpec]]] = {}
    for lang in {i.profile.name for i in file_infos.values()}:
        p = next(x for x in _PROFILES if x.name == lang)
        sanitizers, packs, sources, sinks = _sanitizers(p, config, root)
        model_cache[lang] = (sanitizers, sources, sinks)
        for meta in packs:
            pack_metadata[str(meta["name"])] = meta
    for fn in functions.values():
        ir.functions.append(IRFunction(
            id=fn.id, language=fn.language, module=fn.module, file=fn.file,
            name=fn.name, qualified_name=fn.qualified_name, parameters=fn.parameters,
            class_name=fn.class_name, start_line=fn.start, end_line=fn.end,
            return_source_kinds=tuple(sorted(fn.return_sources)), passthrough_params=tuple(sorted(fn.return_params)),
            endpoint=fn.endpoint, http_methods=fn.methods, authentication_required=fn.auth_required,
        ))
        if fn.endpoint:
            ir.endpoints.append(IREndpoint(fn.id, fn.file, fn.start, fn.endpoint, fn.methods, fn.auth_required))
        _line_cfg(ir, fn, file_infos[fn.file])

    # Seed each function to catch local sources; endpoint parameter contexts are seeded separately.
    queue: deque[Context] = deque()
    for fn in functions.values():
        queue.append(Context(fn.id, (), (fn.qualified_name,), fn.endpoint, fn.methods[0] if fn.methods else "", fn.auth_required))
        marked = _parameter_source_indices(fn, file_infos[fn.file])
        if marked:
            seeded: list[tuple[int, Taint]] = []
            for idx in sorted(marked):
                value = Taint("http.parameter", fn.file, fn.start, fn.parameters[idx], (fn.qualified_name,))
                safe_for = _parameter_scalar_safe_for(fn, file_infos[fn.file], idx)
                if safe_for:
                    value = value.sanitized(safe_for)
                seeded.append((idx, value))
            taints = tuple(seeded)
            queue.append(Context(fn.id, taints, (fn.qualified_name,), fn.endpoint, fn.methods[0] if fn.methods else "", fn.auth_required))

    visited: set[tuple[str, tuple[tuple[int, str, tuple[str, ...]], ...], str]] = set()
    findings_by_identity: dict[str, Finding] = {}
    call_edges_seen: set[tuple[str, str, str, int]] = set()
    contexts = 0

    while queue and contexts < config.semantic.max_contexts:
        ctx = queue.popleft()
        fn = functions.get(ctx.function_id)
        if fn is None:
            continue
        key_taints = tuple((i, t.source_kind, t.path[-4:]) for i, t in ctx.tainted_params)
        key = (fn.id, key_taints, ctx.endpoint)
        if key in visited:
            continue
        visited.add(key); contexts += 1
        info = file_infos[fn.file]
        sanitizers, source_models, sinks = model_cache[fn.language]
        env: dict[str, Taint] = {}
        for idx, taint in ctx.tainted_params:
            if idx < len(fn.parameters):
                env[fn.parameters[idx]] = taint

        def resolve_return(call: Call) -> Taint | None:
            callee_id = _resolve_call(call.callee, fn, file_infos, functions, by_name)
            if not callee_id:
                return None
            callee = functions[callee_id]
            for src in sorted(callee.return_sources):
                value = Taint(src, callee.file, callee.start, callee.name, (*ctx.call_path, callee.qualified_name))
                return value.sanitized(callee.return_sanitized_for) if callee.return_sanitized_for else value
            for idx in sorted(callee.return_params):
                if idx >= len(call.args):
                    continue
                arg = call.args[idx]
                for var, taint in env.items():
                    if _contains_var(arg, var):
                        value = taint.through(callee.qualified_name)
                        return value.sanitized(callee.return_sanitized_for) if callee.return_sanitized_for else value
                direct = next(((kind, callee.start) for pattern, kind in source_models if re.search(pattern, arg)), None)
                if direct:
                    return Taint(direct[0], fn.file, direct[1], "direct-source", (*ctx.call_path, callee.qualified_name))
            return None

        for lineno in range(fn.start, min(fn.end, len(info.lines)) + 1):
            line = info.lines[lineno - 1]
            assignment = _assignment(line, fn.language)
            if assignment:
                name, expr = assignment
                taint = _expr_taint(expr, env, info.profile, source_models, sanitizers, resolve_return)
                if taint:
                    if not taint.file:
                        taint = Taint(taint.source_kind, fn.file, lineno, name, (*ctx.call_path,), taint.sanitized_for)
                    env[name] = taint
                else:
                    env.pop(name, None)

            calls = _extract_calls(line)
            for call in calls:
                sink = _sink_for_call(call, line, sinks)
                if sink:
                    arg = call.args[sink.argument] if sink.argument < len(call.args) else (call.args[0] if call.args else "")
                    taint = _expr_taint(arg, env, info.profile, source_models, sanitizers, resolve_return)
                    if sink.kind == "sensitive-data-log":
                        for candidate in call.args:
                            candidate_taint = _expr_taint(candidate, env, info.profile, source_models, sanitizers, resolve_return)
                            if candidate_taint:
                                taint = candidate_taint
                                arg = candidate
                                break
                    if taint and sink.kind not in taint.sanitized_for:
                        if sink.kind == "ssrf" and not _ssrf_authority_can_be_tainted(arg):
                            continue
                        source_file = taint.file or fn.file
                        source_line = taint.line or lineno
                        endpoint = ctx.endpoint or fn.endpoint
                        method = ctx.method or (fn.methods[0] if fn.methods else "")
                        endpoint_label = f"{method} {endpoint}".strip() if endpoint else ""
                        call_path = list(dict.fromkeys([*taint.path, *ctx.call_path, fn.qualified_name]))
                        attack_path = [x for x in (endpoint_label, *call_path, sink.kind) if x]
                        astish = sha256_text(f"{fn.language}|{fn.qualified_name}|{sink.kind}|{re.sub(r'\\s+', ' ', line.strip())}")
                        semantic = sha256_text(f"v4|{fn.language}|{fn.file}|{fn.qualified_name}|{sink.kind}|{astish}|{taint.source_kind}")
                        dataflow = [
                            DataflowStep(kind="source", file=source_file, start_line=source_line, end_line=source_line, content=(file_infos.get(source_file, info).lines[source_line - 1].strip()[:240] if source_file in file_infos and source_line <= len(file_infos[source_file].lines) else ""), symbol=taint.symbol),
                        ]
                        for node in call_path[-config.semantic.max_call_depth:]:
                            dataflow.append(DataflowStep(kind="call", file=fn.file, start_line=lineno, end_line=lineno, symbol=node))
                        dataflow.append(DataflowStep(kind="sink", file=fn.file, start_line=lineno, end_line=lineno, content=line.strip()[:240], symbol=sink.kind))
                        confidence_score = 0.96 if source_file == fn.file else 0.93
                        finding = Finding(
                            tool="dede-semantic-polyglot", rule_id=f"dede.semantic.{fn.language}.{sink.kind}",
                            category=Category.SECURITY, severity=sink.severity, confidence=Confidence.HIGH,
                            confidence_score=confidence_score, precision=sink.precision, cwe=[sink.cwe],
                            file=fn.file, start_line=lineno, end_line=lineno,
                            message=f"Untrusted {taint.source_kind} data reaches {sink.kind} in {fn.language} code.",
                            recommendation="Use a context-appropriate safe API, parameterization, or strict allow-list validation before this sink.",
                            normalized_type=sink.kind, analysis_kind="semantic-polyglot-v4", dataflow=dataflow,
                            semantic_fingerprint=semantic, ast_fingerprint=astish, function=fn.name,
                            class_name=fn.class_name, module=fn.module, source_kind=taint.source_kind, sink_kind=sink.kind,
                            sanitizers=sorted(taint.sanitized_for), call_path=call_path, reachable=True,
                            exploitability_score=94.0 if endpoint else 82.0, endpoint=endpoint, http_method=method,
                            authentication_required=ctx.auth_required if ctx.auth_required is not None else fn.auth_required,
                            internet_exposed=True if endpoint else None, attack_surface=[endpoint_label] if endpoint_label else [],
                            attack_path=attack_path,
                            evidence=[
                                Evidence(kind="semantic-source", value=f"{taint.source_kind}@{source_file}:{source_line}", confidence=0.98),
                                Evidence(kind="semantic-sink", value=f"{sink.kind}@{fn.file}:{lineno}", confidence=0.99),
                                Evidence(kind="interprocedural-context", value=" -> ".join(call_path[-8:]), confidence=0.93),
                            ],
                            engine_version="semantic-polyglot-v4",
                        )
                        findings_by_identity.setdefault(semantic, finding)
                        ir.security_flows.append(IRSecurityFlow(
                            id=semantic, rule_id=finding.rule_id, cwe=tuple(finding.cwe), severity=finding.severity.value,
                            source_kind=taint.source_kind, sink_kind=sink.kind, sink_file=fn.file, sink_line=lineno,
                            function=fn.qualified_name, endpoint=endpoint, http_method=method,
                            authentication_required=finding.authentication_required, internet_exposed=finding.internet_exposed,
                            exploitability_score=finding.exploitability_score, call_path=tuple(call_path),
                            files=tuple(dict.fromkeys([source_file, fn.file])),
                        ))

                callee_id = _resolve_call(call.callee, fn, file_infos, functions, by_name)
                if not callee_id:
                    continue
                callee = functions[callee_id]
                edge = (fn.id, callee.id, fn.file, lineno)
                if edge not in call_edges_seen:
                    call_edges_seen.add(edge)
                    ir.calls.append(IRCallEdge(fn.id, callee.id, fn.file, lineno, True))
                param_taints: list[tuple[int, Taint]] = []
                for idx, arg in enumerate(call.args[:len(callee.parameters)]):
                    taint = _expr_taint(arg, env, info.profile, source_models, sanitizers, resolve_return)
                    if taint:
                        param_taints.append((idx, taint.through(callee.qualified_name)))
                # A source inside a callee is analyzed by its own seed context.  Only
                # enqueue propagated contexts when actual taint crosses the call.
                if param_taints and len(ctx.call_path) < config.semantic.max_call_depth:
                    queue.append(Context(
                        callee.id, tuple(param_taints), (*ctx.call_path, callee.qualified_name),
                        ctx.endpoint or fn.endpoint, ctx.method or (fn.methods[0] if fn.methods else ""),
                        ctx.auth_required if ctx.auth_required is not None else fn.auth_required,
                    ))

    findings = apply_flow_queries(list(findings_by_identity.values()), config)
    ir.stats = {
        "files": len(file_infos), "functions": len(functions), "calls": len(ir.calls),
        "cfg_edges": len(ir.cfg_edges), "flows": len(findings), "endpoints": len(ir.endpoints), "contexts": contexts,
    }
    meta: dict[str, object] = {
        "model_packs": list(pack_metadata.values()),
        "languages": sorted({i.profile.name for i in file_infos.values()}),
        "contexts": contexts,
    }
    return findings, ir, meta


class PolyglotSemanticAnalyzer(Analyzer):
    name = "dede-semantic-polyglot"

    def supports(self, project: ProjectContext) -> bool:
        return any(_profile(Path(path)) is not None for path in project.files)

    def version(self) -> str:
        return "2.0.0"

    def analyze(self, project: ProjectContext, config: AppConfig, raw_dir: Path) -> AnalyzerResult:
        started = time.perf_counter()
        if not config.semantic.enabled:
            return AnalyzerResult(tool=self.name, status=ToolStatus.SKIPPED, version=self.version(), message="semantic analysis disabled")
        findings, ir, meta = _analyze_project(project, config, raw_dir)
        raw_dir.mkdir(parents=True, exist_ok=True)
        payload = ir.to_dict()
        payload.update(meta)
        out = raw_dir / "semantic-polyglot-ir.json"
        out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return AnalyzerResult(
            tool=self.name, status=ToolStatus.SUCCESS, version=self.version(), findings=findings,
            raw_path=str(out), duration_seconds=time.perf_counter() - started,
            coverage={
                "files": ir.stats.get("files", 0), "languages": meta["languages"],
                "functions": ir.stats.get("functions", 0), "calls": ir.stats.get("calls", 0),
                "contexts": ir.stats.get("contexts", 0), "flows": len(findings), "model_packs": meta["model_packs"],
            },
            dependency_graph=ir.dependencies,
        )
