"""Authoritative language-support matrix shown by the CLI and docs/tests."""
from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class LanguageSupport:
    language: str
    engine: str
    level: str
    project_wide: bool
    cross_file: bool
    call_graph: bool
    cfg: bool
    taint: bool
    notes: str = ""


FULL_LANGUAGE_SUPPORT: tuple[LanguageSupport, ...] = (
    LanguageSupport("Python", "semantic-python-v3", "DEEP_SEMANTIC", True, True, True, True, True, "AST frontend + framework-aware dataflow"),
    LanguageSupport("JavaScript", "semantic-polyglot-v4", "PROJECT_SEMANTIC", True, True, True, True, True, "Express/Node sources and sinks"),
    LanguageSupport("TypeScript", "semantic-polyglot-v4", "PROJECT_SEMANTIC", True, True, True, True, True, "Typed JS syntax + Node/web models"),
    LanguageSupport("Java", "semantic-polyglot-v4", "PROJECT_SEMANTIC", True, True, True, True, True, "Spring/JDBC/web models"),
    LanguageSupport("Kotlin", "semantic-polyglot-v4", "PROJECT_SEMANTIC", True, True, True, True, True, "Ktor/Spring/JVM models"),
    LanguageSupport("C#/.NET", "semantic-polyglot-v4 + native-dotnet", "PROJECT_SEMANTIC", True, True, True, True, True, "ASP.NET/EF/ADO.NET models"),
    LanguageSupport("Go", "semantic-polyglot-v4 + gosec/go-vet when available", "PROJECT_SEMANTIC", True, True, True, True, True, "net/http/Gin-style sources and DB/OS sinks"),
    LanguageSupport("PHP", "semantic-polyglot-v4", "PROJECT_SEMANTIC", True, True, True, True, True, "Laravel/PHP request, PDO/mysqli and OS sinks"),
    LanguageSupport("Ruby", "semantic-polyglot-v4", "PROJECT_SEMANTIC", True, True, True, True, True, "Rails/Rack sources and ActiveRecord/OS sinks"),
    LanguageSupport("Rust", "semantic-polyglot-v4", "PROJECT_SEMANTIC", True, True, True, True, True, "Axum-style extractors, sqlx/reqwest/fs models"),
    LanguageSupport("C", "semantic-polyglot-v4", "PROJECT_SEMANTIC", True, True, True, True, True, "argv/environment/network input to libc/DB sinks"),
    LanguageSupport("C++", "semantic-polyglot-v4", "PROJECT_SEMANTIC", True, True, True, True, True, "C/C++ project calls plus command/DB/file sinks"),
    LanguageSupport("Swift", "semantic-polyglot-v4", "PROJECT_SEMANTIC", True, True, True, True, True, "Vapor-style input, URLSession/FileManager/Process sinks"),
    LanguageSupport("Scala", "semantic-polyglot-v4", "PROJECT_SEMANTIC", True, True, True, True, True, "JVM web/JDBC/URL/file models"),
    LanguageSupport("Dart", "semantic-polyglot-v4", "PROJECT_SEMANTIC", True, True, True, True, True, "HTTP request, dart:io and process models"),
)

RULE_BASED_LANGUAGE_SUPPORT: tuple[str, ...] = (
    "Shell", "PowerShell", "Perl", "Lua", "R", "Julia", "Elixir", "Erlang",
    "Clojure", "Haskell", "OCaml", "Solidity", "Apex", "Zig", "Groovy",
    "Objective-C", "Vue", "Svelte",
)


def support_payload() -> dict[str, object]:
    return {
        "semantic_languages": [asdict(item) for item in FULL_LANGUAGE_SUPPORT],
        "rule_based_languages": list(RULE_BASED_LANGUAGE_SUPPORT),
    }
