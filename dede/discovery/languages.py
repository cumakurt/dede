"""Language detection using extensions, shebang, MIME heuristics, and manifests."""

from __future__ import annotations

from collections import Counter
from io import TextIOWrapper
from pathlib import Path

from dede.models import LanguageStats

EXTENSION_MAP: dict[str, str] = {
    ".py": "Python",
    ".pyw": "Python",
    ".pyi": "Python",
    ".js": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".jsx": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".go": "Go",
    ".rs": "Rust",
    ".java": "Java",
    ".kt": "Kotlin",
    ".kts": "Kotlin",
    ".cs": "C#",
    ".csx": "C#",
    ".cshtml": "Razor",
    ".razor": "Razor",
    ".aspx": "ASP.NET",
    ".ascx": "ASP.NET",
    ".ashx": "ASP.NET",
    ".asmx": "ASP.NET",
    ".vbhtml": "Visual Basic",
    ".vb": "Visual Basic",
    ".fs": "F#",
    ".fsx": "F#",
    ".fsi": "F#",
    ".cpp": "C++",
    ".cc": "C++",
    ".cxx": "C++",
    ".c": "C",
    ".h": "C",
    ".hpp": "C++",
    ".rb": "Ruby",
    ".php": "PHP",
    ".swift": "Swift",
    ".scala": "Scala",
    ".sh": "Shell",
    ".bash": "Shell",
    ".zsh": "Shell",
    ".ps1": "PowerShell",
    ".psm1": "PowerShell",
    ".pl": "Perl",
    ".pm": "Perl",
    ".sql": "SQL",
    ".yml": "YAML",
    ".yaml": "YAML",
    ".toml": "TOML",
    ".json": "JSON",
    ".xml": "XML",
    ".config": "XML",
    ".csproj": "XML",
    ".vbproj": "XML",
    ".fsproj": "XML",
    ".slnx": "XML",
    ".props": "XML",
    ".targets": "XML",
    ".resx": "XML",
    ".xaml": "XML",
    ".axaml": "XML",
    ".html": "HTML",
    ".htm": "HTML",
    ".css": "CSS",
    ".scss": "SCSS",
    ".md": "Markdown",
    ".dockerfile": "Dockerfile",
    ".tf": "Terraform",
    ".tfvars": "Terraform",
    ".cls": "Apex",
    ".sol": "Solidity",
    ".ex": "Elixir",
    ".exs": "Elixir",
    ".clj": "Clojure",
    ".dart": "Dart",
    ".lua": "Lua",
    ".ml": "OCaml",
    ".mli": "OCaml",
    ".r": "R",
    ".rmd": "R",
    ".jl": "Julia",
    ".hs": "Haskell",
    ".lhs": "Haskell",
    ".erl": "Erlang",
    ".hrl": "Erlang",
    ".groovy": "Groovy",
    ".gradle": "Groovy",
    ".gvy": "Groovy",
    ".m": "Objective-C",
    ".mm": "Objective-C++",
    ".vue": "Vue",
    ".svelte": "Svelte",
    ".mts": "TypeScript",
    ".cts": "TypeScript",
    ".psd1": "PowerShell",
    ".cljc": "Clojure",
    ".cljs": "Clojure",
    ".ini": "INI",
    ".jsonc": "JSONC",
    ".zig": "Zig",
}

SHEBANG_MAP = {
    "python": "Python",
    "python3": "Python",
    "node": "JavaScript",
    "bash": "Shell",
    "sh": "Shell",
    "zsh": "Shell",
    "ruby": "Ruby",
    "perl": "Perl",
    "php": "PHP",
    "pwsh": "PowerShell",
    "rscript": "R",
    "julia": "Julia",
}


def _detect_shebang(path: Path) -> str | None:
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            first = handle.readline(256)
    except OSError:
        return None
    if not first.startswith("#!"):
        return None
    lower = first.lower()
    for key, lang in SHEBANG_MAP.items():
        if key in lower:
            return lang
    return None


def _count_lines(path: Path) -> int:
    try:
        with path.open("rb") as handle:
            prefix = handle.read(4)
            handle.seek(0)
            if prefix.startswith((b"\xff\xfe", b"\xfe\xff", b"\x00\x00\xfe\xff")):
                encoding = (
                    "utf-32" if prefix in {b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff"} else "utf-16"
                )
                with TextIOWrapper(handle, encoding=encoding) as text:
                    return sum(1 for _ in text)
            return sum(1 for _ in handle)
    except (OSError, UnicodeError):
        return 0


def detect_file_language(path: Path) -> str | None:
    name = path.name.lower()
    if name == "dockerfile" or name.startswith("dockerfile."):
        return "Dockerfile"
    if name in {"makefile", "gnumakefile"}:
        return "Makefile"
    if name in {".editorconfig", ".npmrc", ".pypirc", "pip.conf"}:
        return "INI"
    if name == "jenkinsfile":
        return "Groovy"
    ext = path.suffix.lower()
    if ext in EXTENSION_MAP:
        return EXTENSION_MAP[ext]
    return _detect_shebang(path)


def detect_languages(files: list[Path], root: Path) -> LanguageStats:
    counts: Counter[str] = Counter()
    total_lines = 0
    for path in files:
        lang = detect_file_language(path)
        if not lang:
            continue
        lines = _count_lines(path)
        counts[lang] += max(1, lines)
        total_lines += lines

    percentages: dict[str, float] = {}
    if counts:
        total = sum(counts.values())
        for lang, value in counts.most_common():
            percentages[lang] = round((value / total) * 100.0, 1)

    return LanguageStats(
        languages=percentages,
        files_scanned=len(files),
        lines_scanned=total_lines,
    )
