"""Offset-preserving lexical preparation for native rules and C# local flow.

This lexer recognizes comments and quoted text; it is deliberately not a
compiler. Strings remain available to API/configuration rules. Token offsets
always refer to the original, newline-normalized source.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache


@dataclass(frozen=True)
class Token:
    text: str
    start: int
    end: int
    kind: str


_SLASH_LANGUAGES = {
    "c#",
    "razor",
    "c",
    "c++",
    "java",
    "javascript",
    "typescript",
    "go",
    "rust",
    "kotlin",
    "scala",
    "swift",
    "dart",
    "php",
    "solidity",
    "apex",
    "f#",
    "groovy",
    "objective-c",
    "objective-c++",
    "hcl",
    "terraform",
    "jsonc",
    "zig",
}
_HASH_LANGUAGES = {
    "python",
    "ruby",
    "shell",
    "powershell",
    "perl",
    "r",
    "julia",
    "yaml",
    "toml",
    "dockerfile",
    "makefile",
    "elixir",
    "php",
    "terraform",
    "hcl",
    "ini",
}
MAX_SOURCE_TOKENS = 200_000


def _quoted_end(text: str, start: int, quote_at: int, *, doubled: bool = False) -> int:
    quote = text[quote_at]
    run = 1
    while quote_at + run < len(text) and text[quote_at + run] == quote:
        run += 1
    delimiter = quote * run if run >= 3 else quote
    i = quote_at + len(delimiter)
    while i < len(text):
        if text.startswith(delimiter, i):
            if doubled and len(delimiter) == 1 and text.startswith(quote * 2, i):
                i += 2
                continue
            return i + len(delimiter)
        if text[i] == "\\" and not doubled and len(delimiter) == 1:
            i += 2
        else:
            i += 1
    return len(text)


def tokens(text: str, language: str = "c#") -> tuple[Token, ...]:
    language = language.lower()
    result: list[Token] = []
    i = 0
    while i < len(text):
        if len(result) >= MAX_SOURCE_TOKENS:
            raise ValueError("Native source token limit exceeded")
        start = i
        if text[i].isspace():
            i += 1
            continue
        block = None
        if language in _SLASH_LANGUAGES and text.startswith("/*", i):
            block = ("/*", "*/")
        elif language in {"html", "xml", "razor", "vue", "svelte", "asp.net"} and text.startswith(
            "<!--", i
        ):
            block = ("<!--", "-->")
        elif language == "asp.net" and text.startswith("<%--", i):
            block = ("<%--", "--%>")
        elif language == "razor" and text.startswith("@*", i):
            block = ("@*", "*@")
        elif language in {"f#", "ocaml"} and text.startswith("(*", i):
            block = ("(*", "*)")
        elif language == "powershell" and text.startswith("<#", i):
            block = ("<#", "#>")
        elif language == "lua" and text.startswith("--[[", i):
            block = ("--[[", "]]")
        elif language == "julia" and text.startswith("#=", i):
            block = ("#=", "=#")
        elif language == "sql" and text.startswith("/*", i):
            block = ("/*", "*/")
        if block:
            opener, closer = block
            i += len(opener)
            depth = 1
            nested = language in {"f#", "ocaml", "rust", "swift", "kotlin", "julia"}
            while i < len(text) and depth:
                if nested and text.startswith(opener, i):
                    depth += 1
                    i += len(opener)
                elif text.startswith(closer, i):
                    depth -= 1
                    i += len(closer)
                else:
                    i += 1
            result.append(Token(text[start:i], start, i, "comment"))
            continue
        line_comment = (
            (language in _SLASH_LANGUAGES and text.startswith("//", i))
            or (language in _HASH_LANGUAGES and text[i] == "#")
            or (language in {"sql", "lua", "haskell"} and text.startswith("--", i))
            or (language == "visual basic" and text[i] == "'")
            or (language in {"clojure", "lisp"} and text[i] == ";")
            or (language in {"erlang", "matlab"} and text[i] == "%")
        )
        if line_comment:
            end = text.find("\n", i)
            i = len(text) if end < 0 else end
            result.append(Token(text[start:i], start, i, "comment"))
            continue
        quote_at = i
        if language in {"c#", "razor"}:
            while quote_at < len(text) and text[quote_at] in "@$":
                quote_at += 1
        lifetime = (
            language in {"rust", "f#", "ocaml"}
            and text[i] == "'"
            and i + 2 < len(text)
            and text[i + 1].isalpha()
            and text[i + 2] != "'"
        )
        if not lifetime and quote_at < len(text) and text[quote_at] in "\"'`":
            i = _quoted_end(
                text,
                start,
                quote_at,
                doubled=("@" in text[start:quote_at] or language in {"visual basic", "sql"}),
            )
            result.append(Token(text[start:i], start, i, "string"))
            continue
        if text[i].isalpha() or text[i] in "_@":
            i += 1
            while i < len(text) and (text[i].isalnum() or text[i] == "_"):
                i += 1
            kind = "identifier"
        elif text[i].isdigit():
            i += 1
            while i < len(text) and (text[i].isalnum() or text[i] == "."):
                i += 1
            kind = "number"
        else:
            i += (
                2
                if text[i : i + 2] in {"=>", "==", "!=", "+=", "??", "?.", "&&", "||", "::"}
                else 1
            )
            kind = "punctuation"
        result.append(Token(text[start:i], start, i, kind))
    return tuple(result)


def mask_comments(text: str, language: str) -> str:
    chunks: list[str] = []
    previous = 0
    for token in tokens(text, language):
        if token.kind != "comment":
            continue
        chunks.append(text[previous : token.start])
        chunks.append("".join("\n" if char == "\n" else " " for char in token.text))
        previous = token.end
    chunks.append(text[previous:])
    return "".join(chunks)


@lru_cache(maxsize=2048)
def compiled_regex(pattern: str):
    import re

    return re.compile(pattern)
