"""Conservative C# local source-to-sink analysis without compiling projects.

Tracks local assignments and expressions in lexical method scopes. Conditional
assignments retain the incoming possibility of taint. Calls are identified by
API names, not resolved types; arbitrary calls propagate argument taint. There
is no interprocedural, heap, control-flow graph or runtime exploitability claim.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from dede.engine.matcher import Match, SourceFile
from dede.engine.rules import DedRule
from dede.engine.source import Token, compiled_regex, tokens

Trace = tuple[dict, ...]
Value = dict[str, Trace]
Environment = dict[str, Value]
_CATEGORIES = {
    "sql",
    "command",
    "arguments",
    "path",
    "ssrf",
    "xss",
    "redirect",
    "xpath",
    "regex",
    "ldap",
    "code",
}
_CONTROL = {"if", "for", "foreach", "while", "switch", "catch", "using", "lock", "fixed"}
_NUMERIC = {
    "int",
    "long",
    "short",
    "byte",
    "uint",
    "ulong",
    "ushort",
    "sbyte",
    "bool",
    "Guid",
    "Int32",
    "Int64",
    "Boolean",
}
_SOURCE_PROPERTIES = {
    "Query",
    "QueryString",
    "Form",
    "Headers",
    "Cookies",
    "Params",
    "Body",
    "RouteValues",
    "RawUrl",
    "Path",
    "Unvalidated",
}
_BINDING = re.compile(r"^From(?:Query|Route|Body|Form|Header)(?:Attribute)?$")
MAX_TRACE_STEPS = 24
MAX_EXPRESSION_DEPTH = 40


def _merge(*values: Value) -> Value:
    merged: Value = {}
    for value in values:
        for category, trace in value.items():
            merged.setdefault(category, trace)
    return merged


def _pairs(items: tuple[Token, ...]) -> dict[int, int]:
    stack: list[int] = []
    pairs: dict[int, int] = {}
    for i, item in enumerate(items):
        if item.text in {"(", "[", "{"}:
            stack.append(i)
        elif item.text in {")", "]", "}"}:
            expected = {")": "(", "]": "[", "}": "{"}[item.text]
            if stack and items[stack[-1]].text == expected:
                start = stack.pop()
                pairs[start] = i
                pairs[i] = start
    return pairs


def _arguments(items: tuple[Token, ...]) -> list[tuple[Token, ...]]:
    groups: list[tuple[Token, ...]] = []
    start = 0
    depth = 0
    for i, item in enumerate(items):
        if item.text in {"(", "[", "{"}:
            depth += 1
        elif item.text in {")", "]", "}"}:
            depth -= 1
        elif item.text == "," and depth == 0:
            groups.append(items[start:i])
            start = i + 1
    if start < len(items):
        groups.append(items[start:])
    return groups


@dataclass(frozen=True)
class Call:
    name: str
    start: int
    opening: int
    end: int
    arguments: list[tuple[Token, ...]]


def _calls(items: tuple[Token, ...]) -> list[Call]:
    pairs = _pairs(items)
    calls: list[Call] = []
    for i, item in enumerate(items):
        if item.text != "(" or i not in pairs or i == 0:
            continue
        last = i - 1
        if items[last].text == ">":
            while last >= 0 and items[last].text != "<":
                last -= 1
            last -= 1
        if last < 0 or items[last].kind != "identifier":
            continue
        start = last
        while (
            start >= 2
            and items[start - 1].text in {".", "?.", "::"}
            and items[start - 2].kind == "identifier"
        ):
            start -= 2
        name = (
            "".join(token.text for token in items[start : last + 1])
            .replace("?.", ".")
            .replace("::", ".")
        )
        end = pairs[i]
        calls.append(Call(name, start, i, end, _arguments(items[i + 1 : end])))
    return calls


class LocalFlow:
    def __init__(self, source: SourceFile, rules: tuple[DedRule, ...], limit: int):
        self.source = source
        self.rules = rules
        self.limit = limit
        self.environment: Environment = {}
        self.request_names = {"Request", "request"}
        self.matches: list[Match] = []
        self.seen: set[tuple[str, int]] = set()
        self.aliases: dict[str, str] = {}

    def step(self, kind: str, token: Token) -> dict:
        line = self.source.line_at(token.start)
        return {
            "kind": kind,
            "file": self.source.relative_path,
            "start_line": line,
            "end_line": self.source.line_at(max(token.start, token.end - 1)),
            "content": self.source.redacted_lines[line - 1][:240],
        }

    def source_value(self, token: Token) -> Value:
        trace = (self.step("source", token),)
        return {category: trace for category in _CATEGORIES}

    def expression(self, items: tuple[Token, ...], depth: int = 0) -> Value:
        if depth > MAX_EXPRESSION_DEPTH:
            raise ValueError("Native C# expression depth limit exceeded")
        if (
            len(items) >= 3
            and items[0].text == "("
            and items[1].text in _NUMERIC
            and items[2].text == ")"
        ):
            nesting = 0
            for i in range(3, len(items)):
                marker = items[i].text
                if nesting == 0 and marker in {"+", "-", "?", "??", "*", "/"}:
                    return self.expression(items[i + 1 :], depth + 1)
                if marker in {"(", "["}:
                    nesting += 1
                elif marker in {")", "]"}:
                    nesting -= 1
            return {}
        value: Value = {}
        calls = {call.start: call for call in _calls(items)}
        i = 0
        while i < len(items):
            token = items[i]
            call = calls.get(i)
            if call:
                args = _merge(*(self.expression(arg, depth + 1) for arg in call.arguments))
                receiver = call.name.split(".")[0]
                args = _merge(self.environment.get(receiver, {}), args)
                short = call.name.rsplit(".", 1)[-1]
                if call.name in {
                    "Console.ReadLine",
                    "Console.Read",
                    "Environment.GetCommandLineArgs",
                }:
                    args = self.source_value(token)
                if call.name in {
                    "WebUtility.HtmlEncode",
                    "HttpUtility.HtmlEncode",
                    "Server.HtmlEncode",
                    "System.Net.WebUtility.HtmlEncode",
                    "System.Web.HttpUtility.HtmlEncode",
                    "HtmlEncoder.Default.Encode",
                    "System.Text.Encodings.Web.HtmlEncoder.Default.Encode",
                }:
                    args.pop("xss", None)
                if call.name in {"Regex.Escape", "System.Text.RegularExpressions.Regex.Escape"}:
                    args.pop("regex", None)
                if short in {
                    "Parse",
                    "ToInt32",
                    "ToInt64",
                    "ToBoolean",
                } and receiver in _NUMERIC | {"Convert"}:
                    args = {}
                value = _merge(value, args)
                i = call.end + 1
                continue
            if token.kind == "string":
                if "$" in token.text[: token.text.find('"')]:
                    # Interpolation holes are expressions; ordinary string
                    # contents cannot introduce taint through identifier text.
                    for hole in re.finditer(r"(?<!\{)\{([^{}]+)\}(?!\})", token.text):
                        inner = tokens(hole.group(1), "c#")
                        shifted = tuple(
                            Token(
                                t.text,
                                token.start + hole.start(1) + t.start,
                                token.start + hole.start(1) + t.end,
                                t.kind,
                            )
                            for t in inner
                        )
                        value = _merge(value, self.expression(shifted, depth + 1))
            elif token.kind == "identifier":
                if (
                    token.text in self.request_names
                    and i + 2 < len(items)
                    and items[i + 1].text in {".", "?."}
                    and items[i + 2].text in _SOURCE_PROPERTIES
                ):
                    value = _merge(value, self.source_value(token))
                elif i == 0 or items[i - 1].text not in {".", "?.", "::"}:
                    value = _merge(value, self.environment.get(token.text, {}))
            i += 1
        return value

    def emit(self, rule: DedRule, token: Token, value: Value) -> None:
        if len(self.matches) >= self.limit:
            return
        trace = value.get(rule.taint_sink)
        key = (rule.id, token.start)
        if not trace or key in self.seen:
            return
        self.seen.add(key)
        line = self.source.line_at(token.start)
        self.matches.append(
            Match(
                rule.id,
                self.source.relative_path,
                line,
                line,
                self.source.redacted_lines[line - 1][:400],
                (*trace, self.step("sink", token)),
            )
        )

    def inspect_calls(self, items: tuple[Token, ...]) -> None:
        for call in _calls(items):
            receiver, separator, suffix = call.name.partition(".")
            call_name = self.aliases.get(receiver, receiver) + separator + suffix
            for rule in self.rules:
                if not compiled_regex(rule.when[0].regex).search(call_name):
                    continue
                if not call.arguments:
                    continue
                position = (
                    1
                    if rule.taint_sink == "regex" and call.name.rsplit(".", 1)[-1] != "Regex"
                    else 0
                )
                expected = {
                    "regex": {"pattern"},
                    "sql": {"sql", "cmdText", "commandText", "query"},
                    "path": {"path", "fileName"},
                    "ssrf": {"requestUri", "address", "url"},
                    "command": {"fileName"},
                    "xss": {"value", "html", "text"},
                    "redirect": {"url", "location"},
                    "xpath": {"xpath", "expression"},
                }.get(rule.taint_sink, set())
                selected = []
                for arg in call.arguments:
                    if expected and len(arg) > 2 and arg[0].text in expected and arg[1].text == ":":
                        selected = [arg[2:]]
                        break
                if not selected and position < len(call.arguments):
                    selected = [call.arguments[position]]
                if (
                    rule.taint_sink == "command"
                    and len(call.arguments) > 1
                    and call_name.endswith(("Process.Start", "ProcessStartInfo"))
                ):
                    executable = call.arguments[0]
                    if len(executable) == 1 and executable[0].kind == "string":
                        name = re.split(r"[/\\]", executable[0].text.strip("@\"'"))[-1].lower()
                        if name in {
                            "sh",
                            "bash",
                            "zsh",
                            "cmd",
                            "cmd.exe",
                            "powershell",
                            "powershell.exe",
                            "pwsh",
                        }:
                            selected = call.arguments[:2]
                if rule.taint_sink == "path" and call.name.endswith(("File.Copy", "File.Move")):
                    selected = call.arguments[:2]
                self.emit(
                    rule, items[call.start], _merge(*(self.expression(arg) for arg in selected))
                )

    def statement(self, items: tuple[Token, ...]) -> None:
        if not items or len(self.matches) >= self.limit:
            return
        arrow = next((i for i, t in enumerate(items) if t.text == "=>"), None)
        if arrow is not None:
            declarations = [c for c in _calls(items[:arrow]) if c.end == arrow - 1 and c.start > 0]
            if declarations:
                declaration = declarations[0]
                incoming, requests = self.environment, self.request_names
                self.environment, self.request_names = {}, {"Request", "request"}
                self.bind_parameters(items[declaration.opening + 1 : declaration.end])
                self.statement(items[arrow + 1 :])
                self.environment, self.request_names = incoming, requests
                return
        self.inspect_calls(items)
        for i, token in enumerate(items):
            if token.text not in {"=", "+="} or i == 0:
                continue
            for rule in self.rules:
                if not compiled_regex(rule.when[0].regex).search(items[i - 1].text):
                    continue
                end, nesting = i + 1, 0
                while end < len(items):
                    marker = items[end].text
                    if nesting == 0 and marker in {",", ";", "}"}:
                        break
                    if marker in {"(", "[", "{"}:
                        nesting += 1
                    elif marker in {")", "]", "}"}:
                        nesting -= 1
                    end += 1
                self.emit(rule, items[i - 1], self.expression(items[i + 1 : end]))
        # A declaration/assignment updates only the actual left-hand variable.
        # Named arguments and equality operators never become assignments.
        depth = 0
        for i, token in enumerate(items):
            if token.text in {"(", "["}:
                depth += 1
            elif token.text in {")", "]"}:
                depth -= 1
            if token.text not in {"=", "+="} or depth or i == 0:
                continue
            lhs = items[i - 1]
            if lhs.kind != "identifier":
                continue
            rhs = items[i + 1 :]
            value = self.expression(rhs)
            if i >= 2 and items[i - 2].text in {".", "?."}:
                continue  # Property/heap alias tracking is outside local scope.
            if token.text == "+=" or any(t.text in {"if", "else"} for t in items[:i]):
                value = _merge(self.environment.get(lhs.text, {}), value)
            self.environment[lhs.text] = {
                kind: (*trace[: MAX_TRACE_STEPS - 2], self.step("propagation", lhs))
                for kind, trace in value.items()
            }
            break
        else:
            if len(items) >= 2 and all(t.kind == "identifier" for t in items):
                self.environment.setdefault(items[-1].text, {})

    def bind_parameters(self, parameters: tuple[Token, ...]) -> None:
        for arg in _arguments(parameters):
            names = [token for token in arg if token.kind == "identifier"]
            if not names:
                continue
            name = names[-1]
            if any(t.text in {"HttpRequest", "HttpRequestBase"} for t in names):
                self.request_names.add(name.text)
            if any(_BINDING.fullmatch(t.text) for t in names) and not any(
                t.text in _NUMERIC for t in names
            ):
                self.environment[name.text] = self.source_value(name)

    def run(self) -> list[Match]:
        language = "razor" if self.source.relative_path.endswith((".razor", ".cshtml")) else "c#"
        items = tuple(t for t in tokens(self.source.text, language) if t.kind != "comment")
        pairs = _pairs(items)
        for i in range(len(items) - 3):
            if items[i].text == "using" and items[i + 2].text == "=":
                end = i + 3
                while end < len(items) and items[end].text != ";":
                    end += 1
                self.aliases[items[i + 1].text] = "".join(
                    t.text for t in items[i + 3 : end]
                ).replace("::", ".")
        # Frames retain method isolation and a conservative merge at branches.
        frames: list[tuple[str, Environment, set[str], int]] = []
        start = 0
        initializer_depth = 0
        paren_depth = 0
        for i, token in enumerate(items):
            if len(self.matches) >= self.limit:
                break
            if token.text == "(":
                paren_depth += 1
            elif token.text == ")":
                paren_depth -= 1
            elif token.text == "{" and token.kind == "punctuation":
                header = items[start:i]
                previous = items[i - 1].text if i else ""
                method_open = pairs.get(i - 1) if previous == ")" else None
                lambda_open = (
                    pairs.get(i - 2)
                    if previous == "=>" and i >= 2 and items[i - 2].text == ")"
                    else None
                )
                opening = method_open if method_open is not None else lambda_open
                name = items[opening - 1].text if opening is not None and opening else ""
                is_method = (
                    opening is not None
                    and name not in _CONTROL
                    and (
                        previous == "=>"
                        or (opening >= 2 and items[opening - 2].text not in {".", "new", "="})
                    )
                )
                is_initializer = initializer_depth > 0 or (
                    not is_method
                    and (previous in {"=", "[", ","} or any(t.text == "new" for t in header))
                )
                if is_initializer:
                    initializer_depth += 1
                    continue
                kind = "method" if is_method else "branch"
                frames.append((kind, dict(self.environment), set(self.request_names), paren_depth))
                if is_method:
                    self.environment = {}
                    self.request_names = {"Request", "request"}
                    paren_depth = 0
                    assert opening is not None
                    self.bind_parameters(items[opening + 1 : pairs[opening]])
                else:
                    self.inspect_calls(header)
                start = i + 1
            elif token.text == "}" and token.kind == "punctuation":
                if initializer_depth:
                    initializer_depth -= 1
                    continue
                self.statement(items[start:i])
                if frames:
                    kind, incoming, requests, incoming_parens = frames.pop()
                    if kind == "method":
                        self.environment = incoming
                        self.request_names = requests
                        paren_depth = incoming_parens
                    else:
                        self.environment = {
                            name: _merge(value, self.environment.get(name, {}))
                            for name, value in incoming.items()
                        }
                start = i + 1
            elif token.text == ";" and paren_depth == 0:
                self.statement(items[start:i])
                start = i + 1
        self.statement(items[start:])
        return self.matches[: self.limit]


def analyze_local_flow(source: SourceFile, rules: tuple[DedRule, ...], limit: int) -> list[Match]:
    return LocalFlow(source, rules, limit).run()
