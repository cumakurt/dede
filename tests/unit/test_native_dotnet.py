"""Native .NET checks: unsafe inputs, safe alternatives and local-flow precision."""

import json
from pathlib import Path

import pytest

from dede.config import AppConfig
from dede.discovery.languages import detect_file_language
from dede.engine.analyzer import DedeEngineAnalyzer
from dede.engine.dotnet import analyze_local_flow
from dede.engine.matcher import SourceFile, match_rule
from dede.engine.rules import load_rules_dir
from dede.models import ProjectContext, ToolStatus

ROOT = Path(__file__).resolve().parents[2]
RULES = tuple(r for f in load_rules_dir(ROOT / "rules/dede-engine") for r in f.rules)
FLOW_RULES = tuple(r for r in RULES if r.mode == "taint")
DOTNET_CASES = json.loads((ROOT / "tests/rule_samples/native_dotnet_cases.json").read_text())


@pytest.mark.parametrize("case", DOTNET_CASES, ids=lambda c: c["rule_id"])
def test_every_dotnet_rule_has_unsafe_and_safe_counterexample(case):
    rule = next(r for r in RULES if r.id == case["rule_id"])
    language = detect_file_language(Path(case["filename"])).lower()
    bad = SourceFile.from_text(case["filename"], case["unsafe"])
    safe = SourceFile.from_text(case["filename"], case["safe"])
    assert match_rule(rule, bad, language), rule.id
    assert not match_rule(rule, safe, language), rule.id
    if language != "json":
        comment = (
            "<!-- {} -->"
            if language in {"xml", "asp.net"}
            else "@* {} *@"
            if language == "razor"
            else "/* {} */"
        )
        assert not match_rule(
            rule, SourceFile.from_text(case["filename"], comment.format(case["unsafe"])), language
        )


def test_dotnet_corpus_covers_complete_declarative_bundle():
    expected = {r.id for r in RULES if r.id.startswith("dede.dotnet.") and r.mode != "taint"}
    assert {case["rule_id"] for case in DOTNET_CASES} == expected


def flow(text, category=None, filename="Controller.cs"):
    matches = analyze_local_flow(SourceFile.from_text(filename, text), FLOW_RULES, 100)
    return [m for m in matches if category is None or m.rule_id == "dede.dotnet.flow." + category]


FLOW_CASES = [
    (
        "sql",
        'new SqlCommand("SELECT * FROM users WHERE name = " + value);',
        'new SqlCommand("SELECT * FROM users WHERE name = @name");',
    ),
    ("command", "Process.Start(value);", 'Process.Start("/usr/bin/fixed-tool");'),
    ("arguments", "process.Arguments = value;", "process.ArgumentList.Add(value);"),
    ("path", "File.ReadAllText(value);", 'File.ReadAllText("approved.txt");'),
    ("ssrf", "client.GetAsync(value);", 'client.GetAsync("https://example.test/");'),
    ("xss", "Html.Raw(value);", "Html.Raw(WebUtility.HtmlEncode(value));"),
    ("redirect", "Redirect(value);", "LocalRedirect(value);"),
    ("xpath", "doc.SelectSingleNode(value);", 'doc.SelectSingleNode("/root/item");'),
    ("regex", 'Regex.IsMatch("text", value);', 'Regex.IsMatch(value, "^[a-z]+$");'),
    ("ldap", "new DirectorySearcher(value);", 'new DirectorySearcher("(objectClass=person)");'),
    ("code", "Assembly.LoadFrom(value);", 'Assembly.LoadFrom("approved.dll");'),
]


@pytest.mark.parametrize("category,unsafe,safe", FLOW_CASES)
def test_each_flow_sink_has_safe_argument_counterexample(category, unsafe, safe):
    prefix = 'var value = Request.Query["input"];\n'
    matches = flow(prefix + unsafe, category)
    assert matches
    assert not flow(prefix + safe, category)
    assert matches[0].dataflow[0]["kind"] == "source"
    assert matches[0].dataflow[-1]["kind"] == "sink"


def test_flow_corpus_covers_every_flow_rule():
    assert {r.taint_sink for r in FLOW_RULES} == {category for category, _, _ in FLOW_CASES}


def test_flow_rules_have_required_security_metadata():
    for rule in FLOW_RULES:
        assert rule.cwe, rule.id
        assert rule.owasp or rule.asvs, rule.id
        assert rule.recommendation, rule.id
        assert rule.references, rule.id


@pytest.mark.parametrize(
    "sink",
    [
        "db.FromSqlRaw(query);",
        "db.ExecuteSqlRawAsync(query);",
        "connection.Query<User>(query);",
        "connection.QueryFirstOrDefaultAsync<User>(query);",
        "cmd.CommandText = query;",
        "new SqlCommand(query);",
    ],
)
def test_sql_aliases_multiline_expressions_and_sink_location(sink):
    source = (
        'public void Get() {\nvar user = Request.Query["user"];\nvar alias = user;\nvar query =\n "SELECT * FROM users WHERE name=" + alias;\n'
        + sink
        + "\n}"
    )
    matches = flow(source, "sql")
    assert len(matches) == 1
    assert matches[0].start_line == 6
    steps = matches[0].dataflow
    assert steps[0]["start_line"] == 2
    assert steps[-1]["start_line"] == 6
    assert any(s["start_line"] == 3 and s["kind"] == "propagation" for s in steps)


@pytest.mark.parametrize(
    "source",
    [
        'Request.Query["q"]',
        'HttpContext.Request.Form["q"]',
        'Request.QueryString["q"]',
        'Request.Headers["q"]',
        'Request.Cookies["q"]',
        'Request.RouteValues["q"]',
        'Request.Unvalidated.QueryString["q"]',
        "Console.ReadLine()",
    ],
)
def test_request_and_console_sources(source):
    assert flow(f"var value = {source}; Process.Start(value);", "command")


@pytest.mark.parametrize(
    "attribute",
    [
        "FromQuery",
        "FromRoute",
        "FromBody",
        "FromForm",
        "FromHeader",
        'Microsoft.AspNetCore.Mvc.FromQueryAttribute(Name = "q")',
    ],
)
def test_bound_string_parameters(attribute):
    assert flow(
        f"public void Get([{attribute}] string value) {{ Process.Start(value); }}", "command"
    )


def test_bound_numeric_parameter_is_not_string_taint():
    assert not flow('public void Get([FromQuery] int id) { db.FromSqlRaw("SELECT " + id); }', "sql")


def test_typed_http_request_lambda_source():
    assert flow(
        'app.MapGet("/", (HttpRequest req) => { var value = req.Query["q"]; return Redirect(value); });',
        "redirect",
    )


def test_expression_bodied_action_parameter():
    assert flow(
        "public IActionResult Get([FromQuery] string value) => Redirect(value);", "redirect"
    )


@pytest.mark.parametrize(
    "statement",
    [
        'var query = $"SELECT {value}"; db.FromSqlRaw(query);',
        'var query = $@"SELECT {value}"; db.FromSqlRaw(query);',
        'var query = $"""SELECT {value}"""; db.FromSqlRaw(query);',
        'var query = string.Format("SELECT {0}", value); db.FromSqlRaw(query);',
    ],
)
def test_interpolation_and_format_propagate(statement):
    assert flow('var value = Request.Query["q"];\n' + statement, "sql")


@pytest.mark.parametrize(
    "statement",
    [
        'db.FromSqlInterpolated($"SELECT {value}");',
        'db.FromSql($"SELECT {value}");',
        'db.FromSqlRaw("SELECT * FROM users WHERE name={0}", value);',
        'connection.Query<User>("SELECT * FROM users WHERE name=@name", new { name = value });',
        'var query = "value"; db.FromSqlRaw(query);',
        'value = "SELECT 1"; db.FromSqlRaw(value);',
        'db.FromSqlRaw("SELECT " + int.Parse(value));',
    ],
)
def test_safe_sql_and_reassignment(statement):
    assert not flow('var value = Request.Query["q"];\n' + statement, "sql")


def test_parameterization_does_not_sanitize_an_already_concatenated_query():
    assert flow('var value = Request.Query["q"]; db.FromSqlRaw("SELECT " + value, 42);', "sql")


def test_safe_reassignment_in_one_branch_does_not_erase_other_path():
    assert flow(
        'var value = Request.Query["q"]; if (flag) { value = "safe"; } Process.Start(value);',
        "command",
    )
    assert flow(
        'var value = Request.Query["q"]; if (flag) value = "safe"; Process.Start(value);', "command"
    )


def test_taint_from_branch_merges_into_outer_declared_variable():
    assert flow(
        'string value; if (flag) { value = Request.Query["q"]; } Process.Start(value);', "command"
    )


def test_method_scope_prevents_variable_name_leakage():
    assert not flow(
        'class C { void A() { var value = Request.Query["q"]; } void B() { var value = "fixed"; Process.Start(value); } }',
        "command",
    )


def test_one_method_cannot_supply_missing_value_in_another():
    assert not flow(
        'class C { void A() { var value = Request.Query["q"]; } void B(string value) { Process.Start(value); } }',
        "command",
    )


def test_strings_and_comments_cannot_create_input_sources():
    assert not flow('var value = "Request.Query[value]"; Process.Start(value);', "command")
    assert not flow('/* var value = Request.Query["q"]; */ Process.Start(value);', "command")


def test_context_specific_sanitizer_does_not_sanitize_sql():
    assert flow(
        'var value = WebUtility.HtmlEncode(Request.Query["q"]); db.FromSqlRaw(value);', "sql"
    )
    assert not flow(
        'var value = WebUtility.HtmlEncode(Request.Query["q"]); Html.Raw(value);', "xss"
    )


def test_encoding_one_operand_does_not_sanitize_another():
    assert flow(
        'var value = Request.Query["q"]; Html.Raw(WebUtility.HtmlEncode(value) + value);', "xss"
    )


def test_regex_escape_is_specific_to_pattern_and_argument_position():
    assert not flow(
        'var value = Request.Query["q"]; Regex.IsMatch("text", Regex.Escape(value));', "regex"
    )
    assert flow('Regex.IsMatch(pattern: Request.Query["q"], input: "fixed");', "regex")


def test_path_normalization_does_not_prove_containment():
    assert flow(
        'var path = Path.GetFullPath(Request.Query["path"]); File.ReadAllText(path);', "path"
    )


def test_numeric_cast_only_sanitizes_its_operand():
    assert not flow('var value = Request.Query["q"]; db.FromSqlRaw((int)value);', "sql")
    assert flow('var value = Request.Query["q"]; db.FromSqlRaw((int)value + value);', "sql")


def test_unresolved_htmlencode_name_is_not_trusted_as_a_sanitizer():
    assert flow('var value = Request.Query["q"]; Html.Raw(custom.HtmlEncode(value));', "xss")


@pytest.mark.parametrize("api", ["Process.Start", "new ProcessStartInfo"])
def test_fixed_shell_executable_still_has_tainted_commands(api):
    assert flow(f'var value = Request.Query["q"]; {api}("/bin/sh", "-c " + value);', "command")


def test_imported_sql_constructor_alias():
    assert flow(
        'using Sql = Microsoft.Data.SqlClient.SqlCommand; var value = Request.Query["q"]; new Sql(value);',
        "sql",
    )


def test_object_initializer_command_text():
    assert flow(
        'var value = Request.Query["q"]; var cmd = new SqlCommand { CommandText = value };', "sql"
    )


@pytest.mark.parametrize(
    "filename,text,rule_id",
    [
        ("Auth.vb", "settings.ValidateIssuer = False", "dede.dotnet.jwt.validate-issuer"),
        ("Auth.fs", "settings.ValidateIssuer <- false", "dede.dotnet.jwt.validate-issuer"),
        (
            "Json.fs",
            "settings.TypeNameHandling <- TypeNameHandling.Auto",
            "dede.dotnet.deserialization.json-type-name",
        ),
        (
            "Json.vb",
            "settings.TypeNameHandling = TypeNameHandling.Auto",
            "dede.dotnet.deserialization.json-type-name",
        ),
        (
            "Tls.vb",
            "handler.ServerCertificateCustomValidationCallback = Function(s, c, ch, e) True",
            "dede.dotnet.tls.callback-always-true",
        ),
        (
            "Tls.fs",
            "handler.ServerCertificateCustomValidationCallback <- (fun _ _ _ _ -> true)",
            "dede.dotnet.tls.callback-always-true",
        ),
    ],
)
def test_vb_and_fsharp_real_syntax(filename, text, rule_id):
    language = "f#" if filename.endswith(".fs") else "visual basic"
    rule = next(r for r in RULES if r.id == rule_id)
    assert match_rule(rule, SourceFile.from_text(filename, text), language)


def test_documentation_string_does_not_trigger_api_rule():
    rule = next(r for r in RULES if r.id == "dede.dotnet.jwt.validate-issuer")
    source = SourceFile.from_text("Docs.cs", 'var help = "ValidateIssuer = false";')
    assert not match_rule(rule, source, "c#")


def test_native_analyzer_emits_flow_and_coverage_without_external_engines(tmp_path):
    path = tmp_path / "Controller.cs"
    path.write_text('var query = Request.Query["q"]; db.FromSqlRaw(query);')
    analyzer = DedeEngineAnalyzer(rules_dir=ROOT / "rules/dede-engine")
    result = analyzer.analyze(
        ProjectContext(root=str(tmp_path), files=[str(path)]), AppConfig(), tmp_path / "raw"
    )
    assert result.status == ToolStatus.SUCCESS, result.message
    finding = next(f for f in result.findings if f.rule_id == "dede.dotnet.flow.sql")
    assert finding.analysis_kind == "taint"
    assert finding.dataflow[0].kind == "source"
    assert result.coverage["languages"]["C#"]["rule_kinds"]["taint"] == 11
