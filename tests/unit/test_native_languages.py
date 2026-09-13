"""Native language support is backed by runnable unsafe/safe rule examples."""

import json
from pathlib import Path

import pytest

from dede.config import AppConfig
from dede.discovery.files import discover_files
from dede.discovery.languages import detect_file_language, detect_languages
from dede.discovery.projects import detect_projects
from dede.engine.matcher import SourceFile, match_rule
from dede.engine.rules import load_rules_dir
from dede.utils.source import read_source_lines

ROOT = Path(__file__).resolve().parents[2]
RULES = tuple(r for f in load_rules_dir(ROOT / "rules/dede-engine") for r in f.rules)
CASES = json.loads((ROOT / "tests/rule_samples/native_language_cases.json").read_text())


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["rule_id"])
def test_native_language_rule_safe_counterexamples(case):
    rule = next(r for r in RULES if r.id == case["rule_id"])
    language = detect_file_language(Path(case["filename"]))
    assert language and language.lower() in rule.languages
    assert match_rule(rule, SourceFile.from_text(case["filename"], case["unsafe"]), language)
    assert not match_rule(rule, SourceFile.from_text(case["filename"], case["safe"]), language)


def test_corpus_covers_all_new_language_rules():
    assert {c["rule_id"] for c in CASES} == {r.id for r in RULES if r.id.startswith("dede.native.")}


@pytest.mark.parametrize(
    "filename,language",
    [
        ("Page.cshtml", "Razor"),
        ("App.razor", "Razor"),
        ("Default.aspx", "ASP.NET"),
        ("Directory.Build.props", "XML"),
        ("Directory.Build.targets", "XML"),
        ("Form.xaml", "XML"),
        ("Program.csx", "C#"),
        ("Types.fsi", "F#"),
        ("script.R", "R"),
        ("module.jl", "Julia"),
        ("app.vue", "Vue"),
        ("app.svelte", "Svelte"),
        ("app.mts", "TypeScript"),
        ("app.cts", "TypeScript"),
        ("app.hs", "Haskell"),
        ("app.erl", "Erlang"),
        ("app.groovy", "Groovy"),
        ("app.m", "Objective-C"),
        ("app.mm", "Objective-C++"),
        ("app.zig", "Zig"),
    ],
)
def test_extended_language_recognition(filename, language):
    assert detect_file_language(Path(filename)) == language


@pytest.mark.parametrize("encoding", ["utf-16", "utf-32"])
def test_windows_encoding_is_discovered_counted_and_available_as_evidence(tmp_path, encoding):
    source = "settings.ValidateIssuer = false;\nvar x = 1;\n"
    path = tmp_path / "Auth.cs"
    path.write_bytes(source.encode(encoding))
    files = discover_files(tmp_path, AppConfig())
    assert files == [path]
    assert detect_languages(files, tmp_path).lines_scanned == 2
    assert read_source_lines(tmp_path, "Auth.cs", 2048) == source.splitlines()


def test_deep_dotnet_project_detection_respects_discovered_files(tmp_path):
    project = tmp_path / "src/services/api/Api.csproj"
    project.parent.mkdir(parents=True)
    project.write_text(
        '<Project Sdk="Microsoft.NET.Sdk.Web"><ItemGroup><PackageReference Include="Microsoft.EntityFrameworkCore.SqlServer" Version="0.0.0-example" /></ItemGroup></Project>'
    )
    types, frameworks = detect_projects(tmp_path, [project])
    assert ".NET" in types
    assert frameworks == ["ASP.NET Core", "EF Core"]
    assert detect_projects(tmp_path, []) == ([], [])


def test_framework_names_in_description_are_not_dependencies(tmp_path):
    package = tmp_path / "package.json"
    package.write_text('{"name":"react-flask-example","description":"next angular vue"}')
    assert detect_projects(tmp_path)[1] == []


def test_nested_framework_dependencies_are_detected(tmp_path):
    package = tmp_path / "src/frontend/package.json"
    package.parent.mkdir(parents=True)
    package.write_text('{"dependencies":{"react":"0.0.0-example"}}')
    assert "react" in detect_projects(tmp_path)[1]


def test_external_symlink_manifest_does_not_influence_project_detection(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    external = tmp_path / "outside.json"
    external.write_text('{"dependencies":{"react":"0.0.0-example"}}')
    (root / "package.json").symlink_to(external)
    assert detect_projects(root) == ([], [])


def test_explicit_external_manifest_does_not_influence_project_detection(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    external = tmp_path / "package.json"
    external.write_text('{"dependencies":{"react":"0.0.0-example"}}')
    assert detect_projects(root, [external]) == ([], [])


@pytest.mark.parametrize("content", ["[", "null", "[]", '{"dependencies": 42}'])
def test_malformed_manifest_does_not_abort_discovery(tmp_path, content):
    (tmp_path / "package.json").write_text(content)
    assert detect_projects(tmp_path) == (["Node.js"], [])
