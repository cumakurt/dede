from __future__ import annotations

import json
from pathlib import Path

import pytest

from dede.config import AppConfig
from dede.models import ProjectContext
from dede.semantic.language_support import FULL_LANGUAGE_SUPPORT, support_payload
from dede.semantic.polyglot import PolyglotSemanticAnalyzer


def _scan(tmp_path: Path, files: dict[str, str]):
    paths: list[Path] = []
    for name, text in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        paths.append(path)
    project = ProjectContext(root=str(tmp_path), files=[str(p) for p in paths])
    return PolyglotSemanticAnalyzer().analyze(project, AppConfig(), tmp_path / "raw")


@pytest.mark.parametrize(
    ("language", "files", "expected"),
    [
        ("javascript", {
            "route.js": "import { search } from './service.js';\nfunction route(req){ const q=req.query.q; return search(q);}\n",
            "service.js": "import { run } from './repo.js';\nexport function search(q){ return run(q);}\n",
            "repo.js": "export function run(q){ return db.query('select '+q);}\n",
        }, "CWE-89"),
        ("typescript", {
            "route.ts": "import { search } from './service';\nfunction route(req: Request){ const q=req.query.q; return search(q);}\n",
            "service.ts": "import { run } from './repo';\nexport function search(q: string){ return run(q);}\n",
            "repo.ts": "export function run(q: string){ return db.query('select '+q);}\n",
        }, "CWE-89"),
        ("java", {
            "Controller.java": "class Controller { String route(HttpServletRequest request){ String q=request.getParameter(\"q\"); return Service.search(q); } }\n",
            "Service.java": "class Service { static String search(String q){ return Repo.run(q); } }\n",
            "Repo.java": "class Repo { static String run(String q){ return statement.executeQuery(\"select \"+q); } }\n",
        }, "CWE-89"),
        ("kotlin", {
            "Controller.kt": "class Controller { fun route(call: ApplicationCall): String { val q=call.parameters[\"q\"]; return Service.search(q) } }\n",
            "Service.kt": "object Service { fun search(q: String): String { return Repo.run(q) } }\n",
            "Repo.kt": "object Repo { fun run(q: String): String { return statement.executeQuery(\"select \"+q) } }\n",
        }, "CWE-89"),
        ("csharp", {
            "Controller.cs": "class Controller { string Route(){ var q=Request.Query[\"q\"]; return Service.Search(q); } }\n",
            "Service.cs": "class Service { public static string Search(string q){ return Repo.Run(q); } }\n",
            "Repo.cs": "class Repo { public static string Run(string q){ return Database.ExecuteSqlRaw(\"select \"+q); } }\n",
        }, "CWE-89"),
        ("go", {
            "route.go": "package app\nfunc Route(r *http.Request) string { q:=r.URL.Query().Get(\"q\"); return Search(q) }\n",
            "service.go": "package app\nfunc Search(q string) string { return Run(q) }\n",
            "repo.go": "package app\nfunc Run(q string) string { return db.Query(\"select \"+q) }\n",
        }, "CWE-89"),
        ("php", {
            "route.php": "<?php function route(){ $q=$_GET['q']; return search($q); }\n",
            "service.php": "<?php function search($q){ return run($q); }\n",
            "repo.php": "<?php function run($q){ return mysqli_query($db, 'select '.$q); }\n",
        }, "CWE-89"),
        ("ruby", {
            "route.rb": "def route\n q=params[:q]\n search(q)\nend\n",
            "service.rb": "def search(q)\n run(q)\nend\n",
            "repo.rb": "def run(q)\n connection.execute('select '+q)\nend\n",
        }, "CWE-89"),
        ("rust", {
            "route.rs": "fn route(req: Request){ let q=Query(req); search(q); }\n",
            "service.rs": "fn search(q: String){ run(q); }\n",
            "repo.rs": "fn run(q: String){ sqlx::query(q); }\n",
        }, "CWE-89"),
        ("c", {
            "route.c": "void route(int argc, char **argv){ char *q=argv[1]; search(q); }\n",
            "service.c": "void search(char *q){ run(q); }\n",
            "repo.c": "void run(char *q){ system(q); }\n",
        }, "CWE-78"),
        ("cpp", {
            "route.cpp": "void route(int argc, char **argv){ auto q=argv[1]; search(q); }\n",
            "service.cpp": "void search(char *q){ run(q); }\n",
            "repo.cpp": "void run(char *q){ system(q); }\n",
        }, "CWE-78"),
        ("swift", {
            "Route.swift": "func route(request: Request){ let q=request.query; search(q) }\n",
            "Service.swift": "func search(q: String){ run(q) }\n",
            "Repo.swift": "func run(q: String){ FileManager.default.contents(q) }\n",
        }, "CWE-22"),
        ("scala", {"A.scala": "def route(request: Req): String = { val q=request.getQueryString(\"q\"); statement.executeQuery(\"select \"+q) }\n"}, "CWE-89"),
        ("dart", {"a.dart": "void route(request){ var q=request.uri.queryParameters['q']; http.get(q); }\n"}, "CWE-918"),
    ],
)
def test_project_semantic_language_flow(tmp_path: Path, language: str, files: dict[str, str], expected: str) -> None:
    result = _scan(tmp_path, files)
    assert language in result.coverage["languages"]
    assert any(expected in f.cwe for f in result.findings)
    assert result.coverage["functions"] >= 1
    assert result.coverage["calls"] >= 1


def test_cross_file_flow_contains_project_call_path(tmp_path: Path) -> None:
    result = _scan(tmp_path, {
        "route.js": "import { search } from './service'; function route(req){ const q=req.query.q; return search(q); }",
        "service.js": "export function search(q){ return repo(q); }",
        "repo.js": "export function repo(q){ return db.query('s'+q); }",
    })
    finding = next(f for f in result.findings if "CWE-89" in f.cwe)
    assert len(finding.call_path) >= 3
    assert finding.engine_version == "semantic-polyglot-v4"
    payload = json.loads(Path(result.raw_path).read_text(encoding="utf-8"))
    assert payload["calls"]
    assert payload["cfg_edges"]


def test_precision_controls_generic_execute_fixed_origin_and_typed_scalar(tmp_path: Path) -> None:
    safe = tmp_path / "safe.js"
    safe.write_text(
        "function x(req, executor){ const q=req.query.q; executor.execute(q); fetch('https://safe.example/api/'+q); }",
        encoding="utf-8",
    )
    result = PolyglotSemanticAnalyzer().analyze(
        ProjectContext(root=str(tmp_path), files=[str(safe)]), AppConfig(), tmp_path / "raw-safe"
    )
    assert result.findings == []

    java = tmp_path / "C.java"
    java.write_text(
        'class C { @GetMapping("/u") int route(@RequestParam int id){ return statement.executeQuery("select "+id); } }',
        encoding="utf-8",
    )
    result = PolyglotSemanticAnalyzer().analyze(
        ProjectContext(root=str(tmp_path), files=[str(java)]), AppConfig(), tmp_path / "raw-java"
    )
    assert result.findings == []


def test_interprocedural_sanitizer_summary_suppresses_only_compatible_sink(tmp_path: Path) -> None:
    source = tmp_path / "app.js"
    source.write_text(
        "function clean(x){\n  return parseInt(x);\n}\n"
        "function x(req){\n  const q=req.query.q;\n  const id=clean(q);\n  db.query('s'+id);\n  fetch(id);\n}\n",
        encoding="utf-8",
    )
    result = PolyglotSemanticAnalyzer().analyze(
        ProjectContext(root=str(tmp_path), files=[str(source)]), AppConfig(), tmp_path / "raw"
    )
    assert not any(f.sink_kind == "sql-execution" for f in result.findings)
    assert any(f.sink_kind == "ssrf" for f in result.findings)


def test_language_support_matrix_has_project_semantic_coverage() -> None:
    names = {x.language for x in FULL_LANGUAGE_SUPPORT}
    for required in {"Python", "JavaScript", "TypeScript", "Java", "Kotlin", "C#/.NET", "Go", "PHP", "Ruby", "Rust", "C", "C++", "Swift", "Scala", "Dart"}:
        assert required in names
    assert all(x.project_wide and x.cross_file and x.call_graph and x.cfg and x.taint for x in FULL_LANGUAGE_SUPPORT)
    assert support_payload()["semantic_languages"]
