import json
from pathlib import Path

from dede.config import AppConfig, SemanticSinkModel, SemanticSourceModel
from dede.models import LanguageStats, ProjectContext, ToolStatus
from dede.semantic.python_ast import PythonSemanticAnalyzer


def _project(tmp_path: Path, files: dict[str, str]) -> ProjectContext:
    paths = []
    for name, source in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
        paths.append(str(path))
    return ProjectContext(
        root=str(tmp_path),
        files=paths,
        languages=LanguageStats(languages={"Python": 100.0}),
        has_python=True,
    )


def test_cross_file_taint_tracks_route_call_graph_and_ir(tmp_path):
    project = _project(
        tmp_path,
        {
            "routes.py": '''from flask import request\nimport service\n\n@app.get("/users/{id}")\ndef handler():\n    user = request.args.get("id")\n    service.lookup(user)\n''',
            "service.py": '''import repo\ndef lookup(value):\n    return repo.run(value)\n''',
            "repo.py": '''def run(value):\n    query = "SELECT * FROM users WHERE id=" + value\n    cursor.execute(query)\n''',
        },
    )
    raw = tmp_path / "raw"
    result = PythonSemanticAnalyzer().analyze(project, AppConfig(), raw)
    assert result.status == ToolStatus.SUCCESS
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.file == "repo.py"
    assert finding.cwe == ["CWE-89"]
    assert finding.call_path == ["routes.handler", "service.lookup", "repo.run"]
    assert finding.attack_surface == ["GET /users/{id}"]
    assert finding.internet_exposed is True
    assert finding.exploitability_score == 100.0
    assert [step.file for step in finding.dataflow if step.kind == "call"] == [
        "routes.py",
        "service.py",
    ]
    assert result.dependency_graph == {
        "repo.py": [],
        "routes.py": ["service.py"],
        "service.py": ["repo.py"],
    }
    ir = json.loads((raw / "semantic-python-ir.json").read_text(encoding="utf-8"))
    assert ir["version"] == "2"
    assert ir["stats"]["resolved_call_edges"] >= 2
    assert ir["stats"]["cfg_edges"] > 0
    assert ir["endpoints"][0]["path"] == "/users/{id}"


def test_returned_source_flows_across_import(tmp_path):
    project = _project(
        tmp_path,
        {
            "inputs.py": '''from flask import request\ndef user_id():\n    return request.args.get("id")\n''',
            "app.py": '''from inputs import user_id\ndef handler():\n    value = user_id()\n    cursor.execute("SELECT " + value)\n''',
        },
    )
    result = PythonSemanticAnalyzer().analyze(project, AppConfig(), tmp_path / "raw")
    assert len(result.findings) == 1
    assert result.findings[0].source_kind == "http.query"
    assert result.findings[0].cwe == ["CWE-89"]


def test_cross_file_sanitizer_summary_breaks_flow(tmp_path):
    project = _project(
        tmp_path,
        {
            "clean.py": '''def numeric(value):\n    return int(value)\n''',
            "app.py": '''from flask import request\nfrom clean import numeric\ndef handler():\n    value = numeric(request.args.get("id"))\n    cursor.execute("SELECT " + str(value))\n''',
        },
    )
    result = PythonSemanticAnalyzer().analyze(project, AppConfig(), tmp_path / "raw")
    assert result.findings == []


def test_guard_and_return_make_later_numeric_use_safe(tmp_path):
    project = _project(
        tmp_path,
        {
            "app.py": '''from flask import request\ndef handler():\n    value = request.args.get("id")\n    if not value.isdigit():\n        return\n    cursor.execute("SELECT " + value)\n'''
        },
    )
    result = PythonSemanticAnalyzer().analyze(project, AppConfig(), tmp_path / "raw")
    assert result.findings == []


def test_unreachable_sink_after_return_is_not_reported(tmp_path):
    project = _project(
        tmp_path,
        {
            "app.py": '''from flask import request\ndef handler():\n    value = request.args.get("id")\n    return value\n    cursor.execute("SELECT " + value)\n'''
        },
    )
    result = PythonSemanticAnalyzer().analyze(project, AppConfig(), tmp_path / "raw")
    assert result.findings == []


def test_auth_decorator_reduces_endpoint_exploitability(tmp_path):
    project = _project(
        tmp_path,
        {
            "app.py": '''from flask import request\n@app.get("/admin")\n@login_required\ndef handler():\n    value = request.args.get("q")\n    cursor.execute("SELECT " + value)\n'''
        },
    )
    result = PythonSemanticAnalyzer().analyze(project, AppConfig(), tmp_path / "raw")
    finding = result.findings[0]
    assert finding.authentication_required is True
    assert finding.attack_surface == ["GET /admin"]
    assert finding.exploitability_score == 92.0


def test_custom_source_and_sink_models(tmp_path):
    project = _project(
        tmp_path,
        {
            "app.py": '''def handler():\n    value = corp.http.request_value()\n    legacydb.run(value)\n'''
        },
    )
    config = AppConfig()
    config.semantic.sources = [SemanticSourceModel(call="corp.http.request_value", kind="http.corp")]
    config.semantic.sinks = [
        SemanticSinkModel(
            call="legacydb.run",
            kind="custom-execution",
            cwe="CWE-20",
            severity="HIGH",
        )
    ]
    result = PythonSemanticAnalyzer().analyze(project, config, tmp_path / "raw")
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.source_kind == "http.corp"
    assert finding.cwe == ["CWE-20"]
    assert finding.normalized_type == "custom-execution"
