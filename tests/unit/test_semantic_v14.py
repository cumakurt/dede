import json
from pathlib import Path

from dede.config import AppConfig
from dede.models import LanguageStats, ProjectContext
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


def test_fastapi_endpoint_parameter_is_http_source_and_exported_to_attack_graph(tmp_path):
    project = _project(
        tmp_path,
        {
            "app.py": '''from fastapi import FastAPI\napp = FastAPI()\n@app.get("/users/{user_id}")\ndef user(user_id: str):\n    cursor.execute(f"SELECT * FROM users WHERE id={user_id}")\n'''
        },
    )
    raw = tmp_path / "reports" / "raw"
    result = PythonSemanticAnalyzer().analyze(project, AppConfig(), raw)
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.source_kind == "http.parameter"
    assert finding.endpoint == "/users/{user_id}"
    assert finding.attack_path[-1] == "cursor.execute"
    assert "dedeql.internet-high-exploitability" in finding.query_matches

    ir = json.loads((raw / "semantic-python-ir.json").read_text(encoding="utf-8"))
    assert ir["version"] == "2"
    assert ir["stats"]["security_flows"] == 1
    assert ir["security_flows"][0]["source_kind"] == "http.parameter"

    graph = json.loads((raw / "semantic-python-attack-graph.json").read_text(encoding="utf-8"))
    assert graph["stats"]["attack_paths"] == 1
    assert graph["attack_paths"][0]["path"][0] == "GET /users/{user_id}"
    assert (raw / "semantic-python-attack-graph.dot").is_file()


def test_fastapi_depends_authentication_is_detected(tmp_path):
    project = _project(
        tmp_path,
        {
            "app.py": '''from fastapi import Depends\n@app.get("/admin/{item}")\ndef admin(item: str, current_user=Depends(get_current_user)):\n    cursor.execute("SELECT " + item)\n'''
        },
    )
    result = PythonSemanticAnalyzer().analyze(project, AppConfig(), tmp_path / "reports" / "raw")
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.authentication_required is True
    assert finding.exploitability_score == 92.0
    assert "dedeql.unauthenticated-injection" not in finding.query_matches


def test_keyword_argument_taint_propagates_across_files(tmp_path):
    project = _project(
        tmp_path,
        {
            "app.py": '''from flask import request\nfrom repo import lookup\ndef handler():\n    lookup(value=request.args.get("id"))\n''',
            "repo.py": '''def lookup(value):\n    cursor.execute("SELECT " + value)\n''',
        },
    )
    result = PythonSemanticAnalyzer().analyze(project, AppConfig(), tmp_path / "reports" / "raw")
    assert len(result.findings) == 1
    assert result.findings[0].call_path == ["app.handler", "repo.lookup"]


def test_ssrf_framework_sink_is_detected(tmp_path):
    project = _project(
        tmp_path,
        {
            "app.py": '''from flask import request\nimport requests\ndef handler():\n    target = request.args.get("url")\n    requests.get(target)\n'''
        },
    )
    result = PythonSemanticAnalyzer().analyze(project, AppConfig(), tmp_path / "reports" / "raw")
    assert len(result.findings) == 1
    assert result.findings[0].cwe == ["CWE-918"]
    assert result.findings[0].normalized_type == "ssrf"


def test_semantic_incremental_cache_reuses_unaffected_findings(tmp_path):
    project = _project(
        tmp_path,
        {
            "a.py": '''from flask import request\ndef a():\n    cursor.execute("SELECT " + request.args.get("x"))\n''',
            "b.py": '''from flask import request\ndef b():\n    cursor.execute("SELECT " + request.args.get("y"))\n''',
        },
    )
    raw = tmp_path / "reports" / "raw"
    analyzer = PythonSemanticAnalyzer()
    first = analyzer.analyze(project, AppConfig(), raw)
    assert len(first.findings) == 2

    (tmp_path / "a.py").write_text("def a():\n    return 1\n", encoding="utf-8")
    project.changed_files = ["a.py"]
    project.affected_files = ["a.py"]
    second = analyzer.analyze(project, AppConfig(), raw)
    assert len(second.findings) == 1
    assert second.findings[0].file == "b.py"
    assert second.coverage["incremental_reused_findings"] == 1
    assert second.coverage["incremental_entry_files"] == 1

def test_cache_only_scan_keeps_security_flows_in_ir(tmp_path):
    project = _project(
        tmp_path,
        {
            "app.py": '''from flask import request\ndef handler():\n    cursor.execute("SELECT " + request.args.get("id"))\n'''
        },
    )
    raw = tmp_path / "reports" / "raw"
    analyzer = PythonSemanticAnalyzer()
    first = analyzer.analyze(project, AppConfig(), raw)
    assert len(first.findings) == 1
    second = analyzer.analyze(project, AppConfig(), raw)
    assert second.coverage["contexts"] == 0
    ir = json.loads((raw / "semantic-python-ir.json").read_text(encoding="utf-8"))
    assert ir["stats"]["security_flows"] == 1
    assert len(ir["security_flows"]) == 1
