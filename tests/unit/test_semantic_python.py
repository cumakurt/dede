from pathlib import Path

from dede.config import AppConfig
from dede.models import LanguageStats, ProjectContext, ToolStatus
from dede.semantic.python_ast import PythonSemanticAnalyzer


def _project(tmp_path: Path, source: str) -> ProjectContext:
    path = tmp_path / "app.py"
    path.write_text(source)
    return ProjectContext(
        root=str(tmp_path),
        files=[str(path)],
        languages=LanguageStats(languages={"Python": 100.0}),
        has_python=True,
    )


def test_semantic_sql_taint(tmp_path):
    project = _project(
        tmp_path,
        '''\nfrom flask import request\n\ndef passthrough(v):\n    return v\n\ndef handler():\n    user = request.args.get("id")\n    value = passthrough(user)\n    query = "SELECT * FROM users WHERE id=" + value\n    cursor.execute(query)\n''',
    )
    result = PythonSemanticAnalyzer().analyze(project, AppConfig(), tmp_path)
    assert result.status == ToolStatus.SUCCESS
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.cwe == ["CWE-89"]
    assert finding.analysis_kind == "semantic-taint"
    assert finding.dataflow[0].kind == "source"
    assert finding.dataflow[-1].kind == "sink"
    assert finding.exploitability_score == 90.0


def test_semantic_sanitizer_breaks_flow(tmp_path):
    project = _project(
        tmp_path,
        '''\nfrom flask import request\ndef handler():\n    user = int(request.args.get("id"))\n    cursor.execute("SELECT * FROM users WHERE id=" + str(user))\n''',
    )
    result = PythonSemanticAnalyzer().analyze(project, AppConfig(), tmp_path)
    assert result.findings == []


def test_subprocess_requires_shell_true(tmp_path):
    project = _project(
        tmp_path,
        '''\nimport subprocess\nvalue = input()\nsubprocess.run(["echo", value])\nsubprocess.run("echo " + value, shell=True)\n''',
    )
    result = PythonSemanticAnalyzer().analyze(project, AppConfig(), tmp_path)
    assert len(result.findings) == 1
    assert result.findings[0].cwe == ["CWE-78"]
