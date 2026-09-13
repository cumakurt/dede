from __future__ import annotations

from pathlib import Path

from dede.config import AppConfig
from dede.models import ProjectContext
from dede.semantic.python_ast import PythonSemanticAnalyzer


def _scan(tmp_path: Path, source: str):
    path = tmp_path / "app.py"
    path.write_text(source, encoding="utf-8")
    project = ProjectContext(root=str(tmp_path), files=[str(path)], has_python=True)
    raw = tmp_path / "raw"
    raw.mkdir()
    return PythonSemanticAnalyzer().analyze(project, AppConfig(), raw).findings


def _types(findings):
    return {finding.normalized_type for finding in findings}


def test_generic_execute_method_is_not_assumed_to_be_sql(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "from flask import request\n"
        "def f():\n"
        "    value = request.args.get('q')\n"
        "    executor.execute(value)\n",
    )
    assert "sql-execution" not in _types(findings)


def test_conventional_database_receiver_still_detects_sql(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "from flask import request\n"
        "def f():\n"
        "    value = request.args.get('q')\n"
        "    cur.execute('SELECT ' + value)\n",
    )
    sql = [finding for finding in findings if finding.normalized_type == "sql-execution"]
    assert len(sql) == 1
    assert sql[0].precision.value == "HIGH"
    assert sql[0].confidence_score == 0.93


def test_fixed_http_origin_with_tainted_path_is_not_ssrf(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "from flask import request\n"
        "import requests\n"
        "def f():\n"
        "    user_id = request.args.get('id')\n"
        "    requests.get('https://api.example.com/users/' + user_id)\n",
    )
    assert "ssrf" not in _types(findings)


def test_dynamic_http_authority_is_ssrf(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "from flask import request\n"
        "import requests\n"
        "def f():\n"
        "    host = request.args.get('host')\n"
        "    requests.get('https://' + host + '/status')\n",
    )
    assert "ssrf" in _types(findings)


def test_yaml_safe_loader_is_not_unsafe_deserialization(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "from flask import request\n"
        "import yaml\n"
        "def f():\n"
        "    payload = request.args.get('p')\n"
        "    yaml.load(payload, Loader=yaml.SafeLoader)\n",
    )
    assert "unsafe-deserialization" not in _types(findings)


def test_yaml_default_loader_remains_detected(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "from flask import request\n"
        "import yaml\n"
        "def f():\n"
        "    payload = request.args.get('p')\n"
        "    yaml.load(payload)\n",
    )
    assert "unsafe-deserialization" in _types(findings)


def test_context_specific_shell_sanitizer_does_not_hide_sql_taint(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "from flask import request\n"
        "import shlex, subprocess\n"
        "def f():\n"
        "    value = request.args.get('q')\n"
        "    quoted = shlex.quote(value)\n"
        "    subprocess.run('echo ' + quoted, shell=True)\n"
        "    cursor.execute('SELECT ' + quoted)\n",
    )
    kinds = _types(findings)
    assert "command-execution" not in kinds
    assert "sql-execution" in kinds


def test_fastapi_dependency_is_not_seeded_as_http_input(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "from fastapi import FastAPI, Depends\n"
        "import requests\n"
        "app = FastAPI()\n"
        "def get_db(): ...\n"
        "@app.get('/x')\n"
        "def route(db=Depends(get_db)):\n"
        "    requests.get(db)\n",
    )
    assert "ssrf" not in _types(findings)


def test_endpoint_parameter_named_user_is_treated_as_untrusted(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.get('/users/{user}')\n"
        "def route(user: str):\n"
        "    cursor.execute('SELECT ' + user)\n",
    )
    assert "sql-execution" in _types(findings)
