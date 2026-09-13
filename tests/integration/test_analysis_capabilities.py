"""Exercise detection and false-positive boundaries with real local engines."""

import json
import shutil
from pathlib import Path

import pytest

from dede.analyzers.bandit import BanditAnalyzer
from dede.analyzers.ruff import RuffAnalyzer
from dede.analyzers.semgrep import SemgrepAnalyzer
from dede.config import AppConfig
from dede.discovery import discover_files
from dede.models import ProjectContext, ToolStatus
from dede.utils.process import run_command

ROOT = Path(__file__).resolve().parents[2]
SAMPLES = ROOT / "tests" / "rule_samples"
pytestmark = pytest.mark.integration


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="Semgrep is not installed")
@pytest.mark.parametrize(
    "filename", ["python_taint.py", "javascript_taint.js", "typescript_taint.ts"]
)
def test_taint_rules_detect_unsafe_and_accept_safe_code(filename, tmp_path):
    source = SAMPLES / filename
    if filename == "typescript_taint.ts":
        source = tmp_path / filename
        source.write_text((SAMPLES / "javascript_taint.js").read_text())
    configs = [
        ROOT / "rules/semgrep/custom/python-taint.yml",
        ROOT / "rules/semgrep/custom/javascript-taint.yml",
    ]
    args = [
        "semgrep",
        "scan",
        "--json",
        "--quiet",
        "--metrics",
        "off",
        "--disable-version-check",
        "--no-rewrite-rule-ids",
    ]
    for config in configs:
        args.extend(["--config", str(config)])
    result = run_command([*args, str(source)], timeout=60)
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert not payload["errors"]
    expected = set()
    safe = set()
    for number, line in enumerate(source.read_text().splitlines(), 1):
        if "ruleid: " in line:
            expected.add((line.split("ruleid: ", 1)[1].strip(), number + 1))
        if "ok: " in line:
            safe.add((line.split("ok: ", 1)[1].strip(), number + 1))
    actual = {(item["check_id"], item["start"]["line"]) for item in payload["results"]}
    assert expected
    assert actual == expected
    assert not actual & safe


@pytest.mark.parametrize(
    "analyzer_class,binary",
    [(SemgrepAnalyzer, "semgrep"), (RuffAnalyzer, "ruff"), (BanditAnalyzer, "bandit")],
)
def test_engines_scan_discovered_test_files_and_preserve_sources(tmp_path, analyzer_class, binary):
    if shutil.which(binary) is None:
        pytest.skip(f"{binary} is not installed")
    tests = tmp_path / "tests"
    tests.mkdir()
    source = tests / "test_app.py"
    text = "import os\n\ndef run(value):\n    os.system(value)\n"
    source.write_text(text)
    # Audit rules and read-only operation must not depend on project lint settings.
    (tmp_path / "ruff.toml").write_text("fix = true\n[lint]\nselect = []\n")
    cfg = AppConfig()
    cfg.semgrep.profile = "custom-only"
    output = tmp_path / "reports"
    output.mkdir()
    cfg.reports.output = str(output)
    project = ProjectContext(
        root=str(tmp_path),
        files=[str(file) for file in discover_files(tmp_path, cfg)],
        has_python=True,
    )
    result = analyzer_class().analyze(project, cfg, output)
    assert result.status == ToolStatus.SUCCESS, result.message
    assert any(finding.file.endswith("test_app.py") for finding in result.findings)
    assert source.read_text() == text
    assert all(finding.code_snippet != "requires login" for finding in result.findings)


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="Semgrep is not installed")
def test_unrelated_exec_and_local_path_are_not_security_findings(tmp_path):
    javascript = tmp_path / "safe.js"
    javascript.write_text('function exec(value) { return value; }\nexec("hello");\n')
    python = tmp_path / "safe.py"
    python.write_text(
        'from pathlib import Path\ndef read_local(root):\n    return open(root / "settings.json")\n'
    )
    cfg = AppConfig()
    cfg.semgrep.profile = "custom-only"
    project = ProjectContext(root=str(tmp_path), files=[str(javascript), str(python)])
    result = SemgrepAnalyzer().analyze(project, cfg, tmp_path)
    assert result.status == ToolStatus.SUCCESS, result.message
    assert not result.findings
