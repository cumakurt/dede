"""Use actual offline engines to challenge model dismissals and unsafe proposals."""

import shutil

import pytest

from dede.config import AppConfig
from dede.llm.verification import verify_ai_reviews
from dede.models import Finding, Severity
from dede.utils.hashes import sha256_text

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not shutil.which("semgrep") or not shutil.which("ruff"),
        reason="Real Semgrep and Ruff are required",
    ),
]


@pytest.mark.parametrize(
    "example,expected",
    [
        ("def run(value):\n    return eval(value)  # noqa: S307\n", "ISSUES_FOUND"),
        (
            'def query(cursor, value):\n    cursor.execute("SELECT * FROM users WHERE id = ?", (value,))\n',
            "CHECKS_PASSED",
        ),
    ],
)
def test_real_engines_reject_sql_dismissal_and_check_example(tmp_path, example, expected):
    source = (
        "from flask import request\n\ndef query(cursor):\n"
        '    value = request.args["id"]\n'
        '    query = "SELECT * FROM users WHERE id = " + value\n'
        "    cursor.execute(query)\n"
    )
    (tmp_path / "app.py").write_text(source)
    item = Finding(
        tool="semgrep",
        rule_id="dede.python.taint.sql-injection",
        file="app.py",
        start_line=6,
        end_line=6,
        severity=Severity.HIGH,
        ai_generated=True,
        ai_status="cached",
        ai_verdict="LIKELY_FALSE_POSITIVE",
        ai_source_digest=sha256_text(source.rstrip("\n")),
        secure_code_example=example,
    )
    cfg = AppConfig()
    cfg.semgrep.profile = "custom-only"
    verify_ai_reviews([item], tmp_path, cfg, tmp_path / "checks")
    assert item.ai_validation_status == "CONFLICT", item.ai_validation_notes
    assert item.ai_fix_status == expected, item.ai_fix_notes
    assert not item.suppressed and item.severity == Severity.HIGH
    assert (tmp_path / "app.py").read_text() == source
    if expected == "ISSUES_FOUND":
        assert any("S307" in note for note in item.ai_fix_notes)


def test_model_code_is_never_executed(tmp_path):
    marker = tmp_path / "must-not-exist"
    source = "print(1)\n"
    (tmp_path / "app.py").write_text(source)
    item = Finding(
        tool="ruff",
        rule_id="S307",
        file="app.py",
        ai_generated=True,
        ai_status="reviewed",
        ai_source_digest=sha256_text(source.rstrip("\n")),
        secure_code_example=f"from pathlib import Path\nPath({str(marker)!r}).touch()\n",
    )
    cfg = AppConfig()
    cfg.semgrep.profile = "custom-only"
    verify_ai_reviews([item], tmp_path, cfg, tmp_path / "checks")
    assert not marker.exists()
    assert item.ai_validation_status == "UNVERIFIED"
