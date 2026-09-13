"""Unit tests for the Dede native engine (rules + matcher + analyzer)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from dede.config import AppConfig
from dede.engine.analyzer import DedeEngineAnalyzer
from dede.engine.matcher import SourceFile, evaluate_when, match_rule
from dede.engine.rules import RuleSchemaError, load_rules_dir
from dede.models import ProjectContext, Severity

REPO_ROOT = Path(__file__).resolve().parents[2]
RULES_DIR = REPO_ROOT / "rules" / "dede-engine"


def _write(tmp_path: Path, name: str, content: str) -> Path:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _scan(tmp_path: Path, files: dict[str, str]) -> tuple:
    for name, content in files.items():
        _write(tmp_path, name, content)
    config = AppConfig()
    config.scan.exclude = []
    analyzer = DedeEngineAnalyzer(rules_dir=RULES_DIR)
    project = ProjectContext(
        root=str(tmp_path),
        files=[str(tmp_path / name) for name in files],
    )
    raw_dir = tmp_path / ".raw"
    raw_dir.mkdir(exist_ok=True)
    result = analyzer.analyze(project, config, raw_dir)
    return result, analyzer


class TestRuleLoading:
    def test_bundled_rules_load(self) -> None:
        files = load_rules_dir(RULES_DIR)
        assert files, "bundled rule files must exist"
        rule_ids = [rule.id for f in files for rule in f.rules]
        assert len(rule_ids) == len(set(rule_ids)), "rule ids must be unique"
        assert all(rule_id.startswith("dede.") for rule_id in rule_ids)

    def test_invalid_rule_rejected(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "bad.json",
            json.dumps(
                {
                    "id": "not-prefixed",
                    "message": "x",
                    "severity": "HIGH",
                    "languages": ["python"],
                    "when": [{"pattern": "x"}],
                }
            ),
        )
        with pytest.raises(RuleSchemaError):
            load_rules_dir(tmp_path)

    def test_severity_validated(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "bad.json",
            json.dumps(
                {
                    "id": "dede.x",
                    "message": "x",
                    "severity": "BLOCKER",
                    "languages": ["python"],
                    "when": [{"pattern": "x"}],
                }
            ),
        )
        with pytest.raises(RuleSchemaError):
            load_rules_dir(tmp_path)


class TestMatcher:
    def test_same_line_pattern(self, tmp_path: Path) -> None:
        from dede.engine.rules import WhenCondition

        path = _write(tmp_path, "a.py", "x = subprocess.run('ls', shell=True)\n")
        source = SourceFile.load(path, "a.py")
        lines = evaluate_when(source, (WhenCondition(pattern="subprocess.", same_line=True),))
        assert lines == [0]

    def test_ordered_flow_requires_use_after_declare(self) -> None:
        from dede.engine.rules import WhenCondition

        source = SourceFile(
            relative_path="a.go",
            lines=('query := "SELECT " + col', "", "safe()"),
            lower_lines=tuple(line.lower() for line in ('query := "SELECT " + col', "", "safe()")),
            text_lower='query := "select " + col\n\nsafe()\n',
        )
        lines = evaluate_when(
            source,
            (
                WhenCondition(pattern="query :=", same_line=True),
                WhenCondition(pattern="select ", same_line=True),
            ),
        )
        assert lines == [0]

    def test_if_not_blocks_file(self) -> None:
        from dede.engine.rules import DedRule, FileCondition, WhenCondition

        rule = DedRule(
            id="dede.t",
            message="m",
            severity="HIGH",
            category="security",
            languages=("python",),
            when=(WhenCondition(pattern="pickle.load("),),
            if_not_conditions=(FileCondition(contains_any=("trusted",)),),
        )
        source = SourceFile(
            relative_path="a.py",
            lines=("pickle.load(f)  # dede: trusted",),
            lower_lines=("pickle.load(f)  # dede: trusted",),
            text_lower="pickle.load(f)  # dede: trusted\n",
        )
        assert match_rule(rule, source, "python") == []


class TestAnalyzer:
    def test_credential_rule_matches_only_literal_secret_assignments(self, tmp_path):
        result, _ = _scan(
            tmp_path,
            {
                "app.py": (
                    "import os\n"
                    "# password handling\n"
                    "count = 12\n"
                    "password = os.getenv('APP_PASSWORD')\n"
                    "api_key = '<example-credential>'\n"
                    "other = 'not a credential'\n"
                    "self.auth_token: str = '<example-token>'\n"
                    "# secret = '<comment-example>'\n"
                )
            },
        )
        hits = [
            f.start_line
            for f in result.findings
            if f.rule_id == "dede.py.secrets.hardcoded-credential"
        ]
        # A safe environment lookup elsewhere in the file must not suppress
        # the independent literal credentials. Unrelated assignments are safe.
        assert hits == [5, 7]

    def test_detects_python_and_go_weaknesses(self, tmp_path: Path) -> None:
        result, analyzer = _scan(
            tmp_path,
            {
                "app.py": ("import subprocess\n" "subprocess.run(cmd, shell=True)\n"),
                "main.go": ("package main\n" 'import "crypto/md5"\n' "h := md5.New()\n"),
            },
        )
        assert analyzer.rule_count() > 0
        assert result.status.value == "SUCCESS"
        rule_ids = {f.rule_id for f in result.findings}
        assert "dede.py.cmd.subprocess-shell-true" in rule_ids
        assert "dede.go.crypto.weak-hash-md5" in rule_ids

    def test_language_scoping(self, tmp_path: Path) -> None:
        # Go rule must not fire on a Python file mentioning md5.New().
        result, _ = _scan(tmp_path, {"x.py": "h = md5.New()\n"})
        assert not [f for f in result.findings if f.rule_id.startswith("dede.go.")]

    def test_multilang_secret_rules(self, tmp_path: Path) -> None:
        result, _ = _scan(
            tmp_path,
            {
                "service.rb": 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n',
                "config.txt": "authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.tokenvalue.1234567890abcdef\n",
            },
        )
        rule_ids = {f.rule_id for f in result.findings}
        assert "dede.any.secrets.aws-access-key" in rule_ids
        assert "dede.any.secrets.bearer-literal" in rule_ids
        critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
        assert critical, "AWS key must be CRITICAL"

    def test_if_condition_gates_match(self, tmp_path: Path) -> None:
        # random.randint alone must not fire; security keywords must coexist.
        result, _ = _scan(tmp_path, {"a.py": "import random\nx = random.randint(1, 6)\n"})
        assert "dede.py.random.insecure-random" not in {f.rule_id for f in result.findings}

        result2, _ = _scan(
            tmp_path,
            {"b.py": "import random\ntoken = random.randint(100000, 999999)\n"},
        )
        assert "dede.py.random.insecure-random" in {f.rule_id for f in result2.findings}

    def test_no_rules_dir_fails_gracefully(self, tmp_path: Path) -> None:
        empty = tmp_path / "no-such"
        analyzer = DedeEngineAnalyzer(rules_dir=empty)
        project = ProjectContext(root=str(tmp_path), files=[str(tmp_path / "a.py")])
        (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
        raw_dir = tmp_path / ".raw"
        raw_dir.mkdir(exist_ok=True)
        result = analyzer.analyze(project, AppConfig(), raw_dir)
        assert result.status.value == "FAILED"
        assert "not found" in result.message.lower() or "invalid" in result.message.lower()
