"""Analyzer errors must not be presented as successful security scans."""

import json
from pathlib import Path

import pytest

from dede.analyzers.gitleaks import GitleaksAnalyzer
from dede.analyzers.gosec import GosecAnalyzer
from dede.analyzers.govet import GoVetAnalyzer
from dede.analyzers.lizard import LizardAnalyzer
from dede.analyzers.semgrep import SemgrepAnalyzer
from dede.config import AppConfig
from dede.models import ProjectContext, ToolStatus
from dede.utils.process import CommandResult


@pytest.mark.parametrize(
    "analyzer_class,module,raw_name,empty",
    [
        (GitleaksAnalyzer, "gitleaks", "gitleaks.json", "[]"),
        (GosecAnalyzer, "gosec", "gosec.json", "{}"),
        (GoVetAnalyzer, "govet", "go_vet.txt", ""),
    ],
)
@pytest.mark.parametrize("returncode,timed_out", [(124, True), (2, False)])
def test_failed_command_is_not_success(
    tmp_path, monkeypatch, analyzer_class, module, raw_name, empty, returncode, timed_out
):
    monkeypatch.setattr(f"dede.analyzers.{module}.which", lambda _: "/tool")
    monkeypatch.setattr(analyzer_class, "version", lambda _: "test")
    # Go analyzers require a module root before they reach the command.
    (tmp_path / "go.mod").write_text("module example.com/test\n", encoding="utf-8")
    (tmp_path / raw_name).write_text(empty)
    monkeypatch.setattr(
        f"dede.analyzers.{module}.run_command",
        lambda *a, **kw: CommandResult(returncode, "", "scanner failed", timed_out),
    )
    result = analyzer_class().analyze(ProjectContext(root=str(tmp_path)), AppConfig(), tmp_path)
    assert result.status == ToolStatus.FAILED
    assert result.message


@pytest.mark.parametrize(
    "analyzer_class,module,raw_name,stale",
    [
        (GitleaksAnalyzer, "gitleaks", "gitleaks.json", [{"RuleID": "old", "File": "old.py"}]),
        (GosecAnalyzer, "gosec", "gosec.json", {"Issues": [{"rule_id": "old", "file": "old.go"}]}),
    ],
)
def test_stale_reports_are_not_reused(
    tmp_path, monkeypatch, analyzer_class, module, raw_name, stale
):
    monkeypatch.setattr(f"dede.analyzers.{module}.which", lambda _: "/tool")
    monkeypatch.setattr(analyzer_class, "version", lambda _: "test")
    (tmp_path / "go.mod").write_text("module example.com/test\n", encoding="utf-8")
    (tmp_path / raw_name).write_text(json.dumps(stale))
    monkeypatch.setattr(
        f"dede.analyzers.{module}.run_command",
        lambda *a, **kw: CommandResult(124, "", "timeout", True),
    )
    result = analyzer_class().analyze(ProjectContext(root=str(tmp_path)), AppConfig(), tmp_path)
    assert not result.findings


@pytest.mark.parametrize(
    "analyzer_class,module,raw_name",
    [
        (GitleaksAnalyzer, "gitleaks", "gitleaks.json"),
        (GosecAnalyzer, "gosec", "gosec.json"),
    ],
)
def test_invalid_json_is_failure(tmp_path, monkeypatch, analyzer_class, module, raw_name):
    monkeypatch.setattr(f"dede.analyzers.{module}.which", lambda _: "/tool")
    monkeypatch.setattr(analyzer_class, "version", lambda _: "test")
    (tmp_path / "go.mod").write_text("module example.com/test\n", encoding="utf-8")

    def run(*args, **kwargs):
        (tmp_path / raw_name).write_text("{broken")
        return CommandResult(0, "", "")

    monkeypatch.setattr(f"dede.analyzers.{module}.run_command", run)
    result = analyzer_class().analyze(ProjectContext(root=str(tmp_path)), AppConfig(), tmp_path)
    assert result.status == ToolStatus.FAILED


def test_gitleaks_requests_full_redaction(tmp_path, monkeypatch):
    monkeypatch.setattr("dede.analyzers.gitleaks.which", lambda _: "/tool")
    monkeypatch.setattr(GitleaksAnalyzer, "version", lambda _: "test")

    def run(args, **kwargs):
        assert "--redact=100" in args
        Path(args[args.index("--report-path") + 1]).write_text("[]")
        return CommandResult(0, "", "")

    monkeypatch.setattr("dede.analyzers.gitleaks.run_command", run)
    result = GitleaksAnalyzer().analyze(ProjectContext(root=str(tmp_path)), AppConfig(), tmp_path)
    assert result.status == ToolStatus.SUCCESS


@pytest.mark.parametrize("analyzer_class,module", [(GoVetAnalyzer, "govet"), (GosecAnalyzer, "gosec")])
def test_go_analyzers_skip_without_module(tmp_path, monkeypatch, analyzer_class, module):
    """Go files without go.mod are NOT_APPLICABLE, never a FAILED scan."""
    monkeypatch.setattr(f"dede.analyzers.{module}.which", lambda _: "/tool")
    monkeypatch.setattr(analyzer_class, "version", lambda _: "test")
    result = analyzer_class().analyze(ProjectContext(root=str(tmp_path)), AppConfig(), tmp_path)
    assert result.status == ToolStatus.NOT_APPLICABLE
    assert "go.mod" in result.message


@pytest.mark.parametrize("analyzer_class,module", [(GoVetAnalyzer, "govet"), (GosecAnalyzer, "gosec")])
def test_go_analyzers_skip_when_binary_missing(tmp_path, monkeypatch, analyzer_class, module):
    """A missing Go toolchain/binary is an offline skip, not a failure."""
    monkeypatch.setattr(f"dede.analyzers.{module}.which", lambda _: None)
    (tmp_path / "go.mod").write_text("module example.com/test\n", encoding="utf-8")
    result = analyzer_class().analyze(ProjectContext(root=str(tmp_path)), AppConfig(), tmp_path)
    assert result.status == ToolStatus.SKIPPED_OFFLINE_DEPENDENCY


def test_lizard_reports_offline_skip_when_module_missing(tmp_path, monkeypatch):
    """Host without the lizard python module: skip, not a FAILED scan."""
    import builtins

    real_import = builtins.__import__

    def no_lizard(name, *args, **kwargs):
        if name == "lizard":
            raise ImportError("No module named 'lizard'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_lizard)
    (tmp_path / "app.py").write_text("print(1)\n", encoding="utf-8")
    result = LizardAnalyzer().analyze(
        ProjectContext(root=str(tmp_path), files=[str(tmp_path / "app.py")]),
        AppConfig(),
        tmp_path,
    )
    assert result.status == ToolStatus.SKIPPED_OFFLINE_DEPENDENCY
    assert "lizard" in result.message.lower()


def test_semgrep_reports_offline_skip_when_binary_missing(tmp_path, monkeypatch):
    """Host without semgrep: skip, since dede-engine still covers the run."""
    (tmp_path / "rules.yml").write_text("rules:\n  - id: r\n    languages: [python]\n")
    monkeypatch.setattr("dede.analyzers.semgrep.which", lambda _: None)
    monkeypatch.setattr(SemgrepAnalyzer, "version", lambda _: "test")
    result = SemgrepAnalyzer().analyze(
        ProjectContext(root=str(tmp_path), files=[str(tmp_path / "rules.yml")]),
        AppConfig(),
        tmp_path,
    )
    assert result.status == ToolStatus.SKIPPED_OFFLINE_DEPENDENCY


def test_semgrep_failure_preserves_partial_findings(tmp_path, monkeypatch):
    (tmp_path / "rules.yml").write_text("rules:\n  - id: r\n    languages: [python]\n")
    monkeypatch.setattr("dede.analyzers.semgrep.which", lambda _: "/tool")
    monkeypatch.setattr(SemgrepAnalyzer, "version", lambda _: "test")
    monkeypatch.setattr(
        "dede.analyzers.semgrep.resolve_semgrep_configs",
        lambda *a, **kw: [tmp_path / "rules.yml"],
    )
    payload = {"results": [{"check_id": "r", "path": "source.py", "extra": {"message": "partial"}}]}
    monkeypatch.setattr(
        "dede.analyzers.semgrep.run_command",
        lambda *a, **kw: CommandResult(2, json.dumps(payload), "incomplete scan"),
    )
    result = SemgrepAnalyzer().analyze(
        ProjectContext(root=str(tmp_path), files=[str(tmp_path / "source.py")]),
        AppConfig(),
        tmp_path,
    )
    assert result.status == ToolStatus.FAILED
    assert len(result.findings) == 1
    assert "incomplete scan" in result.message
