"""Config precedence tests."""

from pathlib import Path

import pytest

from dede.config import AppConfig, build_config, default_report_dir, load_yaml_config


def test_cli_overrides_yaml(tmp_path: Path, monkeypatch):
    cfg_path = tmp_path / ".dede.yml"
    cfg_path.write_text(
        "ai:\n  enabled: true\n  model: yaml-model\nreports:\n  formats: [json]\n",
        encoding="utf-8",
    )
    monkeypatch.delenv("DEDE_MODEL", raising=False)
    cfg = build_config(
        tmp_path,
        config_path=cfg_path,
        cli_overrides={"no_ai": True, "formats": ["html"], "model": "cli-model"},
    )
    assert cfg.ai.enabled is False
    assert cfg.reports.formats == ["html"]
    assert cfg.ai.model == "cli-model"


def test_default_report_dir_under_tmp(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("DEDE_MODEL", raising=False)
    project = tmp_path / "my-cool-app"
    project.mkdir()
    cfg = build_config(project)
    assert cfg.reports.output == "/tmp/my-cool-app"


@pytest.mark.parametrize("symlink", [False, True])
def test_default_report_dir_avoids_foreign_directory(tmp_path, monkeypatch, symlink):
    from types import SimpleNamespace
    from dede import config

    candidate = Path("/tmp/ownership-regression")
    original_stat = Path.stat
    original_is_symlink = Path.is_symlink
    original_exists = Path.exists

    def fake_stat(path, *args, **kwargs):
        if path == candidate:
            return SimpleNamespace(st_uid=1000)
        return original_stat(path, *args, **kwargs)

    monkeypatch.setenv("DEDE_PROJECT_NAME", candidate.name)
    monkeypatch.setattr(config.os, "getuid", lambda: 0)
    monkeypatch.setattr(Path, "stat", fake_stat)
    monkeypatch.setattr(Path, "exists", lambda p: True if p == candidate else original_exists(p))
    monkeypatch.setattr(
        Path, "is_symlink", lambda p: symlink if p == candidate else original_is_symlink(p)
    )
    assert default_report_dir(tmp_path) == Path("/tmp/ownership-regression-0")


def test_project_model_overrides_saved_preference(tmp_path, monkeypatch):
    monkeypatch.delenv("DEDE_MODEL", raising=False)
    monkeypatch.setattr("dede.llm.settings.get_preferred_model", lambda: "saved-model")
    (tmp_path / ".dede.yml").write_text("ai:\n  model: project-model\n")
    assert build_config(tmp_path).ai.model == "project-model"


@pytest.mark.parametrize(
    "section,field,value",
    [
        ("scan", "max_files", 0),
        ("scan", "max_file_size_mb", -1),
        ("scan", "max_file_size_mb", float("inf")),
        ("scan", "analyzer_timeout_seconds", 0),
        ("ai", "concurrency", 0),
        ("ai", "max_findings", -1),
        ("ai", "verification_timeout_seconds", 0),
        ("reports", "formats", ["typo"]),
        ("reports", "formats", []),
        ("severity", "fail_on", "typo"),
    ],
)
def test_invalid_config_values(section, field, value):
    with pytest.raises(ValueError):
        AppConfig.model_validate({section: {field: value}})


def test_invalid_environment_override_is_validated(tmp_path, monkeypatch):
    monkeypatch.setenv("MAX_FILES", "-1")
    with pytest.raises(ValueError, match="max_files"):
        build_config(tmp_path)


def test_invalid_cli_override_is_validated(tmp_path):
    with pytest.raises(ValueError, match="formats"):
        build_config(tmp_path, cli_overrides={"formats": ["typo"]})


@pytest.mark.parametrize(
    "section,values",
    [
        ("ruff", {"select": []}),
        ("ruff", {"select": ["--fix"]}),
        ("semgrep", {"profile": "typo"}),
    ],
)
def test_invalid_analysis_configuration_is_rejected(section, values):
    with pytest.raises(ValueError):
        AppConfig.model_validate({section: values})


@pytest.mark.parametrize(
    "host",
    ["https://example.com", "http://10.0.0.8:11434", "http://localhost:11434/path"],
)
def test_remote_or_pathful_ollama_endpoint_is_rejected(host):
    with pytest.raises(ValueError, match="local HTTP endpoint"):
        AppConfig.model_validate({"ai": {"ollama_host": host}})


def test_semgrep_pack_path_traversal_is_rejected():
    with pytest.raises(ValueError, match="pack names"):
        AppConfig.model_validate({"semgrep": {"extra_packs": ["../../workspace/evil"]}})


@pytest.mark.parametrize("name", [".", ".."])
def test_report_dir_cannot_escape_tmp(tmp_path, monkeypatch, name):
    monkeypatch.setenv("DEDE_PROJECT_NAME", name)
    path = default_report_dir(tmp_path)
    assert path.resolve().parent == Path("/tmp")


def test_explicit_missing_config_is_error(tmp_path):
    with pytest.raises(FileNotFoundError):
        build_config(tmp_path, config_path=tmp_path / "missing.yml")


@pytest.mark.parametrize("content", ["false", "[]", "0", "ai: ["])
def test_invalid_yaml_is_configuration_error(tmp_path, content):
    path = tmp_path / "config.yml"
    path.write_text(content)
    with pytest.raises(ValueError):
        load_yaml_config(path)
