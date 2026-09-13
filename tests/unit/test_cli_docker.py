"""Host CLI isolation and Docker orchestration regressions."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from dede import cli
from typer.testing import CliRunner


@pytest.mark.parametrize(
    "args,code",
    [
        (["--help"], 0),
        (["scan", "--help"], 0),
        (["doctor", "--help"], 0),
        (["scan"], 2),
        (["scan", "/missing-dede-regression-target"], 2),
        (["scan", ".", "--invalid-option"], 2),
    ],
)
def test_cli_help_and_invalid_arguments_do_not_crash(args, code):
    result = CliRunner().invoke(cli.app, args)
    assert result.exit_code == code, result.output
    assert "Traceback" not in result.output
    assert "TypeError" not in result.output
    if code:
        assert isinstance(result.exception, SystemExit)


@pytest.mark.parametrize("foreign", ["reports", "cache"])
@pytest.mark.parametrize("uid", [0, 10001])
def test_foreign_runtime_directories_are_rejected_before_cleanup(
    tmp_path, monkeypatch, foreign, uid
):
    root = tmp_path / "source"
    root.mkdir()
    reports = tmp_path / "reports"
    reports.mkdir(mode=0o755)
    cache = tmp_path / "cache" / "dede"
    cache.mkdir(parents=True, mode=0o755)
    sentinel = reports / "report.json"
    sentinel.write_text("preserve")
    original_stat = Path.stat
    selected = reports if foreign == "reports" else cache

    def fake_stat(path, *args, **kwargs):
        actual = original_stat(path, *args, **kwargs)
        if path in (reports, cache):
            return SimpleNamespace(
                st_uid=uid + 1 if path == selected else uid, st_mode=actual.st_mode
            )
        return actual

    monkeypatch.setenv("XDG_CACHE_HOME", str(cache.parent))
    monkeypatch.setattr(cli.os, "getuid", lambda: uid)
    monkeypatch.setattr(Path, "stat", fake_stat)
    with pytest.raises(RuntimeError, match="owned by another user"):
        cli._host_runtime_env(root, reports, clean_reports=True)
    assert sentinel.read_text() == "preserve"
    assert original_stat(reports).st_mode & 0o777 == 0o755
    assert original_stat(cache).st_mode & 0o777 == 0o755


def test_doctor_runtime_failure_is_readable(monkeypatch):
    monkeypatch.setattr(cli, "_inside_scanner_container", lambda: False)
    monkeypatch.setattr(cli, "_require_scanner_image", lambda: "test-image")

    def fail(*args, **kwargs):
        raise RuntimeError("Runtime directory is owned by another user")

    monkeypatch.setattr(cli, "_host_runtime_env", fail)
    result = CliRunner().invoke(cli.app, ["doctor"])
    assert result.exit_code == 3
    assert "owned by another user" in result.output
    assert "Traceback" not in result.output


def test_unreadable_output_reports_parameter_error(tmp_path):
    if cli.os.getuid() == 0:
        pytest.skip("Root with DAC override can read mode-000 directories")
    output = tmp_path / "unreadable"
    output.mkdir(mode=0o000)
    try:
        result = CliRunner().invoke(cli.app, ["scan", str(tmp_path), "--output", str(output)])
        assert result.exit_code == 2
        assert "not readable" in result.output
        assert "Traceback" not in result.output
        assert isinstance(result.exception, SystemExit)
    finally:
        output.chmod(0o700)


def test_only_pinned_scanner_marker_enables_direct_execution(tmp_path, monkeypatch):
    marker = tmp_path / "scanner-marker"
    monkeypatch.setattr(cli, "SCANNER_MARKER", marker)
    monkeypatch.setenv("DEDE_IN_CONTAINER", "1")

    assert not cli._inside_scanner_container()
    marker.touch()
    assert cli._inside_scanner_container()


def test_compose_prefix_adds_gpu_override_only_when_requested(tmp_path, monkeypatch):
    (tmp_path / "docker-compose.yml").touch()
    (tmp_path / "docker-compose.gpu.yml").touch()

    monkeypatch.setenv("DEDE_DEVICE", "auto")
    assert cli._compose_prefix(tmp_path) == [
        "docker",
        "compose",
        "-f",
        str(tmp_path / "docker-compose.yml"),
    ]

    monkeypatch.setenv("DEDE_DEVICE", "cuda")
    assert cli._compose_prefix(tmp_path)[-2:] == [
        "-f",
        str(tmp_path / "docker-compose.gpu.yml"),
    ]


def test_no_ai_host_scan_is_containerized_without_ollama(tmp_path, monkeypatch):
    target = tmp_path / "source"
    reports = tmp_path / "reports"
    cache = tmp_path / "cache"
    target.mkdir()
    reports.mkdir()
    (reports / "metadata.json").write_text("stale")
    (reports / "raw").mkdir()
    (reports / "raw" / "old.json").write_text("stale")
    captured: dict[str, object] = {}

    monkeypatch.setattr(cli, "_require_scanner_image", lambda: "dede-scanner:1.0.0")
    monkeypatch.setattr(cli, "_compose_prefix", lambda _root: ["docker", "compose"])
    monkeypatch.setattr(cli, "default_report_dir", lambda _root: reports)
    monkeypatch.setenv("XDG_CACHE_HOME", str(cache))

    def fake_run(args, *, env, check):
        captured.update(args=args, env=env, check=check)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(cli.subprocess, "run", fake_run)
    code = cli._docker_scan(
        target,
        formats=["json"],
        output=None,
        no_ai=True,
        offline=False,
        ai_hunt=None,
        severity=None,
        exclude=[],
        respect_gitignore=False,
        baseline=None,
        config=None,
        model=None,
        yes=False,
    )

    args = captured["args"]
    assert code == 0
    assert args[:5] == ["docker", "compose", "run", "--rm", "--no-deps"]
    assert "--build" not in args
    assert "--no-ai" in args
    assert args[args.index("--format") + 1] == "json"
    assert captured["env"]["DEDE_UID"]
    assert captured["env"]["DEDE_GID"]
    assert Path(captured["env"]["DEDE_HOST_CACHE"]).is_dir()
    assert reports.stat().st_mode & 0o777 == 0o700
    assert not (reports / "metadata.json").exists()
    assert not (reports / "raw").exists()


def test_custom_output_and_offline_flag_are_forwarded(tmp_path, monkeypatch):
    target = tmp_path / "source"
    target.mkdir()
    reports = tmp_path / "custom reports"
    captured: dict[str, object] = {}

    monkeypatch.setattr(cli, "_require_scanner_image", lambda: "dede-scanner:1.0.0")
    monkeypatch.setattr(cli, "_compose_prefix", lambda _root: ["docker", "compose"])

    def fake_run(args, *, env, check):
        captured.update(args=args, env=env, check=check)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(cli.subprocess, "run", fake_run)
    assert (
        cli._docker_scan(
            target,
            formats=["json"],
            output=reports,
            no_ai=False,
            offline=True,
            ai_hunt=None,
            severity=None,
            exclude=[],
            respect_gitignore=False,
            baseline=None,
            config=None,
            model=None,
            yes=False,
        )
        == 0
    )
    args = captured["args"]
    assert "--offline" in args
    assert args[args.index("--format") + 1] == "json"
    assert captured["env"]["OUTPUT"] == str(reports.resolve())


def test_host_forwards_model_preference_and_configured_no_ai(tmp_path, monkeypatch):
    target = tmp_path / "source"
    target.mkdir()
    (target / ".dede.yml").write_text("ai:\n  enabled: false\n")
    monkeypatch.setattr("dede.llm.settings.get_preferred_model", lambda: "example:small")
    monkeypatch.delenv("DEDE_MODEL", raising=False)
    monkeypatch.setenv("DEDE_OFFLINE", "true")
    monkeypatch.setattr(cli, "_require_scanner_image", lambda: "test-image")
    monkeypatch.setattr(cli, "_compose_prefix", lambda _root: ["docker", "compose"])
    captured = []
    monkeypatch.setattr(
        cli.subprocess,
        "run",
        lambda args, **kwargs: captured.extend(args) or SimpleNamespace(returncode=0),
    )
    assert (
        cli._docker_scan(
            target,
            formats=["json"],
            output=tmp_path / "reports",
            no_ai=False,
            offline=False,
            ai_hunt=None,
            severity=None,
            exclude=[],
            respect_gitignore=False,
            baseline=None,
            config=None,
            model=None,
            yes=False,
        )
        == 0
    )
    assert "--no-deps" in captured
    assert "--no-ai" in captured
    assert "--offline" in captured
    assert captured[captured.index("--model") + 1] == "example:small"


@pytest.mark.parametrize(
    "case",
    [
        "target",
        "parent",
        "symlink",
        "baseline",
        "missing-config",
        "outside-config",
        "missing-target",
    ],
)
def test_invalid_scan_paths_preserve_existing_reports(tmp_path, monkeypatch, case):
    target = tmp_path / "source"
    target.mkdir()
    reports = tmp_path / "reports"
    reports.mkdir()
    output = reports
    baseline = config = None
    if case == "target":
        output = target
    elif case == "parent":
        output = tmp_path
    elif case == "symlink":
        output = tmp_path / "linked"
        output.symlink_to(reports, target_is_directory=True)
    elif case == "baseline":
        baseline = reports / "report.json"
    elif case == "missing-config":
        config = target / "missing.yml"
    elif case == "outside-config":
        config = tmp_path / "outside.yml"
        config.write_text("{}")
    elif case == "missing-target":
        target = tmp_path / "missing"
    old_report = output / "report.json"
    old_report.write_text('{"findings": []}')
    raw = output / "raw"
    raw.mkdir()
    sentinel = raw / "keep.txt"
    sentinel.write_text("existing data")
    monkeypatch.setattr(cli, "_require_scanner_image", lambda: "test-image")
    monkeypatch.setattr(cli, "_compose_prefix", lambda _root: ["docker", "compose"])
    with pytest.raises((ValueError, FileNotFoundError)):
        cli._docker_scan(
            target,
            formats=["json"],
            output=output,
            no_ai=True,
            offline=True,
            ai_hunt=None,
            severity=None,
            exclude=[],
            respect_gitignore=False,
            baseline=baseline,
            config=config,
            model=None,
            yes=False,
        )
    assert old_report.read_text() == '{"findings": []}'
    assert sentinel.read_text() == "existing data"


def test_auto_runtime_falls_back_to_native_without_docker_image(tmp_path, monkeypatch):
    target = tmp_path / "source"
    target.mkdir()
    called = {"native": 0, "docker": 0}
    monkeypatch.setattr(cli, "_inside_scanner_container", lambda: False)
    monkeypatch.setattr(cli, "_scanner_image_available", lambda: False)

    def native(*args, **kwargs):
        called["native"] += 1
        return 0

    def docker(*args, **kwargs):
        called["docker"] += 1
        return 99

    monkeypatch.setattr(cli, "_native_scan", native)
    monkeypatch.setattr(cli, "_docker_scan", docker)
    result = CliRunner().invoke(cli.app, ["scan", str(target), "--no-ai"])
    assert result.exit_code == 0, result.output
    assert called == {"native": 1, "docker": 0}
    assert "falling back to native runtime" in result.output


def test_explicit_native_runtime_never_checks_for_docker_image(tmp_path, monkeypatch):
    target = tmp_path / "source"
    target.mkdir()
    monkeypatch.setattr(cli, "_inside_scanner_container", lambda: False)
    monkeypatch.setattr(
        cli, "_scanner_image_available", lambda: (_ for _ in ()).throw(AssertionError("docker probe"))
    )
    monkeypatch.setattr(cli, "_native_scan", lambda *args, **kwargs: 0)
    result = CliRunner().invoke(
        cli.app, ["scan", str(target), "--runtime", "native", "--no-ai"]
    )
    assert result.exit_code == 0, result.output
