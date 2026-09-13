"""Exercise installer failures without changing host packages or Docker state."""

import os
import subprocess
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[2]


def run_installer_functions(script, *, env=None):
    return subprocess.run(
        [
            "bash",
            "-c",
            'installer=$1; shift; source "$installer"; ' + script,
            "bash",
            str(ROOT / "install.sh"),
        ],
        capture_output=True,
        text=True,
        timeout=10,
        env=env,
    )


def test_existing_model_volume_keeps_original_compose_configuration():
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
    # Additional labels change Compose's volume hash and request destructive
    # recreation of the pre-existing persistent model store on upgrades.
    assert compose["volumes"]["ollama-data"] in (None, {})


def test_failed_start_exits_immediately_and_keeps_docker_diagnostics(tmp_path):
    log = tmp_path / "install.log"
    result = run_installer_functions(
        """
        INSTALL_LOG="$TEST_LOG"
        ollama_reachable() { return 1; }
        docker() { return 0; }
        dede_compose() { echo "daemon startup failed" >&2; return 42; }
        sleep() { echo "unexpected readiness wait"; return 1; }
        if ensure_ollama_up; then exit 99; else exit 0; fi
    """,
        env={**os.environ, "TEST_LOG": str(log)},
    )
    assert result.returncode == 0
    assert "daemon startup failed" in log.read_text()
    assert str(log) in result.stderr
    assert "exit 42" in result.stderr
    assert "unexpected readiness wait" not in result.stdout


def test_start_cannot_block_forever():
    result = run_installer_functions("""
        OLLAMA_START_TIMEOUT=1
        ollama_reachable() { return 1; }
        docker() { return 0; }
        # Replace only the Docker executable with a deliberately stuck process;
        # keep the installer's real timeout invocation and deadline arguments.
        timeout() { command timeout "$1" "$2" sleep 30; }
        if ensure_ollama_up; then exit 99; else exit 0; fi
    """)
    assert result.returncode == 0
    assert "exit 124" in result.stderr


def test_existing_service_does_not_restart():
    result = run_installer_functions("""
        ollama_reachable() { return 0; }
        dede_compose() { echo "unexpected restart"; return 1; }
        ensure_ollama_up
    """)
    assert result.returncode == 0
    assert "unexpected restart" not in result.stdout


def test_package_status_never_becomes_a_package_name():
    result = run_installer_functions("""
        VERBOSE=1
        pkg_installed() { [[ "$1" == "present" ]]; }
        filter_uninstalled_pkgs present missing
    """)
    assert result.returncode == 0
    assert result.stdout == "missing\n"
    assert "already installed" in result.stderr


def test_start_has_no_input_for_destructive_compose_prompts():
    result = run_installer_functions("""
        calls=0
        ollama_reachable() { calls=$((calls + 1)); [[ "$calls" -gt 1 ]]; }
        docker() { return 0; }
        dede_compose() { local answer; if read -r answer; then return 99; fi; }
        ensure_ollama_up
    """)
    assert result.returncode == 0


def test_broken_venv_is_preserved_even_when_replacement_fails(tmp_path):
    old = tmp_path / ".venv"
    old.mkdir()
    (old / "sentinel.txt").write_text("recoverable environment data")
    result = run_installer_functions(
        """
        ROOT="$TEST_INSTALL_ROOT"
        python3() { return 1; }
        python3.12() { return 1; }
        install_host_cli
    """,
        env={**os.environ, "TEST_INSTALL_ROOT": str(tmp_path)},
    )
    assert result.returncode == 1
    backups = list(tmp_path.glob(".venv-backup.*"))
    assert len(backups) == 1
    assert (backups[0] / "sentinel.txt").read_text() == "recoverable environment data"
    assert "Failed to create venv" in result.stderr


@pytest.mark.parametrize("verbose", [0, 1])
def test_command_output_is_logged_and_failure_is_preserved(tmp_path, verbose):
    log = tmp_path / "install.log"
    result = run_installer_functions(
        """
        INSTALL_LOG="$TEST_LOG"
        VERBOSE="$TEST_VERBOSE"
        run_logged "Checking fixture" bash -c 'echo normal-detail; echo error-detail >&2; exit 42'
    """,
        env={**os.environ, "TEST_LOG": str(log), "TEST_VERBOSE": str(verbose)},
    )
    assert result.returncode == 42
    assert "normal-detail" in log.read_text()
    assert "error-detail" in log.read_text()
    assert ("normal-detail" in result.stdout) is bool(verbose)
    assert "exit 42" in result.stderr


def test_successful_quiet_step_prints_no_rule_inventory(tmp_path):
    result = run_installer_functions(
        """
        run_logged "Checking offline rules" bash -c 'echo pack-already-vendored; echo full-rule-inventory'
        printf 'LOG=%s\n' "$INSTALL_LOG"
    """,
        env={**os.environ, "TMPDIR": str(tmp_path)},
    )
    assert result.returncode == 0
    assert "pack-already-vendored" not in result.stdout
    assert "full-rule-inventory" not in result.stdout
    log = Path(result.stdout.split("LOG=", 1)[1].strip())
    assert "full-rule-inventory" in log.read_text()
    assert log.stat().st_mode & 0o777 == 0o600
    assert log.parent.stat().st_mode & 0o777 == 0o700


# Execute the fake Docker through Bash so this works even when the hardened
# test container mounts /tmp with noexec. GNU timeout still controls real
# processes; only the kill grace is shortened to keep the regression fast.
SCANNER_FIXTURE = r"""
    INSTALL_LOG="$TEST_LOG"
    SCANNER_CHECK_TIMEOUT=1
    docker() {
        printf '%s\n' "$*" >> "$TEST_CALLS"
        if [[ "$1" == run ]]; then
            while [[ $# -gt 0 && "$1" != --cidfile ]]; do shift; done
            printf '%064d' 1 > "$2"
            case "$TEST_MODE" in
                hang) trap '' TERM; sleep 30 ;;
                fail) echo 'scanner fixture failed' >&2; return 42 ;;
                *) return 0 ;;
            esac
        fi
    }
    export -f docker
    timeout() {
        shift
        local duration="$1"; shift
        command timeout --kill-after=0.1 "$duration" bash -c '"$@"' bash "$@"
    }
    verify_scanner_image
"""


@pytest.mark.parametrize("mode", ["success", "fail", "hang"])
def test_scanner_probe_is_isolated_and_failure_cleans_only_its_container(tmp_path, mode):
    log = tmp_path / "install.log"
    calls = tmp_path / "calls"
    result = run_installer_functions(
        SCANNER_FIXTURE,
        env={
            **os.environ,
            "TEST_LOG": str(log),
            "TEST_CALLS": str(calls),
            "TEST_MODE": mode,
        },
    )
    assert result.returncode == (0 if mode == "success" else 1), result.stderr
    commands = calls.read_text().splitlines()
    assert len(commands) == (1 if mode == "success" else 2)
    assert "--pull=never" in commands[0]
    assert "--network none" in commands[0]
    assert "--read-only" in commands[0]
    assert "--cap-drop ALL" in commands[0]
    assert "--volume" not in commands[0]
    assert not any("compose" in command or "ollama" in command for command in commands)
    assert "Killed" not in result.stderr
    if mode != "success":
        assert commands[1] == f'rm -f {"1":0>64}'
        assert "Scanner ready" not in result.stdout
        assert str(log) in result.stderr
    if mode == "hang":
        assert "exit 137" in result.stderr
        assert "1s limit" in result.stderr
        assert "DEDE_SCANNER_CHECK_TIMEOUT=180" in result.stderr
    assert not Path(str(log) + ".scanner.cid").exists()


def test_failed_verification_stops_bootstrap_before_ollama():
    result = run_installer_functions("""
        make() { return 0; }
        image_exists() { return 0; }
        dede_compose() { [[ "$1" == config ]]; }
        verify_scanner_image() { return 42; }
        ensure_ollama_up() { echo 'unexpected model startup'; }
        run_docker_bootstrap
    """)
    assert result.returncode == 42
    assert "unexpected model startup" not in result.stdout


def test_invalid_scanner_timeout_fails_before_setup():
    result = subprocess.run(
        ["bash", str(ROOT / "install.sh"), "-y"],
        env={**os.environ, "DEDE_SCANNER_CHECK_TIMEOUT": "0"},
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 1
    assert "DEDE_SCANNER_CHECK_TIMEOUT must be a positive integer" in result.stderr


def test_cleanup_never_removes_a_container_from_an_invalid_cid(tmp_path):
    cid = tmp_path / "invalid.cid"
    cid.write_text("dede-ollama-1\n")
    result = run_installer_functions(
        """
        SCANNER_CHECK_CID="$TEST_CID"
        docker() { echo 'unexpected removal'; return 99; }
        cleanup_scanner_check
    """,
        env={**os.environ, "TEST_CID": str(cid)},
    )
    assert result.returncode == 0
    assert "unexpected removal" not in result.stdout
    assert not cid.exists()


def test_declined_optional_docker_setup_keeps_native_scanner_ready(tmp_path):
    result = run_installer_functions(
        """
        detect_distro() { return 0; }
        need_docker_compose() { return 0; }
        need_python() { return 0; }
        need_cmd() { return 0; }
        ensure_docker_ready() { return 0; }
        install_host_cli() { return 0; }
        write_env_file() { return 0; }
        dede() { return 0; }
        image_exists() { return 1; }
        confirm() { return 1; }
        run_docker_bootstrap() { echo 'unexpected setup'; return 99; }
        main
    """,
        env={**os.environ, "TMPDIR": str(tmp_path)},
    )
    assert result.returncode == 0, result.stderr
    assert "Native scanner" in result.stdout
    assert "ready" in result.stdout
    assert "unexpected setup" not in result.stdout
    assert "Optional Docker scanner ready" not in result.stdout


def test_exit_cleanup_preserves_original_failure_status(tmp_path):
    cid = tmp_path / "probe.cid"
    cid.write_text("a" * 64)
    log = tmp_path / "install.log"
    result = run_installer_functions(
        """
        SCANNER_CHECK_CID="$TEST_CID"
        INSTALL_LOG="$TEST_LOG"
        timeout() { printf '%s\n' "$*"; }
        trap installer_exit EXIT
        exit 42
    """,
        env={**os.environ, "TEST_CID": str(cid), "TEST_LOG": str(log)},
    )
    assert result.returncode == 42
    assert f'docker rm -f {"a" * 64}' in log.read_text()
    assert not cid.exists()


def test_unavailable_log_directory_prevents_running_the_step(tmp_path):
    unavailable = tmp_path / "not-a-directory"
    unavailable.write_text("fixture")
    result = run_installer_functions(
        """
        if run_logged "Checking fixture" bash -c 'echo unexpected-command'; then exit 99; fi
        [[ -z "$INSTALL_LOG" ]]
    """,
        env={**os.environ, "TMPDIR": str(unavailable)},
    )
    assert result.returncode == 0
    assert "unexpected-command" not in result.stdout


def test_noninteractive_install_accepts_optional_defaults(tmp_path):
    install_root = tmp_path / "install-root"
    result = run_installer_functions(
        """
        ROOT="$TEST_INSTALL_ROOT"
        mkdir -p "$ROOT/.venv/bin"
        printf '#!/bin/sh\nexit 0\n' > "$ROOT/.venv/bin/python"
        chmod +x "$ROOT/.venv/bin/python"
        ASSUME_YES=1
        SKIP_MODEL=1
        detect_distro() { return 0; }
        need_python() { return 0; }
        need_cmd() { return 0; }
        need_optional_pdf() { return 0; }
        ensure_docker_ready() { return 0; }
        install_host_cli() { return 0; }
        write_env_file() { return 0; }
        install_packages() { return 0; }
        run_logged() { return 0; }
        dede() { return 0; }
        image_exists() { return 1; }
        run_scanner_bootstrap() { echo 'default docker build selected'; return 0; }
        main
        """,
        env={**os.environ, "TMPDIR": str(tmp_path), "TEST_INSTALL_ROOT": str(install_root)},
    )
    assert result.returncode == 0, result.stderr
    assert "default docker build selected" in result.stdout
    assert "Native scanner" in result.stdout and "ready" in result.stdout


def test_with_docker_fails_if_optional_runtime_is_unavailable(tmp_path):
    result = run_installer_functions(
        """
        WITH_DOCKER=1
        detect_distro() { return 0; }
        need_python() { return 0; }
        need_cmd() { return 0; }
        ensure_docker_ready() { return 1; }
        install_host_cli() { echo 'unexpected host install'; return 99; }
        main
        """,
        env={**os.environ, "TMPDIR": str(tmp_path)},
    )
    assert result.returncode == 1
    assert "--with-docker requested" in result.stderr
    assert "unexpected host install" not in result.stdout
