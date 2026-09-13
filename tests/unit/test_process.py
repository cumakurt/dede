"""Subprocess input, failure and time limit behavior."""

import sys

from dede.utils.process import run_command


def test_command_receives_supplied_stdin():
    result = run_command(
        [sys.executable, "-c", "import sys; print(sys.stdin.read().upper())"],
        input_text="input payload",
        timeout=5,
    )
    assert result.returncode == 0
    assert result.stdout == "INPUT PAYLOAD\n"


def test_command_without_input_sees_eof():
    result = run_command(
        [sys.executable, "-c", "import sys; print(repr(sys.stdin.read()))"],
        timeout=5,
    )
    assert result.returncode == 0
    assert result.stdout == "''\n"


def test_timeout_terminates_children_holding_output_pipes():
    result = run_command(
        [
            sys.executable,
            "-c",
            "import subprocess,sys,time; subprocess.Popen([sys.executable,'-c',"
            "'import time; time.sleep(30)']); print('started',flush=True); time.sleep(30)",
        ],
        timeout=1,
    )
    assert result.timed_out
    assert result.returncode == 124
    assert "started" in result.stdout
