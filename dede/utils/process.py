"""Safe subprocess helpers (never shell=True)."""

from __future__ import annotations

import os
import signal
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass
class CommandResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


def run_command(
    args: list[str],
    *,
    cwd: Path | str | None = None,
    timeout: int | None = 300,
    env: dict[str, str] | None = None,
    input_text: str | None = None,
) -> CommandResult:
    temporary: tempfile.TemporaryDirectory[str] | None = None
    try:
        effective_env = env
        if args and Path(args[0]).name in {"semgrep", "pysemgrep"}:
            effective_env = dict(env or os.environ)
            effective_env.setdefault("SEMGREP_SEND_METRICS", "off")
            effective_env.setdefault("SEMGREP_ENABLE_VERSION_CHECK", "0")
            effective_env.setdefault("SEMGREP_LOG_FILE", os.devnull)
            effective_env.setdefault("EIO_URING", "posix")
            if "SEMGREP_SETTINGS_FILE" not in effective_env:
                temporary = tempfile.TemporaryDirectory(prefix="dede-semgrep-")
                effective_env["SEMGREP_SETTINGS_FILE"] = str(Path(temporary.name) / "settings.yml")

        process = subprocess.Popen(
            args,
            cwd=str(cwd) if cwd else None,
            stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=effective_env,
            shell=False,
            start_new_session=True,
        )
        try:
            stdout, stderr = process.communicate(input=input_text, timeout=timeout)
        except subprocess.TimeoutExpired:
            # Analyzer CLIs commonly spawn engine children. Killing only the
            # wrapper leaks processes into subsequent scans, so terminate the
            # isolated process group and drain its pipes.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                process.kill()
            stdout, stderr = process.communicate()
            return CommandResult(
                returncode=124,
                stdout=stdout or "",
                stderr=stderr or "timeout",
                timed_out=True,
            )
        return CommandResult(
            returncode=process.returncode,
            stdout=stdout or "",
            stderr=stderr or "",
        )
    except FileNotFoundError as exc:
        return CommandResult(returncode=127, stdout="", stderr=str(exc))
    except PermissionError as exc:
        return CommandResult(returncode=126, stdout="", stderr=str(exc))
    except OSError as exc:
        return CommandResult(returncode=126, stdout="", stderr=str(exc))
    finally:
        if temporary is not None:
            temporary.cleanup()


def which(binary: str) -> str | None:
    from shutil import which as _which

    path = _which(binary)
    if not path:
        return None
    if not os.access(path, os.X_OK):
        return None
    return path
