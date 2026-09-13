#!/usr/bin/env python3
"""Check committed uv exports without changing the checkout."""

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _content(text: str) -> str:
    return "\n".join(line for line in text.splitlines() if not line.startswith("#"))


def main() -> None:
    subprocess.run(["uv", "lock", "--check"], cwd=ROOT, check=True, timeout=120)
    for filename, options in (
        ("requirements-scanner.lock", ["--extra", "scanner", "--no-dev"]),
        ("requirements-dev.lock", ["--all-extras"]),
    ):
        result = subprocess.run(
            [
                "uv",
                "export",
                "--quiet",
                "--frozen",
                "--no-emit-project",
                "--format",
                "requirements.txt",
                *options,
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if _content(result.stdout) != _content((ROOT / filename).read_text()):
            raise SystemExit(f"Stale {filename}; run make lock-update and review the diff")
    print("Locked dependency exports match uv.lock")


if __name__ == "__main__":
    main()
