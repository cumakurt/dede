"""Best-effort git metadata for scan reports."""

from __future__ import annotations

from pathlib import Path

from dede.utils.process import run_command


def collect_git_metadata(root: Path) -> dict[str, str]:
    """Return repository, branch, and commit when the target is a git work tree.

    Missing values are empty strings. Never raises on git failures.
    """
    meta = {"repository": "", "branch": "", "commit": ""}
    root = root.resolve()
    if not (root / ".git").exists() and not _is_git_work_tree(root):
        return meta

    commit = _git_output(root, ["rev-parse", "HEAD"])
    if commit:
        meta["commit"] = commit[:40]

    branch = _git_output(root, ["rev-parse", "--abbrev-ref", "HEAD"])
    if branch and branch != "HEAD":
        meta["branch"] = branch

    remote = _git_output(root, ["config", "--get", "remote.origin.url"])
    if remote:
        meta["repository"] = remote
    else:
        top = _git_output(root, ["rev-parse", "--show-toplevel"])
        if top:
            meta["repository"] = Path(top).name

    return meta


def _is_git_work_tree(root: Path) -> bool:
    out = _git_output(root, ["rev-parse", "--is-inside-work-tree"])
    return out.lower() == "true"


def _git_output(root: Path, args: list[str]) -> str:
    try:
        result = run_command(["git", *args], cwd=str(root), timeout=5)
    except Exception:  # noqa: BLE001
        return ""
    if result.returncode != 0:
        return ""
    return (result.stdout or "").strip()
