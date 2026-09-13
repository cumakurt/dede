"""Target batching must preserve coverage under command limits and failures."""

import json

from dede.analyzers.targets import run_json_targets, target_batches
from dede.utils.process import CommandResult


def test_batches_preserve_all_paths_with_byte_limit():
    paths = [f"/project/{'x' * 30}/{i}.py" for i in range(30)]
    batches = list(target_batches(["tool"], paths, max_bytes=200))
    assert len(batches) > 1
    assert [path for batch in batches for path in batch] == paths
    assert all(
        sum(len(arg.encode()) + 1 for arg in ["tool", "--", *batch]) <= 200 for batch in batches
    )


def test_batches_preserve_partial_findings_on_later_failure(monkeypatch):
    monkeypatch.setattr(
        "dede.analyzers.targets.target_batches", lambda *a: iter([["a.py"], ["b.py"]])
    )
    calls = []

    def runner(args, **kwargs):
        calls.append(args)
        if len(calls) == 1:
            return CommandResult(1, '{"results": [{"id": "r"}], "errors": []}', "")
        return CommandResult(124, "", "timeout", timed_out=True)

    result = run_json_targets(
        ["tool"], ["a.py", "b.py"], key="results", cwd="/tmp", timeout=10, runner=runner
    )
    assert result.timed_out
    assert result.returncode == 124
    assert json.loads(result.stdout)["results"] == [{"id": "r"}]
    assert calls[0] == ["tool", "--", "a.py"]


def test_batches_share_deadline(monkeypatch):
    monkeypatch.setattr(
        "dede.analyzers.targets.target_batches", lambda *a: iter([["a.py"], ["b.py"]])
    )
    ticks = iter([0.0, 1.0, 11.0])
    monkeypatch.setattr("dede.analyzers.targets.time.monotonic", lambda: next(ticks))
    calls = []

    def runner(args, **kwargs):
        calls.append(kwargs["timeout"])
        return CommandResult(0, "[]", "")

    result = run_json_targets(
        ["tool"], ["a.py", "b.py"], key=None, cwd="/tmp", timeout=10, runner=runner
    )
    assert calls == [9.0]
    assert result.timed_out


def test_invalid_json_fails_instead_of_reporting_clean():
    result = run_json_targets(
        ["tool"],
        ["a.py"],
        key="results",
        cwd="/tmp",
        timeout=10,
        runner=lambda *a, **kw: CommandResult(0, "{}", ""),
    )
    assert result.returncode == 2
    assert "Invalid analyzer JSON" in result.stderr
