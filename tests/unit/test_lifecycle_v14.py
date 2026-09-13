from pathlib import Path

from dede.index import ScanIndex
from dede.models import Finding, Severity


def _finding(identity: str, file: str = "a.py") -> Finding:
    return Finding(
        tool="dede",
        rule_id="r",
        file=file,
        severity=Severity.HIGH,
        fingerprint=identity + "-v1",
        semantic_fingerprint=identity,
    )


def test_lifecycle_new_existing_resolved_and_reopened(tmp_path: Path):
    source = tmp_path / "a.py"
    source.write_text("print(1)\n", encoding="utf-8")
    db = tmp_path / "index.db"

    first = _finding("stable")
    with ScanIndex(db) as index:
        diff = index.lifecycle_diff([first])
        assert diff["counts"]["NEW"] == 1
        assert first.lifecycle_status == "NEW"
        index.commit(tmp_path, [str(source)], [first])

    second = _finding("stable")
    with ScanIndex(db) as index:
        diff = index.lifecycle_diff([second])
        assert diff["counts"]["EXISTING"] == 1
        assert second.lifecycle_status == "EXISTING"
        index.commit(tmp_path, [str(source)], [second])

    with ScanIndex(db) as index:
        diff = index.lifecycle_diff([])
        assert diff["counts"]["RESOLVED"] == 1
        index.commit(tmp_path, [str(source)], [])

    reopened = _finding("stable")
    with ScanIndex(db) as index:
        diff = index.lifecycle_diff([reopened])
        assert diff["counts"]["REOPENED"] == 1
        assert reopened.lifecycle_status == "REOPENED"

def test_incomplete_scan_does_not_advance_lifecycle_snapshot(tmp_path: Path):
    source = tmp_path / "a.py"
    source.write_text("print(1)\n", encoding="utf-8")
    db = tmp_path / "index.db"
    finding = _finding("stable")
    with ScanIndex(db) as index:
        index.commit(tmp_path, [str(source)], [finding])
    with ScanIndex(db) as index:
        index.commit(tmp_path, [str(source)], [], update_findings=False)
    with ScanIndex(db) as index:
        diff = index.lifecycle_diff([])
        assert diff["counts"]["RESOLVED"] == 1
