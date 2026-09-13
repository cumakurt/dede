"""Regression coverage for discovery, source boundaries and baseline handling."""

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from dede.config import AppConfig
from dede.discovery.files import discover_files
from dede.llm.enrichment import _context_for_finding
from dede.models import Finding
from dede.normalization.baseline import load_baseline_fingerprints
from dede.normalization.findings import attach_snippets
from dede.pipeline import _relocate_finding_paths


def test_baseline_accepts_report_and_list(tmp_path):
    path = tmp_path / "baseline.json"
    entries = [{"fingerprint": "abc"}]
    for payload in (entries, {"findings": entries}):
        path.write_text(json.dumps(payload))
        assert load_baseline_fingerprints(path) == {"abc"}


@pytest.mark.parametrize("payload", [None, 42, {}, {"findings": "invalid"}])
def test_baseline_rejects_invalid_shape(tmp_path, payload):
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match="baseline"):
        load_baseline_fingerprints(path)


def test_discovery_deduplicates_symlinks_and_skips_loops(tmp_path):
    source = tmp_path / "source.py"
    source.write_text("print(1)\n")
    (tmp_path / "alias.py").symlink_to(source)
    (tmp_path / "loop.py").symlink_to("loop.py")
    files = discover_files(tmp_path, AppConfig())
    assert files == [source]


def test_discovery_exclude_supports_paths_and_patterns(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "generated").mkdir()
    (tmp_path / "src" / "generated" / "auto.py").write_text("print(1)")
    (tmp_path / "src" / "skip_test.py").write_text("print(1)")
    keep = tmp_path / "src" / "keep.py"
    keep.write_text("print(1)")
    cfg = AppConfig()
    cfg.scan.exclude.extend(["src/generated", "*_test.py"])
    assert discover_files(tmp_path, cfg) == [keep]


def test_discovery_skips_special_files_before_opening(tmp_path, monkeypatch):
    fifo = tmp_path / "input.py"
    os.mkfifo(fifo)
    opened = []
    monkeypatch.setattr("dede.discovery.files._is_binary", lambda path: opened.append(path) or True)
    assert discover_files(tmp_path, AppConfig()) == []
    assert not opened


def test_discovery_limit_is_deterministic(tmp_path):
    for name in ("z.py", "b.py", "a.py"):
        (tmp_path / name).write_text("print(1)")
    cfg = AppConfig()
    cfg.scan.max_files = 2
    assert [path.name for path in discover_files(tmp_path, cfg)] == ["a.py", "b.py"]


def test_discovery_skips_in_project_reports(tmp_path):
    source = tmp_path / "source.py"
    source.write_text("print(1)")
    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "old_report.json").write_text("{}")
    cfg = AppConfig()
    cfg.reports.output = str(reports)
    assert discover_files(tmp_path, cfg) == [source]


def test_discovery_skips_installer_venv_backups(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("print(1)")
    backup = tmp_path / ".venv-backup.example"
    backup.mkdir()
    (backup / "dependency.py").write_text("print(2)")
    assert discover_files(tmp_path, AppConfig()) == [source]


def test_source_context_respects_file_size_limit(tmp_path):
    (tmp_path / "large.py").write_text("large_source_marker\n" * 100)
    cfg = AppConfig()
    cfg.scan.max_file_size_mb = 0.001
    finding = Finding(tool="test", rule_id="r", file="large.py")
    attach_snippets([finding], tmp_path, cfg)
    assert not finding.code_snippet
    assert not _context_for_finding(finding, tmp_path, 10, max_bytes=1000)


@pytest.mark.parametrize("kind", ["absolute", "traversal", "symlink"])
def test_source_context_cannot_escape_target(tmp_path, kind):
    root = tmp_path / "project"
    root.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("outside_project_marker")
    if kind == "symlink":
        (root / "alias.py").symlink_to(outside)
        file = "alias.py"
    else:
        file = str(outside) if kind == "absolute" else "../outside.py"
    finding = Finding(tool="test", rule_id="r", file=file)
    attach_snippets([finding], root, AppConfig())
    assert "outside_project_marker" not in finding.code_snippet
    assert "outside_project_marker" not in _context_for_finding(finding, root, 10)


def test_snippets_read_each_file_once(tmp_path):
    source = tmp_path / "source.py"
    source.write_text("print(1)\n" * 100)
    findings = [
        Finding(tool="test", rule_id=str(i), file="source.py", start_line=i, end_line=i)
        for i in range(1, 101)
    ]
    original_open = Path.open
    reads = []

    def tracked_open(path, *args, **kwargs):
        if path == source:
            reads.append(path)
        return original_open(path, *args, **kwargs)

    with patch.object(Path, "open", tracked_open):
        attach_snippets(findings, tmp_path, AppConfig())
    assert all(finding.code_snippet for finding in findings)
    assert len(reads) == 1


def test_path_relocation_checks_directory_boundary(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    external = tmp_path / "project-other" / "source.py"
    finding = Finding(tool="test", rule_id="r", file=str(external))
    _relocate_finding_paths([finding], root)
    assert finding.file == str(external)
