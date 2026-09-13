"""Regression tests for native quality analyzers."""

from pathlib import Path

from dede.analyzers.duplicate import DuplicateAnalyzer, DuplicateBlock, _find_duplicate_groups
from dede.config import AppConfig
from dede.models import ProjectContext


def test_duplicate_analyzer_detects_real_copied_block(tmp_path: Path) -> None:
    copied = "\n".join(
        [
            "value = normalize(value)",
            "if value is None:",
            "    return default",
            "result = validate(value)",
            "audit(result)",
            "return result",
            "notify(result)",
            "cleanup(value)",
        ]
    )
    first = tmp_path / "first.py"
    second = tmp_path / "second.py"
    first.write_text("def first(value):\n" + copied + "\n")
    second.write_text("# shifted preface\ndef second(value):\n" + copied + "\n")
    raw = tmp_path / "raw"
    raw.mkdir()
    result = DuplicateAnalyzer().analyze(
        ProjectContext(root=str(tmp_path), files=[str(first), str(second)]),
        AppConfig(),
        raw,
    )
    assert result.status.value == "SUCCESS"
    assert result.findings
    assert all(not finding.cwe for finding in result.findings)


def test_unique_windows_do_not_hide_duplicates_after_report_limit():
    blocks = [DuplicateBlock(f"unique{i}.py", 1, 6, str(i), "", (str(i),)) for i in range(250)]
    blocks.extend(
        [
            DuplicateBlock("copy1.py", 1, 6, "shared", "", ("shared",)),
            DuplicateBlock("copy2.py", 1, 6, "shared", "", ("shared",)),
        ]
    )
    groups = _find_duplicate_groups(blocks)
    assert len(groups) == 1
    assert [block.file for block in groups[0]] == ["copy1.py", "copy2.py"]
