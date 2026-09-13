"""Integration-ish pipeline tests without Docker (analyzers optional)."""

import json
from pathlib import Path

import pytest

from dede.config import AppConfig, default_report_dir
from dede.pipeline import run_scan


SAMPLES = Path(__file__).resolve().parents[1] / "vulnerable_samples"


@pytest.mark.integration
def test_scan_samples_no_ai(tmp_path: Path):
    out = tmp_path / "reports"
    cfg = AppConfig()
    cfg.ai.enabled = False
    cfg.reports.output = str(out)
    cfg.reports.formats = ["json", "html", "pdf", "sarif"]
    result, code = run_scan(SAMPLES, cfg, progress=False)
    assert code in (0, 1)
    assert (out / "report.json").is_file()
    assert (out / "report.html").is_file()
    assert (out / "report.pdf").read_bytes().startswith(b"%PDF-")
    sarif = json.loads((out / "report.sarif").read_text())
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == len(result.findings)
    assert all(tool.status.value in {"SUCCESS", "NOT_APPLICABLE", "SKIPPED_OFFLINE_DEPENDENCY"} for tool in result.tool_statuses)
    assert result.findings, "Expected findings from vulnerable samples"
    raw = (out / "report.json").read_text(encoding="utf-8")
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in raw


def test_default_report_path_uses_project_name():
    assert default_report_dir(Path("/home/user/myapp")) == Path("/tmp/myapp")
