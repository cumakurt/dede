"""Keep real C compilation available to both offline Go analyzers."""

import os
import shutil

import pytest

from dede.analyzers.gosec import GosecAnalyzer
from dede.analyzers.govet import GoVetAnalyzer
from dede.config import AppConfig
from dede.models import ProjectContext, ToolStatus


@pytest.mark.integration
def test_cgo_module_is_analyzed_offline(tmp_path, monkeypatch):
    missing = [tool for tool in ("go", "gcc", "gosec") if shutil.which(tool) is None]
    if missing and not os.environ.get("DEDE_IN_CONTAINER"):
        pytest.skip(f"Local toolchain unavailable: {missing}")
    assert not missing, f"Scanner image must include Go/cgo tooling: {missing}"
    (tmp_path / "go.mod").write_text("module example.invalid/cgo-fixture\n\ngo 1.22\n")
    source = tmp_path / "sample.go"
    source.write_text("""package sample
/*
#include <stdlib.h>
static int magnitude(int value) { return abs(value); }
*/
import "C"

func Magnitude(value int32) int32 { return int32(C.magnitude(C.int(value))) }
""")
    monkeypatch.setenv("CGO_ENABLED", "1")
    monkeypatch.setenv("GOTOOLCHAIN", "local")
    monkeypatch.setenv("GOSUMDB", "off")
    raw = tmp_path / "raw"
    raw.mkdir()
    project = ProjectContext(root=str(tmp_path), files=[str(source)], has_go=True)
    for analyzer in (GoVetAnalyzer(), GosecAnalyzer()):
        result = analyzer.analyze(project, AppConfig(), raw)
        assert result.status == ToolStatus.SUCCESS, f"{analyzer.name}: {result.message}"
        assert not result.findings
