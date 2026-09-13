"""Discovery unit tests."""

from pathlib import Path

import pytest

from dede.config import AppConfig
from dede.discovery.files import discover_files
from dede.discovery.languages import detect_file_language, detect_languages
from dede.discovery.projects import detect_projects


def test_discover_skips_excluded(tmp_path: Path):
    (tmp_path / "keep.py").write_text("print(1)\n", encoding="utf-8")
    node = tmp_path / "node_modules"
    node.mkdir()
    (node / "x.js").write_text("eval(1)\n", encoding="utf-8")
    files = discover_files(tmp_path, AppConfig())
    rels = [str(p.relative_to(tmp_path)) for p in files]
    assert "keep.py" in rels
    assert not any("node_modules" in r for r in rels)


def test_discover_skips_analysis_caches(tmp_path: Path):
    (tmp_path / "keep.py").write_text("print(1)\n", encoding="utf-8")
    for name in (".mypy_cache", ".pytest_cache", ".ruff_cache"):
        cache = tmp_path / name
        cache.mkdir()
        (cache / "metadata.json").write_text('{"generated": true}\n', encoding="utf-8")
    files = discover_files(tmp_path, AppConfig())
    assert [path.name for path in files] == ["keep.py"]


def test_language_detection(tmp_path: Path):
    (tmp_path / "a.py").write_text("print(1)\n" * 10, encoding="utf-8")
    (tmp_path / "b.js").write_text("console.log(1)\n" * 5, encoding="utf-8")
    files = list(tmp_path.glob("*"))
    stats = detect_languages(files, tmp_path)
    assert "Python" in stats.languages
    assert "JavaScript" in stats.languages


def test_project_detection(tmp_path: Path):
    (tmp_path / "package.json").write_text('{"name":"x","dependencies":{"react":"1"}}\n')
    (tmp_path / "requirements.txt").write_text("flask\n")
    types, frameworks = detect_projects(tmp_path)
    assert "Node.js" in types
    assert "Python" in types
    assert "react" in frameworks


@pytest.mark.parametrize("extension", ["csproj", "vbproj", "fsproj", "sln", "slnx"])
def test_nested_dotnet_project_detection(tmp_path, extension):
    project = tmp_path / "service"
    project.mkdir()
    (project / f"Example.{extension}").write_text("")
    project_types, _ = detect_projects(tmp_path)
    assert ".NET" in project_types


@pytest.mark.parametrize(
    "filename,language",
    [
        ("app.vb", "Visual Basic"),
        ("app.fs", "F#"),
        ("app.fsx", "F#"),
        ("web.config", "XML"),
        ("module.psm1", "PowerShell"),
        ("app.pl", "Perl"),
    ],
)
def test_additional_language_detection(filename, language):
    assert detect_file_language(Path(filename)) == language
