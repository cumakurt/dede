"""Tests for offline Semgrep ruleset resolution."""

from pathlib import Path

import yaml

from dede.analyzers.ruleset import prepare_project_configs, resolve_semgrep_configs
from dede.config import AppConfig, SemgrepConfig
from dede.models import LanguageStats, ProjectContext


RULES = Path(__file__).resolve().parents[2] / "rules" / "semgrep"


def _project(
    *,
    languages: dict[str, float],
    frameworks: list[str] | None = None,
    project_types: list[str] | None = None,
    files: list[str] | None = None,
) -> ProjectContext:
    return ProjectContext(
        root="/tmp/proj",
        files=files or ["/tmp/proj/main.py"],
        languages=LanguageStats(
            languages=languages,
            frameworks=frameworks or [],
            project_types=project_types or [],
        ),
    )


def _stems(paths: list[Path]) -> set[str]:
    return {p.stem for p in paths}


def test_smart_python_selects_python_and_security_packs():
    cfg = AppConfig(semgrep=SemgrepConfig(profile="smart"))
    project = _project(languages={"Python": 100.0}, frameworks=["django"])
    configs = resolve_semgrep_configs(project, cfg, rules_dir=RULES)
    stems = _stems(configs)
    assert "python" in stems
    assert "django" in stems
    assert "security-audit" in stems
    assert "owasp-top-ten" in stems
    assert "golang" not in stems
    assert any(p.parent.name == "custom" for p in configs)


def test_smart_go_and_dockerfile():
    cfg = AppConfig(semgrep=SemgrepConfig(profile="smart"))
    project = _project(
        languages={"Go": 80.0, "Dockerfile": 20.0},
        project_types=["Go", "Docker"],
        files=["/tmp/proj/main.go", "/tmp/proj/Dockerfile"],
    )
    stems = _stems(resolve_semgrep_configs(project, cfg, rules_dir=RULES))
    assert "golang" in stems
    assert "dockerfile" in stems
    assert "python" not in stems


def test_full_profile_prefers_all_dump():
    cfg = AppConfig(semgrep=SemgrepConfig(profile="full"))
    project = _project(languages={"Python": 100.0})
    configs = resolve_semgrep_configs(project, cfg, rules_dir=RULES)
    pack_files = [p for p in configs if p.parent.name == "packs"]
    assert pack_files, "expected at least one pack config"
    # When r/all is vendored, full profile uses only packs/all.yml (+ custom)
    all_dump = RULES / "packs" / "all.yml"
    if all_dump.is_file():
        assert any(p.name == "all.yml" for p in pack_files)
        assert all(p.name == "all.yml" for p in pack_files)
    else:
        assert len(pack_files) >= 20


def test_custom_only_skips_packs_unless_extra():
    cfg = AppConfig(semgrep=SemgrepConfig(profile="custom-only", extra_packs=["nginx"]))
    project = _project(languages={"Python": 100.0})
    configs = resolve_semgrep_configs(project, cfg, rules_dir=RULES)
    stems = _stems(configs)
    assert "python" not in stems
    assert "nginx" in stems
    assert all(p.parent.name in {"custom", "packs"} for p in configs)
    assert any(p.parent.name == "custom" for p in configs)


def test_disable_packs_respected():
    cfg = AppConfig(semgrep=SemgrepConfig(profile="smart", disable_packs=["owasp-top-ten"]))
    project = _project(languages={"Python": 100.0})
    stems = _stems(resolve_semgrep_configs(project, cfg, rules_dir=RULES))
    assert "owasp-top-ten" not in stems
    assert "security-audit" in stems


def test_terraform_from_extension():
    cfg = AppConfig(semgrep=SemgrepConfig(profile="smart"))
    project = _project(
        languages={"Terraform": 100.0},
        files=["/tmp/proj/main.tf"],
    )
    stems = _stems(resolve_semgrep_configs(project, cfg, rules_dir=RULES))
    assert "terraform" in stems


def test_preparation_keeps_applicable_and_generic_rules(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("print(1)")
    config = tmp_path / "all.yml"
    config.write_text(
        yaml.safe_dump(
            {
                "rules": [
                    {"id": "python-rule", "languages": ["python"], "pattern": "eval(...)"},
                    {"id": "apex-rule", "languages": ["apex"], "pattern": "..."},
                    {"id": "generic-rule", "languages": ["generic"], "pattern": "..."},
                ]
            }
        )
    )
    project = ProjectContext(root=str(tmp_path), files=[str(source)])
    selected = prepare_project_configs([config], project, tmp_path)
    assert len(selected) == 1
    prepared = yaml.safe_load(selected[0].read_text())
    assert {rule["id"] for rule in prepared["rules"]} == {"python-rule", "generic-rule"}
    assert len(yaml.safe_load(config.read_text())["rules"]) == 3


def test_preparation_does_not_hide_present_unsupported_languages(tmp_path):
    source = tmp_path / "Example.cls"
    source.write_text("public class Example {}")
    config = tmp_path / "all.yml"
    config.write_text(
        yaml.safe_dump({"rules": [{"id": "apex-rule", "languages": ["apex"], "pattern": "..."}]})
    )
    project = ProjectContext(root=str(tmp_path), files=[str(source)])
    assert prepare_project_configs([config], project, tmp_path) == [config]


def test_typescript_keeps_javascript_compatible_rules(tmp_path):
    source = tmp_path / "app.ts"
    source.write_text("const value: string = 'test';")
    config = tmp_path / "all.yml"
    config.write_text(
        yaml.safe_dump(
            {"rules": [{"id": "js-rule", "languages": ["javascript"], "pattern": "eval(...)"}]}
        )
    )
    project = ProjectContext(root=str(tmp_path), files=[str(source)])
    assert prepare_project_configs([config], project, tmp_path) == [config]
