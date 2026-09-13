"""Require reviewable metadata and regression examples for every added rule."""

import json
import re
from pathlib import Path

import pytest
import yaml

from dede.analyzers.ruleset import prepare_project_configs, resolve_semgrep_configs
from dede.config import AppConfig, SemgrepConfig
from dede.models import ProjectContext

ROOT = Path(__file__).resolve().parents[2]
CONFIGS = sorted((ROOT / "rules/semgrep/custom").glob("*-advanced-security.yml"))
RULES = [rule for path in CONFIGS for rule in yaml.safe_load(path.read_text())["rules"]]
CASES = json.loads((ROOT / "tests/rule_samples/advanced_cases.json").read_text())


@pytest.mark.parametrize("rule", RULES, ids=lambda rule: rule["id"])
def test_each_rule_has_standards_and_regression_examples(rule):
    metadata = rule["metadata"]
    assert metadata["category"] == "security"
    assert metadata["confidence"] in {"HIGH", "MEDIUM", "LOW"}
    assert all(re.fullmatch(r"CWE-\d+", cwe) for cwe in metadata["cwe"])
    assert all(re.fullmatch(r"A\d{2}:2025", item) for item in metadata["owasp"])
    assert all(
        re.fullmatch(r"v5\.0\.0-\d+\.\d+\.\d+", item)
        for item in metadata["standards"]["owasp-asvs-5.0.0"]
    )
    assert metadata["recommendation"]
    assert metadata["references"]
    samples = [case for case in CASES if case["rule_id"] == rule["id"]]
    assert samples and all(case["unsafe"] != case["safe"] for case in samples)
    if rule["languages"] == ["generic"]:
        assert metadata["analysis"] == "regex"
        assert rule["paths"]["include"]
        assert "mode" not in rule
    if rule.get("mode") == "taint":
        assert metadata["analysis"] == "taint"
        assert rule["pattern-sources"] and rule["pattern-sinks"]


@pytest.mark.parametrize("profile", ["smart", "full", "custom-only"])
def test_all_profiles_preserve_new_language_rules(profile, tmp_path):
    files = []
    for index, case in enumerate(CASES):
        path = tmp_path / f"sample_{index}.{case['extension']}"
        path.write_text(case["unsafe"])
        files.append(str(path))
    project = ProjectContext(root=str(tmp_path), files=files)
    selected = resolve_semgrep_configs(
        project,
        AppConfig(semgrep=SemgrepConfig(profile=profile)),
        rules_dir=ROOT / "rules/semgrep",
    )
    assert set(CONFIGS) <= set(selected)
    prepared = prepare_project_configs(CONFIGS, project, tmp_path)
    actual = {rule["id"] for path in prepared for rule in yaml.safe_load(path.read_text())["rules"]}
    assert actual == {rule["id"] for rule in RULES}


def test_updater_includes_every_advanced_config():
    script = (ROOT / "scripts/download_rules.sh").read_text()
    filenames = script.split("CUSTOM_FILES=(", 1)[1].split(")", 1)[0].split()
    assert {path.name for path in CONFIGS} <= set(filenames)
