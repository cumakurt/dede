"""Keep bundled security metadata, deployment selection and examples consistent."""

import hashlib
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from dede.analyzers.ruleset import prepare_project_configs, resolve_semgrep_configs
from dede.config import AppConfig, SemgrepConfig
from dede.models import ProjectContext

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "rules/semgrep"
WEB_CONFIGS = sorted((RULES / "custom").glob("*-web-security.yml"))
WEB_RULES = [rule for path in WEB_CONFIGS for rule in yaml.safe_load(path.read_text())["rules"]]
SAMPLES = {
    "python": "python_web.py",
    "javascript": "javascript_web.js",
    "typescript": "javascript_web.js",
    "java": "JavaWeb.java",
    "go": "go_web.go",
    "php": "php_web.php",
}


@pytest.mark.parametrize("rule", WEB_RULES, ids=lambda rule: rule["id"])
def test_web_rule_has_metadata_and_positive_and_negative_examples(rule):
    metadata = rule["metadata"]
    assert metadata["category"] == "security"
    assert metadata["confidence"] in {"LOW", "MEDIUM", "HIGH"}
    assert metadata["cwe"]
    assert all(re.fullmatch(r"CWE-\d+", cwe) for cwe in metadata["cwe"])
    assert metadata["recommendation"].strip()
    assert metadata["references"]
    assert all(reference.startswith("https://") for reference in metadata["references"])
    if rule.get("mode") == "taint":
        assert metadata["analysis"] == "taint"
        assert rule["pattern-sources"] and rule["pattern-sinks"]
    for language in rule["languages"]:
        sample = (ROOT / "tests/rule_samples" / SAMPLES[language]).read_text()
        assert f"ruleid: {rule['id']}\n" in sample
        assert f"ok: {rule['id']}\n" in sample


def test_bundled_custom_rule_ids_are_unique():
    ids = [
        rule["id"]
        for path in (RULES / "custom").glob("*.yml")
        for rule in yaml.safe_load(path.read_text())["rules"]
    ]
    assert ids and len(ids) == len(set(ids))


@pytest.mark.parametrize("path", WEB_CONFIGS, ids=lambda path: path.stem)
def test_shared_sources_stay_consistent_without_yaml_aliases(path):
    contents = path.read_text()
    # Scanning accepts aliases, but Semgrep's native rule validator rejects them.
    assert not re.search(r"pattern-sources:\s+[&*]", contents)
    rules = yaml.safe_load(contents)["rules"]
    sources = [rule["pattern-sources"] for rule in rules if rule.get("mode") == "taint"]
    assert sources and all(source == sources[0] for source in sources)


@pytest.mark.parametrize("profile", ["full", "smart", "custom-only"])
def test_web_rules_are_enabled_by_all_profiles(profile, tmp_path):
    project = ProjectContext(
        root=str(ROOT / "tests/rule_samples"),
        files=[str(ROOT / "tests/rule_samples" / name) for name in set(SAMPLES.values())],
    )
    config = AppConfig(semgrep=SemgrepConfig(profile=profile))
    selected = resolve_semgrep_configs(project, config, rules_dir=RULES)
    assert WEB_CONFIGS and set(WEB_CONFIGS) <= set(selected)
    prepared = prepare_project_configs(WEB_CONFIGS, project, tmp_path)
    actual = {rule["id"] for path in prepared for rule in yaml.safe_load(path.read_text())["rules"]}
    assert actual == {rule["id"] for rule in WEB_RULES}


def test_rule_update_script_preserves_web_configs():
    script = (ROOT / "scripts/download_rules.sh").read_text()
    custom_files = script.split("CUSTOM_FILES=(", 1)[1].split(")", 1)[0].split()
    assert {path.name for path in WEB_CONFIGS} <= set(custom_files)


def test_manifest_matches_bundled_custom_rule_contents():
    manifest = yaml.safe_load((RULES / "MANIFEST.yml").read_text())
    entries = {item["file"]: item for item in manifest["custom"]}
    paths = sorted((RULES / "custom").glob("*.yml"))
    assert set(entries) == {str(path.relative_to(RULES)) for path in paths}
    for path in paths:
        entry = entries[str(path.relative_to(RULES))]
        contents = path.read_bytes()
        assert entry["sha256"] == hashlib.sha256(contents).hexdigest()
        assert entry["rule_count"] == len(yaml.safe_load(contents)["rules"])


@pytest.mark.skipif(shutil.which("bash") is None, reason="Rule update script requires bash")
def test_invalid_custom_rules_do_not_publish_a_manifest(tmp_path):
    script_source = ROOT / "scripts/download_rules.sh"
    script_text = script_source.read_text()
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    script = scripts / script_source.name
    shutil.copyfile(script_source, script)
    rules_dir = tmp_path / "rules/semgrep"
    for block, directory in [
        ("CUSTOM_FILES", "custom"),
        ("REQUIRED_PACKS", "packs"),
        ("OPTIONAL_PACKS", "packs"),
    ]:
        target = rules_dir / directory
        target.mkdir(parents=True, exist_ok=True)
        for entry in script_text.split(f"{block}=(", 1)[1].split(")", 1)[0].split():
            filename = entry if directory == "custom" else entry.split("/", 1)[1] + ".yml"
            sample = target / filename
            sample.write_text("rules: []\n")
            if directory == "packs":
                sample.chmod(0o600)
    manifest = rules_dir / "MANIFEST.yml"
    manifest.write_text("previous validated manifest\n")
    version = rules_dir / "VERSION"
    version.write_text("previous version\n")
    binaries = tmp_path / "bin"
    binaries.mkdir()
    # Skip parsing cached registry packs; simulate native custom-rule validation failure.
    for name, body in {"python3": "exit 0", "semgrep": "exit 2"}.items():
        binary = binaries / name
        binary.write_text(f"#!/bin/sh\n{body}\n")
        binary.chmod(0o755)
    result = subprocess.run(
        ["bash", str(script)],
        capture_output=True,
        text=True,
        timeout=10,
        env={
            **os.environ,
            "PATH": f"{binaries}{os.pathsep}{os.environ['PATH']}",
            "FORCE_REFRESH": "0",
        },
    )
    assert result.returncode != 0
    assert "Custom rule validation failed" in result.stderr
    assert manifest.read_text() == "previous validated manifest\n"
    assert version.read_text() == "previous version\n"
    assert all(path.stat().st_mode & 0o444 == 0o444 for path in (rules_dir / "packs").iterdir())
