"""Release metadata and bundled-rule validation tests."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest
import yaml

from scripts import validate_release as release
from scripts.validate_release import MANIFEST, _native_snapshot, _validate_semgrep_manifest


def test_stale_installer_image_blocks_release(monkeypatch):
    read_text = Path.read_text

    def stale_installer(path, *args, **kwargs):
        content = read_text(path, *args, **kwargs)
        if path == release.ROOT / "install.sh":
            return content.replace("dede-scanner:1.10.0", "dede-scanner:1.0.0")
        return content

    monkeypatch.setattr(Path, "read_text", stale_installer)
    with pytest.raises(SystemExit, match="install.sh"):
        release._validate_project_metadata()


def test_native_manifest_matches_source_tree() -> None:
    expected = json.loads(MANIFEST.read_text(encoding="utf-8"))
    snapshot = _native_snapshot()
    assert snapshot == expected
    assert snapshot["bundle_count"] == 13
    assert snapshot["rule_count"] == 287
    assert snapshot["mode_counts"] == {"document": 89, "line": 187, "taint": 11}


def test_manifest_is_deterministically_serializable() -> None:
    snapshot = _native_snapshot()
    rendered = json.dumps(snapshot, indent=2, sort_keys=True) + "\n"
    assert rendered == MANIFEST.read_text(encoding="utf-8")


def test_semgrep_manifest_and_checksums_match_vendored_files() -> None:
    _validate_semgrep_manifest()


@pytest.fixture
def small_semgrep(tmp_path, monkeypatch):
    directory = tmp_path / "semgrep"
    entries = {}
    sums = []
    for section in ("packs", "custom"):
        parent = directory / section
        parent.mkdir(parents=True)
        path = parent / "sample.yml"
        path.write_text("rules:\n  - id: sample\n")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        entries[section] = [{"file": f"{section}/sample.yml", "sha256": digest, "rule_count": 1}]
        sums.append(f"{digest}  rules/semgrep/{section}/sample.yml")
    manifest = directory / "MANIFEST.yml"
    manifest.write_text(yaml.safe_dump({"offline_full": True, **entries}))
    checksums = directory / "SHA256SUMS"
    checksums.write_text("\n".join(sums) + "\n")
    monkeypatch.setattr(release, "SEMGREP_DIR", directory)
    monkeypatch.setattr(release, "SEMGREP_MANIFEST", manifest)
    monkeypatch.setattr(release, "SEMGREP_CHECKSUMS", checksums)
    return directory, manifest


def test_manifest_rejects_omitted_existing_file(small_semgrep):
    directory, manifest = small_semgrep
    extra = directory / "packs/extra.yml"
    extra.write_text("rules: [{id: extra}]\n")
    with (directory / "SHA256SUMS").open("a") as stream:
        stream.write(
            f"{hashlib.sha256(extra.read_bytes()).hexdigest()}  rules/semgrep/packs/extra.yml\n"
        )
    with pytest.raises(SystemExit, match="manifest drift"):
        release._validate_semgrep_manifest()


def test_manifest_rejects_duplicate_keys(small_semgrep):
    _, manifest = small_semgrep
    with manifest.open("a") as stream:
        stream.write("offline_full: true\n")
    with pytest.raises(SystemExit, match="Duplicate manifest key"):
        release._validate_semgrep_manifest()


@pytest.mark.parametrize("filename", ["../outside.yml", "/packs/sample.yml", "custom/sample.yml"])
def test_manifest_rejects_wrong_section_or_escape(small_semgrep, filename):
    _, manifest = small_semgrep
    data = yaml.safe_load(manifest.read_text())
    data["packs"][0]["file"] = filename
    manifest.write_text(yaml.safe_dump(data))
    with pytest.raises(SystemExit, match="Invalid Semgrep manifest path"):
        release._validate_semgrep_manifest()


def test_manifest_rejects_changed_custom_content(small_semgrep):
    directory, _ = small_semgrep
    (directory / "custom/sample.yml").write_text("rules: [{id: replaced}]\n")
    with pytest.raises(SystemExit, match="checksum mismatch"):
        release._validate_semgrep_manifest()


@pytest.mark.parametrize("mutation", ["none", "rule", "version", "semgrep", "missing", "extra"])
def test_wheel_requires_exact_bundled_contents(tmp_path, monkeypatch, mutation):
    paths = {}
    for name, contents in {
        "dede-engine/core.json": '{"rules": [{"id": "original"}]}',
        "dede-engine/VERSION": "0.4.0",
        "custom/sample.yml": "rules: [{id: original}]",
    }.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents)
        paths[name] = path
    snapshot = {
        "bundles": {"core.json": {"sha256": release._digest(paths["dede-engine/core.json"])}}
    }
    monkeypatch.setattr(release, "_packaged_rules", lambda: paths)
    wheel = tmp_path / "dede.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("dede-1.1.0.dist-info/METADATA", "Name: dede\nVersion: 1.1.0\n\n")
        for name, path in paths.items():
            if mutation == "missing" and name.endswith("VERSION"):
                continue
            content = path.read_text()
            if mutation == "rule" and name.endswith(".json"):
                content = content.replace("original", "tampered")
            if mutation == "version" and name.endswith("VERSION"):
                content = "0.0.0"
            if mutation == "semgrep" and name.endswith(".yml"):
                content = content.replace("original", "tampered")
            archive.writestr("dede/bundled_rules/" + name, content)
        if mutation == "extra":
            archive.writestr("dede/bundled_rules/custom/unlisted.yml", "rules: []")
    if mutation == "none":
        release._validate_wheel(wheel, snapshot, "1.1.0")
    else:
        with pytest.raises(SystemExit, match="Wheel bundled"):
            release._validate_wheel(wheel, snapshot, "1.1.0")


def test_lock_export_check_fails_without_rewriting(tmp_path, monkeypatch):
    from scripts import check_lock_exports

    path = tmp_path / "requirements-scanner.lock"
    path.write_text("example==1.0\n")
    monkeypatch.setattr(check_lock_exports, "ROOT", tmp_path)
    monkeypatch.setattr(
        check_lock_exports.subprocess,
        "run",
        lambda *a, **kw: subprocess.CompletedProcess(a, 0, "example==2.0\n"),
    )
    with pytest.raises(SystemExit, match="Stale requirements-scanner.lock"):
        check_lock_exports.main()
    assert path.read_text() == "example==1.0\n"


def _fake_program(directory, name, body):
    path = directory / name
    path.write_text(f"#!{sys.executable}\n{body}\n")
    path.chmod(0o755)
    return path


def _fake_environment(binaries):
    # The hardened test container mounts /tmp noexec. Invoke fixture programs
    # through their interpreter without weakening the container's isolation.
    env = {**os.environ, "PATH": f'{binaries}:{os.environ["PATH"]}'}
    for binary in binaries.iterdir():
        env[f"BASH_FUNC_{binary.name}%%"] = (
            f'() {{ {shlex.quote(sys.executable)} {shlex.quote(str(binary))} "$@"; }}'
        )
    return env


@pytest.mark.parametrize("scanner_fails", [False, True])
def test_security_gate_keeps_unfixed_findings_and_redacts_secrets(tmp_path, scanner_fails):
    binaries = tmp_path / "bin"
    binaries.mkdir()
    _fake_program(binaries, "docker", 'print("sha256:test-image")')
    _fake_program(
        binaries,
        "trivy",
        """
import json, os, sys
from datetime import datetime, timezone
from pathlib import Path
args = sys.argv[1:]
if '--version' in args:
    print(json.dumps({'Version': '0.74.0', 'VulnerabilityDB': {'Version': 2, 'UpdatedAt': datetime.now(timezone.utc).isoformat()}}))
    raise SystemExit(0)
assert '--ignore-unfixed=false' in args
assert all(flag in args for flag in ['--offline-scan', '--skip-db-update', '--skip-check-update'])
if os.environ['FAIL_SCAN'] == '1':
    raise SystemExit(3)
result = {'Target': 'fixture', 'Vulnerabilities': [], 'Secrets': []}
report = {'SchemaVersion': 2, 'Trivy': {'Version': '0.74.0'}, 'Results': [result]}
package = {'Name': 'fixture', 'Version': '1'}
if args[0] == 'image':
    report.update(ArtifactType='container_image', Metadata={'ImageID': 'sha256:test-image', 'OS': {'Family': 'wolfi'}})
    report['Results'].extend([
        {'Class': 'os-pkgs', 'Type': 'wolfi', 'Packages': [package]},
        {'Class': 'lang-pkgs', 'Type': 'python-pkg', 'Packages': [{'Name': name, 'Version': '1'} for name in ('dede', 'semgrep')]},
        *[{'Class': 'lang-pkgs', 'Type': 'gobinary', 'Target': target, 'Packages': [package]} for target in ('usr/local/bin/gitleaks', 'usr/local/bin/gosec', 'usr/local/go/bin/go')],
    ])
    result['Vulnerabilities'] = [{'VulnerabilityID': 'CVE-fixture', 'Severity': 'HIGH', 'FixedVersion': ''}]
    result['Secrets'] = [{'Severity': 'LOW', 'Match': 'private-marker', 'Code': {'Lines': [{'Content': 'private-marker', 'Highlighted': 'private-marker'}]}}]
else:
    report['ArtifactType'] = 'repository'
    report['Results'].extend([{'Class': 'lang-pkgs', 'Type': 'uv', 'Packages': [package]}, {'Class': 'config', 'Type': 'dockerfile'}])
Path(args[args.index('--output') + 1]).write_text(json.dumps(report))
""",
    )
    out = tmp_path / "reports"
    result = subprocess.run(
        ["bash", str(release.ROOT / "scripts/security_audit.sh")],
        env={
            **_fake_environment(binaries),
            "DEDE_AUDIT_DIR": str(out),
            "TRIVY_OFFLINE": "true",
            "TRIVY_IGNORE_UNFIXED": "false",
            "FAIL_SCAN": str(int(scanner_fails)),
        },
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == (2 if scanner_fails else 1), result.stderr
    reports = list(out.glob("run-*"))
    summary = json.loads((reports[0] / "summary.json").read_text())
    assert summary["passed"] is False
    assert summary["scan_failed"] is scanner_fails
    if not scanner_fails:
        assert summary["blockers"] == {"image": 1, "source": 0}
        report = (reports[0] / "image.json").read_text()
        assert "private-marker" not in report
        assert "CVE-fixture" in report
    assert not list(reports[0].glob("*.raw.json"))


def test_sbom_requires_available_image_and_preserves_previous_inventory(tmp_path):
    binaries = tmp_path / "bin"
    binaries.mkdir()
    _fake_program(binaries, "docker", "raise SystemExit(2)")
    _fake_program(binaries, "syft", 'raise AssertionError("must not scan source as fallback")')
    out = tmp_path / "sbom"
    out.mkdir()
    inventory = out / "sbom.cdx.json"
    inventory.write_text("previous inventory")
    result = subprocess.run(
        ["bash", str(release.ROOT / "scripts/generate_sbom.sh")],
        env={**_fake_environment(binaries), "DEDE_SBOM_DIR": str(out)},
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode != 0
    assert inventory.read_text() == "previous inventory"


def test_rule_bootstrap_rejects_changed_optional_and_custom_rules(tmp_path):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    script = scripts / "download_rules.sh"
    content = (release.ROOT / "scripts/download_rules.sh").read_text()
    for name, entries in [
        ("CUSTOM_FILES", "custom.yml"),
        ("REQUIRED_PACKS", "r/all"),
        ("OPTIONAL_PACKS", "p/optional"),
    ]:
        content = re.sub(rf"{name}=\([\s\S]*?\)", f"{name}=(\n {entries}\n)", content, count=1)
    script.write_text(content)
    directory = tmp_path / "rules/semgrep"
    for name in ["custom/custom.yml", "packs/all.yml", "packs/optional.yml"]:
        path = directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("rules: [{id: sample}]\n")
    (directory / "MANIFEST.yml").write_text("previous manifest")
    sums = directory / "SHA256SUMS"
    sums.write_text(
        "\n".join(
            f'{"0" * 64}  rules/semgrep/{name}'
            for name in ["custom/custom.yml", "packs/all.yml", "packs/optional.yml"]
        )
    )
    binaries = tmp_path / "bin"
    binaries.mkdir()
    _fake_program(binaries, "semgrep", "raise SystemExit(0)")
    _fake_program(binaries, "curl", 'raise AssertionError("must reject before download")')
    result = subprocess.run(
        ["bash", str(script)],
        env={
            **_fake_environment(binaries),
            "UPDATE_RULE_CHECKSUMS": "0",
            "REQUIRE_RULE_CHECKSUMS": "1",
        },
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode != 0
    assert "Checksum mismatch" in result.stderr
    assert (directory / "MANIFEST.yml").read_text() == "previous manifest"
