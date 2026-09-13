#!/usr/bin/env python3
"""Validate release metadata, native rules, and bundled wheel contents.

Run with the project's locked dependencies. It fails closed when checked-in
manifests or packaged rules differ from the validated checkout.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tarfile
import tomllib
import zipfile
from collections import Counter
from email.parser import Parser
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
RULES_DIR = ROOT / "rules" / "dede-engine"
MANIFEST = RULES_DIR / "MANIFEST.json"
SEMGREP_DIR = ROOT / "rules" / "semgrep"
SEMGREP_MANIFEST = SEMGREP_DIR / "MANIFEST.yml"
SEMGREP_CHECKSUMS = SEMGREP_DIR / "SHA256SUMS"
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:[.-][0-9A-Za-z.-]+)?$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class UniqueKeyLoader(yaml.SafeLoader):
    """Reject ambiguous release manifests instead of accepting the last key."""

    def construct_mapping(self, node: Any, deep: bool = False) -> dict[Any, Any]:
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in result:
                raise yaml.YAMLError(f"Duplicate manifest key: {key}")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _native_snapshot() -> dict[str, Any]:
    # Import from the checkout, never from an installed copy.
    sys.path.insert(0, str(ROOT))
    from dede.engine.rules import load_rules_dir

    rule_files = load_rules_dir(RULES_DIR)
    rules = [rule for bundle in rule_files for rule in bundle.rules]
    modes = Counter(rule.mode for rule in rules)
    bundles: dict[str, Any] = {}
    for bundle in rule_files:
        bundle_modes = Counter(rule.mode for rule in bundle.rules)
        bundles[bundle.path.name] = {
            "sha256": bundle.digest,
            "rules": len(bundle.rules),
            "modes": dict(sorted(bundle_modes.items())),
        }
    return {
        "schema": 1,
        "engine_version": (RULES_DIR / "VERSION").read_text(encoding="utf-8").strip(),
        "bundle_count": len(rule_files),
        "rule_count": len(rules),
        "mode_counts": dict(sorted(modes.items())),
        "bundles": dict(sorted(bundles.items())),
    }


def _load_manifest() -> dict[str, Any]:
    try:
        payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"Invalid native rules manifest: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit("Native rules manifest must be a JSON object")
    return payload


def _validate_project_metadata() -> str:
    try:
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    except (OSError, UnicodeError, tomllib.TOMLDecodeError, KeyError) as exc:
        raise SystemExit(f"Cannot read project metadata: {exc}") from exc
    version = project.get("version")
    if not isinstance(version, str) or not VERSION_RE.fullmatch(version):
        raise SystemExit(f"Invalid project version: {version!r}")
    for required in ("name", "description", "license", "readme"):
        if not project.get(required):
            raise SystemExit(f"Missing project metadata: {required}")
    if not (ROOT / "uv.lock").is_file():
        raise SystemExit("uv.lock is required for reproducible dependency resolution")
    expected_image_tag = f"dede-scanner:{version}"
    for reference_name in (
        "docker-compose.yml",
        "Makefile",
        "install.sh",
        "dede/cli.py",
        "dede/doctor.py",
        "scripts/security_audit.sh",
        "scripts/generate_sbom.sh",
        "scripts/verify_offline.sh",
        ".github/workflows/ci.yml",
    ):
        reference_file = ROOT / reference_name
        try:
            reference_text = reference_file.read_text(encoding="utf-8")
        except OSError as exc:
            raise SystemExit(f"Cannot read release reference {reference_file}: {exc}") from exc
        if expected_image_tag not in reference_text:
            raise SystemExit(f"{reference_file.name} does not reference {expected_image_tag}")
        tags = re.findall(r"dede-scanner(?:-test)?:([0-9]+\.[0-9]+\.[0-9]+)", reference_text)
        if any(tag != version for tag in tags):
            raise SystemExit(f"{reference_name} contains stale scanner image references")
    for lock_name in (
        "requirements-build.lock",
        "requirements-scanner.lock",
        "requirements-dev.lock",
    ):
        lock_path = ROOT / lock_name
        if not lock_path.is_file() or "--hash=sha256:" not in lock_path.read_text(encoding="utf-8"):
            raise SystemExit(f"Hashed lock export is missing or invalid: {lock_name}")
    return version


def _validate_semgrep_manifest() -> None:
    """Validate every vendored Semgrep file against both manifests."""
    try:
        payload = yaml.load(SEMGREP_MANIFEST.read_text(encoding="utf-8"), Loader=UniqueKeyLoader)
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise SystemExit(f"Invalid Semgrep manifest: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("offline_full") is not True:
        raise SystemExit("Semgrep manifest must declare offline_full: true")

    listed: dict[str, dict[str, Any]] = {}
    for section in ("packs", "custom"):
        entries = payload.get(section)
        if not isinstance(entries, list) or not entries:
            raise SystemExit(f"Semgrep manifest section is empty or invalid: {section}")
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get("file"), str):
                raise SystemExit(f"Invalid Semgrep manifest entry in {section}")
            relative = entry["file"]
            parts = Path(relative).parts
            if len(parts) != 2 or parts[0] != section or Path(relative).as_posix() != relative:
                raise SystemExit(f"Invalid Semgrep manifest path in {section}: {relative}")
            if relative in listed:
                raise SystemExit(f"Duplicate Semgrep manifest file: {relative}")
            listed[relative] = entry

    try:
        checksum_lines = SEMGREP_CHECKSUMS.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise SystemExit(f"Cannot read Semgrep checksum manifest: {exc}") from exc
    checksums: dict[str, str] = {}
    for line in checksum_lines:
        if not line.strip():
            continue
        parts = line.split(maxsplit=1)
        if len(parts) != 2 or not SHA256_RE.fullmatch(parts[0]):
            raise SystemExit(f"Invalid Semgrep checksum entry: {line!r}")
        relative = parts[1].lstrip("*")
        if relative in checksums:
            raise SystemExit(f"Duplicate Semgrep checksum entry: {relative}")
        checksums[relative] = parts[0]

    actual_paths = {
        path.relative_to(SEMGREP_DIR).as_posix()
        for parent in (SEMGREP_DIR / "packs", SEMGREP_DIR / "custom")
        for path in parent.rglob("*")
        if path.is_file() and path.suffix in {".yml", ".yaml"}
    }
    if set(listed) != actual_paths:
        raise SystemExit(
            f"Semgrep manifest drift (missing={sorted(actual_paths - listed.keys())}, "
            f"extra={sorted(listed.keys() - actual_paths)})"
        )
    expected_checksum_paths = {path.removeprefix("rules/semgrep/") for path in checksums}
    if actual_paths != expected_checksum_paths:
        missing = sorted(actual_paths - expected_checksum_paths)
        extra = sorted(expected_checksum_paths - actual_paths)
        raise SystemExit(f"Semgrep checksum drift (missing={missing}, extra={extra})")

    for relative, entry in listed.items():
        candidate = (SEMGREP_DIR / relative).resolve()
        if SEMGREP_DIR.resolve() not in candidate.parents or not candidate.is_file():
            raise SystemExit(f"Semgrep manifest file is missing or escapes rules/: {relative}")
        digest = _digest(candidate)
        if entry.get("sha256") != digest or checksums.get(f"rules/semgrep/{relative}") != digest:
            raise SystemExit(f"Semgrep checksum mismatch: {relative}")
        try:
            document = yaml.safe_load(candidate.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, yaml.YAMLError) as exc:
            raise SystemExit(f"Invalid Semgrep YAML {relative}: {exc}") from exc
        rule_list = document.get("rules") if isinstance(document, dict) else None
        if not isinstance(rule_list, list) or not rule_list:
            raise SystemExit(f"Semgrep YAML has no rules: {relative}")
        if entry.get("rule_count") != len(rule_list):
            raise SystemExit(f"Semgrep rule count mismatch: {relative}")


def _validate_wheel(path: Path, snapshot: dict[str, Any], project_version: str) -> None:
    try:
        archive = zipfile.ZipFile(path)
    except (OSError, zipfile.BadZipFile) as exc:
        raise SystemExit(f"Cannot open wheel {path}: {exc}") from exc
    with archive:
        names = set(archive.namelist())
        if len(names) != len(archive.namelist()):
            raise SystemExit("Wheel contains duplicate archive members")
        metadata_names = sorted(name for name in names if name.endswith(".dist-info/METADATA"))
        if len(metadata_names) != 1:
            raise SystemExit(f"Wheel must contain one dist-info METADATA file: {path}")
        metadata = archive.read(metadata_names[0]).decode("utf-8", errors="strict")
        fields = Parser().parsestr(metadata, headersonly=True)
        if fields.get("Name") != "dede" or fields.get("Version") != project_version:
            raise SystemExit(
                f"Wheel metadata does not match project: {fields.get('Name')} {fields.get('Version')}"
            )
        prefix = "dede/bundled_rules/"
        expected = _packaged_rules()
        actual = {name.removeprefix(prefix) for name in names if name.startswith(prefix)}
        if actual != set(expected):
            raise SystemExit("Wheel bundled rules inventory differs from checkout")
        for name, source in expected.items():
            digest = hashlib.sha256(archive.read(prefix + name)).hexdigest()
            if digest != _digest(source):
                raise SystemExit(f"Wheel bundled content mismatch: {name}")
        # Independently bind the packaged native bundles to the validated snapshot.
        for name, bundle in snapshot["bundles"].items():
            if (
                hashlib.sha256(archive.read(prefix + "dede-engine/" + name)).hexdigest()
                != bundle["sha256"]
            ):
                raise SystemExit(f"Wheel native snapshot mismatch: {name}")


def _packaged_rules() -> dict[str, Path]:
    return {
        prefix + path.relative_to(directory).as_posix(): path
        for directory, prefix in ((SEMGREP_DIR, ""), (RULES_DIR, "dede-engine/"))
        for path in directory.rglob("*")
        if path.is_file()
    }


def _validate_sdist(path: Path, project_version: str) -> None:
    prefix = f"dede-{project_version}/"
    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        names = {member.name for member in members}
        if len(names) != len(members) or any(not member.isfile() for member in members):
            raise SystemExit("Sdist has duplicate or non-regular members")
        expected = {
            prefix + path.relative_to(ROOT).as_posix(): path
            for path in (ROOT / "rules").rglob("*")
            if path.is_file()
        }
        actual = {name for name in names if name.startswith(prefix + "rules/")}
        if actual != set(expected):
            raise SystemExit("Sdist rules inventory differs from checkout")
        expected[prefix + "pyproject.toml"] = ROOT / "pyproject.toml"
        for name, source in expected.items():
            stream = archive.extractfile(name)
            if stream is None or hashlib.sha256(stream.read()).hexdigest() != _digest(source):
                raise SystemExit(f"Sdist content mismatch: {name}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="write the native manifest")
    parser.add_argument("--wheel", type=Path, help="validate bundled rules in a wheel")
    parser.add_argument("--sdist", type=Path, help="validate rules and metadata in an sdist")
    parser.add_argument("--tag", help="require the release tag to equal v<project version>")
    args = parser.parse_args()

    project_version = _validate_project_metadata()
    if args.tag is not None and args.tag != f"v{project_version}":
        raise SystemExit(f"Release tag must be v{project_version}, got {args.tag!r}")
    _validate_semgrep_manifest()
    snapshot = _native_snapshot()
    if args.write:
        MANIFEST.write_text(json.dumps(snapshot, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    elif _load_manifest() != snapshot:
        raise SystemExit("rules/dede-engine/MANIFEST.json is stale; run with --write")
    if args.wheel:
        _validate_wheel(args.wheel.resolve(), snapshot, project_version)
    if args.sdist:
        _validate_sdist(args.sdist.resolve(), project_version)
    print(
        f"Release metadata OK: {snapshot['rule_count']} rules in "
        f"{snapshot['bundle_count']} native bundles; engine {snapshot['engine_version']}"
    )
    if args.wheel:
        print(f"Wheel OK: {args.wheel}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
