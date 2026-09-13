"""A successful scanner process is insufficient without complete evidence."""

import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from scripts.validate_security_audit import TRIVY_VERSION, validate_report, validate_scanner

IMAGE_ID = "sha256:fixture"
NOW = datetime(2026, 9, 12, 12, tzinfo=timezone.utc)


@pytest.fixture
def image_report():
    package = {"Name": "fixture", "Version": "1"}
    return {
        "SchemaVersion": 2,
        "Trivy": {"Version": TRIVY_VERSION},
        "ArtifactType": "container_image",
        "Metadata": {"ImageID": IMAGE_ID, "OS": {"Family": "wolfi"}},
        "Results": [
            {"Class": "os-pkgs", "Type": "wolfi", "Packages": [package]},
            {
                "Class": "lang-pkgs",
                "Type": "python-pkg",
                "Packages": [{"Name": name, "Version": "1"} for name in ("dede", "semgrep")],
            },
            *[
                {"Class": "lang-pkgs", "Type": "gobinary", "Target": target, "Packages": [package]}
                for target in (
                    "usr/local/bin/gitleaks",
                    "usr/local/bin/gosec",
                    "usr/local/go/bin/go",
                )
            ],
        ],
    }


def test_complete_clean_inventory_is_accepted(image_report):
    validate_report(image_report, "image", IMAGE_ID)
    validate_scanner(
        {
            "Version": TRIVY_VERSION,
            "VulnerabilityDB": {
                "Version": 2,
                "UpdatedAt": NOW.isoformat(),
            },
        },
        NOW,
    )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda report: report.clear(),
        lambda report: report.update(Results=[]),
        lambda report: report.update(Results=[None]),
        lambda report: report["Metadata"].update(ImageID="sha256:another-image"),
        lambda report: report["Metadata"].update(OS={"Family": "unrecognized"}),
        lambda report: report["Metadata"]["OS"].update(EOSL=True),
        lambda report: report["Results"].pop(0),
        lambda report: report["Results"].pop(1),
        lambda report: report["Results"].pop(),
        lambda report: report["Results"][0].update(Vulnerabilities=[{"Severity": "unexpected"}]),
        lambda report: report["Results"][0].update(Misconfigurations=[{"Severity": "HIGH"}]),
    ],
)
def test_incomplete_or_mismatched_evidence_is_rejected(image_report, mutation):
    mutation(image_report)
    with pytest.raises(ValueError):
        validate_report(image_report, "image", IMAGE_ID)


@pytest.mark.parametrize("age", [timedelta(hours=49), timedelta(hours=-1)])
def test_stale_or_future_database_is_rejected(age):
    with pytest.raises(ValueError, match="48 hours"):
        validate_scanner(
            {
                "Version": TRIVY_VERSION,
                "VulnerabilityDB": {
                    "Version": 2,
                    "UpdatedAt": (NOW - age).isoformat(),
                },
            },
            NOW,
        )


def test_development_scanner_is_rejected():
    with pytest.raises(ValueError, match="require Trivy"):
        validate_scanner({"Version": "dev"}, NOW)


@pytest.mark.parametrize("raw", ["{}", '{"private-marker": invalid}'])
def test_malformed_reports_fail_without_leaking_input(tmp_path, raw):
    for target in ("image", "source"):
        (tmp_path / f"{target}.raw.json").write_text(raw)
    (tmp_path / "scanner.json").write_text("{}")
    script = Path(__file__).resolve().parents[2] / "scripts/validate_security_audit.py"
    result = subprocess.run(
        [sys.executable, str(script), str(tmp_path), IMAGE_ID, "0", "true"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 2
    assert "private-marker" not in result.stdout + result.stderr
    summary = json.loads((tmp_path / "summary.json").read_text())
    assert summary["scan_failed"] is True
    assert summary["passed"] is False
    assert not (tmp_path / "image.json").exists()
