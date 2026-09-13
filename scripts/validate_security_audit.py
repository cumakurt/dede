"""Fail closed on incomplete Trivy evidence and redact secret source lines."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

TRIVY_VERSION = "0.74.0"
SEVERITIES = {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}


def validate_scanner(scanner: dict[str, Any], now: datetime) -> None:
    if scanner.get("Version") != TRIVY_VERSION:
        raise ValueError(f"Release audits require Trivy {TRIVY_VERSION}")
    database = scanner.get("VulnerabilityDB", {})
    if database.get("Version") != 2:
        raise ValueError("Missing or unsupported vulnerability database")
    updated = datetime.fromisoformat(database["UpdatedAt"].replace("Z", "+00:00"))
    if updated.tzinfo is None or not timedelta(0) <= now - updated <= timedelta(hours=48):
        raise ValueError("Vulnerability database must be no more than 48 hours old")


def validate_report(report: dict[str, Any], target: str, image_id: str) -> None:
    if report.get("SchemaVersion") != 2 or report.get("Trivy", {}).get("Version") != TRIVY_VERSION:
        raise ValueError("Missing or unsupported Trivy report schema/version")
    results = report.get("Results")
    if not isinstance(results, list) or not results:
        raise ValueError("Missing scan results")
    inventories = {}
    for result in results:
        if not isinstance(result, dict):
            raise ValueError("Invalid scan result")
        if result.get("Packages"):
            packages = result["Packages"]
            if not isinstance(packages, list) or any(
                not isinstance(package, dict)
                or not package.get("Name")
                or not package.get("Version")
                for package in packages
            ):
                raise ValueError("Invalid package inventory")
            inventories[(result.get("Class"), result.get("Type"))] = packages
        for key in ("Vulnerabilities", "Secrets", "Misconfigurations"):
            findings = result.get(key, [])
            if not isinstance(findings, list):
                raise ValueError("Invalid findings collection")
            for finding in findings:
                if not isinstance(finding, dict) or finding.get("Severity") not in SEVERITIES:
                    raise ValueError("Missing or invalid finding severity")
                if key == "Misconfigurations" and finding.get("Status") not in {
                    "PASS",
                    "FAIL",
                    "EXCEPTION",
                }:
                    raise ValueError("Missing or invalid misconfiguration status")
    if target == "image":
        metadata = report.get("Metadata", {})
        os_info = metadata.get("OS", {})
        family = os_info.get("Family")
        if report.get("ArtifactType") != "container_image" or metadata.get("ImageID") != image_id:
            raise ValueError("Scan does not identify the requested immutable image")
        if family not in {"wolfi", "debian"} or os_info.get("EOSL"):
            raise ValueError("Unverified or end-of-life scanner operating system")
        if ("os-pkgs", family) not in inventories:
            raise ValueError("Missing operating-system package inventory")
        python_packages = {
            package["Name"] for package in inventories.get(("lang-pkgs", "python-pkg"), [])
        }
        if not {"dede", "semgrep"} <= python_packages:
            raise ValueError("Missing scanner Python package inventory")
        go_targets = {
            result.get("Target")
            for result in results
            if result.get("Type") == "gobinary" and result.get("Packages")
        }
        if (
            not {"usr/local/bin/gitleaks", "usr/local/bin/gosec", "usr/local/go/bin/go"}
            <= go_targets
        ):
            raise ValueError("Missing Go toolchain/analyzer package inventory")
    else:
        if report.get("ArtifactType") != "repository" or ("lang-pkgs", "uv") not in inventories:
            raise ValueError("Missing source dependency inventory")
        if not any(result.get("Type") == "dockerfile" for result in results):
            raise ValueError("Missing Dockerfile configuration scan")


def redact_and_count(report: dict[str, Any]) -> int:
    blockers = 0
    for result in report["Results"]:
        for secret in result.get("Secrets", []):
            secret["Match"] = "[REDACTED]"
            for line in secret.get("Code", {}).get("Lines", []):
                line["Content"] = "[REDACTED]"
                line.pop("Highlighted", None)
        for key in ("Vulnerabilities", "Secrets", "Misconfigurations"):
            blockers += sum(
                finding["Severity"] in {"HIGH", "CRITICAL"}
                and (key != "Misconfigurations" or finding["Status"] == "FAIL")
                for finding in result.get(key, [])
            )
    return blockers


def main() -> int:
    out_arg, image_id, scan_failed, offline = sys.argv[1:]
    out = Path(out_arg)
    errors = ["Trivy execution failed"] if scan_failed != "0" else []
    counts = {}
    try:
        scanner = json.loads((out / "scanner.json").read_text())
        validate_scanner(scanner, datetime.now(timezone.utc))
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        errors.append(
            "Invalid scanner metadata; require pinned Trivy and a database under 48 hours old"
        )
    for target in ("image", "source"):
        try:
            report = json.loads((out / f"{target}.raw.json").read_text())
            validate_report(report, target, image_id)
            counts[target] = redact_and_count(report)
            (out / f"{target}.json").write_text(json.dumps(report, indent=2) + "\n")
            print(f"{target}: {counts[target]} HIGH/CRITICAL blocking findings")
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            # Malformed input can contain secrets, including in exception text.
            errors.append(f"{target}: missing, malformed or incomplete scan evidence")
    summary = {
        "image_id": image_id,
        "offline": offline == "true",
        "blockers": counts,
        "scan_failed": bool(errors),
        "errors": errors,
        "passed": not errors and not any(counts.values()),
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    for error in errors:
        print(error, file=sys.stderr)
    print(f"Security reports: {out}")
    return 2 if errors else int(not summary["passed"])


if __name__ == "__main__":
    raise SystemExit(main())
