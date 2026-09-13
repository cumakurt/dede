"""Severity mapping across analyzer tools."""

from __future__ import annotations

from dede.models import Severity


def map_semgrep_severity(value: str) -> Severity:
    mapping = {
        "ERROR": Severity.HIGH,
        "WARNING": Severity.MEDIUM,
        "INFO": Severity.INFO,
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
    }
    return mapping.get(value.upper(), Severity.INFO)


def map_bandit_severity(value: str) -> Severity:
    mapping = {
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
    }
    return mapping.get(value.upper(), Severity.LOW)


def parse_fail_on(value: str | None) -> set[Severity]:
    if not value:
        return set()
    order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    target = value.upper()
    try:
        idx = [s.value for s in order].index(target)
    except ValueError as exc:
        raise ValueError(f"Invalid fail-on severity: {value}") from exc
    return set(order[idx:])
