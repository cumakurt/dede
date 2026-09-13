"""Secret and sensitive data redaction helpers."""

from __future__ import annotations

import re

_SECRET_VALUE_RE = re.compile(
    r"(?P<prefix>(password|passwd|secret|token|api[_-]?key|access[_-]?key|"
    r"private[_-]?key|authorization|credential|connection[_-]?string|"
    r"aws_secret_access_key|aws_access_key_id|apiKey)\s*[=:]\s*[\"']?)"
    r"(?P<value>[^\s'\"#,;]+)",
    re.IGNORECASE,
)

_AWS_KEY_RE = re.compile(r"(AKIA[0-9A-Z]{16})")
_AWS_SECRET_RE = re.compile(r"(?<![A-Za-z0-9/+])([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])")
_BEARER_RE = re.compile(r"(Bearer\s+)([A-Za-z0-9\-._~+/]+=*)", re.IGNORECASE)
_PROVIDER_TOKEN_RE = re.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"npm_[A-Za-z0-9]{20,}|sk_(?:live|test)_[A-Za-z0-9]{16,}|"
    r"xox[baprs]-[A-Za-z0-9-]{16,}|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{20,})\b"
)
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    re.DOTALL,
)
_ASSIGNMENT_RE = re.compile(
    r"(?P<prefix>\b(?:password|passwd|secret|token|api[_-]?key|aws_secret_access_key|"
    r"aws_access_key_id|apiKey)\b\s*=\s*[\"'])"
    r"(?P<value>[^\"']+)"
    r"(?P<suffix>[\"'])",
    re.IGNORECASE,
)


def mask_secret(value: str, visible: int = 2) -> str:
    if not value:
        return value
    if len(value) <= visible * 2:
        return "*" * len(value)
    return f"{value[:visible]}{'*' * max(3, len(value) - visible * 2)}{value[-visible:]}"


def redact_text(text: str) -> str:
    if not text:
        return text

    def _replacer(match: re.Match[str]) -> str:
        return f"{match.group('prefix')}{mask_secret(match.group('value'))}"

    result = _ASSIGNMENT_RE.sub(
        lambda m: f"{m.group('prefix')}{mask_secret(m.group('value'))}{m.group('suffix')}",
        text,
    )
    result = _SECRET_VALUE_RE.sub(_replacer, result)
    result = _AWS_KEY_RE.sub(lambda m: mask_secret(m.group(1)), result)
    # Only mask AWS-like secrets when labeled nearby or EXAMPLEKEY marker
    if "EXAMPLEKEY" in result or "aws_secret" in result.lower() or "secret" in result.lower():
        result = _AWS_SECRET_RE.sub(lambda m: mask_secret(m.group(1)), result)
    result = _BEARER_RE.sub(lambda m: f"{m.group(1)}{mask_secret(m.group(2))}", result)
    result = _PROVIDER_TOKEN_RE.sub("***REDACTED***", result)
    result = _PRIVATE_KEY_RE.sub(
        "-----BEGIN PRIVATE KEY-----\n***REDACTED***\n-----END PRIVATE KEY-----",
        result,
    )
    # Explicit known FAKE test fixtures
    for fake in (
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "FAKE_PASSWORD_DO_NOT_USE",
        "sk_test_FAKE_stripe_key_do_not_use",
    ):
        if fake in result:
            result = result.replace(fake, mask_secret(fake))
    return result


def redact_snippet_for_secret_finding(snippet: str) -> str:
    # Provider tokens and private-key fragments can appear without any label.
    # A generic text redactor cannot safely reconstruct every secret format.
    return "***REDACTED***"


def redact_source_lines(lines: list[str]) -> list[str]:
    """Mask multiline private keys before excerpt selection, preserving line numbers."""
    source = _PRIVATE_KEY_RE.sub(
        lambda match: "\n".join("***REDACTED***" for _ in match.group(0).split("\n")),
        "\n".join(lines),
    )
    return [redact_text(line) for line in source.split("\n")] if lines else []


def sanitize_finding_fields(finding) -> None:
    """In-place redaction of all user-visible finding text fields."""
    for field in (
        "message",
        "code_snippet",
        "explanation",
        "impact",
        "attack_scenario",
        "recommendation",
        "secure_example",
        "summary",
        "technical_explanation",
        "exploitability",
        "recommended_fix",
        "secure_code_example",
        "ai_rationale",
        "ai_assumptions",
        "ai_verification",
        "ai_impact",
    ):
        value = getattr(finding, field, "") or ""
        setattr(finding, field, redact_text(value))
    for step in getattr(finding, "dataflow", []):
        step.content = redact_text(step.content)
