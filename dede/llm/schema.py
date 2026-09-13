"""Validated, advisory-only AI review contract."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from dede.utils.redact import redact_text


class FindingReview(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, str_strip_whitespace=True)

    summary: str = Field(min_length=1, max_length=1000)
    technical_explanation: str = Field(min_length=1, max_length=6000)
    impact: str = Field(max_length=3000)
    exploitability: str = Field(max_length=3000)
    false_positive_probability: Literal["LOW", "MEDIUM", "HIGH"]
    recommended_fix: str = Field(min_length=1, max_length=6000)
    secure_code_example: str = Field(max_length=8000)
    confidence: float = Field(ge=0, le=1, allow_inf_nan=False)
    verdict: Literal["LIKELY_VALID", "LIKELY_FALSE_POSITIVE", "NEEDS_CONTEXT"]
    rationale: str = Field(min_length=1, max_length=3000)
    assumptions: str = Field(max_length=3000)
    verification: str = Field(min_length=1, max_length=3000)


def validate_review(data: object) -> dict | None:
    """Validate both network and cache input; redact before persistence."""
    try:
        review = FindingReview.model_validate(data).model_dump()
    except ValidationError:
        return None
    return {
        key: redact_text(value) if isinstance(value, str) else value
        for key, value in review.items()
    }
