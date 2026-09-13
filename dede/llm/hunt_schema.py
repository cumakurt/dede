"""Validated contracts for AI vulnerability hunting (advisory-only)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from dede.utils.redact import redact_text


class HuntFlow(BaseModel):
    """A cross-file source→sink flow claimed by the model."""

    model_config = ConfigDict(extra="forbid", strict=True, str_strip_whitespace=True)

    description: str = Field(min_length=1, max_length=500)
    file: str = Field(min_length=1, max_length=300)
    start_line: int = Field(ge=1, le=200_000)
    end_line: int = Field(ge=1, le=200_000)
    content: str = Field(max_length=500)

    @model_validator(mode="after")
    def validate_range(self) -> HuntFlow:
        if self.end_line < self.start_line:
            raise ValueError("end_line must be greater than or equal to start_line")
        return self


class VulnHunt(BaseModel):
    """One candidate vulnerability found by reading the provided source."""

    model_config = ConfigDict(extra="forbid", strict=True, str_strip_whitespace=True)

    title: str = Field(min_length=3, max_length=200)
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    category: Literal["security", "bug"] = "security"
    cwe: str = Field(default="", max_length=20)
    file: str = Field(min_length=1, max_length=300)
    start_line: int = Field(ge=1, le=200_000)
    end_line: int = Field(ge=1, le=200_000)
    message: str = Field(min_length=1, max_length=1000)
    explanation: str = Field(min_length=1, max_length=4000)
    impact: str = Field(max_length=2000)
    attack_scenario: str = Field(max_length=2000)
    recommendation: str = Field(min_length=1, max_length=3000)
    confidence: float = Field(ge=0, le=1, allow_inf_nan=False)
    dataflow: list[HuntFlow] = Field(default_factory=list, max_length=32)
    related_files: list[str] = Field(default_factory=list, max_length=20)

    @field_validator("cwe")
    @classmethod
    def validate_cwe(cls, value: str) -> str:
        if value and (not value.startswith("CWE-") or not value[4:].isdigit()):
            raise ValueError("cwe must be empty or use the CWE-<number> form")
        return value

    @model_validator(mode="after")
    def validate_range(self) -> VulnHunt:
        if self.end_line < self.start_line:
            raise ValueError("end_line must be greater than or equal to start_line")
        return self


class VulnHuntResponse(BaseModel):
    """Strict response envelope: no findings means explicitly 'nothing found'."""

    model_config = ConfigDict(extra="forbid", strict=True, str_strip_whitespace=True)

    findings: list[VulnHunt] = Field(max_length=10)


def validate_hunt_response(data: object) -> dict | None:
    """Validate network or cache input and redact every text field."""
    try:
        response = VulnHuntResponse.model_validate(data).model_dump()
    except ValidationError:
        return None
    findings = response.get("findings") or []
    for item in findings:
        for key, value in list(item.items()):
            if isinstance(value, str):
                item[key] = redact_text(value)
        for step in item.get("dataflow") or []:
            for key, value in list(step.items()):
                if isinstance(value, str):
                    step[key] = redact_text(value)
    return response
