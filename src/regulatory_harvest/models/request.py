"""Research request models."""

from datetime import date

from pydantic import Field, field_validator

from .base import StrictModel
from .enums import SourceQuality


def _non_blank(value: str) -> str:
    stripped = value.strip()
    if not stripped:
        raise ValueError("value must not be blank")
    return stripped


class SourceInput(StrictModel):
    location: str
    title: str | None = None
    jurisdiction: str | None = None
    authority_type: str | None = None
    citation: str | None = None
    source_quality: SourceQuality = SourceQuality.UNKNOWN
    license_assertion: str = "unknown"

    _validate_location = field_validator("location")(_non_blank)


class ResearchRequest(StrictModel):
    request_id: str
    question: str
    jurisdictions: list[str] = Field(min_length=1)
    as_of: date
    source_inputs: list[SourceInput] = Field(min_length=1)
    context: str | None = None
    excluded_topics: list[str] = Field(default_factory=list)
    output_instructions: str | None = None

    _validate_required_text = field_validator("request_id", "question")(_non_blank)

    @field_validator("jurisdictions")
    @classmethod
    def validate_jurisdictions(cls, values: list[str]) -> list[str]:
        normalized = [_non_blank(value) for value in values]
        if len(set(normalized)) != len(normalized):
            raise ValueError("jurisdictions must be unique")
        return normalized

