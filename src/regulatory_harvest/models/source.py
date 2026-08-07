"""Source and citation models."""

from datetime import datetime

from pydantic import Field, field_validator, model_validator

from .base import StrictModel
from .enums import FetchStatus, SourceQuality
from .request import _non_blank


class SourceFailure(StrictModel):
    category: str
    retryable: bool = False
    message: str
    provider_status_code: int | None = None

    _validate_text = field_validator("category", "message")(_non_blank)


class SourceRecord(StrictModel):
    source_id: str
    origin: str
    display_name: str
    retrieved_at: datetime
    content_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    media_type: str
    normalized_text: str = ""
    normalization_warnings: list[str] = Field(default_factory=list)
    title: str | None = None
    publisher: str | None = None
    jurisdiction: str | None = None
    authority_type: str | None = None
    citation: str | None = None
    effective_date: str | None = None
    supersession: str | None = None
    license_assertion: str = "unknown"
    source_quality: SourceQuality = SourceQuality.UNKNOWN
    fetch_status: FetchStatus = FetchStatus.SUCCEEDED
    error: SourceFailure | None = None
    external_ids: dict[str, str] = Field(default_factory=dict)

    _validate_text = field_validator(
        "source_id", "origin", "display_name", "media_type", "license_assertion"
    )(_non_blank)

    @model_validator(mode="after")
    def validate_fetch_result(self) -> "SourceRecord":
        if self.fetch_status is FetchStatus.SUCCEEDED and self.content_hash is None:
            raise ValueError("successful sources require a content hash")
        if self.fetch_status is FetchStatus.FAILED and self.error is None:
            raise ValueError("failed sources require an error")
        return self


class CitationSpan(StrictModel):
    citation_id: str
    source_id: str
    start_char: int = Field(ge=0)
    end_char: int = Field(gt=0)
    quote: str
    external_ids: dict[str, str] = Field(default_factory=dict)

    _validate_text = field_validator("citation_id", "source_id", "quote")(_non_blank)

    @model_validator(mode="after")
    def validate_half_open_offsets(self) -> "CitationSpan":
        if self.end_char <= self.start_char:
            raise ValueError("end_char must be greater than start_char")
        return self

