"""Research analysis models."""

from pydantic import Field, field_validator

from .base import StrictModel
from .enums import ClaimKind, ReviewStatus, Severity, SupportStatus
from .request import _non_blank


class ResearchIssue(StrictModel):
    issue_id: str
    title: str
    description: str | None = None
    jurisdictions: list[str] = Field(default_factory=list)

    _validate_text = field_validator("issue_id", "title")(_non_blank)


class Claim(StrictModel):
    claim_id: str
    text: str
    kind: ClaimKind
    citation_ids: list[str] = Field(default_factory=list)
    support_status: SupportStatus = SupportStatus.INDETERMINATE
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    review_status: ReviewStatus = ReviewStatus.PENDING
    external_ids: dict[str, str] = Field(default_factory=dict)

    _validate_text = field_validator("claim_id", "text")(_non_blank)


class Finding(StrictModel):
    finding_id: str
    issue_id: str
    title: str
    jurisdiction: str
    authority: str
    severity: Severity
    practical_implication: str
    claims: list[Claim] = Field(default_factory=list)
    external_ids: dict[str, str] = Field(default_factory=dict)

    _validate_text = field_validator(
        "finding_id",
        "issue_id",
        "title",
        "jurisdiction",
        "authority",
        "practical_implication",
    )(_non_blank)


class Gap(StrictModel):
    gap_id: str
    code: str
    message: str
    jurisdiction: str | None = None
    source_ids: list[str] = Field(default_factory=list)

    _validate_text = field_validator("gap_id", "code", "message")(_non_blank)


ReviewContextValue = str | int | float | bool | None | list[str]


class ReviewItem(StrictModel):
    review_id: str
    code: str
    message: str
    related_ids: list[str] = Field(default_factory=list)
    context: dict[str, ReviewContextValue] = Field(default_factory=dict)
    status: ReviewStatus = ReviewStatus.PENDING

    _validate_text = field_validator("review_id", "code", "message")(_non_blank)

