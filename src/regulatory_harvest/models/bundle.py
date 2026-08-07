"""Canonical portable evidence bundle."""

from typing import Literal

from pydantic import Field

from .analysis import Finding, Gap, ResearchIssue, ReviewItem
from .base import StrictModel
from .request import ResearchRequest
from .run import RunManifest, ValidationReport
from .source import CitationSpan, SourceRecord

DISCLAIMER: Literal[
    "AI-assisted research work product. A qualified attorney must verify the sources, "
    "analysis, currentness, and applicability before relying on it or delivering legal advice."
] = (
    "AI-assisted research work product. A qualified attorney must verify the sources, "
    "analysis, currentness, and applicability before relying on it or delivering legal advice."
)


class ResearchBundle(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    generator_version: str
    request: ResearchRequest
    manifest: RunManifest
    sources: list[SourceRecord] = Field(default_factory=list)
    issues: list[ResearchIssue] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    citations: list[CitationSpan] = Field(default_factory=list)
    gaps: list[Gap] = Field(default_factory=list)
    review_items: list[ReviewItem] = Field(default_factory=list)
    validation: ValidationReport | None = None
    disclaimer: Literal[
        "AI-assisted research work product. A qualified attorney must verify the sources, "
        "analysis, currentness, and applicability before relying on it or delivering legal advice."
    ] = DISCLAIMER
    requires_attorney_review: Literal[True] = True
    bundle_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
