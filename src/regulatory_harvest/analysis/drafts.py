"""Strict, provider-neutral draft models."""

from pydantic import Field

from regulatory_harvest.models import ClaimKind, Severity
from regulatory_harvest.models.base import StrictModel


class ProposedCitation(StrictModel):
    source_id: str
    quote: str
    occurrence: int | None = Field(default=None, ge=1)


class DraftClaim(StrictModel):
    claim_id: str
    text: str
    kind: ClaimKind
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    proposed_citations: list[ProposedCitation] = Field(default_factory=list)


class DraftFinding(StrictModel):
    finding_id: str
    issue_id: str
    title: str
    jurisdiction: str
    authority: str
    severity: Severity
    practical_implication: str
    claims: list[DraftClaim] = Field(default_factory=list)


class DraftIssue(StrictModel):
    issue_id: str
    title: str
    description: str | None = None
    jurisdictions: list[str] = Field(default_factory=list)


class AnalysisDraft(StrictModel):
    issues: list[DraftIssue] = Field(default_factory=list)
    findings: list[DraftFinding] = Field(default_factory=list)
