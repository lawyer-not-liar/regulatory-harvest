"""Conversion from untrusted analysis drafts to canonical evidence artifacts."""

from pydantic import Field

from regulatory_harvest.models import (
    CitationSpan,
    Claim,
    ClaimKind,
    Finding,
    ResearchIssue,
    ReviewItem,
    SourceRecord,
    SupportStatus,
)
from regulatory_harvest.models.base import StrictModel
from regulatory_harvest.storage import sha256_digest
from regulatory_harvest.validation import check_claim_support, resolve_quote

from .drafts import AnalysisDraft, ProposedCitation


class AnalysisBuildResult(StrictModel):
    issues: list[ResearchIssue] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    citations: list[CitationSpan] = Field(default_factory=list)
    review_items: list[ReviewItem] = Field(default_factory=list)


def _citation_id(claim_id: str, index: int, proposal: ProposedCitation) -> str:
    identity = "\0".join(
        [
            claim_id,
            str(index),
            proposal.source_id,
            proposal.quote,
            str(proposal.occurrence or ""),
        ]
    )
    return f"cite_{sha256_digest(identity.encode())[:24]}"


def _review_item(
    claim_id: str,
    proposal_index: int,
    code: str,
    message: str,
    proposal: ProposedCitation,
) -> ReviewItem:
    identity = f"{claim_id}\0{proposal_index}\0{code}\0{proposal.source_id}\0{proposal.quote}"
    return ReviewItem(
        review_id=f"review_{sha256_digest(identity.encode())[:24]}",
        code=code,
        message=message,
        related_ids=[claim_id, proposal.source_id],
        context={
            "source_id": proposal.source_id,
            "quote": proposal.quote,
            "occurrence": proposal.occurrence,
        },
    )


def build_analysis(draft: AnalysisDraft, sources: list[SourceRecord]) -> AnalysisBuildResult:
    """Resolve model-proposed evidence without trusting offsets or confidence."""
    source_by_id = {source.source_id: source for source in sources}
    issues = [
        ResearchIssue(
            issue_id=issue.issue_id,
            title=issue.title,
            description=issue.description,
            jurisdictions=issue.jurisdictions,
        )
        for issue in draft.issues
    ]
    findings: list[Finding] = []
    citations: list[CitationSpan] = []
    review_items: list[ReviewItem] = []

    for draft_finding in draft.findings:
        claims: list[Claim] = []
        for draft_claim in draft_finding.claims:
            claim_citations: list[CitationSpan] = []
            if draft_claim.kind is ClaimKind.SOURCE_SUPPORTED:
                for proposal_index, proposal in enumerate(draft_claim.proposed_citations):
                    source = source_by_id.get(proposal.source_id)
                    if source is None:
                        review_items.append(
                            _review_item(
                                draft_claim.claim_id,
                                proposal_index,
                                "PROPOSED_SOURCE_MISSING",
                                "Proposed citation references a source outside the bundle.",
                                proposal,
                            )
                        )
                        continue
                    resolution = resolve_quote(
                        source.normalized_text,
                        proposal.quote,
                        occurrence=proposal.occurrence,
                    )
                    if not resolution.exact:
                        code = (
                            "PROPOSED_QUOTE_AMBIGUOUS"
                            if resolution.ambiguous
                            else "PROPOSED_QUOTE_NOT_FOUND"
                        )
                        review_items.append(
                            _review_item(
                                draft_claim.claim_id,
                                proposal_index,
                                code,
                                "Proposed quote could not be resolved exactly and uniquely.",
                                proposal,
                            )
                        )
                        continue
                    assert resolution.start_char is not None
                    assert resolution.end_char is not None
                    citation = CitationSpan(
                        citation_id=_citation_id(
                            draft_claim.claim_id, proposal_index, proposal
                        ),
                        source_id=proposal.source_id,
                        start_char=resolution.start_char,
                        end_char=resolution.end_char,
                        quote=proposal.quote,
                    )
                    claim_citations.append(citation)
                    citations.append(citation)

            claim = Claim(
                claim_id=draft_claim.claim_id,
                text=draft_claim.text,
                kind=draft_claim.kind,
                citation_ids=[citation.citation_id for citation in claim_citations],
                confidence=draft_claim.confidence,
            )
            if draft_claim.kind is ClaimKind.SOURCE_SUPPORTED and claim_citations:
                support = check_claim_support(claim, claim_citations, sources)
                claim.support_status = support.status
            elif draft_claim.kind is ClaimKind.ANALYSIS:
                claim.support_status = SupportStatus.INDETERMINATE
            claims.append(claim)

        findings.append(
            Finding(
                finding_id=draft_finding.finding_id,
                issue_id=draft_finding.issue_id,
                title=draft_finding.title,
                jurisdiction=draft_finding.jurisdiction,
                authority=draft_finding.authority,
                severity=draft_finding.severity,
                practical_implication=draft_finding.practical_implication,
                claims=claims,
            )
        )

    return AnalysisBuildResult(
        issues=issues,
        findings=findings,
        citations=citations,
        review_items=review_items,
    )
