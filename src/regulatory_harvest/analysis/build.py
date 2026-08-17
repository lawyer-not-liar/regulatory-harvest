"""Conversion from untrusted analysis drafts to canonical evidence artifacts."""

from pydantic import Field

from regulatory_harvest.models import (
    AttorneyBrief,
    CitationSpan,
    Claim,
    ClaimKind,
    Finding,
    Gap,
    ResearchIssue,
    ReviewItem,
    SourceRecord,
    SupportStatus,
)
from regulatory_harvest.models.base import StrictModel
from regulatory_harvest.models.enums import REQUIRED_ISSUE_CATEGORIES, IssueCategory
from regulatory_harvest.storage import sha256_digest
from regulatory_harvest.validation import check_claim_support, resolve_quote

from .drafts import AnalysisDraft, ProposedCitation


class AnalysisBuildResult(StrictModel):
    issues: list[ResearchIssue] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    citations: list[CitationSpan] = Field(default_factory=list)
    gaps: list[Gap] = Field(default_factory=list)
    review_items: list[ReviewItem] = Field(default_factory=list)
    brief: AttorneyBrief | None = None


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


def _gap_id(
    code: str,
    message: str,
    category: IssueCategory,
    jurisdiction: str | None,
    source_ids: list[str],
    presentation_role: str | None = None,
) -> str:
    identity = "\0".join(
        [code, message, category.value, presentation_role or "", jurisdiction or "", *source_ids]
    )
    return f"gap_{sha256_digest(identity.encode())[:24]}"


_COVERAGE_GAP_MESSAGES = {
    IssueCategory.STATUS: "The retained source set did not establish legal status.",
    IssueCategory.SCOPE: "The retained source set did not establish scope and applicability.",
    IssueCategory.REQUIREMENTS: "The retained source set did not establish legal requirements.",
    IssueCategory.ENFORCEMENT: "The retained source set did not establish enforcement or remedies.",
    IssueCategory.DEADLINES: (
        "The retained source set did not establish deadlines or transition timing."
    ),
    IssueCategory.IMPLEMENTATION: (
        "The retained source set did not establish implementation implications or the client "
        "facts needed to apply them."
    ),
}


def ensure_coverage_gaps(
    issues: list[ResearchIssue], findings: list[Finding], gaps: list[Gap]
) -> list[Gap]:
    """Return gaps that satisfy every required attorney briefing dimension."""
    completed = list(gaps)
    category_by_issue_id = {issue.issue_id: issue.category for issue in issues}
    supported_categories = {
        category_by_issue_id[finding.issue_id]
        for finding in findings
        if finding.issue_id in category_by_issue_id
        and any(
            claim.kind is ClaimKind.SOURCE_SUPPORTED and claim.citation_ids
            for claim in finding.claims
        )
    }
    gap_categories = {gap.category for gap in completed}
    for category in REQUIRED_ISSUE_CATEGORIES:
        if category in supported_categories or category in gap_categories:
            continue
        code = f"COVERAGE_{category.value.upper()}_NOT_ESTABLISHED"
        message = _COVERAGE_GAP_MESSAGES[category]
        completed.append(
            Gap(
                gap_id=_gap_id(code, message, category, None, []),
                code=code,
                message=message,
                category=category,
            )
        )
    return completed


def build_analysis(draft: AnalysisDraft, sources: list[SourceRecord]) -> AnalysisBuildResult:
    """Resolve model-proposed evidence without trusting offsets or confidence."""
    source_by_id = {source.source_id: source for source in sources}
    issues = [
        ResearchIssue(
            issue_id=issue.issue_id,
            title=issue.title,
            description=issue.description,
            jurisdictions=issue.jurisdictions,
            category=issue.category,
            presentation_role=issue.presentation_role,
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
                enforcement_roles=draft_claim.enforcement_roles,
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

    gaps = [
        Gap(
            gap_id=_gap_id(
                gap.code,
                gap.message,
                gap.category,
                gap.jurisdiction,
                gap.source_ids,
                gap.presentation_role.value if gap.presentation_role is not None else None,
            ),
            code=gap.code,
            message=gap.message,
            category=gap.category,
            presentation_role=gap.presentation_role,
            jurisdiction=gap.jurisdiction,
            source_ids=gap.source_ids,
        )
        for gap in draft.gaps
    ]
    gaps = ensure_coverage_gaps(issues, findings, gaps)

    return AnalysisBuildResult(
        issues=issues,
        findings=findings,
        citations=citations,
        gaps=gaps,
        review_items=review_items,
        brief=draft.brief,
    )
