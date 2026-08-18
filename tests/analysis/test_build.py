from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from regulatory_harvest.analysis import (
    AnalysisDraft,
    DraftClaim,
    DraftFinding,
    DraftGap,
    DraftIssue,
    ProposedCitation,
    build_analysis,
)
from regulatory_harvest.models import (
    AttorneyBrief,
    BriefBlock,
    BriefBlockKind,
    BriefBlockPurpose,
    BriefSection,
    BriefSectionRole,
    BriefStructureProfile,
    ClaimKind,
    IssueCategory,
    PresentationRole,
    Severity,
    SourceRecord,
    SupportStatus,
)
from regulatory_harvest.storage import sha256_digest

TEXT = "A controller must document risks. A processor must document risks."


def _source() -> SourceRecord:
    return SourceRecord(
        source_id="src_rule",
        origin="rule.txt",
        display_name="Example Rule",
        retrieved_at=datetime(2026, 8, 5, tzinfo=UTC),
        content_hash=sha256_digest(TEXT.encode()),
        media_type="text/plain",
        normalized_text=TEXT,
        jurisdiction="US",
    )


def _draft(proposed: ProposedCitation) -> AnalysisDraft:
    return AnalysisDraft(
        issues=[
            DraftIssue(
                issue_id="issue-1",
                title="Documentation",
                description="Whether documentation is required.",
                jurisdictions=["US"],
                category="requirements",
            )
        ],
        findings=[
            DraftFinding(
                finding_id="finding-1",
                issue_id="issue-1",
                title="Document risks",
                jurisdiction="US",
                authority="Example Rule",
                severity=Severity.MEDIUM,
                practical_implication="Maintain written records.",
                claims=[
                    DraftClaim(
                        claim_id="claim-1",
                        text="A controller must document risks.",
                        kind=ClaimKind.SOURCE_SUPPORTED,
                        proposed_citations=[proposed],
                    )
                ],
            )
        ],
    )


def test_build_resolves_model_quote_in_trusted_core() -> None:
    """Trusting model offsets instead would make exact core resolution unnecessary."""
    result = build_analysis(
        _draft(
            ProposedCitation(
                source_id="src_rule",
                quote="A controller must document risks.",
            )
        ),
        [_source()],
    )

    assert len(result.citations) == 1
    citation = result.citations[0]
    assert citation.start_char == 0
    assert citation.end_char == 33
    assert citation.quote == "A controller must document risks."
    claim = result.findings[0].claims[0]
    assert claim.citation_ids == [citation.citation_id]
    assert claim.support_status is SupportStatus.SUPPORTED
    assert result.review_items == []


def test_build_preserves_issue_category_for_predictable_reporting() -> None:
    """Discarding the category would collapse the attorney briefing back into a flat list."""
    result = build_analysis(
        _draft(
            ProposedCitation(
                source_id="src_rule",
                quote="A controller must document risks.",
            )
        ),
        [_source()],
    )

    assert result.issues[0].category.value == "requirements"


def test_build_preserves_issue_and_gap_presentation_roles() -> None:
    """Losing roles would collapse findings back into parent-category buckets."""
    draft = _draft(
        ProposedCitation(
            source_id="src_rule",
            quote="A controller must document risks.",
        )
    )
    draft.issues[0].presentation_role = PresentationRole.REQUIREMENT
    draft.gaps = [
        DraftGap(
            code="SCOPE_ACTIVITY_UNKNOWN",
            message="Covered activities were not established.",
            category=IssueCategory.SCOPE,
            presentation_role=PresentationRole.COVERED_ACTIVITIES,
        )
    ]

    result = build_analysis(draft, [_source()])

    assert result.issues[0].presentation_role is PresentationRole.REQUIREMENT
    assert result.gaps[0].presentation_role is PresentationRole.COVERED_ACTIVITIES


def test_build_rejects_ambiguous_quote_without_occurrence() -> None:
    """Silently choosing a repeated phrase would cite the wrong actor."""
    result = build_analysis(
        _draft(ProposedCitation(source_id="src_rule", quote="must document risks")),
        [_source()],
    )

    assert result.citations == []
    assert result.findings[0].claims[0].citation_ids == []
    assert result.review_items[0].code == "PROPOSED_QUOTE_AMBIGUOUS"
    assert result.review_items[0].context["quote"] == "must document risks"


def test_build_rejects_quote_absent_from_source() -> None:
    """Fuzzy adoption of a fabricated quote would make this test fail."""
    result = build_analysis(
        _draft(ProposedCitation(source_id="src_rule", quote="must eliminate every risk")),
        [_source()],
    )
    assert result.citations == []
    assert result.review_items[0].code == "PROPOSED_QUOTE_NOT_FOUND"


def test_build_rejects_unknown_source_identifier() -> None:
    """Creating citations to absent sources would break bundle closure."""
    result = build_analysis(
        _draft(ProposedCitation(source_id="src_missing", quote="must document risks")),
        [_source()],
    )
    assert result.citations == []
    assert result.review_items[0].code == "PROPOSED_SOURCE_MISSING"


def test_build_preserves_uncited_analysis_claim() -> None:
    """Forcing analytical synthesis into a fake source citation would be misleading."""
    draft = _draft(ProposedCitation(source_id="src_rule", quote="must document risks"))
    draft.findings[0].claims = [
        DraftClaim(
            claim_id="claim-analysis",
            text="Counsel should prioritize a documentation workstream.",
            kind=ClaimKind.ANALYSIS,
        )
    ]
    result = build_analysis(draft, [_source()])
    claim = result.findings[0].claims[0]
    assert claim.kind is ClaimKind.ANALYSIS
    assert claim.citation_ids == []
    assert result.review_items == []


def test_build_converts_agent_research_gap_to_stable_bundle_gap() -> None:
    """Leaving search and currentness gaps outside the bundle would break the audit trail."""
    draft = _draft(ProposedCitation(source_id="src_rule", quote="must document risks"))
    draft.gaps = [
        DraftGap(
            code="AUTHORITY_CURRENTNESS_UNVERIFIED",
            message="The official historical register was unavailable.",
            category=IssueCategory.STATUS,
            jurisdiction="US",
            source_ids=["src_rule"],
        )
    ]

    first = build_analysis(draft, [_source()])
    repeated = build_analysis(draft, [_source()])

    assert first.gaps == repeated.gaps
    assert first.gaps[0].gap_id.startswith("gap_")
    assert first.gaps[0].code == "AUTHORITY_CURRENTNESS_UNVERIFIED"
    assert first.gaps[0].category is IssueCategory.STATUS
    assert first.gaps[0].source_ids == ["src_rule"]


def test_build_adds_plain_language_gaps_for_uncovered_dimensions() -> None:
    """Omitted dimensions must become explicit gaps instead of empty report sections."""
    result = build_analysis(
        _draft(
            ProposedCitation(
                source_id="src_rule",
                quote="A controller must document risks.",
            )
        ),
        [_source()],
    )

    gaps_by_category = {gap.category: gap for gap in result.gaps}
    assert set(gaps_by_category) == {
        IssueCategory.STATUS,
        IssueCategory.SCOPE,
        IssueCategory.ENFORCEMENT,
        IssueCategory.DEADLINES,
        IssueCategory.IMPLEMENTATION,
    }
    assert gaps_by_category[IssueCategory.STATUS].code == "COVERAGE_STATUS_NOT_ESTABLISHED"
    assert gaps_by_category[IssueCategory.STATUS].message == (
        "The retained source set did not establish legal status."
    )


def test_build_does_not_duplicate_an_explicit_dimension_gap() -> None:
    """A researched negative result should not be obscured by a generic duplicate."""
    draft = _draft(
        ProposedCitation(
            source_id="src_rule",
            quote="A controller must document risks.",
        )
    )
    draft.gaps = [
        DraftGap(
            code="SCOPE_THRESHOLD_NOT_ESTABLISHED",
            message="The supplied excerpt does not state the coverage threshold.",
            category=IssueCategory.SCOPE,
            jurisdiction="US",
            source_ids=["src_rule"],
        )
    ]

    result = build_analysis(draft, [_source()])

    scope_gaps = [gap for gap in result.gaps if gap.category is IssueCategory.SCOPE]
    assert len(scope_gaps) == 1
    assert scope_gaps[0].code == "SCOPE_THRESHOLD_NOT_ESTABLISHED"


def test_build_preserves_adaptive_attorney_brief() -> None:
    """Discarding the authored brief would force the fixed renderer to invent structure."""
    draft = _draft(
        ProposedCitation(
            source_id="src_rule",
            quote="A controller must document risks.",
        )
    )
    draft.brief = AttorneyBrief(
        structure_profile=BriefStructureProfile.REGULATORY_WALK_V1,
        executive_summary=[
            BriefBlock(
                kind=BriefBlockKind.PARAGRAPH,
                purpose=BriefBlockPurpose.LEGAL_ANALYSIS,
                text="Controllers must document risks.",
                finding_ids=["finding-1"],
            )
        ],
        sections=[
            BriefSection(
                section_id="documentation",
                title="Documentation Requirements",
                role=BriefSectionRole.KEY_REQUIREMENTS,
                blocks=[
                    BriefBlock(
                        kind=BriefBlockKind.PARAGRAPH,
                        purpose=BriefBlockPurpose.APPLICATION,
                        text="Maintain a written record.",
                        finding_ids=["finding-1"],
                    )
                ],
            )
        ],
    )

    result = build_analysis(draft, [_source()])

    assert result.brief == draft.brief


def test_analysis_draft_rejects_an_authored_brief_without_structure_profile() -> None:
    """New host-authored briefs must opt into the enforceable report contract."""
    brief = AttorneyBrief(
        executive_summary=[
            BriefBlock(
                kind=BriefBlockKind.PARAGRAPH,
                purpose=BriefBlockPurpose.LEGAL_ANALYSIS,
                text="Controllers must document risks.",
                finding_ids=["finding-1"],
            )
        ],
        sections=[
            BriefSection(
                section_id="documentation",
                title="Documentation Requirements",
                blocks=[
                    BriefBlock(
                        kind=BriefBlockKind.PARAGRAPH,
                        purpose=BriefBlockPurpose.APPLICATION,
                        text="Maintain a written record.",
                        finding_ids=["finding-1"],
                    )
                ],
            )
        ],
    )

    with pytest.raises(ValidationError, match="structure_profile"):
        AnalysisDraft.model_validate(
            {
                "issues": [],
                "findings": [],
                "brief": brief.model_dump(mode="json"),
            }
        )
