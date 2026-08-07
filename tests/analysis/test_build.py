from datetime import UTC, datetime

from regulatory_harvest.analysis import (
    AnalysisDraft,
    DraftClaim,
    DraftFinding,
    DraftIssue,
    ProposedCitation,
    build_analysis,
)
from regulatory_harvest.models import ClaimKind, Severity, SourceRecord, SupportStatus
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
