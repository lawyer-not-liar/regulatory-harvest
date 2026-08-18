from datetime import UTC, date, datetime

import pytest
from pydantic import ValidationError

from regulatory_harvest.analysis.report import render_audit_markdown, render_markdown
from regulatory_harvest.models import (
    DISCLAIMER,
    AttorneyBrief,
    BriefBlock,
    BriefBlockKind,
    BriefBlockPurpose,
    BriefItem,
    BriefSection,
    BriefSectionRole,
    BriefStructureProfile,
    BriefSubsection,
    BriefTableRow,
    CitationSpan,
    Claim,
    ClaimKind,
    Finding,
    Gap,
    IssueCategory,
    ResearchBundle,
    ResearchIssue,
    ResearchRequest,
    ReviewItem,
    RunManifest,
    Severity,
    SourceFailure,
    SourceInput,
    SourceQuality,
    SourceRecord,
    SourceRole,
)


def _bundle() -> ResearchBundle:
    now = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)
    return ResearchBundle(
        generator_version="0.1.0",
        request=ResearchRequest(
            request_id="demo",
            question="What does *Rule* require?",
            matter_title="Example Regulation",
            jurisdictions=["US"],
            as_of=date(2026, 8, 5),
            source_inputs=[SourceInput(location="/Users/private/matter/rule.txt")],
        ),
        manifest=RunManifest(
            run_id="demo",
            generator_version="0.1.0",
            created_at=now,
            updated_at=now,
            provider_metadata={"model_provider": "example", "api_key": "secret-value"},
        ),
        sources=[
            SourceRecord(
                source_id="src_failed",
                origin="/Users/private/matter/rule.txt",
                display_name="*Draft* Rule",
                retrieved_at=now,
                media_type="text/plain",
                source_quality=SourceQuality.UNUSABLE,
                fetch_status="failed",
                error=SourceFailure(
                    category="file_error",
                    message="/Users/private/matter/rule.txt: secret-value",
                ),
            )
        ],
        gaps=[
            Gap(
                gap_id="gap-1",
                code="SOURCE_RETRIEVAL_FAILED",
                message="The requested source could not be read.",
                jurisdiction="US",
                source_ids=["src_failed"],
            )
        ],
        review_items=[
            ReviewItem(
                review_id="review-1",
                code="VERIFY_CURRENTNESS",
                message="Confirm the rule remains current.",
            )
        ],
    )


def _attorney_bundle(*, with_brief: bool = True) -> ResearchBundle:
    bundle = _bundle()
    text = "The rule is effective. A controller must document material risks."
    source = SourceRecord(
        source_id="src_rule",
        origin="captures/rule.txt",
        canonical_url="https://example.org/rule?view=official#section-4",
        display_name="Example Rule",
        retrieved_at=datetime(2026, 8, 5, 12, 0, tzinfo=UTC),
        content_hash="b" * 64,
        media_type="text/plain",
        normalized_text=text,
        title="Example Rule",
        publisher="Example Legislature",
        jurisdiction="US",
        authority_type="enacted regulation",
        citation="Example Rule section 4",
        effective_date="2026-01-01",
        supersession="No later amendment identified as of 2026-08-05.",
        language="en",
        source_quality=SourceQuality.PRIMARY,
        source_role=SourceRole.OFFICIAL_PRIMARY,
    )
    citation = CitationSpan(
        citation_id="cite_rule",
        source_id=source.source_id,
        start_char=23,
        end_char=len(text),
        quote="A controller must document material risks.",
    )
    issue = ResearchIssue(
        issue_id="issue-requirements",
        title="Operative Requirements",
        description="The retained authority establishes a documentation obligation.",
        jurisdictions=["US"],
        category="requirements",
    )
    finding = Finding(
        finding_id="finding-documentation",
        issue_id=issue.issue_id,
        title="Controllers must document material risks",
        jurisdiction="US",
        authority="Example Rule section 4",
        severity=Severity.HIGH,
        practical_implication="Create and approve a risk record before deployment.",
        claims=[
            Claim(
                claim_id="claim-documentation",
                text="A controller must document material risks.",
                kind=ClaimKind.SOURCE_SUPPORTED,
                citation_ids=[citation.citation_id],
            )
        ],
    )
    bundle.sources = [source]
    bundle.issues = [issue]
    bundle.findings = [finding]
    bundle.citations = [citation]
    bundle.gaps = [
        Gap(
            gap_id=f"gap-{category.value}",
            code=code,
            message=message,
            category=category,
            jurisdiction="US",
            source_ids=[source.source_id],
        )
        for category, code, message in (
            (
                IssueCategory.STATUS,
                "AUTHORITY_CURRENTNESS_UNVERIFIED",
                "No later amendment history was independently verified.",
            ),
            (
                IssueCategory.SCOPE,
                "SCOPE_THRESHOLD_NOT_ESTABLISHED",
                "The retained excerpt does not establish the coverage threshold.",
            ),
            (
                IssueCategory.ENFORCEMENT,
                "ENFORCEMENT_NOT_ESTABLISHED",
                "The retained excerpt does not establish enforcement or remedies.",
            ),
            (
                IssueCategory.DEADLINES,
                "DEADLINES_NOT_ESTABLISHED",
                "The retained excerpt does not establish transition deadlines.",
            ),
            (
                IssueCategory.IMPLEMENTATION,
                "FACTUAL_CONTEXT_REQUIRED",
                "The client's controller posture has not been confirmed.",
            ),
        )
    ]
    if with_brief:
        bundle.brief = AttorneyBrief(
            executive_summary=[
                BriefBlock(
                    kind=BriefBlockKind.PARAGRAPH,
                    purpose=BriefBlockPurpose.LEGAL_ANALYSIS,
                    text=(
                        "The retained authority requires covered controllers to maintain "
                        "documented risk controls."
                    ),
                    finding_ids=[finding.finding_id],
                )
            ],
            sections=[
                BriefSection(
                    section_id="legal-framework",
                    title="Legal Status and Interpretive Framework",
                    blocks=[
                        BriefBlock(
                            kind=BriefBlockKind.PARAGRAPH,
                            purpose=BriefBlockPurpose.LEGAL_ANALYSIS,
                            text="The operative text frames documentation as a legal duty.",
                            finding_ids=[finding.finding_id],
                        )
                    ],
                ),
                BriefSection(
                    section_id="detailed-requirements",
                    title="Detailed Documentation Requirements",
                    subsections=[
                        BriefSubsection(
                            subsection_id="required-record",
                            title="Required Record",
                            blocks=[
                                BriefBlock(
                                    kind=BriefBlockKind.BULLET_LIST,
                                    purpose=BriefBlockPurpose.LEGAL_ANALYSIS,
                                    items=[
                                        BriefItem(
                                            text="Document the material deployment risks.",
                                            finding_ids=[finding.finding_id],
                                        )
                                    ],
                                ),
                                BriefBlock(
                                    kind=BriefBlockKind.NUMBERED_LIST,
                                    purpose=BriefBlockPurpose.APPLICATION,
                                    items=[
                                        BriefItem(
                                            text="Create the risk record before deployment.",
                                            finding_ids=[finding.finding_id],
                                        ),
                                        BriefItem(text="Obtain the required internal approval."),
                                    ],
                                ),
                            ],
                        )
                    ],
                ),
                BriefSection(
                    section_id="implementation",
                    title="Implementation Considerations",
                    blocks=[
                        BriefBlock(
                            kind=BriefBlockKind.TABLE,
                            purpose=BriefBlockPurpose.APPLICATION,
                            columns=["Action", "Owner"],
                            rows=[
                                BriefTableRow(
                                    cells=["Approve the risk record", "Legal"],
                                    finding_ids=[finding.finding_id],
                                )
                            ],
                        )
                    ],
                ),
            ],
        )
    return bundle


@pytest.mark.parametrize(
    ("model", "payload"),
    [
        (
            BriefBlock,
            {
                "kind": "paragraph",
                "purpose": "legal_analysis",
                "text": "The rule states a qualified duty.",
                "atom_ids": ["atom-z", "atom-a"],
                "relationship_ids": ["relationship-z", "relationship-a"],
            },
        ),
        (
            BriefItem,
            {
                "text": "The rule states a qualified duty.",
                "atom_ids": ["atom-z", "atom-a"],
                "relationship_ids": ["relationship-z", "relationship-a"],
            },
        ),
        (
            BriefTableRow,
            {
                "cells": ["Duty", "Qualified"],
                "atom_ids": ["atom-z", "atom-a"],
                "relationship_ids": ["relationship-z", "relationship-a"],
            },
        ),
    ],
)
def test_visible_brief_bindings_are_sorted_and_unique(
    model: type[BriefBlock] | type[BriefItem] | type[BriefTableRow],
    payload: dict[str, object],
) -> None:
    visible_unit = model.model_validate(payload)

    assert visible_unit.atom_ids == ["atom-a", "atom-z"]
    assert visible_unit.relationship_ids == ["relationship-a", "relationship-z"]


@pytest.mark.parametrize("field", ["atom_ids", "relationship_ids"])
@pytest.mark.parametrize(
    ("model", "payload"),
    [
        (
            BriefBlock,
            {
                "kind": "paragraph",
                "purpose": "legal_analysis",
                "text": "The rule states a qualified duty.",
            },
        ),
        (BriefItem, {"text": "The rule states a qualified duty."}),
        (BriefTableRow, {"cells": ["Duty", "Qualified"]}),
    ],
)
def test_visible_brief_bindings_reject_duplicates(
    model: type[BriefBlock] | type[BriefItem] | type[BriefTableRow],
    payload: dict[str, object],
    field: str,
) -> None:
    payload = dict(payload)
    payload[field] = ["same-id", "same-id"]

    with pytest.raises(ValidationError, match="identifiers must be unique"):
        model.model_validate(payload)


def test_visible_brief_bindings_revalidate_model_copy_values() -> None:
    item = BriefItem(text="The rule states a qualified duty.")
    bypassed = item.model_copy(update={"atom_ids": ["same-id", "same-id"]})

    with pytest.raises(ValidationError, match="identifiers must be unique"):
        BriefItem.model_validate(bypassed)


@pytest.mark.parametrize("field", ["atom_ids", "relationship_ids"])
@pytest.mark.parametrize(
    "payload",
    [
        {
            "kind": "bullet_list",
            "purpose": "legal_analysis",
            "items": [{"text": "The rule states a qualified duty."}],
        },
        {
            "kind": "table",
            "purpose": "legal_analysis",
            "columns": ["Duty", "Qualification"],
            "rows": [{"cells": ["Maintain a register", "Unless exempt"]}],
        },
    ],
)
def test_list_and_table_container_bindings_belong_on_items_or_rows(
    payload: dict[str, object], field: str
) -> None:
    payload = dict(payload)
    payload[field] = ["container-binding"]

    with pytest.raises(ValidationError, match="evidence belongs on individual"):
        BriefBlock.model_validate(payload)


def test_report_is_summary_first_and_uses_adaptive_legacy_order() -> None:
    """Restoring a fixed skeleton would bury the answer and recreate empty sections."""
    report = render_markdown(_attorney_bundle())
    headings = (
        "# Example Regulation",
        "## Executive Summary",
        "## Legal Status and Interpretive Framework",
        "## Detailed Documentation Requirements",
        "### Required Record",
        "## Implementation Considerations",
        "## Limitations and Open Questions",
        "## Sources Consulted",
    )

    lines = report.splitlines()
    positions = [lines.index(heading) for heading in headings]

    assert positions == sorted(positions)
    assert "## Priority and Posture" not in report
    assert "## Bottom Line" not in report
    assert "## Scope & Applicability" not in report
    assert "## Enforcement & Remedies" not in report
    assert "The retained source set did not establish this subsection." not in report
    assert report.count("## Limitations and Open Questions") == 1


def test_named_report_and_audit_use_the_regulation_title() -> None:
    """The regulation name, not a generic document label, must lead both artifacts."""
    bundle = _attorney_bundle()

    assert render_markdown(bundle).startswith("# Example Regulation\n")
    assert render_audit_markdown(bundle).startswith(
        "# Example Regulation: Evidence and Validation Audit\n"
    )


def test_unprofiled_report_without_a_title_retains_the_generic_fallback() -> None:
    """Old bundles without the profile or optional title must still render."""
    bundle = _attorney_bundle()
    bundle.request.matter_title = None

    assert render_markdown(bundle).startswith("# Attorney research briefing\n")


def test_report_renders_the_profiled_regulatory_walk_in_canonical_order() -> None:
    """Attorneys must be able to find duties, consequences, and implementation quickly."""
    bundle = _attorney_bundle()
    assert bundle.brief is not None
    bundle.brief.structure_profile = BriefStructureProfile.REGULATORY_WALK_V1
    bundle.brief.sections = [
        BriefSection(
            section_id="key-requirements",
            title="Key Requirements",
            role=BriefSectionRole.KEY_REQUIREMENTS,
            blocks=bundle.brief.sections[0].blocks,
        ),
        BriefSection(
            section_id="penalties-and-enforcement",
            title="Penalties and Enforcement",
            role=BriefSectionRole.PENALTIES_ENFORCEMENT,
            blocks=[
                BriefBlock(
                    kind=BriefBlockKind.PARAGRAPH,
                    purpose=BriefBlockPurpose.LIMITATION,
                    text=(
                        "Not established: The retained evidence does not establish "
                        "penalties or enforcement mechanisms."
                    ),
                )
            ],
        ),
        BriefSection(
            section_id="implementation-workplan",
            title="Implementation Workplan",
            role=BriefSectionRole.IMPLEMENTATION,
            blocks=bundle.brief.sections[-1].blocks,
        ),
    ]

    report = render_markdown(bundle)
    headings = [
        "## Key Requirements",
        "## Penalties and Enforcement",
        "## Implementation Workplan",
    ]
    positions = [report.index(heading) for heading in headings]

    assert positions == sorted(positions)
    assert "Not established:" in report
    assert "## Bottom Line" not in report


def test_report_frontmatter_is_compact_and_excludes_process_metadata() -> None:
    """Research machinery before the summary would repeat the failed reviewer experience."""
    bundle = _attorney_bundle()
    report = render_markdown(bundle)
    frontmatter = report.split("## Executive Summary", maxsplit=1)[0]

    assert "**Jurisdiction:** US" in frontmatter
    assert "**As of:** 2026-08-05" in frontmatter
    assert "**Research scope:** Closed universe of supplied materials" in frontmatter
    assert "**Principal authority:** Example Rule section 4" in frontmatter
    assert (
        "**Currentness:** Not independently verified through 2026-08-05; retained cited primary "
        "authority: Example Rule section 4; attorney verification required"
        in frontmatter
    )
    assert "**Operative date:** 2026-01-01" in frontmatter
    assert bundle.request.question not in report
    assert "Deterministic validation" not in report
    assert "Research priority" not in report
    assert "Client risk" not in report


def test_report_renders_paragraph_lists_and_table_with_source_labels() -> None:
    """Flattening structured blocks would prevent the matter-specific legacy grammar."""
    report = render_markdown(_attorney_bundle())
    source_link = "[S1](https://example.org/rule)"

    assert (
        "The retained authority requires covered controllers to maintain documented "
        f"risk controls. {source_link}"
    ) in report
    assert f"- Document the material deployment risks. {source_link}" in report
    assert f"1. Create the risk record before deployment. {source_link}" in report
    assert "2. Obtain the required internal approval." in report
    assert "| Action | Owner |" in report
    assert f"| Approve the risk record | Legal {source_link} |" in report


def test_profiled_report_markers_come_only_from_bound_claims() -> None:
    """A claim about one authority must not inherit every source used by its finding."""
    bundle = _attorney_bundle()
    assert bundle.brief is not None
    bundle.brief.structure_profile = BriefStructureProfile.REGULATORY_WALK_V1
    summary = bundle.brief.executive_summary[0]
    summary.text = bundle.findings[0].claims[0].text
    summary.claim_ids = [bundle.findings[0].claims[0].claim_id]

    second_text = "The agency may impose a civil penalty after a violation."
    second_source = bundle.sources[0].model_copy(
        update={
            "source_id": "src_enforcement",
            "origin": "captures/enforcement.txt",
            "canonical_url": "https://example.org/enforcement",
            "display_name": "Enforcement Rule",
            "normalized_text": second_text,
            "content_hash": "c" * 64,
            "citation": "Enforcement Rule section 9",
        }
    )
    second_citation = CitationSpan(
        citation_id="cite_enforcement",
        source_id=second_source.source_id,
        start_char=0,
        end_char=len(second_text),
        quote=second_text,
    )
    bundle.sources.append(second_source)
    bundle.citations.append(second_citation)
    bundle.findings[0].claims.append(
        Claim(
            claim_id="claim-enforcement",
            text=second_text,
            kind=ClaimKind.SOURCE_SUPPORTED,
            citation_ids=[second_citation.citation_id],
        )
    )

    summary_line = next(
        line
        for line in render_markdown(bundle).splitlines()
        if line.startswith("A controller must document material risks")
    )

    assert "[S1](https://example.org/rule)" in summary_line
    assert "S2" not in summary_line


def test_report_consolidates_plain_language_gaps_without_machine_codes() -> None:
    """Repeating coded gaps throughout the report would expose internal scaffolding."""
    report = render_markdown(_attorney_bundle())

    for gap in _attorney_bundle().gaps:
        assert report.count(gap.message) == 1
        assert gap.code not in report


def test_report_lists_only_nonempty_source_groups_concisely() -> None:
    """Empty source taxonomies would add the same visible incompleteness as empty issues."""
    report = render_markdown(_attorney_bundle())

    assert "### Official and Primary Sources" in report
    assert "### Secondary Sources" not in report
    assert "### Commentary and Analysis" not in report
    assert "### Unclassified Sources" not in report
    assert "- **S1. Example Rule**" in report
    assert "Example Rule section 4" in report
    assert "[Official source](https://example.org/rule)" in report
    assert "Retained origin" not in report
    assert "Source mode" not in report


def test_audit_contains_evidence_validation_and_run_detail_removed_from_report() -> None:
    """Moving the appendix must preserve the complete deterministic audit trail."""
    bundle = _attorney_bundle()
    report = render_markdown(bundle)
    audit = render_audit_markdown(bundle)
    quote = "A controller must document material risks."

    assert quote not in report
    assert f"> {quote}" in audit
    assert bundle.request.question not in report
    assert "What does \\*Rule\\* require?" in audit
    assert "AUTHORITY_CURRENTNESS_UNVERIFIED" not in report
    assert "AUTHORITY_CURRENTNESS_UNVERIFIED" in audit
    assert "### Deterministic Validation" in audit
    assert "### Methodology and Run Metadata" in audit
    assert "`demo`" in audit
    assert DISCLAIMER in report
    assert DISCLAIMER in audit


def test_original_language_evidence_stays_out_of_english_attorney_report() -> None:
    """Rendering the verified quotation as explanation would repeat the French-output defect."""
    bundle = _attorney_bundle()
    source = bundle.sources[0]
    source.normalized_text = "Le responsable doit documenter les risques matériels."
    source.language = "fr"
    source.content_hash = "c" * 64
    quote = source.normalized_text
    bundle.citations[0].start_char = 0
    bundle.citations[0].end_char = len(quote)
    bundle.citations[0].quote = quote
    bundle.findings[0].claims[0].text = quote

    report = render_markdown(bundle)
    audit = render_audit_markdown(bundle)

    assert "documented risk controls" in report
    assert quote not in report
    assert f"> {quote}" in audit
    assert "Language: fr" in audit


def test_old_bundle_fallback_uses_issue_order_without_fixed_empty_sections() -> None:
    """Backward compatibility must not resurrect the rejected universal outline."""
    bundle = _attorney_bundle(with_brief=False)

    report = render_markdown(bundle)

    assert "## Executive Summary" in report
    assert "## Operative Requirements" in report
    assert "### Controllers must document material risks" in report
    assert "Create and approve a risk record before deployment." in report
    assert "## Scope & Applicability" not in report
    assert "## Enforcement & Remedies" not in report
    assert "## Evidence and Validation Appendix" not in report


def test_principal_authority_requires_cited_primary_source() -> None:
    """Unknown or tangential material must not be promoted into compact frontmatter."""
    bundle = _attorney_bundle()
    bundle.sources.append(
        bundle.sources[0].model_copy(
            update={
                "source_id": "src_tangential",
                "origin": "captures/tangential.txt",
                "canonical_url": "https://example.org/tangential",
                "display_name": "Tangential Statute",
                "title": "Tangential Statute",
                "citation": "Tangential Statute section 1",
            }
        )
    )

    report = render_markdown(bundle)
    frontmatter = report.split("## Executive Summary", maxsplit=1)[0]

    assert "Example Rule section 4" in frontmatter
    assert "Tangential Statute section 1" not in frontmatter
    assert "- **S2. Tangential Statute**" in report

    bundle.sources[0].source_quality = SourceQuality.UNKNOWN
    report = render_markdown(bundle)
    frontmatter = report.split("## Executive Summary", maxsplit=1)[0]
    assert "**Principal authority:** Not established" in frontmatter


def test_web_scope_uses_a_neutral_public_research_label() -> None:
    bundle = _attorney_bundle()
    bundle.request.source_mode = "web"

    frontmatter = render_markdown(bundle).split("## Executive Summary", maxsplit=1)[0]

    assert "**Research scope:** Public-source research" in frontmatter
    assert "Verified public-source research" not in frontmatter


def test_secondary_public_link_is_not_labeled_official() -> None:
    bundle = _attorney_bundle()
    bundle.sources[0].source_role = SourceRole.SECONDARY
    bundle.sources[0].source_quality = SourceQuality.SECONDARY

    report = render_markdown(bundle)

    assert "[Source](https://example.org/rule)" in report
    assert "[Official source](https://example.org/rule)" not in report


def test_status_finding_does_not_become_a_currentness_assurance() -> None:
    """A statement of effectiveness does not prove the absence of later changes."""
    bundle = _attorney_bundle()
    status_quote = "The rule is effective."
    status_citation = CitationSpan(
        citation_id="cite-status",
        source_id="src_rule",
        start_char=0,
        end_char=len(status_quote),
        quote=status_quote,
    )
    status_issue = ResearchIssue(
        issue_id="issue-status",
        title="Status of the Rule",
        jurisdictions=["US"],
        category=IssueCategory.STATUS,
    )
    status_finding = Finding(
        finding_id="finding-status",
        issue_id=status_issue.issue_id,
        title="The retained text states an effective rule",
        jurisdiction="US",
        authority="Example Rule",
        severity=Severity.INFO,
        practical_implication="Verify amendment history before relying on currentness.",
        claims=[
            Claim(
                claim_id="claim-status",
                text=status_quote,
                kind=ClaimKind.SOURCE_SUPPORTED,
                citation_ids=[status_citation.citation_id],
            )
        ],
    )
    bundle.issues.append(status_issue)
    bundle.findings.append(status_finding)
    bundle.citations.append(status_citation)
    bundle.gaps = [
        gap for gap in bundle.gaps if gap.category is not IssueCategory.STATUS
    ]
    bundle.sources[0].supersession = None
    assert bundle.brief is not None
    bundle.brief.executive_summary[0].finding_ids.append(status_finding.finding_id)

    report = render_markdown(bundle)

    assert (
        "**Currentness:** Not independently verified through 2026-08-05; retained cited primary "
        "authority: Example Rule section 4; attorney verification required"
        in report
    )
    assert "inoperative" not in report.casefold()


def test_status_and_dated_supersession_metadata_explain_recorded_currentness() -> None:
    """A positive label must identify its date, retained authority, and review boundary."""
    bundle = _attorney_bundle()
    status_quote = "The rule is effective."
    status_citation = CitationSpan(
        citation_id="cite-status-recorded",
        source_id="src_rule",
        start_char=0,
        end_char=len(status_quote),
        quote=status_quote,
    )
    status_issue = ResearchIssue(
        issue_id="issue-status-recorded",
        title="Status of the Rule",
        jurisdictions=["US"],
        category=IssueCategory.STATUS,
    )
    status_finding = Finding(
        finding_id="finding-status-recorded",
        issue_id=status_issue.issue_id,
        title="The rule is effective",
        jurisdiction="US",
        authority="Example Rule",
        severity=Severity.INFO,
        practical_implication="Confirm the retained amendment check before reliance.",
        claims=[
            Claim(
                claim_id="claim-status-recorded",
                text=status_quote,
                kind=ClaimKind.SOURCE_SUPPORTED,
                citation_ids=[status_citation.citation_id],
            )
        ],
    )
    bundle.issues.append(status_issue)
    bundle.findings.append(status_finding)
    bundle.citations.append(status_citation)
    bundle.gaps = [gap for gap in bundle.gaps if gap.category is not IssueCategory.STATUS]
    assert bundle.brief is not None
    bundle.brief.executive_summary[0].finding_ids.append(status_finding.finding_id)

    report = render_markdown(bundle)

    assert (
        "**Currentness:** Recorded in retained primary-source metadata through 2026-08-05; "
        "retained cited primary authority: Example Rule section 4; attorney verification "
        "required"
        in report
    )


def test_currentness_lists_all_cited_status_authorities_without_inventing_chronology() -> None:
    """Retrieval order must never be mislabeled as substantive authority chronology."""
    bundle = _attorney_bundle()
    source = bundle.sources[0]
    later_text = "The corrigendum corrects the retained rule."
    later_source = source.model_copy(
        update={
            "source_id": "src_corrigendum",
            "display_name": "Example Corrigendum",
            "title": "Example Corrigendum",
            "citation": "Example Corrigendum 2026",
            "retrieved_at": datetime(2026, 8, 5, 11, 0, tzinfo=UTC),
            "normalized_text": later_text,
            "content_hash": "c" * 64,
            "effective_date": "2026-02-01",
            "supersession": "Corrects Example Rule section 4.",
        }
    )
    status_quote = "The rule is effective."
    status_citation = CitationSpan(
        citation_id="cite-status-base",
        source_id=source.source_id,
        start_char=0,
        end_char=len(status_quote),
        quote=status_quote,
    )
    corrigendum_citation = CitationSpan(
        citation_id="cite-status-corrigendum",
        source_id=later_source.source_id,
        start_char=0,
        end_char=len(later_text),
        quote=later_text,
    )
    status_issue = ResearchIssue(
        issue_id="issue-status-chronology",
        title="Status chronology",
        jurisdictions=["US"],
        category=IssueCategory.STATUS,
    )
    status_finding = Finding(
        finding_id="finding-status-chronology",
        issue_id=status_issue.issue_id,
        title="The retained status record includes a corrigendum",
        jurisdiction="US",
        authority="Example Rule and Example Corrigendum",
        severity=Severity.INFO,
        practical_implication="Verify the complete corrected text before reliance.",
        claims=[
            Claim(
                claim_id="claim-status-chronology",
                text="The retained rule is effective and has a corrigendum.",
                kind=ClaimKind.SOURCE_SUPPORTED,
                citation_ids=[status_citation.citation_id, corrigendum_citation.citation_id],
            )
        ],
    )
    bundle.sources.append(later_source)
    bundle.citations.extend([status_citation, corrigendum_citation])
    bundle.issues.append(status_issue)
    bundle.findings.append(status_finding)
    bundle.gaps = [gap for gap in bundle.gaps if gap.category is not IssueCategory.STATUS]

    currentness = next(
        line for line in render_markdown(bundle).splitlines() if line.startswith("**Currentness:**")
    )

    assert (
        "retained cited primary authorities: Example Rule section 4; Example Corrigendum 2026"
        in currentness
    )
    assert "latest retained authority" not in currentness


def test_uncited_source_metadata_cannot_create_a_currentness_assurance() -> None:
    bundle = _attorney_bundle()
    bundle.issues[0].category = IssueCategory.STATUS
    bundle.gaps = [gap for gap in bundle.gaps if gap.category is not IssueCategory.STATUS]
    bundle.sources[0].supersession = None
    bundle.sources.append(
        bundle.sources[0].model_copy(
            update={
                "source_id": "src_uncited_status",
                "display_name": "Uncited Status Page",
                "citation": "Uncited Status Page",
                "canonical_url": "https://example.org/status",
                "supersession": "No later amendment identified as of 2026-08-05.",
            }
        )
    )

    report = render_markdown(bundle)

    assert "**Currentness:** Not independently verified through 2026-08-05" in report
    assert "Recorded in retained primary-source metadata" not in report


def test_currentness_does_not_name_an_uncited_primary_source_as_authority() -> None:
    """A retained file is not a report authority until a supported claim cites it."""
    bundle = _attorney_bundle()
    for finding in bundle.findings:
        finding.claims = []
    bundle.citations = []

    report = render_markdown(bundle)
    currentness = next(
        line for line in report.splitlines() if line.startswith("**Currentness:**")
    )

    assert "**Principal authority:** Not established" in report
    assert "Example Rule section 4" not in currentness
    assert "retained cited primary authority: not identified" in currentness


def test_renderers_escape_untrusted_text_and_hide_sensitive_local_details() -> None:
    """Neither artifact may execute injected markup or disclose paths and secrets."""
    bundle = _bundle()
    bundle.request.question = '<img src=x onerror="alert(1)">'
    bundle.gaps[0].message = '<script>alert("gap")</script>'
    bundle.gaps[0].code = "GAP` ## injected"

    report = render_markdown(bundle)
    audit = render_audit_markdown(bundle)

    assert "<script" not in report
    assert "&lt;script" in report
    assert "<img" not in audit
    assert "&lt;img" in audit
    assert "` ## injected" not in audit
    assert "GAP&#96; ## injected" in audit
    for artifact in (report, audit):
        assert "/Users/private" not in artifact
        assert "secret-value" not in artifact
        assert "rule.txt" in artifact


def test_renderers_redact_windows_paths_and_url_credentials() -> None:
    """Cross-platform source origins must not become disclosure channels."""
    bundle = _bundle()
    bundle.sources[0].origin = r"C:\Users\private\matter\rule.txt"
    windows_report = render_markdown(bundle)
    windows_audit = render_audit_markdown(bundle)
    bundle.sources[0].origin = (
        "https://user:secret@example.org/rule?X-Amz-Credential=hidden&view=public#private"
    )
    url_report = render_markdown(bundle)
    url_audit = render_audit_markdown(bundle)

    for artifact in (windows_report, windows_audit):
        assert "Users" not in artifact
        assert "rule.txt" in artifact
    for artifact in (url_report, url_audit):
        assert "user:secret" not in artifact
        assert "X-Amz-Credential=hidden" not in artifact
        assert "#private" not in artifact
        assert "https://example.org/rule" in artifact
        assert "view=public" not in artifact
