from datetime import UTC, date, datetime

import pytest
from pydantic import ValidationError

from regulatory_harvest.models import (
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
    PresentationRole,
    ResearchBundle,
    ResearchIssue,
    ResearchRequest,
    RunManifest,
    Severity,
    SourceInput,
    SourceRecord,
    SourceRole,
    StageName,
    StageRecord,
    StageStatus,
)


def _now() -> datetime:
    return datetime(2026, 8, 5, 12, 0, tzinfo=UTC)


def _request() -> ResearchRequest:
    return ResearchRequest(
        request_id="demo",
        question="What does the example rule require?",
        jurisdictions=["US"],
        as_of=date(2026, 8, 5),
        source_inputs=[SourceInput(location="example-rule.txt")],
    )


def _bundle() -> ResearchBundle:
    source = SourceRecord(
        source_id="src_example",
        origin="example-rule.txt",
        display_name="Example Rule",
        retrieved_at=_now(),
        content_hash="a" * 64,
        media_type="text/plain",
        normalized_text="A controller must document risks.",
    )
    citation = CitationSpan(
        citation_id="cite-1",
        source_id=source.source_id,
        start_char=13,
        end_char=32,
        quote="must document risks",
    )
    claim = Claim(
        claim_id="claim-1",
        text="The rule requires risk documentation.",
        kind=ClaimKind.SOURCE_SUPPORTED,
        citation_ids=[citation.citation_id],
    )
    finding = Finding(
        finding_id="finding-1",
        issue_id="issue-1",
        title="Risk documentation",
        jurisdiction="US",
        authority="Example Rule",
        severity=Severity.MEDIUM,
        practical_implication="Maintain written risk documentation.",
        claims=[claim],
    )
    manifest = RunManifest(
        run_id="demo",
        generator_version="0.1.0",
        created_at=_now(),
        updated_at=_now(),
        stages=[
            StageRecord(name=name, status=StageStatus.PENDING)
            for name in StageName
        ],
    )
    return ResearchBundle(
        generator_version="0.1.0",
        request=_request(),
        manifest=manifest,
        sources=[source],
        citations=[citation],
        findings=[finding],
    )


def test_request_rejects_empty_jurisdictions() -> None:
    """Removing the non-empty jurisdiction guard would make this test fail."""
    with pytest.raises(ValidationError):
        ResearchRequest(
            request_id="demo",
            question="What does the rule require?",
            jurisdictions=[],
            as_of=date(2026, 8, 5),
            source_inputs=[SourceInput(location="rule.txt")],
        )


@pytest.mark.parametrize("field", ["request_id", "question"])
def test_request_rejects_blank_required_text(field: str) -> None:
    """Removing whitespace stripping from required text would make this test fail."""
    values = _request().model_dump()
    values[field] = "   "
    with pytest.raises(ValidationError):
        ResearchRequest.model_validate(values)


def test_source_input_rejects_blank_location() -> None:
    """Allowing an unusable source location would make this test fail."""
    with pytest.raises(ValidationError):
        SourceInput(location="\t")


def test_source_input_accepts_public_canonical_url_for_local_capture() -> None:
    """A local evidence capture must retain the public authority it represents."""
    source = SourceInput(
        location="capture.txt",
        canonical_url="https://example.org/rules/current?view=official#section-2",
        language="ja",
    )

    assert source.canonical_url == "https://example.org/rules/current"
    assert source.language == "ja"


def test_source_input_accepts_public_ipv6_canonical_url() -> None:
    """Public IPv6 authority URLs must not be mistaken for single-label hostnames."""
    source = SourceInput(
        location="capture.txt",
        canonical_url="https://[2606:4700:4700::1111]/rule",
    )

    assert source.canonical_url == "https://[2606:4700:4700::1111]/rule"


@pytest.mark.parametrize(
    "canonical_url",
    [
        "file:///etc/passwd",
        "https://user:secret@example.org/rule",
        "http://" + "127.0.0.1/private",
        "http://" + "localhost/private",
        "https://" + "authority.internal/rule",
    ],
)
def test_source_input_rejects_unsafe_canonical_url(canonical_url: str) -> None:
    """Canonical provenance must not become a path or credential disclosure channel."""
    with pytest.raises(ValidationError):
        SourceInput(location="capture.txt", canonical_url=canonical_url)


def test_source_input_strips_query_credentials_and_fragments_from_canonical_url() -> None:
    source = SourceInput(
        location="capture.txt",
        canonical_url=(
            "https://example.org/rule?X-Amz-Credential=private&view=official#section"
        ),
    )

    assert source.canonical_url == "https://example.org/rule"


def test_citation_uses_half_open_offsets() -> None:
    """Changing offset semantics from half-open would make this arithmetic fail."""
    citation = CitationSpan(
        citation_id="cite-1",
        source_id="source-1",
        start_char=4,
        end_char=8,
        quote="must",
    )
    assert citation.end_char - citation.start_char == len(citation.quote)


@pytest.mark.parametrize(
    ("start", "end"),
    [(-1, 4), (4, 4), (5, 4)],
)
def test_citation_rejects_invalid_offsets(start: int, end: int) -> None:
    """Dropping offset bounds validation would make this test fail."""
    with pytest.raises(ValidationError):
        CitationSpan(
            citation_id="cite-1",
            source_id="source-1",
            start_char=start,
            end_char=end,
            quote="must",
        )


def test_bundle_round_trip_is_lossless() -> None:
    """Breaking the public JSON contract would make this test fail."""
    bundle = _bundle()
    restored = ResearchBundle.model_validate_json(bundle.model_dump_json())
    assert restored == bundle


def test_bundle_rejects_disabling_attorney_review() -> None:
    """Allowing version 1 bundles to suppress review would make this test fail."""
    values = _bundle().model_dump()
    values["requires_attorney_review"] = False
    with pytest.raises(ValidationError):
        ResearchBundle.model_validate(values)


def test_gap_records_the_attorney_coverage_dimension() -> None:
    """An uncategorized gap cannot satisfy a specific briefing dimension."""
    gap = Gap(
        gap_id="gap-status",
        code="AUTHORITY_STATUS_AMBIGUOUS",
        message="The retained sources do not establish operative status.",
        category=IssueCategory.STATUS,
    )

    assert gap.category is IssueCategory.STATUS


def test_presentation_metadata_round_trips_and_defaults_for_old_bundles() -> None:
    """Dropping optional presentation metadata would flatten the attorney report."""
    issue = ResearchIssue(
        issue_id="scope-territorial",
        title="Territorial reach",
        category=IssueCategory.SCOPE,
        presentation_role=PresentationRole.TERRITORIAL_SCOPE,
    )
    source = SourceInput(
        location="rule.txt",
        source_role=SourceRole.OFFICIAL_PRIMARY,
    )

    restored = ResearchIssue.model_validate(issue.model_dump())

    assert restored.presentation_role is PresentationRole.TERRITORIAL_SCOPE
    assert source.source_role is SourceRole.OFFICIAL_PRIMARY
    assert ResearchIssue(issue_id="old", title="Old bundle").presentation_role is None
    assert SourceInput(location="old.txt").source_role is None


def test_request_accepts_descriptive_matter_title_and_rejects_blank_title() -> None:
    """A blank title must not create an empty report heading."""
    request = _request().model_copy(update={"matter_title": "Example Regulation"})

    assert ResearchRequest.model_validate(request.model_dump()).matter_title == (
        "Example Regulation"
    )
    values = request.model_dump()
    values["matter_title"] = "   "
    with pytest.raises(ValidationError):
        ResearchRequest.model_validate(values)


def test_public_models_reject_unknown_fields() -> None:
    """Relaxing strict schema handling would make this test fail."""
    values = _request().model_dump()
    values["unexpected"] = "silent drift"
    with pytest.raises(ValidationError):
        ResearchRequest.model_validate(values)


def test_manifest_looks_up_each_combine_stage() -> None:
    """Breaking stage addressing would make resume logic fail this test."""
    manifest = _bundle().manifest
    assert manifest.stage(StageName.COLLECT).status is StageStatus.PENDING
    assert [stage.name for stage in manifest.stages] == list(StageName)


def test_manifest_rejects_completed_stage_after_unfinished_stage() -> None:
    """Accepting impossible stage histories would make resume state untrustworthy."""
    stages = [StageRecord(name=name) for name in StageName]
    stages[1].status = StageStatus.COMPLETED

    with pytest.raises(ValidationError, match="terminal stage statuses must form a prefix"):
        RunManifest(
            run_id="demo",
            generator_version="0.1.0",
            created_at=_now(),
            updated_at=_now(),
            stages=stages,
        )


def _adaptive_brief() -> AttorneyBrief:
    return AttorneyBrief(
        executive_summary=[
            BriefBlock(
                kind=BriefBlockKind.PARAGRAPH,
                purpose=BriefBlockPurpose.LEGAL_ANALYSIS,
                text="The rule requires documented risk controls.",
                finding_ids=["finding-1"],
            )
        ],
        sections=[
            BriefSection(
                section_id="legal-framework",
                title="Legal Framework",
                blocks=[
                    BriefBlock(
                        kind=BriefBlockKind.BULLET_LIST,
                        purpose=BriefBlockPurpose.LEGAL_ANALYSIS,
                        items=[
                            BriefItem(
                                text="Document material risks.",
                                finding_ids=["finding-1"],
                            )
                        ],
                    )
                ],
                subsections=[
                    BriefSubsection(
                        subsection_id="implementation-sequence",
                        title="Implementation Sequence",
                        blocks=[
                            BriefBlock(
                                kind=BriefBlockKind.NUMBERED_LIST,
                                purpose=BriefBlockPurpose.APPLICATION,
                                items=[BriefItem(text="Create the risk record first.")],
                            ),
                            BriefBlock(
                                kind=BriefBlockKind.TABLE,
                                purpose=BriefBlockPurpose.APPLICATION,
                                columns=["Action", "Owner"],
                                rows=[
                                    BriefTableRow(
                                        cells=["Approve risk record", "Legal"],
                                        finding_ids=["finding-1"],
                                    )
                                ],
                            ),
                        ],
                    )
                ],
            )
        ],
    )


def test_adaptive_brief_round_trips_all_supported_block_kinds() -> None:
    """Dropping a block kind would prevent legacy-shaped narrative layouts."""
    brief = _adaptive_brief()

    restored = AttorneyBrief.model_validate_json(brief.model_dump_json())

    assert restored == brief
    assert [block.kind for block in restored.sections[0].subsections[0].blocks] == [
        BriefBlockKind.NUMBERED_LIST,
        BriefBlockKind.TABLE,
    ]


def test_brief_units_preserve_claim_bindings_and_enforcement_pairs() -> None:
    """Dropping claim-level bindings would let unrelated findings cite new legal prose."""
    paragraph = BriefBlock.model_validate(
        {
            "kind": "paragraph",
            "purpose": "legal_analysis",
            "text": "A violation permits the agency to impose a civil penalty.",
            "finding_ids": ["finding-enforcement"],
            "claim_ids": ["claim-enforcement"],
            "enforcement_trigger_claim_ids": ["claim-enforcement"],
            "enforcement_consequence_claim_ids": ["claim-enforcement"],
        }
    )
    item = BriefItem.model_validate(
        {
            "text": "A controller must document risks.",
            "finding_ids": ["finding-requirement"],
            "claim_ids": ["claim-requirement"],
        }
    )
    row = BriefTableRow.model_validate(
        {
            "cells": ["Violation", "Civil penalty"],
            "finding_ids": ["finding-enforcement"],
            "claim_ids": ["claim-enforcement"],
            "enforcement_trigger_claim_ids": ["claim-enforcement"],
            "enforcement_consequence_claim_ids": ["claim-enforcement"],
        }
    )

    assert paragraph.claim_ids == ["claim-enforcement"]
    assert paragraph.enforcement_trigger_claim_ids == ["claim-enforcement"]
    assert paragraph.enforcement_consequence_claim_ids == ["claim-enforcement"]
    assert item.claim_ids == ["claim-requirement"]
    assert row.claim_ids == ["claim-enforcement"]


def test_claim_enforcement_roles_are_typed_unique_and_serialized() -> None:
    """A generic claim ID must not acquire trigger or consequence meaning by placement."""
    claim = Claim.model_validate(
        {
            "claim_id": "claim-enforcement",
            "text": "A violation permits the agency to impose a civil penalty.",
            "kind": "source_supported",
            "enforcement_roles": ["trigger", "consequence"],
        }
    )

    restored = Claim.model_validate_json(claim.model_dump_json())

    assert [role.value for role in restored.enforcement_roles] == [
        "trigger",
        "consequence",
    ]
    with pytest.raises(ValidationError):
        Claim.model_validate(
            {
                "claim_id": "claim-enforcement",
                "text": "A violation permits the agency to impose a civil penalty.",
                "kind": "source_supported",
                "enforcement_roles": ["trigger", "trigger"],
            }
        )
    with pytest.raises(ValidationError):
        Claim.model_validate(
            {
                "claim_id": "claim-enforcement",
                "text": "A violation permits the agency to impose a civil penalty.",
                "kind": "source_supported",
                "enforcement_roles": ["generic_requirement"],
            }
        )


def test_profiled_brief_round_trips_structure_profile_and_section_roles() -> None:
    """The semantic anchors must survive the canonical JSON boundary."""
    brief = _adaptive_brief()
    brief.structure_profile = BriefStructureProfile.REGULATORY_WALK_V1
    brief.sections[0].role = BriefSectionRole.KEY_REQUIREMENTS

    restored = AttorneyBrief.model_validate_json(brief.model_dump_json())

    assert restored.structure_profile is BriefStructureProfile.REGULATORY_WALK_V1
    assert restored.sections[0].role is BriefSectionRole.KEY_REQUIREMENTS


@pytest.mark.parametrize(
    "values",
    [
        {
            "kind": "paragraph",
            "purpose": "legal_analysis",
            "items": [{"text": "Wrong payload"}],
        },
        {
            "kind": "bullet_list",
            "purpose": "application",
            "text": "Wrong payload",
        },
        {
            "kind": "table",
            "purpose": "application",
            "columns": ["Only one"],
            "rows": [{"cells": ["value"]}],
        },
        {
            "kind": "table",
            "purpose": "application",
            "columns": ["A", "B"],
            "rows": [{"cells": ["one cell"]}],
        },
    ],
)
def test_adaptive_brief_rejects_payloads_that_do_not_match_block_kind(
    values: dict[str, object],
) -> None:
    """Accepting ambiguous block payloads would fork renderer behavior."""
    with pytest.raises(ValidationError):
        BriefBlock.model_validate(values)


@pytest.mark.parametrize(
    "title",
    [
        "Executive Summary",
        "Priority and Posture",
        "Bottom Line",
        "Limitations and Open Questions",
        "Sources Consulted",
        "Evidence and Validation Appendix",
    ],
)
def test_adaptive_brief_rejects_renderer_owned_section_titles(title: str) -> None:
    """Allowing renderer-owned headings would duplicate the visible report structure."""
    with pytest.raises(ValidationError):
        BriefSection(
            section_id="reserved",
            title=title,
            blocks=[
                BriefBlock(
                    kind="paragraph",
                    purpose="application",
                    text="Example.",
                )
            ],
        )


def test_adaptive_brief_rejects_empty_and_duplicate_sections() -> None:
    """Empty or duplicate sections would recreate the failed fixed skeleton."""
    with pytest.raises(ValidationError):
        BriefSection(section_id="empty", title="Empty")

    section = _adaptive_brief().sections[0]
    with pytest.raises(ValidationError):
        AttorneyBrief(
            executive_summary=_adaptive_brief().executive_summary,
            sections=[section, section],
        )


def test_bundle_accepts_optional_adaptive_brief_without_breaking_old_bundle() -> None:
    """Making the brief mandatory would break version 1 stored bundles."""
    old_bundle = _bundle()
    adaptive_bundle = old_bundle.model_copy(update={"brief": _adaptive_brief()})

    assert ResearchBundle.model_validate(old_bundle.model_dump()).brief is None
    assert ResearchBundle.model_validate(adaptive_bundle.model_dump()).brief == (
        _adaptive_brief()
    )
    assert ResearchBundle.model_validate(adaptive_bundle.model_dump()).brief is not None
    assert (
        ResearchBundle.model_validate(adaptive_bundle.model_dump()).brief.structure_profile
        is None
    )
