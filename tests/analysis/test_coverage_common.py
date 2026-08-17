from copy import deepcopy
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime

import pytest

from regulatory_harvest.analysis.coverage_common import (
    _CitationSpan,
    _Target,
    brief_binding_index,
    claim_index,
    gap_index,
    span_overlaps_target,
    target_indexes,
)
from regulatory_harvest.analysis.drafts import (
    AnalysisDraft,
    DraftClaim,
    DraftFinding,
    DraftGap,
    DraftIssue,
    ProposedCitation,
)
from regulatory_harvest.models import (
    AttorneyBrief,
    BriefBlock,
    BriefBlockKind,
    BriefBlockPurpose,
    BriefItem,
    BriefSection,
    BriefSubsection,
    BriefTableRow,
    ClaimKind,
    Severity,
    SourceRecord,
)
from regulatory_harvest.storage import sha256_digest

SOURCE_TEXT = "A controller must maintain a written register."


def _source(source_id: str = "src_rule") -> SourceRecord:
    return SourceRecord(
        source_id=source_id,
        origin=f"{source_id}.txt",
        display_name="Synthetic Rule",
        retrieved_at=datetime(2026, 8, 14, tzinfo=UTC),
        content_hash=sha256_digest(SOURCE_TEXT.encode()),
        media_type="text/plain",
        normalized_text=SOURCE_TEXT,
        jurisdiction="US",
    )


def _inventories() -> tuple[dict[str, object], dict[str, object]]:
    unit = {
        "unit_id": "unit-1",
        "source_id": "src_rule",
        "start_char": 0,
        "end_char": len(SOURCE_TEXT),
        "excerpt": SOURCE_TEXT,
        "coverage_required": True,
    }
    lead = {
        "lead_id": "lead-1",
        "source_id": "src_rule",
        "start_char": 0,
        "end_char": len(SOURCE_TEXT),
        "excerpt": SOURCE_TEXT,
        "issue_category": "requirements",
        "topic": "written register",
        "review_required": True,
    }
    return (
        {"units": [unit], "unit_count": 1, "required_unit_count": 1},
        {"leads": [lead], "lead_count": 1},
    )


def _claim_draft() -> AnalysisDraft:
    return AnalysisDraft(
        issues=[
            DraftIssue(
                issue_id="issue-requirements",
                title="Requirements",
                category="requirements",
                jurisdictions=["US"],
            )
        ],
        findings=[
            DraftFinding(
                finding_id="finding-requirements",
                issue_id="issue-requirements",
                title="Requirements",
                jurisdiction="US",
                authority="Synthetic Rule",
                severity=Severity.INFO,
                practical_implication="Assess the supported requirement.",
                claims=[
                    DraftClaim(
                        claim_id="claim-rule",
                        text=SOURCE_TEXT,
                        kind=ClaimKind.SOURCE_SUPPORTED,
                        proposed_citations=[
                            ProposedCitation(source_id="src_rule", quote=SOURCE_TEXT)
                        ],
                    )
                ],
            )
        ],
    )


def _bound_item(label: str, *, purpose: str = "legal_analysis") -> BriefBlock:
    return BriefBlock(
        kind="bullet_list",
        purpose=purpose,
        items=[
            BriefItem(
                text=label,
                claim_ids=["claim-rule"],
                atom_ids=["atom-rule"],
                relationship_ids=["relationship-rule"],
            )
        ],
    )


def _bound_paragraph() -> BriefBlock:
    return BriefBlock(
        kind="paragraph",
        purpose="legal_analysis",
        text="Bound rule.",
        claim_ids=["claim-rule"],
        atom_ids=["atom-rule"],
        relationship_ids=["relationship-rule"],
    )


def _neutral_paragraph() -> BriefBlock:
    return BriefBlock(
        kind="paragraph",
        purpose="limitation",
        text="Neutral context.",
    )


def _malformed_bound_brief(mutation: str) -> AttorneyBrief:
    neutral_section = BriefSection(
        section_id="context",
        title="Context",
        blocks=[_neutral_paragraph()],
    )
    if mutation == "paragraph":
        malformed_block = BriefBlock.model_construct(
            kind=BriefBlockKind.PARAGRAPH,
            purpose=BriefBlockPurpose.LEGAL_ANALYSIS,
            text=None,
            finding_ids=[],
            claim_ids=["claim-rule"],
            enforcement_trigger_claim_ids=[],
            enforcement_consequence_claim_ids=[],
            atom_ids=["atom-rule"],
            relationship_ids=["relationship-rule"],
            items=[],
            columns=[],
            rows=[],
        )
        return AttorneyBrief.model_construct(
            structure_profile="regulatory-walk-v1",
            executive_summary=[malformed_block],
            sections=[neutral_section],
        )
    if mutation == "item":
        malformed_item = BriefItem.model_construct(
            text=None,
            finding_ids=[],
            claim_ids=["claim-rule"],
            enforcement_trigger_claim_ids=[],
            enforcement_consequence_claim_ids=[],
            atom_ids=["atom-rule"],
            relationship_ids=["relationship-rule"],
        )
        malformed_list = _bound_item("Valid item.").model_copy(
            update={"items": [malformed_item]}
        )
        return AttorneyBrief.model_construct(
            structure_profile="regulatory-walk-v1",
            executive_summary=[_neutral_paragraph()],
            sections=[
                neutral_section.model_copy(update={"blocks": [malformed_list]})
            ],
        )
    if mutation == "table_row":
        malformed_row = BriefTableRow.model_construct(
            cells=[],
            finding_ids=[],
            claim_ids=["claim-rule"],
            enforcement_trigger_claim_ids=[],
            enforcement_consequence_claim_ids=[],
            atom_ids=["atom-rule"],
            relationship_ids=["relationship-rule"],
        )
        malformed_table = BriefBlock(
            kind="table",
            purpose="legal_analysis",
            columns=["Rule", "Effect"],
            rows=[BriefTableRow(cells=["Register", "Required"])],
        ).model_copy(update={"rows": [malformed_row]})
        return AttorneyBrief.model_construct(
            structure_profile="regulatory-walk-v1",
            executive_summary=[_neutral_paragraph()],
            sections=[
                neutral_section.model_copy(update={"blocks": [malformed_table]})
            ],
        )
    if mutation == "section":
        malformed_section = BriefSection.model_construct(
            section_id="",
            title="",
            role=None,
            blocks=[_bound_paragraph()],
            subsections=[],
        )
        return AttorneyBrief.model_construct(
            structure_profile="regulatory-walk-v1",
            executive_summary=[_neutral_paragraph()],
            sections=[malformed_section],
        )
    if mutation == "subsection":
        malformed_subsection = BriefSubsection.model_construct(
            subsection_id="",
            title="",
            blocks=[_bound_paragraph()],
        )
        return AttorneyBrief.model_construct(
            structure_profile="regulatory-walk-v1",
            executive_summary=[_neutral_paragraph()],
            sections=[
                neutral_section.model_copy(
                    update={"blocks": [], "subsections": [malformed_subsection]}
                )
            ],
        )
    assert mutation == "hierarchy_object"
    return AttorneyBrief.model_construct(
        structure_profile="regulatory-walk-v1",
        executive_summary=[_bound_paragraph()],
        sections=[object()],
    )


def test_frozen_spans_use_half_open_overlap_boundaries() -> None:
    target = _Target("unit-1", "src_rule", 10, 20)

    assert span_overlaps_target(_CitationSpan("src_rule", 9, 10), target) is False
    assert span_overlaps_target(_CitationSpan("src_rule", 20, 21), target) is False
    assert span_overlaps_target(_CitationSpan("src_rule", 9, 11), target) is True
    assert span_overlaps_target(_CitationSpan("src_rule", 19, 21), target) is True
    assert span_overlaps_target(_CitationSpan("other", 10, 20), target) is False
    with pytest.raises(FrozenInstanceError):
        target.start_char = 0  # type: ignore[misc]


def test_target_indexes_reject_duplicate_sources_units_and_leads_without_mutation() -> None:
    units, leads = _inventories()
    duplicate_units = deepcopy(units["units"])
    duplicate_leads = deepcopy(leads["leads"])
    assert isinstance(duplicate_units, list)
    assert isinstance(duplicate_leads, list)
    units["units"] = [*duplicate_units, *deepcopy(duplicate_units)]
    units["unit_count"] = 2
    units["required_unit_count"] = 2
    leads["leads"] = [*duplicate_leads, *deepcopy(duplicate_leads)]
    leads["lead_count"] = 2
    sources = [_source(), _source()]
    before = (deepcopy(units), deepcopy(leads), [source.model_dump() for source in sources])

    indexes, issues = target_indexes(units, leads, sources)

    assert indexes.units == ()
    assert indexes.leads == ()
    assert indexes.unit_by_id == {}
    assert indexes.lead_by_id == {}
    assert {issue["message"] for issue in issues} == {
        "Prepared sources contain a duplicate identifier.",
        "Prepared source units contain a duplicate identifier.",
        "Prepared source unit is malformed or is not an exact source slice.",
        "Prepared provision leads contain a duplicate identifier.",
        "Prepared provision lead is malformed or is not an exact source slice.",
    }
    assert (units, leads, [source.model_dump() for source in sources]) == before


def test_target_indexes_fail_closed_for_malformed_collections_and_counts() -> None:
    units: dict[str, object] = {
        "units": {"unit_id": "not-a-list"},
        "unit_count": True,
        "required_unit_count": 1,
    }
    leads: dict[str, object] = {
        "leads": [None],
        "lead_count": 1,
    }

    indexes, issues = target_indexes(units, leads, [_source()])

    assert indexes.unit_objects == ()
    assert indexes.lead_objects == ()
    assert indexes.declared_unit_ids == frozenset()
    assert indexes.declared_lead_ids == frozenset()
    assert [issue["code"] for issue in issues] == [
        "COVERAGE_ROW_INVALID",
        "COVERAGE_ROW_INVALID",
        "COVERAGE_ROW_INVALID",
    ]
    assert [issue["message"] for issue in issues] == [
        "Prepared coverage inventory collection is malformed.",
        "Prepared coverage inventory contains a malformed target.",
        "Prepared coverage inventory count is inconsistent.",
    ]


def test_target_indexes_fail_closed_for_validation_bypassing_source_ids() -> None:
    units, leads = _inventories()
    malformed_source = _source().model_copy(update={"source_id": ["src_rule"]})

    indexes, issues = target_indexes(units, leads, [malformed_source])

    assert indexes.units == ()
    assert indexes.leads == ()
    assert {issue["message"] for issue in issues} == {
        "Prepared sources contain a malformed row.",
        "Prepared source unit is malformed or is not an exact source slice.",
        "Prepared provision lead is malformed or is not an exact source slice.",
    }


def test_claim_index_returns_frozen_exact_spans_and_duplicate_diagnostics() -> None:
    draft = _claim_draft()
    before = draft.model_dump(mode="json", warnings=False)

    claims, issues = claim_index(draft, [_source()])

    assert issues == []
    assert claims["claim-rule"].kind is ClaimKind.SOURCE_SUPPORTED
    assert claims["claim-rule"].category == "requirements"
    assert claims["claim-rule"].spans == (
        _CitationSpan("src_rule", 0, len(SOURCE_TEXT)),
    )
    with pytest.raises(FrozenInstanceError):
        claims["claim-rule"].category = "other"  # type: ignore[misc]
    assert draft.model_dump(mode="json", warnings=False) == before

    duplicated = draft.model_copy(
        update={
            "issues": [*draft.issues, draft.issues[0]],
            "findings": [*draft.findings, draft.findings[0]],
        }
    )
    duplicate_claims, duplicate_issues = claim_index(duplicated, [_source()])

    assert duplicate_claims == {}
    assert {issue["message"] for issue in duplicate_issues} == {
        "Built analysis issues contain a duplicate identifier.",
        "Built exact citations contain a duplicate identifier.",
        "Built analysis claims contain a duplicate identifier.",
    }


def test_claim_and_gap_indexes_bound_validation_bypasses() -> None:
    draft = _claim_draft().model_copy(update={"findings": [object()]})
    claims, claim_issues = claim_index(draft, [_source()])

    assert claims == {}
    assert claim_issues == [
        {
            "code": "COVERAGE_ROW_INVALID",
            "message": "The analysis draft could not be reconciled into exact evidence.",
            "related_ids": [],
        }
    ]

    malformed_gaps = AnalysisDraft().model_copy(
        update={
            "gaps": [
                DraftGap(
                    code="DUPLICATE_GAP",
                    message="Timing is absent.",
                    category="requirements",
                    source_ids=["src_rule"],
                ),
                DraftGap(
                    code="DUPLICATE_GAP",
                    message="Timing is absent.",
                    category="requirements",
                    source_ids=["src_rule"],
                ),
                object(),
            ]
        }
    )
    gaps, gap_issues = gap_index(malformed_gaps)

    assert gaps == {}
    assert {issue["message"] for issue in gap_issues} == {
        "Authored gaps contain a duplicate mapping code.",
        "The authored gap ledger contains a malformed row.",
    }


def test_brief_binding_index_covers_all_visible_shapes_and_excludes_non_legal() -> None:
    paragraph = BriefBlock(
        kind="paragraph",
        purpose="legal_analysis",
        text="Paragraph.",
        claim_ids=["claim-rule"],
        atom_ids=["atom-rule"],
        relationship_ids=["relationship-rule"],
    )
    table = BriefBlock(
        kind="table",
        purpose="legal_analysis",
        columns=["Rule", "Effect"],
        rows=[
            BriefTableRow(
                cells=["Register", "Required"],
                claim_ids=["claim-rule"],
                atom_ids=["atom-rule"],
                relationship_ids=["relationship-rule"],
            )
        ],
    )
    numbered = BriefBlock(
        kind="numbered_list",
        purpose="legal_analysis",
        items=[
            BriefItem(
                text="Numbered rule.",
                claim_ids=["claim-rule"],
                atom_ids=["atom-rule"],
                relationship_ids=["relationship-rule"],
            )
        ],
    )
    excluded = _bound_item("Application only.", purpose="application")
    brief = AttorneyBrief(
        structure_profile="regulatory-walk-v1",
        executive_summary=[paragraph, excluded],
        sections=[
            BriefSection(
                section_id="requirements",
                title="Requirements Walk",
                blocks=[_bound_item("Bullet rule."), table],
                subsections=[
                    BriefSubsection(
                        subsection_id="details",
                        title="Details",
                        blocks=[numbered],
                    )
                ],
            )
        ],
    )
    before = brief.model_dump(mode="json", warnings=False)

    bindings = brief_binding_index(brief)

    expected_locations = (
        "brief.executive_summary[0]",
        "brief.sections[0].blocks[0].items[0]",
        "brief.sections[0].blocks[1].rows[0]",
        "brief.sections[0].subsections[0].blocks[0].items[0]",
    )
    assert bindings.claim_locations == {"claim-rule": expected_locations}
    assert bindings.atom_locations == {"atom-rule": expected_locations}
    assert bindings.relationship_locations == {
        "relationship-rule": expected_locations
    }
    assert brief.model_dump(mode="json", warnings=False) == before
    assert brief_binding_index(None).claim_locations == {}


def test_brief_binding_index_fails_closed_on_validation_bypasses() -> None:
    malformed = AttorneyBrief.model_construct(
        executive_summary=[object()],
        sections=[object()],
    )

    bindings = brief_binding_index(malformed)

    assert bindings.claim_locations == {}
    assert bindings.atom_locations == {}
    assert bindings.relationship_locations == {}


@pytest.mark.parametrize(
    "mutation",
    ["paragraph", "item", "table_row", "section", "subsection", "hierarchy_object"],
)
def test_brief_binding_index_rejects_complete_malformed_typed_hierarchy(
    mutation: str,
) -> None:
    malformed = _malformed_bound_brief(mutation)
    before = malformed.model_dump(mode="python", warnings=False)

    bindings = brief_binding_index(malformed)

    assert bindings.claim_locations == {}
    assert bindings.atom_locations == {}
    assert bindings.relationship_locations == {}
    assert malformed.model_dump(mode="python", warnings=False) == before
