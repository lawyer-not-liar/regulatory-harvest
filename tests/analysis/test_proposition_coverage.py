from copy import deepcopy
from datetime import UTC, datetime

import pytest

from regulatory_harvest.analysis import (
    AnalysisDraft,
    DraftAtomElement,
    DraftClaim,
    DraftCoverageElement,
    DraftCoverageElements,
    DraftDimensionReview,
    DraftFinding,
    DraftGap,
    DraftIssue,
    DraftLeadDispositionV2,
    DraftLeadReview,
    DraftPropositionCoverage,
    DraftRuleAtom,
    DraftRuleAtomElements,
    DraftUnitReview,
    DraftUnitReviewDimensions,
    ProposedCitation,
    build_evidence_inventory,
    build_source_unit_inventory,
    evaluate_coverage_closure,
    evaluate_proposition_coverage,
    evaluate_provision_recall,
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
from regulatory_harvest.storage import canonical_json_bytes, sha256_digest

FIRST_DUTY = "A controller must maintain a written register."
SECOND_DUTY = "The controller must notify affected persons."


def _source(text: str) -> SourceRecord:
    return SourceRecord(
        source_id="src_rule",
        origin="rule.txt",
        display_name="Synthetic Rule",
        retrieved_at=datetime(2026, 8, 14, tzinfo=UTC),
        content_hash=sha256_digest(text.encode()),
        media_type="text/plain",
        normalized_text=text,
        jurisdiction="US",
    )


def _elements() -> DraftCoverageElements:
    not_applicable = DraftCoverageElement(status="not_applicable")
    return DraftCoverageElements(
        subject=DraftCoverageElement(status="stated", text="controller"),
        operative_rule=DraftCoverageElement(status="stated", text="must act"),
        object=DraftCoverageElement(
            status="stated", text="the regulated record or notice"
        ),
        trigger_or_threshold=not_applicable,
        conditions_or_exceptions=not_applicable,
        timing=not_applicable,
        consequence_or_remedy=not_applicable,
        authority_or_route=not_applicable,
    )


def _target_ids(
    inventory: dict[str, object], quote: str, *, key: str, id_key: str
) -> list[str]:
    items = inventory[key]
    assert isinstance(items, list)
    return [str(item[id_key]) for item in items if quote in str(item["excerpt"])]


def _draft(
    source: SourceRecord,
    *,
    claims: list[DraftClaim],
    rows: list[DraftPropositionCoverage],
    visible_claim_ids: list[str],
) -> AnalysisDraft:
    return AnalysisDraft(
        coverage_contract_version="proposition-coverage-v1",
        proposition_coverage=rows,
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
                practical_implication="Assess the supported requirements.",
                claims=claims,
            )
        ],
        brief=AttorneyBrief(
            structure_profile="regulatory-walk-v1",
            executive_summary=[
                BriefBlock(
                    kind="paragraph",
                    purpose="legal_analysis",
                    text="The rule imposes the supported requirements.",
                    claim_ids=visible_claim_ids,
                )
            ],
            sections=[
                BriefSection(
                    section_id="requirements",
                    title="Requirements Walk",
                    role="other",
                    blocks=[
                        BriefBlock(
                            kind="paragraph",
                            purpose="legal_analysis",
                            text="The controller must comply with the stated duties.",
                            claim_ids=visible_claim_ids,
                        )
                    ],
                )
            ],
        ),
    )


def _inventories(source: SourceRecord) -> tuple[dict[str, object], dict[str, object]]:
    payload = source.model_dump(mode="json")
    return build_source_unit_inventory([payload]), build_evidence_inventory([payload])


def _all_ids(inventory: dict[str, object], key: str, id_key: str) -> list[str]:
    items = inventory[key]
    assert isinstance(items, list)
    return [str(item[id_key]) for item in items]


def _claim(
    claim_id: str,
    text: str,
    *,
    source_id: str = "src_rule",
    kind: ClaimKind = ClaimKind.SOURCE_SUPPORTED,
) -> DraftClaim:
    citations = (
        [ProposedCitation(source_id=source_id, quote=text)]
        if kind is ClaimKind.SOURCE_SUPPORTED
        else []
    )
    return DraftClaim(
        claim_id=claim_id,
        text=text,
        kind=kind,
        proposed_citations=citations,
    )


def _covered_row(
    units: dict[str, object],
    leads: dict[str, object],
    *,
    coverage_id: str = "coverage-all",
    claim_ids: list[str] | None = None,
    elements: DraftCoverageElements | None = None,
    gap_codes: list[str] | None = None,
) -> DraftPropositionCoverage:
    return DraftPropositionCoverage(
        coverage_id=coverage_id,
        unit_ids=_all_ids(units, "units", "unit_id"),
        lead_ids=_all_ids(leads, "leads", "lead_id"),
        category="requirements",
        proposition_type="duty",
        disposition="covered",
        elements=elements or _elements(),
        claim_ids=claim_ids or ["claim-all"],
        gap_codes=gap_codes or [],
    )


def _v1_characterization_cases() -> dict[
    str,
    tuple[
        dict[str, object],
        dict[str, object],
        AnalysisDraft,
        list[SourceRecord],
    ],
]:
    source = _source(FIRST_DUTY)
    units, leads = _inventories(source)
    covered = _draft(
        source,
        claims=[_claim("claim-all", FIRST_DUTY)],
        rows=[_covered_row(units, leads)],
        visible_claim_ids=["claim-all"],
    )

    gap_code = "RULE_TEXT_INCOMPLETE"
    gap_row = DraftPropositionCoverage(
        coverage_id="coverage-rule-gap",
        unit_ids=_all_ids(units, "units", "unit_id"),
        lead_ids=_all_ids(leads, "leads", "lead_id"),
        category="requirements",
        proposition_type="duty",
        disposition="gap",
        gap_codes=[gap_code],
        rationale="The retained excerpt omits the incorporated schedule.",
    )
    gap = _draft(source, claims=[], rows=[gap_row], visible_claim_ids=[]).model_copy(
        update={
            "gaps": [
                DraftGap(
                    code=gap_code,
                    message="The incorporated schedule was not retained.",
                    category="requirements",
                    source_ids=[source.source_id],
                )
            ]
        }
    )

    not_material_row = DraftPropositionCoverage(
        coverage_id="coverage-navigation",
        unit_ids=_all_ids(units, "units", "unit_id"),
        lead_ids=_all_ids(leads, "leads", "lead_id"),
        category="other",
        proposition_type="other",
        disposition="not_material",
        rationale="The host determined the navigation text is outside the question.",
    )
    not_material = _draft(
        source,
        claims=[],
        rows=[not_material_row],
        visible_claim_ids=[],
    )

    second = _source(SECOND_DUTY).model_copy(
        update={
            "source_id": "src_notice",
            "origin": "notice.txt",
            "display_name": "Synthetic Notice",
        }
    )
    multi_payloads = [source.model_dump(mode="json"), second.model_dump(mode="json")]
    multi_units = build_source_unit_inventory(multi_payloads)
    multi_leads = build_evidence_inventory(multi_payloads)
    multi_source = _draft(
        source,
        claims=[
            _claim("claim-first", FIRST_DUTY),
            _claim("claim-second", SECOND_DUTY, source_id=second.source_id),
        ],
        rows=[
            _covered_row(
                multi_units,
                multi_leads,
                coverage_id="coverage-two-sources",
                claim_ids=["claim-first", "claim-second"],
            )
        ],
        visible_claim_ids=["claim-first", "claim-second"],
    )

    malformed_row = _covered_row(units, leads).model_copy(update={"unit_ids": None})
    malformed = covered.model_copy(update={"proposition_coverage": [malformed_row]})

    paragraph = BriefBlock(
        kind="paragraph",
        purpose="legal_analysis",
        text="Supported paragraph.",
        claim_ids=["claim-all"],
    )
    bullet_list = BriefBlock(
        kind="bullet_list",
        purpose="legal_analysis",
        items=[BriefItem(text="Supported list item.", claim_ids=["claim-all"])],
    )
    table = BriefBlock(
        kind="table",
        purpose="legal_analysis",
        columns=["Rule", "Effect"],
        rows=[BriefTableRow(cells=["Register", "Required"], claim_ids=["claim-all"])],
    )
    mixed_brief = AttorneyBrief(
        structure_profile="regulatory-walk-v1",
        executive_summary=[paragraph, bullet_list, table],
        sections=[
            BriefSection(
                section_id="requirements",
                title="Requirements Walk",
                blocks=[paragraph, bullet_list, table],
                subsections=[
                    BriefSubsection(
                        subsection_id="details",
                        title="Detailed Rule",
                        blocks=[paragraph, bullet_list, table],
                    )
                ],
            )
        ],
    )
    mixed = covered.model_copy(update={"brief": mixed_brief})

    return {
        "covered": (units, leads, covered, [source]),
        "gap": (units, leads, gap, [source]),
        "not_material": (units, leads, not_material, [source]),
        "multi_source": (multi_units, multi_leads, multi_source, [source, second]),
        "malformed": (units, leads, malformed, [source]),
        "mixed_brief": (units, leads, mixed, [source]),
    }


def test_canonical_v1_outputs_are_frozen_and_inputs_are_deeply_unmodified() -> None:
    expected_hashes = {
        "covered": (
            "2193bb3d902e82b68e848f3633217e774b5e05b837b8c2063fc0d11a37c755c0",
            "4ffdf6a22ac273ab5803a55f2b4689f1885003e2cb68043a53e6c9f2c9a64e35",
        ),
        "gap": (
            "83b712aaa91e7fb0ca49101527ff20405815d9808b755ce6ed7fc36f0b68c56f",
            "533f7cdfe46fd7016e0f8f669e4f8897b3ceed5dea62afb609801d2b8cb11d0f",
        ),
        "not_material": (
            "d7768d21294a7e476fbd084e957e6148c51f5a047ea632fddb8b6471cd78ec63",
            "47ba3f24b649d82957b942cfd18729338e147953909ecbfdd2011bc66e9560ab",
        ),
        "multi_source": (
            "1d71dc1afc864b3abcafbfe4eecec8e5529ae5ae528f73f20739205d060437bb",
            "970ceac20ffc0fb71bc0b294f74aa9b9410da6c5fbae340e567ca1afd7df3ef0",
        ),
        "malformed": (
            "5dc362c66fbdbf22135ad9fb66b816c5efaf3770b000edac6742e22684be7d02",
            "202e2761f88a5eebba798bce900ff360174e0bd472954f3972d55eafd672b3be",
        ),
        "mixed_brief": (
            "d4f9b52e7ae47ee2ab6e748acc72be04eca7b43c46e1a7edb733f10239e708f7",
            "9e37c6002c28573ebf8317d807b8e4388231e0c7aace5a189cb99f36db583938",
        ),
    }
    actual_hashes: dict[str, tuple[str, str]] = {}

    for name, (units, leads, draft, sources) in _v1_characterization_cases().items():
        before = (
            deepcopy(units),
            deepcopy(leads),
            draft.model_dump(mode="json", warnings=False),
            [source.model_dump(mode="json", warnings=False) for source in sources],
        )

        proposition = evaluate_proposition_coverage(units, leads, draft, sources)
        closure = evaluate_coverage_closure(leads, units, draft, sources)
        actual_hashes[name] = (
            sha256_digest(canonical_json_bytes(proposition)),
            str(closure["coverage_review_hash"]),
        )

        assert units == before[0]
        assert leads == before[1]
        assert draft.model_dump(mode="json", warnings=False) == before[2]
        assert [
            source.model_dump(mode="json", warnings=False) for source in sources
        ] == before[3]

    assert actual_hashes == expected_hashes


def test_every_required_unit_and_every_lead_must_be_dispositioned() -> None:
    source = _source(f"{FIRST_DUTY}\n\n{SECOND_DUTY}")
    source_payload = source.model_dump(mode="json")
    units = build_source_unit_inventory([source_payload])
    leads = build_evidence_inventory([source_payload])
    first_unit_ids = _target_ids(units, FIRST_DUTY, key="units", id_key="unit_id")
    first_lead_ids = _target_ids(leads, FIRST_DUTY, key="leads", id_key="lead_id")
    claim = DraftClaim(
        claim_id="claim-first",
        text=FIRST_DUTY,
        kind=ClaimKind.SOURCE_SUPPORTED,
        proposed_citations=[ProposedCitation(source_id="src_rule", quote=FIRST_DUTY)],
    )
    row = DraftPropositionCoverage(
        coverage_id="coverage-first",
        unit_ids=first_unit_ids,
        lead_ids=first_lead_ids,
        category="requirements",
        proposition_type="duty",
        disposition="covered",
        elements=_elements(),
        claim_ids=["claim-first"],
    )
    review = evaluate_proposition_coverage(
        units,
        leads,
        _draft(source, claims=[claim], rows=[row], visible_claim_ids=["claim-first"]),
        [source],
    )
    assert review["valid"] is False
    assert {issue["code"] for issue in review["issues"]} == {
        "COVERAGE_TARGET_UNRESOLVED"
    }


def test_neighboring_exact_citation_cannot_cover_another_target() -> None:
    source = _source(f"{FIRST_DUTY}\n\n{SECOND_DUTY}")
    source_payload = source.model_dump(mode="json")
    units = build_source_unit_inventory([source_payload])
    leads = build_evidence_inventory([source_payload])
    claim = DraftClaim(
        claim_id="claim-first",
        text=FIRST_DUTY,
        kind=ClaimKind.SOURCE_SUPPORTED,
        proposed_citations=[ProposedCitation(source_id="src_rule", quote=FIRST_DUTY)],
    )
    row = DraftPropositionCoverage(
        coverage_id="coverage-both",
        unit_ids=[str(item["unit_id"]) for item in units["units"]],
        lead_ids=[str(item["lead_id"]) for item in leads["leads"]],
        category="requirements",
        proposition_type="duty",
        disposition="covered",
        elements=_elements(),
        claim_ids=["claim-first"],
    )
    review = evaluate_proposition_coverage(
        units,
        leads,
        _draft(source, claims=[claim], rows=[row], visible_claim_ids=["claim-first"]),
        [source],
    )
    assert review["valid"] is False
    assert "COVERAGE_EVIDENCE_OUTSIDE_TARGET" in {
        issue["code"] for issue in review["issues"]
    }


def test_covered_claim_must_be_visible_in_attorney_brief() -> None:
    source = _source(FIRST_DUTY)
    source_payload = source.model_dump(mode="json")
    units = build_source_unit_inventory([source_payload])
    leads = build_evidence_inventory([source_payload])
    claim = DraftClaim(
        claim_id="claim-first",
        text=FIRST_DUTY,
        kind=ClaimKind.SOURCE_SUPPORTED,
        proposed_citations=[ProposedCitation(source_id="src_rule", quote=FIRST_DUTY)],
    )
    row = DraftPropositionCoverage(
        coverage_id="coverage-first",
        unit_ids=[str(item["unit_id"]) for item in units["units"]],
        lead_ids=[str(item["lead_id"]) for item in leads["leads"]],
        category="requirements",
        proposition_type="duty",
        disposition="covered",
        elements=_elements(),
        claim_ids=["claim-first"],
    )
    review = evaluate_proposition_coverage(
        units,
        leads,
        _draft(source, claims=[claim], rows=[row], visible_claim_ids=[]),
        [source],
    )
    assert review["valid"] is False
    assert "COVERAGE_CLAIM_NOT_VISIBLE" in {
        issue["code"] for issue in review["issues"]
    }


def test_valid_multi_unit_cross_reference_can_use_multiple_exact_claims() -> None:
    source = _source(f"{FIRST_DUTY}\n\n{SECOND_DUTY}")
    units, leads = _inventories(source)
    claims = [
        _claim("claim-first", FIRST_DUTY),
        _claim("claim-second", SECOND_DUTY),
    ]
    row = _covered_row(
        units,
        leads,
        coverage_id="coverage-cross-reference",
        claim_ids=["claim-first", "claim-second"],
    )

    review = evaluate_proposition_coverage(
        units,
        leads,
        _draft(
            source,
            claims=claims,
            rows=[row],
            visible_claim_ids=["claim-first", "claim-second"],
        ),
        [source],
    )

    assert review["valid"] is True
    assert review["issues"] == []
    assert review["disposition_counts"] == {"covered": 1}
    assert all(result["status"] == "mapped" for result in review["units"])
    assert all(result["status"] == "mapped" for result in review["leads"])


def test_covered_row_accepts_a_target_bound_partial_gap() -> None:
    source = _source(FIRST_DUTY)
    units, leads = _inventories(source)
    elements = _elements().model_copy(
        update={"timing": DraftCoverageElement(status="not_established")}
    )
    row = _covered_row(
        units,
        leads,
        claim_ids=["claim-first"],
        elements=elements,
        gap_codes=["REGISTER_TIMING_NOT_ESTABLISHED"],
    )
    draft = _draft(
        source,
        claims=[_claim("claim-first", FIRST_DUTY)],
        rows=[row],
        visible_claim_ids=["claim-first"],
    ).model_copy(
        update={
            "gaps": [
                DraftGap(
                    code="REGISTER_TIMING_NOT_ESTABLISHED",
                    message="The retained rule does not establish timing.",
                    category="requirements",
                    source_ids=["src_rule"],
                )
            ]
        }
    )

    review = evaluate_proposition_coverage(units, leads, draft, [source])

    assert review["valid"] is True
    assert review["issues"] == []


def test_pure_gap_row_validates_category_and_target_sources() -> None:
    source = _source(FIRST_DUTY)
    units, leads = _inventories(source)
    row = DraftPropositionCoverage(
        coverage_id="coverage-rule-gap",
        unit_ids=_all_ids(units, "units", "unit_id"),
        lead_ids=_all_ids(leads, "leads", "lead_id"),
        category="requirements",
        proposition_type="duty",
        disposition="gap",
        gap_codes=["RULE_TEXT_INCOMPLETE"],
        rationale="The retained excerpt does not contain the incorporated schedule.",
    )
    draft = _draft(source, claims=[], rows=[row], visible_claim_ids=[]).model_copy(
        update={
            "gaps": [
                DraftGap(
                    code="RULE_TEXT_INCOMPLETE",
                    message="The incorporated schedule was not retained.",
                    category="requirements",
                    source_ids=["src_rule"],
                )
            ]
        }
    )

    review = evaluate_proposition_coverage(units, leads, draft, [source])

    assert review["valid"] is True
    assert review["disposition_counts"] == {"gap": 1}


def test_not_material_row_needs_no_semantic_materiality_inference() -> None:
    source = _source(FIRST_DUTY)
    units, leads = _inventories(source)
    row = DraftPropositionCoverage(
        coverage_id="coverage-navigation",
        unit_ids=_all_ids(units, "units", "unit_id"),
        lead_ids=_all_ids(leads, "leads", "lead_id"),
        category="other",
        proposition_type="other",
        disposition="not_material",
        rationale="The host determined that this navigation text is outside the question.",
    )

    review = evaluate_proposition_coverage(
        units,
        leads,
        _draft(source, claims=[], rows=[row], visible_claim_ids=[]),
        [source],
    )

    assert review["valid"] is True
    assert review["rows"][0]["rationale"] == row.rationale


@pytest.mark.parametrize("disposition", ["gap", "not_material"])
def test_composite_projects_strict_lead_dispositions_without_duplicate_reviews(
    disposition: str,
) -> None:
    source = _source(FIRST_DUTY)
    units, leads = _inventories(source)
    lead_items = leads["leads"]
    assert isinstance(lead_items, list)
    assert any(item["review_required"] is True for item in lead_items)
    gap_code = "REGISTER_RULE_NOT_ESTABLISHED"
    row = DraftPropositionCoverage(
        coverage_id=f"coverage-{disposition}",
        unit_ids=_all_ids(units, "units", "unit_id"),
        lead_ids=_all_ids(leads, "leads", "lead_id"),
        category="requirements",
        proposition_type="duty",
        disposition=disposition,
        gap_codes=[gap_code] if disposition == "gap" else [],
        rationale=(
            "The retained source does not establish the complete register rule."
            if disposition == "gap"
            else "The register sentence is outside the synthetic research question."
        ),
    )
    draft = _draft(source, claims=[], rows=[row], visible_claim_ids=[])
    if disposition == "gap":
        draft = draft.model_copy(
            update={
                "gaps": [
                    DraftGap(
                        code=gap_code,
                        message="The complete register rule is not established.",
                        category="requirements",
                        source_ids=[source.source_id],
                    )
                ]
            }
        )
    before = draft.model_dump(mode="json")

    proposition = evaluate_proposition_coverage(units, leads, draft, [source])
    legacy = evaluate_provision_recall(leads, draft, [source])
    closure = evaluate_coverage_closure(leads, units, draft, [source])

    assert proposition["valid"] is True
    assert legacy["valid"] is False
    assert closure["valid"] is True
    assert closure["proposition_coverage"] == proposition
    assert closure["lead_recall"]["valid"] is True
    assert closure["lead_recall"]["resolved_counts"] == {disposition: 1}
    assert draft.lead_reviews == []
    assert draft.model_dump(mode="json") == before


def test_composite_projects_multiple_rows_with_gap_precedence_and_sorted_unions(
) -> None:
    source = _source(FIRST_DUTY)
    units, leads = _inventories(source)
    unit_ids = _all_ids(units, "units", "unit_id")
    lead_ids = _all_ids(leads, "leads", "lead_id")
    assert len(lead_ids) == 1
    gap_codes = ["REGISTER_DETAIL_Z_NOT_ESTABLISHED", "REGISTER_DETAIL_A_NOT_ESTABLISHED"]
    rows = [
        DraftPropositionCoverage(
            coverage_id="coverage-gap-z",
            unit_ids=unit_ids,
            lead_ids=lead_ids,
            category="requirements",
            proposition_type="duty",
            disposition="gap",
            gap_codes=[gap_codes[0]],
            rationale="The retained source omits register detail Z.",
        ),
        DraftPropositionCoverage(
            coverage_id="coverage-not-material",
            lead_ids=lead_ids,
            category="requirements",
            proposition_type="duty",
            disposition="not_material",
            rationale="The sentence is outside the narrowed synthetic question.",
        ),
        DraftPropositionCoverage(
            coverage_id="coverage-gap-a",
            lead_ids=lead_ids,
            category="requirements",
            proposition_type="duty",
            disposition="gap",
            gap_codes=[gap_codes[1]],
            rationale="The retained source omits register detail A.",
        ),
    ]
    draft = _draft(source, claims=[], rows=rows, visible_claim_ids=[]).model_copy(
        update={
            "gaps": [
                DraftGap(
                    code=code,
                    message=f"The retained source omits {code}.",
                    category="requirements",
                    source_ids=[source.source_id],
                )
                for code in gap_codes
            ],
            "lead_reviews": [
                DraftLeadReview(
                    lead_id=lead_ids[0],
                    disposition="not_material",
                    rationale="This contradictory host review must be ignored.",
                )
            ],
        }
    )
    before = draft.model_dump(mode="json")

    closure = evaluate_coverage_closure(leads, units, draft, [source])

    assert closure["valid"] is True
    assert closure["proposition_coverage"]["valid"] is True
    assert closure["lead_recall"]["valid"] is True
    assert closure["lead_recall"]["resolved_counts"] == {"gap": 1}
    assert closure["lead_recall"]["leads"] == [
        {
            "lead_id": lead_ids[0],
            "status": "gap",
            "related_ids": sorted(gap_codes),
            "rationale": (
                "Projected from strict proposition coverage rows: "
                "coverage-gap-a, coverage-gap-z."
            ),
        }
    ]
    assert draft.model_dump(mode="json") == before
    assert evaluate_coverage_closure(leads, units, draft, [source]) == closure


def test_unknown_unit_and_lead_targets_are_bounded_separate_defects() -> None:
    source = _source(FIRST_DUTY)
    units, leads = _inventories(source)
    row = _covered_row(units, leads).model_copy(
        update={
            "unit_ids": [*_all_ids(units, "units", "unit_id"), "unit_unknown"],
            "lead_ids": [*_all_ids(leads, "leads", "lead_id"), "lead_unknown"],
        }
    )
    draft = _draft(
        source,
        claims=[_claim("claim-all", FIRST_DUTY)],
        rows=[row],
        visible_claim_ids=["claim-all"],
    )

    review = evaluate_proposition_coverage(units, leads, draft, [source])
    unknown = [
        issue for issue in review["issues"] if issue["code"] == "COVERAGE_TARGET_UNKNOWN"
    ]

    assert len(unknown) == 2
    assert {tuple(issue["related_ids"]) for issue in unknown} == {
        ("coverage-all", "lead_unknown"),
        ("coverage-all", "unit_unknown"),
    }


def test_unknown_and_analysis_claims_use_distinct_diagnostics_without_cascade() -> None:
    source = _source(FIRST_DUTY)
    units, leads = _inventories(source)
    analysis_claim = _claim(
        "claim-analysis", FIRST_DUTY, kind=ClaimKind.ANALYSIS
    )
    row = _covered_row(
        units,
        leads,
        claim_ids=["claim-analysis", "claim-unknown"],
    )
    draft = _draft(
        source,
        claims=[analysis_claim],
        rows=[row],
        visible_claim_ids=["claim-analysis"],
    )

    review = evaluate_proposition_coverage(units, leads, draft, [source])

    assert {issue["code"] for issue in review["issues"]} == {
        "COVERAGE_CLAIM_UNKNOWN",
        "COVERAGE_CLAIM_NOT_SOURCE_SUPPORTED",
    }


def test_every_covered_claim_must_resolve_at_least_one_exact_citation() -> None:
    source = _source(FIRST_DUTY)
    units, leads = _inventories(source)
    unresolved_claim = DraftClaim(
        claim_id="claim-unresolved",
        text="The controller must retain a separate schedule.",
        kind=ClaimKind.SOURCE_SUPPORTED,
        proposed_citations=[
            ProposedCitation(
                source_id="src_rule",
                quote="The controller must retain a separate schedule.",
            )
        ],
    )
    row = _covered_row(
        units,
        leads,
        claim_ids=["claim-all", "claim-unresolved"],
    )
    draft = _draft(
        source,
        claims=[_claim("claim-all", FIRST_DUTY), unresolved_claim],
        rows=[row],
        visible_claim_ids=["claim-all", "claim-unresolved"],
    )

    review = evaluate_proposition_coverage(units, leads, draft, [source])

    assert review["valid"] is False
    assert [
        issue
        for issue in review["issues"]
        if issue["code"] == "COVERAGE_EVIDENCE_OUTSIDE_TARGET"
        and issue["related_ids"] == ["claim-unresolved", "coverage-all"]
    ]


@pytest.mark.parametrize("lead_category", ["scope", "duties"])
def test_covered_or_gap_lead_categories_require_exact_controlled_match(
    lead_category: str,
) -> None:
    source = _source(FIRST_DUTY)
    units, leads = _inventories(source)
    mutated_leads = deepcopy(leads)
    raw_leads = mutated_leads["leads"]
    assert isinstance(raw_leads, list)
    raw_leads[0]["issue_category"] = lead_category
    row = _covered_row(units, mutated_leads)
    draft = _draft(
        source,
        claims=[_claim("claim-all", FIRST_DUTY)],
        rows=[row],
        visible_claim_ids=["claim-all"],
    )

    review = evaluate_proposition_coverage(units, mutated_leads, draft, [source])

    assert "COVERAGE_ROW_INVALID" in {
        issue["code"] for issue in review["issues"]
    }


def test_gap_source_identifiers_must_exactly_match_all_row_target_sources() -> None:
    source = _source(FIRST_DUTY)
    units, leads = _inventories(source)
    row = DraftPropositionCoverage(
        coverage_id="coverage-gap",
        unit_ids=_all_ids(units, "units", "unit_id"),
        lead_ids=_all_ids(leads, "leads", "lead_id"),
        category="requirements",
        proposition_type="duty",
        disposition="gap",
        gap_codes=["RULE_GAP"],
        rationale="The incorporated source is absent.",
    )
    draft = _draft(source, claims=[], rows=[row], visible_claim_ids=[]).model_copy(
        update={
            "gaps": [
                DraftGap(
                    code="RULE_GAP",
                    message="The incorporated source is absent.",
                    category="requirements",
                    source_ids=["src_neighbor"],
                )
            ]
        }
    )

    review = evaluate_proposition_coverage(units, leads, draft, [source])

    assert {issue["code"] for issue in review["issues"]} == {
        "COVERAGE_GAP_INVALID"
    }


def test_not_established_elements_require_a_valid_authored_row_gap() -> None:
    source = _source(FIRST_DUTY)
    units, leads = _inventories(source)
    elements = _elements().model_copy(
        update={"timing": DraftCoverageElement(status="not_established")}
    )
    row = _covered_row(
        units,
        leads,
        claim_ids=["claim-first"],
        elements=elements,
        gap_codes=["MISSING_TIMING_GAP"],
    )
    draft = _draft(
        source,
        claims=[_claim("claim-first", FIRST_DUTY)],
        rows=[row],
        visible_claim_ids=["claim-first"],
    )

    review = evaluate_proposition_coverage(units, leads, draft, [source])

    assert {issue["code"] for issue in review["issues"]} == {
        "COVERAGE_GAP_INVALID",
        "COVERAGE_ELEMENT_INCOMPLETE",
    }
    incomplete = [
        issue
        for issue in review["issues"]
        if issue["code"] == "COVERAGE_ELEMENT_INCOMPLETE"
    ]
    assert incomplete[0]["related_ids"] == ["coverage-all", "timing"]


def test_duplicate_coverage_claim_gap_and_inventory_ids_are_diagnosed() -> None:
    source = _source(FIRST_DUTY)
    units, leads = _inventories(source)
    row = _covered_row(units, leads)
    duplicate_row_draft = _draft(
        source,
        claims=[_claim("claim-all", FIRST_DUTY)],
        rows=[row],
        visible_claim_ids=["claim-all"],
    ).model_copy(update={"proposition_coverage": [row, row]})

    duplicate_claim = _claim("claim-all", FIRST_DUTY)
    duplicate_claim_draft = _draft(
        source,
        claims=[duplicate_claim, duplicate_claim],
        rows=[row],
        visible_claim_ids=["claim-all"],
    )

    duplicate_gap_row = row.model_copy(
        update={
            "elements": _elements().model_copy(
                update={"timing": DraftCoverageElement(status="not_established")}
            ),
            "gap_codes": ["DUPLICATE_GAP"],
        }
    )
    duplicate_gap = DraftGap(
        code="DUPLICATE_GAP",
        message="Timing is absent.",
        category="requirements",
        source_ids=["src_rule"],
    )
    duplicate_gap_draft = _draft(
        source,
        claims=[_claim("claim-all", FIRST_DUTY)],
        rows=[duplicate_gap_row],
        visible_claim_ids=["claim-all"],
    ).model_copy(update={"gaps": [duplicate_gap, duplicate_gap]})

    duplicate_units = deepcopy(units)
    raw_units = duplicate_units["units"]
    assert isinstance(raw_units, list)
    raw_units.append(deepcopy(raw_units[0]))

    reviews = [
        evaluate_proposition_coverage(units, leads, duplicate_row_draft, [source]),
        evaluate_proposition_coverage(units, leads, duplicate_claim_draft, [source]),
        evaluate_proposition_coverage(units, leads, duplicate_gap_draft, [source]),
        evaluate_proposition_coverage(duplicate_units, leads, duplicate_row_draft, [source]),
    ]

    assert all(review["valid"] is False for review in reviews)
    assert all(
        "COVERAGE_ROW_INVALID"
        in {issue["code"] for issue in review["issues"]}
        or "COVERAGE_GAP_INVALID"
        in {issue["code"] for issue in review["issues"]}
        for review in reviews
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "duplicate_target",
        "missing_covered_claim",
        "invalid_proposition_type",
        "missing_gap_code",
        "not_material_claim",
        "not_material_rationale",
    ],
)
def test_corrupted_typed_rows_fail_closed_with_bounded_row_diagnostics(
    mutation: str,
) -> None:
    source = _source(FIRST_DUTY)
    units, leads = _inventories(source)
    row = _covered_row(units, leads)
    claims = [_claim("claim-all", FIRST_DUTY)]
    if mutation == "duplicate_target":
        unit_id = _all_ids(units, "units", "unit_id")[0]
        row = row.model_copy(update={"unit_ids": [unit_id, unit_id]})
    elif mutation == "missing_covered_claim":
        row = row.model_copy(update={"claim_ids": []})
    elif mutation == "invalid_proposition_type":
        row = row.model_copy(update={"proposition_type": "obligation"})
    elif mutation == "missing_gap_code":
        row = DraftPropositionCoverage(
            coverage_id="coverage-gap",
            unit_ids=_all_ids(units, "units", "unit_id"),
            lead_ids=_all_ids(leads, "leads", "lead_id"),
            category="requirements",
            proposition_type="duty",
            disposition="gap",
            gap_codes=["SOURCE_GAP"],
            rationale="The incorporated source was not retained.",
        ).model_copy(update={"gap_codes": []})
    else:
        row = DraftPropositionCoverage(
            coverage_id="coverage-navigation",
            unit_ids=_all_ids(units, "units", "unit_id"),
            lead_ids=_all_ids(leads, "leads", "lead_id"),
            category="other",
            proposition_type="other",
            disposition="not_material",
            rationale="The host found the navigation text outside the question.",
        )
        if mutation == "not_material_claim":
            row = row.model_copy(update={"claim_ids": ["claim-all"]})
        else:
            row = row.model_copy(update={"rationale": None})
    draft = _draft(
        source,
        claims=claims,
        rows=[_covered_row(units, leads)],
        visible_claim_ids=[claim.claim_id for claim in claims],
    ).model_copy(update={"proposition_coverage": [row]})

    review = evaluate_proposition_coverage(units, leads, draft, [source])

    assert review["valid"] is False
    assert "COVERAGE_ROW_INVALID" in {
        issue["code"] for issue in review["issues"]
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("coverage_id", ["coverage-all"]),
        ("unit_ids", None),
        ("unit_ids", [["unit-nested"]]),
        ("lead_ids", None),
        ("claim_ids", None),
        ("gap_codes", None),
        ("elements", "bad"),
        ("rationale", ["not", "text"]),
    ],
)
def test_validation_bypassing_malformed_row_fields_return_bounded_review(
    field: str,
    value: object,
) -> None:
    source = _source(FIRST_DUTY)
    units, leads = _inventories(source)
    valid_row = _covered_row(units, leads)
    malformed_row = valid_row.model_copy(update={field: value})
    draft = _draft(
        source,
        claims=[_claim("claim-all", FIRST_DUTY)],
        rows=[valid_row],
        visible_claim_ids=["claim-all"],
    ).model_copy(update={"proposition_coverage": [malformed_row]})

    review = evaluate_proposition_coverage(units, leads, draft, [source])

    assert review["valid"] is False
    assert "COVERAGE_ROW_INVALID" in {
        issue["code"] for issue in review["issues"]
    }
    assert review["issues"] == sorted(
        review["issues"],
        key=lambda issue: (
            issue["code"], tuple(issue["related_ids"]), issue["message"]
        ),
    )


def test_composite_closure_contains_malformed_row_diagnostic_and_stable_hash() -> None:
    source = _source(FIRST_DUTY)
    units, leads = _inventories(source)
    valid_row = _covered_row(units, leads)
    malformed_row = valid_row.model_copy(update={"unit_ids": None})
    draft = _draft(
        source,
        claims=[_claim("claim-all", FIRST_DUTY)],
        rows=[valid_row],
        visible_claim_ids=["claim-all"],
    ).model_copy(update={"proposition_coverage": [malformed_row]})

    closure = evaluate_coverage_closure(leads, units, draft, [source])
    hash_payload = dict(closure)
    coverage_hash = hash_payload.pop("coverage_review_hash")

    assert closure["valid"] is False
    proposition = closure["proposition_coverage"]
    assert proposition["valid"] is False
    assert "COVERAGE_ROW_INVALID" in {
        issue["code"] for issue in proposition["issues"]
    }
    assert coverage_hash == sha256_digest(canonical_json_bytes(hash_payload))
    assert evaluate_coverage_closure(leads, units, draft, [source]) == closure


def test_malformed_new_contract_fails_closed_without_host_lead_review_fallback() -> None:
    source = _source(FIRST_DUTY)
    units, leads = _inventories(source)
    gap_code = "REGISTER_RULE_NOT_ESTABLISHED"
    valid_gap_row = DraftPropositionCoverage(
        coverage_id="coverage-gap",
        unit_ids=_all_ids(units, "units", "unit_id"),
        lead_ids=_all_ids(leads, "leads", "lead_id"),
        category="requirements",
        proposition_type="duty",
        disposition="gap",
        gap_codes=[gap_code],
        rationale="The complete register rule is not established.",
    )
    malformed_row = valid_gap_row.model_copy(update={"lead_ids": None})
    lead_id = _all_ids(leads, "leads", "lead_id")[0]
    draft = _draft(source, claims=[], rows=[valid_gap_row], visible_claim_ids=[]).model_copy(
        update={
            "gaps": [
                DraftGap(
                    code=gap_code,
                    message="The complete register rule is not established.",
                    category="requirements",
                    source_ids=[source.source_id],
                )
            ],
            "lead_reviews": [
                DraftLeadReview(
                    lead_id=lead_id,
                    disposition="not_material",
                    rationale="A duplicate host review must not rescue malformed coverage.",
                )
            ],
            "proposition_coverage": [malformed_row],
        }
    )
    before = draft.model_dump(mode="json")

    closure = evaluate_coverage_closure(leads, units, draft, [source])

    assert closure["valid"] is False
    assert closure["proposition_coverage"]["valid"] is False
    assert closure["lead_recall"]["valid"] is False
    assert "COVERAGE_ROW_INVALID" in {
        issue["code"] for issue in closure["proposition_coverage"]["issues"]
    }
    assert draft.model_dump(mode="json") == before
    assert evaluate_coverage_closure(leads, units, draft, [source]) == closure


def test_validation_bypassing_nested_element_status_is_revalidated() -> None:
    source = _source(FIRST_DUTY)
    units, leads = _inventories(source)
    valid_row = _covered_row(units, leads)
    assert valid_row.elements is not None
    malformed_status = DraftCoverageElement(status="not_applicable").model_copy(
        update={"status": ["not_applicable"]}
    )
    malformed_elements = valid_row.elements.model_copy(
        update={"timing": malformed_status}
    )
    malformed_row = valid_row.model_copy(update={"elements": malformed_elements})
    draft = _draft(
        source,
        claims=[_claim("claim-all", FIRST_DUTY)],
        rows=[valid_row],
        visible_claim_ids=["claim-all"],
    ).model_copy(update={"proposition_coverage": [malformed_row]})

    review = evaluate_proposition_coverage(units, leads, draft, [source])

    assert review["valid"] is False
    assert "COVERAGE_ROW_INVALID" in {
        issue["code"] for issue in review["issues"]
    }


def test_validation_bypassing_row_missing_coverage_id_returns_bounded_review() -> None:
    source = _source(FIRST_DUTY)
    units, leads = _inventories(source)
    malformed_row = DraftPropositionCoverage.model_construct()
    draft = _draft(
        source,
        claims=[_claim("claim-all", FIRST_DUTY)],
        rows=[_covered_row(units, leads)],
        visible_claim_ids=["claim-all"],
    ).model_copy(update={"proposition_coverage": [malformed_row]})

    review = evaluate_proposition_coverage(units, leads, draft, [source])

    assert review["valid"] is False
    assert [
        issue
        for issue in review["issues"]
        if issue["message"]
        == "The proposition coverage ledger contains a malformed row."
    ] == [
        {
            "code": "COVERAGE_ROW_INVALID",
            "message": "The proposition coverage ledger contains a malformed row.",
            "related_ids": [],
        }
    ]


def test_composite_closure_hashes_row_missing_coverage_id_diagnostic() -> None:
    source = _source(FIRST_DUTY)
    units, leads = _inventories(source)
    malformed_row = DraftPropositionCoverage.model_construct()
    draft = _draft(
        source,
        claims=[_claim("claim-all", FIRST_DUTY)],
        rows=[_covered_row(units, leads)],
        visible_claim_ids=["claim-all"],
    ).model_copy(update={"proposition_coverage": [malformed_row]})

    closure = evaluate_coverage_closure(leads, units, draft, [source])
    hash_payload = dict(closure)
    coverage_hash = hash_payload.pop("coverage_review_hash")

    assert closure["valid"] is False
    assert [
        issue
        for issue in closure["proposition_coverage"]["issues"]
        if issue["message"]
        == "The proposition coverage ledger contains a malformed row."
    ] == [
        {
            "code": "COVERAGE_ROW_INVALID",
            "message": "The proposition coverage ledger contains a malformed row.",
            "related_ids": [],
        }
    ]
    assert coverage_hash == sha256_digest(canonical_json_bytes(hash_payload))
    assert evaluate_coverage_closure(leads, units, draft, [source]) == closure


def test_brief_locations_cover_every_legal_analysis_block_shape() -> None:
    source = _source(FIRST_DUTY)
    units, leads = _inventories(source)
    claim = _claim("claim-all", FIRST_DUTY)
    row = _covered_row(units, leads)
    paragraph = BriefBlock(
        kind="paragraph",
        purpose="legal_analysis",
        text="Supported paragraph.",
        claim_ids=["claim-all"],
    )
    bullet_list = BriefBlock(
        kind="bullet_list",
        purpose="legal_analysis",
        items=[BriefItem(text="Supported list item.", claim_ids=["claim-all"])],
    )
    table = BriefBlock(
        kind="table",
        purpose="legal_analysis",
        columns=["Rule", "Effect"],
        rows=[
            BriefTableRow(
                cells=["Register", "Required"], claim_ids=["claim-all"]
            )
        ],
    )
    brief = AttorneyBrief(
        structure_profile="regulatory-walk-v1",
        executive_summary=[paragraph, bullet_list, table],
        sections=[
            BriefSection(
                section_id="requirements",
                title="Requirements Walk",
                blocks=[paragraph, bullet_list, table],
                subsections=[
                    BriefSubsection(
                        subsection_id="details",
                        title="Detailed Rule",
                        blocks=[paragraph, bullet_list, table],
                    )
                ],
            )
        ],
    )
    draft = _draft(
        source,
        claims=[claim],
        rows=[row],
        visible_claim_ids=[],
    ).model_copy(update={"brief": brief})

    review = evaluate_proposition_coverage(units, leads, draft, [source])

    assert review["valid"] is True
    assert review["rows"][0]["brief_locations"] == [
        "brief.executive_summary[0]",
        "brief.executive_summary[1].items[0]",
        "brief.executive_summary[2].rows[0]",
        "brief.sections[0].blocks[0]",
        "brief.sections[0].blocks[1].items[0]",
        "brief.sections[0].blocks[2].rows[0]",
        "brief.sections[0].subsections[0].blocks[0]",
        "brief.sections[0].subsections[0].blocks[1].items[0]",
        "brief.sections[0].subsections[0].blocks[2].rows[0]",
    ]


def test_non_legal_analysis_bindings_do_not_make_claims_visible() -> None:
    source = _source(FIRST_DUTY)
    units, leads = _inventories(source)
    row = _covered_row(units, leads)
    application = BriefBlock(
        kind="paragraph",
        purpose="application",
        text="Apply the supported rule.",
        claim_ids=["claim-all"],
    )
    brief = AttorneyBrief(
        structure_profile="regulatory-walk-v1",
        executive_summary=[application],
        sections=[
            BriefSection(
                section_id="application",
                title="Application",
                blocks=[application],
            )
        ],
    )
    draft = _draft(
        source,
        claims=[_claim("claim-all", FIRST_DUTY)],
        rows=[row],
        visible_claim_ids=[],
    ).model_copy(update={"brief": brief})

    review = evaluate_proposition_coverage(units, leads, draft, [source])

    assert {issue["code"] for issue in review["issues"]} == {
        "COVERAGE_CLAIM_NOT_VISIBLE"
    }
    assert review["rows"][0]["brief_locations"] == []


def test_malformed_typed_brief_cannot_make_a_covered_claim_visible() -> None:
    source = _source(FIRST_DUTY)
    units, leads = _inventories(source)
    malformed_paragraph = BriefBlock.model_construct(
        kind=BriefBlockKind.PARAGRAPH,
        purpose=BriefBlockPurpose.LEGAL_ANALYSIS,
        text=None,
        finding_ids=[],
        claim_ids=["claim-all"],
        enforcement_trigger_claim_ids=[],
        enforcement_consequence_claim_ids=[],
        atom_ids=["atom-rule"],
        relationship_ids=["relationship-rule"],
        items=[],
        columns=[],
        rows=[],
    )
    brief = AttorneyBrief.model_construct(
        structure_profile="regulatory-walk-v1",
        executive_summary=[malformed_paragraph],
        sections=[
            BriefSection(
                section_id="context",
                title="Context",
                blocks=[
                    BriefBlock(
                        kind="paragraph",
                        purpose="limitation",
                        text="Neutral context.",
                    )
                ],
            )
        ],
    )
    draft = _draft(
        source,
        claims=[_claim("claim-all", FIRST_DUTY)],
        rows=[_covered_row(units, leads)],
        visible_claim_ids=["claim-all"],
    ).model_copy(update={"brief": brief})
    before = draft.model_dump(mode="python", warnings=False)

    review = evaluate_proposition_coverage(units, leads, draft, [source])

    assert review["valid"] is False
    assert {issue["code"] for issue in review["issues"]} == {
        "COVERAGE_CLAIM_NOT_VISIBLE"
    }
    assert review["rows"][0]["brief_locations"] == []
    assert draft.model_dump(mode="python", warnings=False) == before


@pytest.mark.parametrize(
    "mutation",
    [
        "draft_contract",
        "unit_version",
        "unit_collection",
        "unit_slice",
        "unit_count",
        "lead_version",
        "lead_collection",
        "lead_slice",
    ],
)
def test_contract_version_and_malformed_inventory_fail_with_bounded_diagnostics(
    mutation: str,
) -> None:
    source = _source(FIRST_DUTY)
    units, leads = _inventories(source)
    row = _covered_row(units, leads)
    draft = _draft(
        source,
        claims=[_claim("claim-all", FIRST_DUTY)],
        rows=[row],
        visible_claim_ids=["claim-all"],
    )
    mutated_units = deepcopy(units)
    mutated_leads = deepcopy(leads)
    if mutation == "draft_contract":
        draft = draft.model_copy(update={"coverage_contract_version": "wrong-version"})
    elif mutation == "unit_version":
        mutated_units["inventory_version"] = "wrong-version"
    elif mutation == "unit_collection":
        mutated_units["units"] = {"not": "a list"}
    elif mutation == "unit_slice":
        raw_units = mutated_units["units"]
        assert isinstance(raw_units, list)
        raw_units[0]["excerpt"] = "altered excerpt"
    elif mutation == "unit_count":
        mutated_units["unit_count"] = 99
    elif mutation == "lead_version":
        mutated_leads["inventory_version"] = "wrong-version"
    elif mutation == "lead_collection":
        mutated_leads["leads"] = {"not": "a list"}
    else:
        raw_leads = mutated_leads["leads"]
        assert isinstance(raw_leads, list)
        raw_leads[0]["start_char"] = True

    review = evaluate_proposition_coverage(
        mutated_units, mutated_leads, draft, [source]
    )

    assert review["valid"] is False
    assert "COVERAGE_ROW_INVALID" in {
        issue["code"] for issue in review["issues"]
    }
    assert all(
        set(issue) == {"code", "message", "related_ids"}
        for issue in review["issues"]
    )


def test_exact_overlap_uses_half_open_offsets_at_an_adjacent_boundary() -> None:
    source = _source(f"{FIRST_DUTY}{SECOND_DUTY}")
    units, leads = _inventories(source)
    claim = _claim("claim-first", FIRST_DUTY)
    row = _covered_row(units, leads, claim_ids=["claim-first"])
    draft = _draft(
        source,
        claims=[claim],
        rows=[row],
        visible_claim_ids=["claim-first"],
    )

    review = evaluate_proposition_coverage(units, leads, draft, [source])
    outside = [
        issue
        for issue in review["issues"]
        if issue["code"] == "COVERAGE_EVIDENCE_OUTSIDE_TARGET"
    ]

    second_units = set(_target_ids(units, SECOND_DUTY, key="units", id_key="unit_id"))
    assert outside
    assert any(second_units.intersection(issue["related_ids"]) for issue in outside)


def test_multi_source_rows_require_exact_evidence_for_each_source_target() -> None:
    first = _source(FIRST_DUTY)
    second = _source(SECOND_DUTY).model_copy(
        update={
            "source_id": "src_notice",
            "origin": "notice.txt",
            "display_name": "Synthetic Notice",
        }
    )
    payloads = [first.model_dump(mode="json"), second.model_dump(mode="json")]
    units = build_source_unit_inventory(payloads)
    leads = build_evidence_inventory(payloads)
    row = _covered_row(
        units,
        leads,
        coverage_id="coverage-two-sources",
        claim_ids=["claim-first", "claim-second"],
    )
    draft = _draft(
        first,
        claims=[
            _claim("claim-first", FIRST_DUTY),
            _claim("claim-second", SECOND_DUTY, source_id="src_notice"),
        ],
        rows=[row],
        visible_claim_ids=["claim-first", "claim-second"],
    )

    review = evaluate_proposition_coverage(units, leads, draft, [first, second])

    assert review["valid"] is True


def test_outputs_issues_and_composite_hash_are_deterministic_and_legacy_is_immutable() -> None:
    source = _source(f"{FIRST_DUTY}\n\n{SECOND_DUTY}")
    units, leads = _inventories(source)
    claims = [_claim("claim-first", FIRST_DUTY), _claim("claim-second", SECOND_DUTY)]
    first_row = DraftPropositionCoverage(
        coverage_id="coverage-first",
        unit_ids=_target_ids(units, FIRST_DUTY, key="units", id_key="unit_id"),
        lead_ids=_target_ids(leads, FIRST_DUTY, key="leads", id_key="lead_id"),
        category="requirements",
        proposition_type="duty",
        disposition="covered",
        elements=_elements(),
        claim_ids=["claim-first"],
    )
    second_row = DraftPropositionCoverage(
        coverage_id="coverage-second",
        unit_ids=_target_ids(units, SECOND_DUTY, key="units", id_key="unit_id"),
        lead_ids=_target_ids(leads, SECOND_DUTY, key="leads", id_key="lead_id"),
        category="requirements",
        proposition_type="duty",
        disposition="covered",
        elements=_elements(),
        claim_ids=["claim-second"],
    )
    draft = _draft(
        source,
        claims=claims,
        rows=[second_row, first_row],
        visible_claim_ids=["claim-second", "claim-first"],
    )
    legacy_before = evaluate_provision_recall(leads, draft, [source])
    legacy_snapshot = deepcopy(legacy_before)
    inventory_snapshot = deepcopy(leads)

    first_review = evaluate_proposition_coverage(units, leads, draft, [source])
    reordered_units = {**units, "units": list(reversed(units["units"]))}
    reordered_leads = {**leads, "leads": list(reversed(leads["leads"]))}
    reordered_draft = draft.model_copy(
        update={"proposition_coverage": [first_row, second_row]}
    )
    repeated_review = evaluate_proposition_coverage(
        reordered_units, reordered_leads, reordered_draft, [source]
    )
    closure = evaluate_coverage_closure(leads, units, draft, [source])
    closure_without_hash = dict(closure)
    coverage_hash = closure_without_hash.pop("coverage_review_hash")

    assert first_review == repeated_review
    assert [row["coverage_id"] for row in first_review["rows"]] == [
        "coverage-first",
        "coverage-second",
    ]
    assert closure["lead_recall"] == legacy_snapshot
    assert legacy_before == legacy_snapshot
    assert leads == inventory_snapshot
    assert coverage_hash == sha256_digest(canonical_json_bytes(closure_without_hash))
    assert evaluate_coverage_closure(leads, units, draft, [source]) == closure


def _v2_dispatch_case() -> tuple[
    dict[str, object], dict[str, object], AnalysisDraft, list[SourceRecord]
]:
    source = _source(FIRST_DUTY)
    units, leads = _inventories(source)
    unit_ids = _all_ids(units, "units", "unit_id")
    lead_ids = _all_ids(leads, "leads", "lead_id")
    elements = {
        field_name: (
            DraftAtomElement(
                status="stated",
                text=f"Synthetic {field_name.replace('_', ' ')}",
                claim_ids=["claim-all"],
            )
            if field_name in {"actor", "modality", "operative_action", "object"}
            else DraftAtomElement(status="not_applicable")
        )
        for field_name in DraftRuleAtomElements.model_fields
    }
    atom = DraftRuleAtom(
        atom_id="atom-duty",
        unit_ids=unit_ids,
        lead_ids=lead_ids,
        category="requirements",
        proposition_type="duty",
        materiality="material",
        elements=DraftRuleAtomElements(**elements),
        omission_rationale="Omission would hide the synthetic duty.",
    )
    dimensions = DraftUnitReviewDimensions(
        **{
            field_name: DraftDimensionReview(
                disposition="mapped", atom_ids=["atom-duty"]
            )
            if field_name == "duties_rights_prohibitions"
            else DraftDimensionReview(disposition="not_present")
            for field_name in DraftUnitReviewDimensions.model_fields
        }
    )
    block = BriefBlock(
        kind="paragraph",
        purpose="legal_analysis",
        text="The controller must maintain the synthetic register.",
        claim_ids=["claim-all"],
        atom_ids=["atom-duty"],
    )
    draft = AnalysisDraft(
        coverage_contract_version="proposition-coverage-v2",
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
                title="Written register",
                jurisdiction="US",
                authority="Synthetic Rule",
                severity=Severity.INFO,
                practical_implication="Maintain the synthetic register.",
                claims=[_claim("claim-all", FIRST_DUTY)],
            )
        ],
        unit_reviews=[
            DraftUnitReview(unit_id=unit_id, dimensions=dimensions)
            for unit_id in unit_ids
        ],
        lead_dispositions_v2=[
            DraftLeadDispositionV2(
                lead_id=lead_id,
                disposition="mapped",
                atom_ids=["atom-duty"],
            )
            for lead_id in lead_ids
        ],
        rule_atoms=[atom],
        brief=AttorneyBrief(
            structure_profile="regulatory-walk-v1",
            executive_summary=[block],
            sections=[
                BriefSection(
                    section_id="requirements",
                    title="Requirements Walk",
                    blocks=[block],
                )
            ],
        ),
    )
    return units, leads, draft, [source]


def test_version_dispatch_routes_v2_to_schema_three() -> None:
    units, leads, draft, sources = _v2_dispatch_case()

    review = evaluate_coverage_closure(leads, units, draft, sources)

    assert review["schema_version"] == "3.0"
    assert review["coverage_contract_version"] == "proposition-coverage-v2"
    assert review["valid"] is True
    assert set(review) == {
        "schema_version",
        "coverage_contract_version",
        "valid",
        "target_review",
        "rule_graph",
        "counts",
        "issues",
        "coverage_review_hash",
    }


@pytest.mark.parametrize(
    ("version_case", "expected_valid"),
    [("missing", False), ("null", False), ("v1", True), ("unknown", False)],
)
def test_dispatch_preserves_v1_branch_for_missing_null_v1_and_unknown_versions(
    version_case: str,
    expected_valid: bool,
) -> None:
    source = _source(FIRST_DUTY)
    units, leads = _inventories(source)
    v1 = _draft(
        source,
        claims=[_claim("claim-all", FIRST_DUTY)],
        rows=[_covered_row(units, leads)],
        visible_claim_ids=["claim-all"],
    )
    if version_case == "missing":
        payload = v1.model_dump(mode="python", warnings=False)
        payload.pop("coverage_contract_version")
        draft = AnalysisDraft.model_validate(payload)
    elif version_case == "null":
        draft = v1.model_copy(update={"coverage_contract_version": None})
    elif version_case == "unknown":
        draft = v1.model_copy(update={"coverage_contract_version": "proposition-coverage-v3"})
    else:
        draft = v1

    review = evaluate_coverage_closure(leads, units, draft, [source])

    assert review["schema_version"] == "2.0"
    assert review["coverage_contract_version"] == "proposition-coverage-v1"
    assert review["valid"] is expected_valid
    assert set(review) == {
        "schema_version",
        "coverage_contract_version",
        "valid",
        "lead_recall",
        "proposition_coverage",
        "coverage_review_hash",
    }
    if version_case == "v1":
        assert review["coverage_review_hash"] == (
            "4ffdf6a22ac273ab5803a55f2b4689f1885003e2cb68043a53e6c9f2c9a64e35"
        )
