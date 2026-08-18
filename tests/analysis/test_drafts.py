from copy import deepcopy

import pytest
from pydantic import ValidationError

from regulatory_harvest import analysis as analysis_module
from regulatory_harvest.analysis import (
    AnalysisDraft,
    DraftCoverageElement,
    DraftCoverageElements,
    DraftPropositionCoverage,
)
from regulatory_harvest.models import (
    AttorneyBrief,
    CoverageDisposition,
    CoverageElementStatus,
    PropositionType,
)
from regulatory_harvest.models import enums as enum_module


def _elements_payload(*, timing: str = "not_applicable") -> dict[str, object]:
    return {
        "subject": {"status": "stated", "text": "covered operator"},
        "operative_rule": {"status": "stated", "text": "must keep a register"},
        "object": {"status": "stated", "text": "processing activities"},
        "trigger_or_threshold": {"status": "not_applicable"},
        "conditions_or_exceptions": {"status": "not_applicable"},
        "timing": {"status": timing},
        "consequence_or_remedy": {"status": "not_applicable"},
        "authority_or_route": {"status": "not_applicable"},
    }


def _elements(*, timing: str = "not_applicable") -> DraftCoverageElements:
    return DraftCoverageElements.model_validate(_elements_payload(timing=timing))


def _covered_payload() -> dict[str, object]:
    return {
        "coverage_id": "coverage-register",
        "unit_ids": ["unit-one"],
        "category": "requirements",
        "proposition_type": "duty",
        "disposition": "covered",
        "elements": _elements_payload(),
        "claim_ids": ["claim-register"],
    }


def _atom_element(
    status: str = "not_applicable",
    *,
    text: str | None = None,
    claim_ids: list[str] | None = None,
    gap_codes: list[str] | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {"status": status}
    if text is not None:
        payload["text"] = text
    if claim_ids is not None:
        payload["claim_ids"] = claim_ids
    if gap_codes is not None:
        payload["gap_codes"] = gap_codes
    return payload


def _atom_elements(**stated: str) -> dict[str, object]:
    fields = (
        "actor",
        "modality",
        "operative_action",
        "object",
        "trigger",
        "threshold",
        "condition",
        "exception",
        "timing",
        "authority",
        "route",
        "consequence",
        "defined_term",
        "defined_meaning",
    )
    elements = {field: _atom_element() for field in fields}
    for field, text in stated.items():
        elements[field] = _atom_element(
            "stated",
            text=text,
            claim_ids=[f"claim-{field}"],
        )
    return elements


def _dimension(
    disposition: str,
    *,
    atom_ids: list[str] | None = None,
    gap_codes: list[str] | None = None,
    rationale: str | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {"disposition": disposition}
    if atom_ids is not None:
        payload["atom_ids"] = atom_ids
    if gap_codes is not None:
        payload["gap_codes"] = gap_codes
    if rationale is not None:
        payload["rationale"] = rationale
    return payload


def _v2_draft_payload() -> dict[str, object]:
    dimensions = {
        "authority_status_timing": _dimension("mapped", atom_ids=["atom-duty"]),
        "actors_scope_activities": _dimension("mapped", atom_ids=["atom-duty"]),
        "definitions_categories": _dimension("not_present"),
        "duties_rights_prohibitions": _dimension("mapped", atom_ids=["atom-duty"]),
        "triggers_thresholds": _dimension(
            "gap", gap_codes=["TRIGGER_NOT_ESTABLISHED"]
        ),
        "conditions_exceptions_defenses": _dimension(
            "mapped", atom_ids=["atom-exception"]
        ),
        "deadlines_transitions": _dimension("not_present"),
        "enforcement_remedies_consequences": _dimension(
            "not_material",
            rationale="Enforcement is outside this source unit's operative content.",
        ),
        "cross_references_dependencies": _dimension("not_present"),
    }
    duty_elements = _atom_elements(
        actor="a covered operator",
        modality="must",
        operative_action="maintain",
        object="a processing register",
    )
    duty_elements["trigger"] = _atom_element(
        "not_established", gap_codes=["TRIGGER_NOT_ESTABLISHED"]
    )
    return {
        "issues": [],
        "findings": [],
        "coverage_contract_version": "proposition-coverage-v2",
        "unit_reviews": [{"unit_id": "unit-1", "dimensions": dimensions}],
        "lead_dispositions_v2": [
            {
                "lead_id": "lead-duty",
                "disposition": "mapped",
                "atom_ids": ["atom-duty"],
            }
        ],
        "rule_atoms": [
            {
                "atom_id": "atom-duty",
                "unit_ids": ["unit-1"],
                "lead_ids": ["lead-duty"],
                "category": "requirements",
                "proposition_type": "duty",
                "materiality": "critical",
                "elements": duty_elements,
                "omission_rationale": "Omission would hide the operative duty.",
            },
            {
                "atom_id": "atom-exception",
                "unit_ids": ["unit-1"],
                "category": "requirements",
                "proposition_type": "exception",
                "materiality": "material",
                "elements": _atom_elements(exception="unless the record is legally exempt"),
                "omission_rationale": "Omission would overstate the duty's scope.",
            },
        ],
        "rule_relationships": [
            {
                "relationship_id": "relationship-exception",
                "relation_type": "exception_to",
                "source_atom_id": "atom-exception",
                "target_atom_id": "atom-duty",
                "claim_ids": ["claim-exception", "claim-relationship"],
            }
        ],
    }


def test_coverage_enums_expose_the_complete_controlled_vocabulary() -> None:
    assert [item.value for item in CoverageDisposition] == [
        "covered",
        "gap",
        "not_material",
    ]
    assert [item.value for item in CoverageElementStatus] == [
        "stated",
        "not_applicable",
        "not_established",
    ]
    assert [item.value for item in PropositionType] == [
        "status",
        "definition",
        "scope",
        "right",
        "duty",
        "prohibition",
        "exception",
        "deadline",
        "enforcement_trigger",
        "enforcement_route",
        "remedy",
        "penalty",
        "appeal",
        "implementation",
        "other",
    ]


def test_v2_enums_expose_only_the_approved_controlled_vocabularies() -> None:
    expected = {
        "UnitDimensionDisposition": ["mapped", "not_present", "gap", "not_material"],
        "LeadDispositionV2": ["mapped", "gap", "not_material"],
        "AtomMateriality": ["critical", "material", "supporting"],
        "AtomRelationshipType": [
            "qualifies",
            "exception_to",
            "deadline_for",
            "enforces",
            "triggered_by",
            "consequence_of",
            "appeals_from",
            "defines",
        ],
    }

    for name, values in expected.items():
        enum_type = getattr(enum_module, name, None)
        assert enum_type is not None, f"missing {name}"
        assert [item.value for item in enum_type] == values


def test_v2_draft_accepts_one_complete_atomic_rule_graph() -> None:
    draft = AnalysisDraft.model_validate(_v2_draft_payload())

    assert draft.coverage_contract_version == "proposition-coverage-v2"
    assert draft.unit_reviews[0].unit_id == "unit-1"
    assert draft.rule_atoms[0].atom_id == "atom-duty"
    assert draft.rule_atoms[0].claim_ids == [
        "claim-actor",
        "claim-modality",
        "claim-object",
        "claim-operative_action",
    ]
    assert draft.rule_relationships[0].relation_type.value == "exception_to"


@pytest.mark.parametrize("legacy_field", ["lead_reviews", "proposition_coverage"])
def test_v2_draft_rejects_nonempty_legacy_coverage_ledgers(
    legacy_field: str,
) -> None:
    payload = _v2_draft_payload()
    payload[legacy_field] = (
        [
            {
                "lead_id": "lead-legacy",
                "disposition": "not_material",
                "rationale": "Legacy review data cannot coexist with atomic coverage.",
            }
        ]
        if legacy_field == "lead_reviews"
        else [
            {
                "coverage_id": "coverage-legacy",
                "unit_ids": ["unit-1"],
                "category": "other",
                "proposition_type": "other",
                "disposition": "not_material",
                "rationale": "Legacy coverage data cannot coexist with atomic coverage.",
            }
        ]
    )

    with pytest.raises(
        ValidationError,
        match=(
            "proposition-coverage-v2 requires lead_reviews and "
            "proposition_coverage to be empty"
        ),
    ):
        AnalysisDraft.model_validate(payload)


@pytest.mark.parametrize(
    ("disposition", "payload"),
    [
        ("mapped", {"atom_ids": ["atom-duty"]}),
        ("gap", {"gap_codes": ["LEAD_NOT_ESTABLISHED"]}),
        ("not_material", {"rationale": "Navigation only; no operative proposition."}),
    ],
)
def test_v2_lead_disposition_accepts_each_valid_cardinality(
    disposition: str, payload: dict[str, object]
) -> None:
    draft_payload = _v2_draft_payload()
    draft_payload["lead_dispositions_v2"] = [
        {"lead_id": "lead-duty", "disposition": disposition, **payload}
    ]

    disposition_row = AnalysisDraft.model_validate(draft_payload).lead_dispositions_v2[0]

    assert disposition_row.disposition.value == disposition


@pytest.mark.parametrize(
    ("disposition", "payload"),
    [
        ("mapped", {}),
        ("mapped", {"atom_ids": ["atom-duty"], "gap_codes": ["NOT_A_GAP"]}),
        ("gap", {}),
        ("gap", {"atom_ids": ["atom-duty"], "gap_codes": ["UNRESOLVED"]}),
        ("not_material", {}),
        (
            "not_material",
            {
                "atom_ids": ["atom-duty"],
                "rationale": "Navigation only; no operative proposition.",
            },
        ),
    ],
)
def test_v2_lead_disposition_rejects_invalid_cardinality(
    disposition: str, payload: dict[str, object]
) -> None:
    draft_payload = _v2_draft_payload()
    draft_payload["lead_dispositions_v2"] = [
        {"lead_id": "lead-duty", "disposition": disposition, **payload}
    ]

    with pytest.raises(ValidationError):
        AnalysisDraft.model_validate(draft_payload)


@pytest.mark.parametrize(
    "mutation",
    [
        "mapped_without_atom",
        "mapped_with_gap",
        "gap_without_code",
        "gap_with_atom",
        "not_present_with_payload",
        "not_material_without_rationale",
        "not_material_with_atom",
        "stated_element_without_text",
        "stated_element_without_claim",
        "stated_element_with_gap",
        "not_established_element_without_gap",
        "not_established_element_with_claim",
        "not_applicable_element_with_payload",
        "atom_without_target",
        "atom_without_omission_rationale",
        "self_relationship",
        "relationship_without_claim",
        "duplicate_unit_review_id",
        "duplicate_lead_id",
        "duplicate_atom_id",
        "duplicate_relationship_id",
    ],
)
def test_v2_draft_rejects_invalid_cardinality(mutation: str) -> None:
    payload = _v2_draft_payload()
    dimensions = payload["unit_reviews"][0]["dimensions"]  # type: ignore[index]
    atoms = payload["rule_atoms"]  # type: ignore[assignment]
    relationship = payload["rule_relationships"][0]  # type: ignore[index]
    if mutation == "mapped_without_atom":
        dimensions["authority_status_timing"] = _dimension("mapped")  # type: ignore[index]
    elif mutation == "mapped_with_gap":
        dimensions["authority_status_timing"] = _dimension(  # type: ignore[index]
            "mapped", atom_ids=["atom-duty"], gap_codes=["NOT_A_GAP"]
        )
    elif mutation == "gap_without_code":
        dimensions["triggers_thresholds"] = _dimension("gap")  # type: ignore[index]
    elif mutation == "gap_with_atom":
        dimensions["triggers_thresholds"] = _dimension(  # type: ignore[index]
            "gap", atom_ids=["atom-duty"], gap_codes=["TRIGGER_NOT_ESTABLISHED"]
        )
    elif mutation == "not_present_with_payload":
        dimensions["deadlines_transitions"] = _dimension(  # type: ignore[index]
            "not_present", rationale="Unexpected payload."
        )
    elif mutation == "not_material_without_rationale":
        dimensions["enforcement_remedies_consequences"] = _dimension(  # type: ignore[index]
            "not_material"
        )
    elif mutation == "not_material_with_atom":
        dimensions["enforcement_remedies_consequences"] = _dimension(  # type: ignore[index]
            "not_material", atom_ids=["atom-duty"], rationale="Unexpected atom."
        )
    elif mutation == "stated_element_without_text":
        atoms[0]["elements"]["actor"] = _atom_element(  # type: ignore[index]
            "stated", claim_ids=["claim-actor"]
        )
    elif mutation == "stated_element_without_claim":
        atoms[0]["elements"]["actor"] = _atom_element(  # type: ignore[index]
            "stated", text="a covered operator"
        )
    elif mutation == "stated_element_with_gap":
        atoms[0]["elements"]["actor"] = _atom_element(  # type: ignore[index]
            "stated",
            text="a covered operator",
            claim_ids=["claim-actor"],
            gap_codes=["NOT_A_GAP"],
        )
    elif mutation == "not_established_element_without_gap":
        atoms[0]["elements"]["trigger"] = _atom_element("not_established")  # type: ignore[index]
    elif mutation == "not_established_element_with_claim":
        atoms[0]["elements"]["trigger"] = _atom_element(  # type: ignore[index]
            "not_established",
            claim_ids=["claim-trigger"],
            gap_codes=["TRIGGER_NOT_ESTABLISHED"],
        )
    elif mutation == "not_applicable_element_with_payload":
        atoms[0]["elements"]["timing"] = _atom_element(  # type: ignore[index]
            text="unexpected timing"
        )
    elif mutation == "atom_without_target":
        atoms[0]["unit_ids"] = []  # type: ignore[index]
        atoms[0]["lead_ids"] = []  # type: ignore[index]
    elif mutation == "atom_without_omission_rationale":
        atoms[0]["omission_rationale"] = "   "  # type: ignore[index]
    elif mutation == "self_relationship":
        relationship["target_atom_id"] = "atom-exception"  # type: ignore[index]
    elif mutation == "relationship_without_claim":
        relationship["claim_ids"] = []  # type: ignore[index]
    elif mutation == "duplicate_unit_review_id":
        payload["unit_reviews"] = [
            payload["unit_reviews"][0],  # type: ignore[index]
            deepcopy(payload["unit_reviews"][0]),  # type: ignore[index]
        ]
    elif mutation == "duplicate_lead_id":
        payload["lead_dispositions_v2"] = [
            payload["lead_dispositions_v2"][0],  # type: ignore[index]
            deepcopy(payload["lead_dispositions_v2"][0]),  # type: ignore[index]
        ]
    elif mutation == "duplicate_atom_id":
        atoms[1]["atom_id"] = "atom-duty"  # type: ignore[index]
    else:
        payload["rule_relationships"] = [relationship, deepcopy(relationship)]

    with pytest.raises(ValidationError):
        AnalysisDraft.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("unit_ids", ["unit-1", "unit-1"]),
        ("lead_ids", ["lead-duty", "lead-duty"]),
    ],
)
def test_v2_atom_rejects_duplicate_target_identifiers(field: str, value: object) -> None:
    payload = _v2_draft_payload()
    payload["rule_atoms"][0][field] = value  # type: ignore[index]

    with pytest.raises(ValidationError):
        AnalysisDraft.model_validate(payload)


def test_v2_draft_revalidates_values_created_through_model_copy() -> None:
    draft = AnalysisDraft.model_validate(_v2_draft_payload())
    invalid_atom = draft.rule_atoms[0].model_copy(
        update={"unit_ids": [], "lead_ids": [], "materiality": "invented"}
    )
    bypassed = draft.model_copy(update={"rule_atoms": [invalid_atom]})

    with pytest.raises(ValidationError):
        AnalysisDraft.model_validate(bypassed)


def test_v2_nested_models_revalidate_values_created_through_model_copy() -> None:
    draft = AnalysisDraft.model_validate(_v2_draft_payload())
    invalid_atom = draft.rule_atoms[0].model_copy(update={"materiality": "invented"})

    with pytest.raises(ValidationError):
        type(draft.rule_atoms[0]).model_validate(invalid_atom)


def test_atomic_rows_cannot_bypass_validation_under_a_legacy_version() -> None:
    draft = AnalysisDraft.model_validate(_v2_draft_payload())
    invalid_atom = draft.rule_atoms[0].model_copy(
        update={"unit_ids": [], "lead_ids": [], "materiality": "invented"}
    )
    bypassed = draft.model_copy(
        update={
            "coverage_contract_version": "proposition-coverage-v1",
            "rule_atoms": [invalid_atom],
        }
    )

    with pytest.raises(ValidationError):
        AnalysisDraft.model_validate(bypassed)


def test_v2_authoring_models_are_exported_from_analysis() -> None:
    for name in (
        "DraftAtomElement",
        "DraftDimensionReview",
        "DraftLeadDispositionV2",
        "DraftRuleAtom",
        "DraftRuleAtomElements",
        "DraftRuleRelationship",
        "DraftUnitReview",
        "DraftUnitReviewDimensions",
    ):
        assert getattr(analysis_module, name, None) is not None, f"missing {name}"


def test_v2_enums_are_exported_from_canonical_models_package() -> None:
    from regulatory_harvest.models import (
        AtomMateriality,
        AtomRelationshipType,
        LeadDispositionV2,
        UnitDimensionDisposition,
    )

    assert AtomMateriality.CRITICAL.value == "critical"
    assert AtomRelationshipType.EXCEPTION_TO.value == "exception_to"
    assert LeadDispositionV2.MAPPED.value == "mapped"
    assert UnitDimensionDisposition.NOT_PRESENT.value == "not_present"


def _bypass_draft_rows(
    draft: AnalysisDraft, field: str, row: object, method: str
) -> AnalysisDraft:
    if method == "model_copy":
        return draft.model_copy(update={field: [row]})
    values = dict(draft.__dict__)
    values[field] = [row]
    return AnalysisDraft.model_construct(**values)


@pytest.mark.parametrize("method", ["model_copy", "model_construct"])
@pytest.mark.parametrize(
    ("field", "row"),
    [
        ("rule_atoms", {"atom_id": "malformed-atom"}),
        ("rule_atoms", object()),
        ("rule_atoms", analysis_module.DraftRuleAtom.model_construct(atom_id="bad-atom")),
        ("rule_relationships", {"relationship_id": "malformed-relationship"}),
        ("rule_relationships", object()),
        (
            "rule_relationships",
            analysis_module.DraftRuleRelationship.model_construct(
                relationship_id="bad-relationship"
            ),
        ),
    ],
)
def test_v2_draft_rejects_raw_validation_bypasses_with_validation_error(
    field: str, row: object, method: str
) -> None:
    draft = AnalysisDraft.model_validate(_v2_draft_payload())
    bypassed = _bypass_draft_rows(draft, field, row, method)

    with pytest.raises(ValidationError):
        AnalysisDraft.model_validate(bypassed)


def _draft_with_nested_brief(version: str | None) -> AnalysisDraft:
    return AnalysisDraft.model_validate(
        {
            "issues": [],
            "findings": [],
            "coverage_contract_version": version,
            "brief": {
                "structure_profile": "regulatory-walk-v1",
                "executive_summary": [
                    {
                        "kind": "paragraph",
                        "purpose": "legal_analysis",
                        "text": "The retained rule states a qualified duty.",
                    }
                ],
                "sections": [
                    {
                        "section_id": "key-requirements",
                        "title": "Key Requirements",
                        "blocks": [
                            {
                                "kind": "bullet_list",
                                "purpose": "legal_analysis",
                                "items": [{"text": "Maintain the required record."}],
                            },
                            {
                                "kind": "table",
                                "purpose": "legal_analysis",
                                "columns": ["Duty", "Qualification"],
                                "rows": [
                                    {
                                        "cells": [
                                            "Maintain the required record",
                                            "Unless exempt",
                                        ]
                                    }
                                ],
                            },
                        ],
                    }
                ],
            },
        }
    )


def _brief_with_bypass(draft: AnalysisDraft, mutation: str) -> AttorneyBrief:
    assert draft.brief is not None
    section = draft.brief.sections[0]
    list_block, table_block = section.blocks
    if mutation == "item":
        invalid_item = list_block.items[0].model_copy(
            update={"atom_ids": ["duplicate", "duplicate"]}
        )
        list_block = list_block.model_copy(update={"items": [invalid_item]})
    elif mutation == "row":
        invalid_row = table_block.rows[0].model_copy(
            update={"relationship_ids": ["duplicate", "duplicate"]}
        )
        table_block = table_block.model_copy(update={"rows": [invalid_row]})
    else:
        list_block = list_block.model_copy(update={"atom_ids": ["container-atom"]})
    invalid_section = section.model_copy(update={"blocks": [list_block, table_block]})
    return draft.brief.model_copy(update={"sections": [invalid_section]})


@pytest.mark.parametrize("version", [None, "proposition-coverage-v1", "proposition-coverage-v2"])
@pytest.mark.parametrize("mutation", ["item", "row", "container"])
def test_nested_brief_validation_bypasses_fail_closed_for_every_contract(
    version: str | None, mutation: str
) -> None:
    draft = _draft_with_nested_brief(version)
    bypassed = draft.model_copy(update={"brief": _brief_with_bypass(draft, mutation)})

    with pytest.raises(ValidationError):
        AnalysisDraft.model_validate(bypassed)


@pytest.mark.parametrize("version", [None, "proposition-coverage-v1"])
def test_valid_legacy_nested_brief_dump_remains_stable(version: str | None) -> None:
    draft = _draft_with_nested_brief(version)
    before = draft.model_dump(mode="json")

    assert AnalysisDraft.model_validate(before).model_dump(mode="json") == before


def test_covered_row_requires_targets_elements_claims_and_partial_gap_binding() -> None:
    row = DraftPropositionCoverage(
        coverage_id="coverage-register",
        unit_ids=["unit-one"],
        category="requirements",
        proposition_type="duty",
        disposition="covered",
        elements=_elements(timing="not_established"),
        claim_ids=["claim-register"],
        gap_codes=["REGISTER_TIMING_NOT_ESTABLISHED"],
    )

    assert row.model_dump(mode="json") == {
        "coverage_id": "coverage-register",
        "unit_ids": ["unit-one"],
        "lead_ids": [],
        "category": "requirements",
        "proposition_type": "duty",
        "disposition": "covered",
        "elements": {
            "subject": {"status": "stated", "text": "covered operator"},
            "operative_rule": {"status": "stated", "text": "must keep a register"},
            "object": {"status": "stated", "text": "processing activities"},
            "trigger_or_threshold": {"status": "not_applicable", "text": None},
            "conditions_or_exceptions": {"status": "not_applicable", "text": None},
            "timing": {"status": "not_established", "text": None},
            "consequence_or_remedy": {"status": "not_applicable", "text": None},
            "authority_or_route": {"status": "not_applicable", "text": None},
        },
        "claim_ids": ["claim-register"],
        "gap_codes": ["REGISTER_TIMING_NOT_ESTABLISHED"],
        "rationale": None,
    }


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ({"status": "stated"}, "stated status requires nonblank text"),
        ({"status": "stated", "text": "   "}, "stated status requires nonblank text"),
        (
            {"status": "not_applicable", "text": "invented"},
            "not_applicable status requires text to be null",
        ),
        (
            {"status": "not_established", "text": "invented"},
            "not_established status requires text to be null",
        ),
    ],
)
def test_coverage_element_status_controls_text(
    payload: dict[str, object], message: str
) -> None:
    with pytest.raises(ValidationError, match=message):
        DraftCoverageElement.model_validate(payload)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (("elements", None), "covered disposition requires elements"),
        (("claim_ids", []), "covered disposition requires claim_ids"),
        (
            ("elements.subject", {"status": "not_applicable"}),
            "covered disposition requires stated subject and operative_rule",
        ),
        (
            ("elements.operative_rule", {"status": "not_established"}),
            "covered disposition requires stated subject and operative_rule",
        ),
        (("gap_codes", ["UNBOUND_GAP"]), "gap_codes require a not_established element"),
        (
            ("elements.timing", {"status": "not_established"}),
            "not_established elements require gap_codes",
        ),
    ],
)
def test_covered_row_rejects_invalid_cardinality(
    mutation: tuple[str, object], message: str
) -> None:
    payload = _covered_payload()
    path, value = mutation
    if path.startswith("elements."):
        payload["elements"][path.removeprefix("elements.")] = value  # type: ignore[index]
    else:
        payload[path] = value

    with pytest.raises(ValidationError, match=message):
        DraftPropositionCoverage.model_validate(payload)


def test_gap_row_accepts_bounded_gap_with_optional_unstated_elements() -> None:
    elements = _elements_payload(timing="not_established")
    for field in ("subject", "object"):
        elements[field] = {"status": "not_applicable"}
    elements["operative_rule"] = {"status": "not_established"}

    row = DraftPropositionCoverage(
        coverage_id="coverage-register-gap",
        lead_ids=["lead-register"],
        category="requirements",
        proposition_type="duty",
        disposition="gap",
        elements=elements,
        gap_codes=["REGISTER_RULE_NOT_ESTABLISHED"],
        rationale="The retained source does not establish the operative rule.",
    )

    assert row.claim_ids == []
    assert row.elements is not None
    assert row.elements.operative_rule.status is CoverageElementStatus.NOT_ESTABLISHED


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("claim_ids", ["claim-register"], "gap disposition cannot include claim_ids"),
        ("gap_codes", [], "gap disposition requires gap_codes"),
        ("rationale", None, "gap disposition requires a rationale"),
        ("rationale", "   ", "value must not be blank"),
        ("elements", _elements_payload(), "gap disposition cannot include stated elements"),
    ],
)
def test_gap_row_rejects_invalid_cardinality(
    field: str, value: object, message: str
) -> None:
    payload: dict[str, object] = {
        "coverage_id": "coverage-gap",
        "unit_ids": ["unit-one"],
        "category": "scope",
        "proposition_type": "scope",
        "disposition": "gap",
        "gap_codes": ["SCOPE_NOT_ESTABLISHED"],
        "rationale": "The supplied source does not establish scope.",
    }
    payload[field] = value

    with pytest.raises(ValidationError, match=message):
        DraftPropositionCoverage.model_validate(payload)


def test_not_material_row_accepts_only_targets_and_concrete_rationale() -> None:
    row = DraftPropositionCoverage(
        coverage_id="coverage-navigation",
        unit_ids=["unit-navigation"],
        category="other",
        proposition_type="other",
        disposition="not_material",
        rationale="The unit is navigation text unrelated to the research question.",
    )

    assert row.elements is None
    assert row.claim_ids == []
    assert row.gap_codes == []


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("elements", _elements_payload(), "not_material disposition cannot include elements"),
        ("claim_ids", ["claim-one"], "not_material disposition cannot include claim_ids"),
        ("gap_codes", ["NOT_A_GAP"], "not_material disposition cannot include gap_codes"),
        ("rationale", None, "not_material disposition requires a rationale"),
        ("rationale", "   ", "value must not be blank"),
    ],
)
def test_not_material_row_rejects_invalid_cardinality(
    field: str, value: object, message: str
) -> None:
    payload: dict[str, object] = {
        "coverage_id": "coverage-navigation",
        "unit_ids": ["unit-navigation"],
        "category": "other",
        "proposition_type": "other",
        "disposition": "not_material",
        "rationale": "Navigation text is unrelated to the question.",
    }
    payload[field] = value

    with pytest.raises(ValidationError, match=message):
        DraftPropositionCoverage.model_validate(payload)


def test_every_coverage_row_requires_a_unit_or_lead_target() -> None:
    payload = _covered_payload()
    payload["unit_ids"] = []
    with pytest.raises(ValidationError, match="unit_id or lead_id"):
        DraftPropositionCoverage.model_validate(payload)

    payload["lead_ids"] = ["lead-register"]
    assert DraftPropositionCoverage.model_validate(payload).lead_ids == ["lead-register"]


@pytest.mark.parametrize("field", ["unit_ids", "lead_ids", "claim_ids", "gap_codes"])
def test_coverage_row_rejects_duplicate_identifiers(field: str) -> None:
    payload = _covered_payload()
    payload[field] = ["same-id", "same-id"]

    with pytest.raises(ValidationError, match=f"{field} must be unique"):
        DraftPropositionCoverage.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("coverage_id", "   "),
        ("unit_ids", ["   "]),
        ("lead_ids", ["   "]),
        ("claim_ids", ["   "]),
        ("gap_codes", ["   "]),
    ],
)
def test_coverage_row_rejects_blank_identifiers(field: str, value: object) -> None:
    payload = _covered_payload()
    payload[field] = value

    with pytest.raises(ValidationError, match="value must not be blank"):
        DraftPropositionCoverage.model_validate(payload)


def test_draft_rejects_duplicate_coverage_identifiers() -> None:
    row = _covered_payload()
    with pytest.raises(ValidationError, match="coverage identifiers must be unique"):
        AnalysisDraft.model_validate(
            {"issues": [], "findings": [], "proposition_coverage": [row, deepcopy(row)]}
        )


def test_old_draft_without_coverage_fields_remains_parseable() -> None:
    draft = AnalysisDraft.model_validate({"issues": [], "findings": []})

    assert draft.coverage_contract_version is None
    assert draft.proposition_coverage == []


def test_v1_draft_model_dump_remains_exactly_unchanged() -> None:
    draft = AnalysisDraft.model_validate(
        {
            "issues": [],
            "findings": [],
            "coverage_contract_version": "proposition-coverage-v1",
        }
    )

    assert draft.model_dump(mode="json") == {
        "issues": [],
        "findings": [],
        "gaps": [],
        "lead_reviews": [],
        "coverage_contract_version": "proposition-coverage-v1",
        "proposition_coverage": [],
        "brief": None,
    }


def test_v1_draft_with_brief_model_dump_remains_exactly_unchanged() -> None:
    payload = {
        "issues": [],
        "findings": [],
        "coverage_contract_version": "proposition-coverage-v1",
        "brief": {
            "structure_profile": "regulatory-walk-v1",
            "executive_summary": [
                {
                    "kind": "paragraph",
                    "purpose": "legal_analysis",
                    "text": "The retained rule states a duty.",
                }
            ],
            "sections": [
                {
                    "section_id": "key-requirements",
                    "title": "Key Requirements",
                    "blocks": [
                        {
                            "kind": "bullet_list",
                            "purpose": "legal_analysis",
                            "items": [{"text": "Maintain the required record."}],
                        }
                    ],
                }
            ],
        },
    }

    dumped_brief = AnalysisDraft.model_validate(payload).model_dump(mode="json")["brief"]

    assert dumped_brief == {
        "structure_profile": "regulatory-walk-v1",
        "executive_summary": [
            {
                "kind": "paragraph",
                "purpose": "legal_analysis",
                "text": "The retained rule states a duty.",
                "finding_ids": [],
                "claim_ids": [],
                "enforcement_trigger_claim_ids": [],
                "enforcement_consequence_claim_ids": [],
                "items": [],
                "columns": [],
                "rows": [],
            }
        ],
        "sections": [
            {
                "section_id": "key-requirements",
                "title": "Key Requirements",
                "role": None,
                "blocks": [
                    {
                        "kind": "bullet_list",
                        "purpose": "legal_analysis",
                        "text": None,
                        "finding_ids": [],
                        "claim_ids": [],
                        "enforcement_trigger_claim_ids": [],
                        "enforcement_consequence_claim_ids": [],
                        "items": [
                            {
                                "text": "Maintain the required record.",
                                "finding_ids": [],
                                "claim_ids": [],
                                "enforcement_trigger_claim_ids": [],
                                "enforcement_consequence_claim_ids": [],
                            }
                        ],
                        "columns": [],
                        "rows": [],
                    }
                ],
                "subsections": [],
            }
        ],
    }


def test_coverage_contract_version_is_optional_but_strict_when_present() -> None:
    assert (
        AnalysisDraft.model_validate(
            {
                "issues": [],
                "findings": [],
                "coverage_contract_version": "proposition-coverage-v1",
            }
        ).coverage_contract_version
        == "proposition-coverage-v1"
    )
    assert (
        AnalysisDraft.model_validate(
            {
                "issues": [],
                "findings": [],
                "coverage_contract_version": "proposition-coverage-v2",
            }
        ).coverage_contract_version
        == "proposition-coverage-v2"
    )
    assert (
        AnalysisDraft.model_validate(
            {"issues": [], "findings": [], "coverage_contract_version": None}
        ).coverage_contract_version
        is None
    )
    with pytest.raises(ValidationError, match="proposition-coverage-v1"):
        AnalysisDraft.model_validate(
            {
                "issues": [],
                "findings": [],
                "coverage_contract_version": "proposition-coverage-v3",
            }
        )
