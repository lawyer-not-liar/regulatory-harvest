from collections import Counter
from copy import deepcopy
from datetime import UTC, datetime

import pytest

import regulatory_harvest.analysis as analysis_package
from regulatory_harvest.analysis.atomic_coverage import (
    _project_atomic_lead_reviews,
    compose_atomic_coverage_review,
    evaluate_atomic_coverage,
    evaluate_atomic_target_review,
    evaluate_rule_graph,
)
from regulatory_harvest.analysis.drafts import (
    AnalysisDraft,
    DraftAtomElement,
    DraftClaim,
    DraftDimensionReview,
    DraftFinding,
    DraftGap,
    DraftIssue,
    DraftLeadDispositionV2,
    DraftRuleAtom,
    DraftRuleAtomElements,
    DraftRuleRelationship,
    DraftUnitReview,
    DraftUnitReviewDimensions,
    ProposedCitation,
)
from regulatory_harvest.analysis.inventory import (
    PROVISION_LEADS_NOTICE,
    PROVISION_LEADS_VERSION,
)
from regulatory_harvest.analysis.source_units import SOURCE_UNIT_INVENTORY_VERSION
from regulatory_harvest.models import (
    AttorneyBrief,
    BriefBlock,
    BriefItem,
    BriefSection,
    BriefTableRow,
    ClaimKind,
    Severity,
    SourceRecord,
)
from regulatory_harvest.storage import canonical_json_bytes, sha256_digest

DIMENSION_NAMES = tuple(DraftUnitReviewDimensions.model_fields)
SOURCE_TEXT = {
    "src-a": "A controller must maintain a synthetic register.",
    "src-b": "A processor must preserve a synthetic notice.",
}

RULE_GRAPH_CASES = (
    ("status", ("object",), None),
    ("definition", ("defined_term", "defined_meaning"), None),
    ("scope", ("actor", "object"), None),
    ("duty", ("actor", "modality", "operative_action", "object"), None),
    ("prohibition", ("actor", "modality", "operative_action", "object"), None),
    ("right", ("actor", "modality", "operative_action", "object"), None),
    ("exception", ("exception",), "exception_to"),
    ("deadline", ("timing",), "deadline_for"),
    ("enforcement_trigger", ("trigger",), "triggered_by"),
    ("enforcement_route", ("authority", "route"), "enforces"),
    ("remedy", ("consequence",), ("triggered_by", "consequence_of")),
    ("penalty", ("consequence",), ("triggered_by", "consequence_of")),
    ("appeal", ("route",), "appeals_from"),
    ("implementation", ("operative_action", "object"), None),
    ("other", ("object",), None),
)

RELATIONSHIP_DIRECTION_CASES = (
    ("qualifies", "scope", "duty"),
    ("exception_to", "exception", "duty"),
    ("deadline_for", "deadline", "duty"),
    ("enforces", "enforcement_route", "duty"),
    ("triggered_by", "enforcement_trigger", "duty"),
    ("consequence_of", "penalty", "prohibition"),
    ("appeals_from", "appeal", "penalty"),
    ("defines", "definition", "duty"),
)


def _source(source_id: str) -> SourceRecord:
    text = SOURCE_TEXT[source_id]
    return SourceRecord(
        source_id=source_id,
        origin=f"{source_id}.txt",
        display_name=f"Synthetic Rule {source_id}",
        retrieved_at=datetime(2026, 8, 14, tzinfo=UTC),
        content_hash=sha256_digest(text.encode()),
        media_type="text/plain",
        normalized_text=text,
        jurisdiction="US",
    )


def _unit(source_id: str, unit_id: str) -> dict[str, object]:
    text = SOURCE_TEXT[source_id]
    return {
        "unit_id": unit_id,
        "source_id": source_id,
        "start_char": 0,
        "end_char": len(text),
        "heading": None,
        "locator": f"chars:0-{len(text)}",
        "excerpt": text,
        "coverage_required": True,
    }


def _lead(
    source_id: str,
    lead_id: str,
    *,
    category: str = "requirements",
    review_required: bool,
) -> dict[str, object]:
    text = SOURCE_TEXT[source_id]
    return {
        "lead_id": lead_id,
        "source_id": source_id,
        "topic": f"synthetic topic {lead_id}",
        "issue_category": category,
        "start_char": 0,
        "end_char": len(text),
        "heading": None,
        "excerpt": text,
        "signals": ["must"],
        "review_required": review_required,
    }


def _inventories(
    *,
    units: list[dict[str, object]] | None = None,
    leads: list[dict[str, object]] | None = None,
) -> tuple[dict[str, object], dict[str, object]]:
    unit_rows = units if units is not None else [_unit("src-a", "unit-a")]
    lead_rows = (
        leads
        if leads is not None
        else [
            _lead("src-a", "lead-map", review_required=True),
            _lead("src-a", "lead-gap", review_required=True),
            _lead("src-a", "lead-nav", category="other", review_required=False),
        ]
    )
    source_ids = {
        str(row["source_id"])
        for row in [*unit_rows, *lead_rows]
        if isinstance(row.get("source_id"), str)
    }
    priority_count = sum(row.get("review_required") is True for row in lead_rows)
    topic_counts = Counter(
        str(row["topic"]) for row in lead_rows if isinstance(row.get("topic"), str)
    )
    priority_topic_counts = Counter(
        str(row["topic"])
        for row in lead_rows
        if isinstance(row.get("topic"), str) and row.get("review_required") is True
    )
    return (
        {
            "inventory_version": SOURCE_UNIT_INVENTORY_VERSION,
            "eligible_source_count": len(source_ids),
            "unit_count": len(unit_rows),
            "required_unit_count": len(unit_rows),
            "units": unit_rows,
        },
        {
            "inventory_version": PROVISION_LEADS_VERSION,
            "notice": PROVISION_LEADS_NOTICE,
            "source_count": len(source_ids),
            "lead_count": len(lead_rows),
            "priority_lead_count": priority_count,
            "priority_topic_counts": dict(sorted(priority_topic_counts.items())),
            "priority_cap_per_topic": 3,
            "topic_counts": dict(sorted(topic_counts.items())),
            "leads": lead_rows,
        },
    )


def _dimension(
    disposition: str,
    *,
    atom_ids: list[str] | None = None,
    gap_codes: list[str] | None = None,
    rationale: str | None = None,
) -> DraftDimensionReview:
    return DraftDimensionReview(
        disposition=disposition,
        atom_ids=atom_ids or [],
        gap_codes=gap_codes or [],
        rationale=rationale,
    )


def _dimensions(*, atom_id: str, unit_gap_code: str) -> DraftUnitReviewDimensions:
    return DraftUnitReviewDimensions(
        authority_status_timing=_dimension("gap", gap_codes=[unit_gap_code]),
        actors_scope_activities=_dimension(
            "not_material",
            rationale="Navigation identifies no additional responsive actor or scope rule.",
        ),
        definitions_categories=_dimension("not_present"),
        duties_rights_prohibitions=_dimension("mapped", atom_ids=[atom_id]),
        triggers_thresholds=_dimension("not_present"),
        conditions_exceptions_defenses=_dimension("not_present"),
        deadlines_transitions=_dimension("not_present"),
        enforcement_remedies_consequences=_dimension("not_present"),
        cross_references_dependencies=_dimension("not_present"),
    )


def _atom(
    atom_id: str,
    *,
    unit_ids: list[str],
    lead_ids: list[str],
) -> DraftRuleAtom:
    elements = {
        field_name: DraftAtomElement(status="not_applicable")
        for field_name in DraftRuleAtomElements.model_fields
    }
    return DraftRuleAtom(
        atom_id=atom_id,
        unit_ids=unit_ids,
        lead_ids=lead_ids,
        category="requirements",
        proposition_type="duty",
        materiality="material",
        elements=DraftRuleAtomElements(**elements),
        omission_rationale="Omission would hide the synthetic registration duty.",
    )


def _graph_atom(
    atom_id: str,
    proposition_type: str,
    *,
    unit_ids: list[str] | None = None,
    stated_elements: tuple[str, ...] | None = None,
) -> DraftRuleAtom:
    required_elements = next(
        required
        for case_type, required, _ in RULE_GRAPH_CASES
        if case_type == proposition_type
    )
    stated = required_elements if stated_elements is None else stated_elements
    elements = {
        field_name: (
            DraftAtomElement(
                status="stated",
                text=f"Synthetic {field_name.replace('_', ' ')}",
                claim_ids=[f"claim-{atom_id}-{field_name}"],
            )
            if field_name in stated
            else DraftAtomElement(status="not_applicable")
        )
        for field_name in DraftRuleAtomElements.model_fields
    }
    category = {
        "status": "status",
        "scope": "scope",
        "duty": "requirements",
        "prohibition": "requirements",
        "right": "requirements",
        "exception": "requirements",
        "deadline": "deadlines",
        "enforcement_trigger": "enforcement",
        "enforcement_route": "enforcement",
        "remedy": "enforcement",
        "penalty": "enforcement",
        "appeal": "enforcement",
        "implementation": "implementation",
    }.get(proposition_type, "other")
    return DraftRuleAtom(
        atom_id=atom_id,
        unit_ids=unit_ids or ["unit-graph"],
        category=category,
        proposition_type=proposition_type,
        materiality="material",
        elements=DraftRuleAtomElements(**elements),
        omission_rationale=f"Omission would hide the synthetic {proposition_type} rule.",
    )


def _graph_relationship(
    relationship_id: str,
    relation_type: str,
    source_atom_id: str,
    target_atom_id: str,
) -> DraftRuleRelationship:
    return DraftRuleRelationship(
        relationship_id=relationship_id,
        relation_type=relation_type,
        source_atom_id=source_atom_id,
        target_atom_id=target_atom_id,
        claim_ids=[f"claim-{relationship_id}"],
    )


def _graph_draft(
    atoms: list[DraftRuleAtom],
    relationships: list[DraftRuleRelationship] | None = None,
) -> AnalysisDraft:
    return AnalysisDraft(
        coverage_contract_version="proposition-coverage-v2",
        rule_atoms=atoms,
        rule_relationships=relationships or [],
    )


def _minimum_graph_case(proposition_type: str) -> AnalysisDraft:
    subject = _graph_atom("atom-subject", proposition_type)
    atoms = [subject]
    relationships: list[DraftRuleRelationship] = []
    required_relationship = next(
        required
        for case_type, _, required in RULE_GRAPH_CASES
        if case_type == proposition_type
    )
    if required_relationship is None:
        return _graph_draft(atoms)

    relation_type = (
        required_relationship[1]
        if isinstance(required_relationship, tuple)
        else required_relationship
    )
    if proposition_type == "appeal":
        route = _graph_atom("atom-route", "enforcement_route")
        governed = _graph_atom("atom-governed", "duty")
        atoms.extend((route, governed))
        relationships.extend(
            (
                _graph_relationship(
                    "relationship-subject", "appeals_from", "atom-subject", "atom-route"
                ),
                _graph_relationship(
                    "relationship-route", "enforces", "atom-route", "atom-governed"
                ),
            )
        )
    else:
        target_type = (
            "enforcement_trigger"
            if proposition_type in {"remedy", "penalty"}
            and relation_type == "triggered_by"
            else "duty"
        )
        target = _graph_atom("atom-target", target_type)
        atoms.append(target)
        relationships.append(
            _graph_relationship(
                "relationship-subject", relation_type, "atom-subject", "atom-target"
            )
        )
        if target_type == "enforcement_trigger":
            governed = _graph_atom("atom-governed", "duty")
            atoms.append(governed)
            relationships.append(
                _graph_relationship(
                    "relationship-trigger",
                    "triggered_by",
                    "atom-target",
                    "atom-governed",
                )
            )
    return _graph_draft(atoms, relationships)


def _complete_case() -> tuple[
    dict[str, object], dict[str, object], AnalysisDraft, list[SourceRecord]
]:
    units, leads = _inventories()
    draft = AnalysisDraft(
        coverage_contract_version="proposition-coverage-v2",
        gaps=[
            DraftGap(
                code="UNIT_STATUS_GAP",
                message="The synthetic text does not establish status timing.",
                category="status",
                source_ids=["src-a"],
            ),
            DraftGap(
                code="LEAD_REQUIREMENTS_GAP",
                message="The synthetic lead cannot be established.",
                category="requirements",
                source_ids=["src-a"],
            ),
        ],
        unit_reviews=[
            DraftUnitReview(
                unit_id="unit-a",
                dimensions=_dimensions(atom_id="atom-rule", unit_gap_code="UNIT_STATUS_GAP"),
            )
        ],
        lead_dispositions_v2=[
            DraftLeadDispositionV2(
                lead_id="lead-map", disposition="mapped", atom_ids=["atom-rule"]
            ),
            DraftLeadDispositionV2(
                lead_id="lead-gap",
                disposition="gap",
                gap_codes=["LEAD_REQUIREMENTS_GAP"],
            ),
            DraftLeadDispositionV2(
                lead_id="lead-nav",
                disposition="not_material",
                rationale="This duplicate navigation lead adds no responsive legal rule.",
            ),
        ],
        rule_atoms=[_atom("atom-rule", unit_ids=["unit-a"], lead_ids=["lead-map"])],
    )
    return units, leads, draft, [_source("src-a")]


def _all_not_present_dimensions(*, atom_ids: list[str] | None = None) -> DraftUnitReviewDimensions:
    return DraftUnitReviewDimensions(
        **{
            name: _dimension("mapped", atom_ids=atom_ids)
            if name == "duties_rights_prohibitions" and atom_ids
            else _dimension("not_present")
            for name in DIMENSION_NAMES
        }
    )


def _malformed_declared_target_case(
    target_kind: str,
    *,
    atom_count: int,
) -> tuple[dict[str, object], dict[str, object], AnalysisDraft, list[SourceRecord]]:
    atom_ids = [f"atom-{index:02d}" for index in range(atom_count)]
    atoms: list[DraftRuleAtom]
    unit_rows = [_unit("src-a", "unit-a"), _unit("src-b", "unit-b")]
    unit_reviews = [
        DraftUnitReview(
            unit_id="unit-a",
            dimensions=_all_not_present_dimensions(),
        ),
        DraftUnitReview(
            unit_id="unit-b",
            dimensions=_all_not_present_dimensions(
                atom_ids=atom_ids if target_kind == "unit" else None
            ),
        ),
    ]
    if target_kind == "unit":
        unit_rows[1]["excerpt"] = "A malformed neighboring unit slice."
        lead_rows: list[dict[str, object]] = []
        lead_dispositions: list[DraftLeadDispositionV2] = []
        atoms = [_atom(atom_id, unit_ids=["unit-b"], lead_ids=[]) for atom_id in atom_ids]
    else:
        lead_rows = [
            _lead("src-a", "lead-a", review_required=False),
            _lead("src-b", "lead-b", review_required=True),
        ]
        lead_rows[1]["excerpt"] = "A malformed neighboring lead slice."
        lead_dispositions = [
            DraftLeadDispositionV2(
                lead_id="lead-a",
                disposition="not_material",
                rationale="The synthetic navigation lead adds no responsive rule.",
            ),
            DraftLeadDispositionV2(
                lead_id="lead-b",
                disposition="mapped",
                atom_ids=atom_ids,
            ),
        ]
        atoms = [_atom(atom_id, unit_ids=[], lead_ids=["lead-b"]) for atom_id in atom_ids]
    units, leads = _inventories(units=unit_rows, leads=lead_rows)
    return (
        units,
        leads,
        AnalysisDraft(
            coverage_contract_version="proposition-coverage-v2",
            unit_reviews=unit_reviews,
            lead_dispositions_v2=lead_dispositions,
            rule_atoms=atoms,
        ),
        [_source("src-b"), _source("src-a")],
    )


def _duplicate_declared_target_case(
    target_kind: str,
    *,
    atom_count: int,
) -> tuple[dict[str, object], dict[str, object], AnalysisDraft, list[SourceRecord]]:
    units, leads, draft, sources = _malformed_declared_target_case(
        target_kind,
        atom_count=atom_count,
    )
    if target_kind == "unit":
        unit_rows = units["units"]
        assert isinstance(unit_rows, list)
        unit_rows[1]["excerpt"] = SOURCE_TEXT["src-b"]
        unit_rows.append(deepcopy(unit_rows[1]))
        units["unit_count"] = 3
        units["required_unit_count"] = 3
    else:
        lead_rows = leads["leads"]
        assert isinstance(lead_rows, list)
        lead_rows[1]["excerpt"] = SOURCE_TEXT["src-b"]
        lead_rows.append(deepcopy(lead_rows[1]))
        leads["lead_count"] = 3
        leads["priority_lead_count"] = 2
        topic = str(lead_rows[1]["topic"])
        leads["topic_counts"] = {
            str(lead_rows[0]["topic"]): 1,
            topic: 2,
        }
        leads["priority_topic_counts"] = {topic: 2}
    return units, leads, draft, sources


def _issue_codes(review: dict[str, object]) -> list[str]:
    issues = review["issues"]
    assert isinstance(issues, list)
    return [str(issue["code"]) for issue in issues]


def test_atomic_target_review_is_exported_and_closes_all_dimensions_and_leads() -> None:
    units, leads, draft, sources = _complete_case()

    review = evaluate_atomic_target_review(units, leads, draft, sources)

    assert analysis_package.evaluate_atomic_target_review is evaluate_atomic_target_review
    assert review["schema_version"] == "1.0"
    assert review["valid"] is True
    assert review["target_counts"] == {
        "invalid_leads": 0,
        "invalid_units": 0,
        "lead_rows": 3,
        "leads": 3,
        "unit_rows": 1,
        "units": 1,
    }
    assert review["disposition_counts"] == {
        "lead_dispositions": {
            "gap": 1,
            "invalid": 0,
            "mapped": 1,
            "not_material": 1,
            "unresolved": 0,
        },
        "unit_dimensions": {
            "gap": 1,
            "invalid": 0,
            "mapped": 1,
            "not_material": 1,
            "not_present": 6,
            "unresolved": 0,
        },
    }
    unit_result = review["units"][0]
    assert unit_result["target_state"] == "valid"
    assert list(unit_result["dimensions"]) == list(DIMENSION_NAMES)
    assert unit_result["dimensions"]["definitions_categories"] == {
        "disposition": "not_present",
        "atom_ids": [],
        "gap_codes": [],
        "rationale": None,
        "valid": True,
    }
    assert [row["lead_id"] for row in review["leads"]] == [
        "lead-gap",
        "lead-map",
        "lead-nav",
    ]
    assert all(row["target_state"] == "valid" for row in review["leads"])
    assert review["leads"][2]["review_required"] is False
    assert isinstance(review["target_review_hash"], str)
    assert len(review["target_review_hash"]) == 64


@pytest.mark.parametrize(
    ("inventory_name", "field_name", "impossible_value"),
    [
        ("units", "eligible_source_count", 99),
        ("units", "unit_count", 99),
        ("units", "required_unit_count", 99),
        ("leads", "source_count", 99),
        ("leads", "lead_count", 99),
        ("leads", "priority_lead_count", 99),
        ("leads", "priority_topic_counts", {"impossible-topic": 99}),
        ("leads", "topic_counts", {"impossible-topic": 99}),
        ("leads", "priority_cap_per_topic", 0),
        ("leads", "notice", "Mutated inventory notice."),
    ],
)
def test_inventory_summary_metadata_must_match_validated_sources_and_rows(
    inventory_name: str,
    field_name: str,
    impossible_value: object,
) -> None:
    units, leads, draft, sources = _complete_case()
    baseline = evaluate_atomic_target_review(units, leads, draft, sources)
    assert baseline["valid"] is True
    inventory = units if inventory_name == "units" else leads
    inventory[field_name] = impossible_value
    before = (
        deepcopy(units),
        deepcopy(leads),
        draft.model_dump(mode="python", warnings=False),
        [source.model_dump(mode="python", warnings=False) for source in sources],
    )

    review = evaluate_atomic_target_review(units, leads, draft, sources)

    assert review["valid"] is False
    assert _issue_codes(review) == ["ATOMIC_REVIEW_INVALID"]
    assert review["target_review_hash"] != baseline["target_review_hash"]
    assert (
        units,
        leads,
        draft.model_dump(mode="python", warnings=False),
        [source.model_dump(mode="python", warnings=False) for source in sources],
    ) == before


def test_inventory_priority_rows_cannot_exceed_declared_topic_cap() -> None:
    lead_rows = [
        _lead("src-a", f"lead-{index}", review_required=True)
        for index in range(4)
    ]
    for lead in lead_rows:
        lead["topic"] = "shared priority topic"
    units, leads = _inventories(leads=lead_rows)
    draft = AnalysisDraft(
        coverage_contract_version="proposition-coverage-v2",
        unit_reviews=[
            DraftUnitReview(
                unit_id="unit-a",
                dimensions=_all_not_present_dimensions(),
            )
        ],
        lead_dispositions_v2=[
            DraftLeadDispositionV2(
                lead_id=f"lead-{index}",
                disposition="not_material",
                rationale="The synthetic lead adds no distinct responsive proposition.",
            )
            for index in range(4)
        ],
    )

    review = evaluate_atomic_target_review(units, leads, draft, [_source("src-a")])

    assert review["valid"] is False
    assert review["issues"] == [
        {
            "code": "ATOMIC_REVIEW_INVALID",
            "message": "Prepared provision-lead inventory metadata is inconsistent.",
            "related_ids": ["priority_cap_per_topic"],
        }
    ]


@pytest.mark.parametrize("target_kind", ["unit", "lead"])
def test_declared_malformed_target_has_one_stable_root_issue_and_invalid_result(
    target_kind: str,
) -> None:
    one_inputs = _malformed_declared_target_case(target_kind, atom_count=1)
    fifty_inputs = _malformed_declared_target_case(target_kind, atom_count=50)
    one_before = (
        deepcopy(one_inputs[0]),
        deepcopy(one_inputs[1]),
        one_inputs[2].model_dump(mode="python", warnings=False),
        [source.model_dump(mode="python", warnings=False) for source in one_inputs[3]],
    )

    one = evaluate_atomic_target_review(*one_inputs)
    fifty = evaluate_atomic_target_review(*fifty_inputs)

    assert one["valid"] is False
    assert one["issues"] == fifty["issues"]
    assert one["issues"] == [
        {
            "code": "ATOMIC_REVIEW_INVALID",
            "message": (
                "Prepared source unit is malformed or is not an exact source slice."
                if target_kind == "unit"
                else "Prepared provision lead is malformed or is not an exact source slice."
            ),
            "related_ids": sorted(
                ["src-b", "unit-b" if target_kind == "unit" else "lead-b"]
            ),
        }
    ]
    assert one["target_review_hash"] == fifty["target_review_hash"]
    assert one["units"] == fifty["units"]
    assert one["leads"] == fifty["leads"]
    assert one["target_counts"] == fifty["target_counts"]
    target_rows = one["units"] if target_kind == "unit" else one["leads"]
    target_id = "unit-b" if target_kind == "unit" else "lead-b"
    invalid_row = next(row for row in target_rows if row[f"{target_kind}_id"] == target_id)
    assert invalid_row["target_state"] == "invalid"
    assert invalid_row["valid"] is False
    assert one["target_counts"][f"invalid_{target_kind}s"] == 1
    assert (
        one_inputs[0],
        one_inputs[1],
        one_inputs[2].model_dump(mode="python", warnings=False),
        [source.model_dump(mode="python", warnings=False) for source in one_inputs[3]],
    ) == one_before


@pytest.mark.parametrize("target_kind", ["unit", "lead"])
def test_duplicate_declared_target_is_known_invalid_without_reference_cascade(
    target_kind: str,
) -> None:
    one = evaluate_atomic_target_review(
        *_duplicate_declared_target_case(target_kind, atom_count=1)
    )
    fifty = evaluate_atomic_target_review(
        *_duplicate_declared_target_case(target_kind, atom_count=50)
    )

    assert one["valid"] is False
    assert one["issues"] == fifty["issues"]
    assert "ATOMIC_TARGET_UNKNOWN" not in _issue_codes(one)
    assert one["target_review_hash"] == fifty["target_review_hash"]
    assert one["units"] == fifty["units"]
    assert one["leads"] == fifty["leads"]
    target_rows = one["units"] if target_kind == "unit" else one["leads"]
    target_id = "unit-b" if target_kind == "unit" else "lead-b"
    matching_rows = [row for row in target_rows if row[f"{target_kind}_id"] == target_id]
    assert len(matching_rows) == 1
    assert matching_rows[0]["target_state"] == "invalid"
    assert one["target_counts"][f"invalid_{target_kind}s"] == 1


def test_duplicate_unit_counts_raw_rows_separately_from_canonical_targets() -> None:
    review = evaluate_atomic_target_review(
        *_duplicate_declared_target_case("unit", atom_count=1)
    )

    assert review["target_counts"] == {
        "invalid_leads": 0,
        "invalid_units": 1,
        "lead_rows": 0,
        "leads": 0,
        "unit_rows": 3,
        "units": 2,
    }
    assert len(review["units"]) == 2
    assert len(review["leads"]) == 0
    assert sum(review["disposition_counts"]["unit_dimensions"].values()) == 18
    assert sum(review["disposition_counts"]["lead_dispositions"].values()) == 0


def test_duplicate_lead_counts_raw_rows_separately_from_canonical_targets() -> None:
    review = evaluate_atomic_target_review(
        *_duplicate_declared_target_case("lead", atom_count=1)
    )

    assert review["target_counts"] == {
        "invalid_leads": 1,
        "invalid_units": 0,
        "lead_rows": 3,
        "leads": 2,
        "unit_rows": 2,
        "units": 2,
    }
    assert len(review["units"]) == 2
    assert len(review["leads"]) == 2
    assert sum(review["disposition_counts"]["unit_dimensions"].values()) == 18
    assert sum(review["disposition_counts"]["lead_dispositions"].values()) == 2


def test_malformed_no_id_row_counts_only_as_a_raw_inventory_row() -> None:
    units, leads, draft, sources = _complete_case()
    unit_rows = units["units"]
    assert isinstance(unit_rows, list)
    unit_rows.append(
        {
            "source_id": "src-a",
            "start_char": 0,
            "end_char": len(SOURCE_TEXT["src-a"]),
            "excerpt": SOURCE_TEXT["src-a"],
            "coverage_required": True,
        }
    )
    units["unit_count"] = 2
    units["required_unit_count"] = 2
    before = deepcopy(units)

    review = evaluate_atomic_target_review(units, leads, draft, sources)

    assert review["target_counts"] == {
        "invalid_leads": 0,
        "invalid_units": 0,
        "lead_rows": 3,
        "leads": 3,
        "unit_rows": 2,
        "units": 1,
    }
    assert [row["unit_id"] for row in review["units"]] == ["unit-a"]
    assert sum(review["disposition_counts"]["unit_dimensions"].values()) == 9
    assert sum(review["disposition_counts"]["lead_dispositions"].values()) == 3
    assert review["issues"] == [
        {
            "code": "ATOMIC_REVIEW_INVALID",
            "message": "Prepared source unit is malformed or is not an exact source slice.",
            "related_ids": ["src-a"],
        }
    ]
    assert units == before


def test_every_unit_dimension_and_every_lead_must_close() -> None:
    units, leads, draft, sources = _complete_case()
    draft = draft.model_copy(update={"unit_reviews": [], "lead_dispositions_v2": []})

    review = evaluate_atomic_target_review(units, leads, draft, sources)

    assert review["valid"] is False
    assert set(_issue_codes(review)) == {
        "ATOMIC_UNIT_REVIEW_UNRESOLVED",
        "ATOMIC_LEAD_REVIEW_UNRESOLVED",
        "ATOMIC_REVIEW_INVALID",
    }
    assert any(
        issue["code"] == "ATOMIC_LEAD_REVIEW_UNRESOLVED" and "lead-nav" in issue["related_ids"]
        for issue in review["issues"]
    )
    assert all(
        dimension["disposition"] == "unresolved"
        for dimension in review["units"][0]["dimensions"].values()
    )


@pytest.mark.parametrize("side", ["review_to_atom", "atom_to_review"])
def test_mapped_review_requires_reciprocal_atom_target(side: str) -> None:
    units, leads, draft, sources = _complete_case()
    if side == "review_to_atom":
        draft = draft.model_copy(
            update={"rule_atoms": [_atom("atom-rule", unit_ids=[], lead_ids=["lead-map"])]}
        )
    else:
        atom = _atom("atom-extra", unit_ids=["unit-a"], lead_ids=["lead-map"])
        draft = draft.model_copy(update={"rule_atoms": [*draft.rule_atoms, atom]})

    review = evaluate_atomic_target_review(units, leads, draft, sources)

    assert "ATOMIC_REVIEW_INVALID" in _issue_codes(review)


@pytest.mark.parametrize(
    ("field_name", "replacement"),
    [
        (
            "authority_status_timing",
            DraftDimensionReview.model_construct(
                disposition="mapped", atom_ids=[], gap_codes=[], rationale=None
            ),
        ),
        (
            "duties_rights_prohibitions",
            DraftDimensionReview.model_construct(
                disposition="mapped",
                atom_ids=["atom-rule"],
                gap_codes=["UNIT_STATUS_GAP"],
                rationale=None,
            ),
        ),
        (
            "duties_rights_prohibitions",
            DraftDimensionReview.model_construct(
                disposition="mapped",
                atom_ids=["atom-rule"],
                gap_codes=[],
                rationale="A mapped dimension cannot carry a rationale.",
            ),
        ),
        (
            "authority_status_timing",
            DraftDimensionReview.model_construct(
                disposition="gap", atom_ids=[], gap_codes=[], rationale=None
            ),
        ),
        (
            "authority_status_timing",
            DraftDimensionReview.model_construct(
                disposition="gap",
                atom_ids=["atom-rule"],
                gap_codes=["UNIT_STATUS_GAP"],
                rationale=None,
            ),
        ),
        (
            "authority_status_timing",
            DraftDimensionReview.model_construct(
                disposition="gap",
                atom_ids=[],
                gap_codes=["UNIT_STATUS_GAP"],
                rationale="A gap dimension cannot carry a rationale.",
            ),
        ),
        (
            "definitions_categories",
            DraftDimensionReview.model_construct(
                disposition="not_present",
                atom_ids=["atom-rule"],
                gap_codes=[],
                rationale=None,
            ),
        ),
        (
            "definitions_categories",
            DraftDimensionReview.model_construct(
                disposition="not_present",
                atom_ids=[],
                gap_codes=["UNIT_STATUS_GAP"],
                rationale=None,
            ),
        ),
        (
            "definitions_categories",
            DraftDimensionReview.model_construct(
                disposition="not_present",
                atom_ids=[],
                gap_codes=[],
                rationale="Not-present permits no rationale.",
            ),
        ),
        (
            "actors_scope_activities",
            DraftDimensionReview.model_construct(
                disposition="not_material",
                atom_ids=[],
                gap_codes=[],
                rationale=" ",
            ),
        ),
        (
            "actors_scope_activities",
            DraftDimensionReview.model_construct(
                disposition="not_material",
                atom_ids=["atom-rule"],
                gap_codes=[],
                rationale="A concrete but over-populated materiality rationale.",
            ),
        ),
        (
            "actors_scope_activities",
            DraftDimensionReview.model_construct(
                disposition="not_material",
                atom_ids=[],
                gap_codes=["UNIT_STATUS_GAP"],
                rationale="A concrete but over-populated materiality rationale.",
            ),
        ),
    ],
)
def test_unit_dimension_cardinalities_are_revalidated_after_model_bypass(
    field_name: str, replacement: DraftDimensionReview
) -> None:
    units, leads, draft, sources = _complete_case()
    dimensions = draft.unit_reviews[0].dimensions.model_copy(update={field_name: replacement})
    malformed_review = draft.unit_reviews[0].model_copy(update={"dimensions": dimensions})
    draft = draft.model_copy(update={"unit_reviews": [malformed_review]})

    review = evaluate_atomic_target_review(units, leads, draft, sources)

    assert review["valid"] is False
    assert set(_issue_codes(review)) <= {
        "ATOMIC_REVIEW_INVALID",
        "ATOMIC_UNIT_REVIEW_UNRESOLVED",
    }
    assert "ATOMIC_REVIEW_INVALID" in _issue_codes(review)


@pytest.mark.parametrize(
    "malformed",
    [
        DraftLeadDispositionV2.model_construct(
            lead_id="lead-map",
            disposition="mapped",
            atom_ids=[],
            gap_codes=[],
            rationale=None,
        ),
        DraftLeadDispositionV2.model_construct(
            lead_id="lead-map",
            disposition="mapped",
            atom_ids=["atom-rule"],
            gap_codes=["LEAD_REQUIREMENTS_GAP"],
            rationale=None,
        ),
        DraftLeadDispositionV2.model_construct(
            lead_id="lead-map",
            disposition="mapped",
            atom_ids=["atom-rule"],
            gap_codes=[],
            rationale="Mapped permits no rationale.",
        ),
        DraftLeadDispositionV2.model_construct(
            lead_id="lead-map",
            disposition="gap",
            atom_ids=[],
            gap_codes=[],
            rationale=None,
        ),
        DraftLeadDispositionV2.model_construct(
            lead_id="lead-map",
            disposition="gap",
            atom_ids=["atom-rule"],
            gap_codes=["LEAD_REQUIREMENTS_GAP"],
            rationale=None,
        ),
        DraftLeadDispositionV2.model_construct(
            lead_id="lead-map",
            disposition="gap",
            atom_ids=[],
            gap_codes=["LEAD_REQUIREMENTS_GAP"],
            rationale="Gap permits no rationale.",
        ),
        DraftLeadDispositionV2.model_construct(
            lead_id="lead-map",
            disposition="not_material",
            atom_ids=[],
            gap_codes=[],
            rationale=" ",
        ),
        DraftLeadDispositionV2.model_construct(
            lead_id="lead-map",
            disposition="not_material",
            atom_ids=["atom-rule"],
            gap_codes=[],
            rationale="A concrete but over-populated materiality rationale.",
        ),
        DraftLeadDispositionV2.model_construct(
            lead_id="lead-map",
            disposition="not_material",
            atom_ids=[],
            gap_codes=["LEAD_REQUIREMENTS_GAP"],
            rationale="A concrete but over-populated materiality rationale.",
        ),
    ],
)
def test_lead_cardinalities_are_revalidated_after_model_bypass(
    malformed: DraftLeadDispositionV2,
) -> None:
    units, leads, draft, sources = _complete_case()
    dispositions = [
        malformed if row.lead_id == "lead-map" else row for row in draft.lead_dispositions_v2
    ]
    draft = draft.model_copy(update={"lead_dispositions_v2": dispositions})

    review = evaluate_atomic_target_review(units, leads, draft, sources)

    assert "ATOMIC_REVIEW_INVALID" in _issue_codes(review)
    assert "ATOMIC_LEAD_REVIEW_UNRESOLVED" in _issue_codes(review)


@pytest.mark.parametrize(
    "binding",
    [
        "missing",
        "duplicate_gap",
        "wrong_source",
        "duplicate_source",
        "wrong_category",
    ],
)
def test_unit_and_lead_gaps_are_source_and_category_bound(binding: str) -> None:
    units, leads, draft, sources = _complete_case()
    if binding == "missing":
        draft = draft.model_copy(update={"gaps": draft.gaps[1:]})
    elif binding == "duplicate_gap":
        draft = draft.model_copy(update={"gaps": [*draft.gaps, draft.gaps[0]]})
    elif binding == "wrong_source":
        draft.gaps[0] = draft.gaps[0].model_copy(update={"source_ids": ["src-b"]})
    elif binding == "duplicate_source":
        draft.gaps[0] = draft.gaps[0].model_copy(update={"source_ids": ["src-a", "src-a"]})
    else:
        draft.gaps[1] = draft.gaps[1].model_copy(update={"category": "scope"})

    review = evaluate_atomic_target_review(units, leads, draft, sources)

    assert "ATOMIC_GAP_INVALID" in _issue_codes(review)


@pytest.mark.parametrize("duplicate", ["unit_review", "lead_review", "atom"])
def test_duplicate_review_and_atom_ids_fail_closed(duplicate: str) -> None:
    units, leads, draft, sources = _complete_case()
    if duplicate == "unit_review":
        draft = draft.model_copy(
            update={"unit_reviews": [*draft.unit_reviews, draft.unit_reviews[0]]}
        )
    elif duplicate == "lead_review":
        draft = draft.model_copy(
            update={
                "lead_dispositions_v2": [
                    *draft.lead_dispositions_v2,
                    draft.lead_dispositions_v2[0],
                ]
            }
        )
    else:
        draft = draft.model_copy(update={"rule_atoms": [*draft.rule_atoms, draft.rule_atoms[0]]})

    review = evaluate_atomic_target_review(units, leads, draft, sources)

    assert "ATOMIC_REVIEW_INVALID" in _issue_codes(review)


@pytest.mark.parametrize("target", ["unit_review", "lead_review", "atom_unit", "atom_lead"])
def test_unknown_review_and_atom_targets_fail_closed(target: str) -> None:
    units, leads, draft, sources = _complete_case()
    if target == "unit_review":
        draft = draft.model_copy(
            update={
                "unit_reviews": [
                    *draft.unit_reviews,
                    DraftUnitReview(
                        unit_id="unit-unknown",
                        dimensions=_dimensions(
                            atom_id="atom-unknown", unit_gap_code="UNIT_STATUS_GAP"
                        ),
                    ),
                ]
            }
        )
    elif target == "lead_review":
        draft = draft.model_copy(
            update={
                "lead_dispositions_v2": [
                    *draft.lead_dispositions_v2,
                    DraftLeadDispositionV2(
                        lead_id="lead-unknown",
                        disposition="not_material",
                        rationale="The synthetic unknown lead is outside the inventory.",
                    ),
                ]
            }
        )
    elif target == "atom_unit":
        draft = draft.model_copy(
            update={
                "rule_atoms": [
                    draft.rule_atoms[0].model_copy(update={"unit_ids": ["unit-a", "unit-unknown"]})
                ]
            }
        )
    else:
        draft = draft.model_copy(
            update={
                "rule_atoms": [
                    draft.rule_atoms[0].model_copy(
                        update={"lead_ids": ["lead-map", "lead-unknown"]}
                    )
                ]
            }
        )

    review = evaluate_atomic_target_review(units, leads, draft, sources)

    assert "ATOMIC_TARGET_UNKNOWN" in _issue_codes(review)


def test_mapped_review_rejects_an_unknown_atom_identifier() -> None:
    units, leads, draft, sources = _complete_case()
    dimensions = draft.unit_reviews[0].dimensions.model_copy(
        update={"duties_rights_prohibitions": _dimension("mapped", atom_ids=["atom-unknown"])}
    )
    draft = draft.model_copy(
        update={
            "unit_reviews": [draft.unit_reviews[0].model_copy(update={"dimensions": dimensions})]
        }
    )

    review = evaluate_atomic_target_review(units, leads, draft, sources)

    assert "ATOMIC_REVIEW_INVALID" in _issue_codes(review)


def test_malformed_raw_and_typed_rows_return_only_bounded_diagnostics_and_hash() -> None:
    units, leads, draft, sources = _complete_case()
    malformed_atom = draft.rule_atoms[0].model_copy(update={"unit_ids": [["unit-a"]]})
    malformed_gap = draft.gaps[0].model_copy(update={"source_ids": [["src-a"]]})
    draft = draft.model_copy(
        update={
            "unit_reviews": [object()],
            "lead_dispositions_v2": [{"lead_id": "lead-map"}],
            "rule_atoms": [malformed_atom],
            "gaps": [malformed_gap, object()],
        }
    )
    before = (
        deepcopy(units),
        deepcopy(leads),
        draft.model_dump(mode="python", warnings=False),
        [source.model_dump(mode="python", warnings=False) for source in sources],
    )

    review = evaluate_atomic_target_review(units, leads, draft, sources)

    assert review["valid"] is False
    assert set(_issue_codes(review)) <= {
        "ATOMIC_UNIT_REVIEW_UNRESOLVED",
        "ATOMIC_LEAD_REVIEW_UNRESOLVED",
        "ATOMIC_TARGET_UNKNOWN",
        "ATOMIC_REVIEW_INVALID",
        "ATOMIC_GAP_INVALID",
    }
    assert isinstance(review["target_review_hash"], str)
    assert len(review["target_review_hash"]) == 64
    assert (
        units,
        leads,
        draft.model_dump(mode="python", warnings=False),
        [source.model_dump(mode="python", warnings=False) for source in sources],
    ) == before


def test_constructed_review_and_atom_identifiers_are_strictly_revalidated() -> None:
    units, leads, draft, sources = _complete_case()
    malformed_review = DraftUnitReview.model_construct(
        unit_id=["unit-a"], dimensions=draft.unit_reviews[0].dimensions
    )
    malformed_atom = DraftRuleAtom.model_construct(
        **{
            **draft.rule_atoms[0].model_dump(mode="python", warnings=False),
            "atom_id": ["atom-rule"],
        }
    )
    draft = draft.model_copy(
        update={
            "unit_reviews": [malformed_review],
            "rule_atoms": [malformed_atom],
        }
    )

    review = evaluate_atomic_target_review(units, leads, draft, sources)

    assert review["valid"] is False
    assert "ATOMIC_REVIEW_INVALID" in _issue_codes(review)
    assert isinstance(review["target_review_hash"], str)


@pytest.mark.parametrize(
    "mutation",
    [
        "unit_version",
        "lead_version",
        "count",
        "collection",
        "slice",
        "duplicate_target",
        "duplicate_source",
        "source",
    ],
)
def test_malformed_inventories_and_sources_fail_closed_without_escaping(
    mutation: str,
) -> None:
    units, leads, draft, sources = _complete_case()
    if mutation == "unit_version":
        units["inventory_version"] = "source-units-v0"
    elif mutation == "lead_version":
        leads["inventory_version"] = "provision-leads-v0"
    elif mutation == "count":
        units["unit_count"] = True
    elif mutation == "collection":
        units["units"] = {"unit_id": "not-a-list"}
    elif mutation == "slice":
        units["units"][0]["excerpt"] = "neighboring text"
    elif mutation == "duplicate_target":
        units["units"] = [units["units"][0], deepcopy(units["units"][0])]
        units["unit_count"] = 2
        units["required_unit_count"] = 2
    elif mutation == "duplicate_source":
        sources = [sources[0], sources[0]]
    else:
        sources = [sources[0].model_copy(update={"source_id": ["src-a"]})]

    review = evaluate_atomic_target_review(units, leads, draft, sources)

    assert review["valid"] is False
    assert set(_issue_codes(review)) <= {
        "ATOMIC_UNIT_REVIEW_UNRESOLVED",
        "ATOMIC_LEAD_REVIEW_UNRESOLVED",
        "ATOMIC_TARGET_UNKNOWN",
        "ATOMIC_REVIEW_INVALID",
        "ATOMIC_GAP_INVALID",
    }
    assert "ATOMIC_REVIEW_INVALID" in _issue_codes(review)
    assert isinstance(review["target_review_hash"], str)


def test_multi_source_results_hash_and_inputs_are_canonical_and_unmodified() -> None:
    unit_rows = [_unit("src-b", "unit-b"), _unit("src-a", "unit-a")]
    lead_rows = [
        _lead("src-b", "lead-b", review_required=False),
        _lead("src-a", "lead-a", review_required=True),
    ]
    units, leads = _inventories(units=unit_rows, leads=lead_rows)
    atom = _atom(
        "atom-shared",
        unit_ids=["unit-b", "unit-a"],
        lead_ids=["lead-b", "lead-a"],
    )
    reviews = [
        DraftUnitReview(
            unit_id=unit_id,
            dimensions=DraftUnitReviewDimensions(
                **{
                    name: _dimension("mapped", atom_ids=["atom-shared"])
                    if name == "duties_rights_prohibitions"
                    else _dimension("not_present")
                    for name in DIMENSION_NAMES
                }
            ),
        )
        for unit_id in ("unit-b", "unit-a")
    ]
    dispositions = [
        DraftLeadDispositionV2(lead_id=lead_id, disposition="mapped", atom_ids=["atom-shared"])
        for lead_id in ("lead-b", "lead-a")
    ]
    draft = AnalysisDraft(
        coverage_contract_version="proposition-coverage-v2",
        unit_reviews=reviews,
        lead_dispositions_v2=dispositions,
        rule_atoms=[atom],
    )
    sources = [_source("src-b"), _source("src-a")]
    before = (
        deepcopy(units),
        deepcopy(leads),
        draft.model_dump(mode="python", warnings=False),
        [source.model_dump(mode="python", warnings=False) for source in sources],
    )

    first = evaluate_atomic_target_review(units, leads, draft, sources)
    repeated = evaluate_atomic_target_review(units, leads, draft, sources)
    reordered = evaluate_atomic_target_review(
        {**units, "units": list(reversed(units["units"]))},
        {**leads, "leads": list(reversed(leads["leads"]))},
        draft.model_copy(
            update={
                "unit_reviews": list(reversed(draft.unit_reviews)),
                "lead_dispositions_v2": list(reversed(draft.lead_dispositions_v2)),
                "rule_atoms": [
                    atom.model_copy(
                        update={
                            "unit_ids": list(reversed(atom.unit_ids)),
                            "lead_ids": list(reversed(atom.lead_ids)),
                        }
                    )
                ],
            }
        ),
        list(reversed(sources)),
    )

    assert first == repeated == reordered
    assert [row["unit_id"] for row in first["units"]] == ["unit-a", "unit-b"]
    assert [row["lead_id"] for row in first["leads"]] == ["lead-a", "lead-b"]
    assert (
        units,
        leads,
        draft.model_dump(mode="python", warnings=False),
        [source.model_dump(mode="python", warnings=False) for source in sources],
    ) == before


@pytest.mark.parametrize(
    ("proposition_type", "required_elements", "required_relationship"),
    RULE_GRAPH_CASES,
)
def test_rule_graph_accepts_each_category_exact_minimum(
    proposition_type: str,
    required_elements: tuple[str, ...],
    required_relationship: str | tuple[str, ...] | None,
) -> None:
    review = evaluate_rule_graph(_minimum_graph_case(proposition_type))

    assert review["schema_version"] == "1.0"
    assert review["coverage_contract_version"] == "proposition-coverage-v2"
    assert review["valid"] is True
    subject = next(row for row in review["atoms"] if row["atom_id"] == "atom-subject")
    assert subject["required_elements"] == sorted(required_elements)
    assert set(subject["stated_elements"]) == set(required_elements)
    expected_relationships = (
        []
        if required_relationship is None
        else sorted(
            required_relationship
            if isinstance(required_relationship, tuple)
            else (required_relationship,)
        )
    )
    assert subject["required_relationship_types"] == expected_relationships
    assert subject["valid"] is True
    assert isinstance(review["rule_graph_hash"], str)
    assert len(review["rule_graph_hash"]) == 64


@pytest.mark.parametrize(
    ("proposition_type", "required_elements", "required_relationship"),
    RULE_GRAPH_CASES,
)
def test_rule_graph_rejects_each_missing_required_element(
    proposition_type: str,
    required_elements: tuple[str, ...],
    required_relationship: str | tuple[str, ...] | None,
) -> None:
    del required_relationship
    draft = _minimum_graph_case(proposition_type)
    subject = next(atom for atom in draft.rule_atoms if atom.atom_id == "atom-subject")
    missing_element = required_elements[0]
    elements = subject.elements.model_copy(
        update={missing_element: DraftAtomElement(status="not_applicable")}
    )
    replacement = subject.model_copy(update={"elements": elements})
    draft = draft.model_copy(
        update={
            "rule_atoms": [
                replacement if atom.atom_id == "atom-subject" else atom
                for atom in draft.rule_atoms
            ]
        }
    )

    review = evaluate_rule_graph(draft)

    assert review["valid"] is False
    assert any(
        issue["code"] == "ATOMIC_REQUIRED_ELEMENT_MISSING"
        and set(issue["related_ids"]) == {"atom-subject", missing_element}
        for issue in review["issues"]
    )
    subject_result = next(
        row for row in review["atoms"] if row["atom_id"] == "atom-subject"
    )
    assert subject_result["valid"] is False


@pytest.mark.parametrize(
    "proposition_type",
    [
        "exception",
        "deadline",
        "enforcement_trigger",
        "enforcement_route",
        "remedy",
        "penalty",
        "appeal",
    ],
)
def test_rule_graph_requires_each_category_relationship_family(
    proposition_type: str,
) -> None:
    draft = _minimum_graph_case(proposition_type)
    draft = draft.model_copy(
        update={
            "rule_relationships": [
                relationship
                for relationship in draft.rule_relationships
                if relationship.source_atom_id != "atom-subject"
            ]
        }
    )

    review = evaluate_rule_graph(draft)

    assert "ATOMIC_RELATIONSHIP_REQUIRED" in _issue_codes(review)
    assert any(
        issue["code"] == "ATOMIC_RELATIONSHIP_REQUIRED"
        and issue["related_ids"] == ["atom-subject"]
        for issue in review["issues"]
    )


@pytest.mark.parametrize("proposition_type", ["remedy", "penalty"])
@pytest.mark.parametrize("relation_type", ["triggered_by", "consequence_of"])
def test_consequence_categories_accept_exactly_either_relationship_alternative(
    proposition_type: str,
    relation_type: str,
) -> None:
    consequence = _graph_atom("atom-consequence", proposition_type)
    if relation_type == "triggered_by":
        trigger = _graph_atom("atom-trigger", "enforcement_trigger")
        governed = _graph_atom("atom-governed", "duty")
        atoms = [consequence, trigger, governed]
        relationships = [
            _graph_relationship(
                "relationship-consequence",
                "triggered_by",
                "atom-consequence",
                "atom-trigger",
            ),
            _graph_relationship(
                "relationship-trigger", "triggered_by", "atom-trigger", "atom-governed"
            ),
        ]
    else:
        governed = _graph_atom("atom-governed", "duty")
        atoms = [consequence, governed]
        relationships = [
            _graph_relationship(
                "relationship-consequence",
                "consequence_of",
                "atom-consequence",
                "atom-governed",
            )
        ]

    review = evaluate_rule_graph(_graph_draft(atoms, relationships))

    assert review["valid"] is True


@pytest.mark.parametrize(
    ("relation_type", "source_type", "target_type"),
    RELATIONSHIP_DIRECTION_CASES,
)
def test_each_relationship_type_accepts_its_valid_direction_and_categories(
    relation_type: str,
    source_type: str,
    target_type: str,
) -> None:
    source = _graph_atom("atom-source", source_type)
    target = _graph_atom("atom-target", target_type)
    atoms = [source, target]
    relationships = [
        _graph_relationship(
            "relationship-main", relation_type, "atom-source", "atom-target"
        )
    ]
    if target_type == "penalty":
        governed = _graph_atom("atom-governed", "duty")
        atoms.append(governed)
        relationships.append(
            _graph_relationship(
                "relationship-penalty",
                "consequence_of",
                "atom-target",
                "atom-governed",
            )
        )

    review = evaluate_rule_graph(_graph_draft(atoms, relationships))

    assert review["valid"] is True
    main = next(
        row
        for row in review["relationships"]
        if row["relationship_id"] == "relationship-main"
    )
    assert main["valid"] is True


@pytest.mark.parametrize(
    ("relation_type", "source_type", "target_type"),
    RELATIONSHIP_DIRECTION_CASES,
)
def test_each_relationship_type_rejects_reversed_direction(
    relation_type: str,
    source_type: str,
    target_type: str,
) -> None:
    source = _graph_atom("atom-source", source_type)
    target = _graph_atom("atom-target", target_type)
    reversed_relationship = _graph_relationship(
        "relationship-reversed", relation_type, "atom-target", "atom-source"
    )

    review = evaluate_rule_graph(_graph_draft([source, target], [reversed_relationship]))

    assert "ATOMIC_RELATIONSHIP_INVALID" in _issue_codes(review)
    assert any(
        issue["code"] == "ATOMIC_RELATIONSHIP_INVALID"
        and "relationship-reversed" in issue["related_ids"]
        for issue in review["issues"]
    )
    required_relationship = next(
        required
        for case_type, _, required in RULE_GRAPH_CASES
        if case_type == source_type
    )
    if required_relationship is not None:
        assert "ATOMIC_RELATIONSHIP_REQUIRED" in _issue_codes(review)


def test_prohibited_category_valid_relationship_cycle_is_rejected_once() -> None:
    first = _graph_atom("atom-a", "exception")
    second = _graph_atom("atom-b", "exception")
    relationships = [
        _graph_relationship("relationship-a", "exception_to", "atom-a", "atom-b"),
        _graph_relationship("relationship-b", "exception_to", "atom-b", "atom-a"),
    ]

    review = evaluate_rule_graph(_graph_draft([first, second], relationships))

    assert review["issues"] == [
        {
            "code": "ATOMIC_RELATIONSHIP_INVALID",
            "message": "Atomic rule relationships contain a prohibited cycle.",
            "related_ids": ["atom-a", "atom-b"],
        }
    ]
    assert review["rule_counts"]["invalid_atoms"] == 0
    assert review["rule_counts"]["invalid_relationships"] == 2


def test_category_invalid_reverse_edge_cannot_contaminate_valid_edge_or_atom() -> None:
    exception = _graph_atom("atom-exception", "exception")
    duty = _graph_atom("atom-duty", "duty")
    valid = _graph_relationship(
        "relationship-valid",
        "exception_to",
        "atom-exception",
        "atom-duty",
    )
    invalid_reverse = _graph_relationship(
        "relationship-invalid-reverse",
        "deadline_for",
        "atom-duty",
        "atom-exception",
    )

    review = evaluate_rule_graph(
        _graph_draft([exception, duty], [valid, invalid_reverse])
    )

    assert review["issues"] == [
        {
            "code": "ATOMIC_RELATIONSHIP_INVALID",
            "message": "A rule relationship has an invalid direction or endpoint category.",
            "related_ids": [
                "atom-duty",
                "atom-exception",
                "relationship-invalid-reverse",
            ],
        }
    ]
    atom_by_id = {row["atom_id"]: row for row in review["atoms"]}
    relationship_by_id = {
        row["relationship_id"]: row for row in review["relationships"]
    }
    assert atom_by_id["atom-exception"]["valid"] is True
    assert relationship_by_id["relationship-valid"]["valid"] is True
    assert relationship_by_id["relationship-invalid-reverse"]["valid"] is False


def test_one_category_valid_cycle_root_is_bounded_for_two_or_fifty_nodes() -> None:
    def cycle_draft(node_count: int) -> AnalysisDraft:
        atom_ids = [f"atom-{index:02d}" for index in range(node_count)]
        return _graph_draft(
            [_graph_atom(atom_id, "exception") for atom_id in atom_ids],
            [
                _graph_relationship(
                    f"relationship-{index:02d}",
                    "exception_to",
                    atom_id,
                    atom_ids[(index + 1) % node_count],
                )
                for index, atom_id in enumerate(atom_ids)
            ],
        )

    small = evaluate_rule_graph(cycle_draft(2))
    large_draft = cycle_draft(50)
    before = large_draft.model_dump(mode="python", warnings=False)
    large = evaluate_rule_graph(large_draft)
    repeated = evaluate_rule_graph(large_draft)
    reordered = evaluate_rule_graph(
        large_draft.model_copy(
            update={
                "rule_atoms": list(reversed(large_draft.rule_atoms)),
                "rule_relationships": list(reversed(large_draft.rule_relationships)),
            }
        )
    )

    assert len(small["issues"]) == len(large["issues"]) == 1
    assert _issue_codes(small) == _issue_codes(large) == [
        "ATOMIC_RELATIONSHIP_INVALID"
    ]
    assert small["issues"][0]["message"] == large["issues"][0]["message"] == (
        "Atomic rule relationships contain a prohibited cycle."
    )
    assert "ATOMIC_RELATIONSHIP_REQUIRED" not in _issue_codes(large)
    assert large["rule_counts"] == {
        "atom_rows": 50,
        "atoms": 50,
        "invalid_atoms": 0,
        "relationship_rows": 50,
        "relationships": 50,
        "invalid_relationships": 50,
    }
    assert large == repeated == reordered
    assert large_draft.model_dump(mode="python", warnings=False) == before


@pytest.mark.parametrize("relation_type", ["qualifies", "defines"])
def test_qualifies_and_defines_may_form_non_self_cycles(relation_type: str) -> None:
    proposition_type = "scope" if relation_type == "qualifies" else "definition"
    first = _graph_atom("atom-a", proposition_type)
    second = _graph_atom("atom-b", proposition_type)
    relationships = [
        _graph_relationship("relationship-a", relation_type, "atom-a", "atom-b"),
        _graph_relationship("relationship-b", relation_type, "atom-b", "atom-a"),
    ]

    review = evaluate_rule_graph(_graph_draft([first, second], relationships))

    assert review["valid"] is True


def test_self_relationship_bypass_fails_closed() -> None:
    atom = _graph_atom("atom-self", "scope")
    relationship = DraftRuleRelationship.model_construct(
        relationship_id="relationship-self",
        relation_type="qualifies",
        source_atom_id="atom-self",
        target_atom_id="atom-self",
        claim_ids=["claim-self"],
    )
    draft = _graph_draft([atom]).model_copy(
        update={"rule_relationships": [relationship]}
    )

    review = evaluate_rule_graph(draft)

    assert review["valid"] is False
    assert _issue_codes(review) == ["ATOMIC_RELATIONSHIP_INVALID"]
    assert review["rule_counts"] == {
        "atom_rows": 1,
        "atoms": 1,
        "invalid_atoms": 0,
        "relationship_rows": 1,
        "relationships": 1,
        "invalid_relationships": 1,
    }


@pytest.mark.parametrize("endpoint", ["source", "target"])
def test_unknown_relationship_endpoints_fail_closed(endpoint: str) -> None:
    source = _graph_atom("atom-source", "scope")
    source_id = "atom-unknown" if endpoint == "source" else "atom-source"
    target_id = "atom-unknown" if endpoint == "target" else "atom-source"
    relationship = _graph_relationship(
        "relationship-unknown", "qualifies", source_id, target_id
    )

    review = evaluate_rule_graph(_graph_draft([source], [relationship]))

    assert "ATOMIC_RELATIONSHIP_UNKNOWN" in _issue_codes(review)
    assert any(
        issue["code"] == "ATOMIC_RELATIONSHIP_UNKNOWN"
        and issue["related_ids"] == ["atom-unknown"]
        for issue in review["issues"]
    )


def test_unknown_endpoint_diagnostics_do_not_scale_with_references() -> None:
    atom = _graph_atom("atom-source", "scope")

    def review_for(count: int) -> dict[str, object]:
        return evaluate_rule_graph(
            _graph_draft(
                [atom],
                [
                    _graph_relationship(
                        f"relationship-{index:02d}",
                        "qualifies",
                        "atom-source",
                        "atom-unknown",
                    )
                    for index in range(count)
                ],
            )
        )

    one = review_for(1)
    fifty = review_for(50)

    assert one["issues"] == fifty["issues"]
    assert one["issues"] == [
        {
            "code": "ATOMIC_RELATIONSHIP_UNKNOWN",
            "message": "A rule relationship references an unknown atom.",
            "related_ids": ["atom-unknown"],
        }
    ]


@pytest.mark.parametrize("duplicate_kind", ["atom", "relationship"])
def test_duplicate_graph_ids_collapse_to_one_invalid_canonical_result(
    duplicate_kind: str,
) -> None:
    atom = _graph_atom("atom-duplicate", "scope")
    relationship = _graph_relationship(
        "relationship-duplicate", "qualifies", "atom-duplicate", "atom-target"
    )
    target = _graph_atom("atom-target", "duty")
    draft = _graph_draft(
        [atom, target],
        [relationship] if duplicate_kind == "relationship" else [],
    )
    draft = draft.model_copy(
        update={
            "rule_atoms": [atom, atom, target]
            if duplicate_kind == "atom"
            else [atom, target],
            "rule_relationships": [relationship, relationship]
            if duplicate_kind == "relationship"
            else [],
        }
    )

    review = evaluate_rule_graph(draft)

    assert review["valid"] is False
    rows = review["atoms"] if duplicate_kind == "atom" else review["relationships"]
    identifier_field = "atom_id" if duplicate_kind == "atom" else "relationship_id"
    duplicate_id = f"{duplicate_kind}-duplicate"
    matching = [row for row in rows if row[identifier_field] == duplicate_id]
    assert len(matching) == 1
    assert matching[0]["row_state"] == "invalid"
    assert matching[0]["valid"] is False
    counts = review["rule_counts"]
    assert counts[f"{duplicate_kind}_rows"] == (
        3 if duplicate_kind == "atom" else 2
    )
    plural = "atoms" if duplicate_kind == "atom" else "relationships"
    assert counts[plural] == (2 if duplicate_kind == "atom" else 1)
    assert counts[f"invalid_{plural}"] == 1


@pytest.mark.parametrize("row_kind", ["atom", "relationship"])
def test_malformed_no_id_graph_row_counts_only_as_a_raw_row(row_kind: str) -> None:
    atom = _graph_atom("atom-valid", "scope")
    target = _graph_atom("atom-target", "duty")
    relationship = _graph_relationship(
        "relationship-valid", "qualifies", "atom-valid", "atom-target"
    )
    draft = _graph_draft([atom, target], [relationship])
    if row_kind == "atom":
        draft = draft.model_copy(update={"rule_atoms": [atom, target, object()]})
    else:
        draft = draft.model_copy(
            update={"rule_relationships": [relationship, object()]}
        )

    review = evaluate_rule_graph(draft)

    counts = review["rule_counts"]
    assert counts[f"{row_kind}_rows"] == (3 if row_kind == "atom" else 2)
    plural = "atoms" if row_kind == "atom" else "relationships"
    assert counts[plural] == (2 if row_kind == "atom" else 1)
    assert counts[f"invalid_{plural}"] == 0
    expected_code = (
        "ATOMIC_RULE_INVALID"
        if row_kind == "atom"
        else "ATOMIC_RELATIONSHIP_INVALID"
    )
    assert expected_code in _issue_codes(review)


@pytest.mark.parametrize(
    "malformed_atom",
    [
        DraftRuleAtom.model_construct(
            atom_id="atom-no-target",
            unit_ids=[],
            lead_ids=[],
            category="requirements",
            proposition_type="duty",
            materiality="material",
            elements=_graph_atom("seed-target", "duty").elements,
            omission_rationale="A valid-looking but targetless atom.",
        ),
        _graph_atom("atom-no-rationale", "duty").model_copy(
            update={"omission_rationale": " "}
        ),
        DraftRuleAtom.model_construct(
            **{
                **_graph_atom("atom-list-id", "duty").model_dump(
                    mode="python", warnings=False
                ),
                "atom_id": ["atom-list-id"],
            }
        ),
    ],
)
def test_malformed_atom_bypasses_return_bounded_rule_diagnostics(
    malformed_atom: DraftRuleAtom,
) -> None:
    draft = _graph_draft([]).model_copy(update={"rule_atoms": [malformed_atom]})

    review = evaluate_rule_graph(draft)

    assert review["valid"] is False
    assert set(_issue_codes(review)) == {"ATOMIC_RULE_INVALID"}
    assert isinstance(review["rule_graph_hash"], str)


@pytest.mark.parametrize("malformation", ["element_list", "text_list", "duplicate_actions"])
def test_action_bearing_atoms_reject_list_valued_or_duplicate_actions(
    malformation: str,
) -> None:
    atom = _graph_atom("atom-action", "duty")
    if malformation == "element_list":
        elements = atom.elements.model_copy(
            update={
                "operative_action": [
                    atom.elements.operative_action,
                    atom.elements.operative_action,
                ]
            }
        )
    else:
        malformed_element = DraftAtomElement.model_construct(
            status="stated",
            text=["maintain", "maintain"]
            if malformation == "duplicate_actions"
            else ["maintain"],
            claim_ids=["claim-action"],
            gap_codes=[],
        )
        elements = atom.elements.model_copy(update={"operative_action": malformed_element})
    malformed_atom = atom.model_copy(update={"elements": elements})
    draft = _graph_draft([]).model_copy(update={"rule_atoms": [malformed_atom]})

    review = evaluate_rule_graph(draft)

    assert review["valid"] is False
    assert set(_issue_codes(review)) == {"ATOMIC_RULE_INVALID"}


def test_two_independent_atoms_from_one_unit_are_valid() -> None:
    first = _graph_atom("atom-first", "duty", unit_ids=["unit-dense"])
    second = _graph_atom("atom-second", "duty", unit_ids=["unit-dense"])

    review = evaluate_rule_graph(_graph_draft([first, second]))

    assert review["valid"] is True
    assert [row["atom_id"] for row in review["atoms"]] == ["atom-first", "atom-second"]


def test_rule_graph_repeat_reorder_and_inputs_are_deterministic_and_unmodified() -> None:
    draft = _graph_draft(
        [
            _graph_atom("atom-definition", "definition"),
            _graph_atom("atom-duty", "duty"),
            _graph_atom("atom-scope", "scope"),
        ],
        [
            _graph_relationship(
                "relationship-definition", "defines", "atom-definition", "atom-duty"
            ),
            _graph_relationship(
                "relationship-scope", "qualifies", "atom-scope", "atom-duty"
            ),
        ],
    )
    before = draft.model_dump(mode="python", warnings=False)

    first = evaluate_rule_graph(draft)
    repeated = evaluate_rule_graph(draft)
    reordered = evaluate_rule_graph(
        draft.model_copy(
            update={
                "rule_atoms": list(reversed(draft.rule_atoms)),
                "rule_relationships": list(reversed(draft.rule_relationships)),
            }
        )
    )

    assert first == repeated == reordered
    assert draft.model_dump(mode="python", warnings=False) == before


def test_raw_and_constructed_relationship_rows_fail_closed_without_escaping() -> None:
    atom = _graph_atom("atom-scope", "scope")
    target = _graph_atom("atom-duty", "duty")
    malformed = DraftRuleRelationship.model_construct(
        relationship_id=["relationship-malformed"],
        relation_type="qualifies",
        source_atom_id=["atom-scope"],
        target_atom_id="atom-duty",
        claim_ids=[],
    )
    draft = _graph_draft([atom, target]).model_copy(
        update={"rule_relationships": [malformed, {"relationship_id": "raw-row"}]}
    )

    review = evaluate_rule_graph(draft)

    assert review["valid"] is False
    assert set(_issue_codes(review)) == {"ATOMIC_RELATIONSHIP_INVALID"}
    assert isinstance(review["rule_graph_hash"], str)


def _evidence_claim(
    claim_id: str,
    text: str,
    *,
    source_id: str = "src-a",
    kind: ClaimKind = ClaimKind.SOURCE_SUPPORTED,
    citations: list[ProposedCitation] | None = None,
) -> DraftClaim:
    return DraftClaim(
        claim_id=claim_id,
        text=text,
        kind=kind,
        proposed_citations=(
            citations
            if citations is not None
            else (
                [ProposedCitation(source_id=source_id, quote=text)]
                if kind is ClaimKind.SOURCE_SUPPORTED
                else []
            )
        ),
    )


def _evidence_atom(
    atom_id: str,
    proposition_type: str,
    *,
    unit_ids: list[str],
    lead_ids: list[str],
    claim_by_element: dict[str, str],
    materiality: str = "material",
) -> DraftRuleAtom:
    elements = {
        field_name: (
            DraftAtomElement(
                status="stated",
                text=f"Synthetic {field_name.replace('_', ' ')}",
                claim_ids=[claim_by_element[field_name]],
            )
            if field_name in claim_by_element
            else DraftAtomElement(status="not_applicable")
        )
        for field_name in DraftRuleAtomElements.model_fields
    }
    return DraftRuleAtom(
        atom_id=atom_id,
        unit_ids=unit_ids,
        lead_ids=lead_ids,
        category=("deadlines" if proposition_type == "deadline" else "requirements"),
        proposition_type=proposition_type,
        materiality=materiality,
        elements=DraftRuleAtomElements(**elements),
        omission_rationale=f"Omission would hide the synthetic {proposition_type} proposition.",
    )


def _mapped_dimensions(
    dimension_name: str,
    atom_ids: list[str],
) -> DraftUnitReviewDimensions:
    return DraftUnitReviewDimensions(
        **{
            name: (
                _dimension("mapped", atom_ids=atom_ids)
                if name == dimension_name
                else _dimension("not_present")
            )
            for name in DIMENSION_NAMES
        }
    )


def _visible_brief(
    *,
    atom_ids: list[str],
    claim_ids: list[str],
    relationship_ids: list[str] | None = None,
    shape: str = "paragraph",
) -> AttorneyBrief:
    if shape == "paragraph":
        block = BriefBlock(
            kind="paragraph",
            purpose="legal_analysis",
            text="The synthetic rule is stated in natural legal analysis.",
            atom_ids=atom_ids,
            claim_ids=claim_ids,
            relationship_ids=relationship_ids or [],
        )
    elif shape == "item":
        block = BriefBlock(
            kind="bullet_list",
            purpose="legal_analysis",
            items=[
                BriefItem(
                    text="The synthetic rule and its qualification are stated together.",
                    atom_ids=atom_ids,
                    claim_ids=claim_ids,
                    relationship_ids=relationship_ids or [],
                )
            ],
        )
    else:
        block = BriefBlock(
            kind="table",
            purpose="legal_analysis",
            columns=["Rule", "Effect"],
            rows=[
                BriefTableRow(
                    cells=["Synthetic rule", "Synthetic effect"],
                    atom_ids=atom_ids,
                    claim_ids=claim_ids,
                    relationship_ids=relationship_ids or [],
                )
            ],
        )
    return AttorneyBrief(
        structure_profile="regulatory-walk-v1",
        executive_summary=[block],
        sections=[
            BriefSection(
                section_id="requirements",
                title="Synthetic Requirements",
                blocks=[block],
            )
        ],
    )


def _single_atom_coverage_case(
    *,
    materiality: str = "material",
    atom_visible: bool = True,
    claim_visible: bool = True,
    supporting_lead_only: bool = False,
) -> tuple[dict[str, object], dict[str, object], AnalysisDraft, list[SourceRecord]]:
    unit_rows = [] if supporting_lead_only else [_unit("src-a", "unit-a")]
    lead_rows = [_lead("src-a", "lead-a", review_required=True)]
    units, leads = _inventories(units=unit_rows, leads=lead_rows)
    atom = _evidence_atom(
        "atom-duty",
        "duty",
        unit_ids=[] if supporting_lead_only else ["unit-a"],
        lead_ids=["lead-a"],
        claim_by_element={
            "actor": "claim-duty",
            "modality": "claim-duty",
            "operative_action": "claim-duty",
            "object": "claim-duty",
        },
        materiality=materiality,
    )
    claim = _evidence_claim("claim-duty", SOURCE_TEXT["src-a"])
    brief = _visible_brief(
        atom_ids=["atom-duty"] if atom_visible else [],
        claim_ids=["claim-duty"] if claim_visible else [],
    )
    draft = AnalysisDraft(
        coverage_contract_version="proposition-coverage-v2",
        issues=[
            DraftIssue(
                issue_id="issue-requirements",
                title="Synthetic requirements",
                category="requirements",
                jurisdictions=["US"],
            )
        ],
        findings=[
            DraftFinding(
                finding_id="finding-requirements",
                issue_id="issue-requirements",
                title="Synthetic duty",
                jurisdiction="US",
                authority="Synthetic Rule",
                severity=Severity.INFO,
                practical_implication="Assess the synthetic duty.",
                claims=[claim],
            )
        ],
        unit_reviews=(
            []
            if supporting_lead_only
            else [
                DraftUnitReview(
                    unit_id="unit-a",
                    dimensions=_mapped_dimensions(
                        "duties_rights_prohibitions", ["atom-duty"]
                    ),
                )
            ]
        ),
        lead_dispositions_v2=[
            DraftLeadDispositionV2(
                lead_id="lead-a",
                disposition="mapped",
                atom_ids=["atom-duty"],
            )
        ],
        rule_atoms=[atom],
        brief=brief,
    )
    return units, leads, draft, [_source("src-a")]


def _relationship_coverage_case() -> tuple[
    dict[str, object], dict[str, object], AnalysisDraft, list[SourceRecord]
]:
    units, leads = _inventories(
        units=[_unit("src-b", "unit-b"), _unit("src-a", "unit-a")],
        leads=[
            _lead("src-b", "lead-b", review_required=True),
            _lead("src-a", "lead-a", review_required=True),
        ],
    )
    duty = _evidence_atom(
        "atom-duty",
        "duty",
        unit_ids=["unit-a"],
        lead_ids=["lead-a"],
        claim_by_element={
            "actor": "claim-duty",
            "modality": "claim-duty",
            "operative_action": "claim-duty",
            "object": "claim-duty",
        },
    )
    exception = _evidence_atom(
        "atom-exception",
        "exception",
        unit_ids=["unit-b"],
        lead_ids=["lead-b"],
        claim_by_element={"exception": "claim-exception"},
    )
    relationship = DraftRuleRelationship(
        relationship_id="relationship-exception",
        relation_type="exception_to",
        source_atom_id="atom-exception",
        target_atom_id="atom-duty",
        claim_ids=["claim-relationship"],
    )
    claims = [
        _evidence_claim("claim-duty", SOURCE_TEXT["src-a"]),
        _evidence_claim(
            "claim-exception", SOURCE_TEXT["src-b"], source_id="src-b"
        ),
        _evidence_claim(
            "claim-relationship",
            "The synthetic exception qualifies the synthetic duty.",
            citations=[
                ProposedCitation(source_id="src-a", quote=SOURCE_TEXT["src-a"]),
                ProposedCitation(source_id="src-b", quote=SOURCE_TEXT["src-b"]),
            ],
        ),
    ]
    draft = AnalysisDraft(
        coverage_contract_version="proposition-coverage-v2",
        issues=[
            DraftIssue(
                issue_id="issue-requirements",
                title="Synthetic requirements",
                category="requirements",
                jurisdictions=["US"],
            )
        ],
        findings=[
            DraftFinding(
                finding_id="finding-requirements",
                issue_id="issue-requirements",
                title="Synthetic duty and exception",
                jurisdiction="US",
                authority="Synthetic Rules",
                severity=Severity.INFO,
                practical_implication="Read the duty with its exception.",
                claims=claims,
            )
        ],
        unit_reviews=[
            DraftUnitReview(
                unit_id="unit-b",
                dimensions=_mapped_dimensions(
                    "conditions_exceptions_defenses", ["atom-exception"]
                ),
            ),
            DraftUnitReview(
                unit_id="unit-a",
                dimensions=_mapped_dimensions(
                    "duties_rights_prohibitions", ["atom-duty"]
                ),
            ),
        ],
        lead_dispositions_v2=[
            DraftLeadDispositionV2(
                lead_id="lead-b",
                disposition="mapped",
                atom_ids=["atom-exception"],
            ),
            DraftLeadDispositionV2(
                lead_id="lead-a",
                disposition="mapped",
                atom_ids=["atom-duty"],
            ),
        ],
        rule_atoms=[exception, duty],
        rule_relationships=[relationship],
        brief=_visible_brief(
            atom_ids=["atom-duty", "atom-exception"],
            claim_ids=["claim-duty", "claim-exception", "claim-relationship"],
            relationship_ids=["relationship-exception"],
            shape="item",
        ),
    )
    return units, leads, draft, [_source("src-b"), _source("src-a")]


def _visibility_chain_case(
    *,
    visible_atom_ids: list[str] | None = None,
    visible_relationship_ids: list[str] | None = None,
    mapped_supporting_c: bool = False,
) -> tuple[dict[str, object], dict[str, object], AnalysisDraft, list[SourceRecord]]:
    units, leads = _inventories(
        units=[_unit("src-a", "unit-a")],
        leads=[
            _lead("src-a", "lead-b", review_required=True),
            _lead("src-a", "lead-c", review_required=True),
            _lead("src-a", "lead-d", review_required=True),
        ],
    )
    atoms = [
        _evidence_atom(
            "atom-a",
            "duty",
            unit_ids=["unit-a"],
            lead_ids=[],
            claim_by_element={
                "actor": "claim-chain",
                "modality": "claim-chain",
                "operative_action": "claim-chain",
                "object": "claim-chain",
            },
        ),
        *[
            _evidence_atom(
                f"atom-{suffix}",
                "scope",
                unit_ids=["unit-a"] if mapped_supporting_c and suffix == "c" else [],
                lead_ids=[f"lead-{suffix}"],
                claim_by_element={
                    "actor": "claim-chain",
                    "object": "claim-chain",
                },
                materiality="supporting",
            )
            for suffix in ("b", "c", "d")
        ],
    ]
    relationships = [
        DraftRuleRelationship(
            relationship_id=f"relationship-{source}-{target}",
            relation_type="qualifies",
            source_atom_id=f"atom-{source}",
            target_atom_id=f"atom-{target}",
            claim_ids=["claim-chain"],
        )
        for source, target in (("b", "a"), ("c", "b"), ("d", "c"))
    ]
    mapped_atoms = ["atom-a"] + (["atom-c"] if mapped_supporting_c else [])
    draft = AnalysisDraft(
        coverage_contract_version="proposition-coverage-v2",
        issues=[
            DraftIssue(
                issue_id="issue-requirements",
                title="Synthetic requirements",
                category="requirements",
                jurisdictions=["US"],
            )
        ],
        findings=[
            DraftFinding(
                finding_id="finding-chain",
                issue_id="issue-requirements",
                title="Synthetic visibility chain",
                jurisdiction="US",
                authority="Synthetic Rule",
                severity=Severity.INFO,
                practical_implication="Review only directly material relationships.",
                claims=[_evidence_claim("claim-chain", SOURCE_TEXT["src-a"])],
            )
        ],
        unit_reviews=[
            DraftUnitReview(
                unit_id="unit-a",
                dimensions=_mapped_dimensions(
                    "duties_rights_prohibitions", mapped_atoms
                ),
            )
        ],
        lead_dispositions_v2=[
            DraftLeadDispositionV2(
                lead_id=f"lead-{suffix}",
                disposition="mapped",
                atom_ids=[f"atom-{suffix}"],
            )
            for suffix in ("b", "c", "d")
        ],
        rule_atoms=atoms,
        rule_relationships=relationships,
        brief=_visible_brief(
            atom_ids=(
                visible_atom_ids
                if visible_atom_ids is not None
                else ["atom-a", "atom-b"]
            ),
            claim_ids=["claim-chain"],
            relationship_ids=(
                visible_relationship_ids
                if visible_relationship_ids is not None
                else ["relationship-b-a"]
            ),
        ),
    )
    return units, leads, draft, [_source("src-a")]


def _replace_visible_brief(
    draft: AnalysisDraft,
    *,
    atom_ids: list[str],
    claim_ids: list[str],
    relationship_ids: list[str] | None = None,
    shape: str = "paragraph",
) -> AnalysisDraft:
    return draft.model_copy(
        update={
            "brief": _visible_brief(
                atom_ids=atom_ids,
                claim_ids=claim_ids,
                relationship_ids=relationship_ids,
                shape=shape,
            )
        }
    )


def test_atomic_coverage_is_exported_and_composes_canonical_schema_three() -> None:
    units, leads, draft, sources = _single_atom_coverage_case()

    review = evaluate_atomic_coverage(units, leads, draft, sources)
    without_hash = dict(review)
    review_hash = without_hash.pop("coverage_review_hash")

    assert analysis_package.evaluate_atomic_coverage is evaluate_atomic_coverage
    assert analysis_package.compose_atomic_coverage_review is compose_atomic_coverage_review
    assert analysis_package.evaluate_rule_graph is evaluate_rule_graph
    assert review["schema_version"] == "3.0"
    assert review["coverage_contract_version"] == "proposition-coverage-v2"
    assert review["valid"] is True
    assert review["target_review"]["valid"] is True
    assert review["rule_graph"]["valid"] is True
    assert list(review["counts"]) == sorted(review["counts"])
    assert review["issues"] == []
    assert review_hash == sha256_digest(canonical_json_bytes(without_hash))


@pytest.mark.parametrize(
    ("status", "expected_count"),
    [("stated", 5), ("not_established", 1), ("not_applicable", 10)],
)
def test_every_atomic_element_status_has_exact_evidence_or_a_source_tied_gap(
    status: str,
    expected_count: int,
) -> None:
    units, leads, draft, sources = _single_atom_coverage_case()
    atom = draft.rule_atoms[0]
    if status == "stated":
        trigger = DraftAtomElement(
            status="stated",
            text="Synthetic trigger",
            claim_ids=["claim-duty"],
        )
    elif status == "not_established":
        trigger = DraftAtomElement(
            status="not_established", gap_codes=["TRIGGER_NOT_ESTABLISHED"]
        )
        draft = draft.model_copy(
            update={
                "gaps": [
                    DraftGap(
                        code="TRIGGER_NOT_ESTABLISHED",
                        message="The source does not establish a trigger.",
                        category="requirements",
                        source_ids=["src-a"],
                    )
                ]
            }
        )
    else:
        trigger = DraftAtomElement(status="not_applicable")
    atom = atom.model_copy(
        update={"elements": atom.elements.model_copy(update={"trigger": trigger})}
    )
    draft = draft.model_copy(update={"rule_atoms": [atom]})

    review = evaluate_atomic_coverage(units, leads, draft, sources)

    assert review["valid"] is True
    assert review["counts"][f"{status}_elements"] == expected_count


def test_not_established_element_rejects_missing_wrong_source_or_wrong_category_gap() -> None:
    units, leads, draft, sources = _single_atom_coverage_case()
    atom = draft.rule_atoms[0]
    atom = atom.model_copy(
        update={
            "elements": atom.elements.model_copy(
                update={
                    "trigger": DraftAtomElement(
                        status="not_established", gap_codes=["TRIGGER_GAP"]
                    )
                }
            )
        }
    )

    reviews = []
    for gap in (
        None,
        DraftGap(
            code="TRIGGER_GAP",
            message="The wrong source does not establish a trigger.",
            category="requirements",
            source_ids=["src-b"],
        ),
        DraftGap(
            code="TRIGGER_GAP",
            message="The wrong category does not establish a trigger.",
            category="scope",
            source_ids=["src-a"],
        ),
    ):
        reviews.append(
            evaluate_atomic_coverage(
                units,
                leads,
                draft.model_copy(
                    update={"rule_atoms": [atom], "gaps": [] if gap is None else [gap]}
                ),
                sources,
            )
        )

    assert all("ATOMIC_GAP_INVALID" in _issue_codes(review) for review in reviews)


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        ("unknown", "ATOMIC_CLAIM_UNKNOWN"),
        ("analysis", "ATOMIC_CLAIM_NOT_SOURCE_SUPPORTED"),
        ("no_exact_citation", "ATOMIC_EVIDENCE_OUTSIDE_TARGET"),
    ],
)
def test_each_stated_element_claim_must_resolve_to_source_supported_exact_evidence(
    mutation: str,
    expected_code: str,
) -> None:
    units, leads, draft, sources = _single_atom_coverage_case()
    atom = draft.rule_atoms[0]
    actor_claim_id = "claim-unknown" if mutation == "unknown" else "claim-bad"
    actor = atom.elements.actor.model_copy(update={"claim_ids": [actor_claim_id]})
    atom = atom.model_copy(
        update={"elements": atom.elements.model_copy(update={"actor": actor})}
    )
    if mutation == "analysis":
        bad_claim = _evidence_claim(
            actor_claim_id,
            "Analysis of the synthetic actor.",
            kind=ClaimKind.ANALYSIS,
        )
        draft.findings[0].claims.append(bad_claim)
    elif mutation == "no_exact_citation":
        bad_claim = _evidence_claim(
            actor_claim_id,
            "A source-supported claim whose proposed quote is absent.",
        )
        draft.findings[0].claims.append(bad_claim)
    draft = draft.model_copy(update={"rule_atoms": [atom]})

    review = evaluate_atomic_coverage(units, leads, draft, sources)

    assert expected_code in _issue_codes(review)


def test_adjacent_nonoverlapping_claim_span_cannot_support_an_assigned_target() -> None:
    first = "A controller must maintain a synthetic register."
    second = "A processor must preserve a synthetic notice."
    text = first + second
    source = _source("src-a").model_copy(
        update={"normalized_text": text, "content_hash": sha256_digest(text.encode())}
    )
    start = len(first)
    unit = {
        **_unit("src-a", "unit-a"),
        "start_char": start,
        "end_char": len(text),
        "locator": f"chars:{start}-{len(text)}",
        "excerpt": second,
    }
    lead = {
        **_lead("src-a", "lead-a", review_required=True),
        "start_char": start,
        "end_char": len(text),
        "excerpt": second,
    }
    units, leads = _inventories(units=[unit], leads=[lead])
    _, _, draft, _ = _single_atom_coverage_case()
    draft.findings[0].claims = [_evidence_claim("claim-duty", first)]

    review = evaluate_atomic_coverage(units, leads, draft, [source])

    assert "ATOMIC_EVIDENCE_OUTSIDE_TARGET" in _issue_codes(review)


def test_all_assigned_unit_and_lead_contexts_need_evidence_across_elements() -> None:
    units, leads = _inventories(
        units=[_unit("src-a", "unit-a"), _unit("src-b", "unit-b")],
        leads=[
            _lead("src-a", "lead-a", review_required=True),
            _lead("src-b", "lead-b", review_required=True),
        ],
    )
    atom = _evidence_atom(
        "atom-cross-source",
        "duty",
        unit_ids=["unit-a", "unit-b"],
        lead_ids=["lead-a", "lead-b"],
        claim_by_element={
            "actor": "claim-a",
            "modality": "claim-a",
            "operative_action": "claim-a",
            "object": "claim-b",
        },
    )
    base_draft = AnalysisDraft(
        coverage_contract_version="proposition-coverage-v2",
        issues=[
            DraftIssue(
                issue_id="issue-requirements",
                title="Requirements",
                category="requirements",
            )
        ],
        findings=[
            DraftFinding(
                finding_id="finding-requirements",
                issue_id="issue-requirements",
                title="Cross-source duty",
                jurisdiction="US",
                authority="Synthetic Rules",
                severity=Severity.INFO,
                practical_implication="Read both sources.",
                claims=[
                    _evidence_claim("claim-a", SOURCE_TEXT["src-a"]),
                    _evidence_claim(
                        "claim-b", SOURCE_TEXT["src-b"], source_id="src-b"
                    ),
                ],
            )
        ],
        unit_reviews=[
            DraftUnitReview(
                unit_id=unit_id,
                dimensions=_mapped_dimensions(
                    "duties_rights_prohibitions", ["atom-cross-source"]
                ),
            )
            for unit_id in ("unit-a", "unit-b")
        ],
        lead_dispositions_v2=[
            DraftLeadDispositionV2(
                lead_id=lead_id,
                disposition="mapped",
                atom_ids=["atom-cross-source"],
            )
            for lead_id in ("lead-a", "lead-b")
        ],
        rule_atoms=[atom],
        brief=_visible_brief(
            atom_ids=["atom-cross-source"],
            claim_ids=["claim-a", "claim-b"],
        ),
    )
    sources = [_source("src-b"), _source("src-a")]

    complete = evaluate_atomic_coverage(units, leads, base_draft, sources)
    incomplete_atom = atom.model_copy(
        update={
            "elements": atom.elements.model_copy(
                update={
                    "object": atom.elements.object.model_copy(
                        update={"claim_ids": ["claim-a"]}
                    )
                }
            )
        }
    )
    incomplete = evaluate_atomic_coverage(
        units,
        leads,
        base_draft.model_copy(update={"rule_atoms": [incomplete_atom]}),
        sources,
    )

    assert complete["valid"] is True
    assert "ATOMIC_EVIDENCE_OUTSIDE_TARGET" in _issue_codes(incomplete)


def test_duplicate_claim_and_citation_ids_produce_only_bounded_evidence_roots() -> None:
    units, leads, draft, sources = _single_atom_coverage_case()
    duplicate = draft.findings[0].claims[0]
    draft = draft.model_copy(
        update={
            "findings": [
                draft.findings[0].model_copy(update={"claims": [duplicate, duplicate]})
            ]
        }
    )

    review = evaluate_atomic_coverage(units, leads, draft, sources)

    assert review["valid"] is False
    assert set(_issue_codes(review)) == {"ATOMIC_EVIDENCE_INVALID"}
    assert len(review["issues"]) <= 3


@pytest.mark.parametrize("materiality", ["critical", "material"])
def test_critical_and_material_atoms_must_be_visible_with_claim_co_binding(
    materiality: str,
) -> None:
    units, leads, draft, sources = _single_atom_coverage_case(
        materiality=materiality,
        atom_visible=False,
    )

    invisible = evaluate_atomic_coverage(units, leads, draft, sources)
    detached_claim = evaluate_atomic_coverage(
        units,
        leads,
        _replace_visible_brief(
            draft,
            atom_ids=["atom-duty"],
            claim_ids=[],
        ),
        sources,
    )

    assert "ATOMIC_ATOM_NOT_VISIBLE" in _issue_codes(invisible)
    assert "ATOMIC_ATOM_CLAIM_NOT_VISIBLE" in _issue_codes(detached_claim)


def test_supporting_atom_may_remain_internal_only_without_unit_dimension_dependency() -> None:
    internal = _single_atom_coverage_case(
        materiality="supporting",
        atom_visible=False,
        supporting_lead_only=True,
    )
    dependent = _single_atom_coverage_case(
        materiality="supporting",
        atom_visible=False,
    )

    internal_review = evaluate_atomic_coverage(*internal)
    dependent_review = evaluate_atomic_coverage(*dependent)

    assert internal_review["valid"] is True
    assert "ATOMIC_ATOM_NOT_VISIBLE" in _issue_codes(dependent_review)


def test_voluntarily_visible_supporting_atom_still_requires_claim_co_binding() -> None:
    units, leads, draft, sources = _single_atom_coverage_case(
        materiality="supporting",
        claim_visible=False,
        supporting_lead_only=True,
    )

    review = evaluate_atomic_coverage(units, leads, draft, sources)

    assert "ATOMIC_ATOM_CLAIM_NOT_VISIBLE" in _issue_codes(review)


@pytest.mark.parametrize("shape", ["paragraph", "item", "table"])
def test_related_atoms_and_relationship_may_share_one_visible_legal_analysis_unit(
    shape: str,
) -> None:
    units, leads, draft, sources = _relationship_coverage_case()
    draft = _replace_visible_brief(
        draft,
        atom_ids=["atom-duty", "atom-exception"],
        claim_ids=["claim-duty", "claim-exception", "claim-relationship"],
        relationship_ids=["relationship-exception"],
        shape=shape,
    )

    review = evaluate_atomic_coverage(units, leads, draft, sources)

    assert review["valid"] is True


def test_every_relationship_claim_needs_exact_evidence_from_both_endpoint_contexts() -> None:
    units, leads, draft, sources = _relationship_coverage_case()
    relationship_claim = next(
        claim
        for claim in draft.findings[0].claims
        if claim.claim_id == "claim-relationship"
    )
    one_sided = relationship_claim.model_copy(
        update={"proposed_citations": relationship_claim.proposed_citations[:1]}
    )
    draft = draft.model_copy(
        update={
            "findings": [
                draft.findings[0].model_copy(
                    update={
                        "claims": [
                            one_sided if claim.claim_id == one_sided.claim_id else claim
                            for claim in draft.findings[0].claims
                        ]
                    }
                )
            ]
        }
    )

    review = evaluate_atomic_coverage(units, leads, draft, sources)

    assert "ATOMIC_RELATIONSHIP_EVIDENCE_INVALID" in _issue_codes(review)


@pytest.mark.parametrize("detachment", ["missing", "endpoints", "claim"])
def test_material_relationship_rejects_missing_or_detached_visible_bindings(
    detachment: str,
) -> None:
    units, leads, draft, sources = _relationship_coverage_case()
    atom_ids = ["atom-duty", "atom-exception"]
    claim_ids = ["claim-duty", "claim-exception", "claim-relationship"]
    relationship_ids = ["relationship-exception"]
    if detachment == "missing":
        relationship_ids = []
    elif detachment == "endpoints":
        atom_ids = ["atom-exception"]
    else:
        claim_ids = ["claim-duty", "claim-exception"]
    draft = _replace_visible_brief(
        draft,
        atom_ids=atom_ids,
        claim_ids=claim_ids,
        relationship_ids=relationship_ids,
        shape="item",
    )

    review = evaluate_atomic_coverage(units, leads, draft, sources)

    assert "ATOMIC_RELATIONSHIP_NOT_VISIBLE" in _issue_codes(review)


def test_voluntarily_visible_supporting_relationship_requires_both_endpoints() -> None:
    _, _, draft, sources = _relationship_coverage_case()
    units, leads = _inventories(
        units=[],
        leads=[
            _lead("src-a", "lead-a", review_required=True),
            _lead("src-b", "lead-b", review_required=True),
        ],
    )
    supporting_atoms = [
        atom.model_copy(update={"materiality": "supporting", "unit_ids": []})
        for atom in draft.rule_atoms
    ]
    draft = draft.model_copy(
        update={
            "rule_atoms": supporting_atoms,
            "unit_reviews": [],
            "brief": _visible_brief(
                atom_ids=[],
                claim_ids=["claim-relationship"],
                relationship_ids=["relationship-exception"],
            ),
        }
    )

    review = evaluate_atomic_coverage(units, leads, draft, sources)

    assert "ATOMIC_RELATIONSHIP_NOT_VISIBLE" in _issue_codes(review)


def test_visibility_requirements_stop_after_direct_supporting_endpoint() -> None:
    review = evaluate_atomic_coverage(*_visibility_chain_case())

    assert review["valid"] is True


def test_authored_visible_internal_relationship_requires_only_its_endpoints() -> None:
    detached = evaluate_atomic_coverage(
        *_visibility_chain_case(
            visible_relationship_ids=["relationship-b-a", "relationship-d-c"]
        )
    )
    co_bound = evaluate_atomic_coverage(
        *_visibility_chain_case(
            visible_atom_ids=["atom-a", "atom-b", "atom-c", "atom-d"],
            visible_relationship_ids=["relationship-b-a", "relationship-d-c"],
        )
    )

    assert {
        tuple(issue["related_ids"])
        for issue in detached["issues"]
        if issue["code"] in {"ATOMIC_ATOM_NOT_VISIBLE", "ATOMIC_RELATIONSHIP_NOT_VISIBLE"}
    } == {
        ("atom-c",),
        ("atom-d",),
        ("atom-c", "atom-d", "relationship-d-c"),
    }
    assert co_bound["valid"] is True


def test_mapped_supporting_atom_requires_each_incident_relationship_one_hop() -> None:
    incomplete = evaluate_atomic_coverage(
        *_visibility_chain_case(mapped_supporting_c=True)
    )
    complete = evaluate_atomic_coverage(
        *_visibility_chain_case(
            mapped_supporting_c=True,
            visible_atom_ids=["atom-a", "atom-b", "atom-c", "atom-d"],
            visible_relationship_ids=[
                "relationship-b-a",
                "relationship-c-b",
                "relationship-d-c",
            ],
        )
    )

    assert {
        issue["related_ids"][-1]
        for issue in incomplete["issues"]
        if issue["code"] == "ATOMIC_RELATIONSHIP_NOT_VISIBLE"
    } == {"relationship-c-b", "relationship-d-c"}
    assert complete["valid"] is True


def test_visible_penalty_without_trigger_relationship_fails() -> None:
    duty = _evidence_atom(
        "atom-duty",
        "duty",
        unit_ids=["unit-a"],
        lead_ids=["lead-a"],
        claim_by_element={
            "actor": "claim-duty",
            "modality": "claim-duty",
            "operative_action": "claim-duty",
            "object": "claim-duty",
        },
    )
    penalty = _evidence_atom(
        "atom-penalty",
        "penalty",
        unit_ids=["unit-a"],
        lead_ids=["lead-a"],
        claim_by_element={"consequence": "claim-duty"},
    )
    relationship = _graph_relationship(
        "relationship-penalty", "consequence_of", "atom-penalty", "atom-duty"
    ).model_copy(update={"claim_ids": ["claim-duty"]})
    units, leads, draft, sources = _single_atom_coverage_case()
    unit_review = DraftUnitReview(
        unit_id="unit-a",
        dimensions=_mapped_dimensions(
            "duties_rights_prohibitions", ["atom-duty", "atom-penalty"]
        ),
    )
    lead_review = DraftLeadDispositionV2(
        lead_id="lead-a",
        disposition="mapped",
        atom_ids=["atom-duty", "atom-penalty"],
    )
    draft = draft.model_copy(
        update={
            "unit_reviews": [unit_review],
            "lead_dispositions_v2": [lead_review],
            "rule_atoms": [duty, penalty],
            "rule_relationships": [relationship],
            "brief": _visible_brief(
                atom_ids=["atom-duty", "atom-penalty"],
                claim_ids=["claim-duty"],
            ),
        }
    )

    review = evaluate_atomic_coverage(units, leads, draft, sources)

    assert "ATOMIC_RELATIONSHIP_NOT_VISIBLE" in _issue_codes(review)


def test_unknown_visible_atomic_bindings_fail_closed() -> None:
    units, leads, draft, sources = _single_atom_coverage_case()
    draft = _replace_visible_brief(
        draft,
        atom_ids=["atom-duty", "atom-unknown"],
        claim_ids=["claim-duty"],
        relationship_ids=["relationship-unknown"],
    )

    review = evaluate_atomic_coverage(units, leads, draft, sources)

    assert _issue_codes(review).count("ATOMIC_BRIEF_BINDING_INVALID") == 2


def test_malformed_brief_is_one_root_without_visibility_cascades_or_mutation() -> None:
    units, leads, draft, sources = _single_atom_coverage_case()
    assert draft.brief is not None
    malformed_block = draft.brief.executive_summary[0].model_copy(
        update={"claim_ids": [["claim-duty"]]}
    )
    malformed_brief = draft.brief.model_copy(
        update={"executive_summary": [malformed_block]}
    )
    draft = draft.model_copy(update={"brief": malformed_brief})
    before = draft.model_dump(mode="python", warnings=False)

    review = evaluate_atomic_coverage(units, leads, draft, sources)

    assert _issue_codes(review) == ["ATOMIC_BRIEF_INVALID"]
    assert draft.model_dump(mode="python", warnings=False) == before


def test_malformed_evidence_is_one_root_without_claim_or_visibility_cascades() -> None:
    units, leads, draft, sources = _single_atom_coverage_case()
    draft = draft.model_copy(update={"findings": [object()]})
    before = draft.model_dump(mode="python", warnings=False)

    review = evaluate_atomic_coverage(units, leads, draft, sources)

    assert _issue_codes(review) == ["ATOMIC_EVIDENCE_INVALID"]
    assert draft.model_dump(mode="python", warnings=False) == before


def test_partial_target_review_root_suppresses_task_five_derivative_diagnostics() -> None:
    units, leads, draft, sources = _single_atom_coverage_case()
    unit_rows = units["units"]
    assert isinstance(unit_rows, list)
    unit_rows[0]["excerpt"] = "An adjacent but incorrect source slice."

    review = evaluate_atomic_coverage(units, leads, draft, sources)

    assert _issue_codes(review) == ["ATOMIC_REVIEW_INVALID"]


def test_atomic_composite_repeat_reorder_hash_and_inputs_are_canonical_and_unmodified() -> None:
    units, leads, draft, sources = _relationship_coverage_case()
    before = (
        deepcopy(units),
        deepcopy(leads),
        draft.model_dump(mode="python", warnings=False),
        [source.model_dump(mode="python", warnings=False) for source in sources],
    )

    first = evaluate_atomic_coverage(units, leads, draft, sources)
    repeated = evaluate_atomic_coverage(units, leads, draft, sources)
    reordered = evaluate_atomic_coverage(
        {**units, "units": list(reversed(units["units"]))},
        {**leads, "leads": list(reversed(leads["leads"]))},
        draft.model_copy(
            update={
                "findings": [
                    draft.findings[0].model_copy(
                        update={"claims": list(reversed(draft.findings[0].claims))}
                    )
                ],
                "unit_reviews": list(reversed(draft.unit_reviews)),
                "lead_dispositions_v2": list(reversed(draft.lead_dispositions_v2)),
                "rule_atoms": list(reversed(draft.rule_atoms)),
                "rule_relationships": list(reversed(draft.rule_relationships)),
            }
        ),
        list(reversed(sources)),
    )

    assert first == repeated == reordered
    assert (
        units,
        leads,
        draft.model_dump(mode="python", warnings=False),
        [source.model_dump(mode="python", warnings=False) for source in sources],
    ) == before


def test_v2_lead_projection_uses_gap_precedence_over_not_material() -> None:
    projected = _project_atomic_lead_reviews(
        [
            DraftLeadDispositionV2(
                lead_id="lead-a",
                disposition="not_material",
                rationale="The synthetic lead is not material.",
            ),
            DraftLeadDispositionV2(
                lead_id="lead-a",
                disposition="gap",
                gap_codes=["SYNTHETIC_GAP"],
            ),
        ]
    )

    assert projected is not None
    assert [review.model_dump(mode="json") for review in projected] == [
        {
            "lead_id": "lead-a",
            "disposition": "gap",
            "gap_codes": ["SYNTHETIC_GAP"],
            "rationale": "Projected from atomic lead dispositions with gap precedence.",
        }
    ]
