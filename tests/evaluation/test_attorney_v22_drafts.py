"""Protocol 2.2 evaluator-draft compiler tests."""

from __future__ import annotations

import json

import pytest

import regulatory_harvest.evaluation as evaluation
import regulatory_harvest.evaluation.attorney_v22_drafts as drafts_module
from regulatory_harvest.evaluation.attorney_v2_models import SemanticProposal
from regulatory_harvest.evaluation.attorney_v22_drafts import (
    CompiledDraftV22,
    DraftReasonCodeV22,
    EngineDefectV22,
    EvaluatorProvenanceV22,
    NeedsClarificationV22,
    compile_evaluator_draft_v22,
)
from regulatory_harvest.evaluation.attorney_v22_models import (
    EvaluatorOperationV22,
    EvaluatorRequestV22,
)

HASH = "a" * 64


def _request() -> EvaluatorRequestV22:
    return EvaluatorRequestV22(
        operation="source_review_fragment",
        request_fingerprint=HASH,
        system_instructions="Review the frozen source record.",
        json_schema={"type": "object"},
        payload={
            "source_record": {
                "sources": [
                    {
                        "source_id": "rule-1",
                        "normalized_text": "The controller shall act.",
                    }
                ]
            },
            "max_new_proposals": 5,
        },
    )


def _draft(*, quote: str) -> dict[str, object]:
    return {
        "proposals": [
            {
                "statement": "A controller must act.",
                "kind": "obligation",
                "importance": "critical",
                "passages": [{"source_id": "rule-1", "quote": quote}],
                "dependency": None,
                "confidence": "clear",
                "rationale": "The source uses mandatory language.",
            }
        ],
        "review_complete": True,
    }


def _provenance() -> EvaluatorProvenanceV22:
    return EvaluatorProvenanceV22(
        provider_name="scripted",
        model_name="fixture",
        judge_isolation="scripted_fixture",
    )


def test_unique_whitespace_quote_compiles_to_exact_source_bytes() -> None:
    """Changing quote whitespace must not change the bound frozen-source bytes."""
    outcome = compile_evaluator_draft_v22(
        _request(), _draft(quote="The  controller  shall act."), _provenance()
    )

    assert isinstance(outcome, CompiledDraftV22)
    passage = outcome.response.payload["proposals"][0]["passages"][0]  # type: ignore[index]
    assert passage["quote"] == "The controller shall act."  # type: ignore[index]


def test_every_operation_compiles_a_minimal_bound_draft() -> None:
    """Each operation must produce a controller-bound strict inner payload."""
    requests_and_drafts = (
        (
            _request(),
            _draft(quote="The controller shall act."),
        ),
        (
            _request_for(
                "source_audit_fragment",
                {
                    "source_record": _request().model_dump(mode="json")["payload"]["source_record"],
                    "indexed_proposals": [],
                },
            ),
            {"concerns": [], "audit_complete": True},
        ),
        (
            _request_for(
                "source_referee_fragment",
                {
                    "material_disputes": [
                        {
                            "evidence": [
                                {
                                    "evidence_ref": "EVID-0001",
                                    "passage": {
                                        "source_id": "rule-1",
                                        "quote": "The controller shall act.",
                                        "start_char": 0,
                                        "end_char": 25,
                                    },
                                }
                            ]
                        }
                    ]
                },
            ),
            {
                "decision": "accept_reviewer",
                "unresolved_reason": None,
                "evidence_ordinals": [1],
                "rationale": "The sole source passage supports the reviewer.",
            },
        ),
        (
            _request_for(
                "ordinary_grade_fragment",
                {
                    "anonymous_label": "A",
                    "grader_lane": 1,
                    "batch_ref": "GB-A-1-0001",
                    "baseline_fingerprint": HASH,
                    "report_fingerprint": "b" * 64,
                    "report_text": "The report addresses the requirement.",
                    "requirements": [{"requirement_id": "REQ-0001"}],
                },
            ),
            {
                "requirement_grades": [
                    {
                        "requirement_ordinal": 1,
                        "disposition": "met",
                        "report_passages": ["The report addresses the requirement."],
                        "rationale": "The report addresses the requirement.",
                        "omission": None,
                    }
                ],
                "rationale": "The bounded requirement is met.",
            },
        ),
        (
            _request_for(
                "contested_grade_fragment",
                {
                    "anonymous_label": "A",
                    "grader_lane": 1,
                    "baseline_fingerprint": HASH,
                    "report_fingerprint": "b" * 64,
                    "report_text": "The report addresses the alternative.",
                    "contested_requirement": {"contested_requirement_id": "CONT-0001"},
                },
            ),
            {
                "reviewer_alternative_grade": _alternative(),
                "auditor_alternative_grade": _alternative(),
                "ambiguity_disposition": "acknowledged",
                "rationale": "Both alternatives are addressed.",
            },
        ),
    )

    for request, draft in requests_and_drafts:
        outcome = compile_evaluator_draft_v22(request, draft, _provenance())
        assert isinstance(outcome, CompiledDraftV22)
        assert outcome.response.operation is request.operation
        assert outcome.response.request_fingerprint == request.request_fingerprint


def test_json_bytes_key_order_prose_whitespace_and_approved_enum_alias_normalize() -> None:
    """Representational variants compile without authoring controller fields."""
    draft = _draft(quote="The controller shall act.")
    proposal = draft["proposals"][0]  # type: ignore[index]
    proposal["kind"] = "OBLIGATION"  # type: ignore[index]
    proposal["statement"] = "  A controller must act.  "  # type: ignore[index]

    outcome = compile_evaluator_draft_v22(
        _request(), json.dumps(draft, sort_keys=True).encode(), _provenance()
    )

    assert isinstance(outcome, CompiledDraftV22)
    assert outcome.response.payload["proposals"][0]["statement"] == "A controller must act."  # type: ignore[index]


@pytest.mark.parametrize(
    "draft",
    [
        b"{not-json",
        [],
        {"proposals": [], "review_complete": True, "unknown": "field"},
    ],
)
def test_malformed_type_unknown_and_missing_substance_need_clarification(draft: object) -> None:
    """Evaluator-controlled shape failures are never classified as engine defects."""
    outcome = compile_evaluator_draft_v22(_request(), draft, _provenance())

    assert isinstance(outcome, NeedsClarificationV22)
    assert not isinstance(outcome, EngineDefectV22)


def test_missing_required_substance_needs_clarification() -> None:
    missing = _draft(quote="The controller shall act.")
    del missing["proposals"][0]["rationale"]  # type: ignore[index]

    outcome = compile_evaluator_draft_v22(_request(), missing, _provenance())

    assert outcome == NeedsClarificationV22((DraftReasonCodeV22.SUBSTANCE_MISSING,))


def test_ungrounded_or_ambiguous_quotes_need_clarification_without_guessing() -> None:
    """Evidence may bind exactly or uniquely-normalized, but cannot be guessed."""
    missing = compile_evaluator_draft_v22(
        _request(), _draft(quote="Not in the record."), _provenance()
    )
    ambiguous_request = _request()
    ambiguous_request = ambiguous_request.model_copy(
        update={
            "payload": {
                "source_record": {
                    "sources": [
                        {"source_id": "rule-1", "normalized_text": "Act now. Act now."}
                    ]
                }
            }
        }
    )
    ambiguous = compile_evaluator_draft_v22(
        ambiguous_request, _draft(quote="Act now."), _provenance()
    )

    assert missing == NeedsClarificationV22((DraftReasonCodeV22.EVIDENCE_NOT_FOUND,))
    assert ambiguous == NeedsClarificationV22((DraftReasonCodeV22.EVIDENCE_AMBIGUOUS,))


@pytest.mark.parametrize(
    "quote",
    ["the controller shall act.", "The controller shall act!", "The contrôller shall act."],
)
def test_quote_normalization_never_changes_case_punctuation_or_unicode_content(quote: str) -> None:
    outcome = compile_evaluator_draft_v22(_request(), _draft(quote=quote), _provenance())

    assert outcome == NeedsClarificationV22((DraftReasonCodeV22.EVIDENCE_NOT_FOUND,))


def test_exact_duplicates_are_removed_but_nonidentical_local_identity_conflicts_clarify() -> None:
    duplicate = _draft(quote="The controller shall act.")
    duplicate["proposals"].append(duplicate["proposals"][0].copy())  # type: ignore[index]
    conflict = _draft(quote="The controller shall act.")
    conflicting = conflict["proposals"][0].copy()  # type: ignore[index]
    conflicting["rationale"] = "A different explanation changes this item."
    conflict["proposals"].append(conflicting)  # type: ignore[index]

    deduplicated = compile_evaluator_draft_v22(_request(), duplicate, _provenance())
    conflicted = compile_evaluator_draft_v22(_request(), conflict, _provenance())

    assert isinstance(deduplicated, CompiledDraftV22)
    assert len(deduplicated.response.payload["proposals"]) == 1  # type: ignore[arg-type]
    assert "DRAFT_NORMALIZED_DUPLICATES" in deduplicated.normalization_codes
    assert conflicted == NeedsClarificationV22((DraftReasonCodeV22.CONFLICTING_ITEMS,))


def test_resource_limits_and_cycles_need_clarification() -> None:
    oversized_items = _draft(quote="The controller shall act.")
    oversized_items["proposals"] *= 6  # type: ignore[index]
    cyclic: dict[str, object] = {"proposals": []}
    cyclic["cycle"] = cyclic

    item_limit = compile_evaluator_draft_v22(_request(), oversized_items, _provenance())
    cyclic_outcome = compile_evaluator_draft_v22(_request(), cyclic, _provenance())
    byte_limit = compile_evaluator_draft_v22(_request(), b" " * 262_145, _provenance())

    assert item_limit == NeedsClarificationV22((DraftReasonCodeV22.ITEM_LIMIT_EXCEEDED,))
    assert isinstance(cyclic_outcome, NeedsClarificationV22)
    assert byte_limit == NeedsClarificationV22((DraftReasonCodeV22.DRAFT_TOO_LARGE,))


def test_low_quality_but_grounded_judgment_compiles_for_downstream_adjudication() -> None:
    weak = _draft(quote="The controller shall act.")
    weak["proposals"][0]["rationale"] = "This may matter."  # type: ignore[index]

    outcome = compile_evaluator_draft_v22(_request(), weak, _provenance())

    assert isinstance(outcome, CompiledDraftV22)


def test_only_strict_response_construction_failure_is_an_engine_defect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class BrokenResponse:
        def __init__(self, **_: object) -> None:
            raise ValueError("controller response construction failed")

    monkeypatch.setattr(drafts_module, "EvaluatorResponseV22", BrokenResponse)

    outcome = compile_evaluator_draft_v22(
        _request(), _draft(quote="The controller shall act."), _provenance()
    )

    assert outcome == EngineDefectV22("COMPILER_INVARIANT")


def test_package_exports_the_v22_draft_compiler_surface() -> None:
    required = {
        "CompiledDraftV22",
        "DraftCompileOutcomeV22",
        "DraftReasonCodeV22",
        "EngineDefectV22",
        "EvaluatorDraftPromptV22",
        "EvaluatorProvenanceV22",
        "NeedsClarificationV22",
        "compile_evaluator_draft_v22",
        "parse_evaluator_draft_v22",
    }

    assert all(hasattr(evaluation, name) for name in required)


def test_grade_report_passages_must_be_exactly_bound_to_the_controller_report() -> None:
    request = _ordinary_request()
    ordinary = _ordinary_draft()
    ordinary["requirement_grades"][0]["report_passages"] = ["Fabricated report support."]  # type: ignore[index]
    contested = _contested_draft()
    contested["reviewer_alternative_grade"]["report_passages"] = ["Fabricated report support."]  # type: ignore[index]

    ordinary_outcome = compile_evaluator_draft_v22(request, ordinary, _provenance())
    contested_outcome = compile_evaluator_draft_v22(_contested_request(), contested, _provenance())

    assert ordinary_outcome == NeedsClarificationV22(
        (DraftReasonCodeV22.EVIDENCE_NOT_FOUND,)
    )
    assert contested_outcome == NeedsClarificationV22(
        (DraftReasonCodeV22.EVIDENCE_NOT_FOUND,)
    )


def test_dependencies_use_local_ordinals_resolved_from_the_accepted_inventory() -> None:
    request = _request().model_copy(
        update={
            "payload": {
                **_request().model_dump(mode="json")["payload"],
                "accepted_proposals": [
                    {
                        "proposal_ref": "P0001",
                        "proposal": _draft(quote="The controller shall act.")["proposals"][0],
                    }
                ],
            }
        }
    )
    draft = _draft(quote="The controller shall act.")
    draft["proposals"][0]["dependency"] = {  # type: ignore[index]
        "relationship": "depends_on",
        "target_ordinal": 1,
    }

    outcome = compile_evaluator_draft_v22(request, draft, _provenance())

    assert isinstance(outcome, CompiledDraftV22)
    dependency = outcome.response.payload["proposals"][0]["dependency"]  # type: ignore[index]
    assert dependency == {
        "relationship": "depends_on",
        "target_statement": "A controller must act.",
    }


def test_second_review_fragment_replays_plain_history_with_deterministic_ordinals() -> None:
    """A plain accepted proposal must remain usable as the next local ordinal."""
    prior = _draft(quote="The controller shall act.")["proposals"][0]
    request = _request().model_copy(
        update={
            "payload": {
                **_request().model_dump(mode="json")["payload"],
                "accepted_proposals": [prior],
                "fragment_ordinal": 2,
            }
        }
    )
    second = _draft(quote="The controller shall act.")
    second["proposals"][0] = {
        **second["proposals"][0],
        "statement": "A second controller duty applies.",
        "dependency": {"relationship": "depends_on", "target_ordinal": 1},
    }

    outcome = compile_evaluator_draft_v22(request, second, _provenance())

    assert isinstance(outcome, CompiledDraftV22)
    assert outcome.response.payload["proposals"][0]["dependency"] == {  # type: ignore[index]
        "relationship": "depends_on",
        "target_statement": "A controller must act.",
    }


def test_plain_review_history_rejects_duplicates_and_cross_case_evidence() -> None:
    """Controller history must remain unique and bound to the current source record."""
    prior = _draft(quote="The controller shall act.")["proposals"][0]
    duplicate = _request().model_copy(
        update={
            "payload": {
                **_request().model_dump(mode="json")["payload"],
                "accepted_proposals": [prior, prior],
            }
        }
    )
    cross_case = _request().model_copy(
        update={
            "payload": {
                **_request().model_dump(mode="json")["payload"],
                "accepted_proposals": [
                    {
                        **prior,
                        "passages": [{"source_id": "other-rule", "quote": "Other case text."}],
                    }
                ],
            }
        }
    )

    assert compile_evaluator_draft_v22(
        duplicate, _draft(quote="The controller shall act."), _provenance()
    ) == EngineDefectV22("COMPILER_INVARIANT")
    assert compile_evaluator_draft_v22(
        cross_case, _draft(quote="The controller shall act."), _provenance()
    ) == EngineDefectV22("COMPILER_INVARIANT")


def test_plain_review_history_omission_clarifies_and_order_selects_local_target() -> None:
    """Missing ordinals clarify; reordered values deterministically redefine ordinal one."""
    missing = _draft(quote="The controller shall act.")
    missing["proposals"][0]["dependency"] = {  # type: ignore[index]
        "relationship": "depends_on",
        "target_ordinal": 1,
    }
    omitted = compile_evaluator_draft_v22(_request(), missing, _provenance())

    first = _draft(quote="The controller shall act.")["proposals"][0]
    second = {**first, "statement": "The reordered first proposal."}
    reordered_request = _request().model_copy(
        update={
            "payload": {
                **_request().model_dump(mode="json")["payload"],
                "accepted_proposals": [second, first],
            }
        }
    )
    reordered = compile_evaluator_draft_v22(reordered_request, missing, _provenance())

    assert omitted == NeedsClarificationV22((DraftReasonCodeV22.REFERENCE_UNKNOWN,))
    assert isinstance(reordered, CompiledDraftV22)
    assert (
        reordered.response.payload["proposals"][0]["dependency"]["target_statement"]
        == "The reordered first proposal."
    )  # type: ignore[index]


def test_spoofed_or_constructed_request_is_an_engine_defect_not_cross_operation_draft() -> None:
    request = EvaluatorRequestV22.model_construct(
        schema_version="2.2",
        operation="not-an-operation",
        request_fingerprint=HASH,
        system_instructions="Review sources.",
        json_schema={},
        payload={},
        safe_metadata={},
    )

    outcome = compile_evaluator_draft_v22(
        request, _draft(quote="The controller shall act."), _provenance()
    )

    assert outcome == EngineDefectV22("COMPILER_INVARIANT")


def test_ordinary_batch_must_have_unique_request_references_and_exact_draft_coverage() -> None:
    incomplete_draft = _ordinary_draft()
    incomplete_draft["requirement_grades"].pop()  # type: ignore[index]
    missing = compile_evaluator_draft_v22(_ordinary_request(), incomplete_draft, _provenance())
    duplicate_request = _ordinary_request().model_copy(
        update={
            "payload": {
                **_ordinary_request().model_dump(mode="json")["payload"],
                "requirements": [
                    {"requirement_id": "REQ-0001"},
                    {"requirement_id": "REQ-0001"},
                ],
            }
        }
    )
    duplicate = compile_evaluator_draft_v22(duplicate_request, _ordinary_draft(), _provenance())

    assert missing == NeedsClarificationV22((DraftReasonCodeV22.REFERENCE_UNKNOWN,))
    assert duplicate == EngineDefectV22("COMPILER_INVARIANT")


def test_compiled_strict_payload_construction_failures_are_engine_defects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class BrokenPayload:
        def __init__(self, **_: object) -> None:
            raise ValueError("strict payload construction failed")

    monkeypatch.setattr(drafts_module, "SourceReviewFragmentV22", BrokenPayload)

    outcome = compile_evaluator_draft_v22(
        _request(), _draft(quote="The controller shall act."), _provenance()
    )

    assert outcome == EngineDefectV22("COMPILER_INVARIANT")


def test_exact_duplicate_ordinary_and_referee_items_normalize_but_conflicts_clarify() -> None:
    ordinary = _ordinary_draft(single_requirement=True)
    ordinary["requirement_grades"].append(ordinary["requirement_grades"][0].copy())  # type: ignore[index]
    referee = {
        "decision": "accept_reviewer",
        "unresolved_reason": None,
        "evidence_ordinals": [1, 1],
        "rationale": "The sole source passage supports the reviewer.",
    }

    ordinary_outcome = compile_evaluator_draft_v22(
        _ordinary_request(single_requirement=True), ordinary, _provenance()
    )
    referee_outcome = compile_evaluator_draft_v22(
        _referee_request(), referee, _provenance()
    )

    assert isinstance(ordinary_outcome, CompiledDraftV22)
    assert len(ordinary_outcome.response.payload["requirement_grades"]) == 1  # type: ignore[arg-type]
    assert isinstance(referee_outcome, CompiledDraftV22)
    assert referee_outcome.response.payload["evidence_refs"] == ["EVID-0001"]


def test_duplicate_json_keys_and_serializer_failures_are_safe_clarifications() -> None:
    duplicate_keys = b'{"proposals":[],"proposals":[],"review_complete":true}'

    class Unserializable:
        def __iter__(self) -> object:
            raise RuntimeError("do not leak")

    serializer_warning = SemanticProposal.model_construct(
        statement=1,
        kind="obligation",
        importance="critical",
        passages=[],
        dependency=None,
        confidence="clear",
        rationale="x",
    )
    duplicate_outcome = compile_evaluator_draft_v22(_request(), duplicate_keys, _provenance())
    serializer_outcome = compile_evaluator_draft_v22(_request(), Unserializable(), _provenance())
    warning_outcome = compile_evaluator_draft_v22(_request(), serializer_warning, _provenance())

    assert isinstance(duplicate_outcome, NeedsClarificationV22)
    assert isinstance(serializer_outcome, NeedsClarificationV22)
    assert isinstance(warning_outcome, NeedsClarificationV22)


def test_audit_correction_dependency_uses_local_ordinal_and_exact_duplicates_normalize() -> None:
    proposal = _draft(quote="The controller shall act.")["proposals"][0]
    request = _request_for(
        "source_audit_fragment",
        {
            "source_record": _request().model_dump(mode="json")["payload"]["source_record"],
            "indexed_proposals": [{"proposal_ref": "P0001", "proposal": proposal}],
        },
    )
    correction = proposal.copy()
    correction["dependency"] = {"relationship": "depends_on", "target_ordinal": 1}
    concern = {
        "target_proposal_ordinal": None,
        "concern_type": "omission",
        "passages": [{"source_id": "rule-1", "quote": "The controller shall act."}],
        "explanation": "The inventory omitted a related requirement.",
        "correction": correction,
    }

    outcome = compile_evaluator_draft_v22(
        request, {"concerns": [concern, concern.copy()], "audit_complete": True}, _provenance()
    )

    assert isinstance(outcome, CompiledDraftV22)
    concerns = outcome.response.payload["concerns"]
    assert len(concerns) == 1  # type: ignore[arg-type]
    assert concerns[0]["correction"]["dependency"]["target_statement"] == "A controller must act."  # type: ignore[index]


def test_low_quality_but_exactly_grounded_grade_passages_still_compile() -> None:
    grade = _ordinary_draft()
    grade["requirement_grades"][0]["rationale"] = "Maybe."  # type: ignore[index]

    outcome = compile_evaluator_draft_v22(_ordinary_request(), grade, _provenance())

    assert isinstance(outcome, CompiledDraftV22)


@pytest.mark.parametrize(
    ("key", "inventory"),
    [
        (
            "accepted_proposals",
            [{"proposal": _draft(quote="The controller shall act.")["proposals"][0]}],
        ),
        (
            "accepted_proposals",
            [
                {
                    "proposal_ref": "P0001",
                    "proposal": _draft(quote="The controller shall act.")["proposals"][0],
                },
                {
                    "proposal_ref": "P0001",
                    "proposal": _draft(quote="The controller shall act.")["proposals"][0],
                },
            ],
        ),
    ],
)
def test_review_dependency_inventory_requires_unique_controller_proposal_refs(
    key: str, inventory: list[dict[str, object]]
) -> None:
    request = _request().model_copy(
        update={"payload": {**_request().model_dump(mode="json")["payload"], key: inventory}}
    )

    outcome = compile_evaluator_draft_v22(
        request, _draft(quote="The controller shall act."), _provenance()
    )

    assert outcome == EngineDefectV22("COMPILER_INVARIANT")


@pytest.mark.parametrize(
    "inventory",
    [
        [{"proposal": _draft(quote="The controller shall act.")["proposals"][0]}],
        [
            {
                "proposal_ref": "P0001",
                "proposal": _draft(quote="The controller shall act.")["proposals"][0],
            },
            {
                "proposal_ref": "P0001",
                "proposal": _draft(quote="The controller shall act.")["proposals"][0],
            },
        ],
    ],
)
def test_audit_dependency_inventory_requires_unique_controller_proposal_refs(
    inventory: list[dict[str, object]],
) -> None:
    request = _audit_request().model_copy(
        update={
            "payload": {
                **_audit_request().model_dump(mode="json")["payload"],
                "indexed_proposals": inventory,
            }
        }
    )

    outcome = compile_evaluator_draft_v22(
        request, {"concerns": [], "audit_complete": True}, _provenance()
    )

    assert outcome == EngineDefectV22("COMPILER_INVARIANT")


def test_parse_api_revalidates_spoofed_request_and_never_defaults_to_contested() -> None:
    request = EvaluatorRequestV22.model_construct(
        schema_version="2.2",
        operation="spoofed-operation",
        request_fingerprint=HASH,
        system_instructions="Review sources.",
        json_schema={},
        payload={},
        safe_metadata={},
    )

    with pytest.raises(ValueError):
        drafts_module.parse_evaluator_draft_v22(request, _contested_draft())


def test_draft_derived_nested_duplicates_and_whitespace_omission_need_clarification() -> None:
    duplicate_passages = _draft(quote="The controller shall act.")
    duplicate_passages["proposals"][0]["passages"] *= 2  # type: ignore[index]
    whitespace_omission = _ordinary_draft()
    whitespace_omission["requirement_grades"][0]["omission"] = "   "  # type: ignore[index]

    passage_outcome = compile_evaluator_draft_v22(
        _request(), duplicate_passages, _provenance()
    )
    omission_outcome = compile_evaluator_draft_v22(
        _ordinary_request(), whitespace_omission, _provenance()
    )

    assert isinstance(passage_outcome, NeedsClarificationV22)
    assert isinstance(omission_outcome, NeedsClarificationV22)


def test_post_resolution_duplicate_review_passages_normalize_not_engine_defect() -> None:
    review = _draft(quote="The controller shall act.")
    review["proposals"][0]["passages"].append(  # type: ignore[index]
        {"source_id": "rule-1", "quote": "The  controller  shall act."}
    )

    outcome = compile_evaluator_draft_v22(_request(), review, _provenance())

    assert isinstance(outcome, CompiledDraftV22)
    assert len(outcome.response.payload["proposals"][0]["passages"]) == 1  # type: ignore[index]
    assert outcome.normalization_codes == (
        "DRAFT_NORMALIZED_DUPLICATES",
        "DRAFT_NORMALIZED_EVIDENCE_WHITESPACE",
    )


def test_post_resolution_duplicate_audit_passages_normalize_not_engine_defect() -> None:
    concern = _omission_concern("The controller shall act.", "A missing item.")
    concern["passages"].append(  # type: ignore[index]
        {"source_id": "rule-1", "quote": "The  controller  shall act."}
    )

    outcome = compile_evaluator_draft_v22(
        _audit_request(), {"concerns": [concern], "audit_complete": True}, _provenance()
    )

    assert isinstance(outcome, CompiledDraftV22)
    compiled_concern = outcome.response.payload["concerns"][0]  # type: ignore[index]
    assert len(compiled_concern["passages"]) == 1  # type: ignore[index]
    assert outcome.normalization_codes == (
        "DRAFT_NORMALIZED_DUPLICATES",
        "DRAFT_NORMALIZED_EVIDENCE_WHITESPACE",
    )


def test_post_resolution_duplicate_audit_correction_passages_normalize_not_engine_defect() -> None:
    concern = _omission_concern("The controller shall act.", "A missing item.")
    correction = concern["correction"]
    assert isinstance(correction, dict)
    correction["passages"].append(  # type: ignore[index]
        {"source_id": "rule-1", "quote": "The  controller  shall act."}
    )

    outcome = compile_evaluator_draft_v22(
        _audit_request(), {"concerns": [concern], "audit_complete": True}, _provenance()
    )

    assert isinstance(outcome, CompiledDraftV22)
    compiled_concern = outcome.response.payload["concerns"][0]  # type: ignore[index]
    assert len(compiled_concern["correction"]["passages"]) == 1  # type: ignore[index]
    assert outcome.normalization_codes == (
        "DRAFT_NORMALIZED_DUPLICATES",
        "DRAFT_NORMALIZED_EVIDENCE_WHITESPACE",
    )


def test_distinct_omissions_coexist_and_exact_audit_duplicates_only_deduplicate() -> None:
    first = _omission_concern("The controller shall act.", "The inventory omitted the first item.")
    second = _omission_concern(
        "The controller shall act.", "The inventory omitted the second item."
    )
    request = _audit_request()

    distinct = compile_evaluator_draft_v22(
        request, {"concerns": [first, second], "audit_complete": True}, _provenance()
    )
    duplicate = compile_evaluator_draft_v22(
        request, {"concerns": [first, first.copy()], "audit_complete": True}, _provenance()
    )

    assert isinstance(distinct, CompiledDraftV22)
    assert len(distinct.response.payload["concerns"]) == 2  # type: ignore[arg-type]
    assert isinstance(duplicate, CompiledDraftV22)
    assert duplicate.normalization_codes == ("DRAFT_NORMALIZED_DUPLICATES",)


@pytest.mark.parametrize("ordinal", ["1", True, 1.0])
def test_duplicate_report_passages_normalize_and_ordinals_are_strict_integers(
    ordinal: object,
) -> None:
    duplicate_passages = _ordinary_draft(single_requirement=True)
    duplicate_passages["requirement_grades"][0]["report_passages"] *= 2  # type: ignore[index]
    bad_ordinal = _ordinary_draft(single_requirement=True)
    bad_ordinal["requirement_grades"][0]["requirement_ordinal"] = ordinal  # type: ignore[index]

    normalized = compile_evaluator_draft_v22(
        _ordinary_request(single_requirement=True), duplicate_passages, _provenance()
    )
    invalid = compile_evaluator_draft_v22(
        _ordinary_request(single_requirement=True), bad_ordinal, _provenance()
    )

    assert isinstance(normalized, CompiledDraftV22)
    assert "DRAFT_NORMALIZED_DUPLICATES" in normalized.normalization_codes
    assert isinstance(invalid, NeedsClarificationV22)


@pytest.mark.parametrize("ordinal", ["1", True, 1.0])
def test_every_local_ordinal_rejects_coercion(ordinal: object) -> None:
    review = _draft(quote="The controller shall act.")
    review["proposals"][0]["dependency"] = {  # type: ignore[index]
        "relationship": "depends_on",
        "target_ordinal": ordinal,
    }
    audit = _omission_concern("The controller shall act.", "A missing item.")
    audit["target_proposal_ordinal"] = ordinal
    audit["concern_type"] = "incorrect_statement"
    referee = {
        "decision": "accept_reviewer",
        "unresolved_reason": None,
        "evidence_ordinals": [ordinal],
        "rationale": "The sole source passage supports the reviewer.",
    }

    outcomes = (
        compile_evaluator_draft_v22(_request(), review, _provenance()),
        compile_evaluator_draft_v22(
            _audit_request(), {"concerns": [audit], "audit_complete": True}, _provenance()
        ),
        compile_evaluator_draft_v22(_referee_request(), referee, _provenance()),
    )

    assert all(isinstance(outcome, NeedsClarificationV22) for outcome in outcomes)


def _request_for(operation: str, payload: dict[str, object]) -> EvaluatorRequestV22:
    return EvaluatorRequestV22(
        operation=EvaluatorOperationV22(operation),
        request_fingerprint=HASH,
        system_instructions="Return a bounded semantic draft.",
        json_schema={"type": "object"},
        payload=payload,
    )


def _alternative() -> dict[str, object]:
    return {
        "disposition": "met",
        "report_passages": ["The report addresses the alternative."],
        "rationale": "The report addresses the alternative.",
    }


def _ordinary_request(*, single_requirement: bool = False) -> EvaluatorRequestV22:
    requirements = [{"requirement_id": "REQ-0001"}]
    if not single_requirement:
        requirements.append({"requirement_id": "REQ-0002"})
    return _request_for(
        "ordinary_grade_fragment",
        {
            "anonymous_label": "A",
            "grader_lane": 1,
            "batch_ref": "GB-A-1-0001",
            "baseline_fingerprint": HASH,
            "report_fingerprint": "b" * 64,
            "report_text": "The report addresses the first and second requirements.",
            "requirements": requirements,
        },
    )


def _ordinary_draft(*, single_requirement: bool = False) -> dict[str, object]:
    grades = [
        {
            "requirement_ordinal": 1,
            "disposition": "met",
            "report_passages": ["The report addresses the first"],
            "rationale": "The report addresses the first requirement.",
            "omission": None,
        }
    ]
    if not single_requirement:
        grades.append(
            {
                "requirement_ordinal": 2,
                "disposition": "met",
                "report_passages": ["second requirements."],
                "rationale": "The report addresses the second requirement.",
                "omission": None,
            }
        )
    return {"requirement_grades": grades, "rationale": "The bounded batch is met."}


def _contested_request() -> EvaluatorRequestV22:
    return _request_for(
        "contested_grade_fragment",
        {
            "anonymous_label": "A",
            "grader_lane": 1,
            "baseline_fingerprint": HASH,
            "report_fingerprint": "b" * 64,
            "report_text": "The report addresses the alternative.",
            "contested_requirement": {"contested_requirement_id": "CONT-0001"},
        },
    )


def _contested_draft() -> dict[str, object]:
    return {
        "reviewer_alternative_grade": _alternative(),
        "auditor_alternative_grade": _alternative(),
        "ambiguity_disposition": "acknowledged",
        "rationale": "Both alternatives are addressed.",
    }


def _referee_request() -> EvaluatorRequestV22:
    return _request_for(
        "source_referee_fragment",
        {
            "material_disputes": [
                {
                    "evidence": [
                        {
                            "evidence_ref": "EVID-0001",
                            "passage": {
                                "source_id": "rule-1",
                                "quote": "The controller shall act.",
                                "start_char": 0,
                                "end_char": 25,
                            },
                        }
                    ]
                }
            ]
        },
    )


def _audit_request() -> EvaluatorRequestV22:
    proposal = _draft(quote="The controller shall act.")["proposals"][0]
    return _request_for(
        "source_audit_fragment",
        {
            "source_record": _request().model_dump(mode="json")["payload"]["source_record"],
            "indexed_proposals": [{"proposal_ref": "P0001", "proposal": proposal}],
        },
    )


def _omission_concern(quote: str, explanation: str) -> dict[str, object]:
    correction = _draft(quote=quote)["proposals"][0]
    correction["statement"] = explanation
    return {
        "target_proposal_ordinal": None,
        "concern_type": "omission",
        "passages": [{"source_id": "rule-1", "quote": quote}],
        "explanation": explanation,
        "correction": correction,
    }
