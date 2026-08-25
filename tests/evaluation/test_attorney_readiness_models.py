"""Model-boundary tests for the delivery-readiness-v1 companion protocol."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError
from test_attorney_baseline_artifacts import _complete_graph

from regulatory_harvest.evaluation.attorney_baseline_artifacts import (
    initialize_baseline_storage_v1,
    load_verified_baseline_run,
)
from regulatory_harvest.evaluation.attorney_baseline_projection import (
    project_gradeable_baseline_v1,
)
from regulatory_harvest.evaluation.attorney_models import ArtifactRecord
from regulatory_harvest.evaluation.attorney_readiness_models import (
    BaselineLockedContestedGradeV1,
    BaselineLockedGradeBatchV1,
    BaselineLockedGradeFragmentV1,
    BaselineLockedGraderAggregateV1,
    DeliveryReadinessResultV1,
    DeliveryReadinessTierV1,
    FollowUpCodeV1,
    GapFollowUpRowV1,
    GapOriginV1,
    GapVisibilityV1,
    HistoricalV22CrossCheckStatusV1,
    OwnerRoleV1,
    RationaleKindV1,
    ReadinessCallRecordV1,
    ReadinessEvaluatorResponseV1,
    ReadinessInputV1,
    ReadinessManifestV1,
    ReadinessOperationV1,
    ReadinessPhaseV1,
    ReadinessRunStateV1,
    ReadinessVerificationV1,
    RequirementDispositionV1,
    SafetyFindingKindV1,
    SafetyLaneResponseV1,
    load_readiness_rubric_v1,
    validate_readiness_evaluator_response_v1,
    validate_readiness_input_v1,
    validate_readiness_result_v1,
)
from regulatory_harvest.evaluation.attorney_v2_models import RequirementGradeV2

HASH = "a" * 64
ROOT = Path(__file__).resolve().parents[2]
EXPECTED_WARNING = (
    "AI-generated work product may contain errors. A qualified attorney must validate the "
    "report, requirements, gaps, authorities, currentness, applicability, and follow-up "
    "before legal advice or client delivery."
)
EXPECTED_RUBRIC_BYTES = (
    b'{"attorney_review_warning":"AI-generated work product may contain errors. A qualified '
    b"attorney must validate the report, requirements, gaps, authorities, currentness, "
    b'applicability, and follow-up before legal advice or client delivery.","blocking_codes":'
    b'["INTEGRITY_OR_PROVENANCE_INVALID","MINIMUM_LANE_COVERAGE_BELOW_FLOOR",'
    b'"MATERIAL_UNSUPPORTED_ASSERTION","BASELINE_CONTRADICTION","HIDDEN_MATERIAL_GAP",'
    b'"UNDISCLOSED_DISPOSITIVE_CLIENT_FACT","MISLEADING_CURRENTNESS_OR_AUTHORITY",'
    b'"OUTCOME_DETERMINATIVE_CONTEST","MISSING_REQUIRED_FOLLOW_UP",'
    b'"GAP_RATIONALE_INVALID","CRITICAL_DISCLOSURE_INVALID","FALSE_RESOLUTION"],'
    b'"disposition_credit":{"met":1.0,"not_met":0.0,"partially_met":0.5,'
    b'"uncertain":0.0},"follow_up_codes":["VERIFY_PRIMARY_AUTHORITY",'
    b'"CONFIRM_CURRENTNESS","RESOLVE_APPLICABILITY_FACT",'
    b'"OBTAIN_OUTSIDE_COUNSEL_ANALYSIS","EXPAND_REQUIREMENT_ANALYSIS",'
    b'"CORRECT_UNSUPPORTED_ASSERTION","RESOLVE_LANGUAGE_LIMITATION",'
    b'"RESOLVE_CONTESTED_INTERPRETATION"],"generic_rationales":'
    b'["more research needed","insufficient information","requirement partially met"],'
    b'"high_assurance_critical_recall_floor":1.0,'
    b'"high_assurance_weighted_coverage_floor":0.9,'
    b'"owner_roles":["reviewing_attorney","outside_counsel","research_operator"],'
    b'"rationale_kinds":["REPORT_OMISSION","REPORT_PARTIAL_TREATMENT","SOURCE_ABSENT",'
    b'"SOURCE_AMBIGUOUS","SOURCE_CONFLICT","CURRENTNESS_NOT_ESTABLISHED",'
    b'"APPLICABILITY_FACT_MISSING","LANGUAGE_LIMITATION","CONTESTED_INTERPRETATION",'
    b'"UNSUPPORTED_ASSERTION","SAFETY_REVIEW_FINDING"],'
    b'"review_ready_weighted_coverage_floor":0.7,'
    b'"strict_equivalent_scoring_semantics":"attorney-eval-v2.2",'
    b'"strict_importance_weights":{"critical":3,"material":2,"supporting":1},'
    b'"version":"delivery-readiness-v1"}'
)


def valid_result(**updates: object) -> dict[str, object]:
    value: dict[str, object] = {
        "protocol_version": "delivery-readiness-v1",
        "baseline_locked_strict_equivalent_disposition": "PASS",
        "historical_v22_strict_disposition": None,
        "historical_v22_cross_check_status": "NOT_PROVIDED",
        "delivery_readiness": "HIGH_ASSURANCE",
        "minimum_lane_weighted_coverage": 0.90,
        "lane_critical_recall": (1.0, 1.0),
        "lane_weighted_coverage": (0.90, 0.95),
        "requirement_matrix_fingerprint": HASH,
        "gap_matrix_fingerprint": "b" * 64,
        "blocking_codes": (),
        "attorney_review_warning": EXPECTED_WARNING,
        "result_fingerprint": "c" * 64,
    }
    value.update(updates)
    return value


def valid_gap_row(**updates: object) -> dict[str, object]:
    value: dict[str, object] = {
        "gap_id": "GAP-0001",
        "canonical_order": 0,
        "origin": "requirement",
        "subject_id": "REQ-0001",
        "kind": "obligation",
        "importance": "critical",
        "importance_basis": ("legal_bottom_line",),
        "importance_rationale": "Omission could change the legal bottom line.",
        "lane_1_disposition": "partially_met",
        "lane_2_disposition": "not_met",
        "conservative_disposition": "not_met",
        "report_passages": ("The report discusses only part of the duty.",),
        "shortfall_description": "The deadline is omitted.",
        "rationale_kind": "REPORT_PARTIAL_TREATMENT",
        "why_unresolved": "The report does not state the filing deadline.",
        "why_it_matters": "The missing deadline changes the implementation decision.",
        "evidence_refs": ("REQ-0001", "REPORT-0001"),
        "disclosure_location": "Limitations",
        "visibility": "prominent",
        "blocking_code": None,
        "follow_up_code": "EXPAND_REQUIREMENT_ANALYSIS",
        "resolution_test": "Add and verify the deadline against primary authority.",
        "owner_role": "reviewing_attorney",
        "status": "open",
        "referee_dispute_id": None,
        "row_fingerprint": "d" * 64,
    }
    value.update(updates)
    return value


def valid_response(**updates: object) -> dict[str, object]:
    value: dict[str, object] = {
        "protocol_version": "delivery-readiness-v1",
        "operation": "safety_review",
        "request_fingerprint": HASH,
        "provider_name": "provider",
        "model_name": "model",
        "judge_isolation": "fresh_context",
        "payload": {"candidate_assessments": [], "finding_proposals": []},
    }
    value.update(updates)
    return value


def valid_call(*, state: str = "pending", call_id: str = "safety-lane-1") -> dict[str, object]:
    value: dict[str, object] = {
        "call_id": call_id,
        "operation": "safety_review",
        "state": state,
        "attempt": 1,
        "lane": 1,
        "request_artifact_path": f"requests/{call_id}.json",
        "request_fingerprint": HASH,
        "dispute_id": None,
    }
    if state == "accepted":
        value.update(
            {
                "response_artifact_path": f"responses/{call_id}.json",
                "response_fingerprint": "b" * 64,
                "provider_name": "provider",
                "model_name": "model",
                "judge_isolation": "fresh_context",
            }
        )
    return value


def valid_manifest(**updates: object) -> dict[str, object]:
    value: dict[str, object] = {
        "protocol_version": "delivery-readiness-v1",
        "grade_target_fingerprint": HASH,
        "report_hash": "b" * 64,
        "generation_capsule_root": "c" * 64,
        "readiness_rubric_fingerprint": "d" * 64,
        "strict_equivalent_scoring_contract_fingerprint": "e" * 64,
        "phase": "safety_review",
        "terminal_status": None,
        "pending_call": valid_call(),
        "accepted_calls": (),
        "artifacts": (),
        "root_hash": "f" * 64,
        "manifest_fingerprint": "0" * 64,
    }
    value.update(updates)
    return value


def valid_grade(requirement_id: str = "REQ-0001") -> dict[str, object]:
    return {
        "requirement_id": requirement_id,
        "disposition": "met",
        "report_passages": ["The report addresses the requirement."],
        "rationale": "The cited passage addresses the requirement.",
        "omission": None,
    }


def valid_fragment(**updates: object) -> dict[str, object]:
    value: dict[str, object] = {
        "protocol_version": "delivery-readiness-v1",
        "lane": 1,
        "batch_ref": "GB-1-0001",
        "grade_target_fingerprint": HASH,
        "baseline_fingerprint": "b" * 64,
        "report_hash": "c" * 64,
        "strict_equivalent_scoring_contract_fingerprint": "d" * 64,
        "requirement_grades": (valid_grade(),),
        "rationale": "The batch was graded against the locked baseline.",
        "fragment_fingerprint": "e" * 64,
    }
    value.update(updates)
    return value


def valid_contested_grade(**updates: object) -> dict[str, object]:
    value: dict[str, object] = {
        "protocol_version": "delivery-readiness-v1",
        "lane": 1,
        "contested_requirement_id": "CONT-0001",
        "grade_target_fingerprint": HASH,
        "baseline_fingerprint": "b" * 64,
        "report_hash": "c" * 64,
        "strict_equivalent_scoring_contract_fingerprint": "d" * 64,
        "reviewer_alternative_disposition": "met",
        "auditor_alternative_disposition": "partially_met",
        "reviewer_report_passages": (),
        "auditor_report_passages": (),
        "reviewer_rationale": "The reviewer interpretation is plausible.",
        "auditor_rationale": "The auditor interpretation is plausible.",
        "ambiguity_disposition": "both_plausible",
        "rationale": "The locked alternatives remain contested.",
        "grade_fingerprint": "f" * 64,
    }
    value.update(updates)
    return value


def valid_aggregate(**updates: object) -> dict[str, object]:
    fragment = valid_fragment()
    value: dict[str, object] = {
        "protocol_version": "delivery-readiness-v1",
        "lane": 1,
        "grade_target_fingerprint": HASH,
        "baseline_fingerprint": "b" * 64,
        "report_hash": "c" * 64,
        "strict_equivalent_scoring_contract_fingerprint": "d" * 64,
        "ordinary_fragments": (fragment,),
        "contested_grades": (valid_contested_grade(),),
        "requirement_grades": fragment["requirement_grades"],
        "aggregate_fingerprint": "0" * 64,
    }
    value.update(updates)
    return value


def test_readiness_policy_has_exact_canonical_bytes_and_versioned_thresholds() -> None:
    assert (
        ROOT / "src/regulatory_harvest/evaluation/readiness-rubric-v1.json"
    ).read_bytes() == EXPECTED_RUBRIC_BYTES
    rubric = load_readiness_rubric_v1()
    assert rubric.version == "delivery-readiness-v1"
    assert rubric.review_ready_weighted_coverage_floor == 0.70
    assert rubric.high_assurance_weighted_coverage_floor == 0.90
    assert rubric.high_assurance_critical_recall_floor == 1.0
    assert rubric.strict_equivalent_scoring_semantics == "attorney-eval-v2.2"
    assert rubric.strict_importance_weights == {
        "critical": 3,
        "material": 2,
        "supporting": 1,
    }
    assert rubric.disposition_credit == {
        "met": 1.0,
        "partially_met": 0.5,
        "not_met": 0.0,
        "uncertain": 0.0,
    }


def test_fixed_enum_inventories_are_exact() -> None:
    assert {item.value for item in DeliveryReadinessTierV1} == {
        "HIGH_ASSURANCE",
        "REVIEW_READY_WITH_GAPS",
        "NOT_DELIVERABLE",
    }
    assert {item.value for item in RequirementDispositionV1} == {
        "met",
        "partially_met",
        "not_met",
        "uncertain",
    }
    assert {item.value for item in ReadinessOperationV1} == {
        "baseline_locked_grade",
        "baseline_locked_contested_grade",
        "safety_review",
        "safety_referee",
    }
    assert {item.value for item in ReadinessPhaseV1} == {
        "created",
        "baseline_locked_grade",
        "baseline_locked_strict_equivalent",
        "safety_review",
        "safety_referee",
        "compile",
        "completed",
        "inconclusive",
    }
    assert {item.value for item in GapOriginV1} == {
        "requirement",
        "baseline_gap",
        "contested_requirement",
        "safety_finding",
        "prerequisite",
    }
    assert {item.value for item in GapVisibilityV1} == {
        "prominent",
        "visible",
        "hidden",
    }
    assert {item.value for item in SafetyFindingKindV1} == {
        "MATERIAL_UNSUPPORTED_ASSERTION",
        "BASELINE_CONTRADICTION",
        "HIDDEN_OR_UNDERSTATED_LIMITATION",
        "UNDISCLOSED_DISPOSITIVE_CLIENT_FACT",
        "MISLEADING_CURRENTNESS_OR_AUTHORITY",
        "UNDISCLOSED_GRADER_GAP",
    }
    assert {item.value for item in OwnerRoleV1} == {
        "reviewing_attorney",
        "outside_counsel",
        "research_operator",
    }


def test_historical_cross_check_status_inventory_has_exact_five_values() -> None:
    assert [item.value for item in HistoricalV22CrossCheckStatusV1] == [
        "NOT_PROVIDED",
        "BASELINE_NOT_COMPARABLE",
        "REPORT_NOT_COMPARABLE",
        "MATCH",
        "DISPOSITION_DIFFERS",
    ]


def test_rationale_inventory_has_exact_eleven_values() -> None:
    assert [item.value for item in RationaleKindV1] == [
        "REPORT_OMISSION",
        "REPORT_PARTIAL_TREATMENT",
        "SOURCE_ABSENT",
        "SOURCE_AMBIGUOUS",
        "SOURCE_CONFLICT",
        "CURRENTNESS_NOT_ESTABLISHED",
        "APPLICABILITY_FACT_MISSING",
        "LANGUAGE_LIMITATION",
        "CONTESTED_INTERPRETATION",
        "UNSUPPORTED_ASSERTION",
        "SAFETY_REVIEW_FINDING",
    ]


def test_follow_up_inventory_has_exact_eight_values() -> None:
    assert [item.value for item in FollowUpCodeV1] == [
        "VERIFY_PRIMARY_AUTHORITY",
        "CONFIRM_CURRENTNESS",
        "RESOLVE_APPLICABILITY_FACT",
        "OBTAIN_OUTSIDE_COUNSEL_ANALYSIS",
        "EXPAND_REQUIREMENT_ANALYSIS",
        "CORRECT_UNSUPPORTED_ASSERTION",
        "RESOLVE_LANGUAGE_LIMITATION",
        "RESOLVE_CONTESTED_INTERPRETATION",
    ]


def test_result_keeps_fresh_historical_and_readiness_dispositions_distinct() -> None:
    result = DeliveryReadinessResultV1.model_validate(
        valid_result(
            baseline_locked_strict_equivalent_disposition="PASS",
            historical_v22_strict_disposition="FAIL",
            historical_v22_cross_check_status="DISPOSITION_DIFFERS",
            delivery_readiness="REVIEW_READY_WITH_GAPS",
        )
    )
    assert result.baseline_locked_strict_equivalent_disposition.value == "PASS"
    assert result.historical_v22_strict_disposition is not None
    assert result.historical_v22_strict_disposition.value == "FAIL"
    assert result.delivery_readiness.value == "REVIEW_READY_WITH_GAPS"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("minimum_lane_weighted_coverage", True),
        ("lane_critical_recall", (True, 1.0)),
        ("lane_weighted_coverage", (0.9, False)),
    ],
)
def test_result_rejects_booleans_masquerading_as_scores(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        DeliveryReadinessResultV1.model_validate(valid_result(**{field: value}))


def test_result_rejects_forbidden_extra_fields() -> None:
    with pytest.raises(ValidationError, match="extra"):
        DeliveryReadinessResultV1.model_validate(
            valid_result(historical_result_used_for_fresh_grade=True)
        )


def test_response_payload_rejects_non_json_tuple_values() -> None:
    with pytest.raises(ValidationError, match="JSON wire values"):
        ReadinessEvaluatorResponseV1.model_validate(
            valid_response(payload={"not_json": ("tuple",)})
        )


def test_response_boundary_rehydrates_its_own_frozen_json_payload() -> None:
    response = ReadinessEvaluatorResponseV1.model_validate(valid_response())
    checked = validate_readiness_evaluator_response_v1(response)
    assert checked.model_dump(mode="json") == response.model_dump(mode="json")


@pytest.mark.parametrize("status", ["open", "resolved"])
def test_gap_row_accepts_only_open_or_resolved_status(status: str) -> None:
    assert GapFollowUpRowV1.model_validate(valid_gap_row(status=status)).status == status


def test_gap_row_rejects_a_status_outside_the_closed_inventory() -> None:
    with pytest.raises(ValidationError):
        GapFollowUpRowV1.model_validate(valid_gap_row(status="closed"))


@pytest.mark.parametrize(
    "forbidden",
    [
        "gap_id",
        "canonical_order",
        "response_fingerprint",
        "conservative_disposition",
        "final_blocker_precedence",
    ],
)
def test_safety_lane_cannot_author_controller_fields(forbidden: str) -> None:
    value = {
        "protocol_version": "delivery-readiness-v1",
        "lane": 1,
        "candidate_assessments": (),
        "finding_proposals": (),
        forbidden: "forbidden",
    }
    with pytest.raises(ValidationError, match="extra"):
        SafetyLaneResponseV1.model_validate(value)


def test_model_construct_cannot_bypass_strict_result_validation() -> None:
    forged = DeliveryReadinessResultV1.model_construct(
        **valid_result(minimum_lane_weighted_coverage=True)
    )
    with pytest.raises(ValueError, match="delivery readiness result is invalid"):
        validate_readiness_result_v1(forged)


def test_raw_response_boundary_rejects_cycles_with_a_generic_error() -> None:
    cycle: list[object] = []
    cycle.append(cycle)
    forged = ReadinessEvaluatorResponseV1.model_construct(
        **valid_response(payload={"cycle": cycle})
    )
    with pytest.raises(ValueError, match=r"^readiness evaluator response is invalid$") as error:
        validate_readiness_evaluator_response_v1(forged)
    assert error.value.__cause__ is None


@pytest.mark.parametrize(
    "payload",
    [
        {"wide": [None] * 100_001},
        {"oversized": "x" * (16 * 1024 * 1024 + 1)},
    ],
    ids=("node-limit", "byte-limit"),
)
def test_raw_response_boundary_rejects_oversized_wire_trees(
    payload: dict[str, object],
) -> None:
    forged = ReadinessEvaluatorResponseV1.model_construct(**valid_response(payload=payload))
    with pytest.raises(ValueError, match=r"^readiness evaluator response is invalid$"):
        validate_readiness_evaluator_response_v1(forged)


def test_pending_and_accepted_calls_enforce_complete_response_provenance() -> None:
    assert ReadinessCallRecordV1.model_validate(valid_call()).state == "pending"
    assert ReadinessCallRecordV1.model_validate(valid_call(state="accepted")).state == "accepted"
    with pytest.raises(ValidationError, match="pending readiness calls"):
        ReadinessCallRecordV1.model_validate({**valid_call(), "response_fingerprint": "b" * 64})
    accepted = valid_call(state="accepted")
    accepted.pop("model_name")
    with pytest.raises(ValidationError, match="accepted readiness calls"):
        ReadinessCallRecordV1.model_validate(accepted)


def test_manifest_requires_unique_controller_call_ids() -> None:
    duplicate = valid_call(state="accepted")
    with pytest.raises(ValidationError, match="call IDs must be unique"):
        ReadinessManifestV1.model_validate(
            valid_manifest(accepted_calls=(duplicate,), pending_call=valid_call())
        )


@pytest.mark.parametrize(
    "artifacts",
    [
        (
            {"artifact_path": "z.json", "artifact_hash": HASH},
            {"artifact_path": "a.json", "artifact_hash": "b" * 64},
        ),
        (
            {"artifact_path": "a.json", "artifact_hash": HASH},
            {"artifact_path": "a.json", "artifact_hash": HASH},
        ),
    ],
    ids=("unsorted", "duplicate"),
)
def test_manifest_requires_exact_unique_artifact_sorting(
    artifacts: tuple[dict[str, str], ...],
) -> None:
    with pytest.raises(ValidationError, match="uniquely path-sorted"):
        ReadinessManifestV1.model_validate(valid_manifest(artifacts=artifacts))


def test_contested_ids_use_the_stable_projection_contract_end_to_end() -> None:
    assert (
        BaselineLockedContestedGradeV1.model_validate(
            valid_contested_grade()
        ).contested_requirement_id
        == "CONT-0001"
    )
    contested_call = valid_call(call_id="contested-grade-lane-1-CONT-0001")
    contested_call["operation"] = "baseline_locked_contested_grade"
    assert ReadinessCallRecordV1.model_validate(contested_call).call_id.endswith("CONT-0001")
    with pytest.raises(ValidationError):
        BaselineLockedContestedGradeV1.model_validate(
            valid_contested_grade(contested_requirement_id="CT-0001")
        )
    contested_call["call_id"] = "contested-grade-lane-1-CT-0001"
    contested_call["request_artifact_path"] = "requests/contested-grade-lane-1-CT-0001.json"
    with pytest.raises(ValidationError):
        ReadinessCallRecordV1.model_validate(contested_call)


def test_constructed_response_cannot_launder_raw_tuples_into_json_lists() -> None:
    forged = ReadinessEvaluatorResponseV1.model_construct(
        **valid_response(payload={"raw_tuple": ("not", "json")})
    )
    with pytest.raises(ValueError, match=r"^readiness evaluator response is invalid$"):
        validate_readiness_evaluator_response_v1(forged)


@pytest.mark.parametrize(
    ("model", "value", "field"),
    [
        (
            BaselineLockedGradeBatchV1,
            {"batch_ref": "GB-1-0001", "lane": True, "requirement_ids": ("REQ-0001",)},
            "lane",
        ),
        (BaselineLockedGradeFragmentV1, valid_fragment(lane=True), "lane"),
        (BaselineLockedContestedGradeV1, valid_contested_grade(lane=True), "lane"),
        (BaselineLockedGraderAggregateV1, valid_aggregate(lane=True), "lane"),
        (
            SafetyLaneResponseV1,
            {
                "protocol_version": "delivery-readiness-v1",
                "lane": True,
                "candidate_assessments": (),
                "finding_proposals": (),
            },
            "lane",
        ),
        (ReadinessCallRecordV1, valid_call() | {"attempt": True}, "attempt"),
        (ReadinessCallRecordV1, valid_call() | {"lane": True}, "lane"),
    ],
)
def test_lane_and_attempt_fields_reject_booleans(
    model: type[object], value: dict[str, object], field: str
) -> None:
    with pytest.raises(ValidationError, match=field):
        model.model_validate(value)  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    ("collection", "change"),
    [
        ("ordinary_fragments", {"baseline_fingerprint": "9" * 64}),
        ("ordinary_fragments", {"report_hash": "9" * 64}),
        ("ordinary_fragments", {"grade_target_fingerprint": "9" * 64}),
        ("ordinary_fragments", {"strict_equivalent_scoring_contract_fingerprint": "9" * 64}),
        ("contested_grades", {"baseline_fingerprint": "9" * 64}),
        ("contested_grades", {"report_hash": "9" * 64}),
        ("contested_grades", {"grade_target_fingerprint": "9" * 64}),
        ("contested_grades", {"strict_equivalent_scoring_contract_fingerprint": "9" * 64}),
    ],
)
def test_aggregate_rejects_fragment_binding_substitution(
    collection: str, change: dict[str, object]
) -> None:
    item = (
        valid_fragment(**change)
        if collection == "ordinary_fragments"
        else valid_contested_grade(**change)
    )
    with pytest.raises(ValidationError, match="bindings"):
        BaselineLockedGraderAggregateV1.model_validate(valid_aggregate(**{collection: (item,)}))


def test_aggregate_requires_exact_flattened_grades_and_controller_order() -> None:
    second = valid_fragment(
        batch_ref="GB-1-0002",
        requirement_grades=(valid_grade("REQ-0002"),),
        fragment_fingerprint="1" * 64,
    )
    aggregate = valid_aggregate(
        ordinary_fragments=(valid_fragment(), second),
        requirement_grades=(valid_grade(), valid_grade("REQ-0002")),
    )
    assert len(BaselineLockedGraderAggregateV1.model_validate(aggregate).requirement_grades) == 2
    with pytest.raises(ValidationError, match="flattened"):
        BaselineLockedGraderAggregateV1.model_validate(
            aggregate | {"requirement_grades": (valid_grade("REQ-0002"), valid_grade())}
        )
    with pytest.raises(ValidationError, match="controller order"):
        BaselineLockedGraderAggregateV1.model_validate(
            aggregate | {"ordinary_fragments": (second, valid_fragment())}
        )
    with pytest.raises(ValidationError, match="controller order"):
        BaselineLockedGraderAggregateV1.model_validate(
            valid_aggregate(
                contested_grades=(valid_contested_grade(contested_requirement_id="CONT-0002"),)
            )
        )


@pytest.mark.parametrize(
    "unsafe",
    ["/Users/client/private.json", "../private", "private client detail", "safety-lane-1\nsecret"],
)
def test_run_state_rejects_unsafe_current_call_ids(unsafe: str) -> None:
    with pytest.raises(ValidationError):
        ReadinessRunStateV1.model_validate(
            {
                "schema_version": "delivery-readiness-v1",
                "grade_target_fingerprint": HASH,
                "report_hash": "b" * 64,
                "phase": "safety_review",
                "current_call_id": unsafe,
                "terminal_status": None,
                "manifest_fingerprint": None,
            }
        )


@pytest.mark.parametrize(
    "value",
    [
        {"/Users/client/private": True},
        {"private client detail": True},
        {"replay_valid\nsecret": True},
    ],
)
def test_verification_rejects_non_allowlisted_check_names(value: dict[str, bool]) -> None:
    with pytest.raises(ValidationError):
        ReadinessVerificationV1.model_validate({"valid": True, "checks": value, "issues": ()})


@pytest.mark.parametrize(
    "issue", ["/Users/client/private", "private client detail", "CODE\nsecret"]
)
def test_verification_issues_are_safe_bounded_codes(issue: str) -> None:
    with pytest.raises(ValidationError):
        ReadinessVerificationV1.model_validate({"valid": False, "checks": {}, "issues": (issue,)})


def test_manifest_detaches_and_freezes_legacy_artifact_records() -> None:
    original = ArtifactRecord(artifact_path="a.json", artifact_hash=HASH)
    manifest = ReadinessManifestV1.model_validate(valid_manifest(artifacts=(original,)))
    original.artifact_path = "mutated.json"
    assert manifest.artifacts[0].artifact_path == "a.json"
    with pytest.raises(ValidationError, match="frozen"):
        manifest.artifacts[0].artifact_path = "mutated.json"


def test_fragment_detaches_imported_requirement_grade_aliases() -> None:
    original = RequirementGradeV2.model_validate(valid_grade())
    fragment = BaselineLockedGradeFragmentV1.model_validate(
        valid_fragment(requirement_grades=(original,))
    )
    object.__setattr__(original, "rationale", "mutated")
    assert fragment.requirement_grades[0].rationale != "mutated"


def test_input_detaches_and_rehydrates_verified_projection_alias(tmp_path: Path) -> None:
    _, files_by_path, manifest = _complete_graph()
    run_dir = tmp_path / "verified-baseline"
    initialize_baseline_storage_v1(run_dir, manifest, files_by_path)
    projection = project_gradeable_baseline_v1(load_verified_baseline_run(run_dir))
    expected_grade_target = projection.binding.grade_target_fingerprint
    value = ReadinessInputV1.model_validate(
        {
            "protocol_version": "delivery-readiness-v1",
            "gradeable_baseline": projection,
            "grade_target_fingerprint": expected_grade_target,
            "report_text": "A report.",
            "report_hash": HASH,
            "generation_capsule_root": "b" * 64,
            "generation_validation": {
                "receipt_hash": "c" * 64,
                "report_hash": HASH,
                "bundle_hash": "d" * 64,
                "coverage_review_hash": "e" * 64,
                "status": "completed",
                "evidence_precision_valid": True,
                "proposition_coverage_valid": True,
                "provision_recall_valid": True,
            },
            "readiness_rubric_fingerprint": "f" * 64,
            "strict_equivalent_scoring_contract_fingerprint": "0" * 64,
            "historical_v22_cross_check": None,
        }
    )
    object.__setattr__(projection.binding, "grade_target_fingerprint", "9" * 64)
    assert value.gradeable_baseline.binding.grade_target_fingerprint == expected_grade_target
    assert validate_readiness_input_v1(value).model_dump(mode="json") == value.model_dump(
        mode="json"
    )
