"""Scope decisions must stay coherent without excusing substantive report defects."""

from dataclasses import replace

import pytest
from test_attorney_baseline_projection import _resealed_context
from test_attorney_readiness_compiler import (
    _clean_qualification,
    _lanes,
    _with_requirements,
)
from test_attorney_readiness_compiler import (
    inputs as _inputs_fixture,
)
from test_attorney_readiness_requests import _assessment

from regulatory_harvest.evaluation.attorney_baseline_projection import project_gradeable_baseline_v1
from regulatory_harvest.evaluation.attorney_readiness_compiler import (
    compile_gap_follow_up_matrix_v1,
    compile_requirement_matrix_v1,
    derive_baseline_locked_strict_equivalent_v1,
    derive_delivery_readiness_v1,
    reconcile_safety_lanes_v1,
)
from regulatory_harvest.evaluation.attorney_readiness_models import (
    SafetyGapAssessmentV1,
    SafetyLaneResponseV1,
    SafetyRefereeDecisionV1,
)
from regulatory_harvest.evaluation.attorney_readiness_requests import (
    build_gap_candidate_inventory_v1,
    build_safety_disputes_v1,
    build_safety_lane_request_v1,
    build_safety_referee_request_v1,
)

V2 = "readiness-safety-response-v2"


@pytest.fixture
def inputs(tmp_path):
    return _inputs_fixture.__wrapped__(tmp_path)


def _scoped(inputs):
    value = _clean_qualification(_with_requirements(inputs, count=1))
    context = _resealed_context(value.baseline_context, input_mutation={
        "client_facts": None, "client_facts_binding": "explicit-null",
    })
    projection = project_gradeable_baseline_v1(context)
    return replace(
        value,
        baseline_context=context,
        gradeable_baseline=projection,
        generation_binding=replace(value.generation_binding, client_facts_hash=None),
        readiness_input=value.readiness_input.model_copy(
            update={"safety_response_contract_version": V2, "gradeable_baseline": projection,
                    "grade_target_fingerprint": projection.binding.grade_target_fingerprint}
        ),
    )


def _assessment_with_scope(candidate, *, scoped=True, blocker=None):
    raw = _assessment(candidate).model_dump(mode="json")
    raw.update(
        scope_status="not_required_for_scope" if scoped else "open_gap",
        blocking_code=blocker,
    )
    if scoped:
        raw.update(
            shortfall_description="No client fact is needed for this general report.",
            why_unresolved="The report makes no client-specific applicability assertion.",
            report_passages=[],
            disclosure_location=None,
            visibility="hidden",
        )
    return SafetyGapAssessmentV1.model_validate(raw)


def _result(inputs, lanes, candidates, first, second, decisions=()):
    safety = reconcile_safety_lanes_v1(inputs, candidates, first, second, decisions)
    strict = derive_baseline_locked_strict_equivalent_v1(
        inputs.gradeable_baseline, *lanes, inputs.readiness_rubric
    )
    matrix = compile_gap_follow_up_matrix_v1(inputs, strict, candidates, safety)
    result = derive_delivery_readiness_v1(
        inputs, strict, compile_requirement_matrix_v1(inputs, lanes), matrix,
        safety, first, second,
    )
    return matrix, result


def test_scope_cleared_prerequisite_does_not_become_hidden_gap(inputs):
    current = _scoped(inputs)
    lanes = _lanes(current, ("met",))
    candidates = build_gap_candidate_inventory_v1(current, lanes)
    assert [c.subject_id for c in candidates] == ["CLIENT_FACTS"]
    assessment = _assessment_with_scope(candidates[0])
    first = SafetyLaneResponseV1(lane=1, candidate_assessments=(assessment,), finding_proposals=())
    second = first.model_copy(update={"lane": 2})
    matrix, result = _result(current, lanes, candidates, first, second)
    assert matrix.rows[0].status == "not_required_for_scope"
    assert result.blocking_codes == ()
    assert result.delivery_readiness != "NOT_DELIVERABLE"


def test_whole_assessment_selection_cannot_mix_rationale_and_blocker(inputs):
    current = _scoped(inputs)
    lanes = _lanes(current, ("met",))
    candidates = build_gap_candidate_inventory_v1(current, lanes)
    clear = _assessment_with_scope(candidates[0])
    blocked = _assessment_with_scope(
        candidates[0], scoped=False, blocker="UNDISCLOSED_DISPOSITIVE_CLIENT_FACT"
    )
    first = SafetyLaneResponseV1(lane=1, candidate_assessments=(clear,), finding_proposals=())
    second = SafetyLaneResponseV1(lane=2, candidate_assessments=(blocked,), finding_proposals=())
    disputes = build_safety_disputes_v1(current, first, second)
    assert len(disputes) == 1
    dispute = disputes[0]
    assert dispute.dispute_kind == "assessment"
    request = build_safety_referee_request_v1(current, dispute)
    assert request.payload["report_text"] == current.report_text
    for disposition, expected in (("lane_1", clear), ("lane_2", blocked)):
        decision = SafetyRefereeDecisionV1(
            dispute_id=dispute.dispute_id, disposition=disposition,
            rationale="The scoped report evidence supports this complete assessment.",
            evidence_refs=dispute.evidence_refs,
        )
        reconciled = reconcile_safety_lanes_v1(current, candidates, first, second, (decision,))
        assert reconciled.candidate_assessments == (expected,)


def test_scope_clearance_cannot_erase_requirement_shortfall(inputs):
    current = _scoped(inputs)
    candidates = build_gap_candidate_inventory_v1(current, _lanes(current, ("partially_met",)))
    invalid = _assessment_with_scope(candidates[0])
    valid = _assessment_with_scope(candidates[1])
    first = SafetyLaneResponseV1(
        lane=1, candidate_assessments=(invalid, valid), finding_proposals=()
    )
    with pytest.raises(ValueError):
        reconcile_safety_lanes_v1(
            current, candidates, first, first.model_copy(update={"lane": 2}), ()
        )


def test_new_scope_policy_is_bound_into_request_without_changing_grades(inputs):
    current = _scoped(inputs)
    lanes = _lanes(current, ("met",))
    request = build_safety_lane_request_v1(
        current, lanes, build_gap_candidate_inventory_v1(current, lanes), lane=1
    )
    assert request.payload["safety_response_contract"]["version"] == V2
    schema = request.json_schema["properties"]["candidate_assessments"]["prefixItems"][0]
    assert "scope_status" in schema["required"]
