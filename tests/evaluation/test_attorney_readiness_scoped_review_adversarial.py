"""Adversarial scope decisions must remain evidence-bound and fail closed."""

import pytest
from test_attorney_readiness_drafts import _provenance
from test_attorney_readiness_requests import _finding
from test_attorney_readiness_scoped_review import (
    _assessment_with_scope,
    _inputs_fixture,
    _lanes,
    _result,
    _scoped,
)

from regulatory_harvest.evaluation.attorney_readiness_compiler import (
    compile_gap_follow_up_matrix_v1,
    compile_requirement_matrix_v1,
    derive_baseline_locked_strict_equivalent_v1,
    derive_delivery_readiness_v1,
    reconcile_safety_lanes_v1,
)
from regulatory_harvest.evaluation.attorney_readiness_drafts import (
    ReadinessEngineDefectV1,
    compile_readiness_draft_v1,
)
from regulatory_harvest.evaluation.attorney_readiness_models import (
    GapFollowUpMatrixV1,
    ReadinessEvaluatorRequestV1,
    SafetyDisputeV1,
    SafetyLaneResponseV1,
    SafetyRefereeDecisionV1,
)
from regulatory_harvest.evaluation.attorney_readiness_requests import (
    build_gap_candidate_inventory_v1,
    build_safety_disputes_v1,
    build_safety_referee_request_v1,
)
from regulatory_harvest.storage import canonical_json_bytes, sha256_digest


@pytest.fixture
def inputs(tmp_path):
    return _scoped(_inputs_fixture.__wrapped__(tmp_path))


def _disputed(inputs):
    lanes = _lanes(inputs, ("met",))
    candidates = build_gap_candidate_inventory_v1(inputs, lanes)
    clear = _assessment_with_scope(candidates[0])
    blocked = _assessment_with_scope(
        candidates[0], scoped=False, blocker="UNDISCLOSED_DISPOSITIVE_CLIENT_FACT"
    )
    first = SafetyLaneResponseV1(lane=1, candidate_assessments=(clear,), finding_proposals=())
    second = SafetyLaneResponseV1(lane=2, candidate_assessments=(blocked,), finding_proposals=())
    dispute, = build_safety_disputes_v1(inputs, first, second)
    return lanes, candidates, first, second, dispute


@pytest.mark.parametrize("disposition", ["unresolved", "blocking"])
def test_unresolved_scope_dispute_cannot_inherit_nonblocking_lane(inputs, disposition):
    lanes, candidates, first, second, dispute = _disputed(inputs)
    decision = SafetyRefereeDecisionV1(
        dispute_id=dispute.dispute_id,
        disposition=disposition,
        rationale="The missing applicability evidence leaves this scope dispute unresolved.",
        evidence_refs=dispute.evidence_refs,
    )
    _, result = _result(inputs, lanes, candidates, first, second, (decision,))
    assert result.delivery_readiness == "NOT_DELIVERABLE"
    assert "UNDISCLOSED_DISPOSITIVE_CLIENT_FACT" in result.blocking_codes


def test_scope_clearance_never_suppresses_independent_misinformation_finding(inputs):
    lanes, candidates, first, _, _ = _disputed(inputs)
    finding = _finding(
        rationale="The source evidence does not support this report assertion.",
        subject_id="REQ-0001",
    ).model_copy(update={"evidence_refs": ("SOURCE-000001",)})
    first = first.model_copy(update={"finding_proposals": (finding,)})
    second = first.model_copy(update={"lane": 2})
    _, result = _result(inputs, lanes, candidates, first, second)
    assert result.delivery_readiness == "NOT_DELIVERABLE"
    assert "MATERIAL_UNSUPPORTED_ASSERTION" in result.blocking_codes


def test_scope_clearance_still_requires_attorney_ownership(inputs):
    lanes, candidates, first, _, _ = _disputed(inputs)
    original = first.candidate_assessments[0]
    raw = original.model_dump(mode="json")
    raw["owner_role"] = "research_operator"
    first = first.model_copy(update={
        "candidate_assessments": (type(original).model_validate(raw),),
    })
    second = first.model_copy(update={"lane": 2})
    _, result = _result(inputs, lanes, candidates, first, second)
    assert "CRITICAL_DISCLOSURE_INVALID" in result.blocking_codes


@pytest.mark.parametrize("finding_lane", [1, 2])
def test_whole_assessment_can_reject_an_actual_optional_finding(inputs, finding_lane):
    lanes, candidates, first, _, _ = _disputed(inputs)
    finding = _finding(
        rationale="The source evidence does not support this report assertion.",
        subject_id="REQ-0001",
    ).model_copy(update={"evidence_refs": ("SOURCE-000001",)})
    second = first.model_copy(update={"lane": 2})
    if finding_lane == 1:
        first = first.model_copy(update={"finding_proposals": (finding,)})
    else:
        second = second.model_copy(update={"finding_proposals": (finding,)})
    dispute, = build_safety_disputes_v1(inputs, first, second)
    build_safety_referee_request_v1(inputs, dispute)
    decision = SafetyRefereeDecisionV1(
        dispute_id=dispute.dispute_id,
        disposition="lane_2" if finding_lane == 1 else "lane_1",
        rationale="The source evidence supports the report; the alleged defect is absent.",
        evidence_refs=dispute.evidence_refs,
    )
    _, result = _result(inputs, lanes, candidates, first, second, (decision,))
    assert result.blocking_codes == ()


@pytest.mark.parametrize(
    "mutation",
    [
        {"evidence_refs": ["SOURCE-999999"]},
        {"report_passages": ["This sentence is absent from the report."]},
        {"candidate_id": "GC-0002"},
    ],
)
def test_resealed_whole_assessment_cannot_escape_controller_subject_or_evidence(inputs, mutation):
    _, _, _, _, dispute = _disputed(inputs)
    raw = dispute.model_dump(mode="json")
    raw["lane_2_choice"].update(mutation)
    descriptor = {key: value for key, value in raw.items() if key != "dispute_fingerprint"}
    raw["dispute_fingerprint"] = sha256_digest(canonical_json_bytes(descriptor))
    with pytest.raises(ValueError):
        forged = SafetyDisputeV1.model_validate(raw)
        build_safety_referee_request_v1(inputs, forged)


def test_candidate_assessment_cannot_be_removed_using_null_finding_choice(inputs):
    _, _, _, _, dispute = _disputed(inputs)
    raw = dispute.model_dump(mode="json")
    raw["lane_2_choice"] = None
    descriptor = {key: value for key, value in raw.items() if key != "dispute_fingerprint"}
    raw["dispute_fingerprint"] = sha256_digest(canonical_json_bytes(descriptor))
    with pytest.raises(ValueError):
        forged = SafetyDisputeV1.model_validate(raw)
        build_safety_referee_request_v1(inputs, forged)


@pytest.mark.parametrize(
    "mutation",
    [
        {"evidence_refs": ["SOURCE-999999"]},
        {"report_passages": ["This sentence is absent from the report."]},
        {"candidate_id": "GC-0002"},
    ],
)
def test_draft_compiler_rechecks_whole_choice_evidence_after_request_reseal(inputs, mutation):
    _, _, _, _, dispute = _disputed(inputs)
    request = build_safety_referee_request_v1(inputs, dispute)
    raw = request.model_dump(mode="json")
    raw["payload"]["lane_2_choice"].update(mutation)
    descriptor = {key: value for key, value in raw.items() if key != "request_fingerprint"}
    raw["request_fingerprint"] = sha256_digest(canonical_json_bytes(descriptor))
    forged = ReadinessEvaluatorRequestV1.model_validate(raw)
    outcome = compile_readiness_draft_v1(
        forged,
        {
            "dispute_id": dispute.dispute_id,
            "disposition": "lane_2",
            "rationale": "The issued scoped evidence supports this complete assessment.",
            "evidence_refs": list(dispute.evidence_refs),
        },
        _provenance(),
    )
    assert isinstance(outcome, ReadinessEngineDefectV1)


def test_scoped_prerequisite_does_not_relax_minimum_requirement_coverage(inputs):
    lanes = _lanes(inputs, ("partially_met",))
    candidates = build_gap_candidate_inventory_v1(inputs, lanes)
    assessments = tuple(
        _assessment_with_scope(candidate, scoped=candidate.origin == "prerequisite")
        for candidate in candidates
    )
    first = SafetyLaneResponseV1(
        lane=1, candidate_assessments=assessments, finding_proposals=()
    )
    _, result = _result(inputs, lanes, candidates, first, first.model_copy(update={"lane": 2}))
    assert result.delivery_readiness == "NOT_DELIVERABLE"
    assert "MINIMUM_LANE_COVERAGE_BELOW_FLOOR" in result.blocking_codes


@pytest.mark.parametrize(
    ("scope_cleared", "forged_status"),
    [(False, "not_required_for_scope"), (False, "resolved"), (True, "open")],
)
def test_resealed_gap_matrix_cannot_override_reconciled_scope_status(
    inputs, scope_cleared, forged_status
):
    lanes = _lanes(inputs, ("met",))
    candidates = build_gap_candidate_inventory_v1(inputs, lanes)
    first = SafetyLaneResponseV1(
        lane=1,
        candidate_assessments=(_assessment_with_scope(candidates[0], scoped=scope_cleared),),
        finding_proposals=(),
    )
    second = first.model_copy(update={"lane": 2})
    safety = reconcile_safety_lanes_v1(inputs, candidates, first, second, ())
    strict = derive_baseline_locked_strict_equivalent_v1(
        inputs.gradeable_baseline, *lanes, inputs.readiness_rubric
    )
    matrix = compile_gap_follow_up_matrix_v1(inputs, strict, candidates, safety)
    raw = matrix.model_dump(mode="json")
    row = raw["rows"][0]
    row["status"] = forged_status
    row["row_fingerprint"] = sha256_digest(canonical_json_bytes(
        {key: value for key, value in row.items() if key != "row_fingerprint"}
    ))
    raw["matrix_fingerprint"] = sha256_digest(canonical_json_bytes(
        {key: value for key, value in raw.items() if key != "matrix_fingerprint"}
    ))
    forged = GapFollowUpMatrixV1.model_validate(raw)
    result = derive_delivery_readiness_v1(
        inputs, strict, compile_requirement_matrix_v1(inputs, lanes), forged,
        safety, first, second,
    )
    assert result.delivery_readiness == "NOT_DELIVERABLE"
    assert set(result.blocking_codes) & {"FALSE_RESOLUTION", "INTEGRITY_OR_PROVENANCE_INVALID"}
