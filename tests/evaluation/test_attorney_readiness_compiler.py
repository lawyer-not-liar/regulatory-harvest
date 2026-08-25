"""Conservative compilation for ``delivery-readiness-v1``."""

from __future__ import annotations

from dataclasses import replace
from enum import Enum
from pathlib import Path
from typing import ClassVar, cast

import pytest
from test_attorney_baseline_projection import _resealed_context
from test_attorney_readiness_requests import (
    _assessment,
    _digest,
    _finding,
    _requirement,
    _sealed_model,
    _with_report,
)
from test_attorney_readiness_requests import inputs as _request_inputs_fixture

from regulatory_harvest.evaluation.attorney_baseline_projection import (
    project_gradeable_baseline_v1,
    verify_gradeable_baseline_projection_v1,
)
from regulatory_harvest.evaluation.attorney_readiness_compiler import (
    aggregate_baseline_locked_grader_lane_v1,
    compile_gap_follow_up_matrix_v1,
    compile_requirement_matrix_v1,
    derive_baseline_locked_strict_equivalent_v1,
    derive_delivery_readiness_v1,
    reconcile_safety_lanes_v1,
)
from regulatory_harvest.evaluation.attorney_readiness_inputs import (
    VerifiedReadinessInputsV1,
)
from regulatory_harvest.evaluation.attorney_readiness_models import (
    BaselineLockedContestedGradeV1,
    BaselineLockedGradeFragmentV1,
    BaselineLockedGraderAggregateV1,
    BaselineLockedStrictEquivalentV1,
    GapFollowUpMatrixV1,
    GapFollowUpRowV1,
    HistoricalV22CrossCheckV1,
    ReadinessInputV1,
    ReconciledSafetyReviewV1,
    RequirementMatrixV1,
    SafetyFindingProposalV1,
    SafetyGapCandidateV1,
    SafetyLaneResponseV1,
    SafetyRefereeDecisionV1,
)
from regulatory_harvest.evaluation.attorney_readiness_requests import (
    READINESS_STRICT_EQUIVALENT_SCORING_FINGERPRINT_V1,
    build_gap_candidate_inventory_v1,
    build_safety_disputes_v1,
)
from regulatory_harvest.evaluation.attorney_v2_models import RequirementGradeV2
from regulatory_harvest.storage import canonical_json_bytes, sha256_digest


@pytest.fixture
def inputs(tmp_path: Path) -> VerifiedReadinessInputsV1:
    return _request_inputs_fixture.__wrapped__(tmp_path)


def _with_requirements(
    inputs: VerifiedReadinessInputsV1,
    *,
    count: int,
    importance: str = "supporting",
    kind_at: int | None = None,
    contested: bool = False,
) -> VerifiedReadinessInputsV1:
    def requirement(index: int):
        value = _requirement(
            index,
            importance="material" if importance == "supporting" else importance,
            kind="gap" if index == kind_at else "obligation",
        )
        if importance != "supporting":
            return value
        raw = value.model_dump(mode="json")
        raw.update(
            {
                "importance": "supporting",
                "importance_basis": ["implementation_detail"],
                "importance_rationale": ("The point supplies useful implementation detail."),
            }
        )
        return type(value).model_validate(raw)

    requirements = tuple(requirement(index) for index in range(1, count + 1))
    context = _resealed_context(
        inputs.baseline_context,
        baseline_mutation={
            "requirements": requirements,
            "relationships": (),
            "contested_requirements": (
                inputs.baseline_context.baseline.contested_requirements if contested else ()
            ),
        },
    )
    projection = verify_gradeable_baseline_projection_v1(
        context,
        project_gradeable_baseline_v1(context),
    )
    raw = inputs.readiness_input.model_dump(
        mode="python", exclude={"gradeable_baseline", "grade_target_fingerprint"}
    )
    readiness_input = ReadinessInputV1(
        **raw,
        gradeable_baseline=projection,
        grade_target_fingerprint=projection.binding.grade_target_fingerprint,
    )
    return replace(
        inputs,
        readiness_input=readiness_input,
        baseline_context=context,
        gradeable_baseline=projection,
        source_record=projection.baseline_input.sources,
    )


def _grade(requirement_id: str, disposition: str, passage: str) -> RequirementGradeV2:
    return RequirementGradeV2(
        requirement_id=requirement_id,
        disposition=disposition,
        report_passages=(() if disposition in {"not_met", "uncertain"} else (passage,)),
        rationale="The exact stable requirement was graded against the exact report.",
        omission=(
            None
            if disposition == "met"
            else "The report does not supply the complete required treatment."
        ),
    )


def _clean_qualification(
    inputs: VerifiedReadinessInputsV1,
) -> VerifiedReadinessInputsV1:
    return replace(
        inputs,
        qualification_limits=replace(
            inputs.qualification_limits,
            admission_checks=tuple(
                replace(item, satisfied=True)
                for item in inputs.qualification_limits.admission_checks
            ),
            admission_issues=(),
        ),
    )


def _fragments(
    inputs: VerifiedReadinessInputsV1,
    *,
    lane: int,
    dispositions: tuple[str, ...],
    contested: tuple[tuple[str, str], ...] = (),
) -> tuple[
    tuple[BaselineLockedGradeFragmentV1, ...],
    tuple[BaselineLockedContestedGradeV1, ...],
]:
    passage = "The report addresses the notice duty."
    bindings = {
        "lane": lane,
        "grade_target_fingerprint": inputs.readiness_input.grade_target_fingerprint,
        "baseline_fingerprint": inputs.gradeable_baseline.binding.baseline_fingerprint,
        "report_hash": inputs.report_hash,
        "strict_equivalent_scoring_contract_fingerprint": (
            inputs.readiness_input.strict_equivalent_scoring_contract_fingerprint
        ),
    }
    grades = tuple(
        _grade(item.requirement.requirement_id, disposition, passage)
        for item, disposition in zip(
            inputs.gradeable_baseline.requirements, dispositions, strict=True
        )
    )
    ordinary = tuple(
        cast(
            BaselineLockedGradeFragmentV1,
            _sealed_model(
                BaselineLockedGradeFragmentV1,
                "fragment_fingerprint",
                **bindings,
                batch_ref=f"GB-{lane}-{ordinal:04d}",
                requirement_grades=tuple(
                    grade.model_dump(mode="json") for grade in grades[offset : offset + 5]
                ),
                rationale="The exact controller batch was graded.",
            ),
        )
        for ordinal, offset in enumerate(range(0, len(grades), 5), 1)
    )
    contested_grades = tuple(
        cast(
            BaselineLockedContestedGradeV1,
            _sealed_model(
                BaselineLockedContestedGradeV1,
                "grade_fingerprint",
                **bindings,
                contested_requirement_id=(item.contested_requirement.contested_requirement_id),
                reviewer_alternative_disposition=worlds[0],
                auditor_alternative_disposition=worlds[1],
                reviewer_report_passages=(
                    () if worlds[0] in {"not_met", "uncertain"} else (passage,)
                ),
                auditor_report_passages=(
                    () if worlds[1] in {"not_met", "uncertain"} else (passage,)
                ),
                reviewer_rationale="The reviewer alternative was independently graded.",
                auditor_rationale="The auditor alternative was independently graded.",
                ambiguity_disposition=("uncertain" if "uncertain" in worlds else "acknowledged"),
                rationale="Both exact sealed alternatives were graded.",
            ),
        )
        for item, worlds in zip(
            inputs.gradeable_baseline.contested_requirements, contested, strict=True
        )
    )
    return ordinary, contested_grades


def _aggregate(
    inputs: VerifiedReadinessInputsV1,
    *,
    lane: int,
    dispositions: tuple[str, ...],
    contested: tuple[tuple[str, str], ...] = (),
) -> BaselineLockedGraderAggregateV1:
    ordinary, contested_grades = _fragments(
        inputs,
        lane=lane,
        dispositions=dispositions,
        contested=contested,
    )
    return aggregate_baseline_locked_grader_lane_v1(
        inputs,
        lane=cast(int, lane),
        ordinary_fragments=ordinary,
        contested_grades=contested_grades,
    )


def _lanes(
    inputs: VerifiedReadinessInputsV1,
    first: tuple[str, ...],
    second: tuple[str, ...] | None = None,
    *,
    contested_1: tuple[tuple[str, str], ...] = (),
    contested_2: tuple[tuple[str, str], ...] | None = None,
) -> tuple[BaselineLockedGraderAggregateV1, BaselineLockedGraderAggregateV1]:
    return (
        _aggregate(
            inputs,
            lane=1,
            dispositions=first,
            contested=contested_1,
        ),
        _aggregate(
            inputs,
            lane=2,
            dispositions=first if second is None else second,
            contested=contested_1 if contested_2 is None else contested_2,
        ),
    )


def _safety(
    inputs: VerifiedReadinessInputsV1,
    lanes: tuple[BaselineLockedGraderAggregateV1, BaselineLockedGraderAggregateV1],
    *,
    findings_1: tuple[SafetyFindingProposalV1, ...] = (),
    findings_2: tuple[SafetyFindingProposalV1, ...] | None = None,
    mutate_second: tuple[str, object] | None = None,
    decisions: tuple[SafetyRefereeDecisionV1, ...] | None = None,
) -> tuple[
    tuple[SafetyGapCandidateV1, ...],
    ReconciledSafetyReviewV1,
    SafetyLaneResponseV1,
    SafetyLaneResponseV1,
]:
    candidates = build_gap_candidate_inventory_v1(inputs, lanes)
    first_assessments = tuple(_assessment(item) for item in candidates)
    second_assessments = list(first_assessments)
    if mutate_second is not None:
        field, value = mutate_second
        raw = second_assessments[0].model_dump(mode="json")
        raw[field] = value
        second_assessments[0] = type(second_assessments[0]).model_validate(raw)
    lane_1 = SafetyLaneResponseV1(
        lane=1,
        candidate_assessments=first_assessments,
        finding_proposals=findings_1,
    )
    lane_2 = SafetyLaneResponseV1(
        lane=2,
        candidate_assessments=tuple(second_assessments),
        finding_proposals=findings_1 if findings_2 is None else findings_2,
    )
    disputes = build_safety_disputes_v1(inputs, lane_1, lane_2)
    if decisions is None:
        decisions = tuple(
            SafetyRefereeDecisionV1(
                dispute_id=item.dispute_id,
                disposition="lane_1",
                rationale="The first exact choice is better supported by scoped evidence.",
                evidence_refs=item.evidence_refs[:1],
            )
            for item in disputes
        )
    return (
        candidates,
        reconcile_safety_lanes_v1(
            inputs,
            candidates,
            lane_1,
            lane_2,
            decisions,
        ),
        lane_1,
        lane_2,
    )


def _matching_safety_lanes(
    safety: ReconciledSafetyReviewV1,
) -> tuple[SafetyLaneResponseV1, SafetyLaneResponseV1]:
    return (
        SafetyLaneResponseV1(
            lane=1,
            candidate_assessments=safety.candidate_assessments,
            finding_proposals=safety.finding_proposals,
        ),
        SafetyLaneResponseV1(
            lane=2,
            candidate_assessments=safety.candidate_assessments,
            finding_proposals=safety.finding_proposals,
        ),
    )


def _compile(
    inputs: VerifiedReadinessInputsV1,
    lanes: tuple[BaselineLockedGraderAggregateV1, BaselineLockedGraderAggregateV1],
    *,
    findings: tuple[SafetyFindingProposalV1, ...] = (),
) -> tuple[
    BaselineLockedStrictEquivalentV1,
    RequirementMatrixV1,
    GapFollowUpMatrixV1,
    ReconciledSafetyReviewV1,
    object,
]:
    strict = derive_baseline_locked_strict_equivalent_v1(
        inputs.gradeable_baseline,
        lanes[0],
        lanes[1],
        inputs.readiness_rubric,
    )
    requirement_matrix = compile_requirement_matrix_v1(inputs, lanes)
    candidates, safety, safety_lane_1, safety_lane_2 = _safety(
        inputs,
        lanes,
        findings_1=findings,
    )
    gap_matrix = compile_gap_follow_up_matrix_v1(inputs, strict, candidates, safety)
    result = derive_delivery_readiness_v1(
        inputs,
        strict,
        requirement_matrix,
        gap_matrix,
        safety,
        safety_lane_1,
        safety_lane_2,
    )
    return strict, requirement_matrix, gap_matrix, safety, result


def test_aggregate_requires_exact_fragment_coverage_bindings_and_fingerprints(
    inputs: VerifiedReadinessInputsV1,
) -> None:
    ordinary, contested = _fragments(
        inputs,
        lane=1,
        dispositions=("met",) * 7,
        contested=(("met", "met"),),
    )
    aggregate = aggregate_baseline_locked_grader_lane_v1(
        inputs,
        lane=1,
        ordinary_fragments=ordinary,
        contested_grades=contested,
    )
    assert tuple(item.requirement_id for item in aggregate.requirement_grades) == tuple(
        f"REQ-{index:04d}" for index in range(1, 8)
    )
    assert aggregate.aggregate_fingerprint == sha256_digest(
        canonical_json_bytes(aggregate.model_dump(mode="json", exclude={"aggregate_fingerprint"}))
    )

    forged = ordinary[0].model_copy(update={"fragment_fingerprint": "f" * 64})
    with pytest.raises(ValueError, match="grade fragments are invalid"):
        aggregate_baseline_locked_grader_lane_v1(
            inputs,
            lane=1,
            ordinary_fragments=(forged, *ordinary[1:]),
            contested_grades=contested,
        )
    with pytest.raises(ValueError, match="coverage"):
        aggregate_baseline_locked_grader_lane_v1(
            inputs,
            lane=1,
            ordinary_fragments=ordinary[:-1],
            contested_grades=contested,
        )


@pytest.mark.parametrize(
    ("disposition", "expected", "reason"),
    [
        ("uncertain", "INCONCLUSIVE", "GRADE_UNCERTAIN"),
        ("partially_met", "FAIL", "CRITICAL_RECALL_BELOW_FLOOR"),
        ("not_met", "FAIL", "CRITICAL_RECALL_BELOW_FLOOR"),
        ("met", "PASS", None),
    ],
)
def test_retained_v22_ordinary_scoring_vectors(
    inputs: VerifiedReadinessInputsV1,
    disposition: str,
    expected: str,
    reason: str | None,
) -> None:
    compact = _with_requirements(inputs, count=1, importance="critical")
    lanes = _lanes(compact, (disposition,))
    result = derive_baseline_locked_strict_equivalent_v1(
        compact.gradeable_baseline, *lanes, compact.readiness_rubric
    )
    assert result.absolute_disposition == expected
    assert (reason is None) == (not result.reason_codes)
    if reason is not None:
        assert reason in result.reason_codes
    assert result.strict_equivalent_fingerprint == sha256_digest(
        canonical_json_bytes(
            result.model_dump(mode="json", exclude={"strict_equivalent_fingerprint"})
        )
    )


def test_lane_outcome_disagreement_is_retained_v22_inconclusive(
    inputs: VerifiedReadinessInputsV1,
) -> None:
    compact = _with_requirements(inputs, count=1, importance="critical")
    lanes = _lanes(compact, ("met",), ("partially_met",))
    result = derive_baseline_locked_strict_equivalent_v1(
        compact.gradeable_baseline, *lanes, compact.readiness_rubric
    )
    assert result.absolute_disposition == "INCONCLUSIVE"
    assert result.reason_codes == ("GRADER_DISAGREEMENT",)


def test_retained_reason_code_precedence_is_critical_then_weighted(
    inputs: VerifiedReadinessInputsV1,
) -> None:
    compact = _with_requirements(inputs, count=1, importance="critical")
    lanes = _lanes(compact, ("partially_met",))

    result = derive_baseline_locked_strict_equivalent_v1(
        compact.gradeable_baseline,
        lanes[0],
        lanes[1],
        compact.readiness_rubric,
    )

    assert result.absolute_disposition == "FAIL"
    assert result.reason_codes == (
        "CRITICAL_RECALL_BELOW_FLOOR",
        "WEIGHTED_COVERAGE_BELOW_FLOOR",
    )


@pytest.mark.parametrize(
    ("worlds", "reason", "changing"),
    [
        (("met", "not_met"), "OUTCOME_SENSITIVE_BASELINE_DISPUTE", ("CONT-0001",)),
        (("uncertain", "uncertain"), "BASELINE_EVIDENCE_INSUFFICIENT", ()),
    ],
)
def test_retained_v22_contested_sensitivity_vectors(
    inputs: VerifiedReadinessInputsV1,
    worlds: tuple[str, str],
    reason: str,
    changing: tuple[str, ...],
) -> None:
    contested_inputs = _with_requirements(inputs, count=7, importance="critical", contested=True)
    lanes = _lanes(
        contested_inputs,
        ("met",) * 7,
        contested_1=(worlds,),
    )
    result = derive_baseline_locked_strict_equivalent_v1(
        contested_inputs.gradeable_baseline,
        *lanes,
        contested_inputs.readiness_rubric,
    )
    assert result.absolute_disposition == "INCONCLUSIVE"
    assert result.reason_codes == (reason,)
    assert result.outcome_determinative_contested_ids == changing


def test_outcome_determinative_contest_is_a_delivery_blocker(
    inputs: VerifiedReadinessInputsV1,
) -> None:
    contested_inputs = _with_requirements(
        inputs,
        count=7,
        importance="critical",
        contested=True,
    )
    lanes = _lanes(
        contested_inputs,
        ("met",) * 7,
        contested_1=(("met", "not_met"),),
    )

    strict, _, gap, _, result = _compile(contested_inputs, lanes)

    assert strict.outcome_determinative_contested_ids == ("CONT-0001",)
    assert any(row.origin == "contested_requirement" for row in gap.rows)
    assert result.delivery_readiness == "NOT_DELIVERABLE"
    assert "OUTCOME_DETERMINATIVE_CONTEST" in result.blocking_codes


def test_scoring_contract_fingerprint_is_the_packaged_public_descriptor(
    inputs: VerifiedReadinessInputsV1,
) -> None:
    lanes = _lanes(inputs, ("met",) * 7, contested_1=(("met", "met"),))
    strict = derive_baseline_locked_strict_equivalent_v1(
        inputs.gradeable_baseline, *lanes, inputs.readiness_rubric
    )
    assert (
        lanes[0].strict_equivalent_scoring_contract_fingerprint
        == inputs.readiness_input.strict_equivalent_scoring_contract_fingerprint
    )
    assert len(READINESS_STRICT_EQUIVALENT_SCORING_FINGERPRINT_V1) == 64
    assert strict.semantics == "attorney-eval-v2.2-strict-equivalent"


def test_requirement_matrix_is_complete_conservative_and_stably_fingerprinted(
    inputs: VerifiedReadinessInputsV1,
) -> None:
    lanes = _lanes(
        inputs,
        ("met", "partially_met", "not_met", "uncertain", "met", "met", "met"),
        ("met", "met", "partially_met", "not_met", "met", "met", "met"),
        contested_1=(("met", "met"),),
        contested_2=(("met", "met"),),
    )
    matrix = compile_requirement_matrix_v1(inputs, lanes)
    assert tuple(row.requirement_id for row in matrix.rows) == tuple(
        f"REQ-{index:04d}" for index in range(1, 8)
    )
    assert tuple(row.conservative_disposition.value for row in matrix.rows[:4]) == (
        "met",
        "partially_met",
        "not_met",
        "uncertain",
    )
    assert matrix.matrix_fingerprint == sha256_digest(
        canonical_json_bytes(matrix.model_dump(mode="json", exclude={"matrix_fingerprint"}))
    )


def test_downstream_interfaces_reject_resealed_noncanonical_fragment_partition(
    inputs: VerifiedReadinessInputsV1,
) -> None:
    exact = _with_requirements(inputs, count=6, importance="supporting")
    lanes = _lanes(exact, ("met",) * 6)
    first = lanes[0]
    grades = first.requirement_grades
    fragment_1 = cast(
        BaselineLockedGradeFragmentV1,
        _sealed_model(
            BaselineLockedGradeFragmentV1,
            "fragment_fingerprint",
            **first.ordinary_fragments[0].model_dump(
                mode="json",
                exclude={"fragment_fingerprint", "requirement_grades"},
            ),
            requirement_grades=(grades[0].model_dump(mode="json"),),
        ),
    )
    fragment_2 = cast(
        BaselineLockedGradeFragmentV1,
        _sealed_model(
            BaselineLockedGradeFragmentV1,
            "fragment_fingerprint",
            **first.ordinary_fragments[1].model_dump(
                mode="json",
                exclude={"fragment_fingerprint", "requirement_grades"},
            ),
            requirement_grades=tuple(grade.model_dump(mode="json") for grade in grades[1:]),
        ),
    )
    descriptor = first.model_dump(mode="json", exclude={"aggregate_fingerprint"})
    descriptor["ordinary_fragments"] = [
        fragment_1.model_dump(mode="json"),
        fragment_2.model_dump(mode="json"),
    ]
    forged = BaselineLockedGraderAggregateV1.model_validate(
        {
            **descriptor,
            "aggregate_fingerprint": sha256_digest(canonical_json_bytes(descriptor)),
        }
    )

    with pytest.raises(ValueError, match="grader aggregate is invalid"):
        derive_baseline_locked_strict_equivalent_v1(
            exact.gradeable_baseline,
            forged,
            lanes[1],
            exact.readiness_rubric,
        )
    with pytest.raises(ValueError, match="grader aggregate is invalid"):
        compile_requirement_matrix_v1(exact, (forged, lanes[1]))


def test_safety_reconciliation_requires_exact_dispute_and_referee_coverage(
    inputs: VerifiedReadinessInputsV1,
) -> None:
    lanes = _lanes(
        inputs,
        ("partially_met", *(["met"] * 6)),
        contested_1=(("met", "met"),),
    )
    candidates = build_gap_candidate_inventory_v1(inputs, lanes)
    first = tuple(_assessment(item) for item in candidates)
    second = list(first)
    raw = second[0].model_dump(mode="json")
    raw["owner_role"] = "outside_counsel"
    second[0] = type(second[0]).model_validate(raw)
    lane_1 = SafetyLaneResponseV1(lane=1, candidate_assessments=first, finding_proposals=())
    lane_2 = SafetyLaneResponseV1(lane=2, candidate_assessments=tuple(second), finding_proposals=())
    dispute = build_safety_disputes_v1(inputs, lane_1, lane_2)[0]
    with pytest.raises(ValueError, match="referee coverage"):
        reconcile_safety_lanes_v1(inputs, candidates, lane_1, lane_2, ())
    decision = SafetyRefereeDecisionV1(
        dispute_id=dispute.dispute_id,
        disposition="lane_2",
        rationale="The second owner follows the scoped evidence.",
        evidence_refs=dispute.evidence_refs[:1],
    )
    reconciled = reconcile_safety_lanes_v1(inputs, candidates, lane_1, lane_2, (decision,))
    assert reconciled.candidate_assessments[0].owner_role == "outside_counsel"
    assert reconciled.referee_decisions == (decision,)

    with pytest.raises(ValueError, match="referee coverage"):
        reconcile_safety_lanes_v1(
            inputs,
            candidates,
            lane_1,
            lane_2,
            (decision, decision),
        )


def test_safety_referee_decisions_require_exact_canonical_order(
    inputs: VerifiedReadinessInputsV1,
) -> None:
    lanes = _lanes(
        inputs,
        ("partially_met", *("met" for _ in range(6))),
        contested_1=(("met", "met"),),
    )
    candidates = build_gap_candidate_inventory_v1(inputs, lanes)
    first = tuple(_assessment(item) for item in candidates)
    second_raw = first[0].model_dump(mode="json")
    second_raw.update(
        {
            "owner_role": "outside_counsel",
            "visibility": "prominent",
        }
    )
    second = (type(first[0]).model_validate(second_raw), *first[1:])
    lane_1 = SafetyLaneResponseV1(
        lane=1,
        candidate_assessments=first,
        finding_proposals=(),
    )
    lane_2 = SafetyLaneResponseV1(
        lane=2,
        candidate_assessments=second,
        finding_proposals=(),
    )
    disputes = build_safety_disputes_v1(inputs, lane_1, lane_2)
    assert len(disputes) == 2
    decisions = tuple(
        SafetyRefereeDecisionV1(
            dispute_id=dispute.dispute_id,
            disposition="lane_2",
            rationale="The second exact choice follows the scoped evidence.",
            evidence_refs=dispute.evidence_refs[:1],
        )
        for dispute in disputes
    )

    with pytest.raises(ValueError, match="referee coverage"):
        reconcile_safety_lanes_v1(
            inputs,
            candidates,
            lane_1,
            lane_2,
            tuple(reversed(decisions)),
        )


def test_unknown_blocker_codes_are_rejected_on_safety_record_surfaces(
    inputs: VerifiedReadinessInputsV1,
) -> None:
    exact = _clean_qualification(_with_requirements(inputs, count=10, importance="supporting"))
    lanes = _lanes(exact, ("met",) * 9 + ("not_met",))
    candidates = build_gap_candidate_inventory_v1(exact, lanes)
    assessments = tuple(_assessment(candidate) for candidate in candidates)
    first_raw = assessments[0].model_dump(mode="json")
    first_raw["blocking_code"] = "UNKNOWN_NONEMPTY_BLOCKER"
    forged_first = type(assessments[0]).model_validate(first_raw)
    forged_assessments = (forged_first, *assessments[1:])
    lane_1 = SafetyLaneResponseV1(
        lane=1,
        candidate_assessments=forged_assessments,
        finding_proposals=(),
    )
    lane_2 = SafetyLaneResponseV1(
        lane=2,
        candidate_assessments=forged_assessments,
        finding_proposals=(),
    )

    with pytest.raises(ValueError, match="safety blocking code is invalid"):
        reconcile_safety_lanes_v1(
            exact,
            candidates,
            lane_1,
            lane_2,
            (),
        )


def test_gap_matrix_has_one_open_row_per_candidate_and_finding_in_stable_order(
    inputs: VerifiedReadinessInputsV1,
) -> None:
    lanes = _lanes(
        inputs,
        ("partially_met", "met", "met", "met", "met", "met", "met"),
        contested_1=(("met", "met"),),
    )
    strict = derive_baseline_locked_strict_equivalent_v1(
        inputs.gradeable_baseline, *lanes, inputs.readiness_rubric
    )
    finding = _finding(rationale="The cited source does not support the report statement.")
    candidates, safety, _, _ = _safety(inputs, lanes, findings_1=(finding,))
    matrix = compile_gap_follow_up_matrix_v1(inputs, strict, candidates, safety)
    assert len(matrix.rows) == len(candidates) + 1
    assert tuple(row.gap_id for row in matrix.rows) == tuple(
        f"GAP-{index:04d}" for index in range(1, len(matrix.rows) + 1)
    )
    assert all(row.status == "open" for row in matrix.rows)
    assert sum(row.origin == "safety_finding" for row in matrix.rows) == 1
    assert matrix.rows[-1].kind == "MATERIAL_UNSUPPORTED_ASSERTION"


def test_gap_matrix_covers_every_origin_and_rejects_truncated_candidate_inventory(
    inputs: VerifiedReadinessInputsV1,
) -> None:
    exact = _with_requirements(
        inputs,
        count=7,
        importance="supporting",
        kind_at=2,
        contested=True,
    )
    lanes = _lanes(
        exact,
        ("partially_met", *("met" for _ in range(6))),
        contested_1=(("met", "met"),),
    )
    strict = derive_baseline_locked_strict_equivalent_v1(
        exact.gradeable_baseline,
        lanes[0],
        lanes[1],
        exact.readiness_rubric,
    )
    finding = _finding(
        rationale="The cited evidence establishes the report-wide safety defect.",
        subject_id="REQ-0003",
    )
    candidates, safety, _, _ = _safety(exact, lanes, findings_1=(finding,))
    matrix = compile_gap_follow_up_matrix_v1(exact, strict, candidates, safety)

    assert {row.origin.value for row in matrix.rows} == {
        "requirement",
        "baseline_gap",
        "contested_requirement",
        "prerequisite",
        "safety_finding",
    }
    assert tuple(row.gap_id for row in matrix.rows) == tuple(
        f"GAP-{index:04d}" for index in range(1, len(matrix.rows) + 1)
    )
    assert tuple(row.canonical_order for row in matrix.rows) == tuple(range(len(matrix.rows)))
    assert all(row.status == "open" for row in matrix.rows)
    assert all(row.evidence_refs for row in matrix.rows)
    assert all(row.follow_up_code for row in matrix.rows)
    assert all(
        row.row_fingerprint
        == sha256_digest(
            canonical_json_bytes(row.model_dump(mode="json", exclude={"row_fingerprint"}))
        )
        for row in matrix.rows
    )

    with pytest.raises(ValueError, match="candidate inventory"):
        compile_gap_follow_up_matrix_v1(
            exact,
            strict,
            candidates[:-1],
            safety,
        )


def test_exact_seventy_percent_fail_is_review_ready_with_visible_gaps(
    inputs: VerifiedReadinessInputsV1,
) -> None:
    exact = _clean_qualification(_with_requirements(inputs, count=10, importance="supporting"))
    dispositions = ("met",) * 7 + ("not_met",) * 3
    lanes = _lanes(exact, dispositions)
    strict, _, _, _, result = _compile(exact, lanes)
    assert strict.absolute_disposition == "FAIL"
    assert result.minimum_lane_weighted_coverage == 0.7
    assert result.delivery_readiness == "REVIEW_READY_WITH_GAPS"


def test_one_lane_below_exact_seventy_percent_fails_closed(
    inputs: VerifiedReadinessInputsV1,
) -> None:
    exact = _with_requirements(inputs, count=10, importance="supporting")
    lanes = _lanes(
        exact,
        ("met",) * 6 + ("partially_met",) + ("not_met",) * 3,
        ("met",) * 10,
    )
    _, _, _, _, result = _compile(exact, lanes)
    assert result.minimum_lane_weighted_coverage == 0.65
    assert result.delivery_readiness == "NOT_DELIVERABLE"
    assert "MINIMUM_LANE_COVERAGE_BELOW_FLOOR" in result.blocking_codes


def test_exact_six_hundred_ninety_nine_thousandths_fails_rational_floor(
    inputs: VerifiedReadinessInputsV1,
) -> None:
    exact = _clean_qualification(_with_requirements(inputs, count=500, importance="supporting"))
    dispositions = (
        *("met" for _ in range(349)),
        "partially_met",
        *("not_met" for _ in range(150)),
    )
    lanes = _lanes(exact, dispositions)
    strict, requirement, gap, safety, result = _compile(exact, lanes)

    assert strict.lane_weighted_coverage == (0.699, 0.699)
    assert result.minimum_lane_weighted_coverage == 0.699
    assert result.delivery_readiness == "NOT_DELIVERABLE"
    assert result.blocking_codes == ("MINIMUM_LANE_COVERAGE_BELOW_FLOOR",)
    assert len(requirement.rows) == 500
    assert len(gap.rows) == 151
    assert safety.blocking_codes == ()


def test_delivery_floor_counts_each_contested_requirement_once_conservatively(
    inputs: VerifiedReadinessInputsV1,
) -> None:
    exact = _clean_qualification(
        _with_requirements(
            inputs,
            count=7,
            importance="supporting",
            contested=True,
        )
    )
    lanes = _lanes(
        exact,
        ("met",) * 6 + ("partially_met",),
        contested_1=(("not_met", "not_met"),),
    )

    strict, _, _, _, result = _compile(exact, lanes)

    assert strict.absolute_disposition == "FAIL"
    assert result.lane_weighted_coverage == (0.65, 0.65)
    assert result.lane_critical_recall == (0.0, 0.0)
    assert result.delivery_readiness == "NOT_DELIVERABLE"
    assert "MINIMUM_LANE_COVERAGE_BELOW_FLOOR" in result.blocking_codes


def test_exact_ninety_percent_and_full_critical_recall_are_required_for_high_assurance(
    inputs: VerifiedReadinessInputsV1,
) -> None:
    exact = _clean_qualification(_with_requirements(inputs, count=10, importance="supporting"))
    lanes = _lanes(exact, ("met",) * 9 + ("not_met",))
    _, _, _, _, result = _compile(exact, lanes)
    assert result.minimum_lane_weighted_coverage == 0.9
    assert result.delivery_readiness == "HIGH_ASSURANCE"

    all_met = _lanes(exact, ("met",) * 10)
    _, _, gap_matrix, _, high = _compile(exact, all_met)
    assert gap_matrix.rows == ()
    assert high.delivery_readiness == "HIGH_ASSURANCE"


def test_critical_recall_below_one_blocks_high_assurance_even_above_ninety_percent(
    inputs: VerifiedReadinessInputsV1,
) -> None:
    exact = _clean_qualification(_with_requirements(inputs, count=10, importance="critical"))
    lanes = _lanes(exact, ("met",) * 9 + ("partially_met",))
    strict, _, _, _, result = _compile(exact, lanes)

    assert strict.lane_weighted_coverage == (0.95, 0.95)
    assert strict.lane_critical_recall == (0.95, 0.95)
    assert strict.reason_codes == ("CRITICAL_RECALL_BELOW_FLOOR",)
    assert result.delivery_readiness == "REVIEW_READY_WITH_GAPS"


@pytest.mark.parametrize("fresh", ["FAIL", "INCONCLUSIVE"])
def test_substantive_nonpass_can_still_be_review_ready(
    inputs: VerifiedReadinessInputsV1,
    fresh: str,
) -> None:
    exact = _with_requirements(inputs, count=10, importance="supporting")
    dispositions = (
        ("met",) * 6 + ("partially_met",) * 4 if fresh == "FAIL" else ("met",) * 9 + ("uncertain",)
    )
    lanes = _lanes(exact, dispositions)
    strict, _, _, _, result = _compile(exact, lanes)
    assert strict.absolute_disposition == fresh
    assert result.delivery_readiness == "REVIEW_READY_WITH_GAPS"


def test_strict_pass_with_visible_baseline_gap_is_review_ready_not_high_assurance(
    inputs: VerifiedReadinessInputsV1,
) -> None:
    exact = _with_requirements(inputs, count=10, importance="supporting", kind_at=10)
    lanes = _lanes(exact, ("met",) * 10)
    strict, _, gap_matrix, _, result = _compile(exact, lanes)
    assert strict.absolute_disposition == "PASS"
    assert any(row.origin == "baseline_gap" for row in gap_matrix.rows)
    assert result.delivery_readiness == "REVIEW_READY_WITH_GAPS"


def test_historical_disposition_is_attached_after_tier_without_seeding_it(
    inputs: VerifiedReadinessInputsV1,
) -> None:
    exact = _with_requirements(inputs, count=10, importance="supporting")
    lanes = _lanes(exact, ("met",) * 10)
    strict, requirement, gap, safety, without = _compile(exact, lanes)
    historical = HistoricalV22CrossCheckV1(
        report_hash=exact.report_hash,
        strict_disposition="FAIL",
        result_fingerprint=_digest("historical-result"),
        manifest_fingerprint=_digest("historical-manifest"),
        baseline_fingerprint=exact.gradeable_baseline.binding.baseline_fingerprint,
        grader_aggregate_fingerprints=(_digest("h1"), _digest("h2")),
        reason_codes=("CRITICAL_RECALL_BELOW_FLOOR",),
        baseline_comparable=True,
        report_comparable=True,
    )
    with_history = replace(
        exact,
        readiness_input=exact.readiness_input.model_copy(
            update={"historical_v22_cross_check": historical}
        ),
        historical_v22=historical,
    )
    attached = derive_delivery_readiness_v1(
        with_history,
        strict,
        requirement,
        gap,
        safety,
        *_matching_safety_lanes(safety),
    )
    assert attached.delivery_readiness == without.delivery_readiness
    assert attached.blocking_codes == without.blocking_codes
    assert attached.historical_v22_strict_disposition == "FAIL"
    assert attached.historical_v22_cross_check_status == "DISPOSITION_DIFFERS"


@pytest.mark.parametrize("fresh", ["PASS", "FAIL", "INCONCLUSIVE"])
@pytest.mark.parametrize("historical", [None, "PASS", "FAIL", "INCONCLUSIVE"])
def test_historical_cross_product_changes_only_labeled_historical_fields(
    inputs: VerifiedReadinessInputsV1,
    fresh: str,
    historical: str | None,
) -> None:
    exact = _with_requirements(inputs, count=10, importance="supporting")
    dispositions = {
        "PASS": ("met",) * 10,
        "FAIL": ("met",) * 6 + ("partially_met",) * 4,
        "INCONCLUSIVE": ("met",) * 9 + ("uncertain",),
    }[fresh]
    lanes = _lanes(exact, dispositions)
    strict, requirement, gap, safety, without = _compile(exact, lanes)
    assert strict.absolute_disposition == fresh

    if historical is None:
        attached = without
    else:
        cross_check = HistoricalV22CrossCheckV1(
            report_hash=exact.report_hash,
            strict_disposition=historical,
            result_fingerprint=_digest(f"history-result-{historical}"),
            manifest_fingerprint=_digest(f"history-manifest-{historical}"),
            baseline_fingerprint=exact.gradeable_baseline.binding.baseline_fingerprint,
            grader_aggregate_fingerprints=(_digest("history-lane-1"), _digest("history-lane-2")),
            reason_codes=(),
            baseline_comparable=True,
            report_comparable=True,
        )
        with_history = replace(
            exact,
            readiness_input=exact.readiness_input.model_copy(
                update={"historical_v22_cross_check": cross_check}
            ),
            historical_v22=cross_check,
        )
        attached = derive_delivery_readiness_v1(
            with_history,
            strict,
            requirement,
            gap,
            safety,
            *_matching_safety_lanes(safety),
        )

    assert attached.delivery_readiness == without.delivery_readiness
    assert attached.blocking_codes == without.blocking_codes
    assert attached.baseline_locked_strict_equivalent_disposition == fresh
    assert attached.minimum_lane_weighted_coverage == without.minimum_lane_weighted_coverage
    assert attached.lane_critical_recall == without.lane_critical_recall
    assert attached.historical_v22_strict_disposition == historical
    assert attached.historical_v22_cross_check_status == (
        "NOT_PROVIDED"
        if historical is None
        else "MATCH"
        if historical == fresh
        else "DISPOSITION_DIFFERS"
    )


@pytest.mark.parametrize(
    ("finding_kind", "blocking_code"),
    [
        ("MATERIAL_UNSUPPORTED_ASSERTION", "MATERIAL_UNSUPPORTED_ASSERTION"),
        ("BASELINE_CONTRADICTION", "BASELINE_CONTRADICTION"),
        ("UNDISCLOSED_DISPOSITIVE_CLIENT_FACT", "UNDISCLOSED_DISPOSITIVE_CLIENT_FACT"),
        ("MISLEADING_CURRENTNESS_OR_AUTHORITY", "MISLEADING_CURRENTNESS_OR_AUTHORITY"),
        ("HIDDEN_OR_UNDERSTATED_LIMITATION", "HIDDEN_MATERIAL_GAP"),
        ("UNDISCLOSED_GRADER_GAP", "HIDDEN_MATERIAL_GAP"),
    ],
)
def test_each_safety_finding_kind_blocks_in_rubric_order(
    inputs: VerifiedReadinessInputsV1,
    finding_kind: str,
    blocking_code: str,
) -> None:
    exact = _with_requirements(inputs, count=10, importance="supporting")
    lanes = _lanes(exact, ("met",) * 10)
    finding = _finding(
        rationale="The exact cited evidence establishes the safety defect.",
        subject_id="REQ-0001",
        kind=finding_kind,
    )
    raw = finding.model_dump(mode="json")
    raw["blocking_code"] = blocking_code
    exact_finding = SafetyFindingProposalV1.model_validate(raw)
    _, _, _, _, result = _compile(exact, lanes, findings=(exact_finding,))
    assert result.delivery_readiness == "NOT_DELIVERABLE"
    assert blocking_code in result.blocking_codes


def test_safety_finding_kind_rederives_blocker_after_coordinated_field_reseal(
    inputs: VerifiedReadinessInputsV1,
) -> None:
    exact = _clean_qualification(_with_requirements(inputs, count=10, importance="supporting"))
    lanes = _lanes(exact, ("met",) * 10)
    finding = _finding(
        rationale="The exact evidence does not support the material assertion.",
        subject_id="REQ-0003",
        kind="MATERIAL_UNSUPPORTED_ASSERTION",
    )
    strict, requirement, gap, safety, original = _compile(
        exact,
        lanes,
        findings=(finding,),
    )
    assert original.delivery_readiness == "NOT_DELIVERABLE"

    finding_raw = safety.finding_proposals[0].model_dump(mode="json")
    finding_raw["blocking_code"] = None
    changed_finding = SafetyFindingProposalV1.model_validate(finding_raw)
    safety_descriptor = safety.model_dump(
        mode="json",
        exclude={"safety_review_fingerprint"},
    )
    safety_descriptor["finding_proposals"] = [changed_finding.model_dump(mode="json")]
    safety_descriptor["blocking_codes"] = []
    forged_safety = ReconciledSafetyReviewV1.model_validate(
        {
            **safety_descriptor,
            "safety_review_fingerprint": sha256_digest(canonical_json_bytes(safety_descriptor)),
        }
    )

    changed_rows: list[GapFollowUpRowV1] = []
    for row in gap.rows:
        descriptor = row.model_dump(mode="json", exclude={"row_fingerprint"})
        if row.origin == "safety_finding":
            descriptor["blocking_code"] = None
        changed_rows.append(
            GapFollowUpRowV1.model_validate(
                {
                    **descriptor,
                    "row_fingerprint": sha256_digest(canonical_json_bytes(descriptor)),
                }
            )
        )
    matrix_descriptor = gap.model_dump(
        mode="json",
        exclude={"matrix_fingerprint"},
    )
    matrix_descriptor["rows"] = [row.model_dump(mode="json") for row in changed_rows]
    forged_gap = GapFollowUpMatrixV1.model_validate(
        {
            **matrix_descriptor,
            "matrix_fingerprint": sha256_digest(canonical_json_bytes(matrix_descriptor)),
        }
    )

    result = derive_delivery_readiness_v1(
        exact,
        strict,
        requirement,
        forged_gap,
        forged_safety,
        *_matching_safety_lanes(safety),
    )

    assert result.delivery_readiness == "NOT_DELIVERABLE"
    assert "MATERIAL_UNSUPPORTED_ASSERTION" in result.blocking_codes


def test_blocker_precedence_is_stable_and_independent_of_row_order(
    inputs: VerifiedReadinessInputsV1,
) -> None:
    exact = _with_requirements(inputs, count=10, importance="supporting")
    lanes = _lanes(exact, ("met",) * 10)
    strict, requirement, gap, safety, _ = _compile(exact, lanes)
    forged_safety = safety.model_copy(
        update={
            "blocking_codes": (
                "GAP_RATIONALE_INVALID",
                "HIDDEN_MATERIAL_GAP",
                "MATERIAL_UNSUPPORTED_ASSERTION",
                "INTEGRITY_OR_PROVENANCE_INVALID",
            )
        }
    )
    descriptor = forged_safety.model_dump(mode="json", exclude={"safety_review_fingerprint"})
    forged_safety = forged_safety.model_copy(
        update={"safety_review_fingerprint": sha256_digest(canonical_json_bytes(descriptor))}
    )
    result = derive_delivery_readiness_v1(
        exact,
        strict,
        requirement,
        gap,
        forged_safety,
        *_matching_safety_lanes(safety),
    )
    assert result.blocking_codes == (
        "INTEGRITY_OR_PROVENANCE_INVALID",
        "MATERIAL_UNSUPPORTED_ASSERTION",
        "HIDDEN_MATERIAL_GAP",
        "GAP_RATIONALE_INVALID",
    )


def test_finding_input_order_does_not_change_safety_or_gap_outputs(
    inputs: VerifiedReadinessInputsV1,
) -> None:
    exact = _with_requirements(inputs, count=10, importance="supporting")
    lanes = _lanes(exact, ("met",) * 10)
    first = _finding(
        rationale="The first cited source does not support the report statement.",
        subject_id="REQ-0002",
        kind="MATERIAL_UNSUPPORTED_ASSERTION",
    )
    second = _finding(
        rationale="The second cited source contradicts the baseline treatment.",
        subject_id="REQ-0001",
        kind="BASELINE_CONTRADICTION",
    )
    strict_a, requirement_a, gap_a, safety_a, result_a = _compile(
        exact,
        lanes,
        findings=(first, second),
    )
    strict_b, requirement_b, gap_b, safety_b, result_b = _compile(
        exact,
        lanes,
        findings=(second, first),
    )

    assert strict_a == strict_b
    assert requirement_a == requirement_b
    assert safety_a == safety_b
    assert gap_a == gap_b
    assert result_a == result_b


def test_missing_required_gap_row_returns_blocker_not_silent_review_readiness(
    inputs: VerifiedReadinessInputsV1,
) -> None:
    exact = _with_requirements(inputs, count=10, importance="supporting")
    lanes = _lanes(exact, ("met",) * 9 + ("partially_met",))
    strict, requirement, gap, safety, _ = _compile(exact, lanes)
    omitted_rows = tuple(
        row
        for row in gap.rows
        if not (row.origin == "requirement" and row.subject_id == "REQ-0010")
    )
    assert len(omitted_rows) == len(gap.rows) - 1
    renumbered_rows: list[GapFollowUpRowV1] = []
    for index, row in enumerate(omitted_rows, 1):
        row_descriptor = row.model_dump(mode="json", exclude={"row_fingerprint"})
        row_descriptor.update(
            {
                "gap_id": f"GAP-{index:04d}",
                "canonical_order": index - 1,
            }
        )
        renumbered_rows.append(
            GapFollowUpRowV1.model_validate(
                {
                    **row_descriptor,
                    "row_fingerprint": sha256_digest(canonical_json_bytes(row_descriptor)),
                }
            )
        )
    descriptor = gap.model_dump(mode="json", exclude={"matrix_fingerprint"})
    descriptor["rows"] = [row.model_dump(mode="json") for row in renumbered_rows]
    missing = GapFollowUpMatrixV1.model_validate(
        {
            **descriptor,
            "matrix_fingerprint": sha256_digest(canonical_json_bytes(descriptor)),
        }
    )

    result = derive_delivery_readiness_v1(
        exact,
        strict,
        requirement,
        missing,
        safety,
        *_matching_safety_lanes(safety),
    )

    assert result.delivery_readiness == "NOT_DELIVERABLE"
    assert "MISSING_REQUIRED_FOLLOW_UP" in result.blocking_codes


def test_all_compiler_outputs_recompute_canonical_fingerprints(
    inputs: VerifiedReadinessInputsV1,
) -> None:
    exact = _with_requirements(inputs, count=10, importance="supporting")
    lanes = _lanes(exact, ("met",) * 9 + ("partially_met",))
    strict, requirement, gap, safety, result = _compile(exact, lanes)

    outputs_and_fields = (
        (lanes[0], "aggregate_fingerprint"),
        (lanes[1], "aggregate_fingerprint"),
        (strict, "strict_equivalent_fingerprint"),
        (requirement, "matrix_fingerprint"),
        (gap, "matrix_fingerprint"),
        (safety, "safety_review_fingerprint"),
        (result, "result_fingerprint"),
    )
    for output, fingerprint_field in outputs_and_fields:
        assert getattr(output, fingerprint_field) == sha256_digest(
            canonical_json_bytes(output.model_dump(mode="json", exclude={fingerprint_field}))
        )


def test_resealed_fragment_provenance_attack_is_rejected(
    inputs: VerifiedReadinessInputsV1,
) -> None:
    ordinary, contested = _fragments(
        inputs,
        lane=1,
        dispositions=("met",) * 7,
        contested=(("met", "met"),),
    )
    descriptor = ordinary[0].model_dump(mode="json", exclude={"fragment_fingerprint"})
    descriptor["report_hash"] = "f" * 64
    forged = BaselineLockedGradeFragmentV1.model_validate(
        {
            **descriptor,
            "fragment_fingerprint": sha256_digest(canonical_json_bytes(descriptor)),
        }
    )

    with pytest.raises(ValueError, match="grade fragments are invalid"):
        aggregate_baseline_locked_grader_lane_v1(
            inputs,
            lane=1,
            ordinary_fragments=(forged, *ordinary[1:]),
            contested_grades=contested,
        )


def test_resealed_safety_cannot_delete_unresolved_referee_blocker(
    inputs: VerifiedReadinessInputsV1,
) -> None:
    exact = _clean_qualification(_with_requirements(inputs, count=10, importance="supporting"))
    lanes = _lanes(exact, ("met",) * 9 + ("not_met",))
    strict = derive_baseline_locked_strict_equivalent_v1(
        exact.gradeable_baseline,
        lanes[0],
        lanes[1],
        exact.readiness_rubric,
    )
    requirement = compile_requirement_matrix_v1(exact, lanes)
    candidates = build_gap_candidate_inventory_v1(exact, lanes)
    first = tuple(_assessment(candidate) for candidate in candidates)
    second_raw = first[0].model_dump(mode="json")
    second_raw["owner_role"] = "outside_counsel"
    second = (type(first[0]).model_validate(second_raw), *first[1:])
    lane_1 = SafetyLaneResponseV1(
        lane=1,
        candidate_assessments=first,
        finding_proposals=(),
    )
    lane_2 = SafetyLaneResponseV1(
        lane=2,
        candidate_assessments=second,
        finding_proposals=(),
    )
    dispute = build_safety_disputes_v1(exact, lane_1, lane_2)[0]
    unresolved = SafetyRefereeDecisionV1(
        dispute_id=dispute.dispute_id,
        disposition="unresolved",
        rationale="The scoped evidence does not resolve the required owner.",
        evidence_refs=dispute.evidence_refs[:1],
    )
    safety = reconcile_safety_lanes_v1(
        exact,
        candidates,
        lane_1,
        lane_2,
        (unresolved,),
    )
    gap = compile_gap_follow_up_matrix_v1(exact, strict, candidates, safety)
    original = derive_delivery_readiness_v1(
        exact,
        strict,
        requirement,
        gap,
        safety,
        lane_1,
        lane_2,
    )
    assert original.delivery_readiness == "NOT_DELIVERABLE"
    assert "CRITICAL_DISCLOSURE_INVALID" in original.blocking_codes

    descriptor = safety.model_dump(mode="json", exclude={"safety_review_fingerprint"})
    descriptor["blocking_codes"] = []
    forged = ReconciledSafetyReviewV1.model_validate(
        {
            **descriptor,
            "safety_review_fingerprint": sha256_digest(canonical_json_bytes(descriptor)),
        }
    )
    with pytest.raises(ValueError, match="reconciled safety review is invalid"):
        derive_delivery_readiness_v1(
            exact,
            strict,
            requirement,
            gap,
            forged,
            lane_1,
            lane_2,
        )

    descriptor["blocking_codes"] = ["UNKNOWN_NONEMPTY_BLOCKER"]
    forged_unknown = ReconciledSafetyReviewV1.model_validate(
        {
            **descriptor,
            "safety_review_fingerprint": sha256_digest(canonical_json_bytes(descriptor)),
        }
    )
    with pytest.raises(ValueError, match="reconciled safety review is invalid"):
        derive_delivery_readiness_v1(
            exact,
            strict,
            requirement,
            gap,
            forged_unknown,
            lane_1,
            lane_2,
        )

    descriptor["blocking_codes"] = []
    descriptor["referee_decisions"] = []
    forged_removed_decision = ReconciledSafetyReviewV1.model_validate(
        {
            **descriptor,
            "safety_review_fingerprint": sha256_digest(canonical_json_bytes(descriptor)),
        }
    )
    removed_result = derive_delivery_readiness_v1(
        exact,
        strict,
        requirement,
        gap,
        forged_removed_decision,
        lane_1,
        lane_2,
    )
    assert removed_result.delivery_readiness == "NOT_DELIVERABLE"
    assert "CRITICAL_DISCLOSURE_INVALID" in removed_result.blocking_codes

    assessment_raw = safety.candidate_assessments[0].model_dump(mode="json")
    assessment_raw["blocking_code"] = None
    coordinated_assessment = type(safety.candidate_assessments[0]).model_validate(assessment_raw)
    coordinated_safety_descriptor = safety.model_dump(
        mode="json",
        exclude={"safety_review_fingerprint"},
    )
    coordinated_safety_descriptor.update(
        {
            "candidate_assessments": [coordinated_assessment.model_dump(mode="json")],
            "referee_decisions": [],
            "blocking_codes": [],
        }
    )
    coordinated_safety = ReconciledSafetyReviewV1.model_validate(
        {
            **coordinated_safety_descriptor,
            "safety_review_fingerprint": sha256_digest(
                canonical_json_bytes(coordinated_safety_descriptor)
            ),
        }
    )
    coordinated_rows: list[GapFollowUpRowV1] = []
    for row in gap.rows:
        row_descriptor = row.model_dump(
            mode="json",
            exclude={"row_fingerprint"},
        )
        row_descriptor["blocking_code"] = None
        coordinated_rows.append(
            GapFollowUpRowV1.model_validate(
                {
                    **row_descriptor,
                    "row_fingerprint": sha256_digest(canonical_json_bytes(row_descriptor)),
                }
            )
        )
    coordinated_gap_descriptor = gap.model_dump(
        mode="json",
        exclude={"matrix_fingerprint"},
    )
    coordinated_gap_descriptor["rows"] = [row.model_dump(mode="json") for row in coordinated_rows]
    coordinated_gap = GapFollowUpMatrixV1.model_validate(
        {
            **coordinated_gap_descriptor,
            "matrix_fingerprint": sha256_digest(canonical_json_bytes(coordinated_gap_descriptor)),
        }
    )
    coordinated_result = derive_delivery_readiness_v1(
        exact,
        strict,
        requirement,
        coordinated_gap,
        coordinated_safety,
        lane_1,
        lane_2,
    )
    assert coordinated_result.delivery_readiness == "NOT_DELIVERABLE"
    assert "INTEGRITY_OR_PROVENANCE_INVALID" in coordinated_result.blocking_codes


def test_resealed_gap_metadata_cannot_downgrade_critical_partial_shortfall(
    inputs: VerifiedReadinessInputsV1,
) -> None:
    exact = _with_requirements(inputs, count=10, importance="critical")
    lanes = _lanes(exact, ("met",) * 9 + ("partially_met",))
    strict, requirement, gap, safety, _ = _compile(exact, lanes)
    row = next(
        item for item in gap.rows if item.origin == "requirement" and item.subject_id == "REQ-0010"
    )
    row_descriptor = row.model_dump(mode="json", exclude={"row_fingerprint"})
    row_descriptor.update(
        {
            "kind": "arbitrary",
            "importance": "supporting",
            "importance_basis": ["implementation_detail"],
            "importance_rationale": "The point supplies useful implementation detail.",
            "lane_1_disposition": "met",
            "lane_2_disposition": "met",
            "conservative_disposition": "met",
        }
    )
    changed = GapFollowUpRowV1.model_validate(
        {
            **row_descriptor,
            "row_fingerprint": sha256_digest(canonical_json_bytes(row_descriptor)),
        }
    )
    matrix_descriptor = gap.model_dump(mode="json", exclude={"matrix_fingerprint"})
    matrix_descriptor["rows"] = [
        changed.model_dump(mode="json")
        if item.gap_id == row.gap_id
        else item.model_dump(mode="json")
        for item in gap.rows
    ]
    forged = GapFollowUpMatrixV1.model_validate(
        {
            **matrix_descriptor,
            "matrix_fingerprint": sha256_digest(canonical_json_bytes(matrix_descriptor)),
        }
    )

    result = derive_delivery_readiness_v1(
        exact,
        strict,
        requirement,
        forged,
        safety,
        *_matching_safety_lanes(safety),
    )

    assert result.delivery_readiness == "NOT_DELIVERABLE"
    assert "INTEGRITY_OR_PROVENANCE_INVALID" in result.blocking_codes


def test_resealed_gap_rows_cannot_swap_canonical_semantic_order(
    inputs: VerifiedReadinessInputsV1,
) -> None:
    exact = _clean_qualification(_with_requirements(inputs, count=10, importance="supporting"))
    lanes = _lanes(exact, ("met",) * 8 + ("partially_met",) * 2)
    strict, requirement, gap, safety, original = _compile(exact, lanes)
    assert original.delivery_readiness == "HIGH_ASSURANCE"
    assert len(gap.rows) == 2

    swapped: list[GapFollowUpRowV1] = []
    for index, row in enumerate(reversed(gap.rows), 1):
        descriptor = row.model_dump(mode="json", exclude={"row_fingerprint"})
        descriptor.update(
            {
                "gap_id": f"GAP-{index:04d}",
                "canonical_order": index - 1,
            }
        )
        swapped.append(
            GapFollowUpRowV1.model_validate(
                {
                    **descriptor,
                    "row_fingerprint": sha256_digest(canonical_json_bytes(descriptor)),
                }
            )
        )
    matrix_descriptor = gap.model_dump(
        mode="json",
        exclude={"matrix_fingerprint"},
    )
    matrix_descriptor["rows"] = [row.model_dump(mode="json") for row in swapped]
    forged = GapFollowUpMatrixV1.model_validate(
        {
            **matrix_descriptor,
            "matrix_fingerprint": sha256_digest(canonical_json_bytes(matrix_descriptor)),
        }
    )

    result = derive_delivery_readiness_v1(
        exact,
        strict,
        requirement,
        forged,
        safety,
        *_matching_safety_lanes(safety),
    )

    assert result.delivery_readiness == "NOT_DELIVERABLE"
    assert "INTEGRITY_OR_PROVENANCE_INVALID" in result.blocking_codes


def test_false_resolution_hidden_critical_and_missing_evidence_fail_closed(
    inputs: VerifiedReadinessInputsV1,
) -> None:
    exact = _with_requirements(inputs, count=10, importance="critical")
    lanes = _lanes(exact, ("met",) * 9 + ("partially_met",))
    strict, requirement, gap, safety, _ = _compile(exact, lanes)
    row = gap.rows[0]
    mutations = [
        {"status": "resolved"},
        {"visibility": "hidden"},
        {"owner_role": "research_operator"},
        {"evidence_refs": ()},
        {"evidence_refs": ("SOURCE-999999",)},
        {"evidence_refs": ("BASELINE-REQ-0001",)},
        {"why_unresolved": "more research needed"},
        {"follow_up_code": "VERIFY_PRIMARY_AUTHORITY"},
        {"report_passages": ()},
    ]
    expected = [
        "FALSE_RESOLUTION",
        "HIDDEN_MATERIAL_GAP",
        "CRITICAL_DISCLOSURE_INVALID",
        "GAP_RATIONALE_INVALID",
        "GAP_RATIONALE_INVALID",
        "GAP_RATIONALE_INVALID",
        "GAP_RATIONALE_INVALID",
        "MISSING_REQUIRED_FOLLOW_UP",
        "HIDDEN_MATERIAL_GAP",
    ]
    for update, code in zip(mutations, expected, strict=True):
        changed_raw = row.model_dump(mode="json")
        changed_raw.update(update)
        changed_raw["row_fingerprint"] = "0" * 64
        changed = GapFollowUpRowV1.model_validate(changed_raw)
        changed_descriptor = changed.model_dump(mode="json", exclude={"row_fingerprint"})
        changed = GapFollowUpRowV1.model_validate(
            {
                **changed_descriptor,
                "row_fingerprint": sha256_digest(canonical_json_bytes(changed_descriptor)),
            }
        )
        matrix_descriptor = gap.model_dump(mode="json", exclude={"matrix_fingerprint"})
        matrix_descriptor["rows"] = [
            changed.model_dump(mode="json"),
            *matrix_descriptor["rows"][1:],
        ]
        mutated = GapFollowUpMatrixV1.model_validate(
            {
                **matrix_descriptor,
                "matrix_fingerprint": sha256_digest(canonical_json_bytes(matrix_descriptor)),
            }
        )
        result = derive_delivery_readiness_v1(
            exact,
            strict,
            requirement,
            mutated,
            safety,
            *_matching_safety_lanes(safety),
        )
        assert result.delivery_readiness == "NOT_DELIVERABLE"
        assert code in result.blocking_codes


@pytest.mark.parametrize(
    "claim",
    [
        "The report is complete and accurate.",
        "This report comprehensively resolves every material issue and limitation.",
        "There are zero outstanding caveats or uncertainties.",
        "The analysis settles the entire universe of material questions and caveats.",
        "The treatment is definitive on every legally significant question.",
    ],
)
def test_completeness_claim_contradicted_by_visible_gap_fails_closed(
    inputs: VerifiedReadinessInputsV1,
    claim: str,
) -> None:
    exact = _with_requirements(inputs, count=10, importance="supporting")
    exact = _with_report(
        exact,
        f"{exact.report_text}\n\n{claim}",
    )
    lanes = _lanes(exact, ("met",) * 9 + ("partially_met",))
    *_, result = _compile(exact, lanes)

    assert result.delivery_readiness == "NOT_DELIVERABLE"
    assert "HIDDEN_MATERIAL_GAP" in result.blocking_codes


class _TupleSubclass(tuple[object, ...]):
    pass


class _GuardedIterator:
    def __init__(self) -> None:
        self.consumed = False

    def __iter__(self) -> _GuardedIterator:
        self.consumed = True
        return self

    def __next__(self) -> object:
        self.consumed = True
        raise StopIteration


class _FrozenWireTuple(tuple[object, ...]):
    __module__ = "regulatory_harvest.evaluation.attorney_readiness_models"

    def __new__(cls) -> _FrozenWireTuple:
        value = super().__new__(cls)
        value.consumed = False
        return value

    def __iter__(self):
        self.consumed = True
        raise RuntimeError("hostile iterator was consumed")


class _HostileRequirementGrade(RequirementGradeV2):
    consumed: ClassVar[list[str]] = []

    def __getattribute__(self, name: str):
        if name in type(self).model_fields:
            type(self).consumed.append(name)
            raise RuntimeError("hostile model attribute was consumed")
        return super().__getattribute__(name)


_HOSTILE_ENUM_CONSUMED: list[str] = []


class _HostileEnum(Enum):
    TRAP = "hostile"

    def __getattribute__(self, name: str):
        if name == "value":
            _HOSTILE_ENUM_CONSUMED.append(name)
            raise RuntimeError("hostile enum value was consumed")
        return super().__getattribute__(name)


def test_public_inventory_boundaries_reject_subclasses_and_iterators_without_consumption(
    inputs: VerifiedReadinessInputsV1,
) -> None:
    ordinary, contested = _fragments(
        inputs,
        lane=1,
        dispositions=("met",) * 7,
        contested=(("met", "met"),),
    )
    with pytest.raises(ValueError):
        aggregate_baseline_locked_grader_lane_v1(
            inputs,
            lane=1,
            ordinary_fragments=cast(object, _TupleSubclass(ordinary)),
            contested_grades=contested,
        )
    for unsafe_container in (list(ordinary), {"items": ordinary}):
        with pytest.raises(ValueError):
            aggregate_baseline_locked_grader_lane_v1(
                inputs,
                lane=1,
                ordinary_fragments=cast(object, unsafe_container),
                contested_grades=contested,
            )
    guarded = _GuardedIterator()
    with pytest.raises(ValueError):
        aggregate_baseline_locked_grader_lane_v1(
            inputs,
            lane=1,
            ordinary_fragments=cast(object, guarded),
            contested_grades=contested,
        )
    assert guarded.consumed is False


def test_constructed_cycles_depth_nodes_and_bytes_fail_before_compilation(
    inputs: VerifiedReadinessInputsV1,
) -> None:
    ordinary, contested = _fragments(
        inputs,
        lane=1,
        dispositions=("met",) * 7,
        contested=(("met", "met"),),
    )
    spoofed = _FrozenWireTuple()
    raw = ordinary[0].model_dump(mode="python")
    raw["requirement_grades"] = spoofed
    forged_spoof = BaselineLockedGradeFragmentV1.model_construct(**raw)
    with pytest.raises(ValueError, match="grade fragments are invalid"):
        aggregate_baseline_locked_grader_lane_v1(
            inputs,
            lane=1,
            ordinary_fragments=(forged_spoof, *ordinary[1:]),
            contested_grades=contested,
        )
    assert spoofed.consumed is False

    grade_raw = ordinary[0].requirement_grades[0].model_dump(mode="python")
    hostile_grade = _HostileRequirementGrade.model_construct(**grade_raw)
    raw = ordinary[0].model_dump(mode="python")
    raw["requirement_grades"] = (
        hostile_grade,
        *ordinary[0].requirement_grades[1:],
    )
    forged_hostile = BaselineLockedGradeFragmentV1.model_construct(**raw)
    _HostileRequirementGrade.consumed.clear()
    with pytest.raises(ValueError, match="grade fragments are invalid"):
        aggregate_baseline_locked_grader_lane_v1(
            inputs,
            lane=1,
            ordinary_fragments=(forged_hostile, *ordinary[1:]),
            contested_grades=contested,
        )
    assert _HostileRequirementGrade.consumed == []

    raw = ordinary[0].model_dump(mode="python")
    raw["rationale"] = _HostileEnum.TRAP
    forged_enum = BaselineLockedGradeFragmentV1.model_construct(**raw)
    _HOSTILE_ENUM_CONSUMED.clear()
    with pytest.raises(ValueError, match="grade fragments are invalid"):
        aggregate_baseline_locked_grader_lane_v1(
            inputs,
            lane=1,
            ordinary_fragments=(forged_enum, *ordinary[1:]),
            contested_grades=contested,
        )
    assert _HOSTILE_ENUM_CONSUMED == []

    cycle: list[object] = []
    cycle.append(cycle)
    raw = ordinary[0].model_dump(mode="python")
    raw["requirement_grades"] = cycle
    forged_cycle = BaselineLockedGradeFragmentV1.model_construct(**raw)
    with pytest.raises(ValueError, match="grade fragments are invalid"):
        aggregate_baseline_locked_grader_lane_v1(
            inputs,
            lane=1,
            ordinary_fragments=(forged_cycle, *ordinary[1:]),
            contested_grades=contested,
        )

    nested: object = "leaf"
    for _ in range(80):
        nested = (nested,)
    raw = ordinary[0].model_dump(mode="python")
    raw["requirement_grades"] = nested
    forged_depth = BaselineLockedGradeFragmentV1.model_construct(**raw)
    with pytest.raises(ValueError, match="grade fragments are invalid"):
        aggregate_baseline_locked_grader_lane_v1(
            inputs,
            lane=1,
            ordinary_fragments=(forged_depth, *ordinary[1:]),
            contested_grades=contested,
        )

    raw = ordinary[0].model_dump(mode="python")
    raw["requirement_grades"] = tuple("x" for _ in range(100_001))
    forged_nodes = BaselineLockedGradeFragmentV1.model_construct(**raw)
    with pytest.raises(ValueError, match="grade fragments are invalid"):
        aggregate_baseline_locked_grader_lane_v1(
            inputs,
            lane=1,
            ordinary_fragments=(forged_nodes, *ordinary[1:]),
            contested_grades=contested,
        )

    raw = ordinary[0].model_dump(mode="python")
    raw["rationale"] = "x" * (16 * 1024 * 1024 + 1)
    forged_bytes = BaselineLockedGradeFragmentV1.model_construct(**raw)
    with pytest.raises(ValueError, match="grade fragments are invalid"):
        aggregate_baseline_locked_grader_lane_v1(
            inputs,
            lane=1,
            ordinary_fragments=(forged_bytes, *ordinary[1:]),
            contested_grades=contested,
        )
