"""Bounded compilation of fresh delivery-readiness evaluator drafts."""

from __future__ import annotations

import copy
import json
from collections import deque
from pathlib import Path
from typing import cast

import pytest
from test_attorney_readiness_requests import (
    _assessment,
    _finding,
    _grader_lanes,
)
from test_attorney_readiness_requests import (
    inputs as _request_inputs_fixture,
)

from regulatory_harvest.evaluation import attorney_readiness_drafts as drafts_module
from regulatory_harvest.evaluation import attorney_readiness_requests as requests_module
from regulatory_harvest.evaluation.attorney_readiness_drafts import (
    CompiledReadinessDraftV1,
    NeedsReadinessClarificationV1,
    ReadinessDraftReasonCodeV1,
    ReadinessEngineDefectV1,
    ReadinessEvaluatorDraftPromptV1,
    ReadinessEvaluatorProvenanceV1,
    compile_readiness_draft_v1,
)
from regulatory_harvest.evaluation.attorney_readiness_inputs import VerifiedReadinessInputsV1
from regulatory_harvest.evaluation.attorney_readiness_models import (
    BaselineLockedContestedGradeV1,
    BaselineLockedGradeFragmentV1,
    ReadinessEvaluatorRequestV1,
    SafetyLaneResponseV1,
    SafetyRefereeDecisionV1,
)
from regulatory_harvest.evaluation.attorney_readiness_requests import (
    build_baseline_locked_contested_grade_request_v1,
    build_baseline_locked_grade_batches_v1,
    build_baseline_locked_grade_request_v1,
    build_gap_candidate_inventory_v1,
    build_safety_disputes_v1,
    build_safety_lane_request_v1,
    build_safety_referee_request_v1,
)
from regulatory_harvest.storage import canonical_json_bytes, sha256_digest


@pytest.fixture
def inputs(tmp_path: Path) -> VerifiedReadinessInputsV1:
    return _request_inputs_fixture.__wrapped__(tmp_path)


@pytest.fixture
def ordinary_request(inputs: VerifiedReadinessInputsV1) -> ReadinessEvaluatorRequestV1:
    batch = build_baseline_locked_grade_batches_v1(inputs.gradeable_baseline, lane=1)[0]
    return build_baseline_locked_grade_request_v1(inputs, batch)


@pytest.fixture
def contested_request(inputs: VerifiedReadinessInputsV1) -> ReadinessEvaluatorRequestV1:
    return build_baseline_locked_contested_grade_request_v1(
        inputs,
        lane=2,
        contested_requirement_id="CONT-0001",
    )


@pytest.fixture
def safety_request(inputs: VerifiedReadinessInputsV1) -> ReadinessEvaluatorRequestV1:
    lanes = _grader_lanes(inputs)
    candidates = build_gap_candidate_inventory_v1(inputs, lanes)
    return build_safety_lane_request_v1(inputs, lanes, candidates, lane=1)


@pytest.fixture
def referee_request(inputs: VerifiedReadinessInputsV1) -> ReadinessEvaluatorRequestV1:
    lanes = _grader_lanes(inputs)
    candidates = build_gap_candidate_inventory_v1(inputs, lanes)
    first_assessments = tuple(_assessment(item) for item in candidates)
    second_assessments = tuple(_assessment(item) for item in candidates)
    first = SafetyLaneResponseV1(
        lane=1,
        candidate_assessments=first_assessments,
        finding_proposals=(_finding(rationale="The exact source does not support the claim."),),
    )
    changed = type(second_assessments[0]).model_validate(
        {
            **second_assessments[0].model_dump(mode="json"),
            "owner_role": "outside_counsel",
        }
    )
    second = SafetyLaneResponseV1(
        lane=2,
        candidate_assessments=(changed, *second_assessments[1:]),
        finding_proposals=(_finding(rationale="The exact source does not support the claim."),),
    )
    dispute = build_safety_disputes_v1(inputs, first, second)[0]
    return build_safety_referee_request_v1(inputs, dispute)


def _provenance() -> ReadinessEvaluatorProvenanceV1:
    return ReadinessEvaluatorProvenanceV1(
        provider_name="public-test-provider",
        model_name="public-test-model",
        judge_isolation="scripted_fixture",
    )


def _passage(request: ReadinessEvaluatorRequestV1) -> str:
    allowlist = cast(tuple[str, ...], request.payload["report_passage_allowlist"])
    for value in allowlist:
        if value == "The report addresses the notice duty.":
            return value
    return allowlist[0]


def _ordinary_draft(request: ReadinessEvaluatorRequestV1) -> dict[str, object]:
    requirements = cast(tuple[dict[str, object], ...], request.payload["requirements"])
    return {
        "requirement_grades": [
            {
                "requirement_id": item["requirement"]["requirement_id"],
                "disposition": "partially_met",
                "report_passages": [_passage(request)],
                "rationale": "The exact passage addresses part of the requirement.",
                "omission": "The report does not address the remaining implementation detail.",
            }
            for item in requirements
        ],
        "rationale": "Each controller-issued requirement was graded against the exact report.",
    }


def _contested_draft(request: ReadinessEvaluatorRequestV1) -> dict[str, object]:
    return {
        "contested_requirement_id": request.payload["contested_requirement"][
            "contested_requirement"
        ]["contested_requirement_id"],
        "reviewer_alternative_disposition": "partially_met",
        "auditor_alternative_disposition": "met",
        "reviewer_report_passages": [_passage(request)],
        "auditor_report_passages": [_passage(request)],
        "reviewer_rationale": "The reviewer alternative is only partly addressed.",
        "auditor_rationale": "The auditor alternative is addressed by the exact passage.",
        "ambiguity_disposition": "acknowledged",
        "rationale": "The report acknowledges both sealed alternatives.",
    }


def _assessment_draft(candidate: dict[str, object]) -> dict[str, object]:
    refs = cast(tuple[str, ...], candidate["evidence_refs"])
    importance = candidate["importance"]
    origin = candidate["origin"]
    if origin == "prerequisite":
        subject_id = cast(str, candidate["subject_id"])
        if subject_id.startswith("CURRENTNESS:"):
            rationale_kind = "CURRENTNESS_NOT_ESTABLISHED"
            follow_up = "CONFIRM_CURRENTNESS"
            evidence_ref = next(ref for ref in refs if ref.startswith("PREREQUISITE-CURRENTNESS-"))
        elif subject_id.startswith("LANGUAGE:"):
            rationale_kind = "LANGUAGE_LIMITATION"
            follow_up = "RESOLVE_LANGUAGE_LIMITATION"
            evidence_ref = next(ref for ref in refs if ref.startswith("PREREQUISITE-LANGUAGE-"))
        elif subject_id == "CLIENT_FACTS":
            rationale_kind = "APPLICABILITY_FACT_MISSING"
            follow_up = "RESOLVE_APPLICABILITY_FACT"
            evidence_ref = "PREREQUISITE-CLIENT-FACTS"
        else:
            rationale_kind = "SOURCE_ABSENT"
            follow_up = "VERIFY_PRIMARY_AUTHORITY"
            evidence_ref = next(ref for ref in refs if ref.startswith("SOURCE-"))
    elif origin == "contested_requirement":
        rationale_kind = "CONTESTED_INTERPRETATION"
        follow_up = "RESOLVE_CONTESTED_INTERPRETATION"
        evidence_ref = refs[0]
    elif origin == "baseline_gap":
        rationale_kind = "SOURCE_ABSENT"
        follow_up = "VERIFY_PRIMARY_AUTHORITY"
        evidence_ref = next(ref for ref in refs if ref.startswith("SOURCE-"))
    else:
        rationale_kind = "REPORT_PARTIAL_TREATMENT"
        follow_up = "EXPAND_REQUIREMENT_ANALYSIS"
        evidence_ref = refs[0]
    return {
        "candidate_id": candidate["candidate_id"],
        "shortfall_description": "The report does not complete this exact scoped treatment.",
        "rationale_kind": rationale_kind,
        "why_unresolved": "The cited evidence does not establish the missing legal treatment.",
        "why_it_matters": (
            f"legal_conclusion: {evidence_ref} leaves the scoped answer incomplete."
        ),
        "evidence_refs": [evidence_ref],
        "report_passages": ["Currentness remains to be confirmed."],
        "disclosure_location": "Limitations",
        "visibility": "prominent" if importance == "critical" else "visible",
        "blocking_code": None,
        "follow_up_code": follow_up,
        "resolution_test": "Obtain official evidence and verify the complete legal treatment.",
        "owner_role": "reviewing_attorney",
    }


def _finding_draft() -> dict[str, object]:
    return {
        "finding_kind": "MATERIAL_UNSUPPORTED_ASSERTION",
        "subject_id": "report-assertion-1",
        "report_passages": ["The report partially addresses operator identification."],
        "shortfall_description": "The report assertion exceeds the cited authority.",
        "rationale_kind": "UNSUPPORTED_ASSERTION",
        "why_unresolved": "The cited source does not support the report assertion.",
        "why_it_matters": ("legal_conclusion: SOURCE-000001 could change the scoped answer."),
        "evidence_refs": ["SOURCE-000001", "BASELINE-REQ-0003"],
        "disclosure_location": "Limitations",
        "visibility": "prominent",
        "blocking_code": "MATERIAL_UNSUPPORTED_ASSERTION",
        "follow_up_code": "CORRECT_UNSUPPORTED_ASSERTION",
        "resolution_test": "Correct the report or obtain exact supporting evidence.",
        "owner_role": "reviewing_attorney",
    }


def _safety_draft(request: ReadinessEvaluatorRequestV1) -> dict[str, object]:
    candidates = cast(tuple[dict[str, object], ...], request.payload["gap_candidates"])
    return {
        "candidate_assessments": [_assessment_draft(item) for item in candidates],
        "finding_proposals": [_finding_draft()],
    }


def _referee_draft(request: ReadinessEvaluatorRequestV1) -> dict[str, object]:
    refs = cast(tuple[str, ...], request.payload["evidence_refs"])
    return {
        "dispute_id": request.payload["dispute_id"],
        "disposition": "lane_2",
        "rationale": "The scoped evidence supports the second lane choice.",
        "evidence_refs": list(refs[:1]),
    }


def _assert_clarification(
    outcome: object,
    reason: ReadinessDraftReasonCodeV1,
) -> None:
    assert isinstance(outcome, NeedsReadinessClarificationV1)
    assert reason in outcome.reason_codes


def test_prompt_is_request_local_and_second_attempt_carries_codes(
    ordinary_request: ReadinessEvaluatorRequestV1,
) -> None:
    first = ReadinessEvaluatorDraftPromptV1(request=ordinary_request, attempt=1)
    second = ReadinessEvaluatorDraftPromptV1(
        request=ordinary_request,
        attempt=2,
        clarification_codes=(ReadinessDraftReasonCodeV1.RATIONALE_GENERIC,),
    )
    assert first.clarification_codes == ()
    assert second.attempt == 2
    with pytest.raises(ValueError):
        ReadinessEvaluatorDraftPromptV1(
            request=ordinary_request,
            attempt=1,
            clarification_codes=(ReadinessDraftReasonCodeV1.RATIONALE_GENERIC,),
        )
    with pytest.raises(ValueError):
        ReadinessEvaluatorDraftPromptV1(request=ordinary_request, attempt=True)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        ReadinessEvaluatorDraftPromptV1(request=ordinary_request, attempt=2)


def test_compiles_all_four_operation_classes_with_controller_owned_bindings(
    ordinary_request: ReadinessEvaluatorRequestV1,
    contested_request: ReadinessEvaluatorRequestV1,
    safety_request: ReadinessEvaluatorRequestV1,
    referee_request: ReadinessEvaluatorRequestV1,
) -> None:
    ordinary = compile_readiness_draft_v1(
        ordinary_request, _ordinary_draft(ordinary_request), _provenance()
    )
    contested = compile_readiness_draft_v1(
        contested_request, _contested_draft(contested_request), _provenance()
    )
    safety = compile_readiness_draft_v1(
        safety_request, _safety_draft(safety_request), _provenance()
    )
    referee = compile_readiness_draft_v1(
        referee_request, _referee_draft(referee_request), _provenance()
    )
    assert isinstance(ordinary, CompiledReadinessDraftV1)
    assert isinstance(contested, CompiledReadinessDraftV1)
    assert isinstance(safety, CompiledReadinessDraftV1)
    assert isinstance(referee, CompiledReadinessDraftV1)

    ordinary_payload = BaselineLockedGradeFragmentV1.model_validate(ordinary.response.payload)
    contested_payload = BaselineLockedContestedGradeV1.model_validate(contested.response.payload)
    safety_payload = SafetyLaneResponseV1.model_validate(safety.response.payload)
    referee_payload = SafetyRefereeDecisionV1.model_validate(referee.response.payload)
    assert ordinary_payload.lane == ordinary_request.payload["lane"] == 1
    assert ordinary_payload.batch_ref == ordinary_request.payload["batch_ref"]
    ordinary_descriptor = ordinary_payload.model_dump(mode="json", exclude={"fragment_fingerprint"})
    assert ordinary_payload.fragment_fingerprint == sha256_digest(
        canonical_json_bytes(ordinary_descriptor)
    )
    assert contested_payload.lane == contested_request.payload["lane"] == 2
    assert contested_payload.contested_requirement_id == "CONT-0001"
    assert safety_payload.lane == safety_request.payload["lane"] == 1
    assert referee_payload.dispute_id == referee_request.payload["dispute_id"]
    assert ordinary.response.request_fingerprint == ordinary_request.request_fingerprint
    assert ordinary.response.provider_name == "public-test-provider"


@pytest.mark.parametrize(
    "forbidden,value",
    [
        ("gap_id", "GAP-0001"),
        ("canonical_order", 0),
        ("conservative_disposition", "met"),
        ("row_fingerprint", "0" * 64),
        ("delivery_readiness", "HIGH_ASSURANCE"),
        ("baseline_locked_strict_equivalent_disposition", "PASS"),
        ("historical_v22_strict_disposition", "FAIL"),
        ("status", "resolved"),
    ],
)
def test_evaluator_cannot_author_controller_outcomes(
    safety_request: ReadinessEvaluatorRequestV1,
    forbidden: str,
    value: object,
) -> None:
    draft = _safety_draft(safety_request)
    cast(dict[str, object], draft["candidate_assessments"][0])[forbidden] = value
    _assert_clarification(
        compile_readiness_draft_v1(safety_request, draft, _provenance()),
        ReadinessDraftReasonCodeV1.DRAFT_INVALID,
    )


def test_ordinary_grade_requires_exact_ordered_request_coverage(
    ordinary_request: ReadinessEvaluatorRequestV1,
) -> None:
    valid = _ordinary_draft(ordinary_request)
    missing = copy.deepcopy(valid)
    cast(list[object], missing["requirement_grades"]).pop()
    reordered = copy.deepcopy(valid)
    cast(list[object], reordered["requirement_grades"]).reverse()
    unknown = copy.deepcopy(valid)
    cast(dict[str, object], unknown["requirement_grades"][0])["requirement_id"] = "REQ-9999"
    for draft in (missing, reordered, unknown):
        _assert_clarification(
            compile_readiness_draft_v1(ordinary_request, draft, _provenance()),
            ReadinessDraftReasonCodeV1.COVERAGE_INVALID,
        )


def test_identical_duplicates_are_removed_but_conflicts_are_refused(
    ordinary_request: ReadinessEvaluatorRequestV1,
) -> None:
    duplicate = _ordinary_draft(ordinary_request)
    grades = cast(list[dict[str, object]], duplicate["requirement_grades"])
    grades.insert(1, copy.deepcopy(grades[0]))
    compiled = compile_readiness_draft_v1(ordinary_request, duplicate, _provenance())
    assert isinstance(compiled, CompiledReadinessDraftV1)
    assert compiled.normalization_codes == ("DRAFT_NORMALIZED_DUPLICATES",)

    conflict = _ordinary_draft(ordinary_request)
    conflict_grades = cast(list[dict[str, object]], conflict["requirement_grades"])
    changed = copy.deepcopy(conflict_grades[0])
    changed["rationale"] = "A conflicting rationale for the same controller requirement."
    conflict_grades.insert(1, changed)
    _assert_clarification(
        compile_readiness_draft_v1(ordinary_request, conflict, _provenance()),
        ReadinessDraftReasonCodeV1.CONFLICTING_ITEMS,
    )


def test_report_passages_resolve_only_by_exact_request_local_bytes(
    ordinary_request: ReadinessEvaluatorRequestV1,
) -> None:
    exact = _ordinary_draft(ordinary_request)
    exact_passage = cast(dict[str, object], exact["requirement_grades"][0])["report_passages"][0]
    compiled = compile_readiness_draft_v1(ordinary_request, exact, _provenance())
    assert isinstance(compiled, CompiledReadinessDraftV1)
    payload = BaselineLockedGradeFragmentV1.model_validate(compiled.response.payload)
    assert payload.requirement_grades[0].report_passages == [exact_passage]

    for mutation in (
        str(exact_passage).upper(),
        str(exact_passage).replace(".", "!"),
        f" {exact_passage}",
        str(exact_passage).replace("notice", "notic\N{COMBINING ACUTE ACCENT}e"),
    ):
        changed = _ordinary_draft(ordinary_request)
        cast(dict[str, object], changed["requirement_grades"][0])["report_passages"] = [mutation]
        _assert_clarification(
            compile_readiness_draft_v1(ordinary_request, changed, _provenance()),
            ReadinessDraftReasonCodeV1.EVIDENCE_NOT_FOUND,
        )


def test_duplicate_refs_and_passages_are_removed_without_mutating_text(
    safety_request: ReadinessEvaluatorRequestV1,
) -> None:
    draft = _safety_draft(safety_request)
    assessment = cast(dict[str, object], draft["candidate_assessments"][0])
    ref = cast(list[str], assessment["evidence_refs"])[0]
    passage = cast(list[str], assessment["report_passages"])[0]
    assessment["evidence_refs"] = [ref, ref]
    assessment["report_passages"] = [passage, passage]
    compiled = compile_readiness_draft_v1(safety_request, draft, _provenance())
    assert isinstance(compiled, CompiledReadinessDraftV1)
    assert compiled.normalization_codes == ("DRAFT_NORMALIZED_DUPLICATES",)
    response = SafetyLaneResponseV1.model_validate(compiled.response.payload)
    assert response.candidate_assessments[0].evidence_refs == (ref,)
    assert response.candidate_assessments[0].report_passages == (passage,)


@pytest.mark.parametrize(
    "generic",
    [
        "more research needed",
        "More research is needed.",
        "insufficient information",
        "requirement partially met",
        "partially_met",
        "0.5",
    ],
)
@pytest.mark.parametrize(
    "field",
    ["shortfall_description", "why_unresolved", "why_it_matters", "resolution_test"],
)
def test_every_rationale_component_refuses_generic_only_text(
    safety_request: ReadinessEvaluatorRequestV1,
    field: str,
    generic: str,
) -> None:
    draft = _safety_draft(safety_request)
    cast(dict[str, object], draft["candidate_assessments"][0])[field] = generic
    _assert_clarification(
        compile_readiness_draft_v1(safety_request, draft, _provenance()),
        ReadinessDraftReasonCodeV1.RATIONALE_GENERIC,
    )


@pytest.mark.parametrize(
    "field",
    ["shortfall_description", "why_unresolved", "why_it_matters", "resolution_test"],
)
@pytest.mark.parametrize("missing", [None, "", "   "])
def test_every_rationale_component_is_required_without_controller_authorship(
    safety_request: ReadinessEvaluatorRequestV1,
    field: str,
    missing: str | None,
) -> None:
    draft = _safety_draft(safety_request)
    assessment = cast(dict[str, object], draft["candidate_assessments"][0])
    if missing is None:
        assessment.pop(field)
    else:
        assessment[field] = missing
    _assert_clarification(
        compile_readiness_draft_v1(safety_request, draft, _provenance()),
        ReadinessDraftReasonCodeV1.RATIONALE_MISSING,
    )


def test_accepted_rationale_bytes_are_preserved_exactly(
    safety_request: ReadinessEvaluatorRequestV1,
) -> None:
    draft = _safety_draft(safety_request)
    assessment = cast(dict[str, object], draft["candidate_assessments"][0])
    exact = "The cited evidence does not establish the missing legal treatment — yet."
    assessment["why_unresolved"] = exact
    compiled = compile_readiness_draft_v1(safety_request, draft, _provenance())
    assert isinstance(compiled, CompiledReadinessDraftV1)
    response = SafetyLaneResponseV1.model_validate(compiled.response.payload)
    assert response.candidate_assessments[0].why_unresolved.encode("utf-8") == exact.encode("utf-8")


@pytest.mark.parametrize(
    "why_it_matters,reason",
    [
        (
            "SOURCE-000001 leaves the answer incomplete.",
            ReadinessDraftReasonCodeV1.RATIONALE_CONSEQUENCE_MISSING,
        ),
        (
            "legal_conclusion: the answer remains incomplete.",
            ReadinessDraftReasonCodeV1.RATIONALE_EVIDENCE_UNBOUND,
        ),
        (
            "legal_conclusion: SOURCE-999999 changes the answer.",
            ReadinessDraftReasonCodeV1.REFERENCE_UNKNOWN,
        ),
    ],
)
def test_why_it_matters_binds_fixed_consequence_and_exact_evidence(
    safety_request: ReadinessEvaluatorRequestV1,
    why_it_matters: str,
    reason: ReadinessDraftReasonCodeV1,
) -> None:
    draft = _safety_draft(safety_request)
    cast(dict[str, object], draft["candidate_assessments"][0])["why_it_matters"] = why_it_matters
    _assert_clarification(
        compile_readiness_draft_v1(safety_request, draft, _provenance()),
        reason,
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("shortfall_description", "The issue remains open."),
        ("why_unresolved", "The issue remains open."),
        ("why_it_matters", "legal_conclusion: SOURCE-000001."),
    ],
)
def test_rationale_components_require_concrete_substance(
    safety_request: ReadinessEvaluatorRequestV1,
    field: str,
    value: str,
) -> None:
    draft = _safety_draft(safety_request)
    cast(dict[str, object], draft["candidate_assessments"][0])[field] = value
    _assert_clarification(
        compile_readiness_draft_v1(safety_request, draft, _provenance()),
        ReadinessDraftReasonCodeV1.RATIONALE_GENERIC,
    )


@pytest.mark.parametrize(
    "resolution",
    [
        "The issue may eventually be resolved.",
        "Do more work.",
        "Official evidence exists.",
        "Correctness matters.",
    ],
)
def test_resolution_test_requires_an_observable_closing_condition(
    safety_request: ReadinessEvaluatorRequestV1,
    resolution: str,
) -> None:
    draft = _safety_draft(safety_request)
    cast(dict[str, object], draft["candidate_assessments"][0])["resolution_test"] = resolution
    _assert_clarification(
        compile_readiness_draft_v1(safety_request, draft, _provenance()),
        ReadinessDraftReasonCodeV1.RESOLUTION_TEST_INVALID,
    )


@pytest.mark.parametrize(
    "field,value,reason",
    [
        (
            "visibility",
            "visible",
            ReadinessDraftReasonCodeV1.CRITICAL_VISIBILITY_INVALID,
        ),
        (
            "owner_role",
            "research_operator",
            ReadinessDraftReasonCodeV1.CRITICAL_OWNER_INVALID,
        ),
    ],
)
def test_critical_candidates_require_prominent_attorney_ownership(
    safety_request: ReadinessEvaluatorRequestV1,
    field: str,
    value: str,
    reason: ReadinessDraftReasonCodeV1,
) -> None:
    draft = _safety_draft(safety_request)
    candidates = cast(tuple[dict[str, object], ...], safety_request.payload["gap_candidates"])
    index = next(i for i, item in enumerate(candidates) if item["importance"] == "critical")
    cast(dict[str, object], draft["candidate_assessments"][index])[field] = value
    _assert_clarification(
        compile_readiness_draft_v1(safety_request, draft, _provenance()),
        reason,
    )


def test_report_content_finding_requires_allowlisted_passage(
    safety_request: ReadinessEvaluatorRequestV1,
) -> None:
    draft = _safety_draft(safety_request)
    cast(dict[str, object], draft["finding_proposals"][0])["report_passages"] = []
    _assert_clarification(
        compile_readiness_draft_v1(safety_request, draft, _provenance()),
        ReadinessDraftReasonCodeV1.REPORT_PASSAGE_REQUIRED,
    )


def test_finding_rationale_uses_the_same_semantic_evidence_binding(
    safety_request: ReadinessEvaluatorRequestV1,
) -> None:
    draft = _safety_draft(safety_request)
    finding = cast(dict[str, object], draft["finding_proposals"][0])
    finding["rationale_kind"] = "LANGUAGE_LIMITATION"
    finding["follow_up_code"] = "RESOLVE_LANGUAGE_LIMITATION"
    _assert_clarification(
        compile_readiness_draft_v1(safety_request, draft, _provenance()),
        ReadinessDraftReasonCodeV1.RATIONALE_EVIDENCE_UNBOUND,
    )


def test_known_but_unrelated_candidate_evidence_is_refused(
    safety_request: ReadinessEvaluatorRequestV1,
) -> None:
    draft = _safety_draft(safety_request)
    candidates = cast(tuple[dict[str, object], ...], safety_request.payload["gap_candidates"])
    first_refs = set(cast(tuple[str, ...], candidates[0]["evidence_refs"]))
    handles = cast(tuple[dict[str, object], ...], safety_request.payload["evidence_handles"])
    unrelated = next(
        cast(str, item["evidence_ref"])
        for item in handles
        if item["evidence_ref"] not in first_refs
    )
    assessment = cast(dict[str, object], draft["candidate_assessments"][0])
    assessment["evidence_refs"] = [unrelated]
    assessment["why_it_matters"] = (
        f"legal_conclusion: {unrelated} leaves the scoped answer incomplete."
    )
    _assert_clarification(
        compile_readiness_draft_v1(safety_request, draft, _provenance()),
        ReadinessDraftReasonCodeV1.RATIONALE_EVIDENCE_UNBOUND,
    )


def test_semantic_evidence_and_candidate_membership_cannot_be_split_across_refs(
    safety_request: ReadinessEvaluatorRequestV1,
) -> None:
    draft = _safety_draft(safety_request)
    candidates = cast(tuple[dict[str, object], ...], safety_request.payload["gap_candidates"])
    candidate_refs = cast(tuple[str, ...], candidates[0]["evidence_refs"])
    local_ref = next(ref for ref in candidate_refs if ref.startswith("BASELINE-"))
    handles = cast(tuple[dict[str, object], ...], safety_request.payload["evidence_handles"])
    foreign_ref = next(
        cast(str, item["evidence_ref"])
        for item in handles
        if cast(str, item["evidence_ref"]).startswith("PREREQUISITE-CURRENTNESS-")
        and item["evidence_ref"] not in candidate_refs
    )
    assessment = cast(dict[str, object], draft["candidate_assessments"][0])
    assessment["rationale_kind"] = "CURRENTNESS_NOT_ESTABLISHED"
    assessment["follow_up_code"] = "CONFIRM_CURRENTNESS"
    assessment["evidence_refs"] = [local_ref, foreign_ref]
    assessment["why_it_matters"] = (
        f"legal_conclusion: {local_ref} leaves the scoped answer incomplete."
    )
    _assert_clarification(
        compile_readiness_draft_v1(safety_request, draft, _provenance()),
        ReadinessDraftReasonCodeV1.RATIONALE_EVIDENCE_UNBOUND,
    )


def test_why_it_matters_must_cite_the_exact_semantic_evidence_handle(
    safety_request: ReadinessEvaluatorRequestV1,
) -> None:
    draft = _safety_draft(safety_request)
    candidates = cast(tuple[dict[str, object], ...], safety_request.payload["gap_candidates"])
    candidate_refs = cast(tuple[str, ...], candidates[0]["evidence_refs"])
    baseline_ref = next(ref for ref in candidate_refs if ref.startswith("BASELINE-"))
    source_ref = next(ref for ref in candidate_refs if ref.startswith("SOURCE-"))
    assessment = cast(dict[str, object], draft["candidate_assessments"][0])
    assessment["rationale_kind"] = "SOURCE_ABSENT"
    assessment["follow_up_code"] = "VERIFY_PRIMARY_AUTHORITY"
    assessment["evidence_refs"] = [baseline_ref, source_ref]
    assessment["why_it_matters"] = (
        f"legal_conclusion: {baseline_ref} leaves the scoped answer incomplete."
    )
    _assert_clarification(
        compile_readiness_draft_v1(safety_request, draft, _provenance()),
        ReadinessDraftReasonCodeV1.RATIONALE_EVIDENCE_UNBOUND,
    )


@pytest.mark.parametrize(
    "rationale_kind,follow_up_code,candidate_origin",
    [
        ("SOURCE_ABSENT", "VERIFY_PRIMARY_AUTHORITY", "requirement"),
        ("CURRENTNESS_NOT_ESTABLISHED", "CONFIRM_CURRENTNESS", "baseline_gap"),
        ("LANGUAGE_LIMITATION", "RESOLVE_LANGUAGE_LIMITATION", "baseline_gap"),
    ],
)
def test_source_currentness_and_language_assertions_require_exact_evidence_kind(
    safety_request: ReadinessEvaluatorRequestV1,
    rationale_kind: str,
    follow_up_code: str,
    candidate_origin: str,
) -> None:
    draft = _safety_draft(safety_request)
    candidates = cast(tuple[dict[str, object], ...], safety_request.payload["gap_candidates"])
    index = next(i for i, item in enumerate(candidates) if item["origin"] == candidate_origin)
    assessment = cast(dict[str, object], draft["candidate_assessments"][index])
    evidence_ref = cast(list[str], assessment["evidence_refs"])[0]
    assessment["rationale_kind"] = rationale_kind
    assessment["follow_up_code"] = follow_up_code
    assessment["why_it_matters"] = (
        f"legal_conclusion: {evidence_ref} leaves the scoped answer incomplete."
    )
    _assert_clarification(
        compile_readiness_draft_v1(safety_request, draft, _provenance()),
        ReadinessDraftReasonCodeV1.RATIONALE_EVIDENCE_UNBOUND,
    )


@pytest.mark.parametrize(
    "field,value,reason",
    [
        (
            "blocking_code",
            "PRIVATE_OR_UNKNOWN_BLOCKER",
            ReadinessDraftReasonCodeV1.REFERENCE_UNKNOWN,
        ),
        (
            "visibility",
            "visible",
            ReadinessDraftReasonCodeV1.CRITICAL_VISIBILITY_INVALID,
        ),
        (
            "owner_role",
            "research_operator",
            ReadinessDraftReasonCodeV1.CRITICAL_OWNER_INVALID,
        ),
    ],
)
def test_blocking_findings_use_allowlisted_codes_and_prominent_attorney_ownership(
    safety_request: ReadinessEvaluatorRequestV1,
    field: str,
    value: str,
    reason: ReadinessDraftReasonCodeV1,
) -> None:
    draft = _safety_draft(safety_request)
    cast(dict[str, object], draft["finding_proposals"][0])[field] = value
    _assert_clarification(
        compile_readiness_draft_v1(safety_request, draft, _provenance()),
        reason,
    )


def test_safety_candidate_coverage_and_finding_identity_are_deterministic(
    safety_request: ReadinessEvaluatorRequestV1,
) -> None:
    missing = _safety_draft(safety_request)
    cast(list[object], missing["candidate_assessments"]).pop()
    _assert_clarification(
        compile_readiness_draft_v1(safety_request, missing, _provenance()),
        ReadinessDraftReasonCodeV1.COVERAGE_INVALID,
    )

    duplicate = _safety_draft(safety_request)
    findings = cast(list[dict[str, object]], duplicate["finding_proposals"])
    findings.append(copy.deepcopy(findings[0]))
    compiled = compile_readiness_draft_v1(safety_request, duplicate, _provenance())
    assert isinstance(compiled, CompiledReadinessDraftV1)
    assert compiled.normalization_codes == ("DRAFT_NORMALIZED_DUPLICATES",)

    conflict = _safety_draft(safety_request)
    conflict_findings = cast(list[dict[str, object]], conflict["finding_proposals"])
    changed = copy.deepcopy(conflict_findings[0])
    changed["why_unresolved"] = "Different evidence reasoning for the same finding identity."
    conflict_findings.append(changed)
    _assert_clarification(
        compile_readiness_draft_v1(safety_request, conflict, _provenance()),
        ReadinessDraftReasonCodeV1.CONFLICTING_ITEMS,
    )


def test_referee_is_bound_to_exact_dispute_and_scoped_evidence(
    referee_request: ReadinessEvaluatorRequestV1,
) -> None:
    wrong_id = _referee_draft(referee_request)
    wrong_id["dispute_id"] = "SD-9999"
    _assert_clarification(
        compile_readiness_draft_v1(referee_request, wrong_id, _provenance()),
        ReadinessDraftReasonCodeV1.COVERAGE_INVALID,
    )
    wrong_ref = _referee_draft(referee_request)
    wrong_ref["evidence_refs"] = ["SOURCE-999999"]
    _assert_clarification(
        compile_readiness_draft_v1(referee_request, wrong_ref, _provenance()),
        ReadinessDraftReasonCodeV1.REFERENCE_UNKNOWN,
    )
    generic = _referee_draft(referee_request)
    generic["rationale"] = "insufficient information"
    _assert_clarification(
        compile_readiness_draft_v1(referee_request, generic, _provenance()),
        ReadinessDraftReasonCodeV1.RATIONALE_GENERIC,
    )


def test_operation_mismatch_is_refused_without_guessing(
    ordinary_request: ReadinessEvaluatorRequestV1,
    contested_request: ReadinessEvaluatorRequestV1,
) -> None:
    _assert_clarification(
        compile_readiness_draft_v1(
            ordinary_request,
            _contested_draft(contested_request),
            _provenance(),
        ),
        ReadinessDraftReasonCodeV1.OPERATION_MISMATCH,
    )


class _DictSubclass(dict[str, object]):
    pass


class _ListSubclass(list[object]):
    pass


class _GuardedIterator:
    consumed = False

    def __iter__(self) -> _GuardedIterator:
        self.consumed = True
        raise AssertionError("untrusted iterator was consumed")

    def __next__(self) -> object:
        self.consumed = True
        raise AssertionError("untrusted iterator was consumed")


@pytest.mark.parametrize(
    "unsafe",
    [
        _DictSubclass(),
        deque(),
        {"unsafe"},
        _ListSubclass(),
        bytearray(b"{}"),
    ],
)
def test_unsafe_native_container_shapes_are_refused_without_laundering(
    ordinary_request: ReadinessEvaluatorRequestV1,
    unsafe: object,
) -> None:
    _assert_clarification(
        compile_readiness_draft_v1(ordinary_request, unsafe, _provenance()),
        ReadinessDraftReasonCodeV1.DRAFT_INVALID,
    )


def test_iterators_are_rejected_without_consumption(
    ordinary_request: ReadinessEvaluatorRequestV1,
) -> None:
    guarded = _GuardedIterator()
    _assert_clarification(
        compile_readiness_draft_v1(ordinary_request, guarded, _provenance()),
        ReadinessDraftReasonCodeV1.DRAFT_INVALID,
    )
    assert guarded.consumed is False


def test_cycles_depth_nodes_and_bytes_are_bounded_before_compilation(
    ordinary_request: ReadinessEvaluatorRequestV1,
) -> None:
    cyclic: dict[str, object] = {}
    cyclic["cycle"] = cyclic
    deep: dict[str, object] = {}
    cursor = deep
    for _ in range(70):
        child: dict[str, object] = {}
        cursor["child"] = child
        cursor = child
    nodes = {str(index): None for index in range(20_100)}
    oversized = b'{"rationale":"' + (b"x" * 262_145) + b'"}'
    expected = (
        (cyclic, ReadinessDraftReasonCodeV1.DRAFT_INVALID),
        (deep, ReadinessDraftReasonCodeV1.DRAFT_DEPTH_EXCEEDED),
        (nodes, ReadinessDraftReasonCodeV1.DRAFT_NODE_LIMIT_EXCEEDED),
        (oversized, ReadinessDraftReasonCodeV1.DRAFT_TOO_LARGE),
    )
    for draft, reason in expected:
        _assert_clarification(
            compile_readiness_draft_v1(ordinary_request, draft, _provenance()),
            reason,
        )


def test_nested_python_strings_are_byte_bounded_before_canonical_serialization(
    ordinary_request: ReadinessEvaluatorRequestV1,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    draft = _ordinary_draft(ordinary_request)
    oversized = "x" * 262_145
    draft["rationale"] = oversized
    original = drafts_module.canonical_json_bytes

    def guarded_canonical_json_bytes(value: object) -> bytes:
        if type(value) is dict and value.get("rationale") is oversized:
            raise AssertionError("oversized nested string reached canonical serialization")
        return original(value)

    monkeypatch.setattr(drafts_module, "canonical_json_bytes", guarded_canonical_json_bytes)
    _assert_clarification(
        compile_readiness_draft_v1(ordinary_request, draft, _provenance()),
        ReadinessDraftReasonCodeV1.DRAFT_TOO_LARGE,
    )


def test_json_bytes_reject_duplicate_keys_and_non_native_scalars(
    ordinary_request: ReadinessEvaluatorRequestV1,
) -> None:
    duplicate = b'{"rationale":"first","rationale":"second"}'
    _assert_clarification(
        compile_readiness_draft_v1(ordinary_request, duplicate, _provenance()),
        ReadinessDraftReasonCodeV1.DRAFT_INVALID,
    )
    draft = _ordinary_draft(ordinary_request)
    cast(dict[str, object], draft["requirement_grades"][0])["disposition"] = True
    _assert_clarification(
        compile_readiness_draft_v1(ordinary_request, draft, _provenance()),
        ReadinessDraftReasonCodeV1.DRAFT_INVALID,
    )


def _reseal_request(raw: dict[str, object]) -> ReadinessEvaluatorRequestV1:
    descriptor = {key: value for key, value in raw.items() if key != "request_fingerprint"}
    descriptor["request_fingerprint"] = sha256_digest(canonical_json_bytes(descriptor))
    return ReadinessEvaluatorRequestV1.model_validate(descriptor)


def test_resealed_ambiguous_controller_passage_inventory_is_an_engine_defect(
    ordinary_request: ReadinessEvaluatorRequestV1,
) -> None:
    raw = ordinary_request.model_dump(mode="json")
    payload = cast(dict[str, object], raw["payload"])
    allowlist = cast(list[str], payload["report_passage_allowlist"])
    allowlist.append(allowlist[0])
    resealed = _reseal_request(raw)
    assert compile_readiness_draft_v1(
        resealed,
        _ordinary_draft(ordinary_request),
        _provenance(),
    ) == ReadinessEngineDefectV1("READINESS_COMPILER_INVARIANT")


def test_resealed_ordinary_subject_must_match_exact_stable_baseline_member(
    ordinary_request: ReadinessEvaluatorRequestV1,
) -> None:
    raw = ordinary_request.model_dump(mode="json")
    payload = cast(dict[str, object], raw["payload"])
    requirements = cast(list[dict[str, object]], payload["requirements"])
    requirement = cast(dict[str, object], requirements[0]["requirement"])
    requirement["requirement_id"] = "REQ-9999"
    ids = [
        cast(str, cast(dict[str, object], item["requirement"])["requirement_id"])
        for item in requirements
    ]
    allowlist = cast(list[str], payload["report_passage_allowlist"])
    raw["json_schema"] = requests_module._grade_response_schema_for_ids(ids, allowlist)
    resealed = _reseal_request(raw)
    assert compile_readiness_draft_v1(
        resealed,
        _ordinary_draft(resealed),
        _provenance(),
    ) == ReadinessEngineDefectV1("READINESS_COMPILER_INVARIANT")


def test_malformed_resealed_nested_lane_returns_discriminated_engine_defect(
    safety_request: ReadinessEvaluatorRequestV1,
) -> None:
    raw = safety_request.model_dump(mode="json")
    payload = cast(dict[str, object], raw["payload"])
    lanes = cast(list[dict[str, object]], payload["grader_lanes"])
    lane = lanes[0]
    lane["ordinary_fragments"] = None
    descriptor = {key: value for key, value in lane.items() if key != "aggregate_fingerprint"}
    lane["aggregate_fingerprint"] = sha256_digest(canonical_json_bytes(descriptor))
    resealed = _reseal_request(raw)
    assert compile_readiness_draft_v1(
        resealed,
        _safety_draft(safety_request),
        _provenance(),
    ) == ReadinessEngineDefectV1("READINESS_COMPILER_INVARIANT")


@pytest.mark.parametrize("target", ["source_record", "evidence_handle"])
def test_resealed_safety_source_and_handle_content_must_match_stable_baseline(
    safety_request: ReadinessEvaluatorRequestV1,
    target: str,
) -> None:
    raw = safety_request.model_dump(mode="json")
    payload = cast(dict[str, object], raw["payload"])
    if target == "source_record":
        sources = cast(list[dict[str, object]], payload["source_record"])
        sources[0]["normalized_text"] = "Resealed source text."
    else:
        handles = cast(list[dict[str, object]], payload["evidence_handles"])
        source_handle = next(item for item in handles if item["evidence_kind"] == "source")
        evidence = cast(dict[str, object], source_handle["evidence"])
        evidence["title"] = "Resealed evidence description"
    resealed = _reseal_request(raw)
    assert compile_readiness_draft_v1(
        resealed,
        _safety_draft(safety_request),
        _provenance(),
    ) == ReadinessEngineDefectV1("READINESS_COMPILER_INVARIANT")


@pytest.mark.parametrize(
    "target",
    ["candidate", "client_fact_boundary", "generation_validation", "readiness_rubric"],
)
def test_resealed_safety_packet_must_reconstruct_every_controller_binding(
    safety_request: ReadinessEvaluatorRequestV1,
    target: str,
) -> None:
    raw = safety_request.model_dump(mode="json")
    payload = cast(dict[str, object], raw["payload"])
    if target == "candidate":
        candidate = cast(list[dict[str, object]], payload["gap_candidates"])[0]
        candidate["subject_id"] = "REQ-9999"
        descriptor = {
            key: value
            for key, value in candidate.items()
            if key not in {"candidate_id", "canonical_order", "importance", "candidate_fingerprint"}
        }
        candidate["candidate_fingerprint"] = sha256_digest(canonical_json_bytes(descriptor))
    elif target == "client_fact_boundary":
        boundary = cast(dict[str, object], payload[target])
        boundary["client_facts"] = "Resealed client facts."
    elif target == "generation_validation":
        generation = cast(dict[str, object], payload[target])
        generation["report_hash"] = "f" * 64
    else:
        rubric = cast(dict[str, object], payload[target])
        cast(list[str], rubric["generic_rationales"]).append("resealed rationale")
    resealed = _reseal_request(raw)
    assert compile_readiness_draft_v1(
        resealed,
        _safety_draft(safety_request),
        _provenance(),
    ) == ReadinessEngineDefectV1("READINESS_COMPILER_INVARIANT")


def test_request_provenance_rejects_subclasses_constructed_models_and_resealed_schema(
    ordinary_request: ReadinessEvaluatorRequestV1,
) -> None:
    class RequestSubclass(ReadinessEvaluatorRequestV1):
        pass

    subclass = RequestSubclass.model_validate(ordinary_request.model_dump(mode="json"))
    constructed = ReadinessEvaluatorRequestV1.model_construct(
        **ordinary_request.model_dump(mode="python")
    )
    raw = ordinary_request.model_dump(mode="json")
    raw["system_instructions"] = "A resealed but unauthorized instruction."
    resealed = _reseal_request(raw)
    for request in (subclass, constructed, resealed):
        assert compile_readiness_draft_v1(
            request,
            _ordinary_draft(ordinary_request),
            _provenance(),
        ) == ReadinessEngineDefectV1("READINESS_COMPILER_INVARIANT")


def test_draft_preflight_rejects_constructed_and_subclassed_internal_models(
    ordinary_request: ReadinessEvaluatorRequestV1,
) -> None:
    class DraftSubclass(drafts_module._OrdinaryGradeDraftV1):
        pass

    unsafe = (
        drafts_module._OrdinaryGradeDraftV1.model_construct(
            requirement_grades=(),
            rationale="constructed without validation",
        ),
        DraftSubclass.model_construct(
            requirement_grades=(),
            rationale="subclassed without validation",
        ),
    )
    for draft in unsafe:
        _assert_clarification(
            compile_readiness_draft_v1(ordinary_request, draft, _provenance()),
            ReadinessDraftReasonCodeV1.DRAFT_INVALID,
        )


def test_request_provenance_rejects_resealed_binding_and_candidate_fingerprint_tamper(
    safety_request: ReadinessEvaluatorRequestV1,
) -> None:
    report_tamper = safety_request.model_dump(mode="json")
    cast(dict[str, object], report_tamper["payload"])["report_hash"] = "f" * 64
    candidate_tamper = safety_request.model_dump(mode="json")
    candidate = cast(
        dict[str, object],
        cast(dict[str, object], candidate_tamper["payload"])["gap_candidates"][0],
    )
    candidate["candidate_fingerprint"] = "e" * 64
    for request in (_reseal_request(report_tamper), _reseal_request(candidate_tamper)):
        assert compile_readiness_draft_v1(
            request,
            _safety_draft(safety_request),
            _provenance(),
        ) == ReadinessEngineDefectV1("READINESS_COMPILER_INVARIANT")


def test_provenance_is_exact_bounded_and_public_safe(
    ordinary_request: ReadinessEvaluatorRequestV1,
) -> None:
    class ProvenanceSubclass(ReadinessEvaluatorProvenanceV1):
        pass

    invalid_values: tuple[object, ...] = (
        ProvenanceSubclass("provider", "model", "scripted_fixture"),
        ReadinessEvaluatorProvenanceV1("/Users/private/provider", "model", "scripted_fixture"),
        ReadinessEvaluatorProvenanceV1("provider", "file:/private/model", "scripted_fixture"),
    )
    for provenance in invalid_values:
        assert compile_readiness_draft_v1(
            ordinary_request,
            _ordinary_draft(ordinary_request),
            cast(ReadinessEvaluatorProvenanceV1, provenance),
        ) == ReadinessEngineDefectV1("READINESS_COMPILER_INVARIANT")


def test_failed_draft_compilation_is_pure_and_does_not_mutate_inputs(
    safety_request: ReadinessEvaluatorRequestV1,
) -> None:
    draft = _safety_draft(safety_request)
    cast(dict[str, object], draft["candidate_assessments"][0])["why_unresolved"] = (
        "more research needed"
    )
    before_request = canonical_json_bytes(safety_request)
    before_draft = copy.deepcopy(draft)
    outcome = compile_readiness_draft_v1(safety_request, draft, _provenance())
    assert isinstance(outcome, NeedsReadinessClarificationV1)
    assert canonical_json_bytes(safety_request) == before_request
    assert draft == before_draft


def test_attempt_one_and_two_receive_the_same_clarification_without_terminalizing(
    safety_request: ReadinessEvaluatorRequestV1,
) -> None:
    draft = _safety_draft(safety_request)
    cast(dict[str, object], draft["candidate_assessments"][0])["why_unresolved"] = (
        "more research needed"
    )
    first = compile_readiness_draft_v1(safety_request, draft, _provenance())
    second_prompt = ReadinessEvaluatorDraftPromptV1(
        request=safety_request,
        attempt=2,
        clarification_codes=cast(NeedsReadinessClarificationV1, first).reason_codes,
    )
    second = compile_readiness_draft_v1(
        second_prompt.request,
        draft,
        _provenance(),
    )
    assert (
        first
        == second
        == NeedsReadinessClarificationV1((ReadinessDraftReasonCodeV1.RATIONALE_GENERIC,))
    )


def test_models_are_frozen_and_reason_codes_are_deduplicated_in_stable_order(
    ordinary_request: ReadinessEvaluatorRequestV1,
) -> None:
    outcome = NeedsReadinessClarificationV1(
        (
            ReadinessDraftReasonCodeV1.RATIONALE_GENERIC,
            ReadinessDraftReasonCodeV1.RATIONALE_GENERIC,
            ReadinessDraftReasonCodeV1.REFERENCE_UNKNOWN,
        )
    )
    assert outcome.reason_codes == (
        ReadinessDraftReasonCodeV1.RATIONALE_GENERIC,
        ReadinessDraftReasonCodeV1.REFERENCE_UNKNOWN,
    )
    with pytest.raises((AttributeError, TypeError)):
        outcome.reason_codes = ()  # type: ignore[misc]
    with pytest.raises(ValueError):
        ReadinessEvaluatorProvenanceV1(" provider ", "model", "scripted_fixture")
    assert json.loads(canonical_json_bytes(_ordinary_draft(ordinary_request)))["rationale"]
