"""Protocol 2.1 model-boundary tests."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from regulatory_harvest.evaluation.attorney_v21_models import (
    AcceptedRefereeFragmentV21,
    CanonicalBaselineV21,
    ContestedGradeFragmentV21,
    ContestedRequirementV21,
    EvaluationCallRecordV21,
    EvaluationManifestV21,
    EvaluationPhaseV21,
    EvaluationResultV21,
    EvaluationRunStateV21,
    EvaluatorRequestV21,
    EvaluatorResponseV21,
    GraderAggregateV21,
    OrdinaryGradeBatchV21,
    OrdinaryGradeFragmentV21,
    ReconciledGradeV21,
    RefereeAggregateV21,
    RefereeDecisionV21,
    RefereeDisputeV21,
    ReportResultV21,
    RubricV21,
    SensitivityRecordV21,
    SourceReviewV21,
    validate_evaluator_response_v21,
)


def _proposal_payload() -> dict[str, object]:
    return {
        "statement": "A covered operator must file a notice.",
        "kind": "obligation",
        "importance": "critical",
        "passages": [{"source_id": "rule-1", "quote": "must file a notice"}],
        "dependency": None,
        "confidence": "clear",
        "rationale": "The source uses mandatory language.",
    }


def _referee_dispute_payload(
    dispute_id: str = "D0001",
    *,
    case_fingerprint: str = "c" * 64,
    dispute_fingerprint: str | None = None,
) -> dict[str, object]:
    return {
        "case_fingerprint": case_fingerprint,
        "dispute_fingerprint": dispute_fingerprint
        or (("d" if dispute_id == "D0001" else "e") * 64),
        "dispute_id": dispute_id,
        "material_dispute": {
            "dispute_id": dispute_id,
            "target_proposal_ref": None,
            "reviewer_proposal": None,
            "audit_concern": {
                "target_proposal_ref": None,
                "concern_type": "omission",
                "passages": [{"source_id": "rule-1", "quote": "must file a notice"}],
                "explanation": "The filing obligation was omitted.",
                "correction": _proposal_payload(),
            },
        },
        "evidence": [
            {
                "evidence_ref": "EVID-0001",
                "passage": {
                    "source_id": "rule-1",
                    "quote": "must file a notice",
                    "start_char": 0,
                    "end_char": 18,
                },
            }
        ],
    }


def _canonical_requirement_payload() -> dict[str, object]:
    return {
        "requirement_id": "REQ-0001",
        "canonical_order": 0,
        "statement": "A covered operator must file a notice.",
        "kind": "obligation",
        "importance": "critical",
        "passages": [
            {
                "source_id": "rule-1",
                "quote": "must file a notice",
                "start_char": 0,
                "end_char": 18,
            }
        ],
        "dependency": None,
        "confidence": "clear",
        "rationale": "The source uses mandatory language.",
    }


def _accepted_referee_fragment_payload(
    dispute_id: str,
    *,
    case_fingerprint: str = "c" * 64,
    dispute_fingerprint: str | None = None,
) -> dict[str, object]:
    return {
        "case_fingerprint": case_fingerprint,
        "dispute_id": dispute_id,
        "dispute_fingerprint": dispute_fingerprint
        or (("d" if dispute_id == "D0001" else "e") * 64),
        "decision": {
            "schema_version": "2.1",
            "decision": "accept_reviewer",
            "evidence_refs": ["EVID-0001"],
            "rationale": "The review is supported.",
        },
        "response_fingerprint": ("a" if dispute_id == "D0001" else "b") * 64,
    }


def _request_payload() -> dict[str, object]:
    return {
        "schema_version": "2.1",
        "operation": "source_referee_fragment",
        "request_fingerprint": "a" * 64,
        "system_instructions": "Decide the one supplied dispute.",
        "json_schema": {"type": "object"},
        "payload": {"material_disputes": [_referee_dispute_payload()]},
        "safe_metadata": {"protocol": "2.1"},
    }


def _ordinary_fragment_payload(
    *, anonymous_label: str = "A", grader_lane: int = 1, batch_ref: str = "GB-A-1-0001"
) -> dict[str, object]:
    return {
        "schema_version": "2.1",
        "anonymous_label": anonymous_label,
        "grader_lane": grader_lane,
        "batch_ref": batch_ref,
        "baseline_fingerprint": "a" * 64,
        "report_fingerprint": "b" * 64,
        "requirement_grades": [
            {
                "requirement_id": "REQ-0001",
                "disposition": "met",
                "report_passages": ["The report requires filing a notice."],
                "rationale": "The report states the duty.",
            }
        ],
        "rationale": "The batch is fully covered.",
    }


def _rubric() -> RubricV21:
    return RubricV21(
        version="attorney-eval-v2.1",
        importance_weights={"critical": 3, "material": 2, "supporting": 1},
        critical_recall_floor=1.0,
        weighted_coverage_floor=1.0,
        material_unsupported_assertions_allowed=0,
    )


def _baseline() -> CanonicalBaselineV21:
    return CanonicalBaselineV21(
        schema_version="2.1",
        case_fingerprint="a" * 64,
        requirements=[],
        baseline_fingerprint="b" * 64,
    )


def _contested_requirement() -> ContestedRequirementV21:
    return ContestedRequirementV21(
        contested_requirement_id="CONT-0001",
        reviewer_alternative=_canonical_requirement_payload(),
        unresolved_reason="SOURCE_GAP",
        rationale="The retained record does not resolve the disagreement.",
        referee_fragment_fingerprint="a" * 64,
    )


def _inconclusive_report() -> ReportResultV21:
    aggregate_payload = {
        "anonymous_label": "A",
        "baseline_fingerprint": "b" * 64,
        "report_fingerprint": "c" * 64,
        "ordinary_fragments": [],
        "contested_fragments": [],
        "aggregate_fingerprint": "d" * 64,
    }
    first = GraderAggregateV21.validate_for_inventories(
        {**aggregate_payload, "grader_lane": 1}, (), ()
    )
    second = GraderAggregateV21.validate_for_inventories(
        {**aggregate_payload, "grader_lane": 2, "aggregate_fingerprint": "e" * 64}, (), ()
    )
    reconciliation = ReconciledGradeV21.validate_for_inventories(
        {
            "anonymous_label": "A",
            "absolute_disposition": "INCONCLUSIVE",
            "grader_aggregates": [first, second],
            "reconciliation_fingerprint": "f" * 64,
        },
        (),
        (),
    )
    sensitivity = SensitivityRecordV21(
        anonymous_label="A",
        baseline_fingerprint="b" * 64,
        reconciliation_fingerprint="f" * 64,
        absolute_disposition="INCONCLUSIVE",
        reason_codes=["BASELINE_EVIDENCE_INSUFFICIENT"],
        sensitivity_fingerprint="0" * 64,
    )
    return ReportResultV21(
        anonymous_label="A",
        reconciliation=reconciliation,
        sensitivity=sensitivity,
        result_fingerprint="1" * 64,
    )


def test_request_deep_freezes_nested_json_snapshots() -> None:
    request = EvaluatorRequestV21.model_validate(_request_payload())

    with pytest.raises(TypeError):
        request.payload["material_disputes"] = []  # type: ignore[index]
    with pytest.raises(TypeError):
        request.payload["material_disputes"][0]["evidence"].append(  # type: ignore[index,union-attr]
            "EVID-0002"
        )


def test_referee_request_requires_exactly_one_evidence_complete_dispute() -> None:
    request = EvaluatorRequestV21.model_validate(_request_payload())
    assert len(request.payload["material_disputes"]) == 1  # type: ignore[index]

    with pytest.raises(ValidationError, match="at most 1"):
        EvaluatorRequestV21.model_validate(
            {
                **_request_payload(),
                "payload": {
                    "material_disputes": [
                        _referee_dispute_payload(),
                        _referee_dispute_payload("D0002"),
                    ]
                },
            }
        )
    with pytest.raises(ValidationError, match="evidence"):
        EvaluatorRequestV21.model_validate(
            {
                **_request_payload(),
                "payload": {
                    "material_disputes": [
                        {**_referee_dispute_payload(), "evidence": []}
                    ]
                },
            }
        )


def test_contested_request_carries_exactly_one_contested_requirement() -> None:
    payload = {
        "schema_version": "2.1",
        "operation": "contested_grade_fragment",
        "request_fingerprint": "a" * 64,
        "system_instructions": "Grade one disputed requirement.",
        "json_schema": {"type": "object"},
        "payload": {
            "anonymous_label": "A",
            "grader_lane": 1,
            "baseline_fingerprint": "a" * 64,
            "report_text": "The report addresses the requirement.",
            "report_fingerprint": "c" * 64,
            "source_context": {"rule-1": "source context"},
            "rubric": {"version": "attorney-eval-v2.1"},
            "contested_requirement": {
                "contested_requirement_id": "CONT-0001",
                "reviewer_alternative": _canonical_requirement_payload(),
                "auditor_alternative": None,
                "unresolved_reason": "SOURCE_GAP",
                "rationale": "Neither position can be resolved.",
                "referee_fragment_fingerprint": "b" * 64,
            },
        },
    }
    request = EvaluatorRequestV21.model_validate(payload)
    assert request.payload["contested_requirement"]["contested_requirement_id"] == "CONT-0001"  # type: ignore[index]

    with pytest.raises(ValidationError, match="extra"):
        EvaluatorRequestV21.model_validate(
            {**payload, "payload": {**payload["payload"], "contested_requirements": []}}
        )


def test_contested_grade_fragment_binds_exactly_one_controller_requirement() -> None:
    requirement = _contested_requirement()
    payload = {
        "schema_version": "2.1",
        "anonymous_label": "A",
        "grader_lane": 1,
        "contested_requirement_id": "CONT-0001",
        "baseline_fingerprint": "a" * 64,
        "report_fingerprint": "b" * 64,
        "reviewer_alternative_grade": {
            "disposition": "met",
            "report_passages": ["The report addresses the filing duty."],
            "rationale": "The report meets the reviewer alternative.",
        },
        "auditor_alternative_grade": {
            "disposition": "uncertain",
            "report_passages": [],
            "rationale": "The auditor alternative cannot be assessed.",
        },
        "ambiguity_disposition": "acknowledged",
        "rationale": "The report accurately describes the unresolved issue.",
    }
    fragment = ContestedGradeFragmentV21.validate_for_requirement(payload, requirement)
    assert fragment.contested_requirement_id == requirement.contested_requirement_id

    with pytest.raises(ValidationError):
        ContestedGradeFragmentV21.validate_for_requirement(
            {**payload, "contested_requirement_ids": ["CONT-0001", "CONT-0002"]},
            requirement,
        )


def test_source_review_uses_only_the_literal_protocol_21_version() -> None:
    with pytest.raises(ValidationError):
        SourceReviewV21.model_validate({"schema_version": "2.0", "proposals": []})


def test_request_rejects_cyclic_and_overdeep_json_payloads() -> None:
    cyclic: dict[str, object] = {}
    cyclic["self"] = cyclic
    with pytest.raises(ValidationError, match="cycle"):
        EvaluatorRequestV21.model_validate({**_request_payload(), "payload": cyclic})

    value: object = {}
    for _ in range(64):
        value = {"child": value}
    with pytest.raises(ValidationError, match="nesting-depth"):
        EvaluatorRequestV21.model_validate({**_request_payload(), "payload": value})

    with pytest.raises(ValidationError, match="size limit"):
        EvaluatorRequestV21.model_validate(
            {**_request_payload(), "payload": {"text": "x" * (16 * 1024 * 1024)}}
        )


def test_referee_unresolved_requires_substantive_reason() -> None:
    with pytest.raises(ValidationError):
        RefereeDecisionV21(
            schema_version="2.1",
            decision="unresolved",
            unresolved_reason=None,
            evidence_refs=["EVID-0001"],
            rationale="The retained authorities conflict.",
        )


@pytest.mark.parametrize("decision", ["accept_reviewer", "accept_auditor"])
def test_referee_accepted_decisions_forbid_unresolved_reason(decision: str) -> None:
    with pytest.raises(ValidationError, match="unresolved reason"):
        RefereeDecisionV21(
            schema_version="2.1",
            decision=decision,
            unresolved_reason="SOURCE_CONFLICT",
            evidence_refs=["EVID-0001"],
            rationale="The selected alternative is supported.",
        )


def test_referee_decision_requires_known_unique_evidence_refs() -> None:
    payload = {
        "schema_version": "2.1",
        "decision": "accept_reviewer",
        "evidence_refs": ["EVID-0001", "EVID-0001"],
        "rationale": "The review has direct support.",
    }
    with pytest.raises(ValidationError, match="unique"):
        RefereeDecisionV21.model_validate(payload, context={"evidence_refs": {"EVID-0001"}})
    with pytest.raises(ValidationError, match="controller-issued"):
        RefereeDecisionV21.model_validate(
            {**payload, "evidence_refs": ["EVID-9999"]},
            context={"evidence_refs": {"EVID-0001"}},
        )


def test_referee_decision_requires_a_controller_evidence_context() -> None:
    with pytest.raises(ValidationError, match="evidence inventory"):
        RefereeDecisionV21.model_validate(
            {
                "schema_version": "2.1",
                "decision": "accept_reviewer",
                "evidence_refs": ["EVID-0001"],
                "rationale": "The review is supported.",
            }
        )


def test_accepted_referee_fragment_restores_its_dispute_and_evidence_binding() -> None:
    first = RefereeDisputeV21.model_validate(_referee_dispute_payload())
    second = RefereeDisputeV21.model_validate(_referee_dispute_payload("D0002"))
    fragment = {
        "case_fingerprint": "c" * 64,
        "dispute_id": "D0001",
        "dispute_fingerprint": "d" * 64,
        "decision": {
            "schema_version": "2.1",
            "decision": "accept_reviewer",
            "evidence_refs": ["EVID-0001"],
            "rationale": "The review is supported.",
        },
        "response_fingerprint": "a" * 64,
    }

    accepted = AcceptedRefereeFragmentV21.validate_for_dispute(fragment, first)
    assert accepted.dispute_id == first.dispute_id
    with pytest.raises(ValueError, match="dispute"):
        AcceptedRefereeFragmentV21.validate_for_dispute(fragment, second)


def test_accepted_referee_fragment_rejects_an_otherwise_identical_cross_case_dispute() -> None:
    first_case_dispute = RefereeDisputeV21.model_validate(
        _referee_dispute_payload(
            case_fingerprint="a" * 64, dispute_fingerprint="1" * 64
        )
    )
    second_case_dispute = RefereeDisputeV21.model_validate(
        _referee_dispute_payload(
            case_fingerprint="b" * 64, dispute_fingerprint="1" * 64
        )
    )
    fragment = _accepted_referee_fragment_payload(
        "D0001", case_fingerprint="a" * 64, dispute_fingerprint="1" * 64
    )
    assert first_case_dispute.dispute_fingerprint == second_case_dispute.dispute_fingerprint
    assert first_case_dispute.material_dispute == second_case_dispute.material_dispute
    assert first_case_dispute.evidence == second_case_dispute.evidence

    AcceptedRefereeFragmentV21.validate_for_dispute(fragment, first_case_dispute)
    with pytest.raises(ValueError, match="case fingerprint"):
        AcceptedRefereeFragmentV21.validate_for_dispute(fragment, second_case_dispute)
    with pytest.raises(ValueError, match="case fingerprint"):
        RefereeAggregateV21.validate_for_disputes(
            {"fragments": [fragment], "aggregate_fingerprint": "f" * 64},
            (second_case_dispute,),
        )


@pytest.mark.parametrize("field", ["case_fingerprint", "dispute_fingerprint"])
def test_referee_dispute_requires_strict_controller_fingerprints(field: str) -> None:
    payload = _referee_dispute_payload()
    assert RefereeDisputeV21.model_validate(payload).dispute_fingerprint == "d" * 64

    missing = dict(payload)
    del missing[field]
    with pytest.raises(ValidationError, match=field):
        RefereeDisputeV21.model_validate(missing)
    with pytest.raises(ValidationError, match=field):
        RefereeDisputeV21.model_validate({**payload, field: "not-a-fingerprint"})


@pytest.mark.parametrize("field", ["case_fingerprint", "dispute_fingerprint"])
def test_referee_fragment_fingerprint_controls_revalidate_raw_typed_and_constructed(
    field: str,
) -> None:
    dispute = RefereeDisputeV21.model_validate(_referee_dispute_payload())
    raw = _accepted_referee_fragment_payload("D0001")
    typed = AcceptedRefereeFragmentV21.validate_for_dispute(raw, dispute)

    revalidated = AcceptedRefereeFragmentV21.validate_for_dispute(typed, dispute)
    assert revalidated.case_fingerprint == dispute.case_fingerprint
    assert revalidated.dispute_fingerprint == dispute.dispute_fingerprint
    constructed_fields = {
        "case_fingerprint": "c" * 64,
        "dispute_id": "D0001",
        "dispute_fingerprint": "d" * 64,
        "decision": typed.decision,
        "response_fingerprint": "a" * 64,
    }
    missing_constructed_fields = dict(constructed_fields)
    del missing_constructed_fields[field]
    for invalid in (
        {key: value for key, value in raw.items() if key != field},
        {**raw, field: "not-a-fingerprint"},
        AcceptedRefereeFragmentV21.model_construct(**missing_constructed_fields),
        AcceptedRefereeFragmentV21.model_construct(
            **{**constructed_fields, field: "not-a-fingerprint"}
        ),
    ):
        with pytest.raises(ValueError, match=field.replace("_", r"[_ ]")):
            AcceptedRefereeFragmentV21.validate_for_dispute(invalid, dispute)
    with pytest.raises(ValueError, match="extra"):
        AcceptedRefereeFragmentV21.validate_for_dispute(
            {**raw, "artifact_path": "forged"}, dispute
        )


def test_referee_boundaries_reject_constructed_dispute_fingerprints() -> None:
    dispute = RefereeDisputeV21.model_validate(_referee_dispute_payload())
    raw_fragment = _accepted_referee_fragment_payload("D0001")
    valid_fields = {
        "case_fingerprint": "c" * 64,
        "dispute_fingerprint": "d" * 64,
        "dispute_id": "D0001",
        "material_dispute": dispute.material_dispute,
        "evidence": dispute.evidence,
    }
    invalid_disputes = []
    for field in ("case_fingerprint", "dispute_fingerprint"):
        missing = dict(valid_fields)
        del missing[field]
        invalid_disputes.append(RefereeDisputeV21.model_construct(**missing))
        invalid_disputes.append(
            RefereeDisputeV21.model_construct(
                **{**valid_fields, field: "not-a-fingerprint"}
            )
        )

    for invalid_dispute in invalid_disputes:
        with pytest.raises(ValueError, match="fingerprint"):
            AcceptedRefereeFragmentV21.validate_for_dispute(raw_fragment, invalid_dispute)
        with pytest.raises(ValueError, match="fingerprint"):
            RefereeAggregateV21.validate_for_disputes(
                {"fragments": [raw_fragment], "aggregate_fingerprint": "f" * 64},
                (invalid_dispute,),
            )


def test_referee_decision_contains_no_controller_identity() -> None:
    decision = _accepted_referee_fragment_payload("D0001")["decision"]
    assert isinstance(decision, dict)
    for field in ("case_fingerprint", "dispute_fingerprint", "dispute_id"):
        with pytest.raises(ValidationError, match="extra"):
            RefereeDecisionV21.model_validate(
                {**decision, field: "d" * 64},
                context={"evidence_refs": {"EVID-0001"}},
            )


def test_referee_aggregate_rebinds_the_ordered_dispute_inventory() -> None:
    disputes = (
        RefereeDisputeV21.model_validate(_referee_dispute_payload("D0001")),
        RefereeDisputeV21.model_validate(_referee_dispute_payload("D0002")),
    )
    fragments = [
        _accepted_referee_fragment_payload("D0001"),
        _accepted_referee_fragment_payload("D0002"),
    ]
    checked = [
        AcceptedRefereeFragmentV21.validate_for_dispute(fragment, dispute)
        for fragment, dispute in zip(fragments, disputes, strict=True)
    ]
    with pytest.raises(ValidationError, match="referee dispute"):
        RefereeAggregateV21(fragments=checked, aggregate_fingerprint="c" * 64)

    aggregate = RefereeAggregateV21.validate_for_disputes(
        {"fragments": fragments, "aggregate_fingerprint": "c" * 64}, disputes
    )
    assert tuple(fragment.dispute_id for fragment in aggregate.fragments) == ("D0001", "D0002")
    assert RefereeAggregateV21.validate_for_disputes(aggregate, disputes) == aggregate

    with pytest.raises(ValueError, match="coverage"):
        RefereeAggregateV21.validate_for_disputes(
            {"fragments": fragments[:1], "aggregate_fingerprint": "c" * 64}, disputes
        )
    with pytest.raises(ValueError, match="dispute"):
        RefereeAggregateV21.validate_for_disputes(
            {"fragments": fragments[::-1], "aggregate_fingerprint": "c" * 64}, disputes
        )
    with pytest.raises(ValueError, match="dispute"):
        RefereeAggregateV21.validate_for_disputes(
            {"fragments": [fragments[0], fragments[0]], "aggregate_fingerprint": "c" * 64},
            disputes,
        )
    forged = {
        **fragments[0],
        "decision": {**fragments[0]["decision"], "evidence_refs": ["EVID-9999"]},
    }
    with pytest.raises(ValueError, match="controller-issued"):
        RefereeAggregateV21.validate_for_disputes(
            {"fragments": [forged, fragments[1]], "aggregate_fingerprint": "c" * 64},
            disputes,
        )


def test_referee_aggregate_resnapshots_bypass_constructed_nested_fragments() -> None:
    disputes = (
        RefereeDisputeV21.model_validate(_referee_dispute_payload("D0001")),
        RefereeDisputeV21.model_validate(_referee_dispute_payload("D0002")),
    )
    valid_second = _accepted_referee_fragment_payload("D0002")
    invalid_decision = RefereeDecisionV21.model_construct(
        schema_version="2.0",
        decision="accept_reviewer",
        unresolved_reason="SOURCE_GAP",
        evidence_refs=("EVID-0001",),
        rationale=" ",
    )
    bypassed = AcceptedRefereeFragmentV21.model_construct(
        case_fingerprint="c" * 64,
        dispute_id="D0001",
        dispute_fingerprint="d" * 64,
        decision=invalid_decision,
        response_fingerprint="not-a-hash",
    )
    with pytest.raises(ValueError):
        RefereeAggregateV21.validate_for_disputes(
            {"fragments": [bypassed, valid_second], "aggregate_fingerprint": "c" * 64},
            disputes,
        )

    invalid_identifier = AcceptedRefereeFragmentV21.model_construct(
        case_fingerprint="c" * 64,
        dispute_id="not-a-dispute-id",
        dispute_fingerprint="d" * 64,
        decision=RefereeDecisionV21.model_construct(
            schema_version="2.1",
            decision="accept_reviewer",
            unresolved_reason=None,
            evidence_refs=("EVID-0001",),
            rationale="The review is supported.",
        ),
        response_fingerprint="a" * 64,
    )
    with pytest.raises(ValueError):
        RefereeAggregateV21.validate_for_disputes(
            {"fragments": [invalid_identifier, valid_second], "aggregate_fingerprint": "c" * 64},
            disputes,
        )

    cyclic_refs: list[object] = []
    cyclic_refs.append(cyclic_refs)
    cyclic = AcceptedRefereeFragmentV21.model_construct(
        case_fingerprint="c" * 64,
        dispute_id="D0001",
        dispute_fingerprint="d" * 64,
        decision=RefereeDecisionV21.model_construct(
            schema_version="2.1",
            decision="accept_reviewer",
            unresolved_reason=None,
            evidence_refs=cyclic_refs,
            rationale="The review is supported.",
        ),
        response_fingerprint="a" * 64,
    )
    with pytest.raises(ValueError):
        RefereeAggregateV21.validate_for_disputes(
            {"fragments": [cyclic, valid_second], "aggregate_fingerprint": "c" * 64}, disputes
        )
    with pytest.raises(ValueError, match="ordered sequence"):
        RefereeAggregateV21.validate_for_disputes(
            {"fragments": {"D0001": bypassed}, "aggregate_fingerprint": "c" * 64}, disputes
        )


def test_referee_fragment_rejects_extra_keys_and_blank_rationale() -> None:
    with pytest.raises(ValidationError):
        AcceptedRefereeFragmentV21.model_validate(
            {
                "case_fingerprint": "c" * 64,
                "dispute_id": "D0001",
                "dispute_fingerprint": "d" * 64,
                "decision": {
                    "schema_version": "2.1",
                    "decision": "accept_reviewer",
                    "evidence_refs": ["EVID-0001"],
                    "rationale": "  ",
                },
                "response_fingerprint": "b" * 64,
                "artifact_path": "forged",
            }
        )


def test_ordinary_grade_batch_is_bounded() -> None:
    with pytest.raises(ValidationError):
        OrdinaryGradeBatchV21(
            batch_ref="GB-A-1-0001",
            requirement_ids=[f"REQ-{index:04d}" for index in range(6)],
        )


def test_ordinary_grade_batch_rejects_duplicate_or_unhashable_requirement_refs() -> None:
    with pytest.raises(ValidationError, match="unique"):
        OrdinaryGradeBatchV21(batch_ref="GB-A-1-0001", requirement_ids=["REQ-0001", "REQ-0001"])
    with pytest.raises(ValidationError):
        OrdinaryGradeBatchV21.model_validate(
            {"batch_ref": "GB-A-1-0001", "requirement_ids": [["REQ-0001"]]}
        )


def test_batch_refs_bind_the_fragment_and_call_to_the_label_and_lane() -> None:
    batch = OrdinaryGradeBatchV21(batch_ref="GB-A-1-0001", requirement_ids=["REQ-0001"])
    with pytest.raises(ValidationError, match="batch reference"):
        OrdinaryGradeFragmentV21.validate_for_batch(
            _ordinary_fragment_payload(batch_ref="GB-B-2-0001"), batch
        )

    with pytest.raises(ValidationError, match="batch reference"):
        EvaluationCallRecordV21.model_validate(
            {
                "call_id": "call-1",
                "operation": "ordinary_grade_fragment",
                "state": "pending",
                "attempt": 1,
                "request_artifact_path": "requests/call-1.json",
                "request_fingerprint": "a" * 64,
                "anonymous_label": "A",
                "grader_lane": 1,
                "batch_ref": "GB-B-2-0001",
            }
        )


def test_grader_aggregate_requires_the_exact_controller_batch_inventory() -> None:
    batch = OrdinaryGradeBatchV21(batch_ref="GB-A-1-0001", requirement_ids=["REQ-0001"])
    fragment = OrdinaryGradeFragmentV21.validate_for_batch(_ordinary_fragment_payload(), batch)
    payload = {
        "anonymous_label": "A",
        "grader_lane": 1,
        "baseline_fingerprint": "a" * 64,
        "report_fingerprint": "b" * 64,
        "ordinary_fragments": [fragment],
        "contested_fragments": [],
        "aggregate_fingerprint": "c" * 64,
    }
    aggregate = GraderAggregateV21.validate_for_inventories(payload, (batch,), ())
    assert aggregate.ordinary_fragments[0].batch_ref == batch.batch_ref

    with pytest.raises(ValueError, match="inventory"):
        GraderAggregateV21.validate_for_inventories(payload, (), ())


def test_reconciliation_requires_two_distinct_grader_lanes() -> None:
    aggregate = {
        "anonymous_label": "A",
        "grader_lane": 1,
        "baseline_fingerprint": "c" * 64,
        "report_fingerprint": "d" * 64,
        "ordinary_fragments": [],
        "contested_fragments": [],
        "aggregate_fingerprint": "e" * 64,
    }
    with pytest.raises(ValueError, match="canonical"):
        ReconciledGradeV21.validate_for_inventories(
            {
                "anonymous_label": "A",
                "absolute_disposition": "PASS",
                "reason_codes": [],
                "grader_aggregates": [aggregate, aggregate],
                "reconciliation_fingerprint": "f" * 64,
            },
            (),
            (),
        )


def test_response_revalidation_rejects_model_construct_and_forged_lane() -> None:
    response = EvaluatorResponseV21.model_construct(
        schema_version="2.1",
        operation="ordinary_grade_fragment",
        request_fingerprint="a" * 64,
        provider_name="provider",
        model_name="model",
        judge_isolation="fresh_context",
        payload={"grader_lane": 3},
    )
    with pytest.raises(ValueError, match="invalid"):
        validate_evaluator_response_v21(response)


def test_call_record_allows_only_the_initial_or_one_repair_attempt() -> None:
    payload = {
        "call_id": "call-1",
        "operation": "source_review",
        "state": "pending",
        "attempt": 1,
        "request_artifact_path": "requests/call-1.json",
        "request_fingerprint": "a" * 64,
    }
    record = EvaluationCallRecordV21.model_validate(payload)
    assert record.attempt == 1

    with pytest.raises(ValidationError):
        EvaluationCallRecordV21.model_validate({**payload, "attempt": 3})


def test_phase_and_terminal_status_must_correspond_exactly() -> None:
    state = {
        "schema_version": "2.1",
        "case_fingerprint": "a" * 64,
        "phase": EvaluationPhaseV21.COMPLETED,
        "current_call_id": None,
        "terminal_status": "INCONCLUSIVE_MECHANICAL",
        "manifest_fingerprint": "b" * 64,
    }
    with pytest.raises(ValidationError, match="terminal phase and status"):
        EvaluationRunStateV21.model_validate(state)

    manifest = {
        "protocol_version": "2.1",
        "case_fingerprint": "a" * 64,
        "case_envelope_hash": "b" * 64,
        "build_fingerprint": "c" * 64,
        "rubric_fingerprint": "d" * 64,
        "compiler_version": "semantic-compiler-v2.1",
        "phase": "inconclusive_mechanical",
        "terminal_status": "INCONCLUSIVE",
        "calls": [],
        "artifacts": [],
        "referee_disputes": [],
        "ordinary_grade_batches": [],
        "manifest_fingerprint": "e" * 64,
    }
    with pytest.raises(ValidationError, match="terminal phase and status"):
        EvaluationManifestV21.model_validate(manifest)


def test_substantive_inconclusive_requires_sensitivity_backed_report_evidence() -> None:
    with pytest.raises(ValidationError, match="sensitivity"):
        EvaluationResultV21(
            schema_version="2.1",
            rubric=_rubric(),
            baseline=_baseline(),
            reports=[],
            terminal_status="INCONCLUSIVE",
            result_fingerprint="a" * 64,
        )

    result = EvaluationResultV21(
        schema_version="2.1",
        rubric=_rubric(),
        baseline=_baseline(),
        reports=[_inconclusive_report()],
        terminal_status="INCONCLUSIVE",
        result_fingerprint="a" * 64,
    )
    assert result.reports[0].sensitivity.reason_codes == ("BASELINE_EVIDENCE_INSUFFICIENT",)

    with pytest.raises(ValidationError, match="sensitivity"):
        SensitivityRecordV21(
            anonymous_label="A",
            baseline_fingerprint="b" * 64,
            reconciliation_fingerprint="f" * 64,
            absolute_disposition="INCONCLUSIVE",
            reason_codes=["UNRESOLVED_COUNT"],
            sensitivity_fingerprint="0" * 64,
        )
