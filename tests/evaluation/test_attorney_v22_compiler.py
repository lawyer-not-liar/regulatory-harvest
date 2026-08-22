"""Deterministic Protocol 2.2 fragment aggregation tests."""

from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import dataclass
from enum import StrEnum

import pytest
from test_attorney_v21_rubric import baseline_with_contested, baseline_with_requirements
from test_attorney_v22_requests import envelope, proposal

from regulatory_harvest.evaluation import attorney_v22_compiler as compiler_module
from regulatory_harvest.evaluation.attorney_v2_compiler import CompilationError
from regulatory_harvest.evaluation.attorney_v2_models import AbsoluteDispositionV2
from regulatory_harvest.evaluation.attorney_v21_rubric import RUBRIC_V21, RubricValidationError
from regulatory_harvest.evaluation.attorney_v22_compiler import (
    RUBRIC_V22,
    aggregate_grader_lane_v22,
    aggregate_referee_decisions_v22,
    aggregate_source_audit_fragments_v22,
    aggregate_source_review_fragments_v22,
    build_referee_disputes_v22,
    compile_baseline_v22,
    evaluate_outcome_sensitivity_v22,
    ordinary_grade_batches_v22,
    reconcile_grader_lanes_v22,
    validate_grade_fragment_v22,
    validate_referee_fragment_v22,
    verify_canonical_baseline_v22,
    verify_source_audit_aggregate_v22,
    verify_source_review_aggregate_v22,
)
from regulatory_harvest.evaluation.attorney_v22_models import (
    AcceptedRefereeFragmentV22,
    AcceptedSourceAuditFragmentV22,
    AcceptedSourceReviewFragmentV22,
    CanonicalBaselineV22,
    ContestedGradeFragmentV22,
    EvaluatorOperationV22,
    GraderAggregateV22,
    OrdinaryGradeFragmentV22,
    RefereeDisputeV22,
    SourceAuditAggregateV22,
    SourceAuditFragmentV22,
    SourceReviewAggregateV22,
    SourceReviewFragmentV22,
)
from regulatory_harvest.evaluation.attorney_v22_requests import (
    build_ordinary_grade_request_v22,
    build_source_audit_fragment_request_v22,
    build_source_review_fragment_request_v22,
)
from regulatory_harvest.storage import canonical_json_bytes


class _ForeignDecision(StrEnum):
    ACCEPT_REVIEWER = "accept_reviewer"
    RATIONALE = "The evidence supports the reviewer."


class _ForeignImportance(StrEnum):
    CRITICAL = "critical"
    MATERIAL = "material"
    SUPPORTING = "supporting"


def review_fragment(
    ordinal: int, statement: str, *, final: bool = False
) -> AcceptedSourceReviewFragmentV22:
    request_fingerprint = f"{ordinal:064x}"
    if ordinal == 1:
        request_fingerprint = build_source_review_fragment_request_v22(
            envelope(), (), fragment_ordinal=1
        ).request_fingerprint
    return AcceptedSourceReviewFragmentV22(
        fragment_ordinal=ordinal,
        request_fingerprint=request_fingerprint,
        response_fingerprint=f"{ordinal + 32:064x}",
        payload=SourceReviewFragmentV22(proposals=[proposal(statement)], review_complete=final),
    )


def canonical_baseline(requirement_count: int = 1) -> CanonicalBaselineV22:
    raw = baseline_with_requirements(requirement_count).model_dump(mode="json")
    raw["schema_version"] = "2.2"
    raw["baseline_fingerprint"] = hashlib.sha256(
        canonical_json_bytes(
            {key: value for key, value in raw.items() if key != "baseline_fingerprint"}
        )
    ).hexdigest()
    return CanonicalBaselineV22.model_validate(raw)


def _alternative_world_baseline(
    *, ordinary_count: int, contested_count: int
) -> CanonicalBaselineV22:
    ordinary = baseline_with_requirements(ordinary_count, importance="critical")
    contested = baseline_with_contested(contested_count)
    raw = ordinary.model_dump(mode="json")
    raw["schema_version"] = "2.2"
    raw["contested_requirements"] = contested.model_dump(mode="json")[
        "contested_requirements"
    ]
    raw["baseline_fingerprint"] = hashlib.sha256(
        canonical_json_bytes(
            {key: value for key, value in raw.items() if key != "baseline_fingerprint"}
        )
    ).hexdigest()
    return CanonicalBaselineV22.model_validate(raw)


def _alternative_world_aggregate(
    baseline: CanonicalBaselineV22,
    lane: int,
    *,
    ordinary: str = "met",
    contested: tuple[tuple[str, str], ...],
) -> GraderAggregateV22:
    report = "The report addresses the issued requirements."
    ordinary_fragments = []
    for batch in ordinary_grade_batches_v22(baseline, "A", lane):
        ordinary_fragments.append(
            validate_grade_fragment_v22(
                baseline,
                {
                    "schema_version": "2.2",
                    "anonymous_label": "A",
                    "grader_lane": lane,
                    "batch_ref": batch.batch_ref,
                    "baseline_fingerprint": baseline.baseline_fingerprint,
                    "report_fingerprint": hashlib.sha256(report.encode()).hexdigest(),
                    "requirement_grades": [
                        {
                            "requirement_id": requirement_id,
                            "disposition": ordinary,
                            "report_passages": [] if ordinary == "not_met" else [report],
                            "rationale": "The requirement was graded as written.",
                            "omission": "The requirement is absent."
                            if ordinary == "not_met"
                            else None,
                        }
                        for requirement_id in batch.requirement_ids
                    ],
                    "rationale": "The issued ordinary batch was graded.",
                },
                report,
            )
        )
    contested_fragments = []
    for requirement, (reviewer, auditor) in zip(
        baseline.contested_requirements, contested, strict=True
    ):
        def alternative(disposition: str) -> dict[str, object]:
            return {
                "disposition": disposition,
                "report_passages": []
                if disposition in {"not_met", "uncertain"}
                else [report],
                "rationale": "The alternative was graded as written.",
            }

        contested_fragments.append(
            validate_grade_fragment_v22(
                baseline,
                {
                    "schema_version": "2.2",
                    "anonymous_label": "A",
                    "grader_lane": lane,
                    "contested_requirement_id": requirement.contested_requirement_id,
                    "baseline_fingerprint": baseline.baseline_fingerprint,
                    "report_fingerprint": hashlib.sha256(report.encode()).hexdigest(),
                    "reviewer_alternative_grade": alternative(reviewer),
                    "auditor_alternative_grade": alternative(auditor),
                    "ambiguity_disposition": "uncertain"
                    if "uncertain" in {reviewer, auditor}
                    else "acknowledged",
                    "rationale": "Both source alternatives were graded.",
                },
                report,
            )
        )
    return aggregate_grader_lane_v22(
        baseline,
        "A",
        lane,
        tuple(ordinary_fragments),
        tuple(contested_fragments),
    )


def _alternative_world_sensitivity(
    baseline: CanonicalBaselineV22,
    *,
    ordinary: str = "met",
    contested: tuple[tuple[str, str], ...],
):
    first = _alternative_world_aggregate(
        baseline, 1, ordinary=ordinary, contested=contested
    )
    second = _alternative_world_aggregate(
        baseline, 2, ordinary=ordinary, contested=contested
    )
    return evaluate_outcome_sensitivity_v22(
        baseline, reconcile_grader_lanes_v22(baseline, first, second)
    )


def _bound_source_aggregates() -> tuple[SourceReviewAggregateV22, SourceAuditAggregateV22]:
    review_request = build_source_review_fragment_request_v22(envelope(), (), fragment_ordinal=1)
    accepted_review = AcceptedSourceReviewFragmentV22(
        fragment_ordinal=1,
        request_fingerprint=review_request.request_fingerprint,
        response_fingerprint="1" * 64,
        payload=SourceReviewFragmentV22(
            proposals=[proposal("Operators must file.")], review_complete=True
        ),
    )
    review = aggregate_source_review_fragments_v22((accepted_review,))
    audit_request = build_source_audit_fragment_request_v22(
        envelope(), review, (), fragment_ordinal=1
    )
    accepted_audit = AcceptedSourceAuditFragmentV22(
        fragment_ordinal=1,
        request_fingerprint=audit_request.request_fingerprint,
        response_fingerprint="2" * 64,
        payload=SourceAuditFragmentV22(concerns=(), audit_complete=True),
    )
    return review, aggregate_source_audit_fragments_v22(review, (accepted_audit,))


def _bound_disputed_source_aggregates() -> tuple[SourceReviewAggregateV22, SourceAuditAggregateV22]:
    review = aggregate_source_review_fragments_v22(
        (review_fragment(1, "Operators must file.", final=True),)
    )
    audit_request = build_source_audit_fragment_request_v22(
        envelope(), review, (), fragment_ordinal=1
    )
    audit_fragment = AcceptedSourceAuditFragmentV22(
        fragment_ordinal=1,
        request_fingerprint=audit_request.request_fingerprint,
        response_fingerprint="4" * 64,
        payload=SourceAuditFragmentV22(
            concerns=[
                {
                    "target_proposal_ref": "P0001",
                    "concern_type": "incorrect_statement",
                    "passages": [{"source_id": "rule-1", "quote": "operators must file"}],
                    "explanation": "The exception is omitted.",
                    "correction": proposal("Operators must file unless small."),
                }
            ],
            audit_complete=True,
        ),
    )
    return review, aggregate_source_audit_fragments_v22(review, (audit_fragment,))


def _max_bound_source_aggregates() -> tuple[SourceReviewAggregateV22, SourceAuditAggregateV22]:
    from regulatory_harvest.evaluation.attorney_v22_drafts import (
        _SourceAuditDraftV22,
        _SourceReviewDraftV22,
    )
    from regulatory_harvest.evaluation.attorney_v22_requests import (
        _frozen_source_record_v22,
        _new_request_v22,
        _source_metadata,
    )

    case = envelope()
    record, source_fingerprint = _frozen_source_record_v22(case)
    metadata = _source_metadata(case, source_fingerprint)
    review_schema = _SourceReviewDraftV22.model_json_schema()
    accepted_proposals: list[dict[str, object]] = []
    review_fragments: list[AcceptedSourceReviewFragmentV22] = []
    for ordinal in range(1, 129):
        request = _new_request_v22(
            EvaluatorOperationV22.SOURCE_REVIEW_FRAGMENT,
            json_schema=review_schema,
            payload={
                "source_record": record,
                "accepted_proposals": accepted_proposals,
                "fragment_ordinal": ordinal,
                "max_new_proposals": 5,
            },
            safe_metadata=metadata,
        )
        payload = SourceReviewFragmentV22(
            proposals=[proposal(f"Review statement {ordinal}.")],
            review_complete=ordinal == 128,
        )
        review_fragments.append(
            AcceptedSourceReviewFragmentV22(
                fragment_ordinal=ordinal,
                request_fingerprint=request.request_fingerprint,
                response_fingerprint=f"{ordinal + 1024:064x}",
                payload=payload,
            )
        )
        accepted_proposals.extend(item.model_dump(mode="json") for item in payload.proposals)
    review = aggregate_source_review_fragments_v22(tuple(review_fragments))

    audit_schema = _SourceAuditDraftV22.model_json_schema()
    indexed_proposals = [item.model_dump(mode="json") for item in review.proposals]
    accepted_concerns: list[dict[str, object]] = []
    audit_fragments: list[AcceptedSourceAuditFragmentV22] = []
    for ordinal in range(1, 129):
        request = _new_request_v22(
            EvaluatorOperationV22.SOURCE_AUDIT_FRAGMENT,
            json_schema=audit_schema,
            payload={
                "source_record": record,
                "indexed_proposals": indexed_proposals,
                "accepted_concerns": accepted_concerns,
                "fragment_ordinal": ordinal,
                "max_new_concerns": 5,
            },
            safe_metadata=metadata,
        )
        payload = SourceAuditFragmentV22(
            concerns=[
                {
                    "target_proposal_ref": "P0001",
                    "concern_type": "incorrect_statement",
                    "passages": [{"source_id": "rule-1", "quote": "operators must file"}],
                    "explanation": f"Correction {ordinal} is required.",
                    "correction": proposal(f"Corrected statement {ordinal}."),
                }
            ],
            audit_complete=ordinal == 128,
        )
        audit_fragments.append(
            AcceptedSourceAuditFragmentV22(
                fragment_ordinal=ordinal,
                request_fingerprint=request.request_fingerprint,
                response_fingerprint=f"{ordinal + 2048:064x}",
                payload=payload,
            )
        )
        accepted_concerns.extend(item.model_dump(mode="json") for item in payload.concerns)
    audit = aggregate_source_audit_fragments_v22(review, tuple(audit_fragments))
    return review, audit


def test_review_aggregation_assigns_deterministic_controller_references() -> None:
    aggregate = aggregate_source_review_fragments_v22(
        (review_fragment(1, "First."), review_fragment(2, "Second.", final=True))
    )

    assert [item.proposal_ref for item in aggregate.proposals] == ["P0001", "P0002"]
    assert [item.proposal.statement for item in aggregate.proposals] == ["First.", "Second."]
    assert len(aggregate.aggregate_fingerprint) == 64


@pytest.mark.parametrize(
    "fragments",
    [
        (review_fragment(2, "Second.", final=True),),
        (review_fragment(1, "First.", final=True), review_fragment(2, "Second.")),
        (review_fragment(1, "Same."), review_fragment(2, "Same.", final=True)),
    ],
)
def test_review_aggregation_rejects_out_of_order_nonfinal_or_duplicate_semantics(
    fragments: tuple[AcceptedSourceReviewFragmentV22, ...],
) -> None:
    with pytest.raises(ValueError):
        aggregate_source_review_fragments_v22(fragments)


@pytest.mark.parametrize(
    ("changed_rationale", "message"),
    [
        (False, "duplicate accepted source-review proposal"),
        (True, "conflicting accepted source-review proposal"),
    ],
)
def test_source_fragment_semantic_validator_rejects_prefix_duplicate_or_conflict(
    changed_rationale: bool, message: str
) -> None:
    first = SourceReviewFragmentV22(
        proposals=[proposal("Operators must file.")], review_complete=False
    ).proposals[0]
    candidate_value = proposal("Operators must file.")
    if changed_rationale:
        candidate_value["rationale"] = "Different exact bytes for the same semantic duty."
    candidate = SourceReviewFragmentV22(
        proposals=[candidate_value], review_complete=False
    ).proposals[0]

    with pytest.raises(ValueError, match=message):
        compiler_module._validate_source_fragment_semantics_v22(
            (first, candidate), kind="source-review proposal"
        )


def test_review_aggregation_revalidates_model_construct_and_fragment_boundaries() -> None:
    forged = review_fragment(1, "First.", final=True).model_construct(
        fragment_ordinal=1,
        request_fingerprint="1" * 64,
        response_fingerprint="2" * 64,
        payload=SourceReviewFragmentV22.model_construct(proposals=(), review_complete=False),
    )
    with pytest.raises(ValueError):
        aggregate_source_review_fragments_v22((forged,))


def test_audit_aggregation_binds_every_target_to_review_inventory() -> None:
    review = aggregate_source_review_fragments_v22((review_fragment(1, "First.", final=True),))
    fragment = AcceptedSourceAuditFragmentV22(
        fragment_ordinal=1,
        request_fingerprint="3" * 64,
        response_fingerprint="4" * 64,
        payload=SourceAuditFragmentV22(
            concerns=[
                {
                    "target_proposal_ref": "P0001",
                    "concern_type": "ambiguity",
                    "passages": [{"source_id": "rule-1", "quote": "operators must file"}],
                    "explanation": "The source has an exception.",
                    "correction": None,
                }
            ],
            audit_complete=True,
        ),
    )

    aggregate = aggregate_source_audit_fragments_v22(review, (fragment,))
    assert [item.concern_ref for item in aggregate.concerns] == ["C0001"]
    assert aggregate.concerns[0].concern.target_proposal_ref == "P0001"


def test_audit_aggregation_rejects_cross_inventory_target_and_skipped_fragment() -> None:
    review = aggregate_source_review_fragments_v22((review_fragment(1, "First.", final=True),))
    cross = AcceptedSourceAuditFragmentV22(
        fragment_ordinal=2,
        request_fingerprint="3" * 64,
        response_fingerprint="4" * 64,
        payload=SourceAuditFragmentV22(concerns=[], audit_complete=True),
    )
    with pytest.raises(ValueError):
        aggregate_source_audit_fragments_v22(review, (cross,))


def test_audit_aggregation_treats_reordered_passages_as_the_same_semantic_concern() -> None:
    review = aggregate_source_review_fragments_v22((review_fragment(1, "First.", final=True),))
    concern = {
        "target_proposal_ref": "P0001",
        "concern_type": "ambiguity",
        "passages": [
            {"source_id": "rule-1", "quote": "operators must file"},
            {"source_id": "rule-1", "quote": "Small operators"},
        ],
        "explanation": "The exception needs attention.",
        "correction": None,
    }
    reversed_concern = {**concern, "passages": list(reversed(concern["passages"]))}
    fragment = AcceptedSourceAuditFragmentV22(
        fragment_ordinal=1,
        request_fingerprint="3" * 64,
        response_fingerprint="4" * 64,
        payload=SourceAuditFragmentV22(concerns=[concern, reversed_concern], audit_complete=True),
    )

    with pytest.raises(ValueError, match="conflicting accepted source-audit concern"):
        aggregate_source_audit_fragments_v22(review, (fragment,))


def test_fragment_aggregation_rejects_more_than_128_fragments_and_640_items() -> None:
    first = tuple(review_fragment(index, f"Item {index}.", final=False) for index in range(1, 129))
    terminal = review_fragment(128, "Item 128.", final=True)
    bypass = terminal.model_construct(**{**terminal.__dict__, "fragment_ordinal": 129})
    many = (*first, terminal, bypass)
    with pytest.raises(ValueError):
        aggregate_source_review_fragments_v22(many)


def test_review_aggregate_fingerprint_changes_with_exact_fragment_history() -> None:
    first = aggregate_source_review_fragments_v22((review_fragment(1, "First.", final=True),))
    second = aggregate_source_review_fragments_v22((review_fragment(1, "Changed.", final=True),))
    assert first.aggregate_fingerprint != second.aggregate_fingerprint
    assert envelope().case_fingerprint


def test_referee_aggregate_accepts_contextually_valid_nested_decision() -> None:
    review, audit = _bound_disputed_source_aggregates()
    disputes = build_referee_disputes_v22(envelope(), review, audit)
    decision = {
        "decision": "unresolved",
        "unresolved_reason": "SOURCE_GAP",
        "evidence_refs": [disputes[0].evidence[0].evidence_ref],
        "rationale": "The alternatives cannot be resolved.",
    }

    fragment = validate_referee_fragment_v22(disputes[0], decision, response_fingerprint="5" * 64)

    sealed = aggregate_referee_decisions_v22(disputes, (fragment,))
    assert sealed.fragments == (fragment,)

    forged = sealed.model_construct(**{**sealed.__dict__, "aggregate_fingerprint": "0" * 64})
    with pytest.raises(CompilationError, match="REFEREE_FRAGMENT_INVALID"):
        compile_baseline_v22(envelope(), review, audit, forged)


def test_disputed_accept_auditor_compiles_a_nonempty_v22_baseline() -> None:
    review, audit = _bound_disputed_source_aggregates()
    disputes = build_referee_disputes_v22(envelope(), review, audit)
    fragment = validate_referee_fragment_v22(
        disputes[0],
        {
            "decision": "accept_auditor",
            "unresolved_reason": None,
            "evidence_refs": [disputes[0].evidence[0].evidence_ref],
            "rationale": "The correction is supported.",
        },
        response_fingerprint="5" * 64,
    )

    baseline = compile_baseline_v22(
        envelope(), review, audit, aggregate_referee_decisions_v22(disputes, (fragment,))
    )

    assert [item.statement for item in baseline.requirements] == [
        "Operators must file unless small."
    ]


def test_v22_grade_conversion_reconciles_two_lanes_and_preserves_sensitivity() -> None:
    baseline = canonical_baseline()
    report = "The report covers requirement 1."
    aggregates = []
    for lane in (1, 2):
        batch = ordinary_grade_batches_v22(baseline, "A", lane)[0]
        fragment = validate_grade_fragment_v22(
            baseline,
            {
                "schema_version": "2.2",
                "anonymous_label": "A",
                "grader_lane": lane,
                "batch_ref": batch.batch_ref,
                "baseline_fingerprint": baseline.baseline_fingerprint,
                "report_fingerprint": hashlib.sha256(report.encode()).hexdigest(),
                "requirement_grades": [
                    {
                        "requirement_id": "REQ-0001",
                        "disposition": "met",
                        "report_passages": [report],
                        "rationale": "The report covers the requirement.",
                    }
                ],
                "rationale": "The batch is graded.",
            },
            report,
        )
        assert isinstance(fragment, OrdinaryGradeFragmentV22)
        aggregates.append(aggregate_grader_lane_v22(baseline, "A", lane, (fragment,), ()))
    reconciliation = reconcile_grader_lanes_v22(baseline, aggregates[0], aggregates[1])
    sensitivity = evaluate_outcome_sensitivity_v22(baseline, reconciliation)

    assert reconciliation.absolute_disposition == "PASS"
    assert sensitivity.absolute_disposition == "PASS"
    assert sensitivity.outcome_determinative_contested_ids == ()
    forged = aggregates[0].model_construct(
        **{**aggregates[0].__dict__, "aggregate_fingerprint": "0" * 64}
    )
    with pytest.raises(RubricValidationError, match="RECONCILIATION_INVALID"):
        reconcile_grader_lanes_v22(baseline, forged, aggregates[1])

    resealed = reconciliation.model_copy(
        update={
            "grader_aggregates": (forged, aggregates[1]),
            "reconciliation_fingerprint": "0" * 64,
        }
    )
    resealed = resealed.model_copy(
        update={
            "reconciliation_fingerprint": hashlib.sha256(
                canonical_json_bytes(
                    {
                        "anonymous_label": resealed.anonymous_label,
                        "absolute_disposition": resealed.absolute_disposition,
                        "reason_codes": resealed.reason_codes,
                        "grader_aggregates": resealed.grader_aggregates,
                    }
                )
            ).hexdigest()
        }
    )
    with pytest.raises(RubricValidationError, match="RECONCILIATION_INVALID"):
        evaluate_outcome_sensitivity_v22(baseline, resealed)


@pytest.mark.parametrize(
    ("ordinary_count", "ordinary", "alternatives", "expected"),
    [
        (0, "met", (("met", "met"),), "PASS"),
        (0, "met", (("not_met", "not_met"),), "FAIL"),
        (1, "met", (("met", "met"),), "PASS"),
        (1, "not_met", (("met", "met"),), "FAIL"),
    ],
)
def test_outcome_sensitivity_scores_complete_stable_alternative_worlds(
    ordinary_count: int,
    ordinary: str,
    alternatives: tuple[tuple[str, str], ...],
    expected: str,
) -> None:
    baseline = _alternative_world_baseline(
        ordinary_count=ordinary_count, contested_count=len(alternatives)
    )

    sensitivity = _alternative_world_sensitivity(
        baseline, ordinary=ordinary, contested=alternatives
    )

    assert sensitivity.absolute_disposition == expected
    assert sensitivity.outcome_determinative_contested_ids == ()


@pytest.mark.parametrize(
    ("alternatives", "reason"),
    [
        ((("met", "not_met"),), "OUTCOME_SENSITIVE_BASELINE_DISPUTE"),
        ((("uncertain", "uncertain"),), "BASELINE_EVIDENCE_INSUFFICIENT"),
    ],
)
def test_outcome_sensitivity_keeps_substantive_inconclusive_alternative_worlds(
    alternatives: tuple[tuple[str, str], ...], reason: str
) -> None:
    baseline = _alternative_world_baseline(
        ordinary_count=0, contested_count=len(alternatives)
    )

    sensitivity = _alternative_world_sensitivity(baseline, contested=alternatives)

    assert sensitivity.absolute_disposition == "INCONCLUSIVE"
    assert sensitivity.reason_codes == (reason,)


def test_outcome_sensitivity_scores_multi_dispute_worlds_as_a_combination() -> None:
    baseline = _alternative_world_baseline(ordinary_count=3, contested_count=2)

    sensitivity = _alternative_world_sensitivity(
        baseline,
        contested=(("met", "partially_met"), ("met", "partially_met")),
    )

    assert sensitivity.absolute_disposition == "INCONCLUSIVE"
    assert sensitivity.reason_codes == ("OUTCOME_SENSITIVE_BASELINE_DISPUTE",)
    assert sensitivity.outcome_determinative_contested_ids == ("CONT-0001", "CONT-0002")


def test_v22_reconciliation_accepts_native_rubric_without_v21_narrowing() -> None:
    baseline = canonical_baseline()
    report = "The report covers requirement 1."
    aggregates = []
    for lane in (1, 2):
        batch = ordinary_grade_batches_v22(baseline, "A", lane)[0]
        fragment = validate_grade_fragment_v22(
            baseline,
            {
                "schema_version": "2.2",
                "anonymous_label": "A",
                "grader_lane": lane,
                "batch_ref": batch.batch_ref,
                "baseline_fingerprint": baseline.baseline_fingerprint,
                "report_fingerprint": hashlib.sha256(report.encode()).hexdigest(),
                "requirement_grades": [
                    {
                        "requirement_id": "REQ-0001",
                        "disposition": "met",
                        "report_passages": [report],
                        "rationale": "Covered.",
                    }
                ],
                "rationale": "The batch is graded.",
            },
            report,
        )
        assert isinstance(fragment, OrdinaryGradeFragmentV22)
        aggregates.append(aggregate_grader_lane_v22(baseline, "A", lane, (fragment,), ()))

    reconciled = reconcile_grader_lanes_v22(
        baseline,
        aggregates[0],
        aggregates[1],
        RUBRIC_V22.model_copy(update={"material_unsupported_assertions_allowed": 1}),
    )
    assert reconciled.absolute_disposition == "PASS"
    with pytest.raises(RubricValidationError, match="RECONCILIATION_INVALID"):
        reconcile_grader_lanes_v22(baseline, aggregates[0], aggregates[1], RUBRIC_V21)
    invalid = RUBRIC_V22.model_construct(**{**RUBRIC_V22.__dict__, "version": "attorney-eval-v2.1"})
    with pytest.raises(RubricValidationError, match="RECONCILIATION_INVALID"):
        reconcile_grader_lanes_v22(baseline, aggregates[0], aggregates[1], invalid)


def test_ordinary_batches_reject_641_requirements_before_batch_129() -> None:
    baseline = canonical_baseline(641)

    with pytest.raises(RubricValidationError, match="ORDINARY_GRADE_ITEM_LIMIT_EXCEEDED"):
        ordinary_grade_batches_v22(baseline, "A", 1)


def test_compiler_boundaries_reject_a_stale_canonical_baseline_fingerprint() -> None:
    baseline = canonical_baseline()
    stale = baseline.model_copy(
        update={"requirements": baseline.requirements, "baseline_fingerprint": "0" * 64}
    )
    with pytest.raises(RubricValidationError, match="BASELINE_INVALID"):
        ordinary_grade_batches_v22(stale, "A", 1)

    batch = ordinary_grade_batches_v22(baseline, "A", 1)[0]
    with pytest.raises(ValueError, match="canonical baseline"):
        build_ordinary_grade_request_v22(
            stale, batch, "A", 1, "The report covers requirement 1.", {"rule-1": "source"}
        )


def test_nested_constructed_boolean_baseline_values_reject_all_grade_boundaries() -> None:
    baseline = canonical_baseline(2)
    forged_requirement = baseline.requirements[1].model_construct(
        **{**baseline.requirements[1].__dict__, "canonical_order": True}
    )
    forged = baseline.model_construct(
        **{**baseline.__dict__, "requirements": (baseline.requirements[0], forged_requirement)}
    )
    batch = ordinary_grade_batches_v22(baseline, "A", 1)[0]
    report = "The report covers requirements 1 and 2."
    fragment = validate_grade_fragment_v22(
        baseline,
        {
            "schema_version": "2.2",
            "anonymous_label": "A",
            "grader_lane": 1,
            "batch_ref": batch.batch_ref,
            "baseline_fingerprint": baseline.baseline_fingerprint,
            "report_fingerprint": hashlib.sha256(report.encode()).hexdigest(),
            "requirement_grades": [
                {
                    "requirement_id": "REQ-0001",
                    "disposition": "met",
                    "report_passages": [report],
                    "rationale": "Covered.",
                },
                {
                    "requirement_id": "REQ-0002",
                    "disposition": "met",
                    "report_passages": [report],
                    "rationale": "Covered.",
                },
            ],
            "rationale": "The batch is graded.",
        },
        report,
    )
    assert isinstance(fragment, OrdinaryGradeFragmentV22)
    first = aggregate_grader_lane_v22(baseline, "A", 1, (fragment,), ())
    second_fragment = fragment.model_copy(update={"grader_lane": 2, "batch_ref": "GB-A-2-0001"})
    second = aggregate_grader_lane_v22(baseline, "A", 2, (second_fragment,), ())
    reconciliation = reconcile_grader_lanes_v22(baseline, first, second)

    with pytest.raises(RubricValidationError, match="BASELINE_INVALID"):
        verify_canonical_baseline_v22(forged)
    with pytest.raises(RubricValidationError, match="BASELINE_INVALID"):
        ordinary_grade_batches_v22(forged, "A", 1)
    with pytest.raises(ValueError, match="canonical baseline"):
        build_ordinary_grade_request_v22(forged, batch, "A", 1, report, {"rule-1": "source"})
    with pytest.raises(RubricValidationError, match="RECONCILIATION_INVALID"):
        reconcile_grader_lanes_v22(forged, first, second)
    with pytest.raises(RubricValidationError, match="RECONCILIATION_INVALID"):
        evaluate_outcome_sensitivity_v22(forged, reconciliation)


def test_constructed_boolean_rubric_values_reject_request_reconcile_and_sensitivity() -> None:
    baseline = canonical_baseline()
    report = "The report covers requirement 1."
    batch = ordinary_grade_batches_v22(baseline, "A", 1)[0]
    fragment = validate_grade_fragment_v22(
        baseline,
        {
            "schema_version": "2.2",
            "anonymous_label": "A",
            "grader_lane": 1,
            "batch_ref": batch.batch_ref,
            "baseline_fingerprint": baseline.baseline_fingerprint,
            "report_fingerprint": hashlib.sha256(report.encode()).hexdigest(),
            "requirement_grades": [
                {
                    "requirement_id": "REQ-0001",
                    "disposition": "met",
                    "report_passages": [report],
                    "rationale": "Covered.",
                }
            ],
            "rationale": "The batch is graded.",
        },
        report,
    )
    assert isinstance(fragment, OrdinaryGradeFragmentV22)
    first = aggregate_grader_lane_v22(baseline, "A", 1, (fragment,), ())
    second_fragment = fragment.model_copy(update={"grader_lane": 2, "batch_ref": "GB-A-2-0001"})
    second = aggregate_grader_lane_v22(baseline, "A", 2, (second_fragment,), ())
    reconciliation = reconcile_grader_lanes_v22(baseline, first, second)
    forged = RUBRIC_V22.model_construct(
        **{
            **RUBRIC_V22.__dict__,
            "importance_weights": {item: True for item in RUBRIC_V22.importance_weights},
            "critical_recall_floor": True,
            "weighted_coverage_floor": False,
            "material_unsupported_assertions_allowed": True,
        }
    )
    with pytest.raises(ValueError, match="rubric"):
        build_ordinary_grade_request_v22(
            baseline, batch, "A", 1, report, {"rule-1": "source"}, forged
        )
    with pytest.raises(RubricValidationError, match="RECONCILIATION_INVALID"):
        reconcile_grader_lanes_v22(baseline, first, second, forged)
    with pytest.raises(RubricValidationError, match="RECONCILIATION_INVALID"):
        evaluate_outcome_sensitivity_v22(baseline, reconciliation, forged)


def test_constructed_boolean_grade_lane_does_not_normalize_at_fragment_validation() -> None:
    baseline = canonical_baseline()
    report = "The report covers requirement 1."
    batch = ordinary_grade_batches_v22(baseline, "A", 1)[0]
    valid = validate_grade_fragment_v22(
        baseline,
        {
            "schema_version": "2.2",
            "anonymous_label": "A",
            "grader_lane": 1,
            "batch_ref": batch.batch_ref,
            "baseline_fingerprint": baseline.baseline_fingerprint,
            "report_fingerprint": hashlib.sha256(report.encode()).hexdigest(),
            "requirement_grades": [
                {
                    "requirement_id": "REQ-0001",
                    "disposition": "met",
                    "report_passages": [report],
                    "rationale": "Covered.",
                }
            ],
            "rationale": "The batch is graded.",
        },
        report,
    )
    forged = valid.model_construct(**{**valid.__dict__, "grader_lane": True})
    with pytest.raises(RubricValidationError, match="GRADE_FRAGMENT_INVALID"):
        validate_grade_fragment_v22(baseline, forged, report)


def test_constructed_boolean_grader_aggregate_lane_rejects_reconciliation() -> None:
    baseline = canonical_baseline()
    report = "The report covers requirement 1."
    batch = ordinary_grade_batches_v22(baseline, "A", 1)[0]
    fragment = validate_grade_fragment_v22(
        baseline,
        {
            "schema_version": "2.2",
            "anonymous_label": "A",
            "grader_lane": 1,
            "batch_ref": batch.batch_ref,
            "baseline_fingerprint": baseline.baseline_fingerprint,
            "report_fingerprint": hashlib.sha256(report.encode()).hexdigest(),
            "requirement_grades": [
                {
                    "requirement_id": "REQ-0001",
                    "disposition": "met",
                    "report_passages": [report],
                    "rationale": "Covered.",
                }
            ],
            "rationale": "The batch is graded.",
        },
        report,
    )
    assert isinstance(fragment, OrdinaryGradeFragmentV22)
    first = aggregate_grader_lane_v22(baseline, "A", 1, (fragment,), ())
    second_fragment = fragment.model_copy(update={"grader_lane": 2, "batch_ref": "GB-A-2-0001"})
    second = aggregate_grader_lane_v22(baseline, "A", 2, (second_fragment,), ())
    forged = first.model_construct(**{**first.__dict__, "grader_lane": True})
    with pytest.raises(RubricValidationError, match="RECONCILIATION_INVALID"):
        reconcile_grader_lanes_v22(baseline, forged, second)


def test_sensitivity_rejects_a_fully_resealed_fabricated_reconciliation() -> None:
    baseline = canonical_baseline()
    report = "The report covers requirement 1."
    aggregates = []
    for lane in (1, 2):
        batch = ordinary_grade_batches_v22(baseline, "A", lane)[0]
        fragment = validate_grade_fragment_v22(
            baseline,
            {
                "schema_version": "2.2",
                "anonymous_label": "A",
                "grader_lane": lane,
                "batch_ref": batch.batch_ref,
                "baseline_fingerprint": baseline.baseline_fingerprint,
                "report_fingerprint": hashlib.sha256(report.encode()).hexdigest(),
                "requirement_grades": [
                    {
                        "requirement_id": "REQ-0001",
                        "disposition": "met",
                        "report_passages": [report],
                        "rationale": "Covered.",
                    }
                ],
                "rationale": "The batch is graded.",
            },
            report,
        )
        assert isinstance(fragment, OrdinaryGradeFragmentV22)
        aggregates.append(aggregate_grader_lane_v22(baseline, "A", lane, (fragment,), ()))
    reconciliation = reconcile_grader_lanes_v22(baseline, aggregates[0], aggregates[1])
    fabricated = reconciliation.model_copy(
        update={
            "absolute_disposition": AbsoluteDispositionV2.FAIL,
            "reason_codes": ("FABRICATED",),
        }
    )
    fabricated = fabricated.model_copy(
        update={
            "reconciliation_fingerprint": hashlib.sha256(
                canonical_json_bytes(
                    {
                        key: value
                        for key, value in fabricated.model_dump(mode="json").items()
                        if key != "reconciliation_fingerprint"
                    }
                )
            ).hexdigest()
        }
    )
    with pytest.raises(RubricValidationError, match="RECONCILIATION_INVALID"):
        evaluate_outcome_sensitivity_v22(baseline, fabricated)


@pytest.mark.parametrize("forged_ordinal", [True, "1", 1.0], ids=("bool", "str", "float"))
def test_source_aggregation_boundaries_reject_constructed_noninteger_ordinals(
    forged_ordinal: object,
) -> None:
    review = review_fragment(1, "First.", final=True)
    forged_review = AcceptedSourceReviewFragmentV22.model_construct(
        **{**review.__dict__, "fragment_ordinal": forged_ordinal}
    )
    with pytest.raises(ValueError, match="source-review"):
        aggregate_source_review_fragments_v22((forged_review,))

    sealed_review = aggregate_source_review_fragments_v22((review,))
    audit = AcceptedSourceAuditFragmentV22(
        fragment_ordinal=1,
        request_fingerprint="3" * 64,
        response_fingerprint="4" * 64,
        payload=SourceAuditFragmentV22(concerns=(), audit_complete=True),
    )
    forged_audit = AcceptedSourceAuditFragmentV22.model_construct(
        **{**audit.__dict__, "fragment_ordinal": forged_ordinal}
    )
    with pytest.raises(ValueError, match="source-audit"):
        aggregate_source_audit_fragments_v22(sealed_review, (forged_audit,))


def _valid_lane_pair() -> tuple[CanonicalBaselineV22, str, GraderAggregateV22, GraderAggregateV22]:
    baseline = canonical_baseline()
    report = "The report covers requirement 1."
    aggregates = []
    for lane in (1, 2):
        batch = ordinary_grade_batches_v22(baseline, "A", lane)[0]
        fragment = validate_grade_fragment_v22(
            baseline,
            {
                "schema_version": "2.2",
                "anonymous_label": "A",
                "grader_lane": lane,
                "batch_ref": batch.batch_ref,
                "baseline_fingerprint": baseline.baseline_fingerprint,
                "report_fingerprint": hashlib.sha256(report.encode()).hexdigest(),
                "requirement_grades": [
                    {
                        "requirement_id": "REQ-0001",
                        "disposition": "met",
                        "report_passages": [report],
                        "rationale": "Covered.",
                    }
                ],
                "rationale": "The batch is graded.",
            },
            report,
        )
        assert isinstance(fragment, OrdinaryGradeFragmentV22)
        aggregates.append(aggregate_grader_lane_v22(baseline, "A", lane, (fragment,), ()))
    return baseline, report, aggregates[0], aggregates[1]


def _aggregate_with_nested_boolean_lane(aggregate: GraderAggregateV22) -> GraderAggregateV22:
    fragment = aggregate.ordinary_fragments[0]
    forged_fragment = fragment.model_construct(**{**fragment.__dict__, "grader_lane": True})
    return aggregate.model_construct(
        **{**aggregate.__dict__, "ordinary_fragments": (forged_fragment,)}
    )


@pytest.mark.parametrize("boundary", ["aggregate", "reconcile", "sensitivity"])
def test_nested_grade_fragment_boolean_lane_rejects_every_downstream_boundary(
    boundary: str,
) -> None:
    baseline, report, first, second = _valid_lane_pair()
    forged_first = _aggregate_with_nested_boolean_lane(first)

    if boundary == "aggregate":
        with pytest.raises(RubricValidationError):
            aggregate_grader_lane_v22(baseline, "A", 1, forged_first.ordinary_fragments, ())
    elif boundary == "reconcile":
        with pytest.raises(RubricValidationError, match="RECONCILIATION_INVALID"):
            reconcile_grader_lanes_v22(baseline, forged_first, second)
    else:
        reconciliation = reconcile_grader_lanes_v22(baseline, first, second)
        forged_reconciliation = reconciliation.model_construct(
            **{
                **reconciliation.__dict__,
                "grader_aggregates": (forged_first, second),
            }
        )
        with pytest.raises(RubricValidationError, match="RECONCILIATION_INVALID"):
            evaluate_outcome_sensitivity_v22(baseline, forged_reconciliation)
    assert report


@pytest.mark.parametrize("grader_lane", [True, "1", 1.0], ids=("bool", "str", "float"))
def test_lane_aggregation_rejects_noninteger_controller_coordinates(
    grader_lane: object,
) -> None:
    baseline, _, first, _ = _valid_lane_pair()
    with pytest.raises(ValueError):
        aggregate_grader_lane_v22(
            baseline,
            "A",
            grader_lane,  # type: ignore[arg-type]
            first.ordinary_fragments,
            (),
        )


def _dispute_with_boolean_source_offset(
    dispute: RefereeDisputeV22,
) -> RefereeDisputeV22:
    evidence = dispute.evidence[0]
    passage = evidence.passage.model_construct(**{**evidence.passage.__dict__, "start_char": True})
    forged_evidence = evidence.model_construct(**{**evidence.__dict__, "passage": passage})
    forged = dispute.model_construct(
        **{**dispute.__dict__, "evidence": (forged_evidence,), "dispute_fingerprint": "0" * 64}
    )
    from regulatory_harvest.evaluation.attorney_v22_compiler import (
        referee_dispute_fingerprint_v22,
    )

    with pytest.raises(ValueError, match="referee dispute"):
        referee_dispute_fingerprint_v22(forged)
    raw = forged.model_dump(mode="json")
    raw_fingerprint = hashlib.sha256(
        canonical_json_bytes(
            {
                "schema_version": "2.2",
                "case_fingerprint": raw["case_fingerprint"],
                "dispute_id": raw["dispute_id"],
                "material_dispute": raw["material_dispute"],
                "evidence": raw["evidence"],
            }
        )
    ).hexdigest()
    return forged.model_construct(
        **{
            **forged.__dict__,
            "dispute_fingerprint": raw_fingerprint,
        }
    )


@pytest.mark.parametrize("boundary", ["fragment", "aggregate", "baseline"])
def test_referee_boolean_passage_offsets_reject_every_downstream_boundary(boundary: str) -> None:
    review, audit = _bound_disputed_source_aggregates()
    disputes = build_referee_disputes_v22(envelope(), review, audit)
    valid_fragment = validate_referee_fragment_v22(
        disputes[0],
        {
            "decision": "unresolved",
            "unresolved_reason": "SOURCE_GAP",
            "evidence_refs": [disputes[0].evidence[0].evidence_ref],
            "rationale": "The source does not resolve the alternatives.",
        },
        response_fingerprint="5" * 64,
    )
    forged_dispute = _dispute_with_boolean_source_offset(disputes[0])

    if boundary == "fragment":
        with pytest.raises(CompilationError, match="REFEREE_FRAGMENT_INVALID"):
            validate_referee_fragment_v22(
                forged_dispute,
                valid_fragment.decision.model_dump(mode="json"),
                response_fingerprint="5" * 64,
            )
    elif boundary == "aggregate":
        forged_fragment = AcceptedRefereeFragmentV22.model_construct(
            **{
                **valid_fragment.__dict__,
                "dispute_fingerprint": forged_dispute.dispute_fingerprint,
            }
        )
        with pytest.raises(CompilationError):
            aggregate_referee_decisions_v22((forged_dispute,), (forged_fragment,))
    else:
        aggregate = aggregate_referee_decisions_v22(disputes, (valid_fragment,))
        forged_aggregate = aggregate.model_construct(
            **{
                **aggregate.__dict__,
                "fragments": (
                    valid_fragment.model_construct(
                        **{
                            **valid_fragment.__dict__,
                            "dispute_fingerprint": forged_dispute.dispute_fingerprint,
                        }
                    ),
                ),
            }
        )
        with pytest.raises(CompilationError):
            compile_baseline_v22(envelope(), review, audit, forged_aggregate)


@pytest.mark.parametrize(
    ("mutation", "value"),
    [
        ("grader_lane", True),
        ("grader_lane", "1"),
        ("grader_lane", 1.0),
        ("ambiguity_disposition", "not-a-disposition"),
    ],
)
def test_contested_grade_validation_rejects_constructed_scalar_and_enum_bypasses(
    mutation: str,
    value: object,
) -> None:
    from test_attorney_v22_requests import _contested_baseline

    baseline, contested = _contested_baseline()
    report = "The report acknowledges the dispute."
    alternative = {
        "disposition": "uncertain",
        "report_passages": [report],
        "rationale": "The report does not resolve the dispute.",
    }
    raw: dict[str, object] = {
        "schema_version": "2.2",
        "anonymous_label": "A",
        "grader_lane": 1,
        "contested_requirement_id": contested.contested_requirement_id,
        "baseline_fingerprint": baseline.baseline_fingerprint,
        "report_fingerprint": hashlib.sha256(report.encode()).hexdigest(),
        "reviewer_alternative_grade": alternative,
        "auditor_alternative_grade": alternative,
        "ambiguity_disposition": "acknowledged",
        "rationale": "The report acknowledges the ambiguity.",
    }
    raw[mutation] = value
    forged = ContestedGradeFragmentV22.model_construct(**raw)

    with pytest.raises(RubricValidationError, match="GRADE_FRAGMENT_INVALID"):
        validate_grade_fragment_v22(baseline, forged, report)


def test_rejected_raw_wire_values_emit_no_warning_or_value_text() -> None:
    import warnings

    rejected = "REJECTED-RAW-WIRE-SECRET"
    valid_proposal = review_fragment(1, "First.", final=True).payload.proposals[0]
    invalid_proposal = valid_proposal.model_construct(
        **{
            **valid_proposal.__dict__,
            "kind": rejected,
        }
    )
    fragment = review_fragment(1, "First.", final=True)
    forged_payload = fragment.payload.model_construct(
        **{**fragment.payload.__dict__, "proposals": (invalid_proposal,)}
    )
    forged = fragment.model_construct(**{**fragment.__dict__, "payload": forged_payload})

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        with pytest.raises(ValueError) as error:
            aggregate_source_review_fragments_v22((forged,))
    assert rejected not in str(error.value)


@pytest.mark.parametrize("aggregate_kind", ["review", "audit"])
def test_downstream_source_boundaries_reject_forged_aggregate_seals(
    aggregate_kind: str,
) -> None:
    review, audit = _bound_source_aggregates()
    if aggregate_kind == "review":
        review = review.model_copy(update={"aggregate_fingerprint": "f" * 64})
        with pytest.raises(ValueError, match="source-review aggregate"):
            build_source_audit_fragment_request_v22(envelope(), review, (), fragment_ordinal=1)
    else:
        audit = audit.model_copy(update={"aggregate_fingerprint": "f" * 64})

    with pytest.raises(CompilationError):
        build_referee_disputes_v22(envelope(), review, audit)

    referee = aggregate_referee_decisions_v22((), ())
    with pytest.raises(CompilationError):
        compile_baseline_v22(envelope(), review, audit, referee)


def test_downstream_source_boundaries_reject_cross_case_aggregate_histories() -> None:
    from regulatory_harvest.evaluation.attorney_admission import freeze_case

    review, audit = _bound_source_aggregates()
    changed = envelope().case.model_copy(update={"case_id": "other-v22-aggregate-case"})
    other = freeze_case(changed, seed_hex="1" * 64)

    with pytest.raises(ValueError, match="source-review aggregate"):
        build_source_audit_fragment_request_v22(other, review, (), fragment_ordinal=1)
    with pytest.raises(CompilationError):
        build_referee_disputes_v22(other, review, audit)
    with pytest.raises(CompilationError):
        compile_baseline_v22(other, review, audit, aggregate_referee_decisions_v22((), ()))


@pytest.mark.parametrize("aggregate_kind", ["review", "audit"])
def test_source_aggregate_verifiers_reject_resealed_ungrounded_passages(
    aggregate_kind: str,
) -> None:
    review, audit = _bound_disputed_source_aggregates()
    if aggregate_kind == "review":
        fragment = review.fragments[0]
        invalid_proposal = fragment.payload.proposals[0].model_copy(
            update={"passages": ({"source_id": "rule-1", "quote": "not present in frozen source"},)}
        )
        invalid_fragment = fragment.model_copy(
            update={
                "payload": fragment.payload.model_copy(update={"proposals": (invalid_proposal,)})
            }
        )
        resealed_review = aggregate_source_review_fragments_v22((invalid_fragment,))
        with pytest.raises(CompilationError, match="SOURCE_REVIEW_AGGREGATE_INVALID"):
            verify_source_review_aggregate_v22(envelope(), resealed_review)
    else:
        fragment = audit.fragments[0]
        invalid_concern = fragment.payload.concerns[0].model_copy(
            update={"passages": ({"source_id": "rule-1", "quote": "not present in frozen source"},)}
        )
        invalid_fragment = fragment.model_copy(
            update={"payload": fragment.payload.model_copy(update={"concerns": (invalid_concern,)})}
        )
        resealed_audit = aggregate_source_audit_fragments_v22(review, (invalid_fragment,))
        with pytest.raises(CompilationError, match="SOURCE_AUDIT_AGGREGATE_INVALID"):
            verify_source_audit_aggregate_v22(envelope(), review, resealed_audit)


def test_max_source_aggregate_verification_builds_each_request_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import regulatory_harvest.evaluation.attorney_v22_requests as requests

    review, audit = _max_bound_source_aggregates()
    real_new_request = requests._new_request_v22
    calls = 0

    def counted_new_request(*args: object, **kwargs: object) -> object:
        nonlocal calls
        calls += 1
        if calls > 256:
            raise AssertionError("accepted-history request replay was amplified")
        return real_new_request(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(requests, "_new_request_v22", counted_new_request)

    try:
        verified = verify_source_audit_aggregate_v22(envelope(), review, audit)
    finally:
        assert calls <= 256
    assert verified == audit
    assert calls == 256

    calls = 0
    final_request = build_source_audit_fragment_request_v22(
        envelope(), review, audit.fragments[:-1], fragment_ordinal=128
    )
    assert final_request.request_fingerprint == audit.fragments[-1].request_fingerprint
    assert calls == 256


@pytest.mark.parametrize("boundary", ["referee", "baseline"])
def test_downstream_source_boundaries_verify_each_history_once(
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
) -> None:
    import regulatory_harvest.evaluation.attorney_v22_requests as requests

    review, audit = _bound_source_aggregates()
    real_new_request = requests._new_request_v22
    calls = 0

    def counted_new_request(*args: object, **kwargs: object) -> object:
        nonlocal calls
        calls += 1
        return real_new_request(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(requests, "_new_request_v22", counted_new_request)

    if boundary == "referee":
        assert build_referee_disputes_v22(envelope(), review, audit) == ()
    else:
        assert compile_baseline_v22(
            envelope(), review, audit, aggregate_referee_decisions_v22((), ())
        )
    assert calls == 2


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("decision", _ForeignDecision.ACCEPT_REVIEWER),
        ("rationale", _ForeignDecision.RATIONALE),
    ],
    ids=("decision-enum", "rationale-enum"),
)
def test_referee_decision_is_native_v22_strict_before_legacy_conversion(
    field_name: str, value: object
) -> None:
    from test_attorney_v22_requests import referee_inventory

    (dispute,) = referee_inventory(1)
    decision: dict[str, object] = {
        "decision": "accept_reviewer",
        "unresolved_reason": None,
        "evidence_refs": [dispute.evidence[0].evidence_ref],
        "rationale": "The evidence supports the reviewer.",
    }
    decision[field_name] = value

    with pytest.raises(CompilationError, match="REFEREE_FRAGMENT_INVALID"):
        validate_referee_fragment_v22(
            dispute,
            decision,
            response_fingerprint="5" * 64,
        )


def test_rubric_rejects_unrelated_enum_keys_but_accepts_expected_enum_keys() -> None:
    from regulatory_harvest.evaluation.attorney_v2_models import ImportanceV2

    baseline, _, first, second = _valid_lane_pair()
    expected = RUBRIC_V22.model_construct(
        **{
            **RUBRIC_V22.__dict__,
            "importance_weights": {
                ImportanceV2.CRITICAL: 3,
                ImportanceV2.MATERIAL: 2,
                ImportanceV2.SUPPORTING: 1,
            },
        }
    )
    assert reconcile_grader_lanes_v22(baseline, first, second, expected)

    foreign = RUBRIC_V22.model_construct(
        **{
            **RUBRIC_V22.__dict__,
            "importance_weights": {
                _ForeignImportance.CRITICAL: 3,
                _ForeignImportance.MATERIAL: 2,
                _ForeignImportance.SUPPORTING: 1,
            },
        }
    )
    with pytest.raises(RubricValidationError, match="RECONCILIATION_INVALID"):
        reconcile_grader_lanes_v22(baseline, first, second, foreign)


_PolicyCategories = tuple[str, ...]


@dataclass(frozen=True)
class _CanonicalCallTarget:
    target: str


@dataclass(frozen=True)
class _InvalidCallTarget:
    reason: str
    ast_kind: str


_CallTargetClassification = _CanonicalCallTarget | _InvalidCallTarget

_MAX_CALL_ATTRIBUTE_DEPTH = 3


def _classify_call_target(node: object) -> _CallTargetClassification:
    """Accept only a direct name or a short name-rooted attribute chain."""
    import ast

    if isinstance(node, ast.Name):
        return _CanonicalCallTarget(node.id)
    if not isinstance(node, ast.Attribute):
        kind = type(node).__name__
        return _InvalidCallTarget(f"dynamic-call-target:{kind}", kind)
    attributes: list[str] = []
    current: ast.expr = node
    while isinstance(current, ast.Attribute):
        attributes.append(current.attr)
        current = current.value
    if not isinstance(current, ast.Name):
        kind = type(current).__name__
        return _InvalidCallTarget(f"attribute-call-target-root:{kind}", kind)
    if len(attributes) > _MAX_CALL_ATTRIBUTE_DEPTH:
        return _InvalidCallTarget("call-target-depth", "Attribute")
    return _CanonicalCallTarget(".".join((current.id, *reversed(attributes))))


def test_task3_canonical_call_target_classifier_is_total_and_bounded() -> None:
    import ast

    cases = {
        "helper(value)": _CanonicalCallTarget("helper"),
        "value.model_dump(mode='json')": _CanonicalCallTarget("value.model_dump"),
        "value.correction.statement.split()": _CanonicalCallTarget(
            "value.correction.statement.split"
        ),
        "(chosen := helper)(value)": _InvalidCallTarget(
            "dynamic-call-target:NamedExpr", "NamedExpr"
        ),
        "(first if enabled else second)(value)": _InvalidCallTarget(
            "dynamic-call-target:IfExp", "IfExp"
        ),
        "registry[provider](value)": _InvalidCallTarget(
            "dynamic-call-target:Subscript", "Subscript"
        ),
        "factory()(value)": _InvalidCallTarget("dynamic-call-target:Call", "Call"),
        "factory().first.second.third.fourth()": _InvalidCallTarget(
            "attribute-call-target-root:Call", "Call"
        ),
        "root.first.second.third.fourth()": _InvalidCallTarget("call-target-depth", "Attribute"),
    }
    for source, expected in cases.items():
        call = ast.parse(source).body[0].value
        assert isinstance(call, ast.Call)
        assert _classify_call_target(call.func) == expected


@pytest.mark.parametrize(
    ("ast_kind", "expression"),
    (
        ("Constant", '("text")(value)'),
        ("Tuple", "(helper,)(value)"),
        ("List", "[helper](value)"),
        ("Set", "{helper}(value)"),
        ("Dict", "{0: helper}(value)"),
        ("ListComp", "[item for item in providers](value)"),
        ("SetComp", "{item for item in providers}(value)"),
        ("DictComp", "{item: item for item in providers}(value)"),
        ("GeneratorExp", "(item for item in providers)(value)"),
        ("Lambda", "(lambda item: item)(value)"),
        ("BoolOp", "(first or second)(value)"),
        ("BinOp", "(first + second)(value)"),
        ("UnaryOp", "(+provider)(value)"),
        ("Compare", "(left == right)(value)"),
        ("JoinedStr", 'f"{provider}"(value)'),
    ),
)
def test_task3_canonical_call_target_rejects_every_parser_corpus_kind(
    ast_kind: str, expression: str
) -> None:
    import ast

    call = ast.parse(expression).body[0].value
    assert isinstance(call, ast.Call)
    assert type(call.func).__name__ == ast_kind
    assert _classify_call_target(call.func) == _InvalidCallTarget(
        f"dynamic-call-target:{ast_kind}", ast_kind
    )


_Task3Call = tuple[str, str, str, _PolicyCategories, str]
_Task3Import = tuple[
    str,
    str,
    str,
    str,
    int,
    str,
    str,
    str,
    _PolicyCategories,
    str,
]
_Task3Definition = tuple[str, str, str, str]
_Task3SimpleSubscript = tuple[str, str, str, str]
_Task3Violation = tuple[str, str, str, str, str]


@dataclass(frozen=True)
class _Task3SourcePolicy:
    """Development-only syntax findings and human-review drift inventories."""

    calls: Counter[_Task3Call]
    imports: Counter[_Task3Import]
    definitions: Counter[_Task3Definition]
    simple_subscripts: Counter[_Task3SimpleSubscript]
    prohibited: Counter[_Task3Violation]


_FORBIDDEN_REFLECTIVE_NAMES = frozenset(
    {
        "getattr",
        "setattr",
        "delattr",
        "globals",
        "locals",
        "vars",
        "eval",
        "exec",
        "compile",
        "__import__",
        "__builtins__",
        "__dict__",
        "__getattribute__",
        "__getattr__",
        "__setattr__",
        "__delattr__",
        "attrgetter",
        "itemgetter",
        "methodcaller",
        "import_module",
    }
)
_FORBIDDEN_REFLECTIVE_MODULES = frozenset({"builtins", "operator", "importlib"})
_DENIED_REFLECTIVE_PROVIDER_SYMBOLS = (
    frozenset({"attrgetter", "itemgetter", "methodcaller", "import_module"})
    | _FORBIDDEN_REFLECTIVE_NAMES
)


def _scan_task3_source_policy(source: str, filename: str) -> _Task3SourcePolicy:
    """Scan source syntax only; never resolve names or touch evaluator state."""
    import ast
    from pathlib import Path

    tree = ast.parse(source, filename=filename)
    basename = Path(filename).name
    parents: dict[ast.AST, ast.AST] = {}
    paths: dict[ast.AST, str] = {tree: "Module"}

    def index_tree(node: ast.AST) -> None:
        for field, value in ast.iter_fields(node):
            if isinstance(value, ast.AST):
                parents[value] = node
                paths[value] = f"{paths[node]}.{field}"
                index_tree(value)
            elif isinstance(value, list):
                for ordinal, item in enumerate(value):
                    if isinstance(item, ast.AST):
                        parents[item] = node
                        paths[item] = f"{paths[node]}.{field}[{ordinal}]"
                        index_tree(item)

    index_tree(tree)

    scope_ids: dict[ast.AST, str] = {tree: "<module>#1"}
    scope_counts: Counter[tuple[str, str, str]] = Counter()

    def scope_child(parent: str, kind: str, name: str) -> str:
        key = (parent, kind, name)
        scope_counts[key] += 1
        return f"{parent}::{name}#{scope_counts[key]}"

    class _SyntacticOwnerIndexer(ast.NodeVisitor):
        def __init__(self) -> None:
            self.stack = ["<module>#1"]

        @property
        def current(self) -> str:
            return self.stack[-1]

        def _definition(self, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) -> None:
            identity = scope_child(self.current, type(node).__name__, node.name)
            scope_ids[node] = identity
            self.stack.append(identity)
            self.generic_visit(node)
            self.stack.pop()

        visit_FunctionDef = _definition
        visit_AsyncFunctionDef = _definition
        visit_ClassDef = _definition

        def visit_Lambda(self, node: ast.Lambda) -> None:
            identity = scope_child(self.current, "Lambda", "<lambda>")
            scope_ids[node] = identity
            self.stack.append(identity)
            self.generic_visit(node)
            self.stack.pop()

        def _comprehension(self, node: ast.AST) -> None:
            kind = type(node).__name__
            identity = scope_child(self.current, kind, f"<{kind}>")
            scope_ids[node] = identity
            self.stack.append(identity)
            self.generic_visit(node)
            self.stack.pop()

        visit_ListComp = _comprehension
        visit_SetComp = _comprehension
        visit_DictComp = _comprehension
        visit_GeneratorExp = _comprehension

    _SyntacticOwnerIndexer().visit(tree)

    def nearest_owner(node: ast.AST) -> str:
        current: ast.AST | None = node
        while current is not None:
            if current in scope_ids:
                return scope_ids[current]
            current = parents.get(current)
        raise AssertionError("AST node has no syntactic owner")

    def stable_dump(node: ast.AST) -> str:
        # Python 3.12+ adds empty type-parameter fields to definition nodes.
        return ast.dump(node, annotate_fields=True, include_attributes=False).replace(
            ", type_params=[]", ""
        )

    def structural_digest(node: ast.AST, owner: str, context: str) -> str:
        identity = "|".join((basename, owner, context, paths[node], stable_dump(node)))
        return hashlib.sha256(identity.encode("utf-8")).hexdigest()

    prohibited: Counter[_Task3Violation] = Counter()

    def add_violation(
        node: ast.AST,
        display: str,
        reason: str,
        *,
        owner: str | None = None,
        context: str = "syntax",
    ) -> None:
        actual_owner = owner or nearest_owner(node)
        prohibited[
            (
                basename,
                actual_owner,
                display,
                reason,
                structural_digest(node, actual_owner, context),
            )
        ] += 1

    definitions: Counter[_Task3Definition] = Counter()
    for node, owner in scope_ids.items():
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            definitions[
                (
                    basename,
                    owner,
                    type(node).__name__,
                    structural_digest(node, owner, "definition"),
                )
            ] += 1

    imports: Counter[_Task3Import] = Counter()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Import, ast.ImportFrom)):
            continue
        owner = nearest_owner(node)
        for alias in node.names:
            if isinstance(node, ast.Import):
                kind = "import"
                level = 0
                original_module = alias.name
                original_symbol = alias.name
                local = alias.asname or alias.name.split(".", 1)[0]
            else:
                kind = "from"
                level = node.level
                original_module = node.module or ""
                original_symbol = alias.name
                local = alias.asname or alias.name
            categories = _helper_categories(original_symbol.rsplit(".", 1)[-1])
            if original_module != "__future__":
                imports[
                    (
                        basename,
                        owner,
                        owner,
                        kind,
                        level,
                        original_module,
                        original_symbol,
                        local,
                        categories,
                        structural_digest(alias, owner, f"{kind}-alias"),
                    )
                ] += 1
            if original_symbol == "*":
                add_violation(alias, "*", "wildcard-import", owner=owner, context="import")
            module_root = original_module.split(".", 1)[0]
            symbol_leaf = original_symbol.rsplit(".", 1)[-1]
            if (
                module_root in _FORBIDDEN_REFLECTIVE_MODULES
                or symbol_leaf in _DENIED_REFLECTIVE_PROVIDER_SYMBOLS
            ):
                display = (
                    original_symbol
                    if kind == "import"
                    else f"{original_module}.{original_symbol}".lstrip(".")
                )
                add_violation(
                    alias,
                    display,
                    "reflective-import",
                    owner=owner,
                    context="import",
                )

    calls: Counter[_Task3Call] = Counter()
    call_func_nodes: set[ast.AST] = set()
    call_records: list[tuple[ast.Call, str, _CanonicalCallTarget, _PolicyCategories]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        owner = nearest_owner(node)
        classified = _classify_call_target(node.func)
        if isinstance(classified, _InvalidCallTarget):
            add_violation(
                node.func,
                classified.ast_kind,
                classified.reason,
                owner=owner,
                context="call",
            )
            continue
        categories = _helper_categories(classified.target.rsplit(".", 1)[-1])
        calls[
            (
                basename,
                owner,
                classified.target,
                categories,
                structural_digest(node, owner, "call"),
            )
        ] += 1
        call_func_nodes.add(node.func)
        call_records.append((node, owner, classified, categories))

    def statement_for_store(node: ast.AST) -> ast.AST | None:
        current: ast.AST | None = node
        while current is not None:
            current = parents.get(current)
            if isinstance(
                current,
                (
                    ast.Delete,
                    ast.Assign,
                    ast.AnnAssign,
                    ast.AugAssign,
                    ast.For,
                    ast.AsyncFor,
                    ast.With,
                    ast.AsyncWith,
                    ast.comprehension,
                ),
            ):
                return current
        return None

    simple_subscripts: Counter[_Task3SimpleSubscript] = Counter()
    for node in ast.walk(tree):
        if isinstance(node, ast.Delete):
            add_violation(node, ast.unparse(node), "delete-statement", context="delete")
            continue
        if isinstance(node, ast.AugAssign) and isinstance(
            node.target, (ast.Attribute, ast.Subscript)
        ):
            add_violation(
                node.target,
                ast.unparse(node.target),
                "indirect-augmented-assignment",
                context="augmented-assignment",
            )
            continue
        if isinstance(node, ast.AnnAssign) and isinstance(
            node.target, (ast.Attribute, ast.Subscript)
        ):
            add_violation(
                node.target,
                ast.unparse(node.target),
                "indirect-annotated-assignment",
                context="annotated-assignment",
            )
            continue
        if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Store):
            container = statement_for_store(node)
            if isinstance(container, (ast.AugAssign, ast.AnnAssign)):
                continue
            add_violation(node, ast.unparse(node), "attribute-store", context="store")
            continue
        if isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Store):
            container = statement_for_store(node)
            if isinstance(container, (ast.AugAssign, ast.AnnAssign)):
                continue
            owner = nearest_owner(node)
            if (
                isinstance(container, ast.Assign)
                and len(container.targets) == 1
                and container.targets[0] is node
                and isinstance(node.value, ast.Name)
                and isinstance(node.slice, (ast.Name, ast.Constant))
            ):
                simple_subscripts[
                    (
                        basename,
                        owner,
                        ast.unparse(node),
                        structural_digest(node, owner, "simple-subscript-store"),
                    )
                ] += 1
            else:
                add_violation(
                    node,
                    ast.unparse(node),
                    "non-simple-subscript-store",
                    owner=owner,
                    context="store",
                )

    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in _FORBIDDEN_REFLECTIVE_NAMES:
            add_violation(node, node.id, "reflective-lexeme", context="reflective-name")
        elif isinstance(node, ast.Attribute) and node.attr in _FORBIDDEN_REFLECTIVE_NAMES:
            add_violation(
                node,
                node.attr,
                "reflective-lexeme",
                context="reflective-attribute",
            )

    def policy_zone(owner: str) -> str | None:
        if owner == "<module>#1":
            name = "<module>"
        else:
            parts = [
                part.rsplit("#", 1)[0] for part in owner.split("::")[1:] if not part.startswith("<")
            ]
            name = ".".join(parts)
        zones = (
            _REQUEST_ZONES
            if basename == "attorney_v22_requests.py"
            else _COMPILER_ZONES
            if basename == "attorney_v22_compiler.py"
            else {"validation": frozenset(), "serialization": frozenset(), "neutral": frozenset()}
        )
        return next((zone for zone, members in zones.items() if name in members), None)

    def meta_context(node: ast.AST) -> str | None:
        path = paths[node]
        for marker, context in {
            ".decorator_list[": "decorator",
            ".defaults[": "default",
            ".kw_defaults[": "default",
            ".returns": "annotation",
            ".annotation": "annotation",
            ".type_params[": "annotation",
            ".bases[": "class-context",
        }.items():
            if marker in path:
                return context
        current = parents.get(node)
        while current is not None:
            if isinstance(current, ast.ClassDef) and path.startswith(f"{paths[current]}.keywords["):
                return "class-context"
            current = parents.get(current)
        return None

    for node, owner, classified, categories in call_records:
        if not ({"serialization", "validation"} & set(categories)):
            continue
        if (context := meta_context(node)) is not None:
            add_violation(
                node,
                classified.target,
                context,
                owner=owner,
                context="policy-call-context",
            )
        zone = policy_zone(owner)
        if zone is None:
            add_violation(
                node,
                classified.target,
                "unclassified-zone",
                owner=owner,
                context="policy-zone",
            )
        elif zone == "validation" and "serialization" in categories:
            add_violation(
                node,
                classified.target,
                "serializer-in-validation-zone",
                owner=owner,
                context="policy-zone",
            )
        elif zone == "serialization" and "validation" in categories:
            add_violation(
                node,
                classified.target,
                "validator-in-serialization-zone",
                owner=owner,
                context="policy-zone",
            )

    for node in ast.walk(tree):
        if node in call_func_nodes:
            continue
        if isinstance(node, ast.Name):
            symbol = node.id
        elif isinstance(node, ast.Attribute):
            symbol = node.attr
        else:
            continue
        if {"serialization", "validation"} & set(_helper_categories(symbol)):
            add_violation(
                node,
                symbol,
                "policy-symbol-reference",
                context="policy-reference",
            )

    return _Task3SourcePolicy(
        calls=calls,
        imports=imports,
        definitions=definitions,
        simple_subscripts=simple_subscripts,
        prohibited=prohibited,
    )


# Review-only drift inventories. They force a human-readable delta when governed
# source changes; they do not prove Python name resolution or callable provenance.
# fmt: off
_EXPECTED_TASK3_ALL_CALLS: Counter[_Task3Call] = Counter(
    {
        ('attorney_v22_compiler.py', '<module>#1', 'RubricV22', (), '6f4c828cd24e3713fd18910608cbaf67c0d414162b02e2a285e5773e155db7bf'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_audit_fragments#1', 'SourceAuditFragmentV22.validate_for_indexed_proposals', (), '371616c1eda4872bda3ccbe0fd1884f216039ab62f52e7f675e4e0bd10dd3d07'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_audit_fragments#1', 'ValueError', (), '59362ee68d20ee6e36a91fe88a484d6a2b1efb77e590c20914dc76be2bd22fc2'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_audit_fragments#1', 'ValueError', (), 'd4ade8079ef4edcc67548ad68af48190fc952c76fb3487e8ff9f434b13787710'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_audit_fragments#1', 'ValueError', (), 'd7eb292f5f035fab1d8c4169cad57c444555a1416a43a3e451853573ddaa0ca6'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_audit_fragments#1', '_strict_rehydrate_v22', ('validation',), '5e2ac291495fca7156fbf48ea7925d1e61dab58b2a90333ad218f39297ad161f'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_audit_fragments#1', '_strict_rehydrate_v22', ('validation',), '6f713c607c9c178c8fc598baeb70e53b48416baceeae98d91c340dbde00c50a4'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_audit_fragments#1', '_wire_snapshot', ('validation',), '559ee3d00fdd64e26313704c0362cf07e7029d824997b3dcf0e8a64153924d93'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_audit_fragments#1', 'any', (), '705e0beabc29c270fabe3a5ebd541a8982bc2cd74cc1668aae65bcb18bda19d9'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_audit_fragments#1', 'checked_items.append', (), 'b68eb9c84fc38cc7e086e904114e1f2b5a612a5e70e431825afc1c67e01971bc'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_audit_fragments#1', 'isinstance', (), '373d72958e41dbfc51bf380c3f8e3aef0fdb5d8b205c518cafa005e466f24113'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_audit_fragments#1', 'len', (), '1761207ff0da298b75f6db095f255d97837c15aaa281fd1f3c61bb24d65c81f4'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_audit_fragments#1', 'len', (), '7059f96fc4e86c9b5638822831f3ca013cda82a9ff7d04d3a0e44da3a14f953b'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_audit_fragments#1', 'len', (), '82f3d3d4790702a09d4ea1f095e6ca48b4fed945aec4022453071829b1772180'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_audit_fragments#1', 'len', (), 'ced376195e3e1b9f768e78c8f8188798534e5911759233875005710e05ba8139'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_audit_fragments#1', 'list', (), 'af23345f5e3880ebcf6dc3e5199769efb1d402b1f5e0648f50c4bb84411f7163'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_audit_fragments#1', 'range', (), '4b92f891a77ba0858d5cb221e446b8d8be8e35743028553e085054b91298b96d'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_audit_fragments#1', 'raw.get', (), 'e3c4c0a37ebf5d192c13f6c3b93251ba42b66c25a2124473f618efd5fb162769'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_audit_fragments#1', 'sum', (), '7168794e3dc03c734ee633e46ca942705a44137ee1b47415b222249826b24d10'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_audit_fragments#1', 'tuple', (), '92ffdd55f8042a1d3abac95c08608e60d5f5099ca97448a9fa17e50a1d4318c3'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_audit_fragments#1::<GeneratorExp>#2', 'len', (), '433ab58c37fa168a9a714e57476413c8cf04d2745a71beeb13884a6476033208'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_canonical_baseline_fingerprint_from_validated_v22#1', '_hash', (), '3b7f6fc92ded2b9c8db8365adcf7fb93cc311394e9756a9ae6762adcad43d442'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_canonical_baseline_fingerprint_from_validated_v22#1', 'checked.model_dump', ('serialization',), 'e48c84f31254fd35ec94bd88d01c029b1973533314785b3b95cc9e2f2c26904f'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_canonical_baseline_fingerprint_from_validated_v22#1::<DictComp>#1', 'checked_payload.items', (), 'f0e14c67685a22978b2859e945fb7a5cb90b4bb52dd35f59fb00106398332b71'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_canonical_dispute_passages_v22#1', 'passages.extend', (), '46a9731177a968229ac020a6a64a3c6b3981a4c0979be471a10d2ed15a5cac3d'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_canonical_dispute_passages_v22#1', 'passages.extend', (), '695ea7a879f3a51345378d19f9b46b51e5cdd1539b49f2d83d4475909fb7299c'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_canonical_dispute_passages_v22#1', 'passages.extend', (), 'b775cec0edfed513b72852f5c933aaacdd31360409cc54b990d838cb79ec6ef0'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_canonical_dispute_passages_v22#1', 'sorted', (), '49077b8c5b7238fdffaffa02097ff4630e05c6d28b58b9f934448916667110df'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_canonical_dispute_passages_v22#1', 'tuple', (), '401f2e09029055d40dab2339099b7a009d66b2af2d7c334a8202b51a0009b217'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_canonical_dispute_passages_v22#1', 'unique.values', (), '2e93deb8fdfa52237d50d0929fae93416a7031792fe22a146121ed3cc7e027ce'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_canonical_dispute_passages_v22#1::<ListComp>#1', 'resolve_exact_passage', ('validation',), 'b897a3ce304ca327aae51c26abf8f44916e247b68d35799d307d60e301f867d9'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_hash#1', 'canonical_json_bytes', ('serialization',), '7bc6c8fcaeba7955e35f30044232edf9426835b66e2a5fbc426191ddc2d0cae9'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_hash#1', 'digest.hexdigest', ('neutral',), '74a8867d470071905b12abb5b0dc38a5170d916e76b0c0c3fc2f775f9d53cd91'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_hash#1', 'hashlib.sha256', ('neutral',), 'a6f7ef8c57d19ecaefdb87100714d09d1a71ea4ac6217afb8ea238df1e84f7e0'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_referee_dispute_fingerprint_from_validated_v22#1', '_hash', (), 'a3e7300a1f2d2f574be9a437c63d4d9141fde1b967d39ff4301566d46a67935b'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_referee_dispute_fingerprint_from_validated_v22#1', 'checked.material_dispute.model_dump', ('serialization',), 'a4d7b12c2fba438398c8ad4f619d77b6e66feb32705dfd33512da7868b5dc673'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_referee_dispute_fingerprint_from_validated_v22#1::<ListComp>#1', 'item.model_dump', ('serialization',), '423bd6430e12ee608b80356091e3c599d89b930c7507bebae07696e602adc223'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_referee_disputes_from_verified_sources_v22#1', '_v21_inputs', (), 'f986d54cde2083e66035526f95cc7c9e53796039e22b118b7af2b649e113edd2'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_referee_disputes_from_verified_sources_v22#1', 'canonical_referee_disputes_v22', ('validation',), '043a7bd83a42510bc297681e50e4f4b9c993616ca679c048ee756fe2816b451a'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_referee_disputes_from_verified_sources_v22#1', 'tuple', (), '286873c1fbc407f8c2836323e535bd34a8bb8f5306191d0a4d3c0b5a98d38c50'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_referee_disputes_from_verified_sources_v22#1::<GeneratorExp>#1', '_disputes_v21', ('serialization',), 'b31b0fd982c358e7c639029a2e29c096f7cfe2735b192ff9485b3234ed3b711c'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_review_fragments#1', 'ValueError', (), '4ba80f36bdc429cb7550da717db9dd3ccccbb79c3d7be8060472b89408024bd8'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_review_fragments#1', 'ValueError', (), '8498aaee5499c8ed56c7c3d5c41c5cd21bff581650656d58611efdc0883fb240'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_review_fragments#1', 'ValueError', (), 'b72f2bf99f63448480744391b96797e6c349c5c3852b2272c36ac2222ecb2330'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_review_fragments#1', 'any', (), 'dfa9163b2faeac6c242d8dda81cbed87292842776b05a4015e79f873ad1be62f'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_review_fragments#1', 'len', (), '13b4858822f78e4a9a601b9e5a233457e714e98c03be35d5b255d30bc0d33011'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_review_fragments#1', 'len', (), 'acc92e518c947a1389fcc6ecadc6e5707285487f8af9e5cff670023b4c9062c0'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_review_fragments#1', 'len', (), 'dd954f27098125307cc6b91c637c58abaa000811dbbe3006c57f08d516535e4b'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_review_fragments#1', 'len', (), 'ee4a3297c47cb125510ac913ccdd490d05ac8df8254328dd3290cd5e792870f6'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_review_fragments#1', 'list', (), 'b496f35b4a6e1c9302871e26e1c1e4def508fe9eaf5ce581fa0413126697d38e'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_review_fragments#1', 'range', (), '614f2e6d8b5c5fdfc4c992a6c0062bcd875db8930bcee33caf1e800fcf8568b0'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_review_fragments#1', 'sum', (), 'e3d629098c31c0b98348e6d16cbf715017d5e35a24648a7cd5006809dd98c410'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_review_fragments#1', 'tuple', (), '0c6490f9b751e5840d3394855715e37ce30dcd7c9c8a1b5243fb8697850f4c92'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_review_fragments#1::<GeneratorExp>#1', '_strict_rehydrate_v22', ('validation',), '4d5434639885551f39cfb368b002c5899f5782e503c3f875ec8efdbc12487f41'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_review_fragments#1::<GeneratorExp>#3', 'len', (), '9027a46d044cc32d0632daa8de371833e56cac88d8f5e38c6075319e934b47f2'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_same_observations_v22#1', 'view', (), '33b604f4774aab5649ec3e5eab85d85806ac3fe3844c48226015fefe4879a142'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_same_observations_v22#1', 'view', (), '50bb0d5127db07cf2833614071ec1a0b7d24d77d17974bbe42cebc831d148fe8'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_same_observations_v22#1::view#1', 'tuple', (), '2858f9c5f238802cb32bbf4c4828d89529eafef9d2481f0eb916969c1330a965'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_same_observations_v22#1::view#1', 'tuple', (), 'd1c84ff7b3c1f11ce3fadc1d0c40511a841c091413e14dbe487602d7d54e2a2f'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_same_observations_v22#1::view#1::<GeneratorExp>#1', 'tuple', (), 'eb9a4f83c801bb62b0192362517603e631fe07b2ffc242b1861c67f9ec8a9b18'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_score_v22#1', 'any', (), '96432c0b1ee80c2413d0854aa6ab4219b36549b86cb4d4bd6994082a498cb56d'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_score_v22#1', 'len', (), 'bc1ca01a8cb3093be160eeae49561ee18e20b201432bef6740290601a3ef35dd'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_score_v22#1', 'reasons.append', (), '25c310f4329b3a33e7adb7598af673f8c5292e8193000116c75173953163379a'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_score_v22#1', 'reasons.append', (), '33137a1123f2e38addd831bb23e0686289d36c3a3b70e9592d4fa41faca48ed1'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_score_v22#1', 'sum', (), '2741a503839bb57d664748512699fd9402e4415b4e8d7e8a8cfd2c4605bc6d4c'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_score_v22#1', 'sum', (), '3918618757f37556c320b8f75f57188bad3f85b054891f8be2fabc91381154a0'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_score_v22#1', 'sum', (), '3c76de3463cb185941891ac6eeafadd6f2c7864ca6e585e20bd45c244f77b080'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_score_v22#1', 'tuple', (), '96543e3a22228cfac78ccf3a1072b395c7be47a2e6687e11c826718d1f9ee21d'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_semantic_identity#1', 'isinstance', (), 'c88c55d77ca2a97e92945a8cf3a1635a3c49667d7598b3272bee92ac3e47693e'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_semantic_identity#1', 'separator.join', (), '01530ca6846d0e4d38c78fb64b505a5fa96c76d25bd6c9ed09804480e9a55eab'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_semantic_identity#1', 'separator.join', (), '42870e7cf0b7a4e386f905dec82b424771435f9630dc9a65c6bafd31934cb6b8'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_semantic_identity#1', 'sorted', (), '3be2e8d5d9688e50aa703a3062278f7010133771e44ced158091bde302a80c1f'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_semantic_identity#1', 'tuple', (), 'dde7ba98a71759fe6d5bdda8ba08740d5c0b82de17908442f1ccf6754c312bab'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_semantic_identity#1', 'value.correction.statement.split', (), 'f412cc409fc3bb813b222da284d575c5f172821ad1738a773ba16dd9d4fa1fa5'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_semantic_identity#1', 'value.statement.split', (), '3d0be97b1b08e4235ddedebacf9081c25d6baae787a5dc8dda1ae87149d401b4'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_validate_source_fragment_semantics_v22#1', '_SourceFragmentSemanticResponseErrorV22', (), '66248ffea418f8b494b72f9e0ae49b5495396b17fdc7c3a4764c3189f9ea34fa'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_validate_source_fragment_semantics_v22#1', '_SourceFragmentSemanticResponseErrorV22', (), 'a40e420ddb32328ecba79076bbbefdaa899d9ebf97dcfe411e4cdb2639cc43b7'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_validate_source_fragment_semantics_v22#1', '_semantic_identity', (), 'feefaf3b2bf4387f03e854b333fdf257156c8835a87338917c1267ad39eb0609'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_validate_source_fragment_semantics_v22#1', 'canonical_json_bytes', ('serialization',), 'c193020b210eb802d88299b1269d6c296821bac3c87abefb7ffb80c3466ee0b7'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_validate_source_fragment_semantics_v22#1', 'value.model_dump', ('serialization',), '33236b7fe944f5a45f7098f51ed4799942d7995d43becfc8102eca3a36e0e821'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_strict_rubric#1', 'RubricValidationError', (), 'c887c2a9e87f74ed72e92394c85b6dc8ffec13a5122f7250f017d2df78618322'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_strict_rubric#1', 'RubricValidationError', (), 'f9f94c8356569d719fcd33a6d74e496360332e87d3089af58a0020cf7c87a1c1'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_strict_rubric#1', '_strict_rehydrate_v22', ('validation',), '4fef9538fec235a623ef244a4086eb993684a4ab21fea67f34a1a9a01b6c487a'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_strict_rubric#1', 'isinstance', (), '897811643a19d26470edbef4cfef0bac6edd6466b62e3967e401996e02e5e318'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_v21_inputs#1', 'CompilationError', (), '61d22baa293b6611c414b02f42fad219f877a22373f3ed82947bc3b5887462a7'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_v21_inputs#1', 'SourceAuditAggregateV22.validate_for_indexed_proposals', (), '8112bddd58c5691a61b2ffcf8679eb508e2cdcb64986610be882a4e8d8408191'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_v21_inputs#1', 'SourceAuditV21.validate_for_indexed_proposals', (), '60e02f97d2bf394f46519b2cc7c4f385e128b716d84fc9534c5dc1a6095ed989'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_v21_inputs#1', 'SourceReviewV2', (), '37689427897f7c15f9feaf6aca1f6f9aafbe95d2a9217d963ff6e2bc5e02dbc7'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_v21_inputs#1', 'SourceReviewV21', (), '876dfe3171c97c9699975fdaac11e49190d0a613d787b477dfa2941df6ee13ec'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_v21_inputs#1', '_strict_rehydrate_v22', ('validation',), '894eecd7b71cf425d77cc94f9e65b0b764de1878f7e391a48d943f8effb134f9'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_v21_inputs#1', 'index_review', ('serialization', 'validation'), '64fbca11dedce973b72d2cf7d251608fff64d65dc32ff2ab6d93005e04b36dd3'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_v21_inputs#1::<ListComp>#2', 'item.concern.model_dump', ('serialization',), '2ff84cff4278be41722a33fff4a80c2ddc764ec484a103b1d4ac09359ea424bb'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_validated_canonical_baseline_v22#1', '_strict_rehydrate_v22', ('validation',), '1271be626299ba7984e45b79ff036c5f0ab8223226a24462888196344b9cf5a7'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_validated_referee_dispute_v22#1', '_strict_rehydrate_v22', ('validation',), '8986458f4a7e657c22f994c224baae908204d1e480ed29d374b80bbcfb77abf1'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_verified_grader_aggregate#1', 'GraderAggregateV22.validate_for_inventories', (), 'b4832142c0479e3aabf12572aa5b5d12045bcef8ad485bc4ccd837b7d09ea601'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_verified_grader_aggregate#1', 'RubricValidationError', (), '56bdabfa7f853b107e32e7436abde4b340453235558b4d69479867b768aacc7e'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_verified_grader_aggregate#1', 'RubricValidationError', (), 'b0e748f1f9483583c266253be9b9e706003af1120d655fa622b0c698e8724142'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_verified_grader_aggregate#1', 'RubricValidationError', (), 'b1a1875e7c96ffb673c01ea1df24de7ce5da66da64a1eae226c163a5ba57a543'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_verified_grader_aggregate#1', '_hash', (), 'eb3d7009e4a35d80e1fa5c663182f401736b36a7f8dab517c8e8d603fe4144c5'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_verified_grader_aggregate#1', '_strict_grade_coordinate_v22', ('validation',), '787889bc23a261fd846c5afbb2682b4187522c23333424c99ca07f706496d939'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_verified_grader_aggregate#1', '_wire_snapshot', ('validation',), 'abd1af998ae36b70e89e6ac2b8e1d2de661b650be49b38ccbb5bcfca7abf667c'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_verified_grader_aggregate#1', 'isinstance', (), '6900f93d8c5546feab129a69cda4b82e4a83edd17953601b2e8ba56a58778ee0'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_verified_grader_aggregate#1', 'ordinary_grade_batches_v22', ('validation',), '70b8bb15b7b6668362c187a30b81830be318b18dc7225ec094243a25ee228247'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_verified_grader_aggregate#1', 'raw.get', (), '66d04c3157b2235517db6cd3c787c0e7ece272af290baa6686ae7527bcb4f6c3'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_verified_grader_aggregate#1', 'raw.get', (), 'd9877c4bf46fab63f23940f98d7bf7b1504ed05c2812055d4f13add367d70e63'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_verified_grader_aggregate#1', 'verify_canonical_baseline_v22', ('validation',), 'e42eb9e9a2ffd56ba77f06b2da7617eace609228167ee88c1b498304eeeb7c4f'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_verified_source_aggregates_v22#1', 'CompilationError', (), '71de84d754a638dc50ca204a4c43889429bf0acf8b725a99d319c52b59dd4b02'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_verified_source_aggregates_v22#1', 'CompilationError', (), '7f60c3107b24aa054fe1faa9581a274a5d72a47d56eaa96b417ddb527ab6e537'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_verified_source_aggregates_v22#1', '_verified_source_request_context_v22', ('validation',), 'fd01c681225cbe3593f0bd33a9561cccb4388b3890b119d2764961481105c1eb'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_verified_source_aggregates_v22#1', '_verify_source_audit_aggregate_with_context_v22', ('validation',), '8f39518fe88d555afe218fc402fa81a772a04ad9deb5c535208f1d435755d756'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_verified_source_aggregates_v22#1', '_verify_source_review_aggregate_with_context_v22', ('validation',), '4c6efc35cf2f7b85ca96b42f9060c1ea71927d17a822270ac617a82fb3db74ee'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_verify_source_audit_aggregate_with_context_v22#1', 'SourceAuditAggregateV22.validate_for_indexed_proposals', (), '2e2bbe7fd4240f2b3547b0751e6dd58b7dac05573abc2d897450e5fa27abc030'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_verify_source_audit_aggregate_with_context_v22#1', '_audit_history', ('validation',), 'a79a98cf20d5a20652f792ceede1b87f94fb1b4a7be08095d866baf4fe48dd25'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_verify_source_audit_aggregate_with_context_v22#1', 'aggregate_source_audit_fragments_v22', (), '5e19fe832f71935742c0e707b4ba099437f77afe9d5a9a0d2ab7700e254b2b79'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_verify_source_audit_aggregate_with_context_v22#1', 'resolve_exact_passage', ('validation',), '6755d4d246b6e00c62ee4d8e87a8cde0ed9b1af1889a39f872d31367bbda5971'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_verify_source_review_aggregate_with_context_v22#1', '_review_history', ('validation',), '34c4c8dec5c66efbe799e5f9d9ae9a144185c8d33d0631e02d8af42cd0cc138c'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_verify_source_review_aggregate_with_context_v22#1', '_strict_rehydrate_v22', ('validation',), 'f4300d7d532bcdbba72cfd86a969cc56da40cdb46645d3af2070eb28dd542528'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_verify_source_review_aggregate_with_context_v22#1', 'aggregate_source_review_fragments_v22', (), 'a0949427b91efa7853e44e6262a77405f83481dd92f37cbd8ca6b6a624f67f77'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_verify_source_review_aggregate_with_context_v22#1', 'resolve_exact_passage', ('validation',), '9f0de676eaab9eaa90539fc94c52739304aff6245e81550c0b0f86c8a5e75ec6'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_grader_lane_v22#1', 'GraderAggregateV22.validate_for_inventories', (), '2b7bbea47f4592387607c15d2e541592d899b7291cdcc827153d6afce36465c8'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_grader_lane_v22#1', 'RubricValidationError', (), '21e81f6c59106cceb09650f149a8a50d8a4325c98b1cbb23841f5cec9716bca1'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_grader_lane_v22#1', 'RubricValidationError', (), '31cfdea48925ec6450d666a8d7a1539e1e2610e0e76ef33da24541fac93dc76a'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_grader_lane_v22#1', 'RubricValidationError', (), '699fb9dca4b6861ad024129e5e60979ee504af4aed001d1f604a19fcc4658d1d'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_grader_lane_v22#1', 'RubricValidationError', (), 'f3f156f49ba7cf210563f3892e2a520d2e4292fcdc34e8ed589bee14027f0b62'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_grader_lane_v22#1', '_hash', (), '2ba53ea245ca48d0cdb5256f9fdbb7c56a7b52e1a3ea127f285688b8cc37a349'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_grader_lane_v22#1', '_strict_grade_coordinate_v22', ('validation',), 'a12424f5f8f73d703dd3b4ce703af9b2c09703467aecdd110e5f775d85309486'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_grader_lane_v22#1', 'iter', (), '292a3effbd72797350aea1222442eb22258d122802b8be62fd977c10960cba14'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_grader_lane_v22#1', 'len', (), '530492424c0a360695a994eff0783cebb6b61e066e657db79a470a3108a56f37'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_grader_lane_v22#1', 'len', (), '60a785da4a57c2399c28bdafab40b87bcac4a99c2cd35713d36eb41d1d4b87ea'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_grader_lane_v22#1', 'len', (), '62cd23a6667b666643d81ecd787fd1a8621707b2a7c1e45877119c77f16c141f'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_grader_lane_v22#1', 'len', (), 'c696713e2b65bcc0d2e18d8c84562b087284cfb088a3a063b4ca57679ac4c84f'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_grader_lane_v22#1', 'len', (), 'e304552d76de19f4acaf51e8b8b9988aeb2a2eba5b997b75b4ce6eef7a5de781'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_grader_lane_v22#1', 'next', (), '933dad0130e3da958fdb1ec230f6d4d9f69ea8277976ab0f8ae5d1e3bc1273db'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_grader_lane_v22#1', 'ordinary_grade_batches_v22', ('validation',), '7b5ecd359159b05a6da6309f3a4fd9566fe8cacf91a19666dc9e0bdd93d7c9af'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_grader_lane_v22#1', 'reports.update', (), '4c3960ab980be3e3bdc19b452c8fad7a0e173a6aab68f88248074ecb5dc634d4'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_grader_lane_v22#1', 'tuple', (), '7b8595615695e89ca5e3f194d5588b387718cdcf37b5ec02022af412a436f68d'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_grader_lane_v22#1', 'tuple', (), 'a1bf51b1e25ae13e9f64fc3d9a636831d5e64f6a4171d84ace5493142f932e4c'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_grader_lane_v22#1', 'verify_canonical_baseline_v22', ('validation',), 'adaec1c135bed75b1d81b48a8cde68ca994f9f4b5d72d7fb27b07c53f4156999'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_grader_lane_v22#1::<GeneratorExp>#1', 'OrdinaryGradeFragmentV22.validate_for_batch', (), 'c89a173a8c2106e7d48cc706f81d79078c5ab585318c9527c93baf74f6f8d094'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_grader_lane_v22#1::<GeneratorExp>#1', 'zip', (), '4d3933352e0c1fb510213b2d132046dea5ae88e49a97f7c869f769bc4871aaab'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_grader_lane_v22#1::<GeneratorExp>#2', 'ContestedGradeFragmentV22.validate_for_requirement', (), '2248f3b4077d5363bc358d135c379dbb207f6bd910bb7b99c93c9886571c349a'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_grader_lane_v22#1::<GeneratorExp>#2', 'zip', (), '715aaa6a58a7350749252e7eecd9344db2a935a386150d52ca492fb317282c9c'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_referee_decisions_v22#1', 'CompilationError', (), 'a364b3119b5fc1fd3a9fd73aed6fa08d2fae994c71ee16d0045294862f0bbd86'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_referee_decisions_v22#1', 'CompilationError', (), 'df992782edd1ec3144d9d71c98392c42c47d9a3afffd5fc16087d08d9e7be736'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_referee_decisions_v22#1', 'CompilationError', (), 'fc2aa5730529d6e04cb9ab42b4fa05e3ac3e314afec228206e4081ae393a6ee7'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_referee_decisions_v22#1', 'RefereeAggregateV22', (), '89ca0f9c3d1f0f6b8d2ddcdabe12777d39aa5fa55cb83d95badb76fc381c32c8'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_referee_decisions_v22#1', 'RefereeAggregateV22.validate_for_disputes', (), '4b0caf35420587fe2d112353f39bf47db4fd2cc798f19abf9155030e3c36bb47'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_referee_decisions_v22#1', '_hash', (), '8df8f565096c92c0e16cf5db87fd11d2ea5262a3f06b1b3be4c949ad34c956c5'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_referee_decisions_v22#1', '_hash', (), 'eacd7bc38a7bf55e860b43298d5145b9faee7c902afe3ec7e7d33e8395034583'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_referee_decisions_v22#1', 'any', (), '22f2a1c122d2a278bff9a3d4fa0ab0b975fe43b37a98d97e4e835918577a4303'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_referee_decisions_v22#1', 'tuple', (), '69c68b6bdf8e502c8f9c506af2103dd6edf5dabe7a16d3c9d01ebc93de21a210'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_referee_decisions_v22#1', 'tuple', (), 'a8d737bdc80436ee35fc23d57a7a295d54b839c4836dff57093e9d9c385e41bd'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_referee_decisions_v22#1', 'tuple', (), 'c061a101cbe92df041dc27c20327c120602b05b05fa12374ebbad611c54951e5'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_referee_decisions_v22#1', 'tuple', (), 'd2f14be9888ddd35799e8106d2bf9e60008ce53fa8d88c2193ac082000383719'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_referee_decisions_v22#1::<GeneratorExp>#1', '_strict_rehydrate_v22', ('validation',), '2ac7c5b3fa5d3737805e804897102d997cb5e7ee318efe7388f17f63e6abfca2'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_referee_decisions_v22#1::<GeneratorExp>#2', 'referee_dispute_fingerprint_v22', (), '7d036deece7b001ed236c84295c744413a0c90a897c0d1d3b13072251e2118dd'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_referee_decisions_v22#1::<GeneratorExp>#3', 'AcceptedRefereeFragmentV22.validate_for_dispute', (), 'b911274ff2caac37385fa2b6c21a645911a2993d9795202416359742ca3c35d3'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_referee_decisions_v22#1::<GeneratorExp>#3', 'zip', (), '21612789cf24ceecacaf1e5e3e7371349abdd2774c97ca4934bbf8dddbda0928'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_referee_decisions_v22#1::<ListComp>#1', 'item.model_dump', ('serialization',), '9817eef703cc7472e4e29cbe63f7458d15687e1f648f45b4dbaeb2f02f80494f'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_referee_decisions_v22#1::<ListComp>#2', 'item.model_dump', ('serialization',), 'c906122732560e42044bbd02499db29edb4479b3304b5faf5250aa08e9271570'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_referee_decisions_v22#1::<ListComp>#3', 'item.model_dump', ('serialization',), 'b5f51a2f6f5576803fc9de5afb7862cdef3e5d0822656e3f075d56f290602079'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_source_audit_fragments_v22#1', 'SourceAuditAggregateV22', (), '21022732de075c02367166c1f4d854d92c9940ecee52e5679e8768253a2f165e'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_source_audit_fragments_v22#1', '_audit_fragments', (), 'ba9ecde5f3c1ce3bad69982e998b0bf39fa6df36a8aaa2851a2e10fb654a11f5'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_source_audit_fragments_v22#1', '_hash', (), 'b77315f0ce4fc06c8439e70c6974ad60234ebf6c2c784a8171b8aa5538be647b'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_source_audit_fragments_v22#1', '_validate_source_fragment_semantics_v22', (), 'a098d523b14c2355a916e81afdf1d17ae09e7ee4eda4b08c36c6463294d5ca50'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_source_audit_fragments_v22#1', 'tuple', (), '4b60a9ecaf1cf2ad9543eff2b00fee8c2c3933465b42cc8baa8e9eb82f95561d'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_source_audit_fragments_v22#1', 'tuple', (), '83a1a62fdeb919f75e5adfc8913d33e7d50adf9ac9eb6276b94894c8b4a62797'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_source_audit_fragments_v22#1', 'tuple', (), '9079ba9a75dc0b863b8029723483b8476422fdbb12cfa21b6abc591def30b63f'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_source_audit_fragments_v22#1::<GeneratorExp>#1', 'IndexedAuditConcernV22', (), '9bc04d8050358541f58198ebd36c26d99d4f2825dadeac004dcd3348b919261d'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_source_audit_fragments_v22#1::<GeneratorExp>#1', 'enumerate', (), 'e3263e2406dd3f73ae885bd3317695d72675ea11fe8f270a5f1b63bad887cb1c'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_source_audit_fragments_v22#1::<ListComp>#2', 'item.model_dump', ('serialization',), '9c826d1e475eeb0bfd752cb4c57ceb6cb2858128a236501b7233784995d1ac08'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_source_audit_fragments_v22#1::<ListComp>#3', 'item.model_dump', ('serialization',), '667c890f86ce3e358312ed8b1298a86e65c0bdca47451bbf7adcb9b8fb8c4030'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_source_review_fragments_v22#1', 'SourceReviewAggregateV22', (), 'cecf17de2704346509700639aeb44b70bbe655d65b17b2fe0547125b2cc26d54'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_source_review_fragments_v22#1', '_hash', (), '597a9ee214816dbcb55f9d32ab5a0d04cda8122b2e043576df68348ff8cef6dc'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_source_review_fragments_v22#1', '_review_fragments', (), 'be694f808cc6a8874cfcebccb88d56090c3a59c83ca09553b857b4d65fdd84b0'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_source_review_fragments_v22#1', '_validate_source_fragment_semantics_v22', (), '6dc361c1b1a2d9c4b955017b35324ff7c5ae4a8a82bb03c7a985e4f5fcc1bbcf'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_source_review_fragments_v22#1', 'tuple', (), '0d1939453433efae4e08574c79ae59534e8af7291ff82f2ccc7cc9563c2164f1'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_source_review_fragments_v22#1', 'tuple', (), '71ec39542699e9b783594261d4651d7e85d67025c0afdd5e305293425262bab3'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_source_review_fragments_v22#1', 'tuple', (), 'cf5e76865ade49826aadb413950221756609b9cf8a057c3a97556ab51dd18222'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_source_review_fragments_v22#1::<GeneratorExp>#1', 'IndexedProposalV22', (), '06f426427ce3e0dc0b2dd4f2ae70a7e97b84ffd37d6df8aa658266453426f154'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_source_review_fragments_v22#1::<GeneratorExp>#1', 'enumerate', (), '2a85e0a1f0967e0fe11231262a4420562a5949c2df9159d39b3446a351555d89'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_source_review_fragments_v22#1::<ListComp>#2', 'item.model_dump', ('serialization',), '26363bdcd58adf57137b81dda80dd0002cb4df9ddc51913d27c5d4f35deccb84'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_source_review_fragments_v22#1::<ListComp>#3', 'item.model_dump', ('serialization',), 'abba382de6b616cb86125aabcb2d3c7632be7fc22dbb6fc0a0e22e5012053971'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::build_referee_disputes_v22#1', '_referee_disputes_from_verified_sources_v22', (), '0e5c57dddf28948a91485ec0ccd0d778c6a5e714e79ebf5c83d3fa86d97f4536'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::build_referee_disputes_v22#1', '_verified_source_aggregates_v22', (), '698e41fdb49141fc25e41657ec89df608357eedb90a21b0f14c4b8ba161154d6'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::canonical_referee_disputes_v22#1', 'CompilationError', (), '1ec2924f4013d46509f32c8c0af907851ab5ff906fa00492eda54416f9a069fd'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::canonical_referee_disputes_v22#1', 'RefereeDisputeV22', (), '2efa4cac935915a71ae3299ba78ce2175c9b95350e8a248c6ec24937abfb756e'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::canonical_referee_disputes_v22#1', 'ValueError', (), 'd70efd286686657973267be3184ed22cfaae219ddd59ae2e21785a12de4d7936'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::canonical_referee_disputes_v22#1', '_strict_rehydrate_v22', ('validation',), 'f015d7c1a66f7d61bcc23a76491ca7b8f1a91d7e7976274d73c182c6289627d5'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::canonical_referee_disputes_v22#1', 'provisional.model_copy', (), '16da2b10a67c83e44ef5dda9ccae4da9e868876a75dfe8b05026c25c96dd92a3'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::canonical_referee_disputes_v22#1', 'referee_dispute_fingerprint_v22', (), 'a1d4f11abdc437a0c2b0344ba97cc9daafacf2de7cdb53ee4775afc828c200ab'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::canonical_referee_disputes_v22#1', 'result.append', (), '39991765b112c06e49b00da758b88368af74e6e7f9733078a747f7785dc77167'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::canonical_referee_disputes_v22#1', 'sorted', (), 'd0d34fe182b4e867519391143d13186d535e91fe2e477d696fdfe9fff4539b1a'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::canonical_referee_disputes_v22#1', 'tuple', (), '0c29ed1d834a6bea5dcfacedea4b095211f5c092e97b33456c1637c33b7112a6'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::canonical_referee_disputes_v22#1', 'tuple', (), '2509ce52ac14152a2f1298efcfe19c1b83fdf43090d03a321ce60b8c05828824'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::canonical_referee_disputes_v22#1', 'tuple', (), '3cc3a34ac1a0c0aa16a9fa9886c700d788ee5670fd6256726ebaf8fbf8fc26c2'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::canonical_referee_disputes_v22#1::<DictComp>#2', 'enumerate', (), '28dd53ed005d0da91d6c33c8e8cca15a2972584beade32a270a701885df192ec'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::canonical_referee_disputes_v22#1::<GeneratorExp>#1', '_strict_rehydrate_v22', ('validation',), 'f6f21127f6afef24f42fcb81a8c5d84a97a54e224f0f19db8c453cd6629cd8d4'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::canonical_referee_disputes_v22#1::<GeneratorExp>#3', 'RefereeEvidenceV22', (), '0b3d08bcfc0ee8332d06d04c0d08462d794cb3c8f41bd6d26f23162dcf85c072'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::canonical_referee_disputes_v22#1::<ListComp>#2', 'len', (), '1dab7f434fe0047b9f29ce85f6248e25104d0d0ba0b6ba948754d3f3c5fd6781'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::canonical_referee_disputes_v22#1::<ListComp>#2', 'range', (), '5c8b943ea4e80d27285a716f71c40731d42091ba0ab69516ff987f54fc55dc49'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::canonical_referee_disputes_v22#1::<ListComp>#3', '_canonical_dispute_passages_v22', (), 'e441f0ea8c4e36c652d6bc3157f765b71642ea3f5a2a9c7ae51ae8cab668a15a'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::compile_baseline_v22#1', 'CompilationError', (), '5bd0a846468ce547a246b00a9303f23e9b4a27838b76586378dc93737c967859'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::compile_baseline_v22#1', 'RefereeAggregateV22.validate_for_disputes', (), '356a21b47ab01a2220d898b4995c396c8c1979509c32f57a7040244eead25791'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::compile_baseline_v22#1', 'ValueError', (), 'b1b03bea02be9dac36f621f3c2331b77ef5c7ed5d388d9434cbceb4fa301e220'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::compile_baseline_v22#1', '_aggregate_v21', ('serialization',), 'c45c20ba07caa733dac839b7143aa32d7cf000e908285600e17d15dc43b8f5e5'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::compile_baseline_v22#1', '_baseline_v21', ('serialization',), '1f0c9eb5d5d88086be7bf00ad1f789870a90433a5bef9c1fbf63840561d2c7fc'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::compile_baseline_v22#1', '_disputes_v21', ('serialization',), '0da866709fbb0e7b01511bdf5f064f36380511e33815a39059a66abf74fd2b31'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::compile_baseline_v22#1', '_hash', (), 'c56db30a8cfa4d8291d710a3a8d30ae0a6df5c00891eb9f66affd9d07f80b5a3'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::compile_baseline_v22#1', '_referee_disputes_from_verified_sources_v22', (), 'a446cbadfdc9f3b476f93ab3ac337989cd3430a4af4f989c8f24805b3ef76214'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::compile_baseline_v22#1', '_v21_inputs', (), 'dece77de137dead7191c12bf4d77bb915bf9b8598e054cd3baee78e0cd6a951c'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::compile_baseline_v22#1', '_verified_source_aggregates_v22', (), 'eadfcbd34005394602135fb76a865425e5be438a135fc3252320c2edbe2abbc5'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::compile_baseline_v22#1', 'aggregate_referee_decisions_v22', (), '27a6c7a4fe66ac88be270a2e7445c5a28757b98fd411f334f0f551dd9f095071'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::compile_baseline_v22#1', 'legacy.model_dump', ('serialization',), '66dc8648e7530767da1cb21be11677da81257c9ed34efa37ec501216a8807ce4'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::compile_baseline_v22#1', 'tuple', (), 'fa4c2c7ece416d471eabace3473d5a1e94184f2aabe1d9be45560d253b2c903c'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::compile_baseline_v22#1', 'verify_canonical_baseline_v22', ('validation',), '3a75432de3ddecea3bacb6fabbee73818f8babc7a73c62d5222dff3fba1cca92'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::compile_baseline_v22#1::<DictComp>#1', 'raw.items', (), '0c98f10e8bc8539c7216f3250d2e64a9e92561b6d7a3bbdba2e0254ac41e6546'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::compile_baseline_v22#1::<GeneratorExp>#1', '_fragment_v21', ('serialization',), 'a47b6c64e07319e3bd2adc80764f68844da31abda8a57b6f63554228da38605b'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::compile_baseline_v22#1::<GeneratorExp>#1', 'item.decision.model_dump', ('serialization',), '51058ed9ea844df54ea15396754e7f16f3c0d09a71fd4549900e48bee322acd5'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::compile_baseline_v22#1::<GeneratorExp>#1', 'zip', (), '639944494e554faaee7b39a7aa2741a2a809adb50c357fcbeb9c103adc209547'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::compile_baseline_v22#1::<ListComp>#1', 'item.model_dump', ('serialization',), 'a2ff83926a3385245f4eae5f7cc3326871d49f19646d0f24db6ff98d49ce4812'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::evaluate_outcome_sensitivity_v22#1', 'ReconciledGradeV22.validate_for_baseline', (), '82609182ab303aea3ec6e0fc64e645b5e71c8ebd8bd0d73402898107412db905'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::evaluate_outcome_sensitivity_v22#1', 'RubricValidationError', (), '1eaa84d72af6ba0d0ae3fbe3f6c638407a8de5f75a4241df346aeeb9d880cae8'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::evaluate_outcome_sensitivity_v22#1', 'RubricValidationError', (), 'f18861edf04c5a28396306d649182d39ba1ea0caa8908e423c8187600c828de7'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::evaluate_outcome_sensitivity_v22#1', 'SensitivityRecordV22.model_validate', ('validation',), '6a97d9bbf4fec6914efb447d389dfb5c30df2016ee525db54394c29872ad9f5c'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::evaluate_outcome_sensitivity_v22#1', '_hash', (), 'be1a46d500b7e5cdc3be63fb664fdc02361f91682f7ea86a3719575088418d35'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::evaluate_outcome_sensitivity_v22#1', '_ordinary_observations_v22', (), 'b55ad4d5c1f318ab53960161f036931519ba6d25467c341c44b4df2399f57a01'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::evaluate_outcome_sensitivity_v22#1', '_score_v22', (), '1b7676a082252fccaa68222d7f521e56c66af3b9b8df830c697ddf0bd53ec5a9'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::evaluate_outcome_sensitivity_v22#1', '_score_v22', (), '7c86e47ca56233b7f6940dd31fe31fe29c8e54619a0ea0e498a6fdfb57998b1d'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::evaluate_outcome_sensitivity_v22#1', '_strict_rubric', ('validation',), '49888a51ed99832f28dbb28f58ee2679778c3127a187abd908945ebcd7e3d76d'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::evaluate_outcome_sensitivity_v22#1', '_verified_grader_aggregate', (), 'b8b553afdfb731f265d85090c0332cfb7f7f100075cadb36c6ce1bc466de1bc8'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::evaluate_outcome_sensitivity_v22#1', 'auditor_world.append', (), '7653ae69350a7c71f993ae0496ca89e98f215cac8a1c963d2ef8e971a296563a'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::evaluate_outcome_sensitivity_v22#1', 'differing_alternatives.append', (), '3d3b2c2b317aac48792ea59a963e639ef23b1e8d337cd2b3c8e5a5fb4acd1626'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::evaluate_outcome_sensitivity_v22#1', 'list', (), '99eac0140f90120e295c9f0d393edc2ec7cf5f079d403c65c11a9f06b2ea8c72'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::evaluate_outcome_sensitivity_v22#1', 'list', (), 'bb788abdd24ee776973e0a0b07848bd88a5f09208ce4922ccaec4f889ac1a6c7'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::evaluate_outcome_sensitivity_v22#1', 'reconcile_grader_lanes_v22', (), '193cca145ababc1c69d11b0c26b8ff157f5c8add6620331fb4dd056e59c7e6c7'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::evaluate_outcome_sensitivity_v22#1', 'reviewer_world.append', (), '41e7db0b4c7aba4273a418553f84547c04fdd199f5c16436ad9867fee6f1b579'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::evaluate_outcome_sensitivity_v22#1', 'set', (), '237ee594cb4d7455e727a2934f07d100d5022314717cbac861af43d2d64c93a3'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::evaluate_outcome_sensitivity_v22#1', 'sorted', (), '50a7a4b8dc3717ea8bd715ea4a4ad37d73886f316c1a69267c66e1d4b27df177'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::evaluate_outcome_sensitivity_v22#1', 'tuple', (), '1aa2209dee3404e7b7291442af1d877cceb7245e8e45a6670c9b7a72e5bb1fb3'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::evaluate_outcome_sensitivity_v22#1', 'tuple', (), 'fafc343dbebd29da3dc8b48977ea183dee3f67ae47b699b947043d434fd44077'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::evaluate_outcome_sensitivity_v22#1', 'verify_canonical_baseline_v22', ('validation',), '00b5b7d6a22adfc5bd478fe0be4a77810211074909beb0abb54508051fc36457'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::ordinary_grade_batches_v22#1', 'RubricValidationError', (), '54d2ae4d0cdc04a95d1c3e382fae874db37093f43a6253481515b138f5b062ad'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::ordinary_grade_batches_v22#1', '_strict_grade_coordinate_v22', ('validation',), 'e60afb37a863efdb58d538633ac494f9d0f6a074f4c51e224182c293ace29f27'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::ordinary_grade_batches_v22#1', 'len', (), '78ea68ec2879db2d516c6278db5122518928502310e1aa1b3a0469248c2523a8'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::ordinary_grade_batches_v22#1', 'tuple', (), '67a7606cb34226056257d54d545216c7a535366a9eb4a791c6a9b420b8e2e39a'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::ordinary_grade_batches_v22#1', 'verify_canonical_baseline_v22', ('validation',), '24890a3938f01771899533f62997116ea2c8a898cb203380a22dac777922bdea'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::ordinary_grade_batches_v22#1::<GeneratorExp>#1', 'OrdinaryGradeBatchV22', (), 'c08d72ba8b2e4b211852dda1c4af41a439bcac145ce7e7c69fb13749460a6abe'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::ordinary_grade_batches_v22#1::<GeneratorExp>#1', 'len', (), 'e3237cef979e8501a4e0696f4098a42207cfce0f9c61c73b2e89967b32885f7f'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::ordinary_grade_batches_v22#1::<GeneratorExp>#1', 'range', (), '98ef04841c83b469ce774f56b9708ed5508ad6386dcc3bac393a20eb06f2c356'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::ordinary_grade_batches_v22#1::<GeneratorExp>#1', 'tuple', (), '48fa1bebca11e98e13d550308071473cd3d27937f2b323aa17b91e206dd5488e'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::reconcile_grader_lanes_v22#1', 'ReconciledGradeV22.validate_for_baseline', (), '3f8ef2f99710453550bbc888dc9c162d321e96c343482cddf5d6b541a0a4babb'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::reconcile_grader_lanes_v22#1', 'RubricValidationError', (), '56afb3c160c677f9484be7674f5c973a5232594da51f981facef5a1bea728eb0'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::reconcile_grader_lanes_v22#1', 'ValueError', (), 'b76a8116ca28c7a32c1da11c87f0b14bbfd984b9b07510d2f576dbd5cc135ec7'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::reconcile_grader_lanes_v22#1', '_hash', (), 'f3b3b7cc86ae71f35ceec4b45de8a3f5481c21ea464dbbc648214e7fe32c100f'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::reconcile_grader_lanes_v22#1', '_ordinary_observations_v22', (), 'c38f33b4d7c0236c05098213bf9d231a65869d73e3370b7877a3d0e87ff0ef5c'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::reconcile_grader_lanes_v22#1', '_same_observations_v22', (), '3da3f4f89411b480f5bf707ebdce71bdf53c043105294ff91df64123c7fe5830'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::reconcile_grader_lanes_v22#1', '_score_v22', (), '61bded88776a3613aa5bbb03887d6a58a9dc8fef775072e78d999398daee8f52'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::reconcile_grader_lanes_v22#1', '_strict_rubric', ('validation',), '0c5a9a5eb082c077ed2f3eafa7741792e13580c8d4ac5958c490ed1e14da8de4'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::reconcile_grader_lanes_v22#1', '_verified_grader_aggregate', (), '1eeb01d7610c4d30d28fde5383debb491f9054869fd461f618d517ddae909e51'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::reconcile_grader_lanes_v22#1', '_verified_grader_aggregate', (), '67f268e535ccc0c7f5f3c3cd7a324f4f90801355888b85b838a80091a3123ca0'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::reconcile_grader_lanes_v22#1', 'first.model_dump', ('serialization',), 'a18f74cd7445cf72c8cd9ccd6d15f6463edd40ec12aed3141d696fc82406e49c'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::reconcile_grader_lanes_v22#1', 'second.model_dump', ('serialization',), 'db06178b9a1e04be670ce62bc60c6bbe5e2e1fe5ee1bfa743de6d73576b18630'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::reconcile_grader_lanes_v22#1', 'verify_canonical_baseline_v22', ('validation',), 'e8a8532236387765c2082e72d735fd6ae98af9d5ea3393df9bd42691bf9b6ee1'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::referee_dispute_fingerprint_v22#1', '_referee_dispute_fingerprint_from_validated_v22', (), '869282c639376045a495549f676b124766c997cfde86d32cd8a0466d48ac4939'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::referee_dispute_fingerprint_v22#1', '_validated_referee_dispute_v22', (), '4e79ea62e7d1df809df2e63baa6a72b0ab9ecc4ca91d25cbfd94ca389a75e2c5'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::validate_grade_fragment_v22#1', 'ContestedGradeFragmentV22.validate_for_requirement', (), '70853b6ddc120266049f91736f0e86f1ff62db8a40c918433d8c21c1960eb4df'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::validate_grade_fragment_v22#1', 'OrdinaryGradeFragmentV22.validate_for_batch', (), 'dd3010bad5512136cf8de358891d0398286065c18f7b990a0c55e2b2ac0dbd1a'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::validate_grade_fragment_v22#1', 'RubricValidationError', (), 'b564b1664ad0830777ca46797bd9608aaa3a09ca622d23554fabdee64384e57c'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::validate_grade_fragment_v22#1', 'ValueError', (), '2f529a49fb7e60e1eae482e9b1823c31f3e2fc6fb6e06485ef9bd59497eb5a95'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::validate_grade_fragment_v22#1', 'ValueError', (), '327d102c50c8ddc23e54a456dffe8684b31f1d657dde4186a559bd472150e9ad'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::validate_grade_fragment_v22#1', 'ValueError', (), '70ae59d93739bfd1040c132d78cfdec799e3ee4d1f908ed8a33572359f9497fb'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::validate_grade_fragment_v22#1', 'ValueError', (), 'efc5ad4cb76e850763b1ccfcc6f3a2cd4b94234b1eee65e109eb60fb941b8640'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::validate_grade_fragment_v22#1', '_strict_grade_coordinate_v22', ('validation',), '87bd9d9f22653fb86291f04f0381a062693fd96f0563ac96816475437fb1d846'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::validate_grade_fragment_v22#1', '_wire_snapshot', ('validation',), 'ac2792eef91efefb50c686d32a0ece6972712f2ece7c4162afcf68d522eecac6'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::validate_grade_fragment_v22#1', 'any', (), 'd011244e3e8ff7119f149295b8fbe1a5a8a179db27949f52938dad72ddfa0e2c'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::validate_grade_fragment_v22#1', 'hashlib.sha256', ('neutral',), '3a9d009f2206a3e7f2378f3432258f417e3a4c8a1d5f0f42f83678eb4e1a9854'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::validate_grade_fragment_v22#1', 'isinstance', (), '06a4c0cfcdeacba1fbcb618364b4cc0ddc5bf0dd87ba76075ece1984df4a4f1a'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::validate_grade_fragment_v22#1', 'isinstance', (), '7ab6bf3fae0c117bb434373484f57ea0d75714899b5b3e1a6f7900f09beac06c'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::validate_grade_fragment_v22#1', 'isinstance', (), 'ac3a6ecb2cf1bb0cc303cefd5945a64d82e17c94bec26d97c7a823b424e8b08d'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::validate_grade_fragment_v22#1', 'next', (), 'adeae2e0d942f2110d3ad62da5b0db1d97de4b5700e48c576678b3b08201e262'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::validate_grade_fragment_v22#1', 'next', (), 'b3830db328e31f0da0a9a9135e4aeb72d3c9d92da1eda587b9816089f0b4e9f8'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::validate_grade_fragment_v22#1', 'ordinary_grade_batches_v22', ('validation',), '7412c0b3c0536c83c4a2baea5c7e918267ba779757cf65b79e3f15b03aea80f9'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::validate_grade_fragment_v22#1', 'raw.get', (), '30257081a2fe7bb6b11c7d4855a9c1ec236a6d38d12135d7ea1663fc5f29eec9'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::validate_grade_fragment_v22#1', 'raw.get', (), '5d17eb69a75f78c07783c412a06181311f93f6e911619e466df4d1815b1b2b5c'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::validate_grade_fragment_v22#1', 'raw.get', (), 'bf7cd7520a8b7ccd0733ccbc51fc5bd681699a06c2bd380d1838eca1795013f7'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::validate_grade_fragment_v22#1', 'report_digest.hexdigest', ('neutral',), 'e720611413f8a84b1855172cfbc436df5fed66ce7158b3604fdef2f62d85f6ff'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::validate_grade_fragment_v22#1', 'report_text.encode', (), '90a7951e56844503578c437de50e825e27ac9ac455322b8613dcf5ea1b348ded'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::validate_grade_fragment_v22#1', 'verify_canonical_baseline_v22', ('validation',), 'f1af9211c4a2794ef5ddf22079ce7787265ee45dc4ab0db5b1da2ad1e36851c3'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::validate_grade_fragment_v22#1::<GeneratorExp>#1', 'enumerate', (), '7b81fddda975a09c1e9b6ed8324a5a3ea91488ec4fefb3beddf491901ae6ae60'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::validate_grade_fragment_v22#1::<GeneratorExp>#1', 'ordinary_grade_batches_v22', ('validation',), '0f7ddec22cb906d83842f7192dace6cc41f537e6402c9847708ffda9ccf55a1f'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::validate_grade_fragment_v22#1::<GeneratorExp>#3', 'report_text.count', (), '09c272bd9aa96bcf152241d8732bcd0c4dc1afacc79a23509c8fc9a9e3834b54'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::validate_referee_fragment_v22#1', 'AcceptedRefereeFragmentV22.validate_for_dispute', (), '9fbf96605575ed4d94332281537a9aa03b29770206b8af96d919618c795bf5bf'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::validate_referee_fragment_v22#1', 'CompilationError', (), '08c649c5dbd9bc54da53c654467278a936f7ca5b00ef04506a0e4015b5af4826'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::validate_referee_fragment_v22#1', 'RefereeDecisionV22.validate_for_evidence', (), '331fa18b1505e29eed3864453f493a7880c2b438f4a712e189667ad90ce08d90'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::validate_referee_fragment_v22#1', 'RefereeDisputeV21.model_validate', ('validation',), '8d8b59a35408791d7bbc36614afbb975aaf40da8d8a8d1b256b974c24177f20c'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::validate_referee_fragment_v22#1', 'ValueError', (), '45590b0cb9586713bed41b1255a5382a4466a73dffddb289dfe06b0b9ba7817a'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::validate_referee_fragment_v22#1', 'ValueError', (), '5d27f2f5f96f2f91c4ea958de8773ec8a5461fd203ae74e3ed91cb13c29ef0ea'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::validate_referee_fragment_v22#1', '_fragment_v21', ('serialization',), '27ef501237d26dbb6fdd2761d0a20a31c707ddf763e6687cbdbf35615747509d'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::validate_referee_fragment_v22#1', '_strict_rehydrate_v22', ('validation',), '28221d87f561e089d28bfa15caaaed429ce4bf9b457f92e15d563eb3688a5554'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::validate_referee_fragment_v22#1', '_wire_snapshot', ('validation',), '491369d703862354f692a55edb36c9b8fabcbb2bbdc4582836b682354bf9f1cb'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::validate_referee_fragment_v22#1', 'checked.model_dump', ('serialization',), '1c004c15f0ad5878f94026d7ac7733cbd0e727a94005d58102c5179a8e83949e'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::validate_referee_fragment_v22#1', 'checked_decision.model_dump', ('serialization',), '3dfa29939a0549372ede88f7fd104f92193f5cb3fb0dbb14c042b6efa3a0fbf7'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::validate_referee_fragment_v22#1', 'decision_raw.setdefault', (), '2daa3d830868ab44d9e2b7c5731dbca1413601203e939d411d4419b69f938ea6'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::validate_referee_fragment_v22#1', 'isinstance', (), '815799ce584fbbc0ebcfb9a7afed6e46e23b00ab06857dbd7783b04643efb8a4'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::validate_referee_fragment_v22#1', 'referee_dispute_fingerprint_v22', (), '1b3b4f55dfd153cfdcffddc71b1080ce426c50e1793446f7e92a5e200558f0f7'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::verify_canonical_baseline_v22#1', 'RubricValidationError', (), '22bf8fac300b2bf9615b237f2e09c5f86a7ae292b90a1f0304f36d97af4bf755'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::verify_canonical_baseline_v22#1', 'ValueError', (), '20496dacbad9b89d8132bb0d2ab353183cfc47c02b6c0d41f38db2941c1422f8'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::verify_canonical_baseline_v22#1', '_canonical_baseline_fingerprint_from_validated_v22', (), 'a9c39765d57fd8911fb5fe1ff6516819d63a2e11b5e1c26a05db223b186d2550'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::verify_canonical_baseline_v22#1', '_validated_canonical_baseline_v22', (), '31750b86ad4766bf7241074a95a11648e11cfec7f04c2297698723c6f781a4db'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::verify_source_audit_aggregate_v22#1', 'CompilationError', (), 'b0ba9606e4f58a8704d3fd223bc54982c0d33c13211707c2e1961e4aaff21f7f'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::verify_source_audit_aggregate_v22#1', '_verified_source_request_context_v22', ('validation',), '696ab0d4ffe7b3b1088d2961c3f7d21ab9320f03a9dbc313ec8bca37e66736e9'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::verify_source_audit_aggregate_v22#1', '_verify_source_audit_aggregate_with_context_v22', ('validation',), 'aaf61b4deba844ddd1d87b9532e32326a6546365dc9d1e9511c02434e745c5e3'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::verify_source_audit_aggregate_v22#1', '_verify_source_review_aggregate_with_context_v22', ('validation',), '464e007ba6e78c8e08f28c254790aff0906aead42406395b8d9aa31f7417c53e'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::verify_source_review_aggregate_v22#1', 'CompilationError', (), '18bf6d514831f6cceaa8b31d92a537b7035592070fdeb71f9a4952c255251d1b'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::verify_source_review_aggregate_v22#1', '_verified_source_request_context_v22', ('validation',), 'cf2a14f47c5e3ad5bd33971f58f40a2ada647c241f56a1c7d49b5d9dca00fc03'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::verify_source_review_aggregate_v22#1', '_verify_source_review_aggregate_with_context_v22', ('validation',), 'f9d20538e1a9c4fe7c9d837949d3d583724789c4d54728418c5cdd067e9b7af1'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', 'ContestedGradeFragmentV22.model_json_schema', ('serialization',), 'd5d16aa35402601d5c23246178a11385e25c0ebc76df46e4e7e9783b33ccb598'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', 'OrdinaryGradeFragmentV22.model_json_schema', ('serialization',), 'fa83c3d01d1c9d9a529da0728ca8b7e872571c24e974e19215a582c4ce2339d6'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', 'RefereeDecisionV22.model_json_schema', ('serialization',), '7f23a7b92fbcd483557b99151f65efc4ae83c15eda647716823dac81ca6c1203'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', 'RubricV22.model_json_schema', ('serialization',), '19f4dbe9b85f1be37593f28d52d006b6a9032f42a027c974c2e1fdade50c4bc5'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', 'SourceAuditFragmentV22.model_json_schema', ('serialization',), '88e6b636e685ee722e01a5734f122e534f0bcd475658339d262f9957878a9f95'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', 'SourceReviewFragmentV22.model_json_schema', ('serialization',), '6d1a2cbe6d731aded4d0d34c9a599518657d24d2635d35d8b8e8af3f1c49130e'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '_ContestedGradeDraftV22.model_json_schema', ('serialization',), 'e4b8ff0ce515efc5445fddc3852dd76ed2407042ce2daddde5d31b61938000e6'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '_OrdinaryGradeDraftV22.model_json_schema', ('serialization',), '4a796334cbbf3d1365d10895c2128e88b0c53728615b653ca7c0f135069e8dd6'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '_RefereeDraftV22.model_json_schema', ('serialization',), '4543b05db7d6b0c807efbad3b5355bf2b810f04527b99d11a4a2c976611b40ea'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '_SourceAuditDraftV22.model_json_schema', ('serialization',), '23b3f531a8f1bba8942a80a3c6fa5e4b5e567173a7d76b4405cc38e3c76a1cc0'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '_SourceReviewDraftV22.model_json_schema', ('serialization',), 'b7a01d3c57275e56577576f9181d76be1a5f8433380b714d24f56cc28392fa3f'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '_schema_hash', (), '1fbf64f6cfd1f020d9bbba9302dfdac03bf1e74c64964c8f5dcfa8703aefa4b3'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '_schema_hash', (), '3f1bc63ca996dc3f13346e8036bfec8967d525ac28aa006c1914a1ad3bf5e54b'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '_schema_hash', (), '448fe37bae7f7d186abb89f7e48064e2f7604302f801ea3f09622aa19fd8ba4a'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '_schema_hash', (), '4f8f40b6cf2fea2e5150469fc8bf72992ed2e4ef49eee46372ad2b06033c89a6'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '_schema_hash', (), '518dfefaa8387c0239bc493fa6116ccad7c79068cbd639385c00e5e8040d0095'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '_schema_hash', (), '5bbbfc4948e8d22b0a8ffd2575a46421b262987b9c93133013479e8856c40d48'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '_schema_hash', (), '5f225c68ce7ff5b1058ff90e257afffcf151dfc88cecee2af8bf88e3b340624f'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '_schema_hash', (), '711006c36d0dc46d92f6375aa877838be91f9c4b44299a4384ee2755d977f274'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '_schema_hash', (), '7d08d1cc02711952cb52dced4b28d7324d794deed4bc5fff55600148f82991ce'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '_schema_hash', (), '857a33d356db45f6b129d548e91f9968106665e1c0cb22f471aec613bc4077c5'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '_schema_hash', (), 'a134f983053dfe950bf95eb23856f46ca1c578c7c76c84722cea5115ecd79b1d'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', 'compiler_contract_fingerprint_v22', (), '54b50a06e6835d127f2099b164032cdbd99efb3aa8ac5d1e1ed4f1d5c65c92e4'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::<DictComp>#1', '_ENUM_ALIASES.items', (), '8e7fc3515007529985d4ecd8ae09b7d9c909a1450bb15074e4277829060b4038'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::<DictComp>#1', 'sorted', (), '6de83be1eadc9332fdbdef4f721f9bcaf3497f63e6140b696b55bf29938e2b20'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::<DictComp>#1', 'sorted', (), '7195e720a376d4162e9934f2d761786dcb28f01a1e9c22c1cb5ef23cff83c5b3'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_VerifiedSourceRequestContextV22#1', 'dataclass', (), '54211df55b4b3f33f77ab0cf076e30583f77585538ec440208df8e789bf90a18'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_audit_history#1', 'ValueError', (), '325a5445b868ba85168bea375ae58fc747b81246ad19e3dbb56772710442a7bd'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_audit_history#1', 'ValueError', (), '98eeebb025364c00f23ddf928283b4271c31f02324677dad192bc01c54d59ba2'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_audit_history#1', 'ValueError', (), '9a05b8cb94a3003bca93b1a502022167bb85d55b018b6b5d6759c14b26da928e'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_audit_history#1', 'ValueError', (), 'c12e394272d3448341b8c3262d9ea2c1bcb2bd91f730e38c50dc9e4b684b50a1'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_audit_history#1', 'ValueError', (), 'ccb1775dd4919c18fa6ae4686bea1ef1de4e3888202da2026f5106c0b7ea7a5f'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_audit_history#1', 'ValueError', (), 'ceed7a56620eb82af54384a0488e0d61f093934540ad61d1f25f3d70e635981b'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_audit_history#1', '_source_audit_request_from_context_v22', (), 'ba440c46d9d08beb31a90f3e5a3e1299767efe33f263501416acd10960109d94'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_audit_history#1', 'accepted_concerns.extend', (), 'ab9d1f8ef90edc2a8497e7c55c067f93d157f43c26744d17421ac1a4a4ee7fac'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_audit_history#1', 'any', (), '5e1b3031a1071b12ad9e14c994de27d8ab97330474febcdf6b8bbe94f1587767'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_audit_history#1', 'any', (), '6ccd5d901ff3ee222b90e741a1e551835d9bfc74bcff5766a7982711f55f71a4'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_audit_history#1', 'isinstance', (), '56ba2f68ce89846074b95241b18f6929924009a58f6463ccf883cc549175a5b7'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_audit_history#1', 'len', (), '06be2b10d7e8772bad2cc46982d65b02e6f6503139bb2487be4b34aaaa565b56'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_audit_history#1', 'len', (), '532a4a7751141423236a59eac261e6df900530c765b7d6f86e6bf0169afe0466'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_audit_history#1', 'len', (), '716d478e6dd4ad7ab08ffbaa8d00521a26ea675a946d8ce833bc424c4f9ad4a7'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_audit_history#1', 'len', (), 'af13c282a3e51d6aa7438235e58c0b346de0a18cee4c5a839010f3dbee4bdb6e'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_audit_history#1', 'list', (), 'b8103be1f4c16e8052a071913522307582b42b735b2fd68582a74a0ad39b0e2f'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_audit_history#1', 'range', (), '378f75438017bd4dbaa046333b9c5ca65161bdc9eeaad7e38af7aabff677c18e'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_audit_history#1', 'sum', (), 'bc15e41a99de1269d75e14e5b19d44ff8f230e6158d670b2852dfd68c8436798'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_audit_history#1', 'tuple', (), 'c19c4172124e26420040731f687aeecd80cbf223e49796f4aface03b8f2c5d87'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_audit_history#1::<GeneratorExp>#1', '_strict_rehydrate_v22', ('validation',), '2dee8c02ff4e1a0df143a683899304c10b6b543db96675eff2093901d0033be6'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_audit_history#1::<GeneratorExp>#1', 'tuple.__iter__', (), '598932d0f1bfb76f711f2ba5270483c02b0070548ac1379e7e596068fe65a536'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_audit_history#1::<GeneratorExp>#4', 'len', (), '8fb3fecfdb823861cc9f5fb038aaa4fd4dc849ba4384b07221d6757a30a149cc'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_audit_history#1::<GeneratorExp>#5', 'concern.model_dump', ('serialization',), '153cc537c0ac43c0d72e873a41c8e259cd29a2cc4ace7a6792ed45fbf6e4d578'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_context_source_metadata_v22#1', 'dict', (), '3b69a6a41832762888c91ab2f714962a294bea9cb0a241f78627da27bbd8c10b'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_context_source_record_v22#1', 'cast', (), '63ebdd14941cbda90d3a5d56a4f3bbd57eb1af8b1dfff5178d88042b2abda6ce'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_context_source_record_v22#1', 'json.loads', ('serialization',), '34105032792e4f9a81749b415e267e4f8f8009ec12e66795fd84b132eb331995'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_fingerprint#1', 'canonical_json_bytes', ('serialization',), 'f80a834f7b21a53bb7ad1ea91b56f1d7ddeb8b4a845c8ca7e4e025a5df057d78'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_fingerprint#1', 'digest.hexdigest', ('neutral',), 'c0425a2939de9f5d3eef9fa8c56b5a5e4cabb9ee63925f50c512c81376276a0d'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_fingerprint#1', 'hashlib.sha256', ('neutral',), 'fcf65bf022e4349b5f5d787b567ccf26a3aa20b606e642b0b8e2cd70a981d691'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_fingerprint#1', 'request.model_dump', ('serialization',), '03058a640af974c59964315ed31c9afc9bd777ab300ae47201ebf3d00c8ed2a4'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_frozen_source_record_v22#1', '_context_source_record_v22', (), '2aa16b1e5d0e9fdab614561d9f0b24000115b41c79e6cede483d337e3a956e26'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_frozen_source_record_v22#1', '_verified_source_request_context_v22', ('validation',), 'cf4e8ce16b2734e8065319b7c0f79e3b278707baedba67370426527f69b77204'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_grade_context#1', 'ValueError', (), 'b83395914229f1e96b0a4a21bd9e726c999687b5a849919d65319c39d3eb072f'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_grade_context#1', 'ValueError', (), 'db972e69d1750afe3666b01189312d3a56565551d2b6ee987c745c8c5ac7ddfe'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_grade_context#1', '_strict_rubric', ('validation',), '0ba956e7b7eb696bf04e4a35ad9b9130b22d4ca4f686968f7a7eb58570f84484'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_grade_context#1', '_strict_source_context_v22', ('validation',), '1d8380ee0d6b6b7b5441d855e94615c9d1205f3b0913e5db5441a100160779b3'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_grade_context#1', 'checked_rubric.model_dump', ('serialization',), '4f33c8fe91b2c87265adbb4a85a64471940b16566e9a3bb98057c9afb7bb5a1c'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_grade_context#1', 'hashlib.sha256', ('neutral',), '0794c7e05bafcf6ae28983b9e79093495a65274e0dc0ee425cdab31f4eff0554'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_grade_context#1', 'isinstance', (), 'bd0c1a81aa9af49477bd14a65f5f61108a559aa818aaa3831a53e6bb90807cdd'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_grade_context#1', 'report_digest.hexdigest', ('neutral',), '119e1630bc013ecfc2299086300ad2529aa27d66e59f53211ce37a743279b7c5'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_grade_context#1', 'report_text.encode', (), '6bd6ed576ee1522d8f0c220d2bf3e681ef3496327221d1babe928f3baed641f1'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_grade_context#1', 'report_text.strip', (), 'c2defd4af4f182348d494f53991c141b555e42cf112839f78ab400a7f5396d42'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_new_request_v22#1', 'EvaluatorRequestV22', (), 'e447e160b1f20600f9a34a42f1e71fcceb1cee92fe13ffcc4f2e6d2d4548cc63'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_new_request_v22#1', '_fingerprint', (), 'e53cccbcaafe733b41f6ccf0d500684b2dc58867906fa0d3c2fae53c822b769d'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_new_request_v22#1', '_snapshot', (), '2f628082f8b6f786ff4252ca2f638040080d730412f66e7fa42dd5a909a06425'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_new_request_v22#1', '_snapshot', (), 'b05a0ef41dbd5690ebc8f5b1aba15b646fde0f6d5b735959b3ab3eefd089dd0f'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_new_request_v22#1', '_strict_rehydrate_v22', ('validation',), '3a35e7dc68c13fbb62276835797e5631ec93dd89ec84c940e744b41ad26d32e7'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_new_request_v22#1', 'provisional.model_dump', ('serialization',), 'e4f5a35a5e6b3ca2f62663dcf20fc99c2e4d62a7e5c86062ff1e51ee4d220131'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_review_history#1', 'ValueError', (), '01ae9ef142883dab0d4a09dc6d0aa779b4b4d184c981d8858a31020e940be6d9'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_review_history#1', 'ValueError', (), '4f115ea9c99543c74e47c4167ac7e298f9eb917e4e24b92caa8123bad1cb6d05'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_review_history#1', 'ValueError', (), '7c351c49ffbad61d1ba3c1a60d33f655c75eed860f536d3006bf6af67e21c6c7'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_review_history#1', 'ValueError', (), '91764032e2572e035a2a99686fd22b59d40c8bf9937c44618f2f81b5249ac880'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_review_history#1', 'ValueError', (), 'd3a393d72ac499392a0d2c6fa6b573786a07fb34a69bdd9ad3ba856e459f8c4d'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_review_history#1', 'ValueError', (), 'f8c519c2bb4520c3323d0d1fa7b0c0259daa6974adc5e81a10b92d4e44034635'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_review_history#1', '_source_review_request_from_context_v22', (), '414c908f862b0db5e7ba9317ba600c60bea6f413d9407c38d36f948dd3b022b9'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_review_history#1', 'accepted_proposals.extend', (), 'e8a76a2c07c47c704a85754fdaf99f3df77639de7e60d1f35319f31703eb267c'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_review_history#1', 'any', (), '0fed4100ce12dcd15c266d26d6fb047aff6d70b7a0d41b516f5cf55b8ad9e280'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_review_history#1', 'any', (), '1bc84727a1f98fbebe68d62824322959bb56e0322750e517dd85514e765e6648'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_review_history#1', 'isinstance', (), '57533f908fa593f5b2041af3bce1f89d463caccf9d065c25a7970366e6b599ec'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_review_history#1', 'len', (), '14b701b87f96eeafdbd76678191df0a9e1692fa00a948cea16cc718ff7240512'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_review_history#1', 'len', (), '8fc8f1d1829b05f925ed1c1ce4f037dda023307b8fe3d050fc97ff8bbc3d1201'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_review_history#1', 'len', (), 'daa470c7b5c65fdc2402db0eb903474a95be714f9a72a398f601d984d1d3c6b7'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_review_history#1', 'len', (), 'fdebaf23e775b7e89b403da310a78bd0cbff37e7a69b82384bd1c49a9af092f2'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_review_history#1', 'list', (), '8dac369a3ad1a878b36c39eecf72fa2e2cc033cb95447f55be6efce452c57364'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_review_history#1', 'range', (), 'ce4d4387014e755ce8f2dce472fe98536d8e5a6d24de695becefbc943b539120'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_review_history#1', 'sum', (), '42a5ac0f4307a3f4e304fdcb99f6253aa37ec573837de5697dc4ee99cdce7204'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_review_history#1', 'tuple', (), 'c7c90e60794e9250bd3f29528ed28f281ea656cdfd125a8adaa72a95ef8f2e1e'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_review_history#1::<GeneratorExp>#1', '_strict_rehydrate_v22', ('validation',), 'f2ca4ed0776edc24ee5099155c54e83e877b772e77f7de8a99a7380b83089d69'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_review_history#1::<GeneratorExp>#1', 'tuple.__iter__', (), '18d33c940eda0dad427e49bffa49d36974561deb7fa9bd3fbb9e4ad5d8c5da1f'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_review_history#1::<GeneratorExp>#4', 'len', (), 'e24df117c6b1ce8df3dc5c950e0f53b0afca3b2bde0dfa7ad3163a35de7f4607'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_review_history#1::<GeneratorExp>#5', 'proposal.model_dump', ('serialization',), '06f368ce69a39e381d211009a2202870cde8680d2e98e7997bcd4c0bef09c6e3'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_schema_hash#1', 'canonical_json_bytes', ('serialization',), '2c800e7f87141d8e20eb54881ade31e6a840bce23982dda0a6e689198f199ad9'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_schema_hash#1', 'sha256_digest', ('serialization',), '927b9b5b9f2f85e2e21fc544fde3ee6042acbb701b14055c86127aeee92ddf64'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_snapshot#1', 'ValueError', (), '44b26cc8285dc943c78d3ab073bc922d162d66bdaf79ffd671dd8b43173c6e00'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_snapshot#1', 'ValueError', (), 'f11ea1cf059a970cb19c2f879f1a476b68e479d17f1fdc43a224a8f15bd54265'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_snapshot#1', 'canonical_json_bytes', ('serialization',), '7488592a694bd3be27a5a1ce259afb32e0b4460734413dd8e1353cefde956312'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_snapshot#1', 'cast', (), '1b5a8fc3ec8b3297367e2e7ac5afb3772295b09765feae4a03763b87d3148fe5'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_snapshot#1', 'json.loads', ('serialization',), '951b5b75e673632b8ca53e3cdc8463de1d58be04f1e37f40194a868e9254a8d3'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_snapshot#1', 'type', (), '543cc65a05f7830308aca0c02e374e2a2d0a1c315cad203d99a6cea5d317337a'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_audit_request_from_context_v22#1', '_SourceAuditDraftV22.model_json_schema', ('serialization',), '118df3ec93168a001d970408e119fb0886232e4608664d76ed0760b1ce55abae'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_audit_request_from_context_v22#1', '_context_source_metadata_v22', (), '2b52689dab6be36d1e6cf71f3429cc4f9caa3bcf6f014a9c976a7c53b4ea4be9'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_audit_request_from_context_v22#1', '_context_source_record_v22', (), '0fb3d81837c4c7710fa64a1d6f71467c386074f5182a7226e85f1ac7a117fdce'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_audit_request_from_context_v22#1', '_new_request_v22', (), 'bd3c34e84179bbaa9cd75d31fd1f3b188fb7b7cc31112b0582eaf2e83fbc82cf'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_audit_request_from_context_v22#1::<ListComp>#1', 'proposal.model_dump', ('serialization',), 'bc83c6de0336f35c2ec5a352cb7576d5bdcf15b3d00fcabbaeb3e5e472907a57'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_metadata#1', '_strict_rehydrate_v22', ('validation',), 'e703965e70dc47c902e45361fe37deae792789f09638b373155fef4dc33f1b42'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_review_request_from_context_v22#1', '_SourceReviewDraftV22.model_json_schema', ('serialization',), '72652263e2cd3c42b67e245c78f42f18b200460a06a39a29ee09cdb72d76e22b'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_review_request_from_context_v22#1', '_context_source_metadata_v22', (), '3bfae179789ef41f39254635a340c89548e6f5cb2588e5855f5b37325cd72f88'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_review_request_from_context_v22#1', '_context_source_record_v22', (), 'b15a992b8c0259f3ee3ac27f9bece4756a983c54e3bd23cd055a7ea4379846d6'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_review_request_from_context_v22#1', '_new_request_v22', (), '7247b3d21fd4ff489c3e9ddce0fe8d270ae4cb33db2523527ab7e144633e9bdf'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_verified_source_request_context_v22#1', 'ValueError', (), 'd2061bac7f17dbf57498c369b13f6a5de6c4c1f749e1434459ae4e188fc15c97'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_verified_source_request_context_v22#1', '_VerifiedSourceRequestContextV22', (), 'f0af15600b59f7316b067f1b63d8a6d260da5e654d2847eb4cfa8a7a6e552ef8'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_verified_source_request_context_v22#1', '_snapshot', (), '8bf889b1cc44f5377eca5967f701d4a1bf606f85431dec2109aad598fe419034'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_verified_source_request_context_v22#1', '_strict_rehydrate_v22', ('validation',), 'd62801813a8be8b1a276c89bf83050dee944aa675639b9930e8bef006e174f70'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_verified_source_request_context_v22#1', '_validate_envelope_binding', ('validation',), '4bcfdd22a32cd7e2be316d719ed7b306484cf1f28e51ae3ea0629af3b7b3e246'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_verified_source_request_context_v22#1', 'build_source_record', ('serialization',), 'd076c49428a3068c22ede48f7796f09784bf96f55f6a0e38dfa4ccd0f8d493a5'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_verified_source_request_context_v22#1', 'canonical_json_bytes', ('serialization',), '807129ce9f1cf0e8f724bfdf4defbb6277834f96e439b3b473e9cddbbd716186'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_verified_source_request_context_v22#1', 'sha256_digest', ('serialization',), 'e1cbc5e1392efc45a4159dc8ce169a93fadc6a91f4047e7238c1de3314e5dabe'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_contested_grade_request_v22#1', 'ValueError', (), '5b812510d4441fc48e7b201234e9fd99412d6ced8fcd0ab881d2ce0db9485598'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_contested_grade_request_v22#1', 'ValueError', (), '949dc22027f640e4fb3080688c7523ec212309f6daab7270b3c992427c0b84a9'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_contested_grade_request_v22#1', 'ValueError', (), 'f126bd90280e4d9a2e2dd496577546c138d84dd9d5fb8b74f04d2874b147571e'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_contested_grade_request_v22#1', '_ContestedGradeDraftV22.model_json_schema', ('serialization',), 'a6348c5895edc701804d1ff57285e1c753c4ed2838c4b0392496056e634840f9'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_contested_grade_request_v22#1', '_grade_context', (), '48c8465ab92144b494852e359dc9ee4b69d3f8a0e5741d1fe0cb5d52773524fe'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_contested_grade_request_v22#1', '_new_request_v22', (), 'be3746d92ca20f1ec46b9fa3a1c497bbf7d6e9177cabe9b8066250b7f2a280e3'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_contested_grade_request_v22#1', '_strict_grade_coordinate_v22', ('validation',), 'f66abe3f16cd9ed9b4e229f44837c33197160d8faf02a9540bef2deeb982ec80'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_contested_grade_request_v22#1', '_strict_rehydrate_v22', ('validation',), 'd3b6f68764f2c44b574ecd51a15d8d022ccacd3258d657197edf30a5b3e3ef42'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_contested_grade_request_v22#1', 'checked.model_dump', ('serialization',), '8e63b20ce3a6ebc7731cef43c9ebce275794964fd47cddf069e9e8fc54d20638'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_contested_grade_request_v22#1', 'len', (), '703415f9e8011d8ca263817e88328b5b84eb9c74d3a8236848eabc61e65eb215'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_contested_grade_request_v22#1', 'sum', (), 'c5a365b2c9f338a86af078698517310151c29ea67e5fc50b0de63f931658e199'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_contested_grade_request_v22#1', 'verify_canonical_baseline_v22', ('validation',), 'e68a36c9fd08268298b2b3b3a84a11d18f81fc724f33831937609a09750ad114'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_ordinary_grade_request_v22#1', 'ValueError', (), '881132c5cb54336cc553c81d6435b550e3e2d090e67fa7e5606acb76456628fb'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_ordinary_grade_request_v22#1', 'ValueError', (), 'baef17bd48fb9ee6fe9e9ffb5129efa8809ec03bf25e8b0eef1f9046d4134b71'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_ordinary_grade_request_v22#1', '_OrdinaryGradeDraftV22.model_json_schema', ('serialization',), 'd6947dae76f26fa2701b324fdc9144bf2d93e2178bd9db1def0a74370e559356'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_ordinary_grade_request_v22#1', '_grade_context', (), 'f4dcfe2d4b7de300cff78d968da126159343b924139225807c4bd4062361116a'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_ordinary_grade_request_v22#1', '_new_request_v22', (), '4caecc1bbfbde2738b07bde4ad45bac9c29be8136b7f10ba1c64742a3261f1a7'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_ordinary_grade_request_v22#1', '_strict_grade_coordinate_v22', ('validation',), '7fe96b1a50e41fd2bd66f5351128fb98d26586fcf853641c2b25799259eb42c8'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_ordinary_grade_request_v22#1', '_strict_rehydrate_v22', ('validation',), '3313f57fb3ee6b23422fc5b182af95e7e106a5fa7f8256fc8ca2238069551e8f'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_ordinary_grade_request_v22#1', 'ordinary_grade_batches_v22', ('validation',), 'ee06bef3202994c4c626150c9823f75e73d2c5ca07dd7d825a1bb7b635bdc637'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_ordinary_grade_request_v22#1', 'requirement.model_dump', ('serialization',), 'a7b15fbd3029060823d612e41809d0f65bcb53c504b589c6e3c50c5c047073d1'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_ordinary_grade_request_v22#1', 'verify_canonical_baseline_v22', ('validation',), 'd5a4b645c070418f8fcba51b8c44ce1c763ce0934dbab6abec6222e060531770'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_audit_fragment_request_v22#1', 'ValueError', (), '34a2af888f82e6084507b95e768329443cadc973d4060b4d60fcee3639fcc291'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_audit_fragment_request_v22#1', 'ValueError', (), '645321a2a473c29677bf04b68eaa453ccb6c8a3410ab65e2f090ab41e77c76b7'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_audit_fragment_request_v22#1', '_audit_history', ('validation',), '322f7225479754d5d08c0d07eba8a26dc0a2365f75b3490e58f7f0639ca27f03'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_audit_fragment_request_v22#1', '_source_audit_request_from_context_v22', (), '45ae2f6b14fdba56bde2e7ef6801775f654f70b4bbd834c6c3d66657dca5b454'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_audit_fragment_request_v22#1', '_strict_fragment_ordinal_v22', ('validation',), '209cbbe3ee52861b8963e584983c3c8a72fd8ad0af75ea41dbf0de930def1402'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_audit_fragment_request_v22#1', '_verified_source_request_context_v22', ('validation',), '9b6927aaa945828c599d3ceeb913588cc80d99498039d6a493f400cb69e34759'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_audit_fragment_request_v22#1', '_verify_source_review_aggregate_with_context_v22', ('validation',), '8843fdd6a626deb24e2616017a2c7e9e94e962d15b1c63bc4a89e600055033c0'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_audit_fragment_request_v22#1', 'len', (), 'ecba0e594bdd6ebf4c4b965049a871ded8491ef6724d74bb25ba04d2d1b3481e'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_audit_fragment_request_v22#1::<ListComp>#1', 'concern.model_dump', ('serialization',), 'b3bc11c44da1bea3e2241f5f82be80b85918572e6fcd94654554143d46a61df6'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_referee_fragment_request_v22#1', 'ValueError', (), '0ef1580ac8907d1235dda89152332d206c69fcdf44eadef0f911be1ef8420db9'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_referee_fragment_request_v22#1', 'ValueError', (), 'd3a07931904badf5ae666cc27754564c40c8f20b3794aa6a639a55c35bbcf44f'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_referee_fragment_request_v22#1', 'ValueError', (), 'e825d37078964fd71463a21f2b6c016f3610773ff2a3fee10fd5c57c91e9825b'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_referee_fragment_request_v22#1', '_RefereeDraftV22.model_json_schema', ('serialization',), '1c360a81b2cf6a1ca98faeca5686c33f6219ace011597fb07b41486f1de78449'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_referee_fragment_request_v22#1', '_new_request_v22', (), '8d2d1f3d9828f6eea446b59c3dbef71ffdd8c45d2cabb2254e00d116eb4f9942'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_referee_fragment_request_v22#1', '_strict_rehydrate_v22', ('validation',), '6cb5635c6232df27c3e53953cd8e6ab0b9bce3811b4cadc6bc93f8fa025069db'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_referee_fragment_request_v22#1', '_strict_rehydrate_v22', ('validation',), '9f88d357dd5321edeb1add5c21ccc27b371f18841e808919ea61f18817782fc6'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_referee_fragment_request_v22#1', 'any', (), 'a68f8c872509477f7742780a65c67513b0a282a39a165b38d39501baab54d695'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_referee_fragment_request_v22#1', 'canonical_referee_disputes_v22', ('validation',), '9062fcb6c74ca494e28a6ee649b96f50631de2887eeb3add78f37dd270a2c867'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_referee_fragment_request_v22#1', 'checked.model_dump', ('serialization',), '28bbd82397d465953fa98216c82b42bcacd2a84f27744a0a5924c9b97362050d'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_referee_fragment_request_v22#1', 'len', (), '093a0dc4f0b901d36898c27b1088e376d912a9a4c0511c4982954fc236986d2a'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_referee_fragment_request_v22#1', 'sum', (), '81f9c13705dd234f2951d926db101e1441180f5a397e6f7b7eb7ed8b984d7c68'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_referee_fragment_request_v22#1', 'tuple', (), '0a810be1cb400e7cce3553d13788e296305bb719b166bce89eb8c4d487ae7534'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_referee_fragment_request_v22#1', 'tuple', (), 'eb10242b52b9f3d8d525fde6bdff58df382ff01922877525662dccb9cccef161'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_referee_fragment_request_v22#1::<GeneratorExp>#1', '_strict_rehydrate_v22', ('validation',), '69ed522de70f02b5dd1666126188eca00452bcf5ca3dca80f436b6e5e4e053dc'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_referee_fragment_request_v22#1::<ListComp>#2', 'len', (), 'b2b74215ed85425457744635548411542877dc9bb518bcd3f91719b3e2b39cd2'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_referee_fragment_request_v22#1::<ListComp>#2', 'range', (), '2a4c7cdd8bf15a4bbc0035ae0d0b1e504a24d6b50f335e2d3e9aa1027d11807c'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_review_fragment_request_v22#1', 'ValueError', (), 'dd85a6090235004ec47e063189c5173f6ac1d2684e29cead068d1bb84d2bae1f'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_review_fragment_request_v22#1', '_review_history', ('validation',), '7a318ebc6ceed674c64a62963ed6163fcc2b290cd6eb44fd3696e5d62ea34c10'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_review_fragment_request_v22#1', '_source_review_request_from_context_v22', (), 'ae50af3d0d58bbe869307493800a4f6c1ab58b836e23e61fd586aed569dfabb3'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_review_fragment_request_v22#1', '_strict_fragment_ordinal_v22', ('validation',), '996734d224003b12c12dfc1c983e8f82eface2aa2a4405d94905a8a44bf90593'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_review_fragment_request_v22#1', '_verified_source_request_context_v22', ('validation',), 'f198023eccea9db3331103dfe3fcc587381e3a095b0d63266fac57325511c82e'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_review_fragment_request_v22#1', 'len', (), '59ffa7e4228c19c881dc1151281ac09e827e74220a3e18204946cc73d4d01b7f'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_review_fragment_request_v22#1::<ListComp>#1', 'proposal.model_dump', ('serialization',), '8d65d1d0b57900c854123b3397d9f3d0e5b913eacd84f8e7fbb365296cd402c8'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::compiler_contract_fingerprint_v22#1', 'canonical_json_bytes', ('serialization',), '2c8202e04fee0d2ab6f4135ca1738d678499a57b0faa77a15e664bb9d052a384'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::compiler_contract_fingerprint_v22#1', 'sha256_digest', ('serialization',), '0f4ecb9815f43af9b9b507688ff010c41abd72a03e4d97c6bda28bf20286d7f3'): 1,  # noqa: E501
    }
)
# fmt: on
# fmt: off
_EXPECTED_TASK3_ORIGINAL_CALLABLE_IMPORTS: Counter[_Task3Import] = Counter(
    {
        ('attorney_v22_compiler.py', '<module>#1', '<module>#1', 'from', 0, 'regulatory_harvest.storage', 'canonical_json_bytes', 'canonical_json_bytes', ('serialization',), '3162f26688ce863a5e7189b0d6460fc65132f8178f31b204149e0b0c6ef69bf1'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1', '<module>#1', 'from', 0, 'typing', 'Literal', 'Literal', (), '2180bc41993bebcd71e1b441a65740ee3967c7a89d7118134b7eb023a856fc0b'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_models', 'CaseEnvelope', 'CaseEnvelope', (), '1d1a41447bad435e99d460c84e236a3ae5ff4b2b04b8dc16a5c9cc6b32cb506e'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v21_compiler', 'aggregate_referee_decisions', '_aggregate_v21', ('serialization',), '940314183c8105d090a0325a31acae9fbebd5944ebff801e50c80377d5b64775'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v21_compiler', 'build_referee_disputes', '_disputes_v21', ('serialization',), 'e7a605e2a7afc2d3ac8775a4149b6dd7a1d74ee5cf85d02531a22949befe79ff'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v21_compiler', 'compile_baseline_v21', '_baseline_v21', ('serialization',), '0cb2501394215515c20e01ace86c1dc0ac26ca4f63f1041154fadabbfed6470c'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v21_compiler', 'validate_referee_fragment', '_fragment_v21', ('serialization',), '5b9a51b1bffba45de7d521a1f8fd14abe21ad7677e3ad26ad932ac79411c4afa'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v21_models', 'RefereeDisputeV21', 'RefereeDisputeV21', (), 'c5cca4b3106e0dba81d66653218a3e32b1840aa0ec7a8864c5ad2bd486d07e73'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v21_models', 'SourceAuditV21', 'SourceAuditV21', (), '605b89c9862df6fd6e9c8d63739d27a418e4a3d76c46004d3ffd0c38e3d7b538'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v21_models', 'SourceReviewV21', 'SourceReviewV21', (), '68413771844813f67e9647e35ba5546dd305be37e890e6a5f5ae6c1da9808668'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v21_rubric', 'RUBRIC_V21', 'RUBRIC_V21', (), '1aca07f6def8ea61eb4d368e1ae1abf525b7aa68aa91a9f1f930967adc5ae2a1'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v21_rubric', 'RubricValidationError', 'RubricValidationError', (), 'fd327fee018c761885823a40432d0355881847d7768d12398a23fd7b2dd00ed0'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v22_models', 'AcceptedRefereeFragmentV22', 'AcceptedRefereeFragmentV22', (), 'cbc0ba69f216a0e270eab9581a95b0a1fa48ac725a2c7c09a77144cf3a6a6e5e'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v22_models', 'AcceptedSourceAuditFragmentV22', 'AcceptedSourceAuditFragmentV22', (), '8f2c4f13e99c8c59108e66d7b94d35ebcefeddb25ada0475a25592560a701e80'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v22_models', 'AcceptedSourceReviewFragmentV22', 'AcceptedSourceReviewFragmentV22', (), 'ae5e3028b79e94ac01dbc8c12715920ff4987ad47f3c27b116886f89e93a891f'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v22_models', 'AuditConcernV22', 'AuditConcernV22', (), '29de2a4ecb18c78bd084af137f98db8f6d98868ffd7924edd74429d336cf5077'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v22_models', 'CanonicalBaselineV22', 'CanonicalBaselineV22', (), 'f0208a1ebae692c0d55db3a289f2d436436082ba9020fc38d6914fa1505d7141'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v22_models', 'ContestedGradeFragmentV22', 'ContestedGradeFragmentV22', (), 'f2ce755231c2606c5479bfd9d725413fc50f4c54b1f1e007fe7bc214779be87d'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v22_models', 'GraderAggregateV22', 'GraderAggregateV22', (), '28be79eee726273decc83840156d8e2e2f7ba982f29864e47c97478b859baf26'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v22_models', 'IndexedAuditConcernV22', 'IndexedAuditConcernV22', (), '0e4a249a7195a4b65db1a4b2654c6ea2f92fd08ca9d3f47b2c0b46849f54664d'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v22_models', 'IndexedProposalV22', 'IndexedProposalV22', (), '4392c0e5e913e3837d3f79a724014762dc8faecc040f301b63e869b2128ddc08'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v22_models', 'OrdinaryGradeBatchV22', 'OrdinaryGradeBatchV22', (), '436bb895567762d28d456a9eeada5c183fbef1ec04139cb99b1fba8b5dbbce1f'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v22_models', 'OrdinaryGradeFragmentV22', 'OrdinaryGradeFragmentV22', (), 'd921728d311f638511dd41746175d7260d7fa098d5cd139ac80d938f10c91eec'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v22_models', 'ReconciledGradeV22', 'ReconciledGradeV22', (), '331f2229db32c59a387a82d2ffc9f85af638b021ead6c64b897743c2c880d6ad'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v22_models', 'RefereeAggregateV22', 'RefereeAggregateV22', (), '41b80f48a7514c96349af0ab8b1d82bd689e97e49c00cbbeb8f551256770fcee'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v22_models', 'RefereeDecisionV22', 'RefereeDecisionV22', (), 'e76565c073272e79a11761ac116125168558c60d3730d41ba389e28cb8ce9d70'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v22_models', 'RefereeDisputeV22', 'RefereeDisputeV22', (), 'd72f6adcd65752a45fb185fe42308127b46a0cfd6b92e1e1b994f3ab96396153'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v22_models', 'RefereeEvidenceV22', 'RefereeEvidenceV22', (), '07caf4662b5496e925051165826d8d6fb2d5977c707eeb6030f3450c243c6dcf'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v22_models', 'RubricV22', 'RubricV22', (), 'b89d76ff2919a48f3122cd96ebe514097399264b05fd0dcf0f8a497dd3327550'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v22_models', 'SensitivityRecordV22', 'SensitivityRecordV22', (), '949cc53debea5a598c4df06a46725dc84bf4b53cf727c63ed52415eedecc591c'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v22_models', 'SourceAuditAggregateV22', 'SourceAuditAggregateV22', (), '8a02352802402494ae5faf1d20039df79735bc14ab9f9c5c5207d16d9a6cb89f'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v22_models', 'SourceAuditFragmentV22', 'SourceAuditFragmentV22', (), 'f14be21180c168ff0a9249a6148710b392e76083eb6fcc642cdffd5764bdb3d0'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v22_models', 'SourceReviewAggregateV22', 'SourceReviewAggregateV22', (), '92f3d4671e4ca72b17a781430152b94e9ead876b3564a3d98c3f96a4fa37a5df'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v22_models', '_strict_grade_coordinate_v22', '_strict_grade_coordinate_v22', ('validation',), '43aeb54bd2f6a30ccfbd12a49a2c26609a507e61fbecf6ba24ce36df2e7af3c8'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v22_models', '_strict_rehydrate_v22', '_strict_rehydrate_v22', ('validation',), 'b1abf2cce6bc710d427320215bf16b4d892fe6561b7e852f17f448f4d22e1324'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v22_models', '_wire_snapshot', '_wire_snapshot', ('validation',), 'eddc44c61009234408c4fec0215d312bba313ceae3ab4d7da0bc7534b2941367'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v22_requests', '_VerifiedSourceRequestContextV22', '_VerifiedSourceRequestContextV22', (), '9d7957b8a9b0de6d673361b218de6367224e1ecb879a6189de2848d9a31f5aae'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v22_requests', '_audit_history', '_audit_history', ('validation',), '32e88602d29fe3d68281f94de8db7aad4838e31b41859a5e2fda651f387e5207'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v22_requests', '_review_history', '_review_history', ('validation',), '79d8e62cca7e7628e4117cd7adb218455827f8f31b25e5dfb9ef390edc40db20'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v22_requests', '_verified_source_request_context_v22', '_verified_source_request_context_v22', ('validation',), '72a1db80faf8763f6dc253327af620b26cea6930a69d52c14b53e646d2aec903'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v2_compiler', 'CompilationError', 'CompilationError', (), '6304411bb5a060dc1e61e6f4ea3213f7d45939a8c0155a8895fd0bd0c2496c79'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v2_compiler', 'index_review', 'index_review', ('serialization', 'validation'), '38b19e7f8d6fb9888ff8963c88f28f0092827d72e76993280f28123df3b9dcb3'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v2_compiler', 'resolve_exact_passage', 'resolve_exact_passage', ('validation',), 'eb7d06f696e5a732e4174c3d8ab46e58cac07ee2110b04228529e51ce80441d4'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v2_models', 'AbsoluteDispositionV2', 'AbsoluteDispositionV2', (), '80e0f6a62396029a4c0b0cb9a76af566dee5aba2a78c735f4447ca169a23351a'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v2_models', 'ImportanceV2', 'ImportanceV2', (), '59462eeca67e2976dbb02b3db7ad12f448c10b454af469ea0321662733b26c76'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v2_models', 'MaterialDisputeV2', 'MaterialDisputeV2', (), '61ac2b12c3c06abe015021fde128d93bc780ec17d06e57b8054edb314b3feeb7'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v2_models', 'ResolvedPassageV2', 'ResolvedPassageV2', (), '524e647bdbe8a193878c1dfb6ff40ea6569f34c05997ad5e69b3d6989917a4b5'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v2_models', 'SemanticProposal', 'SemanticProposal', (), '3d7e99ec81129e0f15466a5ebb81ce245483817b58f5ef130e8bebfd60858c9f'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v2_models', 'SourceReviewV2', 'SourceReviewV2', (), '55b9f3406d192a021dad921610e667ccd9e74680f95aa8f388578aa37475aa64'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1', '<module>#1', 'import', 0, 'hashlib', 'hashlib', 'hashlib', (), '8b9ba56462004e9ea94469a83250332ec69554ed2b92b6eb818be077514c7f47'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '<module>#1', 'from', 0, 'dataclasses', 'dataclass', 'dataclass', (), '96b7a3ac5e65b6cb06b439014aa735d555b766e5170b02487e4f8b965712366a'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '<module>#1', 'from', 0, 'regulatory_harvest.storage', 'canonical_json_bytes', 'canonical_json_bytes', ('serialization',), '3a91b0c0c9ddd9a53253129a38bbe52ab12aeb1504a155ef776dfd3681a17340'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '<module>#1', 'from', 0, 'regulatory_harvest.storage', 'sha256_digest', 'sha256_digest', ('serialization',), '78f231ef74560b46de6c0444dfc28e4b7a7e3c76443e5749bca1bda8f3e843d0'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '<module>#1', 'from', 0, 'typing', 'Literal', 'Literal', (), '8a01de1ab69183fb7f47b14b36287f63c87636614446b1df747b79b7eea70462'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '<module>#1', 'from', 0, 'typing', 'cast', 'cast', (), 'f91879711da5ae354c5d61fce2b511afa344af61ea7c849b5ceab823ca9ea835'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_admission', '_validate_envelope_binding', '_validate_envelope_binding', ('validation',), 'ef525589041ca7feadee42e891113f08e6334886910debcbfe2138cb797bc573'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_admission', 'build_source_record', 'build_source_record', ('serialization',), '89aae54a219858a388035f193d45eb25e40b511c57d03f80a28270d3fe0a0a03'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_models', 'CaseEnvelope', 'CaseEnvelope', (), 'daaade67af096500ba65ed1a9470768ec2c8c8378ec9755bf2c865a6b74b43fb'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v22_drafts', '_ContestedGradeDraftV22', '_ContestedGradeDraftV22', (), 'c22a742b546cb0f230ed73e53e5bd8c6084cd56a24c8d30877af8d3d968dfd10'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v22_drafts', '_ENUM_ALIASES', '_ENUM_ALIASES', (), '7ff155b1c5b543cb8ee4fd9a787e6df7c82428fd476d9f038b058ce0519ca332'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v22_drafts', '_OrdinaryGradeDraftV22', '_OrdinaryGradeDraftV22', (), '82279ccabe18cab587b9e0e2f586799e0587a21554e3a6e9fe1fe08c621e6768'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v22_drafts', '_RefereeDraftV22', '_RefereeDraftV22', (), 'a5d9ad58038665689376de6e9735d723722da30bfaaeff103121ab23893da8db'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v22_drafts', '_SourceAuditDraftV22', '_SourceAuditDraftV22', (), '35ec9fb430124c3a509c12f37d28f79c668f6b307e9b6154ec81c19d48f30638'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v22_drafts', '_SourceReviewDraftV22', '_SourceReviewDraftV22', (), '9571ce842c13d32be38df64c6a99504e3c3f0ef9536677edc2ae85dc482a4c91'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v22_models', 'AcceptedSourceAuditFragmentV22', 'AcceptedSourceAuditFragmentV22', (), 'd5c9494cc83110a288b184848afec9c996d71e6e398f602811e45b52d35b6cfb'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v22_models', 'AcceptedSourceReviewFragmentV22', 'AcceptedSourceReviewFragmentV22', (), '5020f96ca607de9de3d9345b626539762d1a7c3ebbc4393701cddaf8ffc0e447'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v22_models', 'CanonicalBaselineV22', 'CanonicalBaselineV22', (), '98d6b0c58dd9de4b99f0977a9e8a53fa6cc007ffa311cdeaa03c7a7ae64367df'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v22_models', 'ContestedGradeFragmentV22', 'ContestedGradeFragmentV22', (), 'e022bfab5d14030e7a9d07b9f86342e7b370b40148e6ea7a4fd20eb72edd9430'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v22_models', 'ContestedRequirementV22', 'ContestedRequirementV22', (), '0ddeed9af6146a8a7b810c86968f671073a9cb8940c564244696c7f9ff900922'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v22_models', 'EvaluatorOperationV22', 'EvaluatorOperationV22', (), '2c72f8a9376afd16e2e46960bcf3ae84acca57c6e3ff1fb35cfc2369473135f5'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v22_models', 'EvaluatorRequestV22', 'EvaluatorRequestV22', (), '0d82d9fdbdc67936cceff9dec876f4dfac8e59dc08029d91fa01513cf61a6553'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v22_models', 'OrdinaryGradeBatchV22', 'OrdinaryGradeBatchV22', (), '1f169530877f25158441ad40c894c85f3aeb1d7c954faa9982768690c24f721d'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v22_models', 'OrdinaryGradeFragmentV22', 'OrdinaryGradeFragmentV22', (), 'aac4e8cb68125883b1a43a425ef725ea97ee544214c200892c2fd1f623b4d3e9'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v22_models', 'RefereeDecisionV22', 'RefereeDecisionV22', (), 'f5109c9339d11b3beec5de18c48547ee6165ff63880ff5c99867c51918c2da62'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v22_models', 'RefereeDisputeV22', 'RefereeDisputeV22', (), '6989334942a8b903d389000fa12ebb409cf91f23ad8190933cc1ca37306fccff'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v22_models', 'RubricV22', 'RubricV22', (), 'cdbed7a13e30fb26c00a766e1c13d7288566f0b8f7d3bb87c6c172b8c23120e1'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v22_models', 'SourceAuditFragmentV22', 'SourceAuditFragmentV22', (), 'cbc735ca966b12bba642fe4de809bca4a992e725a2db089e00761eed3dd3a0f8'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v22_models', 'SourceReviewAggregateV22', 'SourceReviewAggregateV22', (), '6885c3e843ba46f60d7db593f01c84a6d88313c5805b853d900bd01a63361fc2'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v22_models', 'SourceReviewFragmentV22', 'SourceReviewFragmentV22', (), 'd2db91a3cd55ab67f6c0c2073919d12bd8d7b9cae83e6dd26febc70a8098fa3a'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v22_models', '_strict_fragment_ordinal_v22', '_strict_fragment_ordinal_v22', ('validation',), '5caa24b8bca846f33718271f26ca234293364ba6248a93c04805625551516b82'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v22_models', '_strict_grade_coordinate_v22', '_strict_grade_coordinate_v22', ('validation',), '19e619db3035977db527f5b75385d8155cdfafdd1b7236be3bf7b00a9be56b68'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v22_models', '_strict_rehydrate_v22', '_strict_rehydrate_v22', ('validation',), '9eb2558f774c300ca6941e73bd99d3fad676fa39ce179a065b41cdad246ccb1e'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '<module>#1', 'from', 1, 'attorney_v22_models', '_strict_source_context_v22', '_strict_source_context_v22', ('validation',), '46731992fcf39fd417a13be5961c8a843cdab7dba4c4e0ea3f6c5e569bf8d24e'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '<module>#1', 'import', 0, 'hashlib', 'hashlib', 'hashlib', (), '3014986f794aec56edbf7380b110927a0083643a540f4723e0fa6d122106d28b'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '<module>#1', 'import', 0, 'json', 'json', 'json', (), '8425e52cf9b23c6be2fdfa3543812ab37457dee33bfdea71818d2ac5a81abf5e'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_grade_context#1', '<module>#1::_grade_context#1', 'from', 1, 'attorney_v22_compiler', '_strict_rubric', '_strict_rubric', ('validation',), '5046996f27afe9d316f213a8dd187ae3fcb6325611245c192790f5d63d0069e9'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_contested_grade_request_v22#1', '<module>#1::build_contested_grade_request_v22#1', 'from', 1, 'attorney_v22_compiler', 'RUBRIC_V22', 'RUBRIC_V22', (), '357bc1fbf86449ce2445c29016a28c7cfe29825a7a570b2d1682b87b966e5363'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_contested_grade_request_v22#1', '<module>#1::build_contested_grade_request_v22#1', 'from', 1, 'attorney_v22_compiler', 'verify_canonical_baseline_v22', 'verify_canonical_baseline_v22', ('validation',), '6ffcc2bbb5693fadf1b4d56b0ff8cfc2b0117ee5cf366663b475971be11ad3c2'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_ordinary_grade_request_v22#1', '<module>#1::build_ordinary_grade_request_v22#1', 'from', 1, 'attorney_v22_compiler', 'RUBRIC_V22', 'RUBRIC_V22', (), '8d70bfd63137dd956e16a929cdadcb6d1d0224a7c1ccce0ae64064a918a36f55'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_ordinary_grade_request_v22#1', '<module>#1::build_ordinary_grade_request_v22#1', 'from', 1, 'attorney_v22_compiler', 'ordinary_grade_batches_v22', 'ordinary_grade_batches_v22', ('validation',), '8ee3cc3dd2f9edbb611fc07f4ac332cb7c2674180339476827593232bdfab21a'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_ordinary_grade_request_v22#1', '<module>#1::build_ordinary_grade_request_v22#1', 'from', 1, 'attorney_v22_compiler', 'verify_canonical_baseline_v22', 'verify_canonical_baseline_v22', ('validation',), 'beb8977a134c79a0cf8eb25996fcb28c686919043227a05a53738d459566dcdd'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_audit_fragment_request_v22#1', '<module>#1::build_source_audit_fragment_request_v22#1', 'from', 1, 'attorney_v22_compiler', '_verify_source_review_aggregate_with_context_v22', '_verify_source_review_aggregate_with_context_v22', ('validation',), 'dc8a9a57d37a06ead20a365dd319164af7be1ee67c90dce338c2c5eaf457ef39'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_referee_fragment_request_v22#1', '<module>#1::build_source_referee_fragment_request_v22#1', 'from', 1, 'attorney_v22_compiler', 'canonical_referee_disputes_v22', 'canonical_referee_disputes_v22', ('validation',), '76ad0ef727075001b9fb463656a2b6f3ffe6ee74b687c4d42cfd9762217620ee'): 1,  # noqa: E501
    }
)
# fmt: on
# fmt: off
_EXPECTED_TASK3_DEFINITIONS: Counter[_Task3Definition] = Counter(
    {
        ('attorney_v22_compiler.py', '<module>#1::_audit_fragments#1', 'FunctionDef', 'e5f1d099f18147418487a83dabc766ed40298b6c2919b2e9f097474ec1f677db'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_canonical_baseline_fingerprint_from_validated_v22#1', 'FunctionDef', '5b0f0ae15ad396d9fa9719ec565f83062d218c645122b54420ab73df4c4e042c'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_canonical_dispute_passages_v22#1', 'FunctionDef', '00ef01d69e0ae9b1886f9c00abd5ddd9a53f2e071eb7854352e36dfc9e03c114'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_hash#1', 'FunctionDef', '4b6fcca82acc80e67a4a48044aa2ee9056db2afc1df3e98b87d522a563bd6c01'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_ordinary_observations_v22#1', 'FunctionDef', 'a7b039f7d132adcc118f11c290b7df889835546a90c5c5536412f2ccd6bc082b'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_referee_dispute_fingerprint_from_validated_v22#1', 'FunctionDef', 'f45f2f6cda88727156a10a6622e75d7b7428140a6cea892ebfce09e5a1524417'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_referee_disputes_from_verified_sources_v22#1', 'FunctionDef', '893d52005cc41c985cacba3f4bb208b589bbe4ad448e707c6b377736df61ea93'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_review_fragments#1', 'FunctionDef', 'fca8ce283eab4f978d704a64dca96d4921f745ae7fb861c2cec2aa9e83c18df8'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_same_observations_v22#1', 'FunctionDef', '1198331158ca1d55cbb44c9bcb16f0d162ca9231a946c2734ea2d4ab3a6c6b22'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_same_observations_v22#1::view#1', 'FunctionDef', '46cdbb6ece1ca5d0cf9f754f268e0c10f71bedca02fb7962244322769c3f29c3'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_score_v22#1', 'FunctionDef', 'a26bebe44a85e45b5587c00d5d490582ef266bbcd8ddfab7acdf9407d402c48a'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_semantic_identity#1', 'FunctionDef', 'd95544c0c85396205078552479f9c42f0f5bc9f555baf529fe53b94840d6d6c2'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_SourceFragmentSemanticResponseErrorV22#1', 'ClassDef', 'bd1e064ac1f92b7d4af4ee10b85af6dd7dc85839d6ca03da8888d605a558c314'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_validate_source_fragment_semantics_v22#1', 'FunctionDef', 'b033545c021132b56628d7721fa6f1f74c09eb371263d0bd8216b07eac185952'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_strict_rubric#1', 'FunctionDef', '7d92124be2006f1758b63b8643a558da1fad25eedc317fba1c4eaccfd17765f2'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_v21_inputs#1', 'FunctionDef', '6a62ca05e75e2bfce22c305987ad65e799c6a0769c416006f30cd2acecdf50a0'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_validated_canonical_baseline_v22#1', 'FunctionDef', '7a174e9767e046223db2b589876f2e0d03165ce5024465af87908fdf3a5ce1af'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_validated_referee_dispute_v22#1', 'FunctionDef', '87ad51c3dc8e25fa05cdf753b843989cfd680bdd7437df910dc20389096754b5'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_verified_grader_aggregate#1', 'FunctionDef', '14a275f4d73120122cc426955abe8ebc37c97630f5bfb56ed8f1a89190d4cb60'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_verified_source_aggregates_v22#1', 'FunctionDef', 'a12e7ee6589a7de78c0e051f38e5738965c4e01ecc31cc7d16cf35d439535ae5'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_verify_source_audit_aggregate_with_context_v22#1', 'FunctionDef', '595b141399b73d6e2692fc4876682b6b38f12d234581e6e21dd1f277ab8f4349'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_verify_source_review_aggregate_with_context_v22#1', 'FunctionDef', 'f8430cb45cf8609727fb67b81b4b41a8033e2f33c9008b0a7bf16ec8e0f709d5'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_grader_lane_v22#1', 'FunctionDef', '98c27518e820c99fc37a70d231f6432d1b59118a2515f512eec6bce594eb1f02'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_referee_decisions_v22#1', 'FunctionDef', '6db4567597efe9604d15ec8f4dc100ea1ea4de1404ad7f6622a2da2e4e627172'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_source_audit_fragments_v22#1', 'FunctionDef', '74058d5bdc28d246f41de45048746b48da1a6b994fb56d6d7127a9d191330a41'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::aggregate_source_review_fragments_v22#1', 'FunctionDef', 'e5b87d9cfad0b97140ead21a8e765cdce78c2e72c45de7e5c1a479b4774cbe04'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::build_referee_disputes_v22#1', 'FunctionDef', '87d269d026607c335c1889b775d0dd45036d64ee4fedf405465009a4cf49d883'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::canonical_referee_disputes_v22#1', 'FunctionDef', '90f399afe29f12febba948ae3ac0e03540e87b9d0bfc8b6b4f7e363d74b5f923'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::compile_baseline_v22#1', 'FunctionDef', '573e72c161d84e2595042bd3cdcdc2c90d5614e34ae463829b3168ba02ca3c5f'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::evaluate_outcome_sensitivity_v22#1', 'FunctionDef', '5f7ad14aa11afbae6c11b1f5a9ff0873e1ad1c7179e063643bbfa8ea3b1abe45'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::ordinary_grade_batches_v22#1', 'FunctionDef', 'cf09d956de18974492485632c53fb3a6e208a0f268255f00f165e90d45f54246'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::reconcile_grader_lanes_v22#1', 'FunctionDef', 'adff33a23ad9c039a6a1025a75fbe2745e19863a312ed218f66f06f45adaeb92'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::referee_dispute_fingerprint_v22#1', 'FunctionDef', '0e9554dff934846b8270466c2889d1565160b41490a7fbf58daa21ff8920a747'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::validate_grade_fragment_v22#1', 'FunctionDef', 'ccaad64028709671383d18c53acdb5152620ba3f2168614818ac4f1c59b6556d'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::validate_referee_fragment_v22#1', 'FunctionDef', '223557feaebbd5f58daa959e94eb4b3a04797502995356695e7bb913445cd0d6'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::verify_canonical_baseline_v22#1', 'FunctionDef', '6328fa58c00cfbb3a58b37806b085d9b8c5596d52e5e817646c39dcd6e91391d'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::verify_source_audit_aggregate_v22#1', 'FunctionDef', '3c25ba0bf134c2436ba7c7841d3fd4ae1380f5606d789e2b2774ec67707bfa38'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::verify_source_review_aggregate_v22#1', 'FunctionDef', '017a2acc5b4803a5dd83df6655bc0bec6c2783eaa3129ad3d4cf4b34bf043494'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_VerifiedSourceRequestContextV22#1', 'ClassDef', '5836cffa1aacda636fc6e258704b758c15db948810e912591b34a32620a8bb32'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_audit_history#1', 'FunctionDef', '7b4aabde3952fd76ee26b451818f1dbf89f435806f2c9ef532121caa611f85df'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_context_source_metadata_v22#1', 'FunctionDef', '5f41c63fd5ff7b0250afc430ff14888eabf0158502b039f6097f79f63f613746'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_context_source_record_v22#1', 'FunctionDef', '557be448ffaa7e090e2d68d8606195cd376b70eaa307b97ee269bef8865146b6'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_fingerprint#1', 'FunctionDef', '6d72d11be6e2e85c4dbaf3575cd38f5dc4830a2883b61c6bc99e46f06531deab'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_frozen_source_record_v22#1', 'FunctionDef', '32867b86bba79145e789799ba0049072541083a334eb1b56d0cac3149b49089d'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_grade_context#1', 'FunctionDef', '81c817a60f08bbbb6dbf06130df64340ef1453cbc7573e81952036496e2a46d7'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_new_request_v22#1', 'FunctionDef', 'cb53c97ba49d33e94001f69213d8d81e379bc912abaf700bae3a8ec4afa00abe'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_review_history#1', 'FunctionDef', 'feb181868520e7572a1e6ecb57934459de54df1d5834065e90a2947700b601f8'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_schema_hash#1', 'FunctionDef', '1bd94a3c517759e9d5e65f9316e6231f1e517aef1f0343881e502e3dc5358610'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_snapshot#1', 'FunctionDef', 'b4d7d555900113325c192bf683e8bebc719f79dda6446290a2b238abb01172a7'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_audit_request_from_context_v22#1', 'FunctionDef', '6f1d2c030098a3366d2407d8e4d0bec7f593b02b00095916a0dbe0027872219b'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_metadata#1', 'FunctionDef', '138b6e618bcee7c13be90c6cd45a95a9790f774069ece5e1db52cc5c95a96dd8'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_review_request_from_context_v22#1', 'FunctionDef', 'c7011d385a9bc68025b64323ef8c25e3bb276c5ab5a7b19949191c36f3e19d05'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_verified_source_request_context_v22#1', 'FunctionDef', '01ebe65c6fd980e46c235671c4402b3e0165301b3521ab0fd3ad241edb3c2ccc'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_contested_grade_request_v22#1', 'FunctionDef', '6c874add72b044fa93ada2d090d3542f6620d222f3206c24f4971ccda26e45be'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_ordinary_grade_request_v22#1', 'FunctionDef', '518f5c42b1d78395262be98e025ac0742f2e36bd7c29ed6366916a802feded70'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_audit_fragment_request_v22#1', 'FunctionDef', '5a1cb4062dcf4213e3573cf59e1e8e78e5515b2c796e71c4ea338ae557a63564'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_referee_fragment_request_v22#1', 'FunctionDef', '1c831bfd995694e2d7ffc6ad549b57356ee5a7eb89de460f93009e6120f97c87'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_review_fragment_request_v22#1', 'FunctionDef', 'dddcc447757eaf612de3f44b559417f3e5e7be95bbf8364875f825ec49fe7d4d'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::compiler_contract_fingerprint_v22#1', 'FunctionDef', 'af2483036474ae71ff5e38923af243a77edd54f376b3dd6dd0e58f6d74e17220'): 1,  # noqa: E501
    }
)
# fmt: on


_EXPECTED_TASK3_SIMPLE_SUBSCRIPTS: Counter[_Task3SimpleSubscript] = Counter(
    {
        (
            "attorney_v22_requests.py",
            "<module>#1::_new_request_v22#1",
            "raw['request_fingerprint']",
            "80c86644b054bd1e53601a84a4a72d08f19764580bd20007ac1135804d982b3b",
        ): 1,
        (
            "attorney_v22_compiler.py",
            "<module>#1::_validate_source_fragment_semantics_v22#1",
            "seen[identity]",
            "ba2c007cfac95b5fa50f061f0d07de57250ae8a886baa2f969a6d5a20342a7ab",
        ): 1,
        (
            "attorney_v22_compiler.py",
            "<module>#1::validate_referee_fragment_v22#1",
            "legacy_raw['dispute_fingerprint']",
            "48dc852b025e2ebdc12063841fe4b8091ebfa0a992aec5060786932aa9c264ef",
        ): 1,
        (
            "attorney_v22_compiler.py",
            "<module>#1::validate_referee_fragment_v22#1",
            "legacy_decision['schema_version']",
            "0ca3dcc0bcfb06380da614c154e89f7f7c7f36eba9d403d4cfac891ab5cbaad1",
        ): 1,
        (
            "attorney_v22_compiler.py",
            "<module>#1::compile_baseline_v22#1",
            "raw['schema_version']",
            "1f0c0a82880ee59817f3585ca7ca5b5b7a5cabdf53cf592bb16f4cb403eb4c66",
        ): 1,
        (
            "attorney_v22_compiler.py",
            "<module>#1::compile_baseline_v22#1",
            "raw['contested_requirements']",
            "285e030754de51abc7a0f150c0cf2b41e4d68f753c7bf7eee6a2c587ec62c182",
        ): 1,
        (
            "attorney_v22_compiler.py",
            "<module>#1::compile_baseline_v22#1",
            "raw['baseline_fingerprint']",
            "38b1bd120992fb28903caa492553d5e0cf7283fd8f565d5420b7b6d7576e31c0",
        ): 1,
        (
            "attorney_v22_compiler.py",
            "<module>#1::reconcile_grader_lanes_v22#1",
            "raw['reconciliation_fingerprint']",
            "0252ddb7ca40eef6c9949c3d6ad1bda0d41fe26a5694d70a789a2e1948d5c8e1",
        ): 1,
        (
            "attorney_v22_compiler.py",
            "<module>#1::evaluate_outcome_sensitivity_v22#1",
            "raw['sensitivity_fingerprint']",
            "0bfed9d0669c59095ec318cd9507d4bac350b6f91eb2723db41f3b1992e35a42",
        ): 1,
    }
)


def _scan_current_task3_source_policy() -> _Task3SourcePolicy:
    """Read only the two governed repository sources for development review."""
    from pathlib import Path

    source_root = Path(__file__).parents[2] / "src" / "regulatory_harvest" / "evaluation"
    combined = _Task3SourcePolicy(
        calls=Counter(),
        imports=Counter(),
        definitions=Counter(),
        simple_subscripts=Counter(),
        prohibited=Counter(),
    )
    for filename in ("attorney_v22_requests.py", "attorney_v22_compiler.py"):
        result = _scan_task3_source_policy(
            (source_root / filename).read_text(encoding="utf-8"),
            filename,
        )
        combined.calls.update(result.calls)
        combined.imports.update(result.imports)
        combined.definitions.update(result.definitions)
        combined.simple_subscripts.update(result.simple_subscripts)
        combined.prohibited.update(result.prohibited)
    return combined


def _task3_reason_count(result: _Task3SourcePolicy, reason: str) -> int:
    return sum(
        count
        for (_file, _owner, _display, actual, _digest), count in result.prohibited.items()
        if actual == reason
    )


def _task3_reasons(result: _Task3SourcePolicy) -> Counter[str]:
    return Counter(
        {
            reason: sum(
                count
                for (_file, _owner, _display, actual, _digest), count in result.prohibited.items()
                if actual == reason
            )
            for reason in {row[3] for row in result.prohibited}
        }
    )


def _task3_displays_and_reasons(
    result: _Task3SourcePolicy,
) -> Counter[tuple[str, str]]:
    assert all(
        owner and len(digest) == 64 for _file, owner, _display, _reason, digest in result.prohibited
    )
    return Counter(
        {
            (display, reason): count
            for (_file, _owner, display, reason, _digest), count in result.prohibited.items()
        }
    )


def test_task3_development_policy_review_inventories_are_exact() -> None:
    observed = _scan_current_task3_source_policy()
    assert observed.calls == _EXPECTED_TASK3_ALL_CALLS
    assert observed.imports == _EXPECTED_TASK3_ORIGINAL_CALLABLE_IMPORTS
    assert observed.definitions == _EXPECTED_TASK3_DEFINITIONS
    assert observed.simple_subscripts == _EXPECTED_TASK3_SIMPLE_SUBSCRIPTS
    assert sum(observed.calls.values()) == 498
    assert sum(observed.imports.values()) == 93
    assert sum(observed.definitions.values()) == 59
    assert sum(observed.simple_subscripts.values()) == 9
    assert not observed.prohibited


def test_task3_development_policy_is_test_only_and_has_no_evaluation_state_surface(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import builtins

    from regulatory_harvest.evaluation import attorney_v22_compiler as compiler_module
    from regulatory_harvest.evaluation import attorney_v22_requests as requests_module

    def refuse_storage_access(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("the syntax scanner attempted filesystem access")

    monkeypatch.setattr(builtins, "open", refuse_storage_access)
    result = _scan_task3_source_policy("helper(value)\n", "/run/private/manifest.json")
    assert result.calls
    assert not result.prohibited
    assert not hasattr(compiler_module, "_scan_task3_source_policy")
    assert not hasattr(requests_module, "_scan_task3_source_policy")
    assert set(_Task3SourcePolicy.__dataclass_fields__) == {
        "calls",
        "imports",
        "definitions",
        "simple_subscripts",
        "prohibited",
    }


def test_task3_development_policy_visits_inner_calls_under_invalid_outer_calls() -> None:
    result = _scan_task3_source_policy("factory()(value)\n", "synthetic.py")
    assert _task3_displays_and_reasons(result) == Counter({("Call", "dynamic-call-target:Call"): 1})
    assert Counter(target for _file, _owner, target, _categories, _digest in result.calls) == (
        Counter({"factory": 1})
    )


def test_task3_development_syntax_policy_rejects_every_delete_statement() -> None:
    result = _scan_task3_source_policy(
        "del value\ndel holder.value\ndel mapping[key]\n",
        "synthetic.py",
    )
    assert _task3_displays_and_reasons(result) == Counter(
        {
            ("del value", "delete-statement"): 1,
            ("del holder.value", "delete-statement"): 1,
            ("del mapping[key]", "delete-statement"): 1,
        }
    )


@pytest.mark.parametrize(
    ("source", "display", "reason", "multiplicity"),
    (
        ("holder.value = item\n", "holder.value", "attribute-store", 1),
        ("for holder.value in items:\n    pass\n", "holder.value", "attribute-store", 1),
        (
            "async def f(items):\n    async for holder.value in items:\n        pass\n",
            "holder.value",
            "attribute-store",
            1,
        ),
        (
            "with context() as holder.value:\n    pass\n",
            "holder.value",
            "attribute-store",
            1,
        ),
        (
            "async def f(context):\n    async with context() as holder.value:\n        pass\n",
            "holder.value",
            "attribute-store",
            1,
        ),
        (
            "values = [item for holder.value in items]\n",
            "holder.value",
            "attribute-store",
            1,
        ),
        (
            "holder.value += item\n",
            "holder.value",
            "indirect-augmented-assignment",
            1,
        ),
        (
            "mapping[key] += item\n",
            "mapping[key]",
            "indirect-augmented-assignment",
            1,
        ),
        (
            "holder.value: object = item\n",
            "holder.value",
            "indirect-annotated-assignment",
            1,
        ),
        (
            "mapping[key]: object = item\n",
            "mapping[key]",
            "indirect-annotated-assignment",
            1,
        ),
        (
            "first, mapping[key] = items\n",
            "mapping[key]",
            "non-simple-subscript-store",
            1,
        ),
        (
            "mapping[key] = other[key] = item\n",
            "mapping[key]",
            "non-simple-subscript-store",
            1,
        ),
        (
            "for mapping[key] in items:\n    pass\n",
            "mapping[key]",
            "non-simple-subscript-store",
            1,
        ),
        (
            "values = [item for mapping[key] in items]\n",
            "mapping[key]",
            "non-simple-subscript-store",
            1,
        ),
        (
            "with context() as mapping[key]:\n    pass\n",
            "mapping[key]",
            "non-simple-subscript-store",
            1,
        ),
        (
            "mapping[first][second] = item\n",
            "mapping[first][second]",
            "non-simple-subscript-store",
            1,
        ),
        (
            "holder.mapping[key] = item\n",
            "holder.mapping[key]",
            "non-simple-subscript-store",
            1,
        ),
        (
            "factory()[key] = item\n",
            "factory()[key]",
            "non-simple-subscript-store",
            1,
        ),
        (
            "mapping[key()] = item\n",
            "mapping[key()]",
            "non-simple-subscript-store",
            1,
        ),
        (
            "mapping[first if enabled else second] = item\n",
            "mapping[first if enabled else second]",
            "non-simple-subscript-store",
            1,
        ),
    ),
)
def test_task3_development_syntax_policy_has_total_write_matrix(
    source: str, display: str, reason: str, multiplicity: int
) -> None:
    result = _scan_task3_source_policy(source, "synthetic.py")
    findings = _task3_displays_and_reasons(result)
    assert findings[(display, reason)] == multiplicity
    expected_total = 2 if source == "mapping[key] = other[key] = item\n" else multiplicity
    assert _task3_reasons(result) == Counter({reason: expected_total})
    if expected_total == 2:
        assert findings[("other[key]", reason)] == 1


@pytest.mark.parametrize(
    "source",
    (
        "mapping[key] = value\n",
        "loaded = holder.value\n",
        "import hashlib\nresult = hashlib.sha256(value)\n",
        "from ordinary import helper as local_helper\nlocal_helper(value)\n",
        "value.ordinary_method()\n",
        "type Alias[T] = tuple[T]\n"
        if hasattr(__import__("ast"), "TypeAlias")
        else "Alias = tuple\n",
    ),
)
def test_task3_development_syntax_policy_allows_audited_safe_controls(source: str) -> None:
    result = _scan_task3_source_policy(source, "synthetic.py")
    assert not result.prohibited
    if source == "mapping[key] = value\n":
        assert sum(result.simple_subscripts.values()) == 1


@pytest.mark.parametrize("name", sorted(_FORBIDDEN_REFLECTIVE_NAMES))
def test_task3_development_syntax_policy_rejects_every_reflective_name(name: str) -> None:
    direct = _scan_task3_source_policy(f"{name}\n", "synthetic.py")
    attribute = _scan_task3_source_policy(f"holder.{name}\n", "synthetic.py")
    assert _task3_reasons(direct) == Counter({"reflective-lexeme": 1})
    assert _task3_reasons(attribute) == Counter({"reflective-lexeme": 1})
    assert _task3_displays_and_reasons(direct) == Counter({(name, "reflective-lexeme"): 1})
    assert _task3_displays_and_reasons(attribute) == Counter({(name, "reflective-lexeme"): 1})


@pytest.mark.parametrize(
    ("source", "expected"),
    (
        ("from ordinary import *\n", Counter({"wildcard-import": 1})),
        ("import builtins\n", Counter({"reflective-import": 1})),
        ("import operator as ordinary\n", Counter({"reflective-import": 1})),
        ("import importlib.util\n", Counter({"reflective-import": 1})),
        (
            "from operator import attrgetter as pick\n",
            Counter({"reflective-import": 1}),
        ),
        (
            "from ordinary import methodcaller as pick\n",
            Counter({"reflective-import": 1}),
        ),
        (
            "from importlib import *\n",
            Counter({"wildcard-import": 1, "reflective-import": 1}),
        ),
    ),
)
def test_task3_development_syntax_policy_has_total_import_matrix(
    source: str, expected: Counter[str]
) -> None:
    result = _scan_task3_source_policy(source, "synthetic.py")
    assert _task3_reasons(result) == expected
    displays = _task3_displays_and_reasons(result)
    expected_displays = {
        "from ordinary import *\n": Counter({("*", "wildcard-import"): 1}),
        "import builtins\n": Counter({("builtins", "reflective-import"): 1}),
        "import operator as ordinary\n": Counter({("operator", "reflective-import"): 1}),
        "import importlib.util\n": Counter({("importlib.util", "reflective-import"): 1}),
        "from operator import attrgetter as pick\n": Counter(
            {("operator.attrgetter", "reflective-import"): 1}
        ),
        "from ordinary import methodcaller as pick\n": Counter(
            {("ordinary.methodcaller", "reflective-import"): 1}
        ),
        "from importlib import *\n": Counter(
            {
                ("*", "wildcard-import"): 1,
                ("importlib.*", "reflective-import"): 1,
            }
        ),
    }
    assert displays == expected_displays[source]


def test_task3_development_syntax_policy_keeps_mutation_precedence_and_reflection_additive() -> (
    None
):
    cases = {
        "del holder.__dict__\n": Counter({"delete-statement": 1, "reflective-lexeme": 1}),
        "holder.value += item\n": Counter({"indirect-augmented-assignment": 1}),
        "mapping[key] += item\n": Counter({"indirect-augmented-assignment": 1}),
        "holder.value: object = item\n": Counter({"indirect-annotated-assignment": 1}),
        "mapping[key]: object = item\n": Counter({"indirect-annotated-assignment": 1}),
    }
    for source, expected in cases.items():
        result = _scan_task3_source_policy(source, "synthetic.py")
        assert _task3_reasons(result) == expected
        if source == "del holder.__dict__\n":
            assert _task3_displays_and_reasons(result) == Counter(
                {
                    ("del holder.__dict__", "delete-statement"): 1,
                    ("__dict__", "reflective-lexeme"): 1,
                }
            )


def test_task3_canonical_classifier_registry_covers_every_runtime_expression_node() -> None:
    import ast

    expected = {
        "Attribute",
        "Await",
        "BinOp",
        "BoolOp",
        "Call",
        "Compare",
        "Constant",
        "Dict",
        "DictComp",
        "FormattedValue",
        "GeneratorExp",
        "IfExp",
        "JoinedStr",
        "Lambda",
        "List",
        "ListComp",
        "Name",
        "NamedExpr",
        "Set",
        "SetComp",
        "Slice",
        "Starred",
        "Subscript",
        "Tuple",
        "UnaryOp",
        "Yield",
        "YieldFrom",
    }
    expected.update(name for name in ("TemplateStr", "Interpolation") if hasattr(ast, name))
    assert {node.__name__ for node in ast.expr.__subclasses__()} == expected


def test_task3_development_syntax_policy_retains_validation_serialization_zones() -> None:
    serializer_in_validation = _scan_task3_source_policy(
        "def _source_metadata(value):\n    return value.model_dump()\n",
        "attorney_v22_requests.py",
    )
    validator_in_serialization = _scan_task3_source_policy(
        "def _schema_hash(value):\n    return value.model_validate({})\n",
        "attorney_v22_requests.py",
    )
    reference = _scan_task3_source_policy(
        "def ordinary():\n    return model_validate\n",
        "synthetic.py",
    )
    assert _task3_reason_count(serializer_in_validation, "serializer-in-validation-zone") == 1
    assert _task3_reason_count(validator_in_serialization, "validator-in-serialization-zone") == 1
    assert _task3_reasons(reference) == Counter({"policy-symbol-reference": 1})


@pytest.mark.parametrize(
    "source",
    (
        "getattr(value, name)\n",
        "setattr(value, name, item)\n",
        "delattr(value, name)\n",
        "value.__setattr__(name, item)\n",
        "value.__delattr__(name)\n",
        "holder.__getattribute__\n",
    ),
)
def test_task3_development_syntax_policy_rejects_reflective_calls_and_references(
    source: str,
) -> None:
    result = _scan_task3_source_policy(source, "synthetic.py")
    assert _task3_reason_count(result, "reflective-lexeme") >= 1


def test_task3_canonical_classifier_covers_constructed_and_versioned_ast_nodes() -> None:
    import ast

    constructed = [
        ast.Await(value=ast.Name(id="provider", ctx=ast.Load())),
        ast.Yield(value=ast.Name(id="provider", ctx=ast.Load())),
        ast.YieldFrom(value=ast.Name(id="provider", ctx=ast.Load())),
        ast.Starred(value=ast.Name(id="provider", ctx=ast.Load()), ctx=ast.Load()),
        ast.FormattedValue(value=ast.Name(id="provider", ctx=ast.Load()), conversion=-1),
        ast.Slice(),
    ]
    if hasattr(ast, "Interpolation"):
        constructed.append(
            ast.Interpolation(
                value=ast.Name(id="provider", ctx=ast.Load()),
                str="provider",
                conversion=-1,
                format_spec=None,
            )
        )
    for node in constructed:
        kind = type(node).__name__
        assert _classify_call_target(node) == _InvalidCallTarget(
            f"dynamic-call-target:{kind}", kind
        )


@pytest.mark.skipif(
    not hasattr(__import__("ast"), "TemplateStr"),
    reason="template strings are available on Python 3.14+",
)
def test_task3_canonical_classifier_rejects_template_string_call_target() -> None:
    import ast

    call = ast.parse('t"{provider}"(value)').body[0].value
    assert isinstance(call, ast.Call)
    assert type(call.func).__name__ == "TemplateStr"
    assert _classify_call_target(call.func) == _InvalidCallTarget(
        "dynamic-call-target:TemplateStr", "TemplateStr"
    )


@pytest.mark.parametrize(
    "source",
    (
        "async def f():\n    return await helper()\n",
        "def f():\n    yield helper()\n",
        "def f():\n    yield from helper()\n",
        "@decorate(helper())\ndef f():\n    pass\n",
        "def f(value=helper()):\n    return value\n",
        "def f(value: Annotated[str, marker()]):\n    return value\n",
        "def f(values):\n    return [helper(v) for v in values]\n",
        "def f(values):\n    return tuple(helper(v) for v in values)\n",
    ),
)
def test_task3_canonical_classifier_allows_ordinary_calls_in_positive_contexts(
    source: str,
) -> None:
    governed = (
        "def helper(*args):\n    return None\n"
        "def decorate(value):\n    return lambda function: function\n"
        "def marker():\n    return None\n" + source
    )
    result = _scan_task3_source_policy(governed, "synthetic.py")
    assert result.calls
    assert not result.prohibited


_REQUEST_ZONES = {
    "validation": frozenset({"_source_metadata"}),
    "serialization": frozenset(
        {
            "<module>",
            "_schema_hash",
            "compiler_contract_fingerprint_v22",
            "_snapshot",
            "_fingerprint",
            "_context_source_record_v22",
            "_source_review_request_from_context_v22",
            "_source_audit_request_from_context_v22",
        }
    ),
    "neutral": frozenset(
        {
            "_new_request_v22",
            "_verified_source_request_context_v22",
            "_context_source_metadata_v22",
            "_frozen_source_record_v22",
            "_review_history",
            "_audit_history",
            "build_source_review_fragment_request_v22",
            "build_source_audit_fragment_request_v22",
            "build_source_referee_fragment_request_v22",
            "_grade_context",
            "build_ordinary_grade_request_v22",
            "build_contested_grade_request_v22",
        }
    ),
}

_COMPILER_ZONES = {
    "validation": frozenset(
        {
            "canonical_referee_disputes_v22",
            "_verify_source_review_aggregate_with_context_v22",
            "verify_source_review_aggregate_v22",
            "verify_source_audit_aggregate_v22",
            "_verify_source_audit_aggregate_with_context_v22",
            "_verified_source_aggregates_v22",
            "ordinary_grade_batches_v22",
            "validate_grade_fragment_v22",
            "_strict_rubric",
            "_validated_referee_dispute_v22",
            "_validated_canonical_baseline_v22",
        }
    ),
    "serialization": frozenset(
        {
            "_hash",
            "_referee_dispute_fingerprint_from_validated_v22",
            "_canonical_baseline_fingerprint_from_validated_v22",
        }
    ),
    "neutral": frozenset(
        {
            "<module>",
            "referee_dispute_fingerprint_v22",
            "verify_canonical_baseline_v22",
            "_canonical_dispute_passages_v22",
            "_semantic_identity",
            "_validate_source_fragment_semantics_v22",
            "_review_fragments",
            "aggregate_source_review_fragments_v22",
            "_audit_fragments",
            "aggregate_source_audit_fragments_v22",
            "_v21_inputs",
            "_referee_disputes_from_verified_sources_v22",
            "build_referee_disputes_v22",
            "validate_referee_fragment_v22",
            "aggregate_referee_decisions_v22",
            "compile_baseline_v22",
            "aggregate_grader_lane_v22",
            "_verified_grader_aggregate",
            "_score_v22",
            "_ordinary_observations_v22",
            "_same_observations_v22",
            "_same_observations_v22.view",
            "reconcile_grader_lanes_v22",
            "evaluate_outcome_sensitivity_v22",
        }
    ),
}

_STANDARD_SERIALIZER_SYMBOLS = frozenset({"loads", "model_dump", "model_json_schema"})
_STANDARD_VALIDATOR_SYMBOLS = frozenset({"model_validate"})
_STANDARD_NEUTRAL_POLICY_SYMBOLS = frozenset({"hexdigest", "sha256"})
_PROJECT_SERIALIZER_HELPERS = frozenset(
    {
        "_aggregate_v21",
        "_baseline_v21",
        "_disputes_v21",
        "_fragment_v21",
        "aggregate_referee_decisions",
        "build_referee_disputes",
        "build_source_record",
        "canonical_json_bytes",
        "compile_baseline_v21",
        "sha256_digest",
        "validate_referee_fragment",
    }
)
_PROJECT_VALIDATOR_HELPERS = frozenset(
    {
        "_audit_history",
        "_review_history",
        "_strict_fragment_ordinal_v22",
        "_strict_grade_coordinate_v22",
        "_strict_rehydrate_v22",
        "_strict_rubric",
        "_strict_source_context_v22",
        "_validate_envelope_binding",
        "_verified_source_request_context_v22",
        "_verify_source_audit_aggregate_with_context_v22",
        "_verify_source_review_aggregate_with_context_v22",
        "_wire_snapshot",
        "canonical_referee_disputes_v22",
        "ordinary_grade_batches_v22",
        "resolve_exact_passage",
        "verify_canonical_baseline_v22",
    }
)
_PROJECT_MIXED_HELPERS = frozenset({"index_review"})


def _helper_categories(symbol: str) -> _PolicyCategories:
    categories = []
    if symbol in _STANDARD_SERIALIZER_SYMBOLS or symbol in _PROJECT_SERIALIZER_HELPERS:
        categories.append("serialization")
    if symbol in _STANDARD_VALIDATOR_SYMBOLS or symbol in _PROJECT_VALIDATOR_HELPERS:
        categories.append("validation")
    if symbol in _PROJECT_MIXED_HELPERS:
        categories.extend(("serialization", "validation"))
    if symbol in _STANDARD_NEUTRAL_POLICY_SYMBOLS:
        categories.append("neutral")
    return tuple(dict.fromkeys(categories))


def test_task3_split_leaves_preserve_public_fingerprint_and_baseline_results() -> None:
    from regulatory_harvest.evaluation.attorney_v22_compiler import (
        _canonical_baseline_fingerprint_from_validated_v22,
        _referee_dispute_fingerprint_from_validated_v22,
        _validated_canonical_baseline_v22,
        _validated_referee_dispute_v22,
        referee_dispute_fingerprint_v22,
    )

    review, audit = _bound_disputed_source_aggregates()
    dispute = build_referee_disputes_v22(envelope(), review, audit)[0]
    baseline = canonical_baseline()

    assert referee_dispute_fingerprint_v22(dispute) == (
        _referee_dispute_fingerprint_from_validated_v22(_validated_referee_dispute_v22(dispute))
    )
    validated_baseline = _validated_canonical_baseline_v22(baseline)
    assert verify_canonical_baseline_v22(baseline) == validated_baseline
    assert (
        _canonical_baseline_fingerprint_from_validated_v22(validated_baseline)
        == baseline.baseline_fingerprint
    )


@pytest.mark.parametrize(
    "split",
    (
        "compiler-hash",
        "request-fingerprint",
        "grade-context-report-hash",
        "grade-fragment-report-hash",
        "baseline-mapping-items",
        "proposal-statement-join",
        "correction-statement-join",
        "ordered-requirements-loop",
    ),
)
def test_task3_eight_production_call_splits_are_differentially_equivalent(
    split: str,
) -> None:
    from regulatory_harvest.evaluation import attorney_v22_compiler as compiler_module
    from regulatory_harvest.evaluation import attorney_v22_requests as request_module
    from regulatory_harvest.evaluation.attorney_v22_models import (
        AuditConcernV22,
        SemanticProposal,
    )

    if split == "compiler-hash":
        value = {"b": 2, "a": 1}
        assert (
            compiler_module._hash(value) == hashlib.sha256(canonical_json_bytes(value)).hexdigest()
        )
        return

    if split == "request-fingerprint":
        request = build_source_review_fragment_request_v22(envelope(), (), fragment_ordinal=1)
        legacy = hashlib.sha256(
            canonical_json_bytes(request.model_dump(mode="json", exclude={"request_fingerprint"}))
        ).hexdigest()
        assert request_module._fingerprint(request) == legacy
        return

    if split == "grade-context-report-hash":
        report = "The report covers the rule."
        context = request_module._grade_context(report, {"SRC-1": "Source text."}, RUBRIC_V22)
        assert context["report_fingerprint"] == hashlib.sha256(report.encode()).hexdigest()
        return

    if split == "grade-fragment-report-hash":
        baseline = canonical_baseline()
        report = "The report covers requirement 1."
        batch = ordinary_grade_batches_v22(baseline, "A", 1)[0]
        expected = hashlib.sha256(report.encode("utf-8")).hexdigest()
        checked = validate_grade_fragment_v22(
            baseline,
            {
                "schema_version": "2.2",
                "anonymous_label": "A",
                "grader_lane": 1,
                "batch_ref": batch.batch_ref,
                "baseline_fingerprint": baseline.baseline_fingerprint,
                "report_fingerprint": expected,
                "requirement_grades": [
                    {
                        "requirement_id": "REQ-0001",
                        "disposition": "met",
                        "report_passages": [report],
                        "rationale": "The report covers the requirement.",
                    }
                ],
                "rationale": "The batch is graded.",
            },
            report,
        )
        assert checked.report_fingerprint == expected
        return

    if split == "baseline-mapping-items":
        baseline = canonical_baseline()
        validated = compiler_module._validated_canonical_baseline_v22(baseline)
        legacy_payload = {
            key: item
            for key, item in validated.model_dump(mode="json").items()
            if key != "baseline_fingerprint"
        }
        assert compiler_module._canonical_baseline_fingerprint_from_validated_v22(
            validated
        ) == compiler_module._hash(legacy_payload)
        return

    if split == "proposal-statement-join":
        semantic = SemanticProposal.model_validate(proposal("Operators   must file."))
        assert compiler_module._semantic_identity(semantic)[1] == " ".join(
            semantic.statement.split()
        )
        return

    if split == "correction-statement-join":
        correction = SemanticProposal.model_validate(
            proposal("Operators   must file unless exempt.")
        )
        concern = AuditConcernV22(
            target_proposal_ref="P0001",
            concern_type="incorrect_statement",
            passages=correction.passages,
            explanation="The qualification is material.",
            correction=correction,
        )
        assert compiler_module._semantic_identity(concern)[-1] == " ".join(
            correction.statement.split()
        )
        return

    baseline = canonical_baseline(3)
    batch = ordinary_grade_batches_v22(baseline, "A", 1)[0]
    request = build_ordinary_grade_request_v22(
        baseline,
        batch,
        "A",
        1,
        "The report covers the requirements.",
        {"SRC-1": "Source text."},
    )
    requirements = {item.requirement_id: item for item in baseline.requirements}
    legacy = [
        requirements[identifier].model_dump(mode="json") for identifier in batch.requirement_ids
    ]
    assert request.payload["requirements"] == legacy
