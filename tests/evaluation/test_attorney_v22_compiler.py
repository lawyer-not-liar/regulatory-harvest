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


def _ordinary_outcome_aggregate(
    baseline: CanonicalBaselineV22,
    lane: int,
    *,
    dispositions: tuple[str, ...],
    passages: tuple[str, ...],
) -> GraderAggregateV22:
    report = "First grading passage. Second grading passage."
    requirement_ids = [item.requirement_id for item in baseline.requirements]
    assert len(requirement_ids) == len(dispositions) == len(passages)
    grade_by_id = dict(zip(requirement_ids, zip(dispositions, passages, strict=True), strict=True))
    fragments = []
    for batch in ordinary_grade_batches_v22(baseline, "A", lane):
        fragments.append(
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
                            "disposition": grade_by_id[requirement_id][0],
                            "report_passages": []
                            if grade_by_id[requirement_id][0] in {"not_met", "uncertain"}
                            else [grade_by_id[requirement_id][1]],
                            "rationale": "The requirement was independently graded.",
                            "omission": None
                            if grade_by_id[requirement_id][0] == "met"
                            else "The report does not fully state the requirement.",
                        }
                        for requirement_id in batch.requirement_ids
                    ],
                    "rationale": "The issued ordinary batch was independently graded.",
                },
                report,
            )
        )
    return aggregate_grader_lane_v22(baseline, "A", lane, tuple(fragments), ())


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
    from regulatory_harvest.evaluation.attorney_v22_requests import (
        _source_audit_request_from_context_v22,
        _source_review_request_from_context_v22,
        _verified_source_request_context_v22,
    )

    case = envelope()
    context = _verified_source_request_context_v22(case)
    accepted_proposals: list[dict[str, object]] = []
    review_fragments: list[AcceptedSourceReviewFragmentV22] = []
    for ordinal in range(1, 129):
        request = _source_review_request_from_context_v22(
            context, accepted_proposals, ordinal
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

    accepted_concerns: list[dict[str, object]] = []
    audit_fragments: list[AcceptedSourceAuditFragmentV22] = []
    for ordinal in range(1, 129):
        request = _source_audit_request_from_context_v22(
            context, review, accepted_concerns, ordinal
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


def test_v22_reconciliation_preserves_common_pass_despite_passage_variance() -> None:
    baseline = _alternative_world_baseline(ordinary_count=1, contested_count=0)
    first = _ordinary_outcome_aggregate(
        baseline,
        1,
        dispositions=("met",),
        passages=("First grading passage.",),
    )
    second = _ordinary_outcome_aggregate(
        baseline,
        2,
        dispositions=("met",),
        passages=("Second grading passage.",),
    )

    reconciliation = reconcile_grader_lanes_v22(baseline, first, second)

    assert reconciliation.absolute_disposition == "PASS"
    assert reconciliation.reason_codes == ()


def test_v22_reconciliation_preserves_common_fail_despite_grade_variance() -> None:
    baseline = _alternative_world_baseline(ordinary_count=2, contested_count=0)
    first = _ordinary_outcome_aggregate(
        baseline,
        1,
        dispositions=("partially_met", "met"),
        passages=("First grading passage.", "Second grading passage."),
    )
    second = _ordinary_outcome_aggregate(
        baseline,
        2,
        dispositions=("partially_met", "partially_met"),
        passages=("First grading passage.", "Second grading passage."),
    )

    reconciliation = reconcile_grader_lanes_v22(baseline, first, second)

    assert reconciliation.absolute_disposition == "FAIL"
    assert reconciliation.reason_codes == (
        "CRITICAL_RECALL_BELOW_FLOOR",
        "WEIGHTED_COVERAGE_BELOW_FLOOR",
    )


def test_v22_reconciliation_keeps_outcome_changing_lane_variance_inconclusive() -> None:
    baseline = _alternative_world_baseline(ordinary_count=1, contested_count=0)
    first = _ordinary_outcome_aggregate(
        baseline,
        1,
        dispositions=("met",),
        passages=("First grading passage.",),
    )
    second = _ordinary_outcome_aggregate(
        baseline,
        2,
        dispositions=("partially_met",),
        passages=("Second grading passage.",),
    )

    reconciliation = reconcile_grader_lanes_v22(baseline, first, second)

    assert reconciliation.absolute_disposition == "INCONCLUSIVE"
    assert reconciliation.reason_codes == ("GRADER_DISAGREEMENT",)


def test_v22_reconciliation_defers_contested_variance_to_sensitivity() -> None:
    baseline = _alternative_world_baseline(ordinary_count=1, contested_count=1)
    first = _alternative_world_aggregate(
        baseline,
        1,
        contested=(("met", "met"),),
    )
    second = _alternative_world_aggregate(
        baseline,
        2,
        contested=(("met", "not_met"),),
    )

    reconciliation = reconcile_grader_lanes_v22(baseline, first, second)
    sensitivity = evaluate_outcome_sensitivity_v22(baseline, reconciliation)

    assert reconciliation.absolute_disposition == "PASS"
    assert reconciliation.reason_codes == ()
    assert sensitivity.absolute_disposition == "INCONCLUSIVE"
    assert sensitivity.reason_codes == ("GRADER_DISAGREEMENT",)
    assert sensitivity.outcome_determinative_contested_ids == ("CONT-0001",)


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
        # Match Python 3.13+'s ``show_empty=False`` on every supported Python.
        import copy

        stable = copy.deepcopy(node)
        for item in ast.walk(stable):
            for name, value in tuple(ast.iter_fields(item)):
                if isinstance(value, list) and not value:
                    delattr(item, name)
        return ast.dump(stable, annotate_fields=True, include_attributes=False)

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
        ('attorney_v22_compiler.py', '<module>#1::_merge_grader_outcomes_v22#1', 'dict.fromkeys', (), 'd982331af4e17ca05d24403db64c2856204968afdd15aee361b06d82b80dac61'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_merge_grader_outcomes_v22#1', 'tuple', (), '59115d76c4e4383dcc773cc4213b7344f14249367af4af4abc46e1d94975d981'): 1,  # noqa: E501
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
        ('attorney_v22_compiler.py', '<module>#1::_validate_source_fragment_semantics_v22#1', '_SourceFragmentSemanticResponseErrorV22', (), '66248ffea418f8b494b72f9e0ae49b5495396b17fdc7c3a4764c3189f9ea34fa'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_validate_source_fragment_semantics_v22#1', '_SourceFragmentSemanticResponseErrorV22', (), 'a40e420ddb32328ecba79076bbbefdaa899d9ebf97dcfe411e4cdb2639cc43b7'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_validate_source_fragment_semantics_v22#1', '_semantic_identity', (), 'feefaf3b2bf4387f03e854b333fdf257156c8835a87338917c1267ad39eb0609'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_validate_source_fragment_semantics_v22#1', 'canonical_json_bytes', ('serialization',), 'c193020b210eb802d88299b1269d6c296821bac3c87abefb7ffb80c3466ee0b7'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_validate_source_fragment_semantics_v22#1', 'value.model_dump', ('serialization',), '33236b7fe944f5a45f7098f51ed4799942d7995d43becfc8102eca3a36e0e821'): 1,  # noqa: E501
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
        ('attorney_v22_compiler.py', '<module>#1::evaluate_outcome_sensitivity_v22#1', 'ReconciledGradeV22.validate_for_baseline', (), '34b596012509e523921a56087a2fca0e4cc6844b46b87dcb4125f5e62ae8d4ab'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::evaluate_outcome_sensitivity_v22#1', 'RubricValidationError', (), '312bffae2c8513cd7918453679739c5a288fe3010f56a0290d2058cb88000e23'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::evaluate_outcome_sensitivity_v22#1', 'RubricValidationError', (), '55250adb6e44ee85e29da80f2acefc0934544655d3565145050a315f43d97c35'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::evaluate_outcome_sensitivity_v22#1', 'SensitivityRecordV22.model_validate', ('validation',), '4699983cf9c19d41b8e5ab6b620d124b939904d40123a054b35ab6797b24e2c5'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::evaluate_outcome_sensitivity_v22#1', '_hash', (), 'ae9c13190600e12c81ced69b221eae4188d32142bc34f22942711fff585a0225'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::evaluate_outcome_sensitivity_v22#1', '_merge_grader_outcomes_v22', (), '34a64218c34a831eb532dc18c933405c6a1afa61aa5be49a0b79c4fc931411b4'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::evaluate_outcome_sensitivity_v22#1', '_strict_rubric', ('validation',), '6e69eebaef5c5002c629df0b9953a9896f70de85c0683f3fd439fdc7a533d421'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::evaluate_outcome_sensitivity_v22#1', '_verified_grader_aggregate', (), 'a09f2633de77e980c37b32e495c3a7a488b7406636d1bf681f1a89cce13ac6f4'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::evaluate_outcome_sensitivity_v22#1', 'dict.fromkeys', (), '9317d41e4b1c8514fab3b4593fc246b97b12a331b5856902f17d6b6346ab0571'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::evaluate_outcome_sensitivity_v22#1', 'reconcile_grader_lanes_v22', (), 'a3b4380a29160cd5819b2215bbd8ae3b0a7c9abc32622d8ad5a15f199aafccc8'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::evaluate_outcome_sensitivity_v22#1', 'tuple', (), 'bf18e4b1e6f79dba5884f1b534bf29461935956cdeddae449e07baa4ec4966b8'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::evaluate_outcome_sensitivity_v22#1', 'verify_canonical_baseline_v22', ('validation',), '4677b286f7b12c6c62c289dd0f9743452cd5456e4fc89f783f6a6d6e2582a617'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::evaluate_outcome_sensitivity_v22#1::<ListComp>#1', 'lane_outcome', (), 'f7dc2d10155fe952dbd83e864d1e4a05a61896ecfb5af046978afeb8f64eac67'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::evaluate_outcome_sensitivity_v22#1::lane_outcome#1', '_merge_grader_outcomes_v22', (), 'e268eb71edffd52490642d80c66c6ab18e130164d8da822afb2ed25bbc608365'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::evaluate_outcome_sensitivity_v22#1::lane_outcome#1', '_ordinary_observations_v22', (), 'f070136d77812a08853d49a748d2e4e4b270a8ec528d7723b8560312cefcc751'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::evaluate_outcome_sensitivity_v22#1::lane_outcome#1', '_score_v22', (), '2579b1ca4ced0005f519b9b81109873cf7252c7b4c9b4458519a8e6cb0dc0ee8'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::evaluate_outcome_sensitivity_v22#1::lane_outcome#1', '_score_v22', (), 'bd1a3d58b9a935992ac21ab0b500e3e875465847116b5291c6f1e79455ea3991'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::evaluate_outcome_sensitivity_v22#1::lane_outcome#1', 'auditor_world.append', (), '081c64da08f2ccb111882fb2b275f2380b7272ab6feedf59a2a6401fe4a9c87a'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::evaluate_outcome_sensitivity_v22#1::lane_outcome#1', 'differing_alternatives.append', (), '1398a8c338c7b71cdb0066d3917633fbe2291af30301f24b3181a846e0b8c710'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::evaluate_outcome_sensitivity_v22#1::lane_outcome#1', 'list', (), '98298fada240e4964ae33fcf0aa734911e0cbc13a2e300a55710cb8a91b588e3'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::evaluate_outcome_sensitivity_v22#1::lane_outcome#1', 'list', (), 'f04d71114630815a3545496ee98144502d83a5300e4d3cc60e1d6d24dc23aa63'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::evaluate_outcome_sensitivity_v22#1::lane_outcome#1', 'reviewer_world.append', (), '6959d8a01b3e1cbcaddfe2573b2f764bdad8e2812d4c4639ae326cd63fcdad52'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::evaluate_outcome_sensitivity_v22#1::lane_outcome#1', 'tuple', (), '4316e3dc4203ac060319695a9a142a4c3e3c90e9c6f86b9dd0de9772abc2c731'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::ordinary_grade_batches_v22#1', 'RubricValidationError', (), '54d2ae4d0cdc04a95d1c3e382fae874db37093f43a6253481515b138f5b062ad'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::ordinary_grade_batches_v22#1', '_strict_grade_coordinate_v22', ('validation',), 'e60afb37a863efdb58d538633ac494f9d0f6a074f4c51e224182c293ace29f27'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::ordinary_grade_batches_v22#1', 'len', (), '78ea68ec2879db2d516c6278db5122518928502310e1aa1b3a0469248c2523a8'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::ordinary_grade_batches_v22#1', 'tuple', (), '67a7606cb34226056257d54d545216c7a535366a9eb4a791c6a9b420b8e2e39a'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::ordinary_grade_batches_v22#1', 'verify_canonical_baseline_v22', ('validation',), '24890a3938f01771899533f62997116ea2c8a898cb203380a22dac777922bdea'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::ordinary_grade_batches_v22#1::<GeneratorExp>#1', 'OrdinaryGradeBatchV22', (), 'c08d72ba8b2e4b211852dda1c4af41a439bcac145ce7e7c69fb13749460a6abe'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::ordinary_grade_batches_v22#1::<GeneratorExp>#1', 'len', (), 'e3237cef979e8501a4e0696f4098a42207cfce0f9c61c73b2e89967b32885f7f'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::ordinary_grade_batches_v22#1::<GeneratorExp>#1', 'range', (), '98ef04841c83b469ce774f56b9708ed5508ad6386dcc3bac393a20eb06f2c356'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::ordinary_grade_batches_v22#1::<GeneratorExp>#1', 'tuple', (), '48fa1bebca11e98e13d550308071473cd3d27937f2b323aa17b91e206dd5488e'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::reconcile_grader_lanes_v22#1', 'ReconciledGradeV22.validate_for_baseline', (), '6ed2bb5f4caeab6448e26f1683543e9afe7cef34482547a3038af606aa8b7a5c'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::reconcile_grader_lanes_v22#1', 'RubricValidationError', (), '56afb3c160c677f9484be7674f5c973a5232594da51f981facef5a1bea728eb0'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::reconcile_grader_lanes_v22#1', 'ValueError', (), 'b76a8116ca28c7a32c1da11c87f0b14bbfd984b9b07510d2f576dbd5cc135ec7'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::reconcile_grader_lanes_v22#1', '_hash', (), '29eefa3c34b1ca4c1c7c540225f4434b2873d66c18f54ebeaabd074008b2a24d'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::reconcile_grader_lanes_v22#1', '_merge_grader_outcomes_v22', (), 'a98441faca6523f5211bb88177389eaf51f8beb627c49a484a0472dcd7983162'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::reconcile_grader_lanes_v22#1', '_ordinary_observations_v22', (), '93eb6c7c477e36dd4a976810807a13dcca6e3ebda9fd41673a380531c4b61bca'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::reconcile_grader_lanes_v22#1', '_ordinary_observations_v22', (), 'c38f33b4d7c0236c05098213bf9d231a65869d73e3370b7877a3d0e87ff0ef5c'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::reconcile_grader_lanes_v22#1', '_score_v22', (), '61bded88776a3613aa5bbb03887d6a58a9dc8fef775072e78d999398daee8f52'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::reconcile_grader_lanes_v22#1', '_score_v22', (), 'c45f6761b5c7472935efc8ef2ddc889fc8dbe7f0281158ff1786eb9cc18ca97c'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::reconcile_grader_lanes_v22#1', '_strict_rubric', ('validation',), '0c5a9a5eb082c077ed2f3eafa7741792e13580c8d4ac5958c490ed1e14da8de4'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::reconcile_grader_lanes_v22#1', '_verified_grader_aggregate', (), '1eeb01d7610c4d30d28fde5383debb491f9054869fd461f618d517ddae909e51'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::reconcile_grader_lanes_v22#1', '_verified_grader_aggregate', (), '67f268e535ccc0c7f5f3c3cd7a324f4f90801355888b85b838a80091a3123ca0'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::reconcile_grader_lanes_v22#1', 'first.model_dump', ('serialization',), '65e0e071055bdbba2d0788721b4bb43bb7e90b2274be91e66885b5662f057eae'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::reconcile_grader_lanes_v22#1', 'second.model_dump', ('serialization',), '4fb512cb681871ff047ed8943e6e6fa8f335c0a343e0b35a94accae2eb140c40'): 1,  # noqa: E501
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
        ('attorney_v22_requests.py', '<module>#1', 'ContestedGradeFragmentV22.model_json_schema', ('serialization',), '547138d8fe1ecf1befbcee29ecce924afe7457a84aff5ce02fb16987c8996d81'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', 'OrdinaryGradeFragmentV22.model_json_schema', ('serialization',), 'f1b883d860d11898e2c3267c588b0f203acc8592a3a1f4e7cd279843478fd9bc'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', 'RefereeDecisionV22.model_json_schema', ('serialization',), '3596505678b0ddb3b9008375d2939f25f72ba959f4abfd970a2411e16f841fd4'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', 'RubricV22.model_json_schema', ('serialization',), 'f1eb60047379fd4c9e315173d13dc2c4ce1cd0ec5248e09bb459047c3a40e40d'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', 'SourceAuditFragmentV22.model_json_schema', ('serialization',), 'd2f0ed20a010a0870bcef2460da5114584a1d82214e029348b7920e2395c8594'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', 'SourceReviewFragmentV22.model_json_schema', ('serialization',), '5cb071a98f1bf7a7ea63b2d7a888af0b64fc9aedc0aa7b4ece14d216f2656606'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '_ContestedGradeDraftV22.model_json_schema', ('serialization',), 'd1946350853fad59386688597df470ca487fc29f1ac8a7ce873ddc1f0e16cc37'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '_OrdinaryGradeDraftV22.model_json_schema', ('serialization',), '98f419d15ef2b07ee1af067fa090eafb685c2ba8cd8fda59af83adaf08782204'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '_RefereeDraftV22.model_json_schema', ('serialization',), 'eea285e03c86599d7662d857500085306592ab36f466efa81719a8bff8c37d13'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '_SourceAuditDraftV22.model_json_schema', ('serialization',), 'b3f73d6a18d8eceb31e06bacc7b2738f1cdb888fdbbbbb47320e12786201a07f'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '_SourceReviewDraftV22.model_json_schema', ('serialization',), '91a7b6181b7978e24d51e4a080e40b02127daba37d96d75c60a673878954b339'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '_schema_hash', (), '18004cba16d27bc9976f684b7ed447035d03ef9142a849aa1ec0eb31d1940194'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '_schema_hash', (), '28c6d6cafa3d956c8073211262aa279dc954db5edae3935b254f45da809786a0'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '_schema_hash', (), '523866da8760e2268fd65f10810db010d41c74f57e980adb4b0261bd2f2bf388'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '_schema_hash', (), '576ccb449ef407683c285d1f34abe4708bc65dbabcf26dba15e782f009ea5017'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '_schema_hash', (), '667f63de5223192ca626942b7ff73558c4e64cd3e912efb5d2e454dede58658d'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '_schema_hash', (), '748a09554a04ad14e416ddc915048d5f90ace04f4519351d693e419a4da67aee'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '_schema_hash', (), '84e9d02b12635fc24a17c026854e10388022edcddedebe486bb7c5df4a23a107'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '_schema_hash', (), '9cf8fed9ade7dea74b51c337d073ff5255edfb4d957dd0c6395612b1496a9f7c'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '_schema_hash', (), 'cae07d5e70aa520ed8d4e25d12b65dfc5dc716af65fdd58896b7c67ae375ff6b'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '_schema_hash', (), 'd0d04295af20e16df79995096b8191913e0819c78613fc6150c6b9f70b4079fd'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', '_schema_hash', (), 'ea68226aa1777247e58ac488060876702fbae68b2ebef7312d6d1d2572af9b44'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1', 'compiler_contract_fingerprint_v22', (), 'c744547fbccffdbe77aa423cda3fbb7fca697456641f459764ac5a254b18fae2'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::<DictComp>#1', '_ENUM_ALIASES.items', (), '473927c940f61f6c722f905bc1a779d0773272d2a5099ec96a98528f05ef7fa4'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::<DictComp>#1', 'sorted', (), '4e57de36c378f2169375400f80097094e995555bf536869e3a7e1537cfdada20'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::<DictComp>#1', 'sorted', (), 'b69167ff8bb1f69486acc8d1099f2e53d20a57b35755e55d48dcdc5d4898a9e3'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_VerifiedSourceRequestContextV22#1', 'dataclass', (), 'f2e86cc1e1811597b52af25239bb363328316f8a19409f96eb844ceb863b58d7'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_audit_history#1', 'ValueError', (), '0958383400002ddd4a11dcf1b98ad7b4f010d97d1d5d6f271ca9799d2b11d6d6'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_audit_history#1', 'ValueError', (), '8968db3b4a5b1e8eb75af9748f38c1a0e47ccf739f0ebb37ac9fc02f95c1a874'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_audit_history#1', 'ValueError', (), 'a7af07ab7c175924d0f063146cfd303d3fc9c84e207f7603b971a9b997bda8cb'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_audit_history#1', 'ValueError', (), 'aec41737e936179e6995282bbd18a82fd7b3aea9b6cebc05bb3da187d38b6d56'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_audit_history#1', 'ValueError', (), 'b637e7bf36adedbbf6fb2642e6b10cfa9863dec87ddec82e6183dcda7df13bee'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_audit_history#1', 'ValueError', (), 'b862fab93d0d935397f9164e484e861b9d35d79f77f025d5a4ad6211a624e06f'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_audit_history#1', '_source_audit_request_from_context_v22', (), '7a420841358173b71a3ed31e5c44966134528803aa18e347b07384953167e7e4'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_audit_history#1', 'accepted_concerns.extend', (), '87b067920c613fba16f42e71b1a88650927a3111977315be8c359ddc57aa2ae8'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_audit_history#1', 'any', (), '2ed6adb6faabe5002ffcb2478707cfac7c46b55169c7b95c97ce7e25f84308e0'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_audit_history#1', 'any', (), 'cc5086eba4d81681490257ab3334041b2030715a6aa140682d7b3be32edbf1d1'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_audit_history#1', 'isinstance', (), 'a3e00cbf0009b6cd1ef98d9f6f0fa3bb29efae2e2e5ee582f5d00468a08a4390'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_audit_history#1', 'len', (), '03a231f260f783ace0d300678526b0ea420ea39bbb29df2963c217c2da762da9'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_audit_history#1', 'len', (), '417b072c4d0bb4f3fc0d1143c14db3905bcbab009f4992712bb54d09d5d8b341'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_audit_history#1', 'len', (), '6956e54091305858485d8157bfb52293656afa99195afd2ea3e219947bb75d9f'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_audit_history#1', 'len', (), '6faae2e29cca837986ba33d1a1ccb2cf128f186f148c4fc2b20bf762a2fd4fbd'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_audit_history#1', 'list', (), '8eea85d1db36471edc460384af2787996cda56ff7b51f3399a2599ccd7ae2928'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_audit_history#1', 'range', (), '03182cadeb5aaf2705baf123601582751718025949b2fff99aad40eb9eb011fd'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_audit_history#1', 'sum', (), '942e1ab0a175271df95ceaaef392a35095b341afa6197e0148d603aa80228bde'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_audit_history#1', 'tuple', (), '10018060284652b9d018d878d5c7c843c7645a826446317ac72881a09cf0c0ee'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_audit_history#1::<GeneratorExp>#1', '_strict_rehydrate_v22', ('validation',), '06d7f60a15c21227f6d825069f39549c6b4b7f4e2f9054068c0753b74d02acac'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_audit_history#1::<GeneratorExp>#1', 'tuple.__iter__', (), '133b8051b65377fca9ea2e35919123e1715b769df81847a25335c67a6f4c70ec'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_audit_history#1::<GeneratorExp>#4', 'len', (), '980b96df8cfe2a9e2de37f865499026c0aed8a004569cb25e2921cba5599208e'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_audit_history#1::<GeneratorExp>#5', 'concern.model_dump', ('serialization',), '33de4e319da32c4d027608c94c846b599b8b2ef97daaae8c7933c5a443bbd8b0'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_context_source_metadata_v22#1', 'dict', (), 'ac963e99dc4a8bd2814287c1be59eb0d04b210aced0bf92c3922a041a6662f62'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_context_source_record_v22#1', 'cast', (), 'e24a17108233f2d5289a911a9fb6e032c0cbe14c7c8b056e1d3d5fee995867c5'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_context_source_record_v22#1', 'json.loads', ('serialization',), '7bf08bb3b27b1496c2316c4dbad371eb1908fb0920bd1a1b3291608e083e5d34'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_fingerprint#1', 'canonical_json_bytes', ('serialization',), '563ca8bafe55289caf1757996c7dc0c1e283afc079f67b8b8939389dcc154380'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_fingerprint#1', 'digest.hexdigest', ('neutral',), 'ac10d42b3508498e3923da7ac8289b880f3fb3b38a23fe0041fb99b3280d7a49'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_fingerprint#1', 'hashlib.sha256', ('neutral',), 'bb4c2f40f63d63a225fdb7911d81f47f9df41731cff727d4339ff669447cf13c'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_fingerprint#1', 'request.model_dump', ('serialization',), '02719390e6fffe56096f360dec5937aed828841996cf91aabf80003cb38cd6ac'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_frozen_source_record_v22#1', '_context_source_record_v22', (), 'd9dae10efffbed56857a2f2df15701ba0771c0f6e61af092ecb9daf5e4b59d91'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_frozen_source_record_v22#1', '_verified_source_request_context_v22', ('validation',), '192c6391386a2a45d565fbedfa8652150a3909649475b65105e8598d788cfa09'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_grade_context#1', 'ValueError', (), '9b27892ff2ba32417bee2fdbf2020811d12fc4a39815075f712341b3099f9cfa'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_grade_context#1', 'ValueError', (), 'e41651572bb11cb4d520903b1e1ceedc3ef56e5d42f59b8c3b717ad99182cab9'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_grade_context#1', '_strict_rubric', ('validation',), '875afded02523dcb4b314f8e5f6c0a431deb1e2522768ddc221443af0aaca751'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_grade_context#1', '_strict_source_context_v22', ('validation',), 'dcdff9bfcbbc68a60e115b84e5873d1191d3b188ecffd587fcbded0e55763db2'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_grade_context#1', 'checked_rubric.model_dump', ('serialization',), '3bcc8465e0d44b86357390a85a9658195de1ea2ac77e6273ecd8eedb67c8aabc'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_grade_context#1', 'hashlib.sha256', ('neutral',), 'e8e52c5e888dae23e8c3b6124b4e11c68bb111a0ce27fb866938ec20509a3c3f'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_grade_context#1', 'isinstance', (), '56c3691c878c3d5a27653af1774cfb5fe853d5b8d00d8558ede1bb1287f10055'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_grade_context#1', 'report_digest.hexdigest', ('neutral',), 'a73d610e3ce6834776cb507d70cf9e192dc256569d5c0b63696b463376af9cf3'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_grade_context#1', 'report_text.encode', (), 'dc33fac5c1a8dc9620bd3f9cc5427bccaca89f3e45111a0385ead394df4e58ca'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_grade_context#1', 'report_text.strip', (), '77d1c4004fb23df712e98085c2f6a441c5f5912381f6efa8af747f9243200bba'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_new_request_v22#1', 'EvaluatorRequestV22', (), '1f874f0300fa67fa19a81e7eff866225cbfc702d02533c79b0e171bb964c9617'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_new_request_v22#1', '_fingerprint', (), '1160f0d747fe687a3be252a0bafb2b080d38bd67a634d996267140a2e6810248'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_new_request_v22#1', '_snapshot', (), '01ff6ff73a86825c504bd02cb5a9077193384147d87d97330b6c796c2851a6c3'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_new_request_v22#1', '_snapshot', (), 'ce295f5cc9272fd24f9c6645d2fb6fea87294590421e4800f0cd9556079b8ec2'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_new_request_v22#1', '_strict_rehydrate_v22', ('validation',), '27e31d57346874dd2b0cc0352cc774403f7e34337e83d5b06c6833e4b83fec67'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_new_request_v22#1', 'provisional.model_dump', ('serialization',), '5890846fb0e2e7eceaa12187aa92f6ee8b6ec633d7a0179ff20137a472768125'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_ordinary_grade_request_contract_v22#1', 'ValueError', (), '6a9a4231ac76bb588151c7eb470a0a8a1746dfb522dfb5452ec801b83cb4851e'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_ordinary_grade_request_contract_v22#1', '_OrdinaryGradeDraftV22.model_json_schema', ('serialization',), '312f246191574a4c5d3e2b454c3ed399568946cbefd693b0bf24392284c49edc'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_ordinary_grade_request_contract_v22#1', '_snapshot', (), '34fec086edb34bad5a2e3140878237025c793798bea9be590da77b7b84e617a3'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_ordinary_grade_request_contract_v22#1', 'cast', (), '4b33f172560138631236c5b637cc8f0ae4471e811cd61f55e943a558c66c7987'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_ordinary_grade_request_contract_v22#1', 'cast', (), '4df781d2bd00ae306093b2ed1bde05113a77c8efd3ac41bda1a774d0d3d8b026'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_ordinary_grade_request_contract_v22#1', 'cast', (), '5f4b865db37167ff2a50734f241bfa448be7c74771c2afb7fb792bb2554c20ab'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_ordinary_grade_request_contract_v22#1', 'cast', (), '73f0a44ac1ca65c77b1e10b6e4f177e92d7055efc0b7c685ec30125a78dd9ad7'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_ordinary_grade_request_contract_v22#1', 'cast', (), '8a085828d0fbd9a319e0f9271633b1a805bc092ff86ac65dca72931274274ef3'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_ordinary_grade_request_contract_v22#1', 'cast', (), '8b4ab30b3f0fae87131b4801d850be35c66cc2bb17e9dbf44760e8292a945c09'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_ordinary_grade_request_contract_v22#1', 'json.dumps', (), '95cb60557d95cfe20a617b74b6d4dde7435dc51fbda2b7a54659c5b47799f239'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_ordinary_grade_request_contract_v22#1', 'list', (), '798d8dfe1a4dbb4b3a7c3bb4b1fee7644a7ace63dccdcbdd1fd6d0fb805fa2c2'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_ordinary_grade_request_contract_v22#1', 'range', (), '948b46f37ae15ef46dc7f80bac07c7e8f02f385f928b9713940d82b6be5e938e'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_review_history#1', 'ValueError', (), '19f9ca4892b7f2f7a3cd2ea839ee90244435fa35e5224e112180308147ade6a6'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_review_history#1', 'ValueError', (), '7eacb5be672c3b44e1ac154357cfd52d5634c9bcd3befccc822330b493f3876d'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_review_history#1', 'ValueError', (), 'b650cc2f819421f721bf3d96bd062dcc9696ef52e49d1bfae5ad5fc53ea58500'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_review_history#1', 'ValueError', (), 'c7e46d7473856506d9fc96714c58deadadd025ed7f40875ee46cd52cc37e4e90'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_review_history#1', 'ValueError', (), 'd94a021564aa84784aecf8d18f51c5079fb8dbc869a91e85b2fd9e26f5867531'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_review_history#1', 'ValueError', (), 'eebf64b1e9123703e076ed2670471eb661e590c1f100e52c1421373337cfd774'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_review_history#1', '_source_review_request_from_context_v22', (), 'ab743509da571b494aeccfe2b1c9d983fe8035051db765bf5e81d679a20441db'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_review_history#1', 'accepted_proposals.extend', (), '31db66af8d46fd1f261e6788b921152b337897e162775188e77edd3429dfefe7'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_review_history#1', 'any', (), '7333d8132856366971b3c49007a7db60e65072c3eb90d96bd2a6aedd53cd98a6'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_review_history#1', 'any', (), 'a977f5efc57b6ea19fb9c7298f0e650ebb2b900fa79f906bd51ec377b3f8ff5d'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_review_history#1', 'isinstance', (), 'fcfc9159a1fd88ae48162e39c7c502f62d6dbdcde45984d5f9d0bfb1fa259993'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_review_history#1', 'len', (), '09d8f341d9c9a76d35f88c59de6c8d03faa47f00ae938298e72ee10e732d7a2c'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_review_history#1', 'len', (), '57b3403b11e3bfca08c22b43864ed74f24e7ff94d60c4e06ab043a4a0865ec8c'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_review_history#1', 'len', (), '76574579459df889f62a23e339be3fcb65bd818add053563a989bcb42a30d043'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_review_history#1', 'len', (), 'f56f2677aef0c227a40ec2f8e8612c354f949727b4abd2c01ce0efe191637463'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_review_history#1', 'list', (), '2814dfccd2e4727a5ae8f560ba74152e80aa2efaf169629c28fe4d661e5f46e5'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_review_history#1', 'range', (), '91d63fca3f92b5eb23a6fca21b9fa29d7b405a9806f9ae629e9d228e99025965'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_review_history#1', 'sum', (), '92ba39b44d6dcc5555df1383aa99484fa7b952042d48fe9da6c676987a598823'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_review_history#1', 'tuple', (), 'f7b1e459bd1646b1442d45a11617e34559152c7a09dd5cedd9a412683578dfb8'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_review_history#1::<GeneratorExp>#1', '_strict_rehydrate_v22', ('validation',), '51521b8246cafb8d4f9aca308fd7148c4f709c503ea0d9a6faec12941379fae9'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_review_history#1::<GeneratorExp>#1', 'tuple.__iter__', (), '14f3e0df6a59f936738be91ff033a0c46e56ffd6e6a62b3976cab0cc74bf17d2'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_review_history#1::<GeneratorExp>#4', 'len', (), 'a449a2ccd2d5346e9ed499a9d33337ecbf9200ed2f165202e56332b27dff5096'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_review_history#1::<GeneratorExp>#5', 'proposal.model_dump', ('serialization',), '023b93114e555be8debe196f576626332b2b4b20be2f08d87bfcc5e4493139fa'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_schema_hash#1', 'canonical_json_bytes', ('serialization',), 'd440de26553e04670477843af30522fd04c3a7e6290b2360bf285d42a0fe8404'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_schema_hash#1', 'sha256_digest', ('serialization',), 'bb9182610ecefce088f32d9217cee286058ef9e9a5be6f96b4de77c6970b869f'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_snapshot#1', 'ValueError', (), '16218cc36e46dfa567eecbb8a6f238d5c17d048e07745a8ef7f7b32d5bc9b83b'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_snapshot#1', 'ValueError', (), 'c84caee774ae122012244c8e6ae9be96ccba7ecc3b7b9c9c31f18b581861388a'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_snapshot#1', 'canonical_json_bytes', ('serialization',), '3aae5946dd8fc02903e6260bd93e1283239d7105139683b71c0736a00c90930d'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_snapshot#1', 'cast', (), '949e463e034eff8228a2c45e5ac0b5e0c8b49036097aa90e99a8859088892a26'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_snapshot#1', 'json.loads', ('serialization',), '9e7151258344ddc0483e58db03927a367cf1be538dccc812501938fc28e83049'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_snapshot#1', 'type', (), '7045de0a2b808cdbc6ccfe77913dfce3f5aef20b861c2b0cc83f9a8ae26951a5'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_audit_request_from_context_v22#1', '_context_source_metadata_v22', (), '8058f8c2a3e1beee0328738f0d3a66e225aa5f5f79ffaa3927e8c81067e389a7'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_audit_request_from_context_v22#1', '_context_source_record_v22', (), 'fac4b271d64e26f02e189b9bc5ea40edb66391ca79201d09c219e75fdc76d04b'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_audit_request_from_context_v22#1', '_new_request_v22', (), '9b099caa827c898f634e0918f02e8e98a4143fbc109834bc7a34a00a9468657e'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_audit_request_from_context_v22#1', '_source_evidence_handles_v22', (), '7d72d0a9d63a781438429c0364d3818503656d340c55581a220a417206463b88'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_audit_request_from_context_v22#1', '_source_fragment_contract_v22', (), '0ae9a0d9fe9490ac173a7b744645f3ed47866af62ff19c19de12a2a72815c34b'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_audit_request_from_context_v22#1', 'len', (), '54ef0a223415d0a2030c9dbbc8cd0c738abea9769aa38b944c5aa14c3bbaef44'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_audit_request_from_context_v22#1::<ListComp>#1', 'proposal.model_dump', ('serialization',), '5bb2090e890c887b47e65b5532abef084c1631459eebbc6866dfbdcd42ee45d1'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_evidence_handles_v22#1::<ListComp>#1', '_source_ids_v22', (), '68113458e39736b25e2d0eca5ef5298f00dcb33a00f982a42a6851b417639ba6'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_evidence_handles_v22#1::<ListComp>#1', 'enumerate', (), '606ffd13a8a2676daac06f39299a52a967a3d2154b3263cb9a7984f5051540db'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_fragment_contract_v22#1', 'ValueError', (), 'c06130465293412e16c856e797a05151357d29bf57937cb16c66335db8dcfaef'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_fragment_contract_v22#1', 'ValueError', (), 'ef727fd179afca9b37e6cb5262860d814bd8e4be953101466ff337db623f0338'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_fragment_contract_v22#1', '_snapshot', (), '27a6f3df3a496af0dfac493e16137fcdccb79ab815a359e7e33efd1ecd5c8343'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_fragment_contract_v22#1', '_snapshot', (), 'd76efc81d942a551fa4f452486ecb0ed5e894bfb45cf3f773c6ba0efee8cc7c9'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_fragment_contract_v22#1', '_source_evidence_handles_v22', (), '7621ea84679db3412a598883ed460ea51f9050a5374d24239590e66a07c3080b'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_fragment_contract_v22#1', 'cast', (), '2dec00b6fe83dbac6a7de7265a43a00ae4d63481cbf7dec3a16f702ac8085e8c'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_fragment_contract_v22#1', 'cast', (), '6ef8d1db2715951b3f6f9b9ae6419af8d7b5b356189d647828f35d35ac3d7516'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_fragment_contract_v22#1', 'cast', (), '8a8e5dd5c51cb2b0f484330597ae2605afd20bc4b9795356ec4ea90b9ad2e809'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_fragment_contract_v22#1', 'cast', (), 'adef1aef3c1d5a5d87d7c051652e7d24b536a8e2c56f262e6a4876a20096990c'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_fragment_contract_v22#1', 'cast', (), 'b8af4e7fb89d3161434688487037bb616b3a5e1b2a038d69243b8b2fe3ddae8f'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_fragment_contract_v22#1', 'cast', (), 'bc0d17ea68fc2de603393f7c98860675779b73acf48acb5d8ebb47f2723be37d'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_fragment_contract_v22#1', 'json.dumps', (), 'c57b793003534ae25d2aa9c465af5ac10f937e85caf683f724cd2de872f0e908'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_ids_v22#1', 'cast', (), 'b0238bc3dd358e49314f84d4a589bf9249d2989e60bfeede11956027abd620c0'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_ids_v22#1::<ListComp>#1', 'cast', (), '91f503ec0195bb7311e2f8b1d757417aaca3d619fc2a8e17eb4adfc24eb45172'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_metadata#1', '_strict_rehydrate_v22', ('validation',), '29ac44f104aded749d8346944d67c14bad1c99f9128bbe03e541c98070de0364'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_review_request_from_context_v22#1', '_context_source_metadata_v22', (), '000bb9e20f3dec0d891fb01a6014ae12da01265d098dc1848c25640a19c49c12'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_review_request_from_context_v22#1', '_context_source_record_v22', (), 'c0c907a0792924045f7537d4547e442520f2dd2dcb3586bbab1a074d6c8996a3'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_review_request_from_context_v22#1', '_new_request_v22', (), '9b5a59434f4834a006459ac67b9b9316b7d3d59987d2de324ce217100c81b1a2'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_review_request_from_context_v22#1', '_source_evidence_handles_v22', (), 'f99766a0b131233dc10d40bbcaf9842d868e548c5ccbe611f4c74ea4609f2601'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_review_request_from_context_v22#1', '_source_fragment_contract_v22', (), 'a253bc2368819e44f16d2b1dab916cd9455ea25ec0f0fad93ea6d816e1515feb'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_review_request_from_context_v22#1', 'len', (), '961cd833429626ab99b43e3271e86725e8c332ec86c953c9ec4289582b5197fc'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_verified_source_request_context_v22#1', 'ValueError', (), '1abfe82589f3651e3c102a75b43a3b0c03d4a35a660d44e13e8091fac1dc1538'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_verified_source_request_context_v22#1', '_VerifiedSourceRequestContextV22', (), '00e27df0e33e84d463d5160d0e2759594fc230074f74705ff7b04426d3451a7f'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_verified_source_request_context_v22#1', '_snapshot', (), '07a1d9f06e500968c0af9dafbc24b151597e796ac485d7f7357b02a7ce938844'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_verified_source_request_context_v22#1', '_strict_rehydrate_v22', ('validation',), '41fe34ffcbbe0def0af7b27cc8c3cb853e54ef8b6e567a70f6f8fc71148fabcf'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_verified_source_request_context_v22#1', '_validate_envelope_binding', ('validation',), 'e61ff2a9d669d787bed260bf417d9325465f9bb7c48239bfbb82c0efbd9beafe'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_verified_source_request_context_v22#1', 'build_source_record', ('serialization',), '0041e109570e3d745742bf4c221060c29a543fb2d711c80f4e490e51a47dd863'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_verified_source_request_context_v22#1', 'canonical_json_bytes', ('serialization',), '51e47f138991c4a58eaacfad4085ab905f3ef549f0786a6b2f3ffb473893e425'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_verified_source_request_context_v22#1', 'sha256_digest', ('serialization',), '758a94ac0d21c4969373eb21d409aef43d52b049ebd5bdefb539814bffd667f2'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_contested_grade_request_v22#1', 'ValueError', (), '273229ed22f5a7263c12cf1f759726579bd92189efb02540edecb3efaa8d1461'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_contested_grade_request_v22#1', 'ValueError', (), '7f6ee32d291b929e7e48e96470857872b946e0ee75bca02e072cfa33e4cb16dc'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_contested_grade_request_v22#1', 'ValueError', (), 'ab5169323407b4b5be1040840b1204237536f35ee7e1e7ba20252d4f9e85475f'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_contested_grade_request_v22#1', '_ContestedGradeDraftV22.model_json_schema', ('serialization',), 'f5f1763c20db9cd65bb1913fff4e813e2b1fe046e1cf2854490468d66a981bcf'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_contested_grade_request_v22#1', '_grade_context', (), '24c924f11b5e3881185c07fc5bc0aa54770be3e459983f9f1f3f5c2c05086b16'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_contested_grade_request_v22#1', '_new_request_v22', (), 'c9dd66065aa492128c72a2259c28ce2c5de60ad8d63aafde7ccf0431df800c0c'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_contested_grade_request_v22#1', '_strict_grade_coordinate_v22', ('validation',), '554048269b0ad01a0b85cc94cfdfb8ac0fbcafd80e27b47ebc6944abe43186fa'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_contested_grade_request_v22#1', '_strict_rehydrate_v22', ('validation',), 'e5147569ac0c784bd0ba45bec90221c53e074d29905768470768737d0d6f34cc'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_contested_grade_request_v22#1', 'checked.model_dump', ('serialization',), '101b214b347f805da952f3312422b9d3aad9967a6a06fe820b3542ffcd2ecf53'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_contested_grade_request_v22#1', 'len', (), '20703c7fb188c222398a2e614da33c026de2d7ac98b5c9aba1102d5e4b43af0d'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_contested_grade_request_v22#1', 'sum', (), 'a8ce24402017c3a9fd0bc25a13ae3ca497fc0c23c37b571cf602b921b3423ddc'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_contested_grade_request_v22#1', 'verify_canonical_baseline_v22', ('validation',), '9ed7c93c75dffae1f44a8eb581a2d41d871474b7525ae39774e202a297a57c5b'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_ordinary_grade_request_v22#1', 'ValueError', (), '09f7520cab417722a07fa33f8098e87e3b9ce583fab279ba365170993bcdd00b'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_ordinary_grade_request_v22#1', 'ValueError', (), 'fda6d5a628bb73cc93b2eb7de2a0c6fc98315d2687395c49ebeb4038e0baf5b5'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_ordinary_grade_request_v22#1', '_grade_context', (), '49f3bf5a0048f8cb514c541056da40318499250a67bbb2c441d4739cf3400d83'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_ordinary_grade_request_v22#1', '_new_request_v22', (), '21cf483a1dd8741f5fe786d2acad017fa8c6af04659252a027cb29b39a1e4a3c'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_ordinary_grade_request_v22#1', '_ordinary_grade_request_contract_v22', (), '3cc505906965e513eff92d1e270b8a3726a48631bbe4731a2556cf9f14ebe99f'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_ordinary_grade_request_v22#1', '_strict_grade_coordinate_v22', ('validation',), 'e1f9a0fa8d30d5266aa655d26205d43db55f3e62c495585424d7b9fce6a252a3'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_ordinary_grade_request_v22#1', '_strict_rehydrate_v22', ('validation',), '706d4dd14c9ef444b9a323676af36c1515ccedb6506a5bf731b74ffac1dc1eb4'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_ordinary_grade_request_v22#1', 'len', (), 'e650610fd19ddde5e3c2932abf5927849333c46d15c39046bf2884015f8c6938'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_ordinary_grade_request_v22#1', 'ordinary_grade_batches_v22', ('validation',), 'a6aea86086fc31591af46c2ecdaf65278cbb004ed076b8707b3b751de575e86d'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_ordinary_grade_request_v22#1', 'requirement.model_dump', ('serialization',), 'c91b38281bfd1d2c7935f9ab76ca8efc5d936d5e6fbf0f365f9a11cc564b2b56'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_ordinary_grade_request_v22#1', 'verify_canonical_baseline_v22', ('validation',), '0262912df935c6a8102b43f9afc1e0617f13fd5a77fb9295ed54757d2de6cc8d'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_audit_fragment_request_v22#1', 'ValueError', (), 'a6de90c6293be61809fcac3d69bc83829c477fd8f36256f6ae3703d5a48844d3'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_audit_fragment_request_v22#1', 'ValueError', (), 'cb2a0ea5a7f52962db0fcd97e15e0e83ac44e80f99de0f38d39f1cc1522c3d5c'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_audit_fragment_request_v22#1', '_audit_history', ('validation',), '05954c39b35e9d9527f4c0c936de81d3bc7e1a54e942d762bc854e5d7ba8c883'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_audit_fragment_request_v22#1', '_source_audit_request_from_context_v22', (), '95fff105e79ed62e3e800ad17a8105289ef22a47f69253f63b3077ca0348fe67'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_audit_fragment_request_v22#1', '_strict_fragment_ordinal_v22', ('validation',), '485549735162ad9cc69e3a6ee26104f44572567ad6fd8263087bb15ab9114448'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_audit_fragment_request_v22#1', '_verified_source_request_context_v22', ('validation',), 'efa6051b6326c3e6ef6a6b8442f42799b3f12679c09299427d5558d6b6d988e3'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_audit_fragment_request_v22#1', '_verify_source_review_aggregate_with_context_v22', ('validation',), '631653a20538410e0c87be4502af44b2da5435039b9a59921ea20a92a3ffa114'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_audit_fragment_request_v22#1', 'len', (), 'a58d450d15afdca5a0e977f081d5fe43ace1065f6fcf502545ef8b27c6711214'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_audit_fragment_request_v22#1::<ListComp>#1', 'concern.model_dump', ('serialization',), 'cc5baca25a99f7c3da53fc264883ad8b7ca19e11fea3afbfe8d798c88365c08e'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_referee_fragment_request_v22#1', 'ValueError', (), '814df0de2db93fbd56a5c241d6d155d7f3a82005f4a27119f15023e0da894e34'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_referee_fragment_request_v22#1', 'ValueError', (), '963344b82fb65703bcfd4788cc4df9ac24a09b1dcf14eaeeb01aaf14fb8a4841'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_referee_fragment_request_v22#1', 'ValueError', (), 'e521eceaa719918dec1ec8056559a1ebb9cac70f2f89e0cd6b3208e278963ec8'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_referee_fragment_request_v22#1', '_RefereeDraftV22.model_json_schema', ('serialization',), '397dfdd8bfb36f1ad8462d9f23e805e84aa3a24270deb763c5d2c534c7f635e2'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_referee_fragment_request_v22#1', '_new_request_v22', (), '4cecf3f5c4f879f4eefd7f182586d8057326f3f450c13c2efce90961b55ca489'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_referee_fragment_request_v22#1', '_strict_rehydrate_v22', ('validation',), '148243882173ee9f67d81f04c0322f94a95b819771410e6dc5677c5ebb12c7b4'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_referee_fragment_request_v22#1', '_strict_rehydrate_v22', ('validation',), 'e99c4a2504acc20ed4e23839261836632decb9ba1ae3e06c890f77375b1148e2'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_referee_fragment_request_v22#1', 'any', (), '845b3f8a3400bc8a4f418376673bdf213976a7e4b45782a9bf1975e5c5631a57'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_referee_fragment_request_v22#1', 'canonical_referee_disputes_v22', ('validation',), 'd37d84639222d5fee8caa33d3263d03b703fd6562e7e6859061fb59efd61b893'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_referee_fragment_request_v22#1', 'checked.model_dump', ('serialization',), '56af9ec0552941e94c9fd66aac86350f8d5123ae207df0e1ad362a3f71d0ea76'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_referee_fragment_request_v22#1', 'len', (), 'c56c4c00f1f914e825dba5a10cba93c7c89b7df856d5fd9ad537ae8ab4b99fec'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_referee_fragment_request_v22#1', 'sum', (), '18670510fbdd368c172ee5a0377458b1af8b29fc15e9a49a574502856ae4527a'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_referee_fragment_request_v22#1', 'tuple', (), '66d837047de6f00fd0cd200f7148ddb055b41c38c35193a6118365cace732d31'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_referee_fragment_request_v22#1', 'tuple', (), '6da8c0229185b76a48ae78f75e1e84ce5f238dde38f44701b40b98caff989e83'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_referee_fragment_request_v22#1::<GeneratorExp>#1', '_strict_rehydrate_v22', ('validation',), 'a37b4d2eef3fb3997507fa172f4f46f56788ce321bcff72d80e4562a62de4248'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_referee_fragment_request_v22#1::<ListComp>#2', 'len', (), '4d3451d6d88f39ea26ee2b91b632da4428f93c4cd86a236e7e2a64b8088017a4'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_referee_fragment_request_v22#1::<ListComp>#2', 'range', (), '3764d65b012e7940eff617190a2d91d88a62a7e684185eb6edeab436cb4addc8'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_review_fragment_request_v22#1', 'ValueError', (), '1baf84d8e44b48289dd2de262662bd8354f97b381230dbd1c493553e09ef2b16'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_review_fragment_request_v22#1', '_review_history', ('validation',), '3ce46b9416a83e51aaa326b6e2956bb715e2716a36da6fb5a31deb2da8deea37'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_review_fragment_request_v22#1', '_source_review_request_from_context_v22', (), '3f7d0b98ebf019a72a529c06dfc59bf1be98a970b6806e91ac2e71e21bfe2585'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_review_fragment_request_v22#1', '_strict_fragment_ordinal_v22', ('validation',), '1a244760479dc892f65fce49cd4c138e73bbe7eee70cf4dee4f7c571f51b0133'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_review_fragment_request_v22#1', '_verified_source_request_context_v22', ('validation',), 'd9cd7d059843997bdafab2ab3f189740ea81dd011f70b94fcf73da7a32943c51'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_review_fragment_request_v22#1', 'len', (), 'f483982d5f09625fe99b89e62c73447354365cf57f59827cd84ecefdb74942e0'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_review_fragment_request_v22#1::<ListComp>#1', 'proposal.model_dump', ('serialization',), 'ee634c56b15c8e681ca01e166590edc2a5bbde40b1da6cbf6d2edf4050ce8703'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::compiler_contract_fingerprint_v22#1', 'canonical_json_bytes', ('serialization',), '71ff8676978679e40d2fa3901189c1ee7d74cd9b1e0344dbddc735172fc07763'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::compiler_contract_fingerprint_v22#1', 'sha256_digest', ('serialization',), '297b2fd1532e153973dec719af51c8b5441736b1019a6a9f4b8c2aee9ffc3f7e'): 1,  # noqa: E501
    }
)

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
        ('attorney_v22_requests.py', '<module>#1::_grade_context#1', '<module>#1::_grade_context#1', 'from', 1, 'attorney_v22_compiler', '_strict_rubric', '_strict_rubric', ('validation',), '6492cdd8959a23a4ca22fa57977e9f406de081f3debf4dc76784d8d2583d4787'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_contested_grade_request_v22#1', '<module>#1::build_contested_grade_request_v22#1', 'from', 1, 'attorney_v22_compiler', 'RUBRIC_V22', 'RUBRIC_V22', (), '67b8fcc39ecffe3bc82902ba3087857e46a72fb318153974e708299d90201578'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_contested_grade_request_v22#1', '<module>#1::build_contested_grade_request_v22#1', 'from', 1, 'attorney_v22_compiler', 'verify_canonical_baseline_v22', 'verify_canonical_baseline_v22', ('validation',), 'd73bd77f614ce36e1b3fe03f01b7ae2e949376a9b0888aad6b885dba67f61e50'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_ordinary_grade_request_v22#1', '<module>#1::build_ordinary_grade_request_v22#1', 'from', 1, 'attorney_v22_compiler', 'RUBRIC_V22', 'RUBRIC_V22', (), '332bcc7b198ea1d3092ac1cd5d589f9e6d88b6a1eab893ac13b55661e8e5eb19'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_ordinary_grade_request_v22#1', '<module>#1::build_ordinary_grade_request_v22#1', 'from', 1, 'attorney_v22_compiler', 'ordinary_grade_batches_v22', 'ordinary_grade_batches_v22', ('validation',), 'f2dba2d70981d58d018c7e7f177af12b90a54cdcbb03b9b3646b11a714c4b6ca'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_ordinary_grade_request_v22#1', '<module>#1::build_ordinary_grade_request_v22#1', 'from', 1, 'attorney_v22_compiler', 'verify_canonical_baseline_v22', 'verify_canonical_baseline_v22', ('validation',), '597155543d6e77407cdc535c9e583c31add4cde578139021a1dceee2b4ffdba3'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_audit_fragment_request_v22#1', '<module>#1::build_source_audit_fragment_request_v22#1', 'from', 1, 'attorney_v22_compiler', '_verify_source_review_aggregate_with_context_v22', '_verify_source_review_aggregate_with_context_v22', ('validation',), '94f54bf1899940ee12ca685a2b12c6573823f5fa85585544070bd850694d8192'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_referee_fragment_request_v22#1', '<module>#1::build_source_referee_fragment_request_v22#1', 'from', 1, 'attorney_v22_compiler', 'canonical_referee_disputes_v22', 'canonical_referee_disputes_v22', ('validation',), 'e41e82d57b14f46b18327f81411712c49c1b99771a0166ceb6b1f16f371ab248'): 1,  # noqa: E501
    }
)

_EXPECTED_TASK3_DEFINITIONS: Counter[_Task3Definition] = Counter(
    {
        ('attorney_v22_compiler.py', '<module>#1::_SourceFragmentSemanticResponseErrorV22#1', 'ClassDef', 'bd1e064ac1f92b7d4af4ee10b85af6dd7dc85839d6ca03da8888d605a558c314'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_audit_fragments#1', 'FunctionDef', 'e5f1d099f18147418487a83dabc766ed40298b6c2919b2e9f097474ec1f677db'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_canonical_baseline_fingerprint_from_validated_v22#1', 'FunctionDef', '5b0f0ae15ad396d9fa9719ec565f83062d218c645122b54420ab73df4c4e042c'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_canonical_dispute_passages_v22#1', 'FunctionDef', '00ef01d69e0ae9b1886f9c00abd5ddd9a53f2e071eb7854352e36dfc9e03c114'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_hash#1', 'FunctionDef', '4b6fcca82acc80e67a4a48044aa2ee9056db2afc1df3e98b87d522a563bd6c01'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_merge_grader_outcomes_v22#1', 'FunctionDef', 'f8cb1ac5378940500194ae724deade5889a34f797e9a271244f852f4c873ac09'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_ordinary_observations_v22#1', 'FunctionDef', 'a7b039f7d132adcc118f11c290b7df889835546a90c5c5536412f2ccd6bc082b'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_referee_dispute_fingerprint_from_validated_v22#1', 'FunctionDef', 'f45f2f6cda88727156a10a6622e75d7b7428140a6cea892ebfce09e5a1524417'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_referee_disputes_from_verified_sources_v22#1', 'FunctionDef', '893d52005cc41c985cacba3f4bb208b589bbe4ad448e707c6b377736df61ea93'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_review_fragments#1', 'FunctionDef', 'fca8ce283eab4f978d704a64dca96d4921f745ae7fb861c2cec2aa9e83c18df8'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_score_v22#1', 'FunctionDef', 'a26bebe44a85e45b5587c00d5d490582ef266bbcd8ddfab7acdf9407d402c48a'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_semantic_identity#1', 'FunctionDef', 'd95544c0c85396205078552479f9c42f0f5bc9f555baf529fe53b94840d6d6c2'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_strict_rubric#1', 'FunctionDef', '7d92124be2006f1758b63b8643a558da1fad25eedc317fba1c4eaccfd17765f2'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_v21_inputs#1', 'FunctionDef', '6a62ca05e75e2bfce22c305987ad65e799c6a0769c416006f30cd2acecdf50a0'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::_validate_source_fragment_semantics_v22#1', 'FunctionDef', 'b033545c021132b56628d7721fa6f1f74c09eb371263d0bd8216b07eac185952'): 1,  # noqa: E501
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
        ('attorney_v22_compiler.py', '<module>#1::evaluate_outcome_sensitivity_v22#1', 'FunctionDef', 'b4e921b5b84d59c6e2bc69ac3f1d3b220bcb6a4c0030e9ff41bfc05e11945da2'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::evaluate_outcome_sensitivity_v22#1::lane_outcome#1', 'FunctionDef', 'e431e25c6fb6f50a1b22c96213218104c460aad0e39a2028624afd8ed6e426d0'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::ordinary_grade_batches_v22#1', 'FunctionDef', 'cf09d956de18974492485632c53fb3a6e208a0f268255f00f165e90d45f54246'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::reconcile_grader_lanes_v22#1', 'FunctionDef', 'a910e37bb34a8c1b19f9591fd994d1fc1181667eabd9a22bcfb18db34fea5312'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::referee_dispute_fingerprint_v22#1', 'FunctionDef', '0e9554dff934846b8270466c2889d1565160b41490a7fbf58daa21ff8920a747'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::validate_grade_fragment_v22#1', 'FunctionDef', 'ccaad64028709671383d18c53acdb5152620ba3f2168614818ac4f1c59b6556d'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::validate_referee_fragment_v22#1', 'FunctionDef', '223557feaebbd5f58daa959e94eb4b3a04797502995356695e7bb913445cd0d6'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::verify_canonical_baseline_v22#1', 'FunctionDef', '6328fa58c00cfbb3a58b37806b085d9b8c5596d52e5e817646c39dcd6e91391d'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::verify_source_audit_aggregate_v22#1', 'FunctionDef', '3c25ba0bf134c2436ba7c7841d3fd4ae1380f5606d789e2b2774ec67707bfa38'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::verify_source_review_aggregate_v22#1', 'FunctionDef', '017a2acc5b4803a5dd83df6655bc0bec6c2783eaa3129ad3d4cf4b34bf043494'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_VerifiedSourceRequestContextV22#1', 'ClassDef', 'cd318010b520978504fc26ba900e333f38f6c51bc2d0ffc662dff8135c7329d9'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_audit_history#1', 'FunctionDef', 'd03ef9cc51d82a2c9fd519f0210aec73df6a274dde6176bffede4ef66a48c8fc'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_context_source_metadata_v22#1', 'FunctionDef', 'd0808dd3fd003d690bb648fc7a420994a2c9e286488defedbd674ad957b0db0f'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_context_source_record_v22#1', 'FunctionDef', 'ddec2709b6099a4c0960b2a7ed9f20e640a0aeef6c18f66e6307d9b7814bd4ce'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_fingerprint#1', 'FunctionDef', 'af6e11e9bc80a9dfacc731cc3bade75d0c9348d8e2c32598e5a9b6f3b9486c87'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_frozen_source_record_v22#1', 'FunctionDef', 'e7992e017ee3c89b5c2a604fa77198f618496b4d295fdaef6cc346414744086e'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_grade_context#1', 'FunctionDef', 'f2e0adca1f9d11bba55953c9b8e2a9aeaf7836aacd9b02ff2a42e0c27a65fa17'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_new_request_v22#1', 'FunctionDef', '632be9b84ced1b426b0d62568e6f3a39e061f0f6a87def02615e7b15b5164db4'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_ordinary_grade_request_contract_v22#1', 'FunctionDef', '71fb1e0bd3d8df50952f15ce4b23ad95f63308d8660c4c8eeda22da38d6b03b0'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_review_history#1', 'FunctionDef', 'e3c15681f9e8e3337c2c405ea3014f0ae3311250e22d6318bd38ffe892b40991'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_schema_hash#1', 'FunctionDef', 'c932f7e13c22efd442e19de25b98b0232071a4e8323a4ab5b7c1b7eaa999992e'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_snapshot#1', 'FunctionDef', 'cc20796a843493c9e7a8a58e8d37207aeda12a214402e03abb60a061f5849b47'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_audit_request_from_context_v22#1', 'FunctionDef', '29a0e4723100922b54e3f4a10c233ae7df163c6309752a19baa6adf46786af51'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_evidence_handles_v22#1', 'FunctionDef', '00adcd67caaebe926675ebd9dc533d4ad00cfa55b63f094d31524e6d462dbf1c'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_fragment_contract_v22#1', 'FunctionDef', 'fc5b63a5d4a9bb0f13d26348100367c4850412939d21ba95bd5a99a4a163f3f7'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_ids_v22#1', 'FunctionDef', 'a4476935ff5d44c608784580d846a0838472b831e90a574175ce2c7a30333049'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_metadata#1', 'FunctionDef', 'e10b408bbf1e64a1f521435adde0e86a886e18f2ee8b228eb65a5108082754ba'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_review_request_from_context_v22#1', 'FunctionDef', '5e67febc66d85782304097a586af686cbd76c7ca04fe08b30abb4e927087729b'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_verified_source_request_context_v22#1', 'FunctionDef', '2c0d4470bb0f335f6239f5fdc7eb458a442c8c6fdfd2e17c73836e8f2ef02a0a'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_contested_grade_request_v22#1', 'FunctionDef', '0346fe5799b1d895cc0cd170242c9ccb0a01baedadd678c347b990be471f1bf2'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_ordinary_grade_request_v22#1', 'FunctionDef', 'c39681ede1aa76efa62889823f90b29139a4b3f934ffdedf5e4e304ec1b695fa'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_audit_fragment_request_v22#1', 'FunctionDef', 'e792a19ed7dd3b1fa7c260f71492f62c8040ee48d24c18aa88bb4f3eb8b6b4e7'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_referee_fragment_request_v22#1', 'FunctionDef', '49f8abae91ebc89b9824364c8a680260260b92609f5b2d52392a76e6a58bf45a'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::build_source_review_fragment_request_v22#1', 'FunctionDef', 'd850afa7fd7c68fe9e6d25b08a0b706b2c9f32704f851b686be8700c0c9a5699'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::compiler_contract_fingerprint_v22#1', 'FunctionDef', '704c30f2144193d6c20588578c162572ae198b92e8d5add500cedfb523086de7'): 1,  # noqa: E501
    }
)

_EXPECTED_TASK3_SIMPLE_SUBSCRIPTS: Counter[_Task3SimpleSubscript] = Counter(
    {
        ('attorney_v22_compiler.py', '<module>#1::_validate_source_fragment_semantics_v22#1', 'seen[identity]', 'ba2c007cfac95b5fa50f061f0d07de57250ae8a886baa2f969a6d5a20342a7ab'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::compile_baseline_v22#1', "raw['baseline_fingerprint']", '38b1bd120992fb28903caa492553d5e0cf7283fd8f565d5420b7b6d7576e31c0'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::compile_baseline_v22#1', "raw['contested_requirements']", '285e030754de51abc7a0f150c0cf2b41e4d68f753c7bf7eee6a2c587ec62c182'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::compile_baseline_v22#1', "raw['schema_version']", '1f0c0a82880ee59817f3585ca7ca5b5b7a5cabdf53cf592bb16f4cb403eb4c66'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::evaluate_outcome_sensitivity_v22#1', "raw['sensitivity_fingerprint']", '0fba8d14593fd33cc0bc29de76b621c7fe8a82af6d68d82ac5161b8941909176'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::reconcile_grader_lanes_v22#1', "raw['reconciliation_fingerprint']", '863412839320dbc119420a83a47a515d043e0885de24b9f18c8de6d7ab2de658'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::validate_referee_fragment_v22#1', "legacy_decision['schema_version']", '0ca3dcc0bcfb06380da614c154e89f7f7c7f36eba9d403d4cfac891ab5cbaad1'): 1,  # noqa: E501
        ('attorney_v22_compiler.py', '<module>#1::validate_referee_fragment_v22#1', "legacy_raw['dispute_fingerprint']", '48dc852b025e2ebdc12063841fe4b8091ebfa0a992aec5060786932aa9c264ef'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_new_request_v22#1', "raw['request_fingerprint']", 'adbebcda570dc58e435978ce7f2df10eab9e4bdb10e865070d87e07755380439'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_ordinary_grade_request_contract_v22#1', "grades['maxItems']", '6de3e0c13b4b8ae3770ea14a0e61b390c827ec849e273f241e3ee0b811f5638c'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_ordinary_grade_request_contract_v22#1', "grades['minItems']", '30ad16da686b3288152b34a5dc6ad43d9b8f54c02d8dd90e78016aa663f94a8b'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_ordinary_grade_request_contract_v22#1', "ordinal['enum']", '41faf50853e4343c0bf1af86febc0d7f8d30ee45a8ff88602fff3b9e5c228ea4'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_fragment_contract_v22#1', "concern['target_proposal_ordinal']", '1dc1797ff3c7b05ffd85e638404752b544604c605044c18dd55ff1444ea8812b'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_fragment_contract_v22#1', "concern_passages['items']", 'f407916e4dd16125e748ed483e674ffeacd970e761dc2ee3969d65a9949e801e'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_fragment_contract_v22#1', "dependency_target_schema['maximum']", 'f348afb34944a9997679b45cf701b61e62699507adeac326296020710bf8ca42'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_fragment_contract_v22#1', "handle_field['enum']", 'b99f66e4488c421193a2ccbcbd62de4d08f3b0631c5a944d10968824463f0ec5'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_fragment_contract_v22#1', "proposal['dependency']", '35185630ef25fc8c26666a7c0c9b833bc98898cb062f2ade2782367b40e50bef'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_fragment_contract_v22#1', "proposal_passages['items']", '18c3a102fb838a8de7e10f48117885c8f8b0f7b575940918018a3b4912442ea9'): 1,  # noqa: E501
        ('attorney_v22_requests.py', '<module>#1::_source_fragment_contract_v22#1', "target['maximum']", '07f0cd997e4aaea2684f8786b7027dea9d0d41659f860201b5aa3d65ff1d7786'): 1,  # noqa: E501
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
    assert sum(observed.calls.values()) == 532
    assert sum(observed.imports.values()) == 93
    assert sum(observed.definitions.values()) == 63
    assert sum(observed.simple_subscripts.values()) == 19
    assert not observed.prohibited


def test_task3_structural_digests_do_not_rewrite_string_literal_contents() -> None:
    empty = _scan_task3_source_policy('helper("")\n', "synthetic.py")
    field_syntax = _scan_task3_source_policy('helper("field=[]")\n', "synthetic.py")

    assert empty.calls != field_syntax.calls


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
            "_ordinary_grade_request_contract_v22",
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
