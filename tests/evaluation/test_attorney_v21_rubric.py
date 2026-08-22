# ruff: noqa: E501
"""Behavioral tests for bounded protocol-2.1 grading."""

from __future__ import annotations

import hashlib

import pytest

from regulatory_harvest.evaluation.attorney_v21_models import (
    CanonicalBaselineV21,
    ContestedRequirementV21,
)
from regulatory_harvest.evaluation.attorney_v21_rubric import (
    RUBRIC_V21,
    RubricValidationError,
    _reconciliation_fingerprint,
    aggregate_grader_lane,
    evaluate_outcome_sensitivity,
    ordinary_grade_batches,
    reconcile_grader_lanes,
    validate_grade_fragment_v21,
)

REPORT = "\n".join(f"The report covers requirement {index}." for index in range(1, 13))


def _requirement(index: int, *, importance: str = "material") -> dict[str, object]:
    return {
        "requirement_id": f"REQ-{index:04d}",
        "canonical_order": index - 1,
        "statement": f"Requirement {index} applies.",
        "kind": "obligation",
        "importance": importance,
        "passages": [
            {"source_id": "rule-1", "quote": "requirement", "start_char": 0, "end_char": 11}
        ],
        "dependency": None,
        "confidence": "clear",
        "rationale": "The source is explicit.",
    }


def baseline_with_requirements(count: int, *, importance: str = "material") -> CanonicalBaselineV21:
    return CanonicalBaselineV21(
        schema_version="2.1",
        case_fingerprint="a" * 64,
        requirements=[_requirement(index, importance=importance) for index in range(1, count + 1)],
        baseline_fingerprint="b" * 64,
    )


def baseline_with_contested(count: int) -> CanonicalBaselineV21:
    return CanonicalBaselineV21(
        schema_version="2.1",
        case_fingerprint="a" * 64,
        requirements=[_requirement(1, importance="critical")],
        contested_requirements=[
            ContestedRequirementV21(
                contested_requirement_id=f"CONT-{index:04d}",
                reviewer_alternative=_requirement(index + 1),
                auditor_alternative=_requirement(index + 1),
                unresolved_reason="SOURCE_GAP",
                rationale="The source dispute remains unresolved.",
                referee_fragment_fingerprint=f"{index:064x}",
            )
            for index in range(1, count + 1)
        ],
        baseline_fingerprint="b" * 64,
    )


def _report_fingerprint() -> str:
    return hashlib.sha256(REPORT.encode("utf-8")).hexdigest()


def _ordinary_fragment(
    baseline: CanonicalBaselineV21, batch_ref: str, ids: tuple[str, ...], lane: int, *, disposition: str = "met"
) -> dict[str, object]:
    return {
        "schema_version": "2.1",
        "anonymous_label": "A",
        "grader_lane": lane,
        "batch_ref": batch_ref,
        "baseline_fingerprint": baseline.baseline_fingerprint,
        "report_fingerprint": _report_fingerprint(),
        "requirement_grades": [
            {
                "requirement_id": requirement_id,
                "disposition": disposition,
                "report_passages": [f"The report covers requirement {int(requirement_id[-4:])}."],
                "rationale": "The report addresses this requirement.",
            }
            for requirement_id in ids
        ],
        "rationale": "The batch is fully graded.",
    }


def _contested_fragment(
    baseline: CanonicalBaselineV21, contested_id: str, lane: int, *, auditor: str = "met"
) -> dict[str, object]:
    return {
        "schema_version": "2.1",
        "anonymous_label": "A",
        "grader_lane": lane,
        "contested_requirement_id": contested_id,
        "baseline_fingerprint": baseline.baseline_fingerprint,
        "report_fingerprint": _report_fingerprint(),
        "reviewer_alternative_grade": {
            "disposition": auditor if auditor == "uncertain" else "met",
            "report_passages": [] if auditor == "uncertain" else ["The report covers requirement 1."],
            "rationale": "The reviewer alternative is met.",
        },
        "auditor_alternative_grade": {
            "disposition": auditor,
            "report_passages": ["The report covers requirement 1."] if auditor != "uncertain" else [],
            "rationale": "The auditor alternative was assessed.",
        },
        "ambiguity_disposition": "acknowledged",
        "rationale": "The disputed source issue is acknowledged.",
    }


def _aggregate(
    baseline: CanonicalBaselineV21, lane: int, *, contested_auditor: str = "met", ordinary: str = "met"
):
    batches = ordinary_grade_batches(baseline, "A", lane)
    ordinary_fragments = tuple(
        validate_grade_fragment_v21(
            baseline,
            _ordinary_fragment(baseline, batch.batch_ref, batch.requirement_ids, lane, disposition=ordinary),
            REPORT,
        )
        for batch in batches
    )
    contested_fragments = tuple(
        validate_grade_fragment_v21(
            baseline,
            _contested_fragment(baseline, item.contested_requirement_id, lane, auditor=contested_auditor),
            REPORT,
        )
        for item in baseline.contested_requirements
    )
    return aggregate_grader_lane(baseline, "A", lane, ordinary_fragments, contested_fragments)


def test_ordinary_batches_are_stable_and_never_exceed_five() -> None:
    batches = ordinary_grade_batches(baseline_with_requirements(12), "A", 1)

    assert [len(batch.requirement_ids) for batch in batches] == [5, 5, 2]
    assert [batch.batch_ref for batch in batches] == ["GB-A-1-0001", "GB-A-1-0002", "GB-A-1-0003"]


def test_grade_fragment_requires_exact_report_passages_and_the_bound_lane() -> None:
    baseline = baseline_with_requirements(1)
    batch = ordinary_grade_batches(baseline, "A", 1)[0]
    payload = _ordinary_fragment(baseline, batch.batch_ref, batch.requirement_ids, 1)

    accepted = validate_grade_fragment_v21(baseline, payload, REPORT)
    assert accepted.batch_ref == "GB-A-1-0001"

    with pytest.raises(RubricValidationError, match="GRADE_REPORT_PASSAGE_AMBIGUOUS"):
        validate_grade_fragment_v21(
            baseline,
            {**payload, "requirement_grades": [{**payload["requirement_grades"][0], "report_passages": ["report"]}]},  # type: ignore[index]
            REPORT,
        )


def test_aggregate_requires_complete_batch_and_contested_coverage() -> None:
    baseline = baseline_with_contested(1)
    with pytest.raises(RubricValidationError, match="GRADE_FRAGMENT_COVERAGE_INVALID"):
        aggregate_grader_lane(baseline, "A", 1, (), ())


def test_reconciliation_requires_two_isolated_lanes_and_preserves_stable_pass() -> None:
    baseline = baseline_with_requirements(1)
    first = _aggregate(baseline, 1)
    second = _aggregate(baseline, 2)

    reconciliation = reconcile_grader_lanes(baseline, first, second, RUBRIC_V21)

    assert reconciliation.absolute_disposition == "PASS"
    assert reconciliation.reason_codes == ()


def test_reconciliation_preserves_stable_fail() -> None:
    baseline = baseline_with_requirements(1)
    reconciliation = reconcile_grader_lanes(
        baseline, _aggregate(baseline, 1, ordinary="not_met"), _aggregate(baseline, 2, ordinary="not_met"), RUBRIC_V21
    )

    assert reconciliation.absolute_disposition == "FAIL"
    assert "WEIGHTED_COVERAGE_BELOW_FLOOR" in reconciliation.reason_codes


def test_outcome_sensitivity_is_inconclusive_when_an_alternative_changes_result() -> None:
    baseline = baseline_with_contested(1)
    reconciliation = reconcile_grader_lanes(
        baseline, _aggregate(baseline, 1, contested_auditor="not_met"), _aggregate(baseline, 2, contested_auditor="not_met"), RUBRIC_V21
    )

    record = evaluate_outcome_sensitivity(baseline, reconciliation, RUBRIC_V21)

    assert record.absolute_disposition == "INCONCLUSIVE"
    assert record.reason_codes == ("OUTCOME_SENSITIVE_BASELINE_DISPUTE",)
    assert record.outcome_determinative_contested_ids == ("CONT-0001",)


def test_outcome_sensitivity_is_inconclusive_when_neither_branch_is_meaningfully_gradable() -> None:
    baseline = baseline_with_contested(1)
    reconciliation = reconcile_grader_lanes(
        baseline, _aggregate(baseline, 1, contested_auditor="uncertain"), _aggregate(baseline, 2, contested_auditor="uncertain"), RUBRIC_V21
    )

    record = evaluate_outcome_sensitivity(baseline, reconciliation, RUBRIC_V21)

    assert record.absolute_disposition == "INCONCLUSIVE"
    assert record.reason_codes == ("BASELINE_EVIDENCE_INSUFFICIENT",)


def test_outcome_sensitivity_ignores_raw_unresolved_count() -> None:
    baseline = baseline_with_contested(10)
    reconciliation = reconcile_grader_lanes(baseline, _aggregate(baseline, 1), _aggregate(baseline, 2), RUBRIC_V21)

    record = evaluate_outcome_sensitivity(baseline, reconciliation, RUBRIC_V21)

    assert record.absolute_disposition == "PASS"
    assert record.outcome_determinative_contested_ids == ()


def test_reconciliation_rejects_forged_fingerprint_and_swapped_lanes() -> None:
    baseline = baseline_with_requirements(1)
    first = _aggregate(baseline, 1)
    second = _aggregate(baseline, 2)
    forged = first.model_construct(**{**first.__dict__, "aggregate_fingerprint": "0" * 64})

    with pytest.raises(RubricValidationError, match="RECONCILIATION_INVALID"):
        reconcile_grader_lanes(baseline, forged, second, RUBRIC_V21)
    with pytest.raises(RubricValidationError, match="RECONCILIATION_INVALID"):
        reconcile_grader_lanes(baseline, second, first, RUBRIC_V21)


def test_sensitivity_rejects_reconciliation_for_another_baseline() -> None:
    baseline = baseline_with_requirements(1)
    reconciliation = reconcile_grader_lanes(baseline, _aggregate(baseline, 1), _aggregate(baseline, 2))
    other = baseline.model_copy(update={"baseline_fingerprint": "c" * 64})

    with pytest.raises(RubricValidationError, match="RECONCILIATION_INVALID"):
        evaluate_outcome_sensitivity(other, reconciliation)


def test_sensitivity_rejects_nested_aggregate_forgery_with_resealed_outer_hash() -> None:
    baseline = baseline_with_requirements(1)
    reconciliation = reconcile_grader_lanes(baseline, _aggregate(baseline, 1), _aggregate(baseline, 2))
    forged_aggregate = reconciliation.grader_aggregates[0].model_construct(
        **{**reconciliation.grader_aggregates[0].__dict__, "aggregate_fingerprint": "0" * 64}
    )
    forged = reconciliation.model_construct(
        **{**reconciliation.__dict__, "grader_aggregates": (forged_aggregate, reconciliation.grader_aggregates[1])}
    )
    resealed = forged.model_construct(
        **{**forged.__dict__, "reconciliation_fingerprint": _reconciliation_fingerprint(forged)}
    )

    with pytest.raises(RubricValidationError, match="RECONCILIATION_INVALID"):
        evaluate_outcome_sensitivity(baseline, resealed)


def test_sensitivity_rejects_raw_nested_aggregate_forgery_with_resealed_outer_hash() -> None:
    baseline = baseline_with_requirements(1)
    reconciliation = reconcile_grader_lanes(baseline, _aggregate(baseline, 1), _aggregate(baseline, 2))
    raw = reconciliation.model_dump(mode="json")
    raw["grader_aggregates"][0]["aggregate_fingerprint"] = "0" * 64  # type: ignore[index]
    typed = type(reconciliation).validate_for_inventories(
        raw, ordinary_grade_batches(baseline, "A", 1), baseline.contested_requirements
    )
    resealed = typed.model_construct(
        **{**typed.__dict__, "reconciliation_fingerprint": _reconciliation_fingerprint(typed)}
    )

    with pytest.raises(RubricValidationError, match="RECONCILIATION_INVALID"):
        evaluate_outcome_sensitivity(baseline, resealed)


def test_sensitivity_rejects_typed_nested_aggregate_forgery_with_resealed_outer_hash() -> None:
    baseline = baseline_with_requirements(1)
    reconciliation = reconcile_grader_lanes(baseline, _aggregate(baseline, 1), _aggregate(baseline, 2))
    forged_aggregate = reconciliation.grader_aggregates[0].model_copy(
        update={"aggregate_fingerprint": "0" * 64}
    )
    typed = reconciliation.model_copy(
        update={"grader_aggregates": (forged_aggregate, reconciliation.grader_aggregates[1])}
    )
    resealed = typed.model_copy(
        update={"reconciliation_fingerprint": _reconciliation_fingerprint(typed)}
    )

    with pytest.raises(RubricValidationError, match="RECONCILIATION_INVALID"):
        evaluate_outcome_sensitivity(baseline, resealed)


def test_critical_recall_uses_partial_credit_and_the_rubric_floor() -> None:
    baseline = baseline_with_requirements(1, importance="critical")
    rubric = RUBRIC_V21.model_copy(update={"critical_recall_floor": 0.5, "weighted_coverage_floor": 0.5})
    reconciliation = reconcile_grader_lanes(
        baseline, _aggregate(baseline, 1, ordinary="partially_met"), _aggregate(baseline, 2, ordinary="partially_met"), rubric
    )

    assert reconciliation.absolute_disposition == "PASS"
