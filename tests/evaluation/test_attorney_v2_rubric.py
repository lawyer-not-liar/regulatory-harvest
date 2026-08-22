"""Behavioral tests for the protocol-2.0 deterministic grading rubric."""

from __future__ import annotations

import pytest

from regulatory_harvest.evaluation.attorney_v2_models import (
    AbsoluteDispositionV2,
    CanonicalBaselineV2,
    CanonicalRequirementV2,
    ComparisonDispositionV2,
    GradeResponseV2,
    ImportanceV2,
    ReportResultV2,
    ResolvedPassageV2,
)
from regulatory_harvest.evaluation.attorney_v2_rubric import (
    RUBRIC_V2,
    RubricValidationError,
    compare_report_results,
    reconcile_grades,
    score_report,
    validate_grade_response,
)

REPORT = """The operator must file a notice by Friday.
The operator must retain the notice for five years.
"""


def baseline(*, unresolved: list[str] | None = None) -> CanonicalBaselineV2:
    return CanonicalBaselineV2(
        case_fingerprint="a" * 64,
        requirements=[
            CanonicalRequirementV2(
                requirement_id="REQ-0001",
                canonical_order=0,
                statement="File a notice by Friday.",
                kind="obligation",
                importance="critical",
                passages=[
                    ResolvedPassageV2(
                        source_id="rule-1",
                        quote="must file a notice",
                        start_char=0,
                        end_char=18,
                    )
                ],
                confidence="clear",
                rationale="The source uses mandatory language.",
            ),
            CanonicalRequirementV2(
                requirement_id="REQ-0002",
                canonical_order=1,
                statement="Retain the notice for five years.",
                kind="obligation",
                importance="material",
                passages=[
                    ResolvedPassageV2(
                        source_id="rule-1",
                        quote="must retain the notice",
                        start_char=20,
                        end_char=42,
                    )
                ],
                confidence="clear",
                rationale="The source uses mandatory language.",
            ),
        ],
        unresolved_dispute_ids=unresolved or [],
        baseline_fingerprint="b" * 64,
    )


def grade_payload(
    *,
    label: str = "A",
    first: str = "met",
    second: str = "met",
    first_passages: list[str] | None = None,
    second_passages: list[str] | None = None,
    unsupported: list[dict[str, str]] | None = None,
    baseline_defect: str | None = None,
    baseline_fingerprint: str = "b" * 64,
) -> dict[str, object]:
    return {
        "schema_version": "2.0",
        "anonymous_label": label,
        "baseline_fingerprint": baseline_fingerprint,
        "requirement_grades": [
            {
                "requirement_id": "REQ-0001",
                "disposition": first,
                "report_passages": first_passages or ["must file a notice by Friday"],
                "rationale": "The report states the filing duty.",
            },
            {
                "requirement_id": "REQ-0002",
                "disposition": second,
                "report_passages": second_passages or ["must retain the notice for five years"],
                "rationale": "The report states the retention duty.",
            },
        ],
        "unsupported_assertions": unsupported or [],
        "baseline_defect": baseline_defect,
    }


def grade(
    *, reference_baseline: CanonicalBaselineV2 | None = None, **updates: object
) -> GradeResponseV2:
    target = reference_baseline or baseline()
    updates.setdefault("baseline_fingerprint", target.baseline_fingerprint)
    return GradeResponseV2.validate_for_baseline(grade_payload(**updates), target)


def test_validate_grade_response_requires_every_known_requirement_once() -> None:
    payload = grade_payload()
    payload["requirement_grades"] = payload["requirement_grades"][:1]  # type: ignore[index]
    bypass = GradeResponseV2.model_construct(**payload)

    with pytest.raises(RubricValidationError, match="GRADE_REQUIREMENTS_INVALID"):
        validate_grade_response(baseline(), bypass, REPORT)


@pytest.mark.parametrize(
    ("passage", "expected"),
    [
        ("does not occur", "REPORT_PASSAGE_NOT_FOUND"),
        ("notice", "REPORT_PASSAGE_AMBIGUOUS"),
    ],
)
def test_validate_grade_response_requires_unique_exact_report_passages(
    passage: str, expected: str
) -> None:
    with pytest.raises(RubricValidationError, match=expected):
        validate_grade_response(baseline(), grade(first_passages=[passage]), REPORT)


def test_validate_grade_response_rejects_unknown_and_duplicate_requirement_ids() -> None:
    payload = grade_payload()
    payload["requirement_grades"] = [
        {
            "requirement_id": "REQ-0001",
            "disposition": "met",
            "report_passages": ["must file a notice by Friday"],
            "rationale": "The report states the filing duty.",
        },
        {
            "requirement_id": "REQ-0001",
            "disposition": "met",
            "report_passages": ["must file a notice by Friday"],
            "rationale": "The report repeats the filing duty.",
        },
        {
            "requirement_id": "REQ-9999",
            "disposition": "met",
            "report_passages": ["must retain the notice for five years"],
            "rationale": "The report states a requirement.",
        },
    ]
    bypass = GradeResponseV2.model_construct(**payload)

    with pytest.raises(RubricValidationError, match="GRADE_REQUIREMENTS_INVALID"):
        validate_grade_response(baseline(), bypass, REPORT)


def test_material_grade_disagreement_is_inconclusive() -> None:
    result = reconcile_grades(baseline(), grade(), grade(second="partially_met"), REPORT)

    assert result.disposition is AbsoluteDispositionV2.INCONCLUSIVE
    assert result.reason_codes == ("GRADER_DISAGREEMENT",)


def test_agreement_preserves_both_grader_observations_without_merging_rationales() -> None:
    first = grade()
    second_payload = grade_payload()
    second_payload["requirement_grades"][0]["rationale"] = "The filing rule is express."  # type: ignore[index]
    second = GradeResponseV2.validate_for_baseline(second_payload, baseline())

    result = reconcile_grades(baseline(), first, second, REPORT)

    assert result.disposition is AbsoluteDispositionV2.PASS
    assert result.grader_responses == (first, second)
    assert result.requirement_reconciliations[0].rationale == first.requirement_grades[0].rationale


def test_baseline_defect_uncertain_and_unresolved_dispute_are_inconclusive() -> None:
    defect = reconcile_grades(
        baseline(), grade(baseline_defect="The baseline omits a condition."), grade(), REPORT
    )
    uncertain = reconcile_grades(
        baseline(), grade(first="uncertain"), grade(first="uncertain"), REPORT
    )
    unresolved = reconcile_grades(baseline(unresolved=["D0001"]), grade(), grade(), REPORT)

    assert defect.reason_codes == ("BASELINE_DEFECT_REPORTED",)
    assert uncertain.reason_codes == ("GRADE_UNCERTAIN",)
    assert unresolved.reason_codes == ("BASELINE_DISPUTE_UNRESOLVED",)


def test_unsupported_assertion_identity_includes_resolved_passage_and_importance() -> None:
    material = [
        {
            "report_passage": "must file a notice by Friday",
            "importance": "material",
            "rationale": "Unsupported.",
        }
    ]
    critical = [
        {
            "report_passage": "must file a notice by Friday",
            "importance": "critical",
            "rationale": "Unsupported.",
        }
    ]

    result = reconcile_grades(
        baseline(), grade(unsupported=material), grade(unsupported=critical), REPORT
    )

    assert result.reason_codes == ("GRADER_DISAGREEMENT",)


@pytest.mark.parametrize(
    ("first", "second", "unsupported", "expected", "reason"),
    [
        ("not_met", "met", [], AbsoluteDispositionV2.FAIL, "CRITICAL_RECALL_BELOW_FLOOR"),
        ("met", "partially_met", [], AbsoluteDispositionV2.FAIL, "WEIGHTED_COVERAGE_BELOW_FLOOR"),
        (
            "met",
            "met",
            [
                {
                    "report_passage": "must file a notice by Friday",
                    "importance": "material",
                    "rationale": "Unsupported.",
                }
            ],
            AbsoluteDispositionV2.FAIL,
            "MATERIAL_UNSUPPORTED_ASSERTION",
        ),
        ("met", "met", [], AbsoluteDispositionV2.PASS, None),
    ],
)
def test_score_report_applies_each_named_gate(
    first: str,
    second: str,
    unsupported: list[dict[str, str]],
    expected: AbsoluteDispositionV2,
    reason: str | None,
) -> None:
    reconciled = reconcile_grades(
        baseline(),
        grade(first=first, second=second, unsupported=unsupported),
        grade(first=first, second=second, unsupported=unsupported),
        REPORT,
    )

    result = score_report(baseline(), reconciled, RUBRIC_V2)

    assert result.absolute_disposition is expected
    assert (reason in result.reason_codes) is (reason is not None)
    assert "retry" not in result.model_dump(mode="json")


def test_score_report_keeps_an_inconclusive_reconciliation_unscored() -> None:
    reconciled = reconcile_grades(baseline(), grade(), grade(second="not_met"), REPORT)

    result = score_report(baseline(), reconciled, RUBRIC_V2)

    assert result.absolute_disposition is AbsoluteDispositionV2.INCONCLUSIVE
    assert result.reconciliation.requirement_reconciliations == ()


@pytest.mark.parametrize(
    ("candidate", "comparator", "expected", "winner"),
    [
        (
            AbsoluteDispositionV2.PASS,
            AbsoluteDispositionV2.FAIL,
            ComparisonDispositionV2.CANDIDATE_WIN,
            "A",
        ),
        (
            AbsoluteDispositionV2.FAIL,
            AbsoluteDispositionV2.PASS,
            ComparisonDispositionV2.COMPARATOR_WIN,
            "B",
        ),
        (AbsoluteDispositionV2.PASS, AbsoluteDispositionV2.PASS, ComparisonDispositionV2.TIE, None),
        (
            AbsoluteDispositionV2.FAIL,
            AbsoluteDispositionV2.FAIL,
            ComparisonDispositionV2.NEITHER,
            None,
        ),
        (
            AbsoluteDispositionV2.INCONCLUSIVE,
            AbsoluteDispositionV2.PASS,
            ComparisonDispositionV2.INCONCLUSIVE,
            None,
        ),
    ],
)
def test_compare_report_results_never_forces_a_winner_from_inconclusive(
    candidate: AbsoluteDispositionV2,
    comparator: AbsoluteDispositionV2,
    expected: ComparisonDispositionV2,
    winner: str | None,
) -> None:
    candidate_grade = grade(first="met" if candidate is AbsoluteDispositionV2.PASS else "not_met")
    if candidate is AbsoluteDispositionV2.INCONCLUSIVE:
        candidate_reconciled = reconcile_grades(
            baseline(), candidate_grade, grade(second="not_met"), REPORT
        )
    else:
        candidate_reconciled = reconcile_grades(
            baseline(), candidate_grade, candidate_grade, REPORT
        )
    candidate_result = score_report(baseline(), candidate_reconciled, RUBRIC_V2)
    comparator_payload = grade_payload(label="B")
    comparator_grade = GradeResponseV2.validate_for_baseline(comparator_payload, baseline())
    if comparator is AbsoluteDispositionV2.INCONCLUSIVE:
        comparator_reconciled = reconcile_grades(
            baseline(), comparator_grade, grade(label="B", second="not_met"), REPORT
        )
    elif comparator is AbsoluteDispositionV2.FAIL:
        comparator_grade = grade(label="B", first="not_met")
        comparator_reconciled = reconcile_grades(
            baseline(), comparator_grade, comparator_grade, REPORT
        )
    else:
        comparator_reconciled = reconcile_grades(
            baseline(), comparator_grade, comparator_grade, REPORT
        )
    comparator_result = score_report(baseline(), comparator_reconciled, RUBRIC_V2)

    result = compare_report_results(candidate_result, comparator_result)

    assert result.disposition is expected
    assert result.winner_label == winner


def test_rubric_has_the_approved_fixed_weights_and_floor() -> None:
    assert RUBRIC_V2.importance_weights == {
        ImportanceV2.CRITICAL: 3,
        ImportanceV2.MATERIAL: 2,
        ImportanceV2.SUPPORTING: 1,
    }
    assert RUBRIC_V2.weighted_coverage_floor == 0.90


def test_compare_report_results_rejects_different_sealed_baselines() -> None:
    other_baseline = baseline().model_copy(update={"baseline_fingerprint": "c" * 64})
    candidate = score_report(
        baseline(), reconcile_grades(baseline(), grade(), grade(), REPORT), RUBRIC_V2
    )
    comparator_grade = grade(label="B", reference_baseline=other_baseline)
    comparator = score_report(
        other_baseline,
        reconcile_grades(other_baseline, comparator_grade, comparator_grade, REPORT),
        RUBRIC_V2,
    )

    with pytest.raises(RubricValidationError, match="COMPARISON_BASELINE_MISMATCH"):
        compare_report_results(candidate, comparator)


def test_validate_grade_response_rejects_duplicate_resolved_requirement_passages() -> None:
    with pytest.raises(RubricValidationError, match="GRADE_REPORT_PASSAGE_DUPLICATE"):
        validate_grade_response(
            baseline(),
            grade(first_passages=["must file a notice by Friday"] * 2),
            REPORT,
        )


@pytest.mark.parametrize(
    "corruption",
    [
        "string_disposition",
        "cyclic_reconciliation",
        "unhashable_baseline_fingerprint",
        "result_fingerprint",
    ],
)
def test_compare_report_results_revalidates_bypassed_report_results(
    corruption: str,
) -> None:
    candidate = score_report(
        baseline(), reconcile_grades(baseline(), grade(), grade(), REPORT), RUBRIC_V2
    )
    comparator_grade = grade(label="B")
    comparator = score_report(
        baseline(),
        reconcile_grades(baseline(), comparator_grade, comparator_grade, REPORT),
        RUBRIC_V2,
    )
    if corruption == "string_disposition":
        bypass = ReportResultV2.model_construct(
            **{**candidate.__dict__, "absolute_disposition": "FAIL"}
        )
    elif corruption == "cyclic_reconciliation":
        cyclic: dict[str, object] = {}
        cyclic["self"] = cyclic
        bypass = ReportResultV2.model_construct(**{**candidate.__dict__, "reconciliation": cyclic})
    elif corruption == "unhashable_baseline_fingerprint":
        response = candidate.reconciliation.grader_responses[0].model_construct(
            **{
                **candidate.reconciliation.grader_responses[0].__dict__,
                "baseline_fingerprint": [],
            }
        )
        reconciliation = candidate.reconciliation.model_construct(
            **{
                **candidate.reconciliation.__dict__,
                "grader_responses": (response, response),
            }
        )
        bypass = ReportResultV2.model_construct(
            **{**candidate.__dict__, "reconciliation": reconciliation}
        )
    else:
        bypass = ReportResultV2.model_construct(
            **{**candidate.__dict__, "result_fingerprint": "0" * 64}
        )

    with pytest.raises(RubricValidationError, match="COMPARISON_RESULT_INVALID"):
        compare_report_results(bypass, comparator)
