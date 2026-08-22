"""Deterministic reconciliation and scoring for evaluator protocol 2.0."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from typing import Any

from pydantic import ValidationError

from regulatory_harvest.storage import canonical_json_bytes

from .attorney_v2_models import (
    AbsoluteDispositionV2,
    CanonicalBaselineV2,
    ComparisonDispositionV2,
    ComparisonResultV2,
    GradeResponseV2,
    ImportanceV2,
    ReconciledGradeV2,
    ReconciledRequirementGradeV2,
    ReportResultV2,
    RubricV2,
    UnsupportedAssertionV2,
)


class RubricValidationError(ValueError):
    """Raised when a grader or rubric input is mechanically invalid."""


RUBRIC_V2 = RubricV2(
    version="attorney-eval-v2",
    importance_weights={
        ImportanceV2.CRITICAL: 3,
        ImportanceV2.MATERIAL: 2,
        ImportanceV2.SUPPORTING: 1,
    },
    critical_recall_floor=1.0,
    weighted_coverage_floor=0.90,
    material_unsupported_assertions_allowed=0,
)

DISPOSITION_CREDIT = {
    "met": 1.0,
    "partially_met": 0.5,
    "not_met": 0.0,
    "uncertain": 0.0,
}


def validate_grade_response(
    baseline: CanonicalBaselineV2,
    grade: GradeResponseV2,
    report_text: str,
) -> GradeResponseV2:
    """Revalidate one grader response and resolve every cited report passage.

    Malformed responses are mechanical failures handled by the controller's
    bounded repair boundary.  Only accepted, baseline-bound observations can
    become part of a reconciliation artifact.
    """
    sealed_baseline = _baseline_snapshot(baseline)
    if not isinstance(report_text, str):
        raise RubricValidationError("REPORT_TEXT_INVALID")
    try:
        snapshot = GradeResponseV2.validate_for_baseline(_model_payload(grade), sealed_baseline)
    except (TypeError, ValueError, ValidationError) as error:
        raise RubricValidationError("GRADE_REQUIREMENTS_INVALID") from error

    seen_assertions: set[tuple[int, int, ImportanceV2]] = set()
    for requirement_grade in snapshot.requirement_grades:
        seen_passages: set[tuple[int, int, str]] = set()
        for passage in requirement_grade.report_passages:
            start, end = _resolve_exact_report_passage(report_text, passage)
            identity = (start, end, passage)
            if identity in seen_passages:
                raise RubricValidationError("GRADE_REPORT_PASSAGE_DUPLICATE")
            seen_passages.add(identity)
    for assertion in snapshot.unsupported_assertions:
        identity = (
            *_resolve_exact_report_passage(report_text, assertion.report_passage),
            assertion.importance,
        )
        if identity in seen_assertions:
            raise RubricValidationError("GRADE_UNSUPPORTED_ASSERTION_DUPLICATE")
        seen_assertions.add(identity)
    return snapshot


def reconcile_grades(
    baseline: CanonicalBaselineV2,
    first: GradeResponseV2,
    second: GradeResponseV2,
    report_text: str,
) -> ReconciledGradeV2:
    """Preserve two accepted observations and fail closed on material disagreement."""
    sealed_baseline = _baseline_snapshot(baseline)
    first_snapshot = validate_grade_response(sealed_baseline, first, report_text)
    second_snapshot = validate_grade_response(sealed_baseline, second, report_text)
    if first_snapshot.anonymous_label != second_snapshot.anonymous_label:
        raise RubricValidationError("GRADER_LABEL_MISMATCH")

    common: dict[str, object] = {
        "anonymous_label": first_snapshot.anonymous_label,
        "grader_responses": (first_snapshot, second_snapshot),
    }
    if sealed_baseline.unresolved_dispute_ids:
        return _reconciliation(
            sealed_baseline, common, "INCONCLUSIVE", "BASELINE_DISPUTE_UNRESOLVED"
        )
    if first_snapshot.baseline_defect is not None or second_snapshot.baseline_defect is not None:
        return _reconciliation(sealed_baseline, common, "INCONCLUSIVE", "BASELINE_DEFECT_REPORTED")
    if _has_uncertain_grade(first_snapshot) or _has_uncertain_grade(second_snapshot):
        return _reconciliation(sealed_baseline, common, "INCONCLUSIVE", "GRADE_UNCERTAIN")
    if _material_disagreement(report_text, first_snapshot, second_snapshot):
        return _reconciliation(sealed_baseline, common, "INCONCLUSIVE", "GRADER_DISAGREEMENT")

    first_by_requirement = {
        grade.requirement_id: grade for grade in first_snapshot.requirement_grades
    }
    reconciliations = tuple(
        ReconciledRequirementGradeV2(
            requirement_id=requirement.requirement_id,
            disposition=first_by_requirement[requirement.requirement_id].disposition,
            report_passages=first_by_requirement[requirement.requirement_id].report_passages,
            rationale=first_by_requirement[requirement.requirement_id].rationale,
            graders_agree=True,
        )
        for requirement in sealed_baseline.requirements
    )
    return _reconciliation(
        sealed_baseline,
        common,
        "PASS",
        requirement_reconciliations=reconciliations,
        unsupported_assertions=tuple(first_snapshot.unsupported_assertions),
    )


def score_report(
    baseline: CanonicalBaselineV2,
    reconciled: ReconciledGradeV2,
    rubric: RubricV2 = RUBRIC_V2,
) -> ReportResultV2:
    """Apply the fixed rubric once; unfavorable substantive results are not retried."""
    sealed_baseline = _baseline_snapshot(baseline)
    rubric_snapshot = _rubric_snapshot(rubric)
    reconciliation = _reconciliation_snapshot(sealed_baseline, reconciled)
    if reconciliation.disposition is AbsoluteDispositionV2.INCONCLUSIVE:
        return _report_result(
            reconciliation,
            critical_recall=0.0,
            weighted_coverage=0.0,
        )

    grades = {item.requirement_id: item for item in reconciliation.requirement_reconciliations}
    if set(grades) != {item.requirement_id for item in sealed_baseline.requirements}:
        raise RubricValidationError("RECONCILIATION_REQUIREMENTS_INVALID")

    critical_credits: list[float] = []
    total_weight = 0
    credited_weight = 0.0
    for requirement in sealed_baseline.requirements:
        credit = DISPOSITION_CREDIT[grades[requirement.requirement_id].disposition]
        weight = rubric_snapshot.importance_weights[requirement.importance]
        total_weight += weight
        credited_weight += weight * credit
        if requirement.importance is ImportanceV2.CRITICAL:
            critical_credits.append(credit)
    critical_recall = sum(critical_credits) / len(critical_credits) if critical_credits else 1.0
    weighted_coverage = credited_weight / total_weight if total_weight else 1.0

    reason_codes: list[str] = []
    if critical_recall < rubric_snapshot.critical_recall_floor:
        reason_codes.append("CRITICAL_RECALL_BELOW_FLOOR")
    if weighted_coverage < rubric_snapshot.weighted_coverage_floor:
        reason_codes.append("WEIGHTED_COVERAGE_BELOW_FLOOR")
    if any(
        assertion.importance in {ImportanceV2.CRITICAL, ImportanceV2.MATERIAL}
        for assertion in reconciliation.unsupported_assertions
    ):
        reason_codes.append("MATERIAL_UNSUPPORTED_ASSERTION")

    disposition = AbsoluteDispositionV2.FAIL if reason_codes else AbsoluteDispositionV2.PASS
    scored = _reconciliation(
        sealed_baseline,
        {
            "anonymous_label": reconciliation.anonymous_label,
            "grader_responses": reconciliation.grader_responses,
        },
        disposition.value,
        *reason_codes,
        requirement_reconciliations=reconciliation.requirement_reconciliations,
        unsupported_assertions=reconciliation.unsupported_assertions,
    )
    return _report_result(
        scored,
        critical_recall=critical_recall,
        weighted_coverage=weighted_coverage,
    )


def compare_report_results(
    candidate: ReportResultV2,
    comparator: ReportResultV2,
) -> ComparisonResultV2:
    """Compare two conclusive reports without inventing a winner from uncertainty."""
    candidate = _report_result_snapshot(candidate)
    comparator = _report_result_snapshot(comparator)
    if candidate.anonymous_label != "A" or comparator.anonymous_label != "B":
        raise RubricValidationError("COMPARISON_LABELS_INVALID")
    candidate_fingerprints = {
        response.baseline_fingerprint for response in candidate.reconciliation.grader_responses
    }
    comparator_fingerprints = {
        response.baseline_fingerprint for response in comparator.reconciliation.grader_responses
    }
    if candidate_fingerprints != comparator_fingerprints:
        raise RubricValidationError("COMPARISON_BASELINE_MISMATCH")
    if (
        candidate.absolute_disposition is AbsoluteDispositionV2.INCONCLUSIVE
        or comparator.absolute_disposition is AbsoluteDispositionV2.INCONCLUSIVE
    ):
        return ComparisonResultV2(
            disposition=ComparisonDispositionV2.INCONCLUSIVE,
            rationale="At least one report is inconclusive.",
        )
    if (
        candidate.absolute_disposition is AbsoluteDispositionV2.PASS
        and comparator.absolute_disposition is AbsoluteDispositionV2.FAIL
    ):
        return ComparisonResultV2(
            disposition=ComparisonDispositionV2.CANDIDATE_WIN,
            winner_label="A",
            rationale="Only the candidate report passed the rubric.",
        )
    if (
        candidate.absolute_disposition is AbsoluteDispositionV2.FAIL
        and comparator.absolute_disposition is AbsoluteDispositionV2.PASS
    ):
        return ComparisonResultV2(
            disposition=ComparisonDispositionV2.COMPARATOR_WIN,
            winner_label="B",
            rationale="Only the comparator report passed the rubric.",
        )
    if candidate.absolute_disposition is AbsoluteDispositionV2.FAIL:
        return ComparisonResultV2(
            disposition=ComparisonDispositionV2.NEITHER,
            rationale="Neither report passed the rubric.",
        )
    return ComparisonResultV2(
        disposition=ComparisonDispositionV2.TIE,
        rationale="Both reports passed the rubric.",
    )


def _baseline_snapshot(baseline: CanonicalBaselineV2) -> CanonicalBaselineV2:
    try:
        return CanonicalBaselineV2.model_validate(_model_payload(baseline))
    except (TypeError, ValueError, ValidationError) as error:
        raise RubricValidationError("BASELINE_INVALID") from error


def _rubric_snapshot(rubric: RubricV2) -> RubricV2:
    try:
        snapshot = RubricV2.model_validate(_model_payload(rubric))
    except (TypeError, ValueError, ValidationError) as error:
        raise RubricValidationError("RUBRIC_INVALID") from error
    expected_importance = set(ImportanceV2)
    if set(snapshot.importance_weights) != expected_importance or any(
        type(weight) is not int or weight <= 0 for weight in snapshot.importance_weights.values()
    ):
        raise RubricValidationError("RUBRIC_WEIGHTS_INVALID")
    return snapshot


def _reconciliation_snapshot(
    baseline: CanonicalBaselineV2, reconciled: ReconciledGradeV2
) -> ReconciledGradeV2:
    try:
        return ReconciledGradeV2.validate_for_baseline(_model_payload(reconciled), baseline)
    except (TypeError, ValueError, ValidationError) as error:
        raise RubricValidationError("RECONCILIATION_INVALID") from error


def _report_result_snapshot(result: ReportResultV2) -> ReportResultV2:
    """Revalidate an untrusted report result without inventing a baseline."""
    try:
        payload = _model_payload(result)
        reconciliation = _reconciliation_result_snapshot(payload["reconciliation"])
        payload["reconciliation"] = reconciliation
        snapshot = ReportResultV2.model_validate(payload)
        if snapshot.result_fingerprint != _report_result_fingerprint(snapshot):
            raise ValueError("result fingerprint does not match its contents")
        return snapshot
    except (
        AttributeError,
        KeyError,
        RecursionError,
        TypeError,
        ValidationError,
        ValueError,
    ) as error:
        raise RubricValidationError("COMPARISON_RESULT_INVALID") from error


def _reconciliation_result_snapshot(value: object) -> ReconciledGradeV2:
    """Validate a reconciliation using only its own retained grader observations."""
    payload = _model_payload(value)
    raw_responses = payload["grader_responses"]
    if not isinstance(raw_responses, (list, tuple)) or len(raw_responses) != 2:
        raise ValueError("reconciliation must retain two grader responses")
    first_response = _model_payload(raw_responses[0])
    raw_grades = first_response["requirement_grades"]
    if not isinstance(raw_grades, (list, tuple)):
        raise ValueError("grader response must contain requirement grades")
    requirement_ids = {_model_field(item, "requirement_id") for item in raw_grades}
    baseline_fingerprint = first_response["baseline_fingerprint"]
    if any(
        not isinstance(requirement_id, str) for requirement_id in requirement_ids
    ) or not isinstance(baseline_fingerprint, str):
        raise ValueError("reconciliation references are invalid")
    return ReconciledGradeV2.model_validate(
        payload,
        context={
            "requirement_ids": requirement_ids,
            "baseline_fingerprint": baseline_fingerprint,
        },
    )


def _model_payload(value: object) -> dict[str, Any]:
    raw = getattr(value, "__dict__", None)
    if not isinstance(raw, dict):
        raise TypeError("value must be a strict protocol model")
    return dict(raw)


def _model_field(value: object, name: str) -> object:
    if isinstance(value, dict):
        return value[name]
    return getattr(value, name)


def _all_occurrences(text: str, quote: str) -> Iterable[int]:
    start = 0
    while True:
        found = text.find(quote, start)
        if found == -1:
            return
        yield found
        start = found + 1


def _resolve_exact_report_passage(report_text: str, quote: str) -> tuple[int, int]:
    occurrences = tuple(_all_occurrences(report_text, quote))
    if not occurrences:
        raise RubricValidationError("REPORT_PASSAGE_NOT_FOUND")
    if len(occurrences) != 1:
        raise RubricValidationError("REPORT_PASSAGE_AMBIGUOUS")
    return occurrences[0], occurrences[0] + len(quote)


def _has_uncertain_grade(grade: GradeResponseV2) -> bool:
    return any(item.disposition == "uncertain" for item in grade.requirement_grades)


def _material_disagreement(
    report_text: str, first: GradeResponseV2, second: GradeResponseV2
) -> bool:
    first_dispositions = {
        item.requirement_id: item.disposition for item in first.requirement_grades
    }
    second_dispositions = {
        item.requirement_id: item.disposition for item in second.requirement_grades
    }
    if first_dispositions != second_dispositions:
        return True
    return _unsupported_assertion_identities(
        report_text, first
    ) != _unsupported_assertion_identities(report_text, second)


def _unsupported_assertion_identities(
    report_text: str, grade: GradeResponseV2
) -> frozenset[tuple[int, int, ImportanceV2]]:
    return frozenset(
        (
            *_resolve_exact_report_passage(report_text, assertion.report_passage),
            assertion.importance,
        )
        for assertion in grade.unsupported_assertions
    )


def _reconciliation(
    baseline: CanonicalBaselineV2,
    common: dict[str, object],
    disposition: str,
    *reason_codes: str,
    requirement_reconciliations: tuple[ReconciledRequirementGradeV2, ...] = (),
    unsupported_assertions: tuple[UnsupportedAssertionV2, ...] = (),
) -> ReconciledGradeV2:
    payload = {
        **common,
        "disposition": disposition,
        "reason_codes": reason_codes,
        "requirement_reconciliations": requirement_reconciliations,
        "unsupported_assertions": unsupported_assertions,
    }
    try:
        return ReconciledGradeV2.validate_for_baseline(payload, baseline)
    except (TypeError, ValueError, ValidationError) as error:
        raise RubricValidationError("RECONCILIATION_INVALID") from error


def _report_result(
    reconciliation: ReconciledGradeV2, *, critical_recall: float, weighted_coverage: float
) -> ReportResultV2:
    payload: dict[str, object] = {
        "anonymous_label": reconciliation.anonymous_label,
        "absolute_disposition": reconciliation.disposition,
        "reconciliation": reconciliation,
        "critical_recall": critical_recall,
        "weighted_coverage": weighted_coverage,
        "reason_codes": reconciliation.reason_codes,
    }
    fingerprint = _fingerprint(payload)
    return ReportResultV2.model_validate({**payload, "result_fingerprint": fingerprint})


def _report_result_fingerprint(result: ReportResultV2) -> str:
    return _fingerprint(
        {
            "anonymous_label": result.anonymous_label,
            "absolute_disposition": result.absolute_disposition,
            "reconciliation": result.reconciliation,
            "critical_recall": result.critical_recall,
            "weighted_coverage": result.weighted_coverage,
            "reason_codes": result.reason_codes,
        }
    )


def _fingerprint(payload: dict[str, object]) -> str:
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
