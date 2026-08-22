# ruff: noqa: E501
"""Bounded, independently sealed grading for evaluator protocol 2.1."""

from __future__ import annotations

import hashlib
from typing import Literal

from pydantic import ValidationError

from regulatory_harvest.storage import canonical_json_bytes

from .attorney_v2_models import AbsoluteDispositionV2, ImportanceV2
from .attorney_v21_models import (
    CanonicalBaselineV21,
    ContestedGradeFragmentV21,
    GraderAggregateV21,
    OrdinaryGradeBatchV21,
    OrdinaryGradeFragmentV21,
    ReconciledGradeV21,
    RubricV21,
    SensitivityRecordV21,
)


class RubricValidationError(ValueError):
    """Raised when a protocol-2.1 grade artifact is mechanically invalid."""


RUBRIC_V21 = RubricV21(
    version="attorney-eval-v2.1",
    importance_weights={ImportanceV2.CRITICAL: 3, ImportanceV2.MATERIAL: 2, ImportanceV2.SUPPORTING: 1},
    critical_recall_floor=1.0,
    weighted_coverage_floor=0.90,
    material_unsupported_assertions_allowed=0,
)


def _fingerprint(payload: dict[str, object]) -> str:
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def _aggregate_fingerprint(aggregate: GraderAggregateV21) -> str:
    return _fingerprint(
        {
            "anonymous_label": aggregate.anonymous_label,
            "grader_lane": aggregate.grader_lane,
            "baseline_fingerprint": aggregate.baseline_fingerprint,
            "report_fingerprint": aggregate.report_fingerprint,
            "ordinary_fragments": aggregate.ordinary_fragments,
            "contested_fragments": aggregate.contested_fragments,
        }
    )


def _reconciliation_fingerprint(reconciliation: ReconciledGradeV21) -> str:
    return _fingerprint(
        {
            "anonymous_label": reconciliation.anonymous_label,
            "absolute_disposition": reconciliation.absolute_disposition,
            "reason_codes": reconciliation.reason_codes,
            "grader_aggregates": reconciliation.grader_aggregates,
        }
    )


def _snapshot_baseline(value: CanonicalBaselineV21) -> CanonicalBaselineV21:
    try:
        return CanonicalBaselineV21.model_validate(value.model_dump(mode="json", warnings="error"))
    except (AttributeError, TypeError, ValidationError, ValueError) as error:
        raise RubricValidationError("BASELINE_INVALID") from error


def _snapshot_rubric(value: RubricV21) -> RubricV21:
    try:
        return RubricV21.model_validate(value.model_dump(mode="json", warnings="error"))
    except (AttributeError, TypeError, ValidationError, ValueError) as error:
        raise RubricValidationError("RUBRIC_INVALID") from error


def ordinary_grade_batches(
    baseline: CanonicalBaselineV21, anonymous_label: Literal["A", "B"], grader_lane: Literal[1, 2]
) -> tuple[OrdinaryGradeBatchV21, ...]:
    sealed = _snapshot_baseline(baseline)
    if anonymous_label not in {"A", "B"} or grader_lane not in {1, 2}:
        raise RubricValidationError("GRADE_LANE_INVALID")
    ids = tuple(item.requirement_id for item in sealed.requirements)
    return tuple(
        OrdinaryGradeBatchV21(
            batch_ref=f"GB-{anonymous_label}-{grader_lane}-{index // 5 + 1:04d}",
            requirement_ids=ids[index:index + 5],
        )
        for index in range(0, len(ids), 5)
    )


def _exact_passage(report_text: str, passage: str) -> None:
    if not isinstance(report_text, str):
        raise RubricValidationError("REPORT_TEXT_INVALID")
    if report_text.count(passage) == 0:
        raise RubricValidationError("GRADE_REPORT_PASSAGE_NOT_FOUND")
    if report_text.count(passage) != 1:
        raise RubricValidationError("GRADE_REPORT_PASSAGE_AMBIGUOUS")


def validate_grade_fragment_v21(
    baseline: CanonicalBaselineV21, fragment: object, report_text: str
) -> OrdinaryGradeFragmentV21 | ContestedGradeFragmentV21:
    sealed = _snapshot_baseline(baseline)
    report_fingerprint = hashlib.sha256(report_text.encode("utf-8")).hexdigest()
    try:
        raw = fragment.model_dump(mode="json", warnings="error") if isinstance(
            fragment, (OrdinaryGradeFragmentV21, ContestedGradeFragmentV21)
        ) else fragment
        if not isinstance(raw, dict):
            raise ValueError("grade fragment must be an object")
        if "batch_ref" in raw:
            label = raw.get("anonymous_label")
            lane = raw.get("grader_lane")
            if label not in {"A", "B"} or lane not in {1, 2}:
                raise ValueError("grade lane invalid")
            result: OrdinaryGradeFragmentV21 | ContestedGradeFragmentV21 = OrdinaryGradeFragmentV21.model_validate(
                raw, context={"ordinary_grade_batches": ordinary_grade_batches(sealed, label, lane)}
            )
            assert isinstance(result, OrdinaryGradeFragmentV21)
            for grade in result.requirement_grades:
                for passage in grade.report_passages:
                    _exact_passage(report_text, passage)
        else:
            result = ContestedGradeFragmentV21.model_validate(
                raw, context={"contested_requirements": sealed.contested_requirements}
            )
            assert isinstance(result, ContestedGradeFragmentV21)
            for alternative in (result.reviewer_alternative_grade, result.auditor_alternative_grade):
                for passage in alternative.report_passages:
                    _exact_passage(report_text, passage)
        if result.baseline_fingerprint != sealed.baseline_fingerprint:
            raise RubricValidationError("GRADE_BASELINE_MISMATCH")
        if result.report_fingerprint != report_fingerprint:
            raise RubricValidationError("GRADE_REPORT_FINGERPRINT_MISMATCH")
        return result
    except RubricValidationError:
        raise
    except (AttributeError, TypeError, ValidationError, ValueError) as error:
        raise RubricValidationError("GRADE_FRAGMENT_INVALID") from error


def aggregate_grader_lane(
    baseline: CanonicalBaselineV21, anonymous_label: Literal["A", "B"], grader_lane: Literal[1, 2],
    ordinary_fragments: tuple[OrdinaryGradeFragmentV21, ...],
    contested_fragments: tuple[ContestedGradeFragmentV21, ...],
) -> GraderAggregateV21:
    sealed = _snapshot_baseline(baseline)
    batches = ordinary_grade_batches(sealed, anonymous_label, grader_lane)
    try:
        if (not ordinary_fragments and batches) or (not contested_fragments and sealed.contested_requirements):
            raise ValueError("fragment coverage missing")
        report_fingerprints = {item.report_fingerprint for item in ordinary_fragments}
        report_fingerprints.update(item.report_fingerprint for item in contested_fragments)
        if len(report_fingerprints) != 1:
            raise ValueError("report binding differs")
        payload: dict[str, object] = {
            "anonymous_label": anonymous_label, "grader_lane": grader_lane,
            "baseline_fingerprint": sealed.baseline_fingerprint,
            "report_fingerprint": next(iter(report_fingerprints)),
            "ordinary_fragments": ordinary_fragments, "contested_fragments": contested_fragments,
        }
        aggregate = GraderAggregateV21.validate_for_inventories(
            {**payload, "aggregate_fingerprint": _fingerprint(payload)}, batches, sealed.contested_requirements
        )
        return aggregate
    except (TypeError, ValidationError, ValueError) as error:
        raise RubricValidationError("GRADE_FRAGMENT_COVERAGE_INVALID") from error


def _score(dispositions: list[tuple[ImportanceV2, str]], rubric: RubricV21) -> tuple[AbsoluteDispositionV2, tuple[str, ...]]:
    if any(disposition == "uncertain" for _, disposition in dispositions):
        return AbsoluteDispositionV2.INCONCLUSIVE, ("GRADE_UNCERTAIN",)
    total = sum(rubric.importance_weights[importance] for importance, _ in dispositions)
    credited = sum(rubric.importance_weights[importance] * {"met": 1.0, "partially_met": .5, "not_met": 0.0}[disposition] for importance, disposition in dispositions)
    credit = {"met": 1.0, "partially_met": 0.5, "not_met": 0.0}
    critical = [credit[disposition] for importance, disposition in dispositions if importance is ImportanceV2.CRITICAL]
    reasons: list[str] = []
    critical_recall = sum(critical) / len(critical) if critical else 1.0
    if critical_recall < rubric.critical_recall_floor:
        reasons.append("CRITICAL_RECALL_BELOW_FLOOR")
    if total and credited / total < rubric.weighted_coverage_floor:
        reasons.append("WEIGHTED_COVERAGE_BELOW_FLOOR")
    return (AbsoluteDispositionV2.FAIL if reasons else AbsoluteDispositionV2.PASS, tuple(reasons))


def _ordinary_observations(baseline: CanonicalBaselineV21, aggregate: GraderAggregateV21) -> list[tuple[ImportanceV2, str]]:
    grades = {grade.requirement_id: grade for fragment in aggregate.ordinary_fragments for grade in fragment.requirement_grades}
    return [(item.importance, grades[item.requirement_id].disposition) for item in baseline.requirements]


def _same_observations(first: GraderAggregateV21, second: GraderAggregateV21) -> bool:
    def view(aggregate: GraderAggregateV21) -> tuple[object, ...]:
        return tuple(tuple((g.requirement_id, g.disposition, g.report_passages) for g in f.requirement_grades) for f in aggregate.ordinary_fragments) + tuple((f.contested_requirement_id, f.reviewer_alternative_grade.disposition, f.auditor_alternative_grade.disposition, f.ambiguity_disposition) for f in aggregate.contested_fragments)
    return view(first) == view(second)


def reconcile_grader_lanes(
    baseline: CanonicalBaselineV21, first: GraderAggregateV21, second: GraderAggregateV21, rubric: RubricV21 = RUBRIC_V21
) -> ReconciledGradeV21:
    sealed, checked_rubric = _snapshot_baseline(baseline), _snapshot_rubric(rubric)
    try:
        if first.anonymous_label != second.anonymous_label or first.grader_lane == second.grader_lane:
            raise ValueError("lane isolation invalid")
        inventories = ordinary_grade_batches(sealed, first.anonymous_label, first.grader_lane)
        checked_first = GraderAggregateV21.validate_for_inventories(first.model_dump(mode="json"), inventories, sealed.contested_requirements)
        checked_second = GraderAggregateV21.validate_for_inventories(second.model_dump(mode="json"), ordinary_grade_batches(sealed, second.anonymous_label, second.grader_lane), sealed.contested_requirements)
        if (
            checked_first.aggregate_fingerprint != _aggregate_fingerprint(checked_first)
            or checked_second.aggregate_fingerprint != _aggregate_fingerprint(checked_second)
            or checked_first.grader_lane != 1
            or checked_second.grader_lane != 2
            or checked_first.baseline_fingerprint != sealed.baseline_fingerprint
            or checked_second.baseline_fingerprint != sealed.baseline_fingerprint
            or checked_first.report_fingerprint != checked_second.report_fingerprint
        ):
            raise ValueError("aggregate binding or fingerprint is invalid")
        disposition, reasons = _score(_ordinary_observations(sealed, checked_first), checked_rubric)
        if not _same_observations(checked_first, checked_second):
            disposition, reasons = AbsoluteDispositionV2.INCONCLUSIVE, ("GRADER_DISAGREEMENT",)
        payload: dict[str, object] = {"anonymous_label": checked_first.anonymous_label, "absolute_disposition": disposition, "reason_codes": reasons, "grader_aggregates": (checked_first, checked_second)}
        return ReconciledGradeV21.validate_for_inventories(
            {**payload, "reconciliation_fingerprint": _fingerprint(payload)}, inventories, sealed.contested_requirements
        )
    except (AttributeError, TypeError, ValidationError, ValueError) as error:
        raise RubricValidationError("RECONCILIATION_INVALID") from error


def evaluate_outcome_sensitivity(baseline: CanonicalBaselineV21, reconciliation: ReconciledGradeV21, rubric: RubricV21 = RUBRIC_V21) -> SensitivityRecordV21:
    sealed, checked_rubric = _snapshot_baseline(baseline), _snapshot_rubric(rubric)
    try:
        if reconciliation.reconciliation_fingerprint != _reconciliation_fingerprint(reconciliation):
            raise ValueError("reconciliation fingerprint is invalid")
        checked = ReconciledGradeV21.validate_for_inventories(
            reconciliation.model_dump(mode="json"),
            ordinary_grade_batches(sealed, reconciliation.anonymous_label, 1),
            sealed.contested_requirements,
        )
        if (
            checked.grader_aggregates[0].aggregate_fingerprint
            != _aggregate_fingerprint(checked.grader_aggregates[0])
            or checked.grader_aggregates[1].aggregate_fingerprint
            != _aggregate_fingerprint(checked.grader_aggregates[1])
            or checked.grader_aggregates[0].grader_lane != 1
            or checked.grader_aggregates[1].grader_lane != 2
            or checked.grader_aggregates[0].baseline_fingerprint != sealed.baseline_fingerprint
            or checked.grader_aggregates[1].baseline_fingerprint != sealed.baseline_fingerprint
            or checked.grader_aggregates[0].report_fingerprint != checked.grader_aggregates[1].report_fingerprint
        ):
            raise ValueError("reconciliation binding is invalid")
    except (AttributeError, TypeError, ValidationError, ValueError) as error:
        raise RubricValidationError("RECONCILIATION_INVALID") from error
    first = checked.grader_aggregates[0]
    ordinary = _ordinary_observations(sealed, first)
    contested = {item.contested_requirement_id: item for item in first.contested_fragments}
    changing: list[str] = []
    insufficient = False
    reasons: tuple[str, ...]
    for item in sealed.contested_requirements:
        grade = contested[item.contested_requirement_id]
        if grade.reviewer_alternative_grade.disposition == "uncertain" and grade.auditor_alternative_grade.disposition == "uncertain":
            insufficient = True
            continue
        reviewer = _score(
            [*ordinary, (item.reviewer_alternative.importance if item.reviewer_alternative else ImportanceV2.SUPPORTING, grade.reviewer_alternative_grade.disposition)],
            checked_rubric,
        )[0]
        auditor = _score(
            [*ordinary, (item.auditor_alternative.importance if item.auditor_alternative else ImportanceV2.SUPPORTING, grade.auditor_alternative_grade.disposition)],
            checked_rubric,
        )[0]
        if reviewer != auditor:
            changing.append(item.contested_requirement_id)
    if changing:
        disposition, reasons = AbsoluteDispositionV2.INCONCLUSIVE, ("OUTCOME_SENSITIVE_BASELINE_DISPUTE",)
    elif insufficient:
        disposition, reasons = AbsoluteDispositionV2.INCONCLUSIVE, ("BASELINE_EVIDENCE_INSUFFICIENT",)
    else:
        disposition, reasons = reconciliation.absolute_disposition, reconciliation.reason_codes
    payload: dict[str, object] = {"anonymous_label": reconciliation.anonymous_label, "baseline_fingerprint": sealed.baseline_fingerprint, "reconciliation_fingerprint": reconciliation.reconciliation_fingerprint, "absolute_disposition": disposition, "reason_codes": reasons, "outcome_determinative_contested_ids": tuple(changing)}
    return SensitivityRecordV21.model_validate({**payload, "sensitivity_fingerprint": _fingerprint(payload)})
