"""Deterministic attorney-evaluation scoring and blinded comparison."""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from datetime import date
from typing import Any

from pydantic import ConfigDict, ValidationError

from regulatory_harvest.storage import canonical_json_bytes, sha256_digest

from .attorney_grading import (
    GradeInconclusiveError,
    ResolvedGrade,
    disposition_credit,
    strict_resolved_grade_snapshot,
)
from .attorney_models import (
    EVALUATION_ARTIFACT_SCHEMA_VERSION,
    AbsoluteDisposition,
    ComparativeDisposition,
    ComparisonEvaluation,
    CoverageDisposition,
    DeterministicChecks,
    EvaluationMode,
    EvaluationRubric,
    EvaluationSource,
    IssueSeverity,
    LedgerCategory,
    Materiality,
    ReportEvaluation,
    RequestedAuthority,
    SealedLedger,
    model_fingerprint,
)


class ScoringInconclusiveError(ValueError):
    """Raised when scoring inputs cannot be safely interpreted."""


SCORE_INPUT_SCHEMA_VERSION = "1.4"


@dataclass(frozen=True)
class ReportScoreInputs:
    """Independent inputs required to replay one published report score."""

    sealed_ledger: SealedLedger
    resolved_grade: ResolvedGrade
    deterministic_checks: DeterministicChecks
    source_record: bytes


class _ImmutableEvaluationRubric(EvaluationRubric):
    model_config = ConfigDict(extra="forbid", frozen=True)


class _FrozenDict(dict[Any, Any]):
    """A serializer-compatible immutable dictionary for rubric constants."""

    @staticmethod
    def _blocked(*args: object, **kwargs: object) -> None:
        raise TypeError("rubric mappings are immutable")

    __setitem__ = _blocked
    __delitem__ = _blocked
    clear = _blocked
    pop = _blocked
    popitem = _blocked  # type: ignore[assignment]
    setdefault = _blocked
    update = _blocked
    __ior__ = _blocked  # type: ignore[assignment]

    def __copy__(self) -> _FrozenDict:
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> _FrozenDict:
        return self


_RUBRIC_V1_DATA = {
    "version": "attorney-eval-v1",
    "materiality_weights": {
        Materiality.CRITICAL: 5,
        Materiality.MATERIAL: 3,
        Materiality.SUPPORTING: 1,
    },
    "critical_recall_floor": 1.0,
    "weighted_recall_floor": 0.90,
    "claim_precision_floor": 0.95,
    "walk_average_floor": 3.0,
    "walk_dimension_floor": 2,
    "comparison_weights": {"recall": 0.45, "precision": 0.25, "walk": 0.30},
    "comparison_margin": 5.0,
}

_rubric_v1 = _ImmutableEvaluationRubric.model_validate(_RUBRIC_V1_DATA)
object.__setattr__(
    _rubric_v1,
    "materiality_weights",
    _FrozenDict(_rubric_v1.materiality_weights),
)
object.__setattr__(
    _rubric_v1,
    "comparison_weights",
    _FrozenDict(_rubric_v1.comparison_weights),
)
RUBRIC_V1: EvaluationRubric = _rubric_v1

_LEGAL_MISSTATEMENTS = frozenset(
    {
        CoverageDisposition.UNSUPPORTED,
        CoverageDisposition.OVERSTATED,
        CoverageDisposition.CONTRADICTED,
    }
)
_SAFETY_CATEGORY = {
    LedgerCategory.STATUS: "STATUS",
    LedgerCategory.REQUIREMENT: "OBLIGATION",
    LedgerCategory.PROHIBITION: "OBLIGATION",
    LedgerCategory.DEADLINE: "DEADLINE",
    LedgerCategory.ENFORCEMENT: "ENFORCEMENT",
    LedgerCategory.REMEDY: "REMEDY",
    LedgerCategory.PENALTY: "PENALTY",
}


def score_report(
    sealed_ledger: SealedLedger,
    resolved_grade: ResolvedGrade,
    deterministic_checks: DeterministicChecks,
    rubric: EvaluationRubric = RUBRIC_V1,
    *,
    source_record: object,
) -> ReportEvaluation:
    """Score one reconciled anonymous report under the exact v1 safety gates."""
    rubric_snapshot = _rubric_snapshot(rubric)
    try:
        resolved = strict_resolved_grade_snapshot(sealed_ledger, resolved_grade)
    except GradeInconclusiveError as error:
        raise ScoringInconclusiveError(str(error)) from error
    checks = _checks_snapshot(deterministic_checks)
    sealed = _sealed_snapshot(sealed_ledger)
    source_record_snapshot = _source_record_snapshot(source_record)
    _validate_scoring_source_binding(sealed, resolved, source_record_snapshot)
    if resolved.anonymous_label != checks.anonymous_label:
        raise ScoringInconclusiveError(
            "resolved grade and deterministic checks must bind the same anonymous label"
        )

    entries_by_id = {grade.ledger_id: grade for grade in resolved.entry_grades}
    recall_denominator = 0
    recall_numerator = 0.0
    critical_credits: list[float] = []
    for ledger_entry in sealed.ledger.entries:
        weight = rubric_snapshot.materiality_weights[ledger_entry.materiality]
        credit = disposition_credit(entries_by_id[ledger_entry.ledger_id].disposition)
        recall_denominator += weight
        recall_numerator += weight * credit
        if ledger_entry.materiality is Materiality.CRITICAL:
            critical_credits.append(credit)
    weighted_recall = recall_numerator / recall_denominator if recall_denominator else 1.0
    critical_recall = sum(critical_credits) / len(critical_credits) if critical_credits else 1.0

    precision_denominator = 0
    precision_numerator = 0.0
    for claim in resolved.out_of_ledger_claims:
        weight = rubric_snapshot.materiality_weights[claim.materiality]
        precision_denominator += weight
        precision_numerator += weight * disposition_credit(claim.disposition)
    claim_precision = precision_numerator / precision_denominator if precision_denominator else 1.0

    narrative_values = [score.score for score in resolved.narrative_scores]
    walk_average = sum(narrative_values) / len(narrative_values)
    walk_minimum = min(narrative_values)
    normalized_score = 100.0 * (
        rubric_snapshot.comparison_weights["recall"] * weighted_recall
        + rubric_snapshot.comparison_weights["precision"] * claim_precision
        + rubric_snapshot.comparison_weights["walk"] * (walk_average / 4.0)
    )
    _require_finite(
        critical_recall,
        weighted_recall,
        claim_precision,
        walk_average,
        normalized_score,
    )

    blocking_codes: list[str] = []
    issue_codes = _semantic_issue_codes(resolved)
    critical_defect = False
    if checks.valid is not True:
        blocking_codes.append("DETERMINISTIC_CHECKS_INVALID")
        critical_defect = True
    for code in checks.critical_codes:
        blocking_codes.append(code)
        critical_defect = True
    for issue in checks.issues:
        if issue.severity is IssueSeverity.ERROR:
            blocking_codes.append(issue.code)
    if critical_recall < rubric_snapshot.critical_recall_floor:
        blocking_codes.append("CRITICAL_RECALL_BELOW_FLOOR")
        critical_defect = True
    if weighted_recall < rubric_snapshot.weighted_recall_floor:
        blocking_codes.append("WEIGHTED_RECALL_BELOW_FLOOR")
    if claim_precision < rubric_snapshot.claim_precision_floor:
        blocking_codes.append("CLAIM_PRECISION_BELOW_FLOOR")
    if walk_average < rubric_snapshot.walk_average_floor:
        blocking_codes.append("WALK_AVERAGE_BELOW_FLOOR")
    if any(score < rubric_snapshot.walk_dimension_floor for score in narrative_values):
        blocking_codes.append("WALK_DIMENSION_BELOW_FLOOR")

    legal_codes = _legal_safety_codes(sealed, resolved)
    if legal_codes:
        blocking_codes.extend(legal_codes)
        critical_defect = True
    blocking_codes = _unique_codes(blocking_codes)
    absolute_disposition = (
        AbsoluteDisposition.PASS if not blocking_codes else AbsoluteDisposition.FAIL
    )
    score_payload: dict[str, object] = {
        "schema_version": EVALUATION_ARTIFACT_SCHEMA_VERSION,
        "anonymous_label": resolved.anonymous_label,
        "absolute_disposition": absolute_disposition,
        "critical_recall": critical_recall,
        "weighted_recall": weighted_recall,
        "claim_precision": claim_precision,
        "walk_average": walk_average,
        "walk_minimum": walk_minimum,
        "normalized_score": normalized_score,
        "critical_defect": critical_defect,
        "issue_codes": issue_codes,
        "blocking_codes": blocking_codes,
        "ledger_fingerprint": sealed.ledger_fingerprint,
        "resolved_grade_fingerprint": resolved.resolution_fingerprint,
        "deterministic_checks_fingerprint": model_fingerprint(checks),
        "rubric_fingerprint": model_fingerprint(rubric_snapshot),
    }
    score_payload["score_fingerprint"] = sha256_digest(canonical_json_bytes(score_payload))
    return ReportEvaluation.model_validate(score_payload, strict=True)


def compare_reports(
    candidate: ReportEvaluation,
    comparator: ReportEvaluation,
    rubric: EvaluationRubric = RUBRIC_V1,
    *,
    candidate_inputs: ReportScoreInputs,
    comparator_inputs: ReportScoreInputs,
) -> ComparisonEvaluation:
    """Replay and compare two reports, treating arguments as candidate then comparator.

    Report identity remains represented only by anonymous labels.  The caller
    may unblind the winning label after this aggregation boundary.  Task 4
    proves deterministic consistency from the supplied inputs; Task 5 binds
    those input artifacts and their execution provenance immutably.
    """
    rubric_snapshot = _rubric_snapshot(rubric)
    candidate_snapshot, candidate_sealed = _replayed_report_snapshot(
        candidate,
        candidate_inputs,
        rubric_snapshot,
    )
    comparator_snapshot, comparator_sealed = _replayed_report_snapshot(
        comparator,
        comparator_inputs,
        rubric_snapshot,
    )
    if candidate_snapshot.anonymous_label == comparator_snapshot.anonymous_label:
        raise ScoringInconclusiveError("reports must have distinct anonymous labels")
    if candidate_snapshot.ledger_fingerprint != comparator_snapshot.ledger_fingerprint:
        raise ScoringInconclusiveError("reports must bind the same sealed ledger fingerprint")
    if candidate_sealed != comparator_sealed:
        raise ScoringInconclusiveError("reports must use the same strict sealed ledger snapshot")
    if candidate_snapshot.absolute_disposition not in {
        AbsoluteDisposition.PASS,
        AbsoluteDisposition.FAIL,
    } or comparator_snapshot.absolute_disposition not in {
        AbsoluteDisposition.PASS,
        AbsoluteDisposition.FAIL,
    }:
        raise ScoringInconclusiveError("comparison requires replayed PASS or FAIL reports")
    candidate_unsafe = candidate_snapshot.absolute_disposition is AbsoluteDisposition.FAIL
    comparator_unsafe = comparator_snapshot.absolute_disposition is AbsoluteDisposition.FAIL
    if candidate_unsafe and comparator_unsafe:
        return ComparisonEvaluation(
            disposition=ComparativeDisposition.NEITHER,
            rationale_codes=["BOTH_REPORTS_UNSAFE"],
        )
    if candidate_unsafe:
        return ComparisonEvaluation(
            disposition=ComparativeDisposition.COMPARATOR_WIN,
            winner_label=comparator_snapshot.anonymous_label,
            rationale_codes=["CANDIDATE_UNSAFE"],
        )
    if comparator_unsafe:
        return ComparisonEvaluation(
            disposition=ComparativeDisposition.REGULATORY_HARVEST_WIN,
            winner_label=candidate_snapshot.anonymous_label,
            rationale_codes=["COMPARATOR_UNSAFE"],
        )

    difference = abs(candidate_snapshot.normalized_score - comparator_snapshot.normalized_score)
    if difference < rubric_snapshot.comparison_margin:
        return ComparisonEvaluation(
            disposition=ComparativeDisposition.TIE,
            score_difference=difference,
            rationale_codes=["COMPARISON_MARGIN_NOT_MET"],
        )
    if candidate_snapshot.normalized_score > comparator_snapshot.normalized_score:
        return ComparisonEvaluation(
            disposition=ComparativeDisposition.REGULATORY_HARVEST_WIN,
            winner_label=candidate_snapshot.anonymous_label,
            score_difference=difference,
            rationale_codes=["COMPARISON_MARGIN_MET"],
        )
    return ComparisonEvaluation(
        disposition=ComparativeDisposition.COMPARATOR_WIN,
        winner_label=comparator_snapshot.anonymous_label,
        score_difference=difference,
        rationale_codes=["COMPARISON_MARGIN_MET"],
    )


def _legal_safety_codes(sealed_ledger: SealedLedger, resolved_grade: ResolvedGrade) -> list[str]:
    codes: list[str] = []
    entries_by_id = {entry.ledger_id: entry for entry in sealed_ledger.ledger.entries}
    for grade in resolved_grade.entry_grades:
        ledger_entry = entries_by_id[grade.ledger_id]
        code = _legal_safety_code(
            grade.disposition,
            ledger_entry.category,
            ledger_entry.materiality,
        )
        if code is not None:
            codes.append(code)
    for claim in resolved_grade.out_of_ledger_claims:
        code = _legal_safety_code(
            claim.disposition,
            claim.category,
            claim.materiality,
        )
        if code is not None:
            codes.append(code)
    return _unique_codes(codes)


def _semantic_issue_codes(resolved_grade: ResolvedGrade) -> list[str]:
    """Return stable, non-gating semantic findings selected during blind resolution."""
    codes = [code.value for entry in resolved_grade.entry_grades for code in entry.finding_codes]
    codes.extend(
        code.value for score in resolved_grade.narrative_scores for code in score.finding_codes
    )
    return _unique_codes(codes)


def _legal_safety_code(
    disposition: CoverageDisposition,
    category: LedgerCategory,
    materiality: Materiality,
) -> str | None:
    if disposition not in _LEGAL_MISSTATEMENTS or materiality is Materiality.SUPPORTING:
        return None
    category_token = _SAFETY_CATEGORY.get(category)
    if category_token is None:
        if materiality is not Materiality.CRITICAL:
            return None
        category_token = "LEGAL_CLAIM"
    return f"{disposition.value}_{materiality.value.upper()}_{category_token}"


def _source_record_snapshot(value: object) -> dict[str, object]:
    """Return one strict, canonical common-source snapshot for scoring."""
    try:
        if isinstance(value, bytes):
            decoded = json.loads(value.decode("utf-8"))
            if canonical_json_bytes(decoded) != value:
                raise ScoringInconclusiveError(
                    "scoring source record bytes must be canonical JSON"
                )
        else:
            decoded = json.loads(canonical_json_bytes(value).decode("utf-8"))
    except ScoringInconclusiveError:
        raise
    except (TypeError, UnicodeDecodeError, ValueError) as error:
        raise ScoringInconclusiveError("malformed scoring source record") from error
    if type(decoded) is not dict:
        raise ScoringInconclusiveError("scoring source record must be an object")
    snapshot = decoded
    expected_fields = {
        "schema_version",
        "mode",
        "question",
        "jurisdiction",
        "as_of",
        "requested_authorities",
        "sources",
        "source_record_fingerprint",
    }
    if set(snapshot) != expected_fields:
        raise ScoringInconclusiveError("scoring source record has an unexpected shape")
    if snapshot["schema_version"] not in {"1.0", "1.1"}:
        raise ScoringInconclusiveError("scoring source record schema is unsupported")
    if snapshot["mode"] not in {mode.value for mode in EvaluationMode}:
        raise ScoringInconclusiveError("scoring source record mode is unsupported")
    if any(
        type(snapshot[field]) is not str or not snapshot[field].strip()
        for field in ("question", "jurisdiction")
    ):
        raise ScoringInconclusiveError("scoring source record text fields are malformed")
    try:
        if type(snapshot["as_of"]) is not str:
            raise TypeError("as_of must be a string")
        date.fromisoformat(snapshot["as_of"])
    except (TypeError, ValueError) as error:
        raise ScoringInconclusiveError("scoring source record date is malformed") from error
    authorities_value = snapshot["requested_authorities"]
    sources_value = snapshot["sources"]
    if type(authorities_value) is not list or type(sources_value) is not list:
        raise ScoringInconclusiveError("scoring source record arrays are malformed")
    try:
        authorities = [
            RequestedAuthority.model_validate_json(
                canonical_json_bytes(item),
                strict=True,
            )
            for item in authorities_value
        ]
        sources = [
            EvaluationSource.model_validate_json(
                canonical_json_bytes(item),
                strict=True,
            )
            for item in sources_value
        ]
    except (TypeError, ValidationError, ValueError) as error:
        raise ScoringInconclusiveError("malformed scoring source record") from error
    if not authorities or not sources:
        raise ScoringInconclusiveError("scoring source record must retain authorities and sources")
    if [item.model_dump(mode="json") for item in authorities] != authorities_value:
        raise ScoringInconclusiveError("scoring source authorities changed during validation")
    if [item.model_dump(mode="json") for item in sources] != sources_value:
        raise ScoringInconclusiveError("scoring sources changed during validation")
    source_ids = [source.source_id for source in sources]
    authority_ids = [authority.authority_id for authority in authorities]
    if len(source_ids) != len(set(source_ids)) or len(authority_ids) != len(
        set(authority_ids)
    ):
        raise ScoringInconclusiveError("scoring source identifiers must be unique")
    if any(
        set(authority.source_ids) - set(source_ids)
        for authority in authorities
    ):
        raise ScoringInconclusiveError("scoring authorities identify unknown sources")
    if any(
        source.content_hash
        != sha256_digest(source.normalized_text.encode("utf-8"))
        for source in sources
    ):
        raise ScoringInconclusiveError("scoring source content hash is invalid")
    supplied_fingerprint = snapshot["source_record_fingerprint"]
    projection = {
        key: item
        for key, item in snapshot.items()
        if key != "source_record_fingerprint"
    }
    expected_fingerprint = sha256_digest(canonical_json_bytes(projection))
    if supplied_fingerprint != expected_fingerprint:
        raise ScoringInconclusiveError("scoring source record fingerprint is invalid")
    return snapshot


def _validate_scoring_source_binding(
    sealed: SealedLedger,
    resolved: ResolvedGrade,
    source_record: dict[str, object],
) -> None:
    """Require each scored claim span to be exact within the bound source record."""
    fingerprint = source_record["source_record_fingerprint"]
    assert isinstance(fingerprint, str)
    if sealed.ledger.case_fingerprint != fingerprint:
        raise ScoringInconclusiveError(
            "sealed ledger does not bind the scoring source record"
        )
    sources_value = source_record["sources"]
    assert isinstance(sources_value, list)
    sources = {
        source["source_id"]: source["normalized_text"]
        for source in sources_value
        if isinstance(source, dict)
    }
    for claim in resolved.out_of_ledger_claims:
        if claim.source_record_fingerprint != fingerprint:
            raise ScoringInconclusiveError(
                "out-of-ledger claim does not bind the scoring source record"
            )
        for span in claim.evidence_spans:
            text = sources.get(span.source_id)
            if not isinstance(text, str):
                raise ScoringInconclusiveError(
                    "exact source span identifies an unknown source"
                )
            if (
                span.end_char > len(text)
                or text[span.start_char : span.end_char] != span.quote
            ):
                raise ScoringInconclusiveError(
                    "out-of-ledger evidence is not an exact source span"
                )


def _rubric_snapshot(rubric: EvaluationRubric) -> EvaluationRubric:
    if not isinstance(rubric, EvaluationRubric):
        raise ScoringInconclusiveError("rubric must be an EvaluationRubric")
    try:
        if not _raw_rubric_types_valid(rubric):
            raise TypeError("rubric contains a coerced numeric field")
        snapshot = EvaluationRubric.model_validate(
            rubric.model_dump(mode="python", warnings="error"), strict=True
        )
        canonical = EvaluationRubric.model_validate(_RUBRIC_V1_DATA)
    except (TypeError, ValidationError, ValueError) as error:
        raise ScoringInconclusiveError("malformed evaluation rubric") from error
    if snapshot != canonical:
        raise ScoringInconclusiveError("unsupported or mutated evaluation rubric")
    numeric_values = [
        snapshot.critical_recall_floor,
        snapshot.weighted_recall_floor,
        snapshot.claim_precision_floor,
        snapshot.walk_average_floor,
        snapshot.comparison_margin,
        *snapshot.comparison_weights.values(),
    ]
    _require_finite(*numeric_values)
    return snapshot


def _checks_snapshot(value: DeterministicChecks) -> DeterministicChecks:
    if not isinstance(value, DeterministicChecks):
        raise ScoringInconclusiveError("deterministic checks must be a DeterministicChecks")
    try:
        if type(value.valid) is not bool:
            raise TypeError("deterministic check validity must be boolean")
        return DeterministicChecks.model_validate(
            value.model_dump(mode="python", warnings="error"), strict=True
        )
    except (TypeError, ValidationError, ValueError) as error:
        raise ScoringInconclusiveError("malformed deterministic checks") from error


def _sealed_snapshot(value: SealedLedger) -> SealedLedger:
    if not isinstance(value, SealedLedger):
        raise ScoringInconclusiveError("sealed ledger must be a SealedLedger")
    try:
        return SealedLedger.model_validate(
            value.model_dump(mode="python", warnings="error"), strict=True
        )
    except (TypeError, ValidationError, ValueError) as error:
        raise ScoringInconclusiveError("malformed sealed ledger") from error


def _replayed_report_snapshot(
    value: ReportEvaluation,
    inputs: ReportScoreInputs,
    rubric: EvaluationRubric,
) -> tuple[ReportEvaluation, SealedLedger]:
    supplied = _report_snapshot(value, rubric)
    if not isinstance(inputs, ReportScoreInputs):
        raise ScoringInconclusiveError("comparison score inputs must be ReportScoreInputs")
    sealed = _sealed_snapshot(inputs.sealed_ledger)
    recomputed = score_report(
        sealed,
        inputs.resolved_grade,
        inputs.deterministic_checks,
        rubric,
        source_record=inputs.source_record,
    )
    if supplied.anonymous_label != recomputed.anonymous_label:
        raise ScoringInconclusiveError(
            "report evaluation and score inputs must bind the same anonymous label"
        )
    if supplied != recomputed:
        raise ScoringInconclusiveError("report evaluation does not match replayed score inputs")
    return recomputed, sealed


def _report_snapshot(value: ReportEvaluation, rubric: EvaluationRubric) -> ReportEvaluation:
    if not isinstance(value, ReportEvaluation):
        raise ScoringInconclusiveError("comparison input must be a ReportEvaluation")
    if not all(
        type(component) is float
        for component in (
            value.critical_recall,
            value.weighted_recall,
            value.claim_precision,
            value.walk_average,
            value.normalized_score,
        )
    ):
        raise ScoringInconclusiveError("report evaluation numeric fields must remain floats")
    if type(value.walk_minimum) is not int:
        raise ScoringInconclusiveError("report walk minimum must remain an integer")
    if type(value.critical_defect) is not bool:
        raise ScoringInconclusiveError("critical defect must remain boolean")
    try:
        snapshot = ReportEvaluation.model_validate(
            value.model_dump(mode="python", warnings="error"), strict=True
        )
    except (TypeError, ValidationError, ValueError) as error:
        raise ScoringInconclusiveError("malformed report evaluation") from error
    _require_finite(
        snapshot.critical_recall,
        snapshot.weighted_recall,
        snapshot.claim_precision,
        snapshot.walk_average,
        snapshot.normalized_score,
    )
    if not 0.0 <= snapshot.critical_recall <= 1.0:
        raise ScoringInconclusiveError("critical recall must be between zero and one")
    if not 0.0 <= snapshot.weighted_recall <= 1.0:
        raise ScoringInconclusiveError("weighted recall must be between zero and one")
    if not 0.0 <= snapshot.claim_precision <= 1.0:
        raise ScoringInconclusiveError("claim precision must be between zero and one")
    if not 1.0 <= snapshot.walk_average <= 4.0:
        raise ScoringInconclusiveError("walk average must be between one and four")
    if not 0.0 <= snapshot.normalized_score <= 100.0:
        raise ScoringInconclusiveError("normalized score must be between zero and one hundred")
    if not 1 <= snapshot.walk_minimum <= 4:
        raise ScoringInconclusiveError("walk minimum must be between one and four")
    if snapshot.walk_minimum > snapshot.walk_average:
        raise ScoringInconclusiveError("walk minimum cannot exceed walk average")
    if snapshot.rubric_fingerprint != model_fingerprint(rubric):
        raise ScoringInconclusiveError("report rubric fingerprint does not match supplied rubric")
    expected_score = 100.0 * (
        rubric.comparison_weights["recall"] * snapshot.weighted_recall
        + rubric.comparison_weights["precision"] * snapshot.claim_precision
        + rubric.comparison_weights["walk"] * (snapshot.walk_average / 4.0)
    )
    if not math.isclose(
        snapshot.normalized_score,
        expected_score,
        rel_tol=0.0,
        abs_tol=1e-12,
    ):
        raise ScoringInconclusiveError("normalized score conflicts with component metrics")
    safety_codes = {
        "CRITICAL_RECALL_BELOW_FLOOR",
        "DETERMINISTIC_CHECKS_INVALID",
    }
    code_requires_critical_defect = bool(safety_codes & set(snapshot.blocking_codes)) or any(
        code.startswith(("UNSUPPORTED_", "OVERSTATED_", "CONTRADICTED_"))
        for code in snapshot.blocking_codes
    )
    if code_requires_critical_defect and not snapshot.critical_defect:
        raise ScoringInconclusiveError("critical defect flag conflicts with safety blocking codes")
    if snapshot.absolute_disposition is AbsoluteDisposition.PASS and snapshot.blocking_codes:
        raise ScoringInconclusiveError("passing report cannot retain blocking codes")
    if snapshot.absolute_disposition is AbsoluteDisposition.PASS and snapshot.critical_defect:
        raise ScoringInconclusiveError("passing report cannot retain a critical defect")
    gate_results = (
        (
            "CRITICAL_RECALL_BELOW_FLOOR",
            snapshot.critical_recall < rubric.critical_recall_floor,
            "critical recall",
        ),
        (
            "WEIGHTED_RECALL_BELOW_FLOOR",
            snapshot.weighted_recall < rubric.weighted_recall_floor,
            "weighted recall",
        ),
        (
            "CLAIM_PRECISION_BELOW_FLOOR",
            snapshot.claim_precision < rubric.claim_precision_floor,
            "claim precision",
        ),
        (
            "WALK_AVERAGE_BELOW_FLOOR",
            snapshot.walk_average < rubric.walk_average_floor,
            "walk average",
        ),
        (
            "WALK_DIMENSION_BELOW_FLOOR",
            snapshot.walk_minimum < rubric.walk_dimension_floor,
            "walk minimum",
        ),
    )
    blocking_code_set = set(snapshot.blocking_codes)
    if snapshot.absolute_disposition in {
        AbsoluteDisposition.PASS,
        AbsoluteDisposition.FAIL,
    }:
        for code, failed, gate_name in gate_results:
            if snapshot.absolute_disposition is AbsoluteDisposition.PASS and failed:
                raise ScoringInconclusiveError(
                    f"passing report {gate_name} does not meet the v1 floor"
                )
            if failed and code not in blocking_code_set:
                raise ScoringInconclusiveError(
                    f"report {gate_name} failure omits its blocking code"
                )
            if not failed and code in blocking_code_set:
                raise ScoringInconclusiveError(
                    f"report {gate_name} blocking code conflicts with its metric"
                )
    if snapshot.absolute_disposition is AbsoluteDisposition.FAIL and not snapshot.blocking_codes:
        raise ScoringInconclusiveError("failing report must retain a blocking code")
    return snapshot


def _raw_rubric_types_valid(rubric: EvaluationRubric) -> bool:
    float_fields = (
        rubric.critical_recall_floor,
        rubric.weighted_recall_floor,
        rubric.claim_precision_floor,
        rubric.walk_average_floor,
        rubric.comparison_margin,
    )
    return (
        all(type(value) is float for value in float_fields)
        and type(rubric.walk_dimension_floor) is int
        and isinstance(rubric.materiality_weights, dict)
        and set(rubric.materiality_weights) == set(Materiality)
        and all(
            type(key) is Materiality and type(value) is int
            for key, value in rubric.materiality_weights.items()
        )
        and isinstance(rubric.comparison_weights, dict)
        and set(rubric.comparison_weights) == {"recall", "precision", "walk"}
        and all(type(value) is float for value in rubric.comparison_weights.values())
    )


def _require_finite(*values: float) -> None:
    if not all(math.isfinite(value) for value in values):
        raise ScoringInconclusiveError("scoring values must be finite")


def _unique_codes(codes: list[str]) -> list[str]:
    return list(dict.fromkeys(codes))
