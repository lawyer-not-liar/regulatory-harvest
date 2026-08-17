from __future__ import annotations

from dataclasses import FrozenInstanceError
from inspect import Parameter, signature
from typing import Literal

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError
from test_attorney_grading import (
    DIMENSIONS,
    claim,
    entry_grade,
    grade,
    material_disputes,
    narrative_scores,
    referee,
    sealed,
)
from test_attorney_ledger import QUOTE, SOURCE_TEXT, admitted_envelope, entry

from regulatory_harvest.evaluation.attorney_admission import build_admission_packet
from regulatory_harvest.evaluation.attorney_grading import resolve_grades
from regulatory_harvest.evaluation.attorney_models import (
    AbsoluteDisposition,
    CandidateGrade,
    ComparativeDisposition,
    ComparisonEvaluation,
    CoverageDisposition,
    DeterministicChecks,
    EntryFindingCode,
    EvaluationIssue,
    EvaluationRubric,
    GradeAlternative,
    IssueSeverity,
    LedgerCategory,
    LedgerCitation,
    LegalLedger,
    Materiality,
    NarrativeFindingCode,
    NarrativeScore,
    OutOfLedgerClaim,
    ReportEvaluation,
    SealedLedger,
    model_fingerprint,
)
from regulatory_harvest.evaluation.attorney_scoring import (
    RUBRIC_V1,
    ReportScoreInputs,
    ScoringInconclusiveError,
    compare_reports,
    score_report,
)
from regulatory_harvest.storage import canonical_json_bytes, sha256_digest


def checks(
    label: Literal["A", "B"] = "A",
    valid: bool = True,
    *,
    critical_codes: list[str] | None = None,
    issues: list[EvaluationIssue] | None = None,
) -> DeterministicChecks:
    return DeterministicChecks(
        anonymous_label=label,
        valid=valid,
        critical_codes=critical_codes or [],
        issues=issues or [],
    )


def resolved(ledger, candidate_grade: CandidateGrade):  # type: ignore[no-untyped-def]
    peer = CandidateGrade.model_validate(candidate_grade.model_dump(mode="python"), strict=True)
    peer.request_fingerprint = (
        "e" * 64 if candidate_grade.request_fingerprint != "e" * 64 else "f" * 64
    )
    return resolve_grades(ledger, candidate_grade, peer, [])


def report_score_fingerprint(payload: dict[str, object]) -> str:
    return sha256_digest(
        canonical_json_bytes(
            {key: value for key, value in payload.items() if key != "score_fingerprint"}
        )
    )


def rehashed_report(report: ReportEvaluation, **updates: object) -> ReportEvaluation:
    payload = report.model_dump(mode="python")
    payload.update(updates)
    payload["score_fingerprint"] = report_score_fingerprint(payload)
    return ReportEvaluation.model_validate(payload, strict=True)


def scoring_source_record() -> dict[str, object]:
    return build_admission_packet(admitted_envelope()).payload


def exact_source_claim(
    *,
    disposition: CoverageDisposition = CoverageDisposition.COMPLETE,
) -> OutOfLedgerClaim:
    source_record = scoring_source_record()
    fingerprint = source_record["source_record_fingerprint"]
    assert isinstance(fingerprint, str)
    span_start = SOURCE_TEXT.index(QUOTE)
    return OutOfLedgerClaim(
        claim_id="exact-claim",
        claim_text="The regulator may impose a separate civil penalty.",
        report_location="p. 2",
        disposition=disposition,
        category=LedgerCategory.DEFINITION,
        materiality=Materiality.SUPPORTING,
        related_ledger_ids=[],
        source_record_fingerprint=fingerprint,
        evidence_basis="source_spans",
        evidence_spans=[
            LedgerCitation(
                source_id="example-statute-1",
                start_char=span_start,
                end_char=span_start + len(QUOTE),
                quote=QUOTE,
            )
        ],
        rationale="The exact common source record supports the claim.",
    )


def test_score_report_requires_the_common_source_record() -> None:
    ledger = sealed(entry("L1"))
    resolved_grade = resolved(ledger, grade(ledger, entry_grade("L1")))

    with pytest.raises(TypeError, match="source_record"):
        score_report(ledger, resolved_grade, checks(), RUBRIC_V1)


def test_score_report_credits_a_verified_exact_source_span() -> None:
    ledger = sealed(entry("L1"))
    candidate_grade = grade(
        ledger,
        entry_grade("L1"),
        claims=[exact_source_claim()],
    )

    evaluation = score_report(
        ledger,
        resolved(ledger, candidate_grade),
        checks(),
        RUBRIC_V1,
        source_record=scoring_source_record(),
    )

    assert evaluation.claim_precision == 1.0
    assert evaluation.absolute_disposition is AbsoluteDisposition.PASS


@pytest.mark.parametrize(
    "mutation",
    ["fingerprint", "source_id", "bounds", "quote"],
)
def test_score_report_rejects_fabricated_or_unbound_exact_evidence(
    mutation: str,
) -> None:
    ledger = sealed(entry("L1"))
    finding = exact_source_claim()
    span = finding.evidence_spans[0]
    if mutation == "fingerprint":
        finding.source_record_fingerprint = "f" * 64
    elif mutation == "source_id":
        span.source_id = "unknown-source"
    elif mutation == "bounds":
        span.end_char = len(SOURCE_TEXT) + 1
    else:
        span.quote = "fabricated exact quote"
    candidate_grade = grade(ledger, entry_grade("L1"), claims=[finding])

    with pytest.raises(ScoringInconclusiveError, match=r"source record|exact source span"):
        score_report(
            ledger,
            resolved(ledger, candidate_grade),
            checks(),
            RUBRIC_V1,
            source_record=scoring_source_record(),
        )


def test_score_report_rejects_invalid_referee_replacement_source_evidence() -> None:
    ledger = sealed(entry("L1"))
    unsupported = claim("claim-a", claim_text="A disputed extra legal statement.")
    supported = exact_source_claim(disposition=CoverageDisposition.PARTIAL)
    supported.claim_id = "claim-b"
    supported.claim_text = unsupported.claim_text
    grader_1 = grade(ledger, entry_grade("L1"), claims=[unsupported])
    grader_2 = grade(
        ledger,
        entry_grade("L1"),
        claims=[supported],
        request_marker="b",
    )
    disputes = material_disputes(ledger, grader_1, grader_2)
    dispute = disputes[0]
    replacement_claim = exact_source_claim()
    replacement_claim.claim_id = dispute.subject_id
    replacement_claim.claim_text = unsupported.claim_text
    replacement_claim.evidence_spans[0].quote = "fabricated exact quote"
    decision = referee(
        dispute,
        "replace",
        replacement=GradeAlternative(
            request_fingerprint="c" * 64,
            out_of_ledger_claim=replacement_claim,
        ),
    )
    decisions = [decision]
    decisions.extend(referee(item, "accept_grader_1") for item in disputes[1:])
    resolved_grade = resolve_grades(ledger, grader_1, grader_2, decisions)

    with pytest.raises(ScoringInconclusiveError, match="exact source span"):
        score_report(
            ledger,
            resolved_grade,
            checks(),
            RUBRIC_V1,
            source_record=scoring_source_record(),
        )


def test_report_score_inputs_are_a_frozen_public_scoring_value() -> None:
    ledger = sealed(entry("L1"))
    score_inputs = ReportScoreInputs(
        sealed_ledger=ledger,
        resolved_grade=resolved(ledger, grade(ledger, entry_grade("L1"))),
        deterministic_checks=checks(),
        source_record=canonical_json_bytes(scoring_source_record()),
    )

    with pytest.raises(FrozenInstanceError):
        score_inputs.sealed_ledger = ledger  # type: ignore[misc]


def test_score_derives_semantic_issue_codes_without_changing_existing_gates() -> None:
    ledger = sealed(entry("critical-duty", materiality=Materiality.CRITICAL))
    narratives = narratives_at((4, 4, 2, 4, 4, 4, 4, 4))
    narratives[2] = narratives[2].model_copy(
        update={"finding_codes": [NarrativeFindingCode.KEY_REQUIREMENTS_ACTION_PLAN]}
    )
    candidate = grade(
        ledger,
        entry_grade(
            "critical-duty",
            CoverageDisposition.MISSING,
            report_location=None,
            finding_codes=[EntryFindingCode.CRITICAL_LEDGER_ENTRY_MISSING],
        ),
        narratives=narratives,
    )

    result, inputs = scored_report(ledger, candidate)

    assert result.issue_codes == [
        "CRITICAL_LEDGER_ENTRY_MISSING",
        "KEY_REQUIREMENTS_ACTION_PLAN",
    ]
    assert result.blocking_codes == [
        "CRITICAL_RECALL_BELOW_FLOOR",
        "WEIGHTED_RECALL_BELOW_FLOOR",
    ]
    forged = rehashed_report(result, issue_codes=[])
    with pytest.raises(ScoringInconclusiveError, match="replayed score inputs"):
        compare_reports(
            forged,
            result.model_copy(update={"anonymous_label": "B"}),
            RUBRIC_V1,
            candidate_inputs=inputs,
            comparator_inputs=inputs,
        )


def test_compare_reports_requires_keyword_only_score_inputs() -> None:
    parameters = signature(compare_reports).parameters

    assert parameters["rubric"].kind is Parameter.POSITIONAL_OR_KEYWORD
    for name in ("candidate_inputs", "comparator_inputs"):
        assert parameters[name].kind is Parameter.KEYWORD_ONLY
        assert parameters[name].default is Parameter.empty


def scored_report(
    ledger: SealedLedger,
    candidate_grade: CandidateGrade,
    deterministic_checks: DeterministicChecks | None = None,
) -> tuple[ReportEvaluation, ReportScoreInputs]:
    resolved_grade = resolved(ledger, candidate_grade)
    score_checks = (
        deterministic_checks
        if deterministic_checks is not None
        else checks(candidate_grade.anonymous_label)
    )
    score_inputs = ReportScoreInputs(
        sealed_ledger=ledger,
        resolved_grade=resolved_grade,
        deterministic_checks=score_checks,
        source_record=canonical_json_bytes(scoring_source_record()),
    )
    return (
        score_report(
            ledger,
            resolved_grade,
            score_checks,
            RUBRIC_V1,
            source_record=scoring_source_record(),
        ),
        score_inputs,
    )


def compare_scored(
    candidate: tuple[ReportEvaluation, ReportScoreInputs],
    comparator: tuple[ReportEvaluation, ReportScoreInputs],
) -> ComparisonEvaluation:
    return compare_reports(
        candidate[0],
        comparator[0],
        RUBRIC_V1,
        candidate_inputs=candidate[1],
        comparator_inputs=comparator[1],
    )


def narratives_at(values: tuple[int, ...]) -> list[NarrativeScore]:
    return [
        NarrativeScore(
            dimension=dimension,  # type: ignore[arg-type]
            score=value,
            rationale="This score is derived from the blinded report fixture.",
            report_passage="The blinded report fixture passage.",
        )
        for dimension, value in zip(DIMENSIONS, values, strict=True)
    ]


def precision_boundary_claims() -> list[OutOfLedgerClaim]:
    return [
        claim(
            f"claim-{index}",
            claim_text=f"Ancillary supported statement number {index}.",
            disposition=(
                CoverageDisposition.PARTIAL if index == 9 else CoverageDisposition.COMPLETE
            ),
            category=LedgerCategory.DEFINITION,
            materiality=Materiality.SUPPORTING,
        )
        for index in range(10)
    ]


def exact_boundary_grade(
    ledger: SealedLedger,
    *,
    label: Literal["A", "B"] = "A",
) -> CandidateGrade:
    return grade(
        ledger,
        entry_grade("critical"),
        entry_grade("material"),
        entry_grade("support-1"),
        entry_grade("support-2", CoverageDisposition.MISSING, report_location=None),
        label=label,
        claims=precision_boundary_claims(),
        narratives=narratives_at((2, 3, 3, 3, 3, 3, 3, 4)),
    )


def test_comparison_rejects_self_hashed_phantom_blocker_against_score_inputs() -> None:
    ledger = sealed(entry("L1"))
    candidate = scored_report(ledger, grade(ledger, entry_grade("L1"), label="A"))
    comparator = scored_report(ledger, grade(ledger, entry_grade("L1"), label="B"))
    forged = rehashed_report(
        comparator[0],
        absolute_disposition=AbsoluteDisposition.FAIL,
        blocking_codes=["PHANTOM_BLOCKER"],
    )

    with pytest.raises(ScoringInconclusiveError, match="replayed score inputs"):
        compare_reports(
            candidate[0],
            forged,
            RUBRIC_V1,
            candidate_inputs=candidate[1],
            comparator_inputs=comparator[1],
        )


def test_comparison_rejects_critical_defect_without_replayed_critical_cause() -> None:
    ledger = sealed(
        entry("critical", materiality=Materiality.CRITICAL),
        entry("material", materiality=Materiality.MATERIAL),
    )
    candidate = scored_report(
        ledger,
        grade(ledger, entry_grade("critical"), entry_grade("material"), label="A"),
    )
    comparator = scored_report(
        ledger,
        grade(
            ledger,
            entry_grade("critical"),
            entry_grade("material", CoverageDisposition.PARTIAL),
            label="B",
        ),
    )
    assert comparator[0].blocking_codes == ["WEIGHTED_RECALL_BELOW_FLOOR"]
    assert comparator[0].critical_defect is False
    forged = rehashed_report(comparator[0], critical_defect=True)

    with pytest.raises(ScoringInconclusiveError, match="replayed score inputs"):
        compare_reports(
            candidate[0],
            forged,
            RUBRIC_V1,
            candidate_inputs=candidate[1],
            comparator_inputs=comparator[1],
        )


@pytest.mark.parametrize(
    "disposition",
    [
        CoverageDisposition.UNSUPPORTED,
        CoverageDisposition.OVERSTATED,
        CoverageDisposition.CONTRADICTED,
    ],
)
@pytest.mark.parametrize(
    ("category", "suffix"),
    [
        (LedgerCategory.STATUS, "STATUS"),
        (LedgerCategory.REQUIREMENT, "OBLIGATION"),
        (LedgerCategory.DEADLINE, "DEADLINE"),
        (LedgerCategory.ENFORCEMENT, "ENFORCEMENT"),
        (LedgerCategory.REMEDY, "REMEDY"),
        (LedgerCategory.PENALTY, "PENALTY"),
    ],
)
def test_material_legal_misstatements_drive_stable_blocking_codes(
    disposition: CoverageDisposition,
    category: LedgerCategory,
    suffix: str,
) -> None:
    ledger = sealed(entry("L1"))
    finding = claim(
        "claim-1",
        disposition=disposition,
        category=category,
        materiality=Materiality.MATERIAL,
    )

    evaluation = score_report(
        ledger,
        resolved(ledger, grade(ledger, entry_grade("L1"), claims=[finding])),
        checks(),
        RUBRIC_V1,
        source_record=scoring_source_record(),
    )

    assert evaluation.absolute_disposition is AbsoluteDisposition.FAIL
    assert f"{disposition.value}_MATERIAL_{suffix}" in evaluation.blocking_codes
    assert evaluation.critical_defect is True


def test_scoring_uses_separate_materiality_weighted_denominators() -> None:
    ledger = sealed(
        entry("critical", materiality=Materiality.CRITICAL),
        entry("support", materiality=Materiality.SUPPORTING),
    )
    finding = claim(
        "claim-1",
        disposition=CoverageDisposition.PARTIAL,
        category=LedgerCategory.STATUS,
        materiality=Materiality.SUPPORTING,
    )
    evaluation = score_report(
        ledger,
        resolved(
            ledger,
            grade(
                ledger,
                entry_grade("critical"),
                entry_grade("support", CoverageDisposition.PARTIAL),
                claims=[finding],
            ),
        ),
        checks(),
        RUBRIC_V1,
        source_record=scoring_source_record(),
    )

    assert evaluation.weighted_recall == 11 / 12
    assert evaluation.claim_precision == 0.5


def test_score_report_populates_complete_canonical_evidence_payload() -> None:
    ledger = sealed(entry("L1", materiality=Materiality.CRITICAL))
    candidate_grade = grade(ledger, entry_grade("L1"))
    resolved_grade = resolved(ledger, candidate_grade)
    deterministic = checks()

    evaluation = score_report(
        ledger,
        resolved_grade,
        deterministic,
        RUBRIC_V1,
        source_record=scoring_source_record(),
    )

    assert evaluation.critical_recall == 1.0
    assert evaluation.walk_minimum == 4
    assert evaluation.ledger_fingerprint == ledger.ledger_fingerprint
    assert evaluation.resolved_grade_fingerprint == resolved_grade.resolution_fingerprint
    assert evaluation.deterministic_checks_fingerprint == model_fingerprint(deterministic)
    assert evaluation.rubric_fingerprint == model_fingerprint(RUBRIC_V1)
    assert evaluation.score_fingerprint == report_score_fingerprint(
        evaluation.model_dump(mode="json")
    )


def test_absent_claims_and_empty_denominators_are_finite_and_safe() -> None:
    ledger = sealed(entry("L1"))

    evaluation = score_report(
        ledger,
        resolved(ledger, grade(ledger, entry_grade("L1"))),
        checks(),
        RUBRIC_V1,
        source_record=scoring_source_record(),
    )

    assert evaluation.claim_precision == 1.0
    assert evaluation.normalized_score == 100.0

    empty_ledger = SealedLedger(
        ledger=LegalLedger(
            case_fingerprint=scoring_source_record()["source_record_fingerprint"],
            entries=[],
        ),
        audit_fingerprint="d" * 64,
        ledger_fingerprint="e" * 64,
    )
    empty_grade = grade(empty_ledger)
    empty_evaluation = score_report(
        empty_ledger,
        resolved(empty_ledger, empty_grade),
        checks(),
        RUBRIC_V1,
        source_record=scoring_source_record(),
    )
    assert empty_evaluation.weighted_recall == 1.0
    assert empty_evaluation.claim_precision == 1.0
    assert empty_evaluation.normalized_score == 100.0


def test_absolute_pass_accepts_every_threshold_at_its_exact_boundary() -> None:
    ledger_entries = [
        entry("critical", materiality=Materiality.CRITICAL),
        entry("material", materiality=Materiality.MATERIAL),
        entry("support-1", materiality=Materiality.SUPPORTING),
        entry("support-2", materiality=Materiality.SUPPORTING),
    ]
    ledger = sealed(*ledger_entries)
    claims = [
        claim(
            f"claim-{index}",
            claim_text=f"Ancillary statement number {index}.",
            disposition=(
                CoverageDisposition.PARTIAL if index == 9 else CoverageDisposition.COMPLETE
            ),
            category=LedgerCategory.DEFINITION,
            materiality=Materiality.SUPPORTING,
        )
        for index in range(10)
    ]
    narratives = [
        NarrativeScore(
            dimension=dimension,  # type: ignore[arg-type]
            score=score,
            rationale="This score exercises the exact rubric boundary.",
            report_passage="The exact rubric boundary passage.",
        )
        for dimension, score in zip(DIMENSIONS, [2, 3, 3, 3, 3, 3, 3, 4], strict=True)
    ]
    candidate_grade = grade(
        ledger,
        entry_grade("critical"),
        entry_grade("material"),
        entry_grade("support-1"),
        entry_grade("support-2", CoverageDisposition.MISSING, report_location=None),
        claims=claims,
        narratives=narratives,
    )

    evaluation = score_report(
        ledger,
        resolved(ledger, candidate_grade),
        checks(),
        RUBRIC_V1,
        source_record=scoring_source_record(),
    )

    assert evaluation.weighted_recall == 0.9
    assert evaluation.claim_precision == 0.95
    assert evaluation.walk_average == 3.0
    assert evaluation.absolute_disposition is AbsoluteDisposition.PASS
    assert evaluation.blocking_codes == []


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        ("recall", "WEIGHTED_RECALL_BELOW_FLOOR"),
        ("precision", "CLAIM_PRECISION_BELOW_FLOOR"),
        ("average", "WALK_AVERAGE_BELOW_FLOOR"),
        ("dimension", "WALK_DIMENSION_BELOW_FLOOR"),
    ],
)
def test_each_absolute_threshold_blocks_immediately_below_its_floor(
    mutation: str,
    expected_code: str,
) -> None:
    ledger = sealed(entry("critical", materiality=Materiality.CRITICAL), entry("material"))
    grades = [entry_grade("critical"), entry_grade("material")]
    claims: list[OutOfLedgerClaim] = []
    narratives = narrative_scores()
    if mutation == "recall":
        grades[1] = entry_grade("material", CoverageDisposition.PARTIAL)
    elif mutation == "precision":
        claims = [claim("claim-1", materiality=Materiality.SUPPORTING)]
    elif mutation == "average":
        narratives = narrative_scores(changed="scanability", changed_score=1)
        for score in narratives[:-1]:
            score.score = 3
    else:
        narratives = narrative_scores(changed="scanability", changed_score=1)

    evaluation = score_report(
        ledger,
        resolved(
            ledger,
            grade(ledger, *grades, claims=claims, narratives=narratives),
        ),
        checks(),
        RUBRIC_V1,
        source_record=scoring_source_record(),
    )

    assert evaluation.absolute_disposition is AbsoluteDisposition.FAIL
    assert expected_code in evaluation.blocking_codes


def test_critical_recall_and_deterministic_failures_override_prose() -> None:
    ledger = sealed(entry("critical", materiality=Materiality.CRITICAL))
    invalid = EvaluationIssue(
        code="REPORT_SCHEMA_INVALID",
        severity=IssueSeverity.ERROR,
        message="The report failed deterministic validation.",
    )
    evaluation = score_report(
        ledger,
        resolved(
            ledger,
            grade(
                ledger,
                entry_grade("critical", CoverageDisposition.PARTIAL),
            ),
        ),
        checks(valid=False, critical_codes=["REPORT_SCHEMA_INVALID"], issues=[invalid]),
        RUBRIC_V1,
        source_record=scoring_source_record(),
    )

    assert evaluation.critical_defect is True
    assert {
        "CRITICAL_RECALL_BELOW_FLOOR",
        "DETERMINISTIC_CHECKS_INVALID",
        "REPORT_SCHEMA_INVALID",
    } <= set(evaluation.blocking_codes)


def test_score_report_rejects_label_mismatch_and_mutated_checks() -> None:
    ledger = sealed(entry("L1"))
    candidate_grade = grade(ledger, entry_grade("L1"))

    with pytest.raises(ScoringInconclusiveError, match="anonymous label"):
        score_report(
            ledger,
            resolved(ledger, candidate_grade),
            checks("B"),
            RUBRIC_V1,
            source_record=scoring_source_record(),
        )

    mutated = checks()
    mutated.valid = "true"  # type: ignore[assignment]
    with pytest.raises(ScoringInconclusiveError, match="deterministic checks"):
        score_report(
            ledger,
            resolved(ledger, candidate_grade),
            mutated,
            RUBRIC_V1,
            source_record=scoring_source_record(),
        )

    with pytest.raises(ScoringInconclusiveError, match="resolved grade"):
        score_report(  # type: ignore[arg-type]
            ledger,
            candidate_grade,
            checks(),
            RUBRIC_V1,
            source_record=scoring_source_record(),
        )

    numeric_mutation = RUBRIC_V1.model_dump(mode="python")
    numeric_mutation["comparison_margin"] = 5
    mutated_rubric = EvaluationRubric.model_construct(**numeric_mutation)
    with pytest.raises(ScoringInconclusiveError, match="rubric"):
        score_report(
            ledger,
            resolved(ledger, candidate_grade),
            checks(),
            mutated_rubric,
            source_record=scoring_source_record(),
        )


def test_one_safe_report_beats_an_unsafe_higher_scoring_report() -> None:
    ledger = sealed(
        entry("critical", materiality=Materiality.CRITICAL),
        entry("material", materiality=Materiality.MATERIAL),
        entry("support-1", materiality=Materiality.SUPPORTING),
        entry("support-2", materiality=Materiality.SUPPORTING),
    )
    unsafe = scored_report(
        ledger,
        grade(
            ledger,
            entry_grade("critical", CoverageDisposition.PARTIAL),
            entry_grade("material"),
            entry_grade("support-1"),
            entry_grade("support-2"),
            label="A",
        ),
    )
    safe = scored_report(ledger, exact_boundary_grade(ledger, label="B"))

    assert unsafe[0].normalized_score > safe[0].normalized_score

    comparison = compare_scored(unsafe, safe)

    assert comparison.winner_label == "B"
    assert comparison.disposition is ComparativeDisposition.COMPARATOR_WIN


def test_one_safe_report_beats_a_noncritical_threshold_failure() -> None:
    ledger = sealed(entry("L1"))
    unsafe_narratives = narrative_scores(changed="scanability", changed_score=1)
    unsafe = scored_report(
        ledger,
        grade(ledger, entry_grade("L1"), label="A", narratives=unsafe_narratives),
    )
    safe = scored_report(
        ledger,
        grade(ledger, entry_grade("L1"), label="B"),
    )

    assert unsafe[0].absolute_disposition is AbsoluteDisposition.FAIL
    assert unsafe[0].critical_defect is False
    assert compare_scored(unsafe, safe).winner_label == "B"


def test_two_noncritical_threshold_failures_are_neither() -> None:
    ledger = sealed(entry("L1"))
    narratives = narrative_scores(changed="scanability", changed_score=1)
    unsafe_a = scored_report(
        ledger,
        grade(ledger, entry_grade("L1"), label="A", narratives=narratives),
    )
    unsafe_b = scored_report(
        ledger,
        grade(
            ledger,
            entry_grade("L1"),
            label="B",
            narratives=narrative_scores(changed="limitations", changed_score=1),
        ),
    )

    assert unsafe_a[0].critical_defect is unsafe_b[0].critical_defect is False
    assert compare_scored(unsafe_a, unsafe_b).disposition is (ComparativeDisposition.NEITHER)


def test_comparison_ties_below_five_and_selects_winner_at_five() -> None:
    ledger = sealed(entry("L1"))
    high = scored_report(
        ledger,
        grade(ledger, entry_grade("L1"), label="A"),
    )
    below = scored_report(
        ledger,
        grade(
            ledger,
            entry_grade("L1"),
            label="B",
            claims=precision_boundary_claims(),
            narratives=narratives_at((2, 3, 4, 4, 4, 4, 4, 4)),
        ),
    )
    boundary = scored_report(
        ledger,
        grade(
            ledger,
            entry_grade("L1"),
            label="B",
            claims=precision_boundary_claims(),
            narratives=narratives_at((2, 3, 3, 4, 4, 4, 4, 4)),
        ),
    )

    assert high[0].normalized_score - below[0].normalized_score == 4.0625
    assert compare_scored(high, below).disposition is ComparativeDisposition.TIE
    at_boundary = compare_scored(high, boundary)
    assert at_boundary.winner_label == "A"
    assert at_boundary.score_difference == 5.0


@given(
    narrative_values=st.sampled_from(
        [
            (4, 4, 4, 4, 4, 4, 4, 4),
            (3, 4, 4, 4, 4, 4, 4, 4),
            (3, 3, 4, 4, 4, 4, 4, 4),
            (2, 4, 4, 4, 4, 4, 4, 4),
            (2, 3, 4, 4, 4, 4, 4, 4),
        ]
    ),
    at_precision_boundary=st.booleans(),
)
def test_every_generated_safe_score_difference_below_margin_is_a_tie(
    narrative_values: tuple[int, ...],
    at_precision_boundary: bool,
) -> None:
    ledger = sealed(entry("L1"))
    first = scored_report(
        ledger,
        grade(ledger, entry_grade("L1"), label="A"),
    )
    second = scored_report(
        ledger,
        grade(
            ledger,
            entry_grade("L1"),
            label="B",
            claims=precision_boundary_claims() if at_precision_boundary else [],
            narratives=narratives_at(narrative_values),
        ),
    )

    difference = first[0].normalized_score - second[0].normalized_score
    assert second[0].absolute_disposition is AbsoluteDisposition.PASS
    assert 0.0 <= difference < RUBRIC_V1.comparison_margin

    assert compare_scored(first, second).disposition is ComparativeDisposition.TIE


def test_both_unsafe_reports_are_neither() -> None:
    ledger = sealed(entry("critical", materiality=Materiality.CRITICAL))
    unsafe_a = scored_report(
        ledger,
        grade(
            ledger,
            entry_grade("critical", CoverageDisposition.MISSING, report_location=None),
            label="A",
        ),
    )
    unsafe_b = scored_report(
        ledger,
        grade(
            ledger,
            entry_grade("critical", CoverageDisposition.MISSING, report_location=None),
            label="B",
        ),
    )

    comparison = compare_scored(unsafe_a, unsafe_b)

    assert comparison.disposition is ComparativeDisposition.NEITHER
    assert comparison.winner_label is None


def test_comparison_rejects_same_labels_and_nonfinite_mutated_scores() -> None:
    ledger = sealed(entry("L1"))
    candidate = scored_report(
        ledger,
        grade(ledger, entry_grade("L1"), label="A"),
    )
    comparator = scored_report(
        ledger,
        grade(ledger, entry_grade("L1"), label="B"),
    )

    with pytest.raises(ScoringInconclusiveError, match="distinct anonymous labels"):
        compare_scored(candidate, candidate)

    mutated = comparator[0].model_copy(deep=True)
    mutated.normalized_score = float("nan")
    with pytest.raises(ScoringInconclusiveError, match=r"malformed|finite"):
        compare_reports(
            candidate[0],
            mutated,
            RUBRIC_V1,
            candidate_inputs=candidate[1],
            comparator_inputs=comparator[1],
        )

    finite_mutation = rehashed_report(
        comparator[0],
        normalized_score=99.0,
    )
    with pytest.raises(ScoringInconclusiveError, match="normalized score"):
        compare_reports(
            candidate[0],
            finite_mutation,
            RUBRIC_V1,
            candidate_inputs=candidate[1],
            comparator_inputs=comparator[1],
        )

    integer_mutation = comparator[0].model_copy(deep=True)
    integer_mutation.weighted_recall = 1  # type: ignore[assignment]
    with pytest.raises(ScoringInconclusiveError, match="numeric fields"):
        compare_reports(
            candidate[0],
            integer_mutation,
            RUBRIC_V1,
            candidate_inputs=candidate[1],
            comparator_inputs=comparator[1],
        )

    with pytest.raises(ScoringInconclusiveError, match="same anonymous label"):
        compare_reports(
            candidate[0],
            comparator[0],
            RUBRIC_V1,
            candidate_inputs=candidate[1],
            comparator_inputs=candidate[1],
        )


def test_comparison_rejects_internally_inconsistent_mutated_safety_state() -> None:
    ledger = sealed(entry("critical", materiality=Materiality.CRITICAL))
    unsafe = scored_report(
        ledger,
        grade(
            ledger,
            entry_grade("critical", CoverageDisposition.MISSING, report_location=None),
            label="A",
        ),
    )
    safe = scored_report(
        ledger,
        grade(ledger, entry_grade("critical"), label="B"),
    )
    forged = rehashed_report(unsafe[0], critical_defect=False)

    with pytest.raises(ScoringInconclusiveError, match="critical defect"):
        compare_reports(
            forged,
            safe[0],
            RUBRIC_V1,
            candidate_inputs=unsafe[1],
            comparator_inputs=safe[1],
        )


@pytest.mark.parametrize(
    ("updates", "expected_message"),
    [
        ({"critical_recall": 0.5}, "critical recall"),
        (
            {"weighted_recall": 0.89, "normalized_score": 95.05},
            "weighted recall",
        ),
        (
            {"claim_precision": 0.94, "normalized_score": 98.5},
            "claim precision",
        ),
        (
            {"walk_average": 2.99, "walk_minimum": 2, "normalized_score": 92.425},
            "walk average",
        ),
        ({"walk_minimum": 1}, "walk minimum"),
    ],
)
def test_comparison_rejects_self_hashed_forged_pass_for_every_v1_gate(
    updates: dict[str, object],
    expected_message: str,
) -> None:
    ledger = sealed(entry("L1"))
    first = scored_report(ledger, grade(ledger, entry_grade("L1"), label="A"))
    second = scored_report(ledger, grade(ledger, entry_grade("L1"), label="B"))
    forged = rehashed_report(second[0], **updates)

    with pytest.raises(ScoringInconclusiveError, match=expected_message):
        compare_reports(
            first[0],
            forged,
            RUBRIC_V1,
            candidate_inputs=first[1],
            comparator_inputs=second[1],
        )


def test_comparison_rejects_wrong_rubric_and_cross_ledger_score_bindings() -> None:
    ledger = sealed(entry("L1"))
    first = scored_report(ledger, grade(ledger, entry_grade("L1"), label="A"))
    second = scored_report(ledger, grade(ledger, entry_grade("L1"), label="B"))
    wrong_rubric = rehashed_report(second[0], rubric_fingerprint="f" * 64)
    with pytest.raises(ScoringInconclusiveError, match="rubric fingerprint"):
        compare_reports(
            first[0],
            wrong_rubric,
            RUBRIC_V1,
            candidate_inputs=first[1],
            comparator_inputs=second[1],
        )

    wrong_ledger = rehashed_report(second[0], ledger_fingerprint="f" * 64)
    with pytest.raises(ScoringInconclusiveError, match="replayed score inputs"):
        compare_reports(
            first[0],
            wrong_ledger,
            RUBRIC_V1,
            candidate_inputs=first[1],
            comparator_inputs=second[1],
        )

    other_ledger = sealed(entry("L2"))
    cross_ledger = scored_report(
        other_ledger,
        grade(other_ledger, entry_grade("L2"), label="B"),
    )
    with pytest.raises(ScoringInconclusiveError, match="sealed ledger fingerprint"):
        compare_scored(first, cross_ledger)

    impossible_walk = rehashed_report(
        second[0],
        walk_average=3.0,
        walk_minimum=4,
        normalized_score=92.5,
    )
    with pytest.raises(ScoringInconclusiveError, match=r"walk minimum.*average"):
        compare_reports(
            first[0],
            impossible_walk,
            RUBRIC_V1,
            candidate_inputs=first[1],
            comparator_inputs=second[1],
        )


def test_comparison_requires_exact_shared_sealed_ledger_snapshot() -> None:
    first_ledger = sealed(entry("L1"))
    second_ledger = sealed(
        entry(
            "L1",
            materiality_rationale="A different rationale changes the strict ledger snapshot.",
        )
    )
    second_ledger.ledger_fingerprint = first_ledger.ledger_fingerprint
    first = scored_report(
        first_ledger,
        grade(first_ledger, entry_grade("L1"), label="A"),
    )
    second = scored_report(
        second_ledger,
        grade(second_ledger, entry_grade("L1"), label="B"),
    )

    assert first[0].ledger_fingerprint == second[0].ledger_fingerprint
    with pytest.raises(ScoringInconclusiveError, match="strict sealed ledger snapshot"):
        compare_scored(first, second)


@pytest.mark.parametrize(
    "terminal_disposition",
    [AbsoluteDisposition.CASE_INVALID, AbsoluteDisposition.INCONCLUSIVE],
)
def test_comparison_rejects_non_scored_terminal_summary(
    terminal_disposition: AbsoluteDisposition,
) -> None:
    ledger = sealed(entry("L1"))
    first = scored_report(ledger, grade(ledger, entry_grade("L1"), label="A"))
    second = scored_report(ledger, grade(ledger, entry_grade("L1"), label="B"))
    forged = rehashed_report(second[0], absolute_disposition=terminal_disposition)

    with pytest.raises(ScoringInconclusiveError, match="replayed score inputs"):
        compare_reports(
            first[0],
            forged,
            RUBRIC_V1,
            candidate_inputs=first[1],
            comparator_inputs=second[1],
        )


@pytest.mark.parametrize("critical", [False, True])
def test_comparison_accepts_dynamic_blocker_only_when_derived_from_checks(
    critical: bool,
) -> None:
    ledger = sealed(entry("L1"))
    first = scored_report(ledger, grade(ledger, entry_grade("L1"), label="A"))
    code = "DYNAMIC_CRITICAL_CODE" if critical else "DYNAMIC_REPORT_ERROR"
    deterministic = checks(
        "B",
        critical_codes=[code] if critical else [],
        issues=(
            []
            if critical
            else [
                EvaluationIssue(
                    code=code,
                    severity=IssueSeverity.ERROR,
                    message="A dynamic deterministic check failed.",
                )
            ]
        ),
    )
    second = scored_report(
        ledger,
        grade(ledger, entry_grade("L1"), label="B"),
        deterministic,
    )

    assert second[0].blocking_codes == [code]
    assert second[0].critical_defect is critical
    comparison = compare_scored(first, second)
    assert comparison.disposition is ComparativeDisposition.REGULATORY_HARVEST_WIN
    assert comparison.winner_label == "A"


def test_comparison_allows_same_grade_request_fingerprint_at_pure_score_layer() -> None:
    """Task 5 JudgeCallRecord evidence, not score comparison, proves independence."""
    ledger = sealed(entry("L1"))
    candidate_grade = grade(
        ledger,
        entry_grade("L1"),
        label="A",
        request_marker="a",
    )
    comparator_grade = grade(
        ledger,
        entry_grade("L1"),
        label="B",
        request_marker="a",
    )
    candidate = scored_report(
        ledger,
        candidate_grade,
    )
    comparator = scored_report(
        ledger,
        comparator_grade,
    )

    assert candidate_grade.request_fingerprint == comparator_grade.request_fingerprint
    assert compare_scored(candidate, comparator).disposition is (ComparativeDisposition.TIE)


def test_rubric_v1_is_immutable_and_rejects_mutated_equivalents() -> None:
    ledger = sealed(entry("L1"))
    candidate_grade = resolved(ledger, grade(ledger, entry_grade("L1")))

    with pytest.raises(ValidationError):
        RUBRIC_V1.comparison_margin = 4.0
    with pytest.raises(TypeError):
        RUBRIC_V1.comparison_weights["recall"] = 0.50

    mutated = EvaluationRubric.model_validate(RUBRIC_V1.model_dump(mode="python"))
    mutated.comparison_weights["recall"] = 0.50
    with pytest.raises(ScoringInconclusiveError, match="mutated"):
        score_report(
            ledger,
            candidate_grade,
            checks(),
            mutated,
            source_record=scoring_source_record(),
        )
