from __future__ import annotations

from typing import Literal

import pytest
from test_attorney_ledger import (
    QUOTE,
    SOURCE_TEXT,
    admitted_envelope,
    at_order,
    audit,
    entry,
    seal_ledger,
    source_record_fingerprint,
    valid_ledger,
)

from regulatory_harvest.evaluation.attorney_grading import (
    GradeInconclusiveError,
    GradeResolution,
    _resolution_fingerprint,
    disposition_credit,
    material_disputes,
    resolve_grades,
    strict_resolved_grade_snapshot,
    validate_grade,
)
from regulatory_harvest.evaluation.attorney_models import (
    CandidateGrade,
    CoverageDisposition,
    EntryFindingCode,
    EntryGrade,
    GradeAlternative,
    GradeDispute,
    LedgerCategory,
    LedgerCitation,
    Materiality,
    NarrativeFindingCode,
    NarrativeScore,
    OutOfLedgerClaim,
    RefereeDecision,
    SealedLedger,
    model_fingerprint,
)

DIMENSIONS = (
    "executive_summary",
    "regulatory_walk",
    "key_requirements",
    "penalties_enforcement",
    "qualification_placement",
    "requirements_workplan_boundary",
    "limitations",
    "scanability",
)


def sealed(*entries) -> SealedLedger:  # type: ignore[no-untyped-def]
    positioned = [at_order(value, index) for index, value in enumerate(entries)]
    return seal_ledger(admitted_envelope(), valid_ledger(*positioned), audit(), None)


def narrative_scores(*, changed: str | None = None, changed_score: int = 4) -> list[NarrativeScore]:
    return [
        NarrativeScore(
            dimension=dimension,  # type: ignore[arg-type]
            score=changed_score if dimension == changed else 4,
            rationale=f"The {dimension} dimension is assessed from the blinded report.",
            report_passage="The blinded report passage.",
        )
        for dimension in DIMENSIONS
    ]


def grade(
    ledger: SealedLedger,
    *grades: EntryGrade,
    label: Literal["A", "B"] = "A",
    request_marker: str = "a",
    claims: list[OutOfLedgerClaim] | None = None,
    narratives: list[NarrativeScore] | None = None,
) -> CandidateGrade:
    return CandidateGrade(
        request_fingerprint=request_marker * 64,
        anonymous_label=label,
        ledger_fingerprint=ledger.ledger_fingerprint,
        entry_grades=list(grades),
        out_of_ledger_claims=claims or [],
        narrative_scores=narratives or narrative_scores(),
    )


def entry_grade(
    ledger_id: str,
    disposition: CoverageDisposition = CoverageDisposition.COMPLETE,
    *,
    rationale: str = "The report accurately covers this legal proposition.",
    report_location: str | None = "p. 1",
    finding_codes: list[EntryFindingCode] | None = None,
) -> EntryGrade:
    return EntryGrade(
        ledger_id=ledger_id,
        disposition=disposition,
        rationale=rationale,
        report_location=report_location,
        report_passage=(
            None
            if disposition is CoverageDisposition.MISSING
            else "The report passage."
        ),
        finding_codes=finding_codes or [],
    )


def claim(
    claim_id: str,
    *,
    claim_text: str = "The regulator may impose a separate civil penalty.",
    report_location: str = "p. 2",
    disposition: CoverageDisposition = CoverageDisposition.UNSUPPORTED,
    category: LedgerCategory = LedgerCategory.PENALTY,
    materiality: Materiality = Materiality.MATERIAL,
    related_ledger_ids: list[str] | None = None,
    rationale: str = "The assertion is not supported by the sealed legal ledger.",
) -> OutOfLedgerClaim:
    source_bound = disposition is not CoverageDisposition.UNSUPPORTED
    span_start = SOURCE_TEXT.index(QUOTE)
    return OutOfLedgerClaim(
        claim_id=claim_id,
        claim_text=claim_text,
        report_location=report_location,
        disposition=disposition,
        category=category,
        materiality=materiality,
        related_ledger_ids=related_ledger_ids or [],
        source_record_fingerprint=ledger_source_fingerprint(),
        evidence_basis="source_spans" if source_bound else "closed_universe_absence",
        evidence_spans=(
            [
                LedgerCitation(
                    source_id="example-statute-1",
                    start_char=span_start,
                    end_char=span_start + len(QUOTE),
                    quote=QUOTE,
                )
            ]
            if source_bound
            else []
        ),
        rationale=rationale,
    )


def ledger_source_fingerprint() -> str:
    return source_record_fingerprint(admitted_envelope())


def referee(
    dispute: GradeDispute,
    resolution: Literal["accept_grader_1", "accept_grader_2", "replace"],
    *,
    replacement: GradeAlternative | None = None,
    fingerprint: str | None = None,
) -> RefereeDecision:
    return RefereeDecision(
        dispute_id=dispute.dispute_id,
        selected_grade_resolution=resolution,
        grade_dispute_fingerprint=fingerprint or model_fingerprint(dispute),
        replacement_grade_alternative=replacement,
        rationale="The referee selected the outcome supported by the dispute record.",
    )


def test_grade_must_dispose_every_applicable_ledger_entry_once() -> None:
    ledger = sealed(entry("L1"), entry("L2"))

    issues = validate_grade(ledger, grade(ledger, entry_grade("L1")))

    assert {issue.code for issue in issues} == {"GRADE_LEDGER_ENTRY_MISSING"}


@pytest.mark.parametrize(
    ("ledger_entry", "finding", "disposition"),
    [
        (
            entry("critical-duty", materiality=Materiality.CRITICAL),
            EntryFindingCode.CRITICAL_LEDGER_ENTRY_MISSING,
            CoverageDisposition.MISSING,
        ),
        (
            entry(
                "exception",
                category=LedgerCategory.EXCEPTION,
                materiality=Materiality.MATERIAL,
            ).model_copy(update={"conditions": ["The records are sealed."]}),
            EntryFindingCode.MATERIAL_EXCEPTION_MISSING,
            CoverageDisposition.MISSING,
        ),
        (
            entry(
                "partial-exception",
                category=LedgerCategory.EXCEPTION,
                materiality=Materiality.MATERIAL,
            ).model_copy(update={"conditions": ["The records are sealed."]}),
            EntryFindingCode.MATERIAL_EXCEPTION_MISSING,
            CoverageDisposition.PARTIAL,
        ),
        (
            entry(
                "penalty",
                category=LedgerCategory.PENALTY,
                materiality=Materiality.MATERIAL,
                relationship_ids=["critical-duty"],
                consequence="A civil penalty may be imposed.",
            ),
            EntryFindingCode.CONSEQUENCE_TRIGGER_DETACHED,
            CoverageDisposition.CONTRADICTED,
        ),
    ],
)
def test_grade_accepts_only_contextual_entry_semantic_findings(
    ledger_entry,  # type: ignore[no-untyped-def]
    finding: EntryFindingCode,
    disposition: CoverageDisposition,
) -> None:
    entries = [entry("critical-duty", materiality=Materiality.CRITICAL)]
    if ledger_entry.ledger_id != "critical-duty":
        entries.append(ledger_entry)
    ledger = sealed(*entries)
    entry_grades = []
    for item in entries:
        mutated = item.ledger_id == ledger_entry.ledger_id
        entry_grades.append(
            entry_grade(
                item.ledger_id,
                disposition if mutated else CoverageDisposition.COMPLETE,
                report_location=(
                    None if mutated and disposition is CoverageDisposition.MISSING else "p. 1"
                ),
                finding_codes=[finding] if mutated else [],
            )
        )

    assert validate_grade(ledger, grade(ledger, *entry_grades)) == []


@pytest.mark.parametrize(
    ("finding", "ledger_entry", "disposition"),
    [
        (
            EntryFindingCode.CRITICAL_LEDGER_ENTRY_MISSING,
            entry("material-duty", materiality=Materiality.MATERIAL),
            CoverageDisposition.MISSING,
        ),
        (
            EntryFindingCode.MATERIAL_EXCEPTION_MISSING,
            entry("critical-duty", materiality=Materiality.CRITICAL),
            CoverageDisposition.PARTIAL,
        ),
        (
            EntryFindingCode.MATERIAL_EXCEPTION_MISSING,
            entry(
                "complete-exception",
                category=LedgerCategory.EXCEPTION,
                materiality=Materiality.CRITICAL,
            ).model_copy(update={"conditions": ["The records are sealed."]}),
            CoverageDisposition.COMPLETE,
        ),
        (
            EntryFindingCode.MATERIAL_EXCEPTION_MISSING,
            entry(
                "overstated-exception",
                category=LedgerCategory.EXCEPTION,
                materiality=Materiality.MATERIAL,
            ).model_copy(update={"conditions": ["The records are sealed."]}),
            CoverageDisposition.OVERSTATED,
        ),
        (
            EntryFindingCode.MATERIAL_EXCEPTION_MISSING,
            entry(
                "supporting-exception",
                category=LedgerCategory.EXCEPTION,
                materiality=Materiality.SUPPORTING,
            ).model_copy(update={"conditions": ["The records are sealed."]}),
            CoverageDisposition.PARTIAL,
        ),
        (
            EntryFindingCode.CONSEQUENCE_TRIGGER_DETACHED,
            entry("critical-duty", materiality=Materiality.CRITICAL),
            CoverageDisposition.PARTIAL,
        ),
    ],
)
def test_grade_rejects_context_inconsistent_entry_semantic_findings(
    finding: EntryFindingCode,
    ledger_entry,  # type: ignore[no-untyped-def]
    disposition: CoverageDisposition,
) -> None:
    ledger = sealed(ledger_entry)
    report_location = None if disposition is CoverageDisposition.MISSING else "p. 1"

    issues = validate_grade(
        ledger,
        grade(
            ledger,
            entry_grade(
                ledger_entry.ledger_id,
                disposition,
                report_location=report_location,
                finding_codes=[finding],
            ),
        ),
    )

    assert {issue.code for issue in issues} == {"GRADE_ENTRY_FINDING_CONTEXT_INVALID"}


def test_invalid_entry_finding_context_names_only_the_safe_subject_and_contract() -> None:
    """A wrong finding branch must expose its repairable anonymous-safe context."""
    ledger = sealed(entry("notice-duty", materiality=Materiality.CRITICAL))

    issues = validate_grade(
        ledger,
        grade(
            ledger,
            entry_grade(
                "notice-duty",
                CoverageDisposition.PARTIAL,
                finding_codes=[EntryFindingCode.MATERIAL_EXCEPTION_MISSING],
            ),
        ),
    )

    assert [issue.message for issue in issues] == [
        "ledger_id=notice-duty finding_code=MATERIAL_EXCEPTION_MISSING "
        "allowed_context=disposition in [MISSING, PARTIAL]; category=exception; "
        "materiality in [critical, material]."
    ]
    assert issues[0].related_ids == ["notice-duty"]


def test_all_invalid_entry_finding_contexts_remain_distinct_and_deterministic() -> None:
    """Each invalid code needs its own repair context even on the same ledger entry."""
    ledger = sealed(entry("notice-duty", materiality=Materiality.CRITICAL))
    finding_codes = [
        EntryFindingCode.CRITICAL_LEDGER_ENTRY_MISSING,
        EntryFindingCode.MATERIAL_EXCEPTION_MISSING,
        EntryFindingCode.CONSEQUENCE_TRIGGER_DETACHED,
    ]

    issues = validate_grade(
        ledger,
        grade(
            ledger,
            entry_grade(
                "notice-duty",
                CoverageDisposition.COMPLETE,
                finding_codes=finding_codes,
            ),
        ),
    )

    assert [issue.code for issue in issues] == [
        "GRADE_ENTRY_FINDING_CONTEXT_INVALID",
        "GRADE_ENTRY_FINDING_CONTEXT_INVALID",
        "GRADE_ENTRY_FINDING_CONTEXT_INVALID",
    ]
    assert [issue.message for issue in issues] == [
        "ledger_id=notice-duty finding_code=CRITICAL_LEDGER_ENTRY_MISSING "
        "allowed_context=disposition in [MISSING]; materiality in [critical].",
        "ledger_id=notice-duty finding_code=MATERIAL_EXCEPTION_MISSING "
        "allowed_context=disposition in [MISSING, PARTIAL]; category=exception; "
        "materiality in [critical, material].",
        "ledger_id=notice-duty finding_code=CONSEQUENCE_TRIGGER_DETACHED "
        "allowed_context=disposition in [PARTIAL, OVERSTATED, CONTRADICTED]; category in "
        "[enforcement, penalty, remedy]; consequence required; trigger or relationship_ids "
        "required.",
    ]
    assert [issue.related_ids for issue in issues] == [["notice-duty"]] * 3


def test_grade_rejects_duplicate_or_unknown_semantic_findings() -> None:
    ledger = sealed(entry("critical-duty", materiality=Materiality.CRITICAL))
    duplicate = grade(
        ledger,
        entry_grade(
            "critical-duty",
            CoverageDisposition.MISSING,
            report_location=None,
            finding_codes=[
                EntryFindingCode.CRITICAL_LEDGER_ENTRY_MISSING,
                EntryFindingCode.CRITICAL_LEDGER_ENTRY_MISSING,
            ],
        ),
    )
    unknown = grade(ledger, entry_grade("critical-duty"))
    unknown.entry_grades[0].finding_codes = ["UNKNOWN"]  # type: ignore[list-item]

    assert {issue.code for issue in validate_grade(ledger, duplicate)} == {
        "GRADE_ENTRY_FINDING_DUPLICATE"
    }
    assert {issue.code for issue in validate_grade(ledger, unknown)} == {"GRADE_MALFORMED"}


def test_narrative_finding_disagreement_requires_referee_and_survives_resolution() -> None:
    ledger = sealed(entry("critical-duty", materiality=Materiality.CRITICAL))
    first_narratives = narrative_scores(changed="key_requirements", changed_score=2)
    first_narratives[2] = first_narratives[2].model_copy(
        update={"finding_codes": [NarrativeFindingCode.KEY_REQUIREMENTS_ACTION_PLAN]}
    )
    second_narratives = narrative_scores(changed="key_requirements", changed_score=2)
    first = grade(ledger, entry_grade("critical-duty"), narratives=first_narratives)
    second = grade(
        ledger,
        entry_grade("critical-duty"),
        request_marker="b",
        narratives=second_narratives,
    )
    disputes = material_disputes(ledger, first, second)

    assert [dispute.subject_id for dispute in disputes] == ["key_requirements"]
    with pytest.raises(GradeInconclusiveError, match="requires referee"):
        resolve_grades(ledger, first, second)
    resolved = resolve_grades(ledger, first, second, referee(disputes[0], "accept_grader_1"))
    assert resolved.narrative_scores[2].finding_codes == [
        NarrativeFindingCode.KEY_REQUIREMENTS_ACTION_PLAN
    ]
    assert strict_resolved_grade_snapshot(ledger, resolved) == resolved


@pytest.mark.parametrize(
    ("disposition", "expected"),
    [
        (CoverageDisposition.COMPLETE, 1.0),
        (CoverageDisposition.PARTIAL, 0.5),
        (CoverageDisposition.MISSING, 0.0),
        (CoverageDisposition.OVERSTATED, 0.0),
        (CoverageDisposition.CONTRADICTED, 0.0),
        (CoverageDisposition.UNSUPPORTED, 0.0),
        (CoverageDisposition.NOT_APPLICABLE, 0.0),
    ],
)
def test_every_coverage_disposition_has_exact_rubric_credit(
    disposition: CoverageDisposition,
    expected: float,
) -> None:
    assert disposition_credit(disposition) == expected


def test_grade_rejects_unknown_and_post_construction_duplicate_ledger_ids() -> None:
    ledger = sealed(entry("L1"), entry("L2"))
    duplicate = grade(ledger, entry_grade("L1"), entry_grade("outside"))
    duplicate.entry_grades.append(entry_grade("L1"))

    assert {issue.code for issue in validate_grade(ledger, duplicate)} == {
        "GRADE_DUPLICATE_LEDGER_ID",
        "GRADE_LEDGER_ENTRY_MISSING",
        "GRADE_LEDGER_ENTRY_UNKNOWN",
    }


def test_grade_rejects_not_applicable_without_contract_legal_basis() -> None:
    ledger = sealed(entry("L1"))

    issues = validate_grade(
        ledger,
        grade(ledger, entry_grade("L1", CoverageDisposition.NOT_APPLICABLE)),
    )

    assert {issue.code for issue in issues} == {"GRADE_NOT_APPLICABLE_UNSUPPORTED"}


def test_grade_requires_report_location_for_a_report_content_finding() -> None:
    ledger = sealed(entry("L1"))

    issues = validate_grade(
        ledger,
        grade(
            ledger,
            entry_grade(
                "L1",
                CoverageDisposition.CONTRADICTED,
                report_location=None,
            ),
        ),
    )

    assert {issue.code for issue in issues} == {"GRADE_REPORT_LOCATION_MISSING"}

    missing_with_location = grade(
        ledger,
        entry_grade(
            "L1",
            CoverageDisposition.MISSING,
            report_location="p. 1",
        ),
    )
    assert {issue.code for issue in validate_grade(ledger, missing_with_location)} == {
        "GRADE_REPORT_LOCATION_UNEXPECTED"
    }


def test_grade_requires_all_eight_narrative_dimensions_once() -> None:
    ledger = sealed(entry("L1"))
    candidate_grade = grade(ledger, entry_grade("L1"))
    candidate_grade.narrative_scores.pop()

    issues = validate_grade(ledger, candidate_grade)

    assert {issue.code for issue in issues} == {"GRADE_NARRATIVE_DIMENSION_MISSING"}


def test_grade_rejects_strict_post_construction_score_and_boolean_mutations() -> None:
    ledger = sealed(entry("L1"))
    mutated_score = grade(ledger, entry_grade("L1"))
    mutated_score.narrative_scores[0].score = "4"  # type: ignore[assignment]

    assert {issue.code for issue in validate_grade(ledger, mutated_score)} == {"GRADE_MALFORMED"}

    mutated_enum = grade(ledger, entry_grade("L1"))
    mutated_enum.entry_grades[0].disposition = "COMPLETE"  # type: ignore[assignment]
    assert {issue.code for issue in validate_grade(ledger, mutated_enum)} == {"GRADE_MALFORMED"}


def test_grade_validates_claim_relationships_disposition_and_ledger_binding() -> None:
    ledger = sealed(entry("L1"))
    candidate_grade = grade(
        ledger,
        entry_grade("L1"),
        claims=[
            claim(
                "claim-1",
                disposition=CoverageDisposition.NOT_APPLICABLE,
                related_ledger_ids=["missing"],
            )
        ],
    )
    candidate_grade.ledger_fingerprint = "b" * 64

    assert {issue.code for issue in validate_grade(ledger, candidate_grade)} == {
        "GRADE_LEDGER_FINGERPRINT_MISMATCH",
        "GRADE_OUT_OF_LEDGER_DISPOSITION_INVALID",
        "GRADE_OUT_OF_LEDGER_RELATIONSHIP_UNKNOWN",
    }


def test_referee_replacement_cannot_introduce_positive_credit_absence_binding() -> None:
    ledger = sealed(entry("L1"))
    grader_1 = grade(ledger, entry_grade("L1"), claims=[claim("claim-1")])
    grader_2 = grade(
        ledger,
        entry_grade("L1"),
        claims=[claim("claim-2", disposition=CoverageDisposition.PARTIAL)],
        request_marker="b",
    )
    dispute = material_disputes(ledger, grader_1, grader_2)[0]
    replacement = GradeAlternative(
        request_fingerprint="c" * 64,
        out_of_ledger_claim=claim(
            dispute.subject_id,
            disposition=CoverageDisposition.PARTIAL,
        ),
    )
    decision = referee(dispute, "replace", replacement=replacement)
    assert decision.replacement_grade_alternative is not None
    assert decision.replacement_grade_alternative.out_of_ledger_claim is not None
    replacement_claim = decision.replacement_grade_alternative.out_of_ledger_claim
    replacement_claim.evidence_basis = "closed_universe_absence"
    replacement_claim.evidence_spans = []

    with pytest.raises(GradeInconclusiveError, match="malformed referee decision"):
        resolve_grades(ledger, grader_1, grader_2, [decision])


def test_grade_rejects_ambiguous_duplicate_claim_identity_even_with_unique_ids() -> None:
    ledger = sealed(entry("L1"))
    candidate_grade = grade(
        ledger,
        entry_grade("L1"),
        claims=[claim("claim-1"), claim("claim-2", disposition=CoverageDisposition.PARTIAL)],
    )

    issues = validate_grade(ledger, candidate_grade)

    assert {issue.code for issue in issues} == {"GRADE_OUT_OF_LEDGER_CLAIM_AMBIGUOUS"}


def test_material_disputes_use_the_public_contract_and_authoritative_materiality() -> None:
    ledger = sealed(entry("L1"), entry("L2", materiality=Materiality.CRITICAL))
    grader_1 = grade(
        ledger,
        entry_grade("L1"),
        entry_grade("L2"),
        request_marker="a",
    )
    grader_2 = grade(
        ledger,
        entry_grade("L1"),
        entry_grade("L2", CoverageDisposition.PARTIAL),
        request_marker="b",
    )

    disputes = material_disputes(ledger, grader_1, grader_2)

    assert len(disputes) == 1
    dispute = disputes[0]
    assert isinstance(dispute, GradeDispute)
    assert dispute.dispute_id == "grade-entry-L2"
    assert dispute.kind == "entry_grade"
    assert dispute.materiality is Materiality.CRITICAL
    assert dispute.grader_1.request_fingerprint == grader_1.request_fingerprint
    assert dispute.grader_2.request_fingerprint == grader_2.request_fingerprint
    assert dispute.grader_2.entry_grade == grader_2.entry_grades[1]
    serialized = dispute.model_dump_json()
    assert "L1" not in serialized
    assert "candidate_id" not in serialized
    assert "comparator" not in serialized
    assert "regulatory_harvest" not in serialized


def test_rationale_only_differences_resolve_without_referee_and_remain_auditable() -> None:
    ledger = sealed(entry("L1"))
    grader_1 = grade(ledger, entry_grade("L1", rationale="First legal rationale."))
    grader_2 = grade(
        ledger,
        entry_grade("L1", rationale="Second legal rationale."),
        request_marker="b",
    )

    assert material_disputes(ledger, grader_1, grader_2) == []
    resolved = resolve_grades(ledger, grader_1, grader_2, [])

    assert resolved.entry_grades[0].rationale == "First legal rationale."
    assert resolved.audit[0].grader_1.entry_grade is not None
    assert resolved.audit[0].grader_1.entry_grade.rationale == "First legal rationale."
    assert resolved.audit[0].grader_2.entry_grade is not None
    assert resolved.audit[0].grader_2.entry_grade.rationale == "Second legal rationale."
    assert resolved.audit[0].dispute is None


def test_agreement_requires_equal_claim_materiality_and_preserves_both_claim_rationales() -> None:
    ledger = sealed(entry("L1"))
    grader_1 = grade(
        ledger,
        entry_grade("L1"),
        claims=[claim("one", rationale="First unsupported-claim rationale.")],
    )
    grader_2 = grade(
        ledger,
        entry_grade("L1"),
        claims=[claim("two", rationale="Second unsupported-claim rationale.")],
        request_marker="b",
    )

    assert material_disputes(ledger, grader_1, grader_2) == []
    resolved = resolve_grades(ledger, grader_1, grader_2, [])
    claim_audit = next(value for value in resolved.audit if value.kind == "out_of_ledger_claim")

    assert claim_audit.grader_1.out_of_ledger_claim is not None
    assert claim_audit.grader_2.out_of_ledger_claim is not None
    assert claim_audit.grader_1.out_of_ledger_claim.rationale.startswith("First")
    assert claim_audit.grader_2.out_of_ledger_claim.rationale.startswith("Second")


def test_entry_location_only_difference_is_audited_without_referee() -> None:
    ledger = sealed(entry("L1"))
    grader_1 = grade(ledger, entry_grade("L1", report_location="p. 1"))
    grader_2 = grade(
        ledger,
        entry_grade("L1", report_location="p. 3"),
        request_marker="b",
    )

    assert material_disputes(ledger, grader_1, grader_2) == []

    resolved = resolve_grades(ledger, grader_1, grader_2, [])
    resolution = resolved.audit[0]

    assert resolved.entry_grades[0].report_location == "p. 1"
    assert resolution.grader_1.entry_grade is not None
    assert resolution.grader_2.entry_grade is not None
    assert resolution.grader_1.entry_grade.report_location == "p. 1"
    assert resolution.grader_2.entry_grade.report_location == "p. 3"
    assert resolution.selected == resolution.grader_1
    assert resolution.dispute is None
    assert resolution.referee is None


def test_narrative_score_difference_remains_referee_routed() -> None:
    ledger = sealed(entry("L1"))
    grader_1 = grade(ledger, entry_grade("L1"))
    grader_2 = grade(
        ledger,
        entry_grade("L1"),
        request_marker="b",
        narratives=narrative_scores(changed="scanability", changed_score=3),
    )

    disputes = material_disputes(ledger, grader_1, grader_2)

    assert [(value.kind, value.subject_id) for value in disputes] == [
        ("narrative_score", "scanability"),
    ]
    assert disputes[0].materiality is None


def test_claim_matching_ignores_generated_ids_case_and_collapsed_whitespace() -> None:
    ledger = sealed(entry("L1"))
    grader_1_claim = claim("grader-one", claim_text="A  MATERIAL penalty applies.")
    grader_2_claim = claim(
        "grader-two",
        claim_text=" a material PENALTY applies. ",
        disposition=CoverageDisposition.PARTIAL,
    )
    grader_1 = grade(ledger, entry_grade("L1"), claims=[grader_1_claim])
    grader_2 = grade(
        ledger,
        entry_grade("L1"),
        claims=[grader_2_claim],
        request_marker="b",
    )

    disputes = material_disputes(ledger, grader_1, grader_2)

    assert len(disputes) == 1
    dispute = disputes[0]
    assert dispute.kind == "out_of_ledger_claim"
    assert dispute.grader_1.out_of_ledger_claim is not None
    assert dispute.grader_2.out_of_ledger_claim is not None
    assert dispute.grader_1.out_of_ledger_claim.claim_id == dispute.subject_id
    assert dispute.grader_2.out_of_ledger_claim.claim_id == dispute.subject_id


def test_claim_dispute_never_exposes_a_shared_grader_generated_identifier() -> None:
    ledger = sealed(entry("L1"))
    grader_1 = grade(
        ledger,
        entry_grade("L1"),
        claims=[claim("candidate-system-identity")],
    )
    grader_2 = grade(
        ledger,
        entry_grade("L1"),
        claims=[
            claim(
                "candidate-system-identity",
                disposition=CoverageDisposition.PARTIAL,
            )
        ],
        request_marker="b",
    )

    dispute = material_disputes(ledger, grader_1, grader_2)[0]

    assert dispute.subject_id == "matched-claim-0001"
    assert "candidate-system-identity" not in dispute.model_dump_json()


def test_claim_presence_and_outcome_relevant_identity_changes_are_routed() -> None:
    ledger = sealed(entry("L1"))
    grader_1 = grade(ledger, entry_grade("L1"), claims=[claim("one")])
    grader_2 = grade(
        ledger,
        entry_grade("L1"),
        claims=[claim("two", category=LedgerCategory.ENFORCEMENT)],
        request_marker="b",
    )

    disputes = material_disputes(ledger, grader_1, grader_2)

    assert len(disputes) == 2
    assert all(value.kind == "out_of_ledger_claim" for value in disputes)
    assert all(value.grader_1.absent_claim is not value.grader_2.absent_claim for value in disputes)


def test_resolve_requires_one_exactly_bound_referee_decision_per_dispute() -> None:
    ledger = sealed(entry("L1"))
    grader_1 = grade(ledger, entry_grade("L1"))
    grader_2 = grade(
        ledger,
        entry_grade("L1", CoverageDisposition.MISSING, report_location=None),
        request_marker="b",
    )
    dispute = material_disputes(ledger, grader_1, grader_2)[0]

    with pytest.raises(GradeInconclusiveError, match="requires referee"):
        resolve_grades(ledger, grader_1, grader_2, [])
    with pytest.raises(GradeInconclusiveError, match="fingerprint"):
        resolve_grades(
            ledger,
            grader_1,
            grader_2,
            [referee(dispute, "accept_grader_2", fingerprint="f" * 64)],
        )

    resolved = resolve_grades(
        ledger,
        grader_1,
        grader_2,
        referee(dispute, "accept_grader_2"),
    )

    assert resolved.entry_grades[0] == dispute.grader_2.entry_grade
    assert resolved.audit[0].dispute == dispute
    assert resolved.audit[0].referee is not None
    assert resolved.audit[0].referee.rationale.startswith("The referee selected")


def test_resolved_grade_fingerprint_detects_mutated_audit_before_scoring() -> None:
    ledger = sealed(entry("L1"))
    grader_1 = grade(ledger, entry_grade("L1"))
    grader_2 = grade(
        ledger,
        entry_grade("L1", CoverageDisposition.PARTIAL),
        request_marker="b",
    )
    dispute = material_disputes(ledger, grader_1, grader_2)[0]
    resolved = resolve_grades(
        ledger,
        grader_1,
        grader_2,
        [referee(dispute, "accept_grader_1")],
    )
    assert resolved.audit[0].referee is not None
    resolved.audit[0].referee.rationale = "A post-resolution mutation."

    with pytest.raises(GradeInconclusiveError, match="fingerprint"):
        strict_resolved_grade_snapshot(ledger, resolved)

    resolved = resolve_grades(
        ledger,
        grader_1,
        grader_2,
        [referee(dispute, "accept_grader_1")],
    )
    object.__setattr__(resolved.audit[0], "referee", None)
    object.__setattr__(
        resolved,
        "resolution_fingerprint",
        _resolution_fingerprint(
            resolved.grade,
            resolved.audit,
            resolved.original_grader_1,
            resolved.original_grader_2,
            resolved.referee_decisions,
        ),
    )
    with pytest.raises(GradeInconclusiveError, match="audit"):
        strict_resolved_grade_snapshot(ledger, resolved)

    resolved = resolve_grades(ledger, grader_1, grader_1, [])
    absence = GradeAlternative(request_fingerprint="a" * 64, absent_claim=True)
    phantom = GradeResolution(
        kind="out_of_ledger_claim",
        subject_id="matched-claim-0001",
        grader_1=absence,
        grader_2=absence,
        selected=absence,
        dispute=None,
        referee=None,
    )
    forged_audit = (resolved.audit[0], phantom, *resolved.audit[1:])
    object.__setattr__(resolved, "audit", forged_audit)
    object.__setattr__(
        resolved,
        "resolution_fingerprint",
        _resolution_fingerprint(
            resolved.grade,
            resolved.audit,
            resolved.original_grader_1,
            resolved.original_grader_2,
            resolved.referee_decisions,
        ),
    )
    with pytest.raises(GradeInconclusiveError, match="audit"):
        strict_resolved_grade_snapshot(ledger, resolved)


@pytest.mark.parametrize(
    "disposition",
    [value for value in CoverageDisposition if value is not CoverageDisposition.UNSUPPORTED],
)
def test_rebound_resolved_grade_rejects_nonunsupported_absence_binding(
    disposition: CoverageDisposition,
) -> None:
    ledger = sealed(entry("L1"))
    first = grade(
        ledger,
        entry_grade("L1"),
        claims=[claim("claim-a")],
    )
    second = grade(
        ledger,
        entry_grade("L1"),
        claims=[claim("claim-b")],
        request_marker="b",
    )
    resolved = resolve_grades(ledger, first, second, [])

    rebound_claims = [
        resolved.grade.out_of_ledger_claims[0],
        resolved.original_grader_1.out_of_ledger_claims[0],
        resolved.original_grader_2.out_of_ledger_claims[0],
    ]
    claim_resolution = next(item for item in resolved.audit if item.kind == "out_of_ledger_claim")
    for alternative in (
        claim_resolution.grader_1,
        claim_resolution.grader_2,
        claim_resolution.selected,
    ):
        assert alternative.out_of_ledger_claim is not None
        rebound_claims.append(alternative.out_of_ledger_claim)
    for rebound_claim in rebound_claims:
        rebound_claim.disposition = disposition
    object.__setattr__(
        resolved,
        "resolution_fingerprint",
        _resolution_fingerprint(
            resolved.grade,
            resolved.audit,
            resolved.original_grader_1,
            resolved.original_grader_2,
            resolved.referee_decisions,
        ),
    )

    with pytest.raises(GradeInconclusiveError, match="malformed resolved grade"):
        strict_resolved_grade_snapshot(ledger, resolved)


def test_resolved_grade_replay_rejects_self_consistent_derived_audit_rewrite() -> None:
    ledger = sealed(entry("L1"))
    grader_1 = grade(ledger, entry_grade("L1"))
    grader_2 = grade(
        ledger,
        entry_grade("L1", CoverageDisposition.PARTIAL),
        request_marker="b",
    )
    dispute = material_disputes(ledger, grader_1, grader_2)[0]
    resolved = resolve_grades(
        ledger,
        grader_1,
        grader_2,
        [referee(dispute, "accept_grader_1")],
    )
    forged_peer = GradeAlternative(
        request_fingerprint=grader_2.request_fingerprint,
        entry_grade=grader_1.entry_grades[0].model_copy(
            update={"rationale": "A forged agreement replacing the second blind grade."},
            deep=True,
        ),
    )
    forged_resolution = GradeResolution(
        kind="entry_grade",
        subject_id="L1",
        grader_1=resolved.audit[0].grader_1,
        grader_2=forged_peer,
        selected=resolved.audit[0].grader_1,
        dispute=None,
        referee=None,
    )
    forged_audit = (forged_resolution, *resolved.audit[1:])
    object.__setattr__(resolved, "audit", forged_audit)
    object.__setattr__(
        resolved,
        "resolution_fingerprint",
        _resolution_fingerprint(
            resolved.grade,
            forged_audit,
            resolved.original_grader_1,
            resolved.original_grader_2,
            resolved.referee_decisions,
        ),
    )

    with pytest.raises(GradeInconclusiveError, match="replay"):
        strict_resolved_grade_snapshot(ledger, resolved)


def test_resolved_grade_replay_rejects_mutated_original_artifact_and_decision() -> None:
    """Task 5 binds provenance; Task 4 must still reject stale retained evidence."""
    ledger = sealed(entry("L1"))
    grader_1 = grade(ledger, entry_grade("L1"))
    grader_2 = grade(
        ledger,
        entry_grade("L1", CoverageDisposition.PARTIAL),
        request_marker="b",
    )
    dispute = material_disputes(ledger, grader_1, grader_2)[0]
    resolved = resolve_grades(
        ledger,
        grader_1,
        grader_2,
        [referee(dispute, "accept_grader_1")],
    )

    assert resolved.original_grader_1 == grader_1
    assert resolved.original_grader_2 == grader_2
    assert resolved.referee_decisions[0] == resolved.audit[0].referee

    resolved.original_grader_2.entry_grades[0].rationale = "Mutated retained evidence."
    object.__setattr__(
        resolved,
        "resolution_fingerprint",
        _resolution_fingerprint(
            resolved.grade,
            resolved.audit,
            resolved.original_grader_1,
            resolved.original_grader_2,
            resolved.referee_decisions,
        ),
    )
    with pytest.raises(GradeInconclusiveError, match="replay"):
        strict_resolved_grade_snapshot(ledger, resolved)

    resolved = resolve_grades(
        ledger,
        grader_1,
        grader_2,
        [referee(dispute, "accept_grader_1")],
    )
    resolved.referee_decisions[0].rationale = "Mutated retained referee evidence."
    object.__setattr__(
        resolved,
        "resolution_fingerprint",
        _resolution_fingerprint(
            resolved.grade,
            resolved.audit,
            resolved.original_grader_1,
            resolved.original_grader_2,
            resolved.referee_decisions,
        ),
    )
    with pytest.raises(GradeInconclusiveError, match="replay"):
        strict_resolved_grade_snapshot(ledger, resolved)


def test_same_grade_request_fingerprint_is_allowed_at_pure_resolution_layer() -> None:
    """Task 5, not pure reconciliation, proves independent judge-call provenance."""
    ledger = sealed(entry("L1"))
    grader_1 = grade(ledger, entry_grade("L1"), request_marker="a")
    grader_2 = grade(
        ledger,
        entry_grade("L1", rationale="The second grader independently agrees."),
        request_marker="a",
    )

    resolved = resolve_grades(ledger, grader_1, grader_2, [])
    snapshot = strict_resolved_grade_snapshot(ledger, resolved)

    assert snapshot.original_grader_1.request_fingerprint == "a" * 64
    assert snapshot.original_grader_2.request_fingerprint == "a" * 64
    assert snapshot.entry_grades[0] == grader_1.entry_grades[0]


def test_referee_accepts_an_entire_alternative_not_only_its_disposition() -> None:
    ledger = sealed(entry("L1"))
    grader_1 = grade(ledger, entry_grade("L1", report_location="p. 1"))
    grader_2 = grade(
        ledger,
        entry_grade(
            "L1",
            CoverageDisposition.PARTIAL,
            rationale="The condition is missing.",
            report_location="p. 7",
        ),
        request_marker="b",
    )
    dispute = material_disputes(ledger, grader_1, grader_2)[0]

    resolved = resolve_grades(
        ledger,
        grader_1,
        grader_2,
        [referee(dispute, "accept_grader_2")],
    )

    assert resolved.entry_grades[0].model_dump() == grader_2.entry_grades[0].model_dump()


def test_referee_can_replace_an_entry_with_the_exact_bound_subject() -> None:
    ledger = sealed(entry("L1"))
    grader_1 = grade(ledger, entry_grade("L1"))
    grader_2 = grade(
        ledger,
        entry_grade("L1", CoverageDisposition.MISSING, report_location=None),
        request_marker="b",
    )
    dispute = material_disputes(ledger, grader_1, grader_2)[0]
    replacement_grade = entry_grade(
        "L1",
        CoverageDisposition.PARTIAL,
        rationale="The referee found partial coverage at the cited location.",
        report_location="p. 9",
    )
    replacement = GradeAlternative(
        request_fingerprint="c" * 64,
        entry_grade=replacement_grade,
    )

    resolved = resolve_grades(
        ledger,
        grader_1,
        grader_2,
        [referee(dispute, "replace", replacement=replacement)],
    )

    assert resolved.entry_grades == [replacement_grade]


def test_referee_can_resolve_a_narrative_score_without_rewriting_other_dimensions() -> None:
    ledger = sealed(entry("L1"))
    grader_1 = grade(
        ledger,
        entry_grade("L1"),
        narratives=narrative_scores(changed="scanability", changed_score=2),
    )
    grader_2 = grade(
        ledger,
        entry_grade("L1"),
        request_marker="b",
        narratives=narrative_scores(changed="scanability", changed_score=3),
    )
    dispute = material_disputes(ledger, grader_1, grader_2)[0]

    resolved = resolve_grades(
        ledger,
        grader_1,
        grader_2,
        [referee(dispute, "accept_grader_2")],
    )

    scores = {score.dimension: score.score for score in resolved.narrative_scores}
    assert scores["scanability"] == 3
    assert all(score == 4 for dimension, score in scores.items() if dimension != "scanability")


def test_referee_replacement_must_match_kind_subject_and_claim_identity() -> None:
    ledger = sealed(entry("L1"))
    grader_1 = grade(ledger, entry_grade("L1"), claims=[claim("one")])
    grader_2 = grade(ledger, entry_grade("L1"), request_marker="b")
    dispute = material_disputes(ledger, grader_1, grader_2)[0]
    wrong_kind = GradeAlternative(
        request_fingerprint="c" * 64,
        entry_grade=entry_grade("L1"),
    )
    wrong_identity = GradeAlternative(
        request_fingerprint="c" * 64,
        out_of_ledger_claim=claim(
            dispute.subject_id,
            claim_text="A completely different legal assertion.",
        ),
    )

    with pytest.raises(GradeInconclusiveError, match="replacement kind"):
        resolve_grades(
            ledger,
            grader_1,
            grader_2,
            [referee(dispute, "replace", replacement=wrong_kind)],
        )
    with pytest.raises(GradeInconclusiveError, match="claim identity"):
        resolve_grades(
            ledger,
            grader_1,
            grader_2,
            [referee(dispute, "replace", replacement=wrong_identity)],
        )


def test_referee_claim_replacement_cannot_understate_materiality_but_may_select_absence() -> None:
    ledger = sealed(entry("L1"))
    grader_1 = grade(ledger, entry_grade("L1"), claims=[claim("one")])
    grader_2 = grade(ledger, entry_grade("L1"), request_marker="b")
    dispute = material_disputes(ledger, grader_1, grader_2)[0]
    understated = GradeAlternative(
        request_fingerprint="c" * 64,
        out_of_ledger_claim=claim(
            dispute.subject_id,
            materiality=Materiality.SUPPORTING,
        ),
    )
    absence = GradeAlternative(request_fingerprint="c" * 64, absent_claim=True)

    with pytest.raises(GradeInconclusiveError, match="understate"):
        resolve_grades(
            ledger,
            grader_1,
            grader_2,
            [referee(dispute, "replace", replacement=understated)],
        )

    resolved = resolve_grades(
        ledger,
        grader_1,
        grader_2,
        [referee(dispute, "replace", replacement=absence)],
    )
    assert resolved.out_of_ledger_claims == []

    present_replacement = GradeAlternative(
        request_fingerprint="d" * 64,
        out_of_ledger_claim=claim(
            dispute.subject_id,
            disposition=CoverageDisposition.PARTIAL,
        ),
    )
    present = resolve_grades(
        ledger,
        grader_1,
        grader_2,
        [referee(dispute, "replace", replacement=present_replacement)],
    )
    assert present.out_of_ledger_claims[0].disposition is CoverageDisposition.PARTIAL


def test_referee_cannot_use_legacy_selector_or_rewrite_undisputed_grade() -> None:
    ledger = sealed(entry("L1"))
    agreed = grade(ledger, entry_grade("L1"))
    legacy = RefereeDecision(
        dispute_id="grade-entry-L1",
        selected_disposition=CoverageDisposition.MISSING,
        rationale="This legacy selector is not a bound grade decision.",
    )

    with pytest.raises(GradeInconclusiveError, match="undisputed"):
        resolve_grades(ledger, agreed, agreed, [legacy])


def test_referee_rejects_duplicate_decisions_and_legacy_domain_mixing() -> None:
    ledger = sealed(entry("L1"))
    grader_1 = grade(ledger, entry_grade("L1"))
    grader_2 = grade(
        ledger,
        entry_grade("L1", CoverageDisposition.PARTIAL),
        request_marker="b",
    )
    dispute = material_disputes(ledger, grader_1, grader_2)[0]
    accepted = referee(dispute, "accept_grader_1")
    mixed = accepted.model_copy(update={"selected_disposition": CoverageDisposition.PARTIAL})

    with pytest.raises(GradeInconclusiveError, match="duplicate"):
        resolve_grades(ledger, grader_1, grader_2, [accepted, accepted])
    with pytest.raises(GradeInconclusiveError, match="legacy"):
        resolve_grades(ledger, grader_1, grader_2, [mixed])


def test_post_construction_entry_dispute_materiality_mismatch_is_detected() -> None:
    ledger = sealed(entry("L1", materiality=Materiality.CRITICAL))
    grader_1 = grade(ledger, entry_grade("L1"))
    grader_2 = grade(
        ledger,
        entry_grade("L1", CoverageDisposition.PARTIAL),
        request_marker="b",
    )
    dispute = material_disputes(ledger, grader_1, grader_2)[0]
    decision = referee(dispute, "accept_grader_1")
    dispute.materiality = Materiality.SUPPORTING
    decision.grade_dispute_fingerprint = model_fingerprint(dispute)

    with pytest.raises(GradeInconclusiveError, match="fingerprint"):
        resolve_grades(ledger, grader_1, grader_2, [decision])


def test_grades_for_different_anonymous_reports_never_enter_one_dispute() -> None:
    ledger = sealed(entry("L1"))
    grader_1 = grade(ledger, entry_grade("L1"), label="A")
    grader_2 = grade(ledger, entry_grade("L1"), label="B", request_marker="b")

    with pytest.raises(GradeInconclusiveError, match="anonymous labels"):
        material_disputes(ledger, grader_1, grader_2)
