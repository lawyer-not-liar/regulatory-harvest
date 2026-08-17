"""Blind, fail-closed reconciliation of independent attorney report grades."""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from typing import Literal, TypeAlias

from pydantic import ValidationError

from regulatory_harvest.storage import canonical_json_bytes, sha256_digest

from .attorney_models import (
    CandidateGrade,
    CoverageDisposition,
    EntryFindingCode,
    EntryGrade,
    EvaluationIssue,
    GradeAlternative,
    GradeDispute,
    IssueSeverity,
    LedgerCategory,
    LedgerEntry,
    Materiality,
    NarrativeFindingCode,
    NarrativeScore,
    OutOfLedgerClaim,
    RefereeDecision,
    SealedLedger,
    model_fingerprint,
)

DisputeKind: TypeAlias = Literal["entry_grade", "out_of_ledger_claim", "narrative_score"]
NarrativeDimension: TypeAlias = Literal[
    "executive_summary",
    "regulatory_walk",
    "key_requirements",
    "penalties_enforcement",
    "qualification_placement",
    "requirements_workplan_boundary",
    "limitations",
    "scanability",
]
ClaimIdentity: TypeAlias = tuple[str, str, str, tuple[str, ...]]

_NARRATIVE_DIMENSIONS: tuple[NarrativeDimension, ...] = (
    "executive_summary",
    "regulatory_walk",
    "key_requirements",
    "penalties_enforcement",
    "qualification_placement",
    "requirements_workplan_boundary",
    "limitations",
    "scanability",
)
_NARRATIVE_DIMENSION_SET = frozenset(_NARRATIVE_DIMENSIONS)
_REPORT_CONTENT_DISPOSITIONS = frozenset(
    {
        CoverageDisposition.COMPLETE,
        CoverageDisposition.PARTIAL,
        CoverageDisposition.OVERSTATED,
        CoverageDisposition.CONTRADICTED,
        CoverageDisposition.UNSUPPORTED,
    }
)
_CREDIT = {
    CoverageDisposition.COMPLETE: 1.0,
    CoverageDisposition.PARTIAL: 0.5,
    CoverageDisposition.MISSING: 0.0,
    CoverageDisposition.OVERSTATED: 0.0,
    CoverageDisposition.CONTRADICTED: 0.0,
    CoverageDisposition.UNSUPPORTED: 0.0,
    CoverageDisposition.NOT_APPLICABLE: 0.0,
}
_MATERIALITY_RANK = {
    Materiality.SUPPORTING: 0,
    Materiality.MATERIAL: 1,
    Materiality.CRITICAL: 2,
}


def _finding_code_contract() -> dict[str, object]:
    """Return every closed finding code's deterministic allowed context."""
    return {
        "entry_finding_codes": {
            "CONSEQUENCE_TRIGGER_DETACHED": {
                "allowed_dispositions": ["PARTIAL", "OVERSTATED", "CONTRADICTED"],
                "ledger_categories": ["enforcement", "penalty", "remedy"],
                "ledger_fields": {
                    "consequence": "required",
                    "trigger_or_relationship_ids": "at_least_one_required",
                },
            },
            "CRITICAL_LEDGER_ENTRY_MISSING": {
                "allowed_dispositions": ["MISSING"],
                "ledger_materialities": ["critical"],
            },
            "MATERIAL_EXCEPTION_MISSING": {
                "allowed_dispositions": ["MISSING", "PARTIAL"],
                "ledger_categories": ["exception"],
                "ledger_materialities": ["critical", "material"],
            },
        },
        "narrative_finding_codes": {
            "KEY_REQUIREMENTS_ACTION_PLAN": {
                "allowed_dimensions": [
                    "key_requirements",
                    "requirements_workplan_boundary",
                ],
                "maximum_score": 2,
            }
        },
    }


def _entry_finding_allowed_context(code: EntryFindingCode) -> str:
    contexts = {
        EntryFindingCode.CRITICAL_LEDGER_ENTRY_MISSING: (
            "disposition in [MISSING]; materiality in [critical]"
        ),
        EntryFindingCode.MATERIAL_EXCEPTION_MISSING: (
            "disposition in [MISSING, PARTIAL]; category=exception; "
            "materiality in [critical, material]"
        ),
        EntryFindingCode.CONSEQUENCE_TRIGGER_DETACHED: (
            "disposition in [PARTIAL, OVERSTATED, CONTRADICTED]; category in "
            "[enforcement, penalty, remedy]; consequence required; trigger or "
            "relationship_ids required"
        ),
    }
    return contexts[code]


def _narrative_finding_allowed_context(code: NarrativeFindingCode) -> str:
    if code is NarrativeFindingCode.KEY_REQUIREMENTS_ACTION_PLAN:
        return (
            "dimension in [key_requirements, requirements_workplan_boundary]; "
            "score at most 2"
        )
    raise ValueError("unknown narrative finding code")


class GradeInconclusiveError(ValueError):
    """Raised when blinded grades cannot be safely reconciled."""


@dataclass(frozen=True)
class GradeResolution:
    """Audit evidence for one deterministic agreement or referee resolution."""

    kind: DisputeKind
    subject_id: str
    grader_1: GradeAlternative
    grader_2: GradeAlternative
    selected: GradeAlternative
    dispute: GradeDispute | None
    referee: RefereeDecision | None


@dataclass(frozen=True)
class ResolvedGrade:
    """A replayable reconciled grade with an identity-free audit trail.

    The original blind-grade snapshots and exact referee decisions make local
    derivation replayable.  Task 5 must bind these artifacts and their request
    provenance immutably; content hashes alone do not establish authenticity.
    """

    grade: CandidateGrade
    audit: tuple[GradeResolution, ...]
    resolution_fingerprint: str
    original_grader_1: CandidateGrade
    original_grader_2: CandidateGrade
    referee_decisions: tuple[RefereeDecision, ...]

    @property
    def anonymous_label(self) -> Literal["A", "B"]:
        return self.grade.anonymous_label

    @property
    def ledger_fingerprint(self) -> str:
        return self.grade.ledger_fingerprint

    @property
    def entry_grades(self) -> list[EntryGrade]:
        return self.grade.entry_grades

    @property
    def out_of_ledger_claims(self) -> list[OutOfLedgerClaim]:
        return self.grade.out_of_ledger_claims

    @property
    def narrative_scores(self) -> list[NarrativeScore]:
        return self.grade.narrative_scores


@dataclass(frozen=True)
class _ComparisonRecord:
    kind: DisputeKind
    subject_id: str
    materiality: Materiality | None
    grader_1: GradeAlternative
    grader_2: GradeAlternative
    claim_identity: ClaimIdentity | None
    dispute: GradeDispute | None


def disposition_credit(value: CoverageDisposition) -> float:
    """Return the rubric's fixed coverage credit without coercion."""
    if type(value) is not CoverageDisposition:
        raise TypeError("value must be a CoverageDisposition")
    return _CREDIT[value]


def validate_grade(
    sealed_ledger: SealedLedger, candidate_grade: CandidateGrade
) -> list[EvaluationIssue]:
    """Return deterministic validity defects for one blind candidate grade.

    Claim matching uses normalized claim text, normalized report location,
    category, and sorted related ledger IDs.  Grader-generated claim IDs,
    disposition, materiality, and rationale are deliberately excluded.
    """
    try:
        sealed_ledger = _sealed_snapshot(sealed_ledger)
    except (TypeError, ValidationError, ValueError):
        return [_issue("GRADE_SEALED_LEDGER_MALFORMED", "The sealed ledger is malformed.")]

    raw_entry_issues = _raw_entry_identity_issues(sealed_ledger, candidate_grade)
    duplicate_claim_ids = _raw_duplicate_claim_ids(candidate_grade)
    try:
        if not _raw_grade_types_valid(candidate_grade):
            raise TypeError("candidate grade contains a coerced field")
        candidate_grade = _grade_snapshot(candidate_grade)
    except (TypeError, ValidationError, ValueError):
        issues = list(raw_entry_issues)
        if duplicate_claim_ids:
            issues.append(
                _issue(
                    "GRADE_OUT_OF_LEDGER_DUPLICATE_ID",
                    "Out-of-ledger claim IDs must be unique.",
                )
            )
        return issues or [
            _issue("GRADE_MALFORMED", "Candidate grade is not a strict valid snapshot.")
        ]

    issues = []
    ledger_entries = {entry.ledger_id: entry for entry in sealed_ledger.ledger.entries}
    ledger_ids = set(ledger_entries)
    grade_ids = [entry_grade.ledger_id for entry_grade in candidate_grade.entry_grades]
    grade_id_set = set(grade_ids)
    unknown = grade_id_set - ledger_ids
    missing = ledger_ids - grade_id_set
    if len(grade_ids) != len(grade_id_set):
        issues.append(
            _issue(
                "GRADE_DUPLICATE_LEDGER_ID",
                "A ledger entry must receive exactly one grade.",
            )
        )
    if unknown:
        issues.append(
            _issue(
                "GRADE_LEDGER_ENTRY_UNKNOWN",
                "Entry grades must identify sealed ledger entries.",
                sorted(unknown),
            )
        )
    if missing:
        issues.append(
            _issue(
                "GRADE_LEDGER_ENTRY_MISSING",
                "Every sealed ledger entry must receive exactly one grade.",
                sorted(missing),
            )
        )
    if candidate_grade.ledger_fingerprint != sealed_ledger.ledger_fingerprint:
        issues.append(
            _issue(
                "GRADE_LEDGER_FINGERPRINT_MISMATCH",
                "Grade must bind the exact sealed ledger fingerprint.",
            )
        )

    for entry_grade_value in candidate_grade.entry_grades:
        if entry_grade_value.disposition is CoverageDisposition.NOT_APPLICABLE:
            issues.append(
                _issue(
                    "GRADE_NOT_APPLICABLE_UNSUPPORTED",
                    "The contract has no legal-basis field that can exempt a sealed entry.",
                    [entry_grade_value.ledger_id],
                )
            )
        elif (
            entry_grade_value.disposition in _REPORT_CONTENT_DISPOSITIONS
            and entry_grade_value.report_location is None
        ):
            issues.append(
                _issue(
                    "GRADE_REPORT_LOCATION_MISSING",
                    "A report-content finding requires a concrete report location.",
                    [entry_grade_value.ledger_id],
                )
            )
        elif (
            entry_grade_value.disposition is CoverageDisposition.MISSING
            and entry_grade_value.report_location is not None
        ):
            issues.append(
                _issue(
                    "GRADE_REPORT_LOCATION_UNEXPECTED",
                    "A missing-entry finding cannot identify report content as coverage.",
                    [entry_grade_value.ledger_id],
                )
            )
        issues.extend(
            _entry_finding_issues(
                entry_grade_value,
                ledger_entries.get(entry_grade_value.ledger_id),
            )
        )

    claim_ids = [claim.claim_id for claim in candidate_grade.out_of_ledger_claims]
    if len(claim_ids) != len(set(claim_ids)):
        issues.append(
            _issue(
                "GRADE_OUT_OF_LEDGER_DUPLICATE_ID",
                "Out-of-ledger claim IDs must be unique.",
            )
        )
    claim_identities: dict[ClaimIdentity, list[str]] = {}
    for claim in candidate_grade.out_of_ledger_claims:
        unknown_relationships = set(claim.related_ledger_ids) - ledger_ids
        if unknown_relationships:
            issues.append(
                _issue(
                    "GRADE_OUT_OF_LEDGER_RELATIONSHIP_UNKNOWN",
                    "Out-of-ledger claims may relate only to sealed ledger entries.",
                    [claim.claim_id, *sorted(unknown_relationships)],
                )
            )
        if claim.disposition in {
            CoverageDisposition.MISSING,
            CoverageDisposition.NOT_APPLICABLE,
        }:
            issues.append(
                _issue(
                    "GRADE_OUT_OF_LEDGER_DISPOSITION_INVALID",
                    "A present out-of-ledger claim cannot be missing or not applicable.",
                    [claim.claim_id],
                )
            )
        claim_identities.setdefault(_claim_identity(claim), []).append(claim.claim_id)
    for identifiers in claim_identities.values():
        if len(identifiers) > 1:
            issues.append(
                _issue(
                    "GRADE_OUT_OF_LEDGER_CLAIM_AMBIGUOUS",
                    "More than one finding has the same deterministic claim identity.",
                    sorted(identifiers),
                )
            )

    dimensions = [score.dimension for score in candidate_grade.narrative_scores]
    dimension_set = set(dimensions)
    missing_dimensions = _NARRATIVE_DIMENSION_SET - dimension_set
    if missing_dimensions:
        issues.append(
            _issue(
                "GRADE_NARRATIVE_DIMENSION_MISSING",
                "Each required narrative dimension must appear exactly once.",
                sorted(missing_dimensions),
            )
        )
    if len(dimensions) != len(dimension_set):
        issues.append(
            _issue(
                "GRADE_NARRATIVE_DIMENSION_DUPLICATE",
                "Narrative dimensions must not repeat.",
            )
        )
    for score in candidate_grade.narrative_scores:
        issues.extend(_narrative_finding_issues(score))
    return _unique_issues(issues)


def material_disputes(
    sealed_ledger: SealedLedger,
    grader_1: CandidateGrade,
    grader_2: CandidateGrade,
) -> list[GradeDispute]:
    """Return every outcome-relevant disagreement in stable rubric order."""
    sealed, first, second = _validated_grade_pair(sealed_ledger, grader_1, grader_2)
    return [
        _dispute_snapshot(record.dispute)
        for record in _comparison_records(sealed, first, second)
        if record.dispute is not None
    ]


def resolve_grades(
    sealed_ledger: SealedLedger,
    grader_1: CandidateGrade,
    grader_2: CandidateGrade,
    referee_decisions: (
        RefereeDecision | list[RefereeDecision] | tuple[RefereeDecision, ...] | None
    ) = None,
) -> ResolvedGrade:
    """Resolve a blind grade pair using one exact decision per disagreement."""
    sealed, first, second = _validated_grade_pair(sealed_ledger, grader_1, grader_2)
    records = _comparison_records(sealed, first, second)
    disputes = {
        record.dispute.dispute_id: record.dispute
        for record in records
        if record.dispute is not None
    }
    decision_values: list[RefereeDecision] | tuple[RefereeDecision, ...]
    if referee_decisions is None:
        decision_values = []
    elif isinstance(referee_decisions, RefereeDecision):
        decision_values = [referee_decisions]
    else:
        decision_values = referee_decisions
    decisions = _strict_decisions(decision_values)
    decision_ids = [decision.dispute_id for decision in decisions]
    if len(decision_ids) != len(set(decision_ids)):
        raise GradeInconclusiveError("duplicate referee decision ID")
    expected_ids = set(disputes)
    actual_ids = set(decision_ids)
    unknown = actual_ids - expected_ids
    if unknown:
        if not expected_ids:
            raise GradeInconclusiveError("referee cannot rewrite an undisputed grade")
        raise GradeInconclusiveError("referee decision does not identify a material grade dispute")
    missing = expected_ids - actual_ids
    if missing:
        raise GradeInconclusiveError(
            "material grade dispute requires referee decision: " + ", ".join(sorted(missing))
        )
    decisions_by_id = {decision.dispute_id: decision for decision in decisions}

    entry_grades: list[EntryGrade] = []
    claims: list[OutOfLedgerClaim] = []
    narrative_scores: list[NarrativeScore] = []
    audit: list[GradeResolution] = []
    for record in records:
        decision = None if record.dispute is None else decisions_by_id[record.dispute.dispute_id]
        selected = _selected_alternative(sealed, record, decision)
        if selected.entry_grade is not None:
            entry_grades.append(selected.entry_grade.model_copy(deep=True))
        elif selected.out_of_ledger_claim is not None:
            claims.append(selected.out_of_ledger_claim.model_copy(deep=True))
        elif selected.narrative_score is not None:
            narrative_scores.append(selected.narrative_score.model_copy(deep=True))
        audit.append(
            GradeResolution(
                kind=record.kind,
                subject_id=record.subject_id,
                grader_1=_alternative_snapshot(record.grader_1),
                grader_2=_alternative_snapshot(record.grader_2),
                selected=_alternative_snapshot(selected),
                dispute=(None if record.dispute is None else _dispute_snapshot(record.dispute)),
                referee=(None if decision is None else _referee_snapshot(decision)),
            )
        )

    resolved_candidate = CandidateGrade(
        request_fingerprint=first.request_fingerprint,
        anonymous_label=first.anonymous_label,
        ledger_fingerprint=first.ledger_fingerprint,
        entry_grades=entry_grades,
        out_of_ledger_claims=claims,
        narrative_scores=narrative_scores,
    )
    issues = validate_grade(sealed, resolved_candidate)
    if issues:
        raise GradeInconclusiveError(
            "resolved grade is invalid: " + ", ".join(issue.code for issue in issues)
        )
    audit_tuple = tuple(audit)
    ordered_decisions = tuple(
        _referee_snapshot(decisions_by_id[record.dispute.dispute_id])
        for record in records
        if record.dispute is not None
    )
    original_grader_1 = _grade_snapshot(first)
    original_grader_2 = _grade_snapshot(second)
    return ResolvedGrade(
        grade=resolved_candidate,
        audit=audit_tuple,
        resolution_fingerprint=_resolution_fingerprint(
            resolved_candidate,
            audit_tuple,
            original_grader_1,
            original_grader_2,
            ordered_decisions,
        ),
        original_grader_1=original_grader_1,
        original_grader_2=original_grader_2,
        referee_decisions=ordered_decisions,
    )


def strict_resolved_grade_snapshot(
    sealed_ledger: SealedLedger, resolved_grade: ResolvedGrade
) -> ResolvedGrade:
    """Revalidate a resolved grade and its audit at a scoring boundary."""
    sealed = _require_valid_sealed_ledger(sealed_ledger)
    if not isinstance(resolved_grade, ResolvedGrade):
        raise GradeInconclusiveError("score_report requires a resolved grade")
    try:
        grade_snapshot = _grade_snapshot(resolved_grade.grade)
        if not isinstance(resolved_grade.audit, tuple):
            raise TypeError("resolved audit must be a tuple")
        audit_snapshot = tuple(
            _grade_resolution_snapshot(resolution) for resolution in resolved_grade.audit
        )
        original_grader_1 = _grade_snapshot(resolved_grade.original_grader_1)
        original_grader_2 = _grade_snapshot(resolved_grade.original_grader_2)
        if not isinstance(resolved_grade.referee_decisions, tuple):
            raise TypeError("retained referee decisions must be a tuple")
        referee_decisions = tuple(
            _referee_snapshot(decision) for decision in resolved_grade.referee_decisions
        )
    except (TypeError, ValidationError, ValueError) as error:
        raise GradeInconclusiveError("malformed resolved grade") from error
    _validate_resolved_audit(sealed, grade_snapshot, audit_snapshot)
    expected_fingerprint = _resolution_fingerprint(
        grade_snapshot,
        audit_snapshot,
        original_grader_1,
        original_grader_2,
        referee_decisions,
    )
    if resolved_grade.resolution_fingerprint != expected_fingerprint:
        raise GradeInconclusiveError("resolved grade fingerprint mismatch")
    issues = validate_grade(sealed, grade_snapshot)
    if issues:
        raise GradeInconclusiveError(
            "invalid resolved grade: " + ", ".join(issue.code for issue in issues)
        )
    try:
        replay = resolve_grades(
            sealed,
            original_grader_1,
            original_grader_2,
            referee_decisions,
        )
    except GradeInconclusiveError as error:
        raise GradeInconclusiveError("resolved grade original evidence replay failed") from error
    if (
        grade_snapshot != replay.grade
        or audit_snapshot != replay.audit
        or expected_fingerprint != replay.resolution_fingerprint
    ):
        raise GradeInconclusiveError("resolved grade does not match original evidence replay")
    return replay


def _validate_resolved_audit(
    sealed_ledger: SealedLedger,
    candidate_grade: CandidateGrade,
    audit: tuple[GradeResolution, ...],
) -> None:
    entry_count = len(sealed_ledger.ledger.entries)
    narrative_count = len(_NARRATIVE_DIMENSIONS)
    if len(audit) < entry_count + narrative_count:
        raise GradeInconclusiveError("resolved audit is incomplete")
    expected_entry_subjects = [entry.ledger_id for entry in sealed_ledger.ledger.entries]
    entry_resolutions = audit[:entry_count]
    claim_resolutions = audit[entry_count:-narrative_count]
    narrative_resolutions = audit[-narrative_count:]
    if [resolution.kind for resolution in entry_resolutions] != ["entry_grade"] * entry_count or [
        resolution.subject_id for resolution in entry_resolutions
    ] != expected_entry_subjects:
        raise GradeInconclusiveError("resolved audit entry coverage is invalid")
    if any(resolution.kind != "out_of_ledger_claim" for resolution in claim_resolutions) or len(
        {resolution.subject_id for resolution in claim_resolutions}
    ) != len(claim_resolutions):
        raise GradeInconclusiveError("resolved audit claim coverage is invalid")
    if [resolution.kind for resolution in narrative_resolutions] != [
        "narrative_score"
    ] * narrative_count or [resolution.subject_id for resolution in narrative_resolutions] != list(
        _NARRATIVE_DIMENSIONS
    ):
        raise GradeInconclusiveError("resolved audit narrative coverage is invalid")

    grader_1_requests: set[str] = set()
    grader_2_requests: set[str] = set()
    selected_entries: list[EntryGrade] = []
    selected_claims: list[OutOfLedgerClaim] = []
    selected_narratives: list[NarrativeScore] = []
    for resolution in audit:
        grader_1_requests.add(resolution.grader_1.request_fingerprint)
        grader_2_requests.add(resolution.grader_2.request_fingerprint)
        _validate_resolution_alternative(
            resolution.kind, resolution.subject_id, resolution.grader_1
        )
        _validate_resolution_alternative(
            resolution.kind, resolution.subject_id, resolution.grader_2
        )
        _validate_resolution_alternative(
            resolution.kind, resolution.subject_id, resolution.selected
        )
        expected_selected = _audit_selected_alternative(sealed_ledger, candidate_grade, resolution)
        if resolution.selected != expected_selected:
            raise GradeInconclusiveError("resolved audit selected alternative is inconsistent")
        if resolution.selected.entry_grade is not None:
            selected_entries.append(resolution.selected.entry_grade)
        elif resolution.selected.out_of_ledger_claim is not None:
            selected_claims.append(resolution.selected.out_of_ledger_claim)
        elif resolution.selected.narrative_score is not None:
            selected_narratives.append(resolution.selected.narrative_score)
    if grader_1_requests != {candidate_grade.request_fingerprint}:
        raise GradeInconclusiveError("resolved audit grader-1 request binding is invalid")
    if len(grader_2_requests) != 1:
        raise GradeInconclusiveError("resolved audit grader-2 request binding is invalid")
    if selected_entries != candidate_grade.entry_grades:
        raise GradeInconclusiveError("resolved audit entry selection does not match grade")
    if selected_claims != candidate_grade.out_of_ledger_claims:
        raise GradeInconclusiveError("resolved audit claim selection does not match grade")
    if selected_narratives != candidate_grade.narrative_scores:
        raise GradeInconclusiveError("resolved audit narrative selection does not match grade")


def _validate_resolution_alternative(
    kind: DisputeKind,
    subject_id: str,
    alternative: GradeAlternative,
) -> None:
    if kind == "entry_grade":
        if alternative.entry_grade is None or alternative.entry_grade.ledger_id != subject_id:
            raise GradeInconclusiveError("resolved audit entry alternative is invalid")
        return
    if kind == "narrative_score":
        if (
            alternative.narrative_score is None
            or alternative.narrative_score.dimension != subject_id
        ):
            raise GradeInconclusiveError("resolved audit narrative alternative is invalid")
        return
    if alternative.absent_claim:
        return
    if (
        alternative.out_of_ledger_claim is None
        or alternative.out_of_ledger_claim.claim_id != subject_id
    ):
        raise GradeInconclusiveError("resolved audit claim alternative is invalid")


def _audit_selected_alternative(
    sealed_ledger: SealedLedger,
    candidate_grade: CandidateGrade,
    resolution: GradeResolution,
) -> GradeAlternative:
    outcome_equal = _resolution_outcome_equal(resolution)
    if resolution.dispute is None:
        if resolution.referee is not None or not outcome_equal:
            raise GradeInconclusiveError("resolved audit agreement is invalid")
        return resolution.grader_1
    if resolution.referee is None or outcome_equal:
        raise GradeInconclusiveError("resolved audit dispute is invalid")
    dispute = resolution.dispute
    if (
        dispute.anonymous_label != candidate_grade.anonymous_label
        or dispute.ledger_fingerprint != candidate_grade.ledger_fingerprint
        or dispute.kind != resolution.kind
        or dispute.subject_id != resolution.subject_id
        or dispute.grader_1 != resolution.grader_1
        or dispute.grader_2 != resolution.grader_2
    ):
        raise GradeInconclusiveError("resolved audit dispute binding is invalid")
    claim_identity = None
    if resolution.kind == "out_of_ledger_claim":
        present_claims = [
            alternative.out_of_ledger_claim
            for alternative in (resolution.grader_1, resolution.grader_2)
            if alternative.out_of_ledger_claim is not None
        ]
        if not present_claims:
            raise GradeInconclusiveError("resolved audit claim dispute is invalid")
        identities = {_claim_identity(claim) for claim in present_claims}
        if len(identities) != 1:
            raise GradeInconclusiveError("resolved audit claim identity is invalid")
        claim_identity = next(iter(identities))
    if resolution.kind == "entry_grade":
        authoritative = next(
            entry.materiality
            for entry in sealed_ledger.ledger.entries
            if entry.ledger_id == resolution.subject_id
        )
        if dispute.materiality is not authoritative:
            raise GradeInconclusiveError("resolved audit entry materiality is not authoritative")
    record = _ComparisonRecord(
        kind=resolution.kind,
        subject_id=resolution.subject_id,
        materiality=dispute.materiality,
        grader_1=resolution.grader_1,
        grader_2=resolution.grader_2,
        claim_identity=claim_identity,
        dispute=dispute,
    )
    _validate_grade_referee(sealed_ledger, record, resolution.referee)
    if resolution.referee.selected_grade_resolution == "accept_grader_1":
        return resolution.grader_1
    if resolution.referee.selected_grade_resolution == "accept_grader_2":
        return resolution.grader_2
    assert resolution.referee.replacement_grade_alternative is not None
    return resolution.referee.replacement_grade_alternative


def _resolution_outcome_equal(resolution: GradeResolution) -> bool:
    if resolution.kind == "entry_grade":
        return _entry_outcome_equal(
            resolution.grader_1.entry_grade,
            resolution.grader_2.entry_grade,
        )
    if resolution.kind == "narrative_score":
        first = resolution.grader_1.narrative_score
        second = resolution.grader_2.narrative_score
        assert first is not None and second is not None
        return _narrative_outcome_equal(first, second)
    return _claim_outcome_equal(
        resolution.grader_1.out_of_ledger_claim,
        resolution.grader_2.out_of_ledger_claim,
    )


def _validated_grade_pair(
    sealed_ledger: SealedLedger,
    grader_1: CandidateGrade,
    grader_2: CandidateGrade,
) -> tuple[SealedLedger, CandidateGrade, CandidateGrade]:
    sealed = _require_valid_sealed_ledger(sealed_ledger)
    first = _require_valid_grade(sealed, grader_1)
    second = _require_valid_grade(sealed, grader_2)
    if first.anonymous_label != second.anonymous_label:
        raise GradeInconclusiveError("grades must have matching anonymous labels")
    return sealed, first, second


def _comparison_records(
    sealed_ledger: SealedLedger,
    grader_1: CandidateGrade,
    grader_2: CandidateGrade,
) -> list[_ComparisonRecord]:
    records: list[_ComparisonRecord] = []
    first_entries = {grade.ledger_id: grade for grade in grader_1.entry_grades}
    second_entries = {grade.ledger_id: grade for grade in grader_2.entry_grades}
    for entry in sealed_ledger.ledger.entries:
        first = _entry_alternative(grader_1.request_fingerprint, first_entries[entry.ledger_id])
        second = _entry_alternative(grader_2.request_fingerprint, second_entries[entry.ledger_id])
        different = not _entry_outcome_equal(first.entry_grade, second.entry_grade)
        dispute = (
            _build_dispute(
                grader_1,
                "entry_grade",
                entry.ledger_id,
                entry.materiality,
                first,
                second,
            )
            if different
            else None
        )
        records.append(
            _ComparisonRecord(
                "entry_grade",
                entry.ledger_id,
                entry.materiality,
                first,
                second,
                None,
                dispute,
            )
        )

    first_claims = {_claim_identity(claim): claim for claim in grader_1.out_of_ledger_claims}
    second_claims = {_claim_identity(claim): claim for claim in grader_2.out_of_ledger_claims}
    claim_identities = sorted(set(first_claims) | set(second_claims))
    subjects = _claim_subject_ids(claim_identities)
    for identity in claim_identities:
        subject_id = subjects[identity]
        first_claim = first_claims.get(identity)
        second_claim = second_claims.get(identity)
        first = _claim_alternative(grader_1.request_fingerprint, first_claim, subject_id)
        second = _claim_alternative(grader_2.request_fingerprint, second_claim, subject_id)
        different = not _claim_outcome_equal(first_claim, second_claim)
        present_claims = [claim for claim in (first_claim, second_claim) if claim is not None]
        materiality = max(
            (claim.materiality for claim in present_claims),
            key=_MATERIALITY_RANK.__getitem__,
        )
        dispute = (
            _build_dispute(
                grader_1,
                "out_of_ledger_claim",
                subject_id,
                materiality,
                first,
                second,
            )
            if different
            else None
        )
        records.append(
            _ComparisonRecord(
                "out_of_ledger_claim",
                subject_id,
                materiality,
                first,
                second,
                identity,
                dispute,
            )
        )

    first_scores = {score.dimension: score for score in grader_1.narrative_scores}
    second_scores = {score.dimension: score for score in grader_2.narrative_scores}
    for dimension in _NARRATIVE_DIMENSIONS:
        first = _narrative_alternative(grader_1.request_fingerprint, first_scores[dimension])
        second = _narrative_alternative(grader_2.request_fingerprint, second_scores[dimension])
        different = not _narrative_outcome_equal(first_scores[dimension], second_scores[dimension])
        dispute = (
            _build_dispute(
                grader_1,
                "narrative_score",
                dimension,
                None,
                first,
                second,
            )
            if different
            else None
        )
        records.append(
            _ComparisonRecord(
                "narrative_score",
                dimension,
                None,
                first,
                second,
                None,
                dispute,
            )
        )
    return records


def _build_dispute(
    candidate_grade: CandidateGrade,
    kind: DisputeKind,
    subject_id: str,
    materiality: Materiality | None,
    grader_1: GradeAlternative,
    grader_2: GradeAlternative,
) -> GradeDispute:
    rationale = {
        "entry_grade": "The blind graders disagree on an outcome-relevant entry-grade field.",
        "out_of_ledger_claim": (
            "The blind graders disagree on claim presence or an outcome-relevant claim field."
        ),
        "narrative_score": "The blind graders assign different narrative scores.",
    }[kind]
    return GradeDispute(
        dispute_id=f"grade-{_kind_token(kind)}-{subject_id}",
        anonymous_label=candidate_grade.anonymous_label,
        ledger_fingerprint=candidate_grade.ledger_fingerprint,
        kind=kind,
        subject_id=subject_id,
        materiality=materiality,
        grader_1=grader_1,
        grader_2=grader_2,
        rationale=rationale,
    )


def _selected_alternative(
    sealed_ledger: SealedLedger,
    record: _ComparisonRecord,
    decision: RefereeDecision | None,
) -> GradeAlternative:
    if record.dispute is None:
        if decision is not None:
            raise GradeInconclusiveError("referee cannot rewrite an undisputed value")
        return _alternative_snapshot(record.grader_1)
    if decision is None:
        raise GradeInconclusiveError("material grade dispute requires referee decision")
    _validate_grade_referee(sealed_ledger, record, decision)
    if decision.selected_grade_resolution == "accept_grader_1":
        return _alternative_snapshot(record.grader_1)
    if decision.selected_grade_resolution == "accept_grader_2":
        return _alternative_snapshot(record.grader_2)
    assert decision.selected_grade_resolution == "replace"
    assert decision.replacement_grade_alternative is not None
    return _alternative_snapshot(decision.replacement_grade_alternative)


def _validate_grade_referee(
    sealed_ledger: SealedLedger,
    record: _ComparisonRecord,
    decision: RefereeDecision,
) -> None:
    dispute = record.dispute
    assert dispute is not None
    if decision.selected_grade_resolution is None:
        raise GradeInconclusiveError("grade referee must select one grade resolution")
    if (
        decision.selected_disposition is not None
        or decision.selected_ledger_resolution is not None
        or decision.replacement_entries
    ):
        raise GradeInconclusiveError("grade referee cannot use a legacy resolution domain")
    if decision.source_ids:
        raise GradeInconclusiveError("grade referee may use only the supplied dispute")
    strict_dispute = _dispute_snapshot(dispute)
    if decision.grade_dispute_fingerprint != model_fingerprint(strict_dispute):
        raise GradeInconclusiveError("grade referee dispute fingerprint mismatch")
    if decision.selected_grade_resolution == "replace":
        replacement = decision.replacement_grade_alternative
        assert replacement is not None
        _validate_replacement(sealed_ledger, record, replacement)


def _validate_replacement(
    sealed_ledger: SealedLedger,
    record: _ComparisonRecord,
    replacement: GradeAlternative,
) -> None:
    replacement = _alternative_snapshot(replacement)
    if record.kind == "entry_grade":
        entry_value = replacement.entry_grade
        if entry_value is None:
            raise GradeInconclusiveError("replacement kind does not match entry-grade dispute")
        if entry_value.ledger_id != record.subject_id:
            raise GradeInconclusiveError("replacement entry subject mismatch")
        ledger_materiality = next(
            entry.materiality
            for entry in sealed_ledger.ledger.entries
            if entry.ledger_id == record.subject_id
        )
        if record.materiality is not ledger_materiality:
            raise GradeInconclusiveError("entry dispute understates ledger materiality")
        return
    if record.kind == "narrative_score":
        narrative_value = replacement.narrative_score
        if narrative_value is None:
            raise GradeInconclusiveError("replacement kind does not match narrative dispute")
        if narrative_value.dimension != record.subject_id:
            raise GradeInconclusiveError("replacement narrative subject mismatch")
        return
    if replacement.absent_claim:
        return
    claim_value = replacement.out_of_ledger_claim
    if claim_value is None:
        raise GradeInconclusiveError("replacement kind does not match claim dispute")
    if claim_value.claim_id != record.subject_id:
        raise GradeInconclusiveError("replacement claim subject mismatch")
    assert record.claim_identity is not None
    if _claim_identity(claim_value) != record.claim_identity:
        raise GradeInconclusiveError("replacement claim identity mismatch")
    assert record.materiality is not None
    if _MATERIALITY_RANK[claim_value.materiality] < _MATERIALITY_RANK[record.materiality]:
        raise GradeInconclusiveError("replacement claim cannot understate materiality")


def _claim_subject_ids(
    identities: list[ClaimIdentity],
) -> dict[ClaimIdentity, str]:
    return {
        identity: f"matched-claim-{index:04d}" for index, identity in enumerate(identities, start=1)
    }


def _claim_identity(claim: OutOfLedgerClaim) -> ClaimIdentity:
    return (
        _normalize_claim_identity_text(claim.claim_text),
        _normalize_claim_identity_text(claim.report_location),
        claim.category.value,
        tuple(sorted(claim.related_ledger_ids)),
    )


def _normalize_claim_identity_text(value: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", value).casefold().split())


def _entry_outcome_equal(first: EntryGrade | None, second: EntryGrade | None) -> bool:
    assert first is not None and second is not None
    # Locations and rationales remain as audit evidence but do not change the
    # disposition credit or any published v1 safety gate.  The deterministic
    # agreement therefore selects grader 1 without a referee.
    return (
        first.ledger_id == second.ledger_id
        and first.disposition is second.disposition
        and first.finding_codes == second.finding_codes
    )


def _narrative_outcome_equal(first: NarrativeScore, second: NarrativeScore) -> bool:
    return first.score == second.score and first.finding_codes == second.finding_codes


def _claim_outcome_equal(first: OutOfLedgerClaim | None, second: OutOfLedgerClaim | None) -> bool:
    if first is None or second is None:
        return False
    return (
        _claim_identity(first) == _claim_identity(second)
        and first.disposition is second.disposition
        and first.materiality is second.materiality
    )


def _entry_alternative(request_fingerprint: str, grade: EntryGrade) -> GradeAlternative:
    return GradeAlternative(
        request_fingerprint=request_fingerprint,
        entry_grade=grade.model_copy(deep=True),
    )


def _claim_alternative(
    request_fingerprint: str,
    claim: OutOfLedgerClaim | None,
    subject_id: str,
) -> GradeAlternative:
    if claim is None:
        return GradeAlternative(
            request_fingerprint=request_fingerprint,
            absent_claim=True,
        )
    return GradeAlternative(
        request_fingerprint=request_fingerprint,
        out_of_ledger_claim=claim.model_copy(update={"claim_id": subject_id}, deep=True),
    )


def _narrative_alternative(request_fingerprint: str, score: NarrativeScore) -> GradeAlternative:
    return GradeAlternative(
        request_fingerprint=request_fingerprint,
        narrative_score=score.model_copy(deep=True),
    )


def _kind_token(kind: DisputeKind) -> str:
    return {
        "entry_grade": "entry",
        "out_of_ledger_claim": "claim",
        "narrative_score": "narrative",
    }[kind]


def _require_valid_sealed_ledger(sealed_ledger: SealedLedger) -> SealedLedger:
    try:
        return _sealed_snapshot(sealed_ledger)
    except (TypeError, ValidationError, ValueError) as error:
        raise GradeInconclusiveError("malformed sealed ledger") from error


def _require_valid_grade(
    sealed_ledger: SealedLedger, candidate_grade: CandidateGrade
) -> CandidateGrade:
    issues = validate_grade(sealed_ledger, candidate_grade)
    if issues:
        raise GradeInconclusiveError(
            "invalid candidate grade: " + ", ".join(issue.code for issue in issues)
        )
    try:
        return _grade_snapshot(candidate_grade)
    except (TypeError, ValidationError, ValueError) as error:
        raise GradeInconclusiveError("malformed candidate grade") from error


def _sealed_snapshot(value: SealedLedger) -> SealedLedger:
    if not isinstance(value, SealedLedger):
        raise TypeError("sealed_ledger must be a SealedLedger")
    return SealedLedger.model_validate(
        value.model_dump(mode="python", warnings="error"), strict=True
    )


def _grade_snapshot(value: CandidateGrade) -> CandidateGrade:
    if not isinstance(value, CandidateGrade):
        raise TypeError("candidate_grade must be a CandidateGrade")
    return CandidateGrade.model_validate(
        value.model_dump(mode="python", warnings="error"), strict=True
    )


def _alternative_snapshot(value: GradeAlternative) -> GradeAlternative:
    if not isinstance(value, GradeAlternative):
        raise TypeError("alternative must be a GradeAlternative")
    return GradeAlternative.model_validate(
        value.model_dump(mode="python", warnings="error"), strict=True
    )


def _dispute_snapshot(value: GradeDispute | None) -> GradeDispute:
    if not isinstance(value, GradeDispute):
        raise TypeError("dispute must be a GradeDispute")
    return GradeDispute.model_validate(
        value.model_dump(mode="python", warnings="error"), strict=True
    )


def _referee_snapshot(value: RefereeDecision) -> RefereeDecision:
    if not isinstance(value, RefereeDecision):
        raise TypeError("referee decision must be a RefereeDecision")
    return RefereeDecision.model_validate(
        value.model_dump(mode="python", warnings="error"), strict=True
    )


def _strict_decisions(
    values: list[RefereeDecision] | tuple[RefereeDecision, ...],
) -> list[RefereeDecision]:
    if not isinstance(values, (list, tuple)):
        raise GradeInconclusiveError("referee decisions must be a list or tuple")
    snapshots: list[RefereeDecision] = []
    for value in values:
        try:
            snapshots.append(_referee_snapshot(value))
        except (TypeError, ValidationError, ValueError) as error:
            raise GradeInconclusiveError("malformed referee decision") from error
    return snapshots


def _grade_resolution_snapshot(value: GradeResolution) -> GradeResolution:
    if not isinstance(value, GradeResolution):
        raise TypeError("audit item must be a GradeResolution")
    if value.kind not in {
        "entry_grade",
        "out_of_ledger_claim",
        "narrative_score",
    }:
        raise TypeError("audit item has an invalid kind")
    return GradeResolution(
        kind=value.kind,
        subject_id=value.subject_id,
        grader_1=_alternative_snapshot(value.grader_1),
        grader_2=_alternative_snapshot(value.grader_2),
        selected=_alternative_snapshot(value.selected),
        dispute=None if value.dispute is None else _dispute_snapshot(value.dispute),
        referee=None if value.referee is None else _referee_snapshot(value.referee),
    )


def _resolution_fingerprint(
    grade: CandidateGrade,
    audit: tuple[GradeResolution, ...],
    original_grader_1: CandidateGrade,
    original_grader_2: CandidateGrade,
    referee_decisions: tuple[RefereeDecision, ...],
) -> str:
    return sha256_digest(
        canonical_json_bytes(
            {
                "grade": grade.model_dump(mode="json"),
                "audit": [_grade_resolution_payload(value) for value in audit],
                "original_grader_1": original_grader_1.model_dump(mode="json"),
                "original_grader_2": original_grader_2.model_dump(mode="json"),
                "referee_decisions": [
                    decision.model_dump(mode="json") for decision in referee_decisions
                ],
            }
        )
    )


def _grade_resolution_payload(value: GradeResolution) -> dict[str, object]:
    return {
        "kind": value.kind,
        "subject_id": value.subject_id,
        "grader_1": value.grader_1.model_dump(mode="json"),
        "grader_2": value.grader_2.model_dump(mode="json"),
        "selected": value.selected.model_dump(mode="json"),
        "dispute": None if value.dispute is None else value.dispute.model_dump(mode="json"),
        "referee": None if value.referee is None else value.referee.model_dump(mode="json"),
    }


def _raw_entry_identity_issues(
    sealed_ledger: SealedLedger, value: CandidateGrade
) -> list[EvaluationIssue]:
    if not isinstance(value, CandidateGrade) or not isinstance(value.entry_grades, list):
        return []
    if not all(
        isinstance(entry, EntryGrade) and type(entry.ledger_id) is str
        for entry in value.entry_grades
    ):
        return []
    ledger_ids = {entry.ledger_id for entry in sealed_ledger.ledger.entries}
    identifiers = [entry.ledger_id for entry in value.entry_grades]
    identifier_set = set(identifiers)
    issues: list[EvaluationIssue] = []
    if len(identifiers) != len(identifier_set):
        issues.append(
            _issue(
                "GRADE_DUPLICATE_LEDGER_ID",
                "A ledger entry must receive exactly one grade.",
            )
        )
    unknown = identifier_set - ledger_ids
    if unknown:
        issues.append(
            _issue(
                "GRADE_LEDGER_ENTRY_UNKNOWN",
                "Entry grades must identify sealed ledger entries.",
                sorted(unknown),
            )
        )
    missing = ledger_ids - identifier_set
    if missing:
        issues.append(
            _issue(
                "GRADE_LEDGER_ENTRY_MISSING",
                "Every sealed ledger entry must receive exactly one grade.",
                sorted(missing),
            )
        )
    return issues


def _raw_grade_types_valid(value: CandidateGrade) -> bool:
    if not isinstance(value, CandidateGrade):
        return False
    return (
        isinstance(value.entry_grades, list)
        and all(
            isinstance(entry, EntryGrade)
            and type(entry.disposition) is CoverageDisposition
            and isinstance(entry.finding_codes, list)
            and all(type(code) is EntryFindingCode for code in entry.finding_codes)
            for entry in value.entry_grades
        )
        and isinstance(value.out_of_ledger_claims, list)
        and all(
            isinstance(claim, OutOfLedgerClaim)
            and type(claim.disposition) is CoverageDisposition
            and type(claim.category) is LedgerCategory
            and type(claim.materiality) is Materiality
            for claim in value.out_of_ledger_claims
        )
        and isinstance(value.narrative_scores, list)
        and all(
            isinstance(score, NarrativeScore)
            and type(score.score) is int
            and isinstance(score.finding_codes, list)
            and all(type(code) is NarrativeFindingCode for code in score.finding_codes)
            for score in value.narrative_scores
        )
    )


def _raw_duplicate_claim_ids(value: CandidateGrade) -> bool:
    if not isinstance(value, CandidateGrade) or not isinstance(value.out_of_ledger_claims, list):
        return False
    identifiers = [
        claim.claim_id
        for claim in value.out_of_ledger_claims
        if isinstance(claim, OutOfLedgerClaim)
    ]
    return len(identifiers) == len(value.out_of_ledger_claims) and len(identifiers) != len(
        set(identifiers)
    )


def _entry_finding_issues(
    grade: EntryGrade,
    ledger_entry: object,
) -> list[EvaluationIssue]:
    if len(grade.finding_codes) != len(set(grade.finding_codes)):
        return [
            _issue(
                "GRADE_ENTRY_FINDING_DUPLICATE",
                "Entry semantic finding codes must not repeat.",
                [grade.ledger_id],
            )
        ]
    if not isinstance(ledger_entry, LedgerEntry):
        return []
    invalid_codes: list[EntryFindingCode] = []
    for code in grade.finding_codes:
        if code is EntryFindingCode.CRITICAL_LEDGER_ENTRY_MISSING:
            valid = (
                grade.disposition is CoverageDisposition.MISSING
                and ledger_entry.materiality is Materiality.CRITICAL
            )
        elif code is EntryFindingCode.MATERIAL_EXCEPTION_MISSING:
            valid = (
                grade.disposition
                in {CoverageDisposition.MISSING, CoverageDisposition.PARTIAL}
                and ledger_entry.category is LedgerCategory.EXCEPTION
                and ledger_entry.materiality in {Materiality.MATERIAL, Materiality.CRITICAL}
            )
        elif code is EntryFindingCode.CONSEQUENCE_TRIGGER_DETACHED:
            valid = (
                grade.disposition
                in {
                    CoverageDisposition.PARTIAL,
                    CoverageDisposition.OVERSTATED,
                    CoverageDisposition.CONTRADICTED,
                }
                and ledger_entry.category
                in {
                    LedgerCategory.PENALTY,
                    LedgerCategory.ENFORCEMENT,
                    LedgerCategory.REMEDY,
                }
                and ledger_entry.consequence is not None
                and (ledger_entry.trigger is not None or bool(ledger_entry.relationship_ids))
            )
        else:
            valid = False
        if not valid:
            invalid_codes.append(code)
    return [
        _issue(
            "GRADE_ENTRY_FINDING_CONTEXT_INVALID",
            f"ledger_id={grade.ledger_id} finding_code={code.value} "
            f"allowed_context={_entry_finding_allowed_context(code)}.",
            [grade.ledger_id],
        )
        for code in invalid_codes
    ]


def _narrative_finding_issues(score: NarrativeScore) -> list[EvaluationIssue]:
    if len(score.finding_codes) != len(set(score.finding_codes)):
        return [
            _issue(
                "GRADE_NARRATIVE_FINDING_DUPLICATE",
                "Narrative semantic finding codes must not repeat.",
                [score.dimension],
            )
        ]
    return [
        _issue(
            "GRADE_NARRATIVE_FINDING_CONTEXT_INVALID",
            f"dimension={score.dimension} finding_code={code.value} "
            f"allowed_context={_narrative_finding_allowed_context(code)}.",
            [score.dimension],
        )
        for code in score.finding_codes
        if code is not NarrativeFindingCode.KEY_REQUIREMENTS_ACTION_PLAN
        or score.dimension not in {"key_requirements", "requirements_workplan_boundary"}
        or score.score > 2
    ]


def _issue(code: str, message: str, related_ids: list[str] | None = None) -> EvaluationIssue:
    return EvaluationIssue(
        code=code,
        severity=IssueSeverity.ERROR,
        message=message,
        related_ids=related_ids or [],
    )


def _unique_issues(issues: list[EvaluationIssue]) -> list[EvaluationIssue]:
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    result: list[EvaluationIssue] = []
    for issue in issues:
        key = (issue.code, issue.message, tuple(issue.related_ids))
        if key not in seen:
            seen.add(key)
            result.append(issue)
    return result
