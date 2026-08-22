"""Deterministic semantic-baseline compiler tests."""

from __future__ import annotations

import hashlib
from datetime import date

import pytest

from regulatory_harvest.evaluation.attorney_models import (
    AttorneyEvaluationCase,
    BlindAssignment,
    CandidateReport,
    CandidateRole,
    CaseEnvelope,
    EvaluationMode,
    EvaluationSource,
    RequestedAuthority,
    model_fingerprint,
)
from regulatory_harvest.evaluation.attorney_v2_compiler import (
    CompilationError,
    compile_baseline,
    index_review,
    material_disputes,
    resolve_exact_passage,
)
from regulatory_harvest.evaluation.attorney_v2_models import (
    SemanticPassage,
    SemanticProposal,
    SourceAuditV2,
    SourceRefereeResponseV2,
    SourceReviewV2,
)
from regulatory_harvest.models import SourceQuality, SourceRole
from regulatory_harvest.storage import canonical_json_bytes

SOURCE_TEXT = (
    "A covered operator must file a notice. "
    "The filing duty does not apply to an exempt operator. "
    "An exempt operator means an operator with no covered activity."
)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def envelope() -> CaseEnvelope:
    report_text = "A placeholder candidate report."
    source = EvaluationSource(
        source_id="rule-1",
        title="Example Rule",
        normalized_text=SOURCE_TEXT,
        content_hash=_sha256(SOURCE_TEXT),
        jurisdiction="Example State",
        authority_type="regulation",
        source_role=SourceRole.OFFICIAL_PRIMARY,
        source_quality=SourceQuality.PRIMARY,
        completeness="complete",
        language="en",
    )
    case = AttorneyEvaluationCase(
        case_id="example-case",
        mode=EvaluationMode.CLOSED_UNIVERSE,
        question="What does the example rule require?",
        jurisdiction="Example State",
        as_of=date(2026, 8, 18),
        requested_authorities=[
            RequestedAuthority(
                authority_id="example-rule",
                title="Example Rule",
                jurisdiction="Example State",
                authority_type="regulation",
                source_ids=[source.source_id],
            )
        ],
        sources=[source],
        candidates=[
            CandidateReport(
                candidate_id="candidate",
                role=CandidateRole.CANDIDATE,
                report_text=report_text,
                report_hash=_sha256(report_text),
            )
        ],
    )
    return CaseEnvelope(
        case=case,
        assignments=[BlindAssignment(anonymous_label="A", candidate_id="candidate")],
        case_fingerprint=model_fingerprint(case),
        seed_fingerprint="f" * 64,
    )


def proposal(
    statement: str,
    quote: str,
    *,
    kind: str = "obligation",
    importance: str = "critical",
    dependency: dict[str, str] | None = None,
) -> dict[str, object]:
    return {
        "statement": statement,
        "kind": kind,
        "importance": importance,
        "passages": [{"source_id": "rule-1", "quote": quote}],
        "dependency": dependency,
        "confidence": "clear",
        "rationale": "The cited operative text supports this semantic proposal.",
    }


def review_with_exception() -> SourceReviewV2:
    return SourceReviewV2.model_validate(
        {
            "schema_version": "2.0",
            "proposals": [
                proposal(
                    "A covered operator must file a notice.",
                    "must file a notice",
                ),
                proposal(
                    "The filing duty does not apply to an exempt operator.",
                    "does not apply to an exempt operator",
                    kind="exception",
                    importance="material",
                    dependency={
                        "relationship": "exception_to",
                        "target_statement": "A covered operator must file a notice.",
                    },
                ),
            ],
        }
    )


def empty_audit(review: SourceReviewV2 | None = None) -> SourceAuditV2:
    effective_review = review or review_with_exception()
    return SourceAuditV2.validate_for_indexed_proposals(
        {"schema_version": "2.0", "concerns": []}, index_review(effective_review)
    )


def audit_with_omission(review: SourceReviewV2) -> SourceAuditV2:
    return SourceAuditV2.validate_for_indexed_proposals(
        {
            "schema_version": "2.0",
            "concerns": [
                {
                    "target_proposal_ref": None,
                    "concern_type": "omission",
                    "passages": [
                        {
                            "source_id": "rule-1",
                            "quote": (
                                "An exempt operator means an operator with no covered activity"
                            ),
                        }
                    ],
                    "explanation": "The definition is material to the exception.",
                    "correction": proposal(
                        "An exempt operator means an operator with no covered activity.",
                        "An exempt operator means an operator with no covered activity",
                        kind="definition",
                        importance="material",
                    ),
                }
            ],
        },
        index_review(review),
    )


def audit_with_ambiguity(review: SourceReviewV2) -> SourceAuditV2:
    return SourceAuditV2.validate_for_indexed_proposals(
        {
            "schema_version": "2.0",
            "concerns": [
                {
                    "target_proposal_ref": "P0001",
                    "concern_type": "ambiguity",
                    "passages": [{"source_id": "rule-1", "quote": "must file a notice"}],
                    "explanation": "The source does not resolve the filing trigger.",
                    "correction": None,
                }
            ],
        },
        index_review(review),
    )


def audit_with_target_correction(review: SourceReviewV2) -> SourceAuditV2:
    return SourceAuditV2.validate_for_indexed_proposals(
        {
            "schema_version": "2.0",
            "concerns": [
                {
                    "target_proposal_ref": "P0002",
                    "concern_type": "incorrect_statement",
                    "passages": [
                        {"source_id": "rule-1", "quote": "does not apply to an exempt operator"}
                    ],
                    "explanation": "The exception omits the relevant condition.",
                    "correction": proposal(
                        (
                            "The filing duty does not apply to an exempt operator "
                            "with no covered activity."
                        ),
                        "does not apply to an exempt operator",
                        kind="exception",
                        importance="material",
                        dependency={
                            "relationship": "exception_to",
                            "target_statement": "A covered operator must file a notice.",
                        },
                    ),
                }
            ],
        },
        index_review(review),
    )


def referee_for(
    review: SourceReviewV2, audit: SourceAuditV2, decision: str
) -> SourceRefereeResponseV2:
    disputes = material_disputes(review, audit)
    return SourceRefereeResponseV2.validate_for_disputes(
        {
            "schema_version": "2.0",
            "decisions": [
                {
                    "dispute_id": disputes[0].dispute_id,
                    "decision": decision,
                    "passages": [{"source_id": "rule-1", "quote": "must file a notice"}],
                    "rationale": "The decision is limited to the cited source text.",
                }
            ],
        },
        disputes,
    )


def referee_with_decisions(
    review: SourceReviewV2, audit: SourceAuditV2, decisions: list[str]
) -> SourceRefereeResponseV2:
    disputes = material_disputes(review, audit)
    return SourceRefereeResponseV2.validate_for_disputes(
        {
            "schema_version": "2.0",
            "decisions": [
                {
                    "dispute_id": dispute.dispute_id,
                    "decision": decision,
                    "passages": [{"source_id": "rule-1", "quote": "must file a notice"}],
                    "rationale": "The decision is limited to the cited source text.",
                }
                for dispute, decision in zip(disputes, decisions, strict=True)
            ],
        },
        disputes,
    )


def test_index_review_assigns_request_local_proposal_references() -> None:
    review = SourceReviewV2.model_validate(
        {
            "schema_version": "2.0",
            "proposals": [
                {
                    "statement": "An operator must file a notice.",
                    "kind": "obligation",
                    "importance": "critical",
                    "passages": [{"source_id": "rule-1", "quote": "must file a notice"}],
                    "dependency": None,
                    "confidence": "clear",
                    "rationale": "The operative text is mandatory.",
                }
            ],
        }
    )

    assert [item.proposal_ref for item in index_review(review)] == ["P0001"]


def test_compiler_rejects_nonunique_exact_quote() -> None:
    with pytest.raises(CompilationError, match="PASSAGE_AMBIGUOUS"):
        resolve_exact_passage("notice notice", SemanticPassage(source_id="s", quote="notice"))


def test_compiler_rejects_overlapping_exact_quote_occurrences() -> None:
    with pytest.raises(CompilationError, match="PASSAGE_AMBIGUOUS"):
        resolve_exact_passage("aaa", SemanticPassage(source_id="s", quote="aa"))


@pytest.mark.parametrize(
    ("source_text", "passage"),
    [
        ("notice", {"source_id": "s", "quote": "notice"}),
        ([], SemanticPassage(source_id="s", quote="notice")),
        (
            "notice",
            SemanticPassage.model_construct(source_id=["s"], quote="notice"),
        ),
        ([[]], SemanticPassage(source_id="s", quote="notice")),
    ],
)
def test_resolve_exact_passage_bounds_raw_and_validation_bypass_inputs(
    source_text: object, passage: object
) -> None:
    with pytest.raises(CompilationError) as error:
        resolve_exact_passage(source_text, passage)  # type: ignore[arg-type]

    assert str(error.value) == "INPUT_INVALID"


def test_resolve_exact_passage_bounds_cyclic_bypass_input() -> None:
    cyclic: list[object] = []
    cyclic.append(cyclic)

    with pytest.raises(CompilationError) as error:
        resolve_exact_passage(cyclic, SemanticPassage(source_id="s", quote="notice"))  # type: ignore[arg-type]

    assert str(error.value) == "INPUT_INVALID"


def test_resolve_exact_passage_bounds_deep_model_construct_passage() -> None:
    deep: object = "notice"
    for _ in range(65):
        deep = [deep]
    malformed = SemanticPassage.model_construct(source_id="s", quote=deep)

    with pytest.raises(CompilationError) as error:
        resolve_exact_passage("notice", malformed)

    assert str(error.value) == "INPUT_INVALID"


def test_compiler_assigns_ids_after_semantic_decisions() -> None:
    baseline = compile_baseline(envelope(), review_with_exception(), empty_audit(), None)

    assert [item.requirement_id for item in baseline.requirements] == ["REQ-0001", "REQ-0002"]
    assert baseline.relationships[0].relationship_id == "REL-0001"
    assert baseline.relationships[0].source_requirement_id == "REQ-0002"
    assert baseline.relationships[0].target_requirement_id == "REQ-0001"


def test_compiler_accepts_an_auditor_omission_only_after_referee_acceptance() -> None:
    review = review_with_exception()
    audit = audit_with_omission(review)
    baseline = compile_baseline(
        envelope(), review, audit, referee_for(review, audit, "accept_auditor")
    )

    assert [item.statement for item in baseline.requirements] == [
        "A covered operator must file a notice.",
        "The filing duty does not apply to an exempt operator.",
        "An exempt operator means an operator with no covered activity.",
    ]
    assert baseline.unresolved_dispute_ids == []


def test_compiler_retains_reviewer_proposal_and_records_unresolved_dispute() -> None:
    review = review_with_exception()
    audit = audit_with_omission(review)
    baseline = compile_baseline(envelope(), review, audit, referee_for(review, audit, "unresolved"))

    assert len(baseline.requirements) == 2
    assert baseline.unresolved_dispute_ids == ["D0001"]


@pytest.mark.parametrize(
    ("decision", "expected_unresolved"),
    [
        ("accept_reviewer", []),
        ("accept_auditor", ["D0001"]),
        ("unresolved", ["D0001"]),
    ],
)
def test_compiler_retains_ambiguity_semantics_for_each_referee_choice(
    decision: str, expected_unresolved: list[str]
) -> None:
    review = review_with_exception()
    audit = audit_with_ambiguity(review)

    baseline = compile_baseline(envelope(), review, audit, referee_for(review, audit, decision))

    assert baseline.requirements[0].confidence == "clear"
    assert baseline.unresolved_dispute_ids == expected_unresolved


@pytest.mark.parametrize(
    ("decision", "expected_statement", "expected_unresolved"),
    [
        (
            "accept_reviewer",
            "The filing duty does not apply to an exempt operator.",
            [],
        ),
        (
            "accept_auditor",
            "The filing duty does not apply to an exempt operator with no covered activity.",
            [],
        ),
        (
            "unresolved",
            "The filing duty does not apply to an exempt operator.",
            ["D0001"],
        ),
    ],
)
def test_compiler_applies_each_referee_choice_for_a_corrected_concern(
    decision: str, expected_statement: str, expected_unresolved: list[str]
) -> None:
    review = review_with_exception()
    audit = audit_with_target_correction(review)

    baseline = compile_baseline(envelope(), review, audit, referee_for(review, audit, decision))

    assert baseline.requirements[1].statement == expected_statement
    assert baseline.unresolved_dispute_ids == expected_unresolved


def test_compiler_accepts_the_reviewer_without_applying_a_rejected_omission() -> None:
    review = review_with_exception()
    audit = audit_with_omission(review)

    baseline = compile_baseline(
        envelope(), review, audit, referee_for(review, audit, "accept_reviewer")
    )

    assert len(baseline.requirements) == 2
    assert baseline.unresolved_dispute_ids == []


def test_material_disputes_index_every_returned_audit_concern() -> None:
    review = review_with_exception()
    audit = audit_with_omission(review)

    disputes = material_disputes(review, audit)

    assert [(item.dispute_id, item.target_proposal_ref) for item in disputes] == [("D0001", None)]
    assert disputes[0].reviewer_proposal is None


def test_material_disputes_bounds_a_model_construct_review_bypass() -> None:
    malformed_review = SourceReviewV2.model_construct(
        schema_version="2.0", proposals=[{"bad": "shape"}]
    )

    with pytest.raises(CompilationError) as error:
        material_disputes(malformed_review, empty_audit())

    assert str(error.value) == "INPUT_INVALID"


@pytest.mark.parametrize(
    "review",
    [
        SourceReviewV2.model_construct(schema_version="2.0", proposals=[{"bad": "shape"}]),
        SourceReviewV2.model_construct(
            schema_version="2.0",
            proposals=[
                SemanticProposal.model_validate(
                    proposal("A covered operator must file a notice.", "must file a notice")
                )
            ]
            * 129,
        ),
        {"schema_version": "2.0", "proposals": []},
    ],
)
def test_index_review_bounds_raw_malformed_and_oversize_inputs(review: object) -> None:
    with pytest.raises(CompilationError) as error:
        index_review(review)  # type: ignore[arg-type]

    assert str(error.value) == "INPUT_INVALID"


def test_index_review_bounds_cyclic_model_construct_input() -> None:
    cyclic: list[object] = []
    cyclic.append(cyclic)
    review = SourceReviewV2.model_construct(schema_version="2.0", proposals=cyclic)

    with pytest.raises(CompilationError) as error:
        index_review(review)

    assert str(error.value) == "INPUT_INVALID"


def test_index_review_bounds_deep_model_construct_input() -> None:
    deep: object = []
    for _ in range(65):
        deep = [deep]
    review = SourceReviewV2.model_construct(schema_version="2.0", proposals=deep)

    with pytest.raises(CompilationError) as error:
        index_review(review)

    assert str(error.value) == "INPUT_INVALID"


def test_public_helpers_accept_repeated_acyclic_valid_inputs_without_mutation() -> None:
    proposal_payload = proposal("A covered operator must file a notice.", "must file a notice")
    review = SourceReviewV2.model_validate(
        {"schema_version": "2.0", "proposals": [proposal_payload, proposal_payload]}
    )
    before = canonical_json_bytes(review)

    indexed = index_review(review)
    passage = resolve_exact_passage("notice", SemanticPassage(source_id="s", quote="notice"))

    assert [item.proposal_ref for item in indexed] == ["P0001", "P0002"]
    assert passage.start_char == 0
    assert canonical_json_bytes(review) == before


def test_compiler_applies_an_accepted_auditor_correction_to_its_target() -> None:
    review = review_with_exception()
    audit = SourceAuditV2.validate_for_indexed_proposals(
        {
            "schema_version": "2.0",
            "concerns": [
                {
                    "target_proposal_ref": "P0002",
                    "concern_type": "incorrect_statement",
                    "passages": [{"source_id": "rule-1", "quote": "must file a notice"}],
                    "explanation": "The reviewer omitted the regulated actor.",
                    "correction": proposal(
                        (
                            "The filing duty does not apply to an exempt operator "
                            "with no covered activity."
                        ),
                        "does not apply to an exempt operator",
                        kind="exception",
                        importance="material",
                        dependency={
                            "relationship": "exception_to",
                            "target_statement": "A covered operator must file a notice.",
                        },
                    ),
                }
            ],
        },
        index_review(review),
    )

    baseline = compile_baseline(
        envelope(), review, audit, referee_for(review, audit, "accept_auditor")
    )

    assert baseline.requirements[1].statement == (
        "The filing duty does not apply to an exempt operator with no covered activity."
    )


@pytest.mark.parametrize(
    ("referee", "message"),
    [
        (None, "REFEREE_REQUIRED"),
        ("unexpected", "REFEREE_UNEXPECTED"),
    ],
)
def test_compiler_enforces_one_referee_batch_only_when_audit_is_material(
    referee: str | None, message: str
) -> None:
    review = review_with_exception()
    audit = audit_with_omission(review) if referee is None else empty_audit(review)
    referee_response = (
        None
        if referee is None
        else SourceRefereeResponseV2.validate_for_disputes(
            {"schema_version": "2.0", "decisions": []}, ()
        )
    )

    with pytest.raises(CompilationError, match=message):
        compile_baseline(envelope(), review, audit, referee_response)


def test_compiler_rejects_exact_duplicate_accepted_proposals() -> None:
    payload = proposal("A covered operator must file a notice.", "must file a notice")
    review = SourceReviewV2.model_validate(
        {"schema_version": "2.0", "proposals": [payload, payload]}
    )

    with pytest.raises(CompilationError, match="DUPLICATE_ACCEPTED_PROPOSAL"):
        compile_baseline(envelope(), review, empty_audit(review), None)


def test_compiler_rejects_conflicting_accepted_corrections_for_one_target() -> None:
    review = review_with_exception()
    audit = SourceAuditV2.validate_for_indexed_proposals(
        {
            "schema_version": "2.0",
            "concerns": [
                {
                    "target_proposal_ref": "P0002",
                    "concern_type": "incorrect_statement",
                    "passages": [
                        {"source_id": "rule-1", "quote": "does not apply to an exempt operator"}
                    ],
                    "explanation": "The exception needs one correction.",
                    "correction": proposal(
                        (
                            "The filing duty does not apply to an exempt operator "
                            "with no covered activity."
                        ),
                        "does not apply to an exempt operator",
                        kind="exception",
                        dependency={
                            "relationship": "exception_to",
                            "target_statement": "A covered operator must file a notice.",
                        },
                    ),
                },
                {
                    "target_proposal_ref": "P0002",
                    "concern_type": "incorrect_statement",
                    "passages": [
                        {"source_id": "rule-1", "quote": "does not apply to an exempt operator"}
                    ],
                    "explanation": "The exception needs a different correction.",
                    "correction": proposal(
                        "The filing duty does not apply to any exempt operator.",
                        "does not apply to an exempt operator",
                        kind="exception",
                        dependency={
                            "relationship": "exception_to",
                            "target_statement": "A covered operator must file a notice.",
                        },
                    ),
                },
            ],
        },
        index_review(review),
    )

    with pytest.raises(CompilationError, match="AUDIT_CONFLICT"):
        compile_baseline(
            envelope(),
            review,
            audit,
            referee_with_decisions(review, audit, ["accept_auditor", "accept_auditor"]),
        )


def test_compiler_rejects_unresolved_or_nonexistent_dependency_target() -> None:
    review = SourceReviewV2.model_validate(
        {
            "schema_version": "2.0",
            "proposals": [
                proposal(
                    "A covered operator must file a notice.",
                    "must file a notice",
                    dependency={"relationship": "depends_on", "target_statement": "missing"},
                )
            ],
        }
    )

    with pytest.raises(CompilationError, match="DEPENDENCY_TARGET_UNRESOLVED"):
        compile_baseline(envelope(), review, empty_audit(review), None)


def test_compiler_has_order_independent_canonical_bytes_for_shuffled_proposals() -> None:
    ordered = review_with_exception()
    shuffled = SourceReviewV2.model_validate(
        {
            "schema_version": "2.0",
            "proposals": list(reversed(ordered.model_dump(mode="json")["proposals"])),
        }
    )

    ordered_baseline = compile_baseline(envelope(), ordered, empty_audit(ordered), None)
    shuffled_baseline = compile_baseline(envelope(), shuffled, empty_audit(shuffled), None)

    assert canonical_json_bytes(ordered_baseline) == canonical_json_bytes(shuffled_baseline)
    assert ordered_baseline.baseline_fingerprint == shuffled_baseline.baseline_fingerprint


def test_compiler_uses_resolved_proposal_hash_to_break_equal_primary_sort_keys() -> None:
    first = proposal("A covered operator must file a notice.", "must file a notice")
    second = {**first, "rationale": "A distinct but source-bound semantic rationale."}
    review = SourceReviewV2.model_validate({"schema_version": "2.0", "proposals": [first, second]})
    shuffled = SourceReviewV2.model_validate(
        {"schema_version": "2.0", "proposals": [second, first]}
    )

    baseline = compile_baseline(envelope(), review, empty_audit(review), None)
    shuffled_baseline = compile_baseline(envelope(), shuffled, empty_audit(shuffled), None)

    assert canonical_json_bytes(baseline) == canonical_json_bytes(shuffled_baseline)


def test_compiler_uses_normalized_statement_text_for_exact_dependency_matching() -> None:
    review = SourceReviewV2.model_validate(
        {
            "schema_version": "2.0",
            "proposals": [
                proposal(
                    "A  covered operator must file a notice.",
                    "must file a notice",
                ),
                proposal(
                    "The filing duty does not apply to an exempt operator.",
                    "does not apply to an exempt operator",
                    kind="exception",
                    dependency={
                        "relationship": "exception_to",
                        "target_statement": "A covered operator must file a notice.",
                    },
                ),
            ],
        }
    )

    baseline = compile_baseline(envelope(), review, empty_audit(review), None)

    assert baseline.relationships[0].relationship == "exception_to"
    assert baseline.relationships[0].target_requirement_id == "REQ-0001"


def test_compiler_rejects_dependency_target_matching_multiple_accepted_statements() -> None:
    review = SourceReviewV2.model_validate(
        {
            "schema_version": "2.0",
            "proposals": [
                proposal("A covered operator must file a notice.", "must file a notice"),
                proposal("A  covered operator must file a notice.", "must file a notice"),
                proposal(
                    "The filing duty does not apply to an exempt operator.",
                    "does not apply to an exempt operator",
                    kind="exception",
                    dependency={
                        "relationship": "exception_to",
                        "target_statement": "A covered operator must file a notice.",
                    },
                ),
            ],
        }
    )

    with pytest.raises(CompilationError, match="DEPENDENCY_TARGET_UNRESOLVED"):
        compile_baseline(envelope(), review, empty_audit(review), None)


def test_compiler_validates_unaccepted_auditor_evidence_against_frozen_bytes() -> None:
    review = review_with_exception()
    audit = SourceAuditV2.validate_for_indexed_proposals(
        {
            "schema_version": "2.0",
            "concerns": [
                {
                    "target_proposal_ref": "P0001",
                    "concern_type": "incorrect_evidence",
                    "passages": [{"source_id": "rule-1", "quote": "not in source"}],
                    "explanation": "The evidence needs a correction.",
                    "correction": proposal(
                        "A covered operator must file a notice under the rule.",
                        "must file a notice",
                    ),
                }
            ],
        },
        index_review(review),
    )

    with pytest.raises(CompilationError, match="PASSAGE_NOT_FOUND"):
        compile_baseline(envelope(), review, audit, referee_for(review, audit, "accept_reviewer"))


def test_compiler_fingerprint_omits_its_own_field_and_binds_relationships() -> None:
    baseline = compile_baseline(envelope(), review_with_exception(), empty_audit(), None)
    payload = baseline.model_dump(mode="json")
    payload.pop("baseline_fingerprint")

    assert (
        baseline.baseline_fingerprint == hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    )


@pytest.mark.parametrize("malformed_kind", ["review", "audit", "referee"])
def test_compiler_rejects_model_construct_bypass_with_one_safe_root_diagnostic(
    malformed_kind: str,
) -> None:
    review = review_with_exception()
    audit = audit_with_omission(review)
    referee = referee_for(review, audit, "accept_reviewer")
    if malformed_kind == "review":
        review = SourceReviewV2.model_construct(schema_version="2.0", proposals=[{"bad": "shape"}])
    elif malformed_kind == "audit":
        audit = SourceAuditV2.model_construct(schema_version="2.0", concerns=[{"bad": "shape"}])
    else:
        referee = SourceRefereeResponseV2.model_construct(
            schema_version="2.0", decisions=[{"bad": "shape"}]
        )

    with pytest.raises(CompilationError) as error:
        compile_baseline(envelope(), review, audit, referee)

    assert str(error.value) == "INPUT_INVALID"


def test_compiler_does_not_mutate_validated_inputs() -> None:
    review = review_with_exception()
    audit = empty_audit(review)
    review_before = canonical_json_bytes(review)
    audit_before = canonical_json_bytes(audit)

    compile_baseline(envelope(), review, audit, None)

    assert canonical_json_bytes(review) == review_before
    assert canonical_json_bytes(audit) == audit_before
