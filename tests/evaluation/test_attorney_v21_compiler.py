"""Deterministic fragmented-adjudication compiler tests."""

from __future__ import annotations

import hashlib
from datetime import date

import pytest

from regulatory_harvest.evaluation.attorney_admission import freeze_case
from regulatory_harvest.evaluation.attorney_models import (
    AttorneyEvaluationCase,
    CandidateReport,
    CandidateRole,
    CaseEnvelope,
    EvaluationMode,
    EvaluationSource,
    RequestedAuthority,
)
from regulatory_harvest.evaluation.attorney_v21_compiler import (
    CompilationError,
    aggregate_referee_decisions,
    build_referee_disputes,
    compile_baseline_v21,
    validate_referee_fragment,
)
from regulatory_harvest.evaluation.attorney_v21_models import (
    AcceptedRefereeFragmentV21,
    SourceAuditV21,
    SourceReviewV21,
)
from regulatory_harvest.models import SourceQuality, SourceRole


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def envelope() -> CaseEnvelope:
    source_text = "Rule 1: operators must file. Rule 2: filing excludes small operators."
    report_a = "Operators must file."
    report_b = "Small operators are excluded."
    case = AttorneyEvaluationCase(
        case_id="v21-synthetic-case",
        mode=EvaluationMode.CLOSED_UNIVERSE,
        question="What must operators file?",
        jurisdiction="Example State",
        as_of=date(2026, 8, 18),
        requested_authorities=[
            RequestedAuthority(
                authority_id="example-rule",
                title="Example Rule",
                jurisdiction="Example State",
                authority_type="regulation",
                source_ids=["rule-1"],
            )
        ],
        sources=[
            EvaluationSource(
                source_id="rule-1",
                title="Example Rule",
                normalized_text=source_text,
                content_hash=_sha256(source_text),
                jurisdiction="Example State",
                authority_type="regulation",
                source_role=SourceRole.OFFICIAL_PRIMARY,
                source_quality=SourceQuality.PRIMARY,
                completeness="complete",
                language="en",
            )
        ],
        candidates=[
            CandidateReport(
                candidate_id="candidate", role=CandidateRole.CANDIDATE,
                report_text=report_a, report_hash=_sha256(report_a),
            ),
            CandidateReport(
                candidate_id="comparator", role=CandidateRole.COMPARATOR,
                report_text=report_b, report_hash=_sha256(report_b),
            ),
        ],
    )
    return freeze_case(case, seed_hex="0" * 64)


def _proposal(statement: str, quote: str) -> dict[str, object]:
    return {
        "statement": statement,
        "kind": "obligation",
        "importance": "critical",
        "passages": [{"source_id": "rule-1", "quote": quote}],
        "dependency": None,
        "confidence": "clear",
        "rationale": "The operative wording supports this proposal.",
    }


def review() -> SourceReviewV21:
    return SourceReviewV21.model_validate(
        {
            "schema_version": "2.1",
            "proposals": [_proposal("Operators must file.", "operators must file")],
        }
    )


def audit() -> SourceAuditV21:
    return SourceAuditV21.model_validate(
        {
            "schema_version": "2.1",
            "concerns": [
                {
                    "target_proposal_ref": "P0001",
                    "concern_type": "incorrect_statement",
                    "passages": [{"source_id": "rule-1", "quote": "operators must file"}],
                    "explanation": "The duty omits its exception.",
                    "correction": _proposal(
                        "Operators must file unless they are small operators.",
                        "filing excludes small operators",
                    ),
                }
            ],
        },
        context={"proposal_refs": {"P0001"}},
    )


def audit_with_two_concerns() -> SourceAuditV21:
    return SourceAuditV21.model_validate(
        {
            "schema_version": "2.1",
            "concerns": [
                *audit().model_dump(mode="json")["concerns"],
                {
                    "target_proposal_ref": None,
                    "concern_type": "omission",
                    "passages": [
                        {"source_id": "rule-1", "quote": "small operators"}
                    ],
                    "explanation": "The definition of small operators is omitted.",
                    "correction": _proposal(
                        "Small operators are excluded from filing.", "small operators"
                    ),
                },
            ],
        },
        context={"proposal_refs": {"P0001"}},
    )


def audit_with_ambiguity() -> SourceAuditV21:
    return SourceAuditV21.model_validate(
        {
            "schema_version": "2.1",
            "concerns": [
                {
                    "target_proposal_ref": "P0001",
                    "concern_type": "ambiguity",
                    "passages": [{"source_id": "rule-1", "quote": "operators must file"}],
                    "explanation": "The filing duty does not apply to every operator.",
                    "correction": None,
                }
            ],
        },
        context={"proposal_refs": {"P0001"}},
    )


def dependency_envelope() -> CaseEnvelope:
    original = envelope()
    source_text = original.case.sources[0].normalized_text + " Rule 3: filing is mandatory."
    source = original.case.sources[0].model_copy(
        update={"normalized_text": source_text, "content_hash": _sha256(source_text)}
    )
    case = original.case.model_copy(update={"sources": [source]})
    return freeze_case(case, seed_hex="3" * 64)


def dependency_review(target_statement: str = "Operators must file.") -> SourceReviewV21:
    return SourceReviewV21.model_validate(
        {
            "schema_version": "2.1",
            "proposals": [
                _proposal("Operators must file.", "operators must file"),
                {
                    **_proposal("Filing is mandatory.", "filing is mandatory"),
                    "dependency": {
                        "relationship": "depends_on",
                        "target_statement": target_statement,
                    },
                },
            ],
        }
    )


def dependency_audit(
    correction_statement: str = "Operators must file if not small.",
) -> SourceAuditV21:
    return SourceAuditV21.model_validate(
        {
            "schema_version": "2.1",
            "concerns": [
                {
                    "target_proposal_ref": "P0001",
                    "concern_type": "incorrect_statement",
                    "passages": [{"source_id": "rule-1", "quote": "operators must file"}],
                    "explanation": "The filing duty has a disputed exception.",
                    "correction": _proposal(correction_statement, "operators must file"),
                }
            ],
        },
        context={"proposal_refs": {"P0001", "P0002"}},
    )


def _fragment(dispute: object, decision: str = "unresolved") -> AcceptedRefereeFragmentV21:
    fragment = validate_referee_fragment(
        dispute,
        {
            "schema_version": "2.1",
            "decision": decision,
            "unresolved_reason": "SOURCE_AMBIGUITY" if decision == "unresolved" else None,
            "evidence_refs": [dispute.evidence[0].evidence_ref],  # type: ignore[union-attr]
            "rationale": "The source does not resolve the alternatives.",
        },
        response_fingerprint="a" * 64,
    )
    return fragment


def test_disputes_resolve_exact_passages_and_assign_stable_evidence_refs() -> None:
    disputes = build_referee_disputes(envelope(), review(), audit())

    assert [item.dispute_id for item in disputes] == ["D0001"]
    assert [item.evidence_ref for item in disputes[0].evidence] == ["EVID-0001", "EVID-0002"]
    assert [(item.passage.start_char, item.passage.end_char) for item in disputes[0].evidence] == [
        (8, 27),
        (37, 68),
    ]


def test_dispute_order_and_evidence_refs_remain_stable_across_multiple_concerns() -> None:
    first = build_referee_disputes(envelope(), review(), audit_with_two_concerns())
    second = build_referee_disputes(envelope(), review(), audit_with_two_concerns())

    assert first == second
    assert [item.dispute_id for item in first] == ["D0001", "D0002"]
    assert [item.evidence_ref for item in first[0].evidence] == ["EVID-0001", "EVID-0002"]
    assert [item.evidence_ref for item in first[1].evidence] == ["EVID-0003"]


def test_unresolved_compiles_contested_requirement_without_choosing_an_alternative() -> None:
    disputes = build_referee_disputes(envelope(), review(), audit())
    aggregate = aggregate_referee_decisions(disputes, (_fragment(disputes[0]),))

    baseline = compile_baseline_v21(envelope(), review(), audit(), aggregate)

    assert baseline.requirements == ()
    assert len(baseline.contested_requirements) == 1
    contested = baseline.contested_requirements[0]
    assert contested.reviewer_alternative is not None
    assert contested.auditor_alternative is not None


def test_mixed_reviewer_and_auditor_decisions_compile_their_selected_common_proposals() -> None:
    concerns = audit_with_two_concerns()
    disputes = build_referee_disputes(envelope(), review(), concerns)
    aggregate = aggregate_referee_decisions(
        disputes,
        (
            _fragment(disputes[0], "accept_reviewer"),
            _fragment(disputes[1], "accept_auditor"),
        ),
    )

    baseline = compile_baseline_v21(envelope(), review(), concerns, aggregate)

    assert [item.statement for item in baseline.requirements] == [
        "Operators must file.",
        "Small operators are excluded from filing.",
    ]
    assert baseline.contested_requirements == ()


def test_accept_auditor_without_a_correction_omits_the_target_proposal() -> None:
    concerns = audit_with_ambiguity()
    disputes = build_referee_disputes(envelope(), review(), concerns)
    aggregate = aggregate_referee_decisions(
        disputes, (_fragment(disputes[0], "accept_auditor"),)
    )

    baseline = compile_baseline_v21(envelope(), review(), concerns, aggregate)

    assert baseline.requirements == ()
    assert baseline.contested_requirements == ()


def test_empty_auditor_alternative_is_mechanically_invalid() -> None:
    invalid = SourceAuditV21.model_construct(
        schema_version="2.1",
        concerns=[
            {
                "target_proposal_ref": None,
                "concern_type": "ambiguity",
                "passages": [{"source_id": "rule-1", "quote": "operators must file"}],
                "explanation": "No auditor alternative was supplied.",
                "correction": None,
            }
        ],
    )

    with pytest.raises(CompilationError, match="INPUT_INVALID"):
        build_referee_disputes(envelope(), review(), invalid)


def test_unresolved_dependency_to_one_contested_alternative_preserves_context_without_edge(
) -> None:
    frozen = dependency_envelope()
    source_review = dependency_review()
    concerns = dependency_audit()
    disputes = build_referee_disputes(frozen, source_review, concerns)
    aggregate = aggregate_referee_decisions(disputes, (_fragment(disputes[0]),))

    baseline = compile_baseline_v21(frozen, source_review, concerns, aggregate)

    assert [item.statement for item in baseline.requirements] == ["Filing is mandatory."]
    assert baseline.requirements[0].dependency is not None
    assert baseline.requirements[0].dependency.target_statement == "Operators must file."
    assert baseline.relationships == ()


@pytest.mark.parametrize(
    ("target_statement", "correction_statement"),
    [
        ("No matching requirement.", "Operators must file if not small."),
        ("Operators must file.", "Operators must file."),
    ],
)
def test_unresolved_dependency_fails_when_its_target_is_missing_or_ambiguous(
    target_statement: str, correction_statement: str
) -> None:
    frozen = dependency_envelope()
    source_review = dependency_review(target_statement)
    concerns = dependency_audit(correction_statement)
    disputes = build_referee_disputes(frozen, source_review, concerns)
    aggregate = aggregate_referee_decisions(disputes, (_fragment(disputes[0]),))

    with pytest.raises(CompilationError, match="DEPENDENCY_TARGET_UNRESOLVED"):
        compile_baseline_v21(frozen, source_review, concerns, aggregate)


def test_aggregate_rejects_swapped_or_cross_dispute_fragment() -> None:
    disputes = build_referee_disputes(envelope(), review(), audit())
    fragment = _fragment(disputes[0])

    with pytest.raises(CompilationError, match="REFEREE_FRAGMENT_COVERAGE_INVALID"):
        aggregate_referee_decisions((), (fragment,))


def test_compiler_rejects_aggregate_from_a_different_frozen_case() -> None:
    original = envelope()
    disputes = build_referee_disputes(original, review(), audit())
    aggregate = aggregate_referee_decisions(disputes, (_fragment(disputes[0]),))
    other_case = original.case.model_copy(update={"case_id": "other-v21-synthetic-case"})
    other_envelope = freeze_case(other_case, seed_hex="1" * 64)

    with pytest.raises(CompilationError, match="REFEREE_FRAGMENT_INVALID"):
        compile_baseline_v21(other_envelope, review(), audit(), aggregate)
