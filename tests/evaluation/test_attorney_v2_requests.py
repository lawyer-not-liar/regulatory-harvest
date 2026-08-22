"""Wire-boundary tests for simplified evaluator protocol 2.0 requests."""

from __future__ import annotations

import copy
import hashlib
from datetime import date

import pytest
from pydantic import ValidationError

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
from regulatory_harvest.evaluation.attorney_v2_models import (
    AuditConcernV2,
    CanonicalBaselineV2,
    CanonicalRequirementV2,
    EvaluatorOperationV2,
    EvaluatorRequestV2,
    ImportanceV2,
    IndexedProposalV2,
    MaterialDisputeV2,
    RequirementKindV2,
    ResolvedPassageV2,
    RubricV2,
    SemanticPassage,
    SemanticProposal,
    evaluator_request_fingerprint,
)
from regulatory_harvest.evaluation.attorney_v2_requests import (
    build_grade_request,
    build_source_audit_request,
    build_source_referee_request,
    build_source_review_request,
    mechanical_retry_request,
)
from regulatory_harvest.models import SourceQuality, SourceRole
from regulatory_harvest.storage import canonical_json_bytes, sha256_digest


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def envelope() -> CaseEnvelope:
    source_text = "Section 1. A controller shall document its processing activities."
    report_a = "The controller must document its processing activities."
    report_b = "Documentation is required for processing activities."
    case = AttorneyEvaluationCase(
        case_id="synthetic-case",
        mode=EvaluationMode.CLOSED_UNIVERSE,
        question="What documentation is required?",
        jurisdiction="Example State",
        as_of=date(2026, 8, 17),
        requested_authorities=[
            RequestedAuthority(
                authority_id="example-statute",
                title="Example Privacy Act",
                jurisdiction="Example State",
                authority_type="statute",
                source_ids=["example-statute-1"],
            )
        ],
        sources=[
            EvaluationSource(
                source_id="example-statute-1",
                title="Example Privacy Act",
                normalized_text=source_text,
                content_hash=_sha256(source_text),
                jurisdiction="Example State",
                authority_type="statute",
                source_role=SourceRole.OFFICIAL_PRIMARY,
                source_quality=SourceQuality.PRIMARY,
                completeness="complete",
                language="en",
            )
        ],
        candidates=[
            CandidateReport(
                candidate_id="candidate-report",
                role=CandidateRole.CANDIDATE,
                report_text=report_a,
                report_hash=_sha256(report_a),
            ),
            CandidateReport(
                candidate_id="comparison-report",
                role=CandidateRole.COMPARATOR,
                report_text=report_b,
                report_hash=_sha256(report_b),
            ),
        ],
    )
    return freeze_case(case, seed_hex="0" * 64)


def proposal() -> SemanticProposal:
    return SemanticProposal(
        statement="A controller must document processing activities.",
        kind=RequirementKindV2.OBLIGATION,
        importance=ImportanceV2.CRITICAL,
        passages=[
            SemanticPassage(
                source_id="example-statute-1",
                quote="A controller shall document its processing activities.",
            )
        ],
        confidence="clear",
        rationale="The operative text states a mandatory documentation duty.",
    )


def indexed() -> tuple[IndexedProposalV2, ...]:
    return (IndexedProposalV2(proposal_ref="P0001", proposal=proposal()),)


def disputes() -> tuple[MaterialDisputeV2, ...]:
    concern = AuditConcernV2(
        target_proposal_ref="P0001",
        concern_type="ambiguity",
        passages=[
            SemanticPassage(
                source_id="example-statute-1",
                quote="A controller shall document its processing activities.",
            )
        ],
        explanation="The source leaves the scope of processing activities ambiguous.",
    )
    return (
        MaterialDisputeV2(
            dispute_id="D0001",
            target_proposal_ref="P0001",
            reviewer_proposal=proposal(),
            audit_concern=concern,
        ),
    )


def baseline(case_fingerprint: str = "a" * 64) -> CanonicalBaselineV2:
    requirement = CanonicalRequirementV2(
        requirement_id="REQ-0001",
        canonical_order=0,
        statement="A controller must document processing activities.",
        kind=RequirementKindV2.OBLIGATION,
        importance=ImportanceV2.CRITICAL,
        passages=[
            ResolvedPassageV2(
                source_id="example-statute-1",
                quote="A controller shall document its processing activities.",
                start_char=11,
                end_char=65,
            )
        ],
        confidence="clear",
        rationale="The operative text states a mandatory documentation duty.",
    )
    return CanonicalBaselineV2(
        case_fingerprint=case_fingerprint,
        requirements=[requirement],
        baseline_fingerprint="b" * 64,
    )


RUBRIC_V2 = RubricV2(
    version="attorney-eval-v2",
    importance_weights={
        ImportanceV2.CRITICAL: 3,
        ImportanceV2.MATERIAL: 2,
        ImportanceV2.SUPPORTING: 1,
    },
    critical_recall_floor=1.0,
    weighted_coverage_floor=0.9,
    material_unsupported_assertions_allowed=0,
)


def test_source_review_request_contains_sources_but_no_candidate() -> None:
    request = build_source_review_request(envelope())
    encoded = canonical_json_bytes(request.model_dump(mode="json"))

    assert request.operation is EvaluatorOperationV2.SOURCE_REVIEW
    assert set(request.model_dump(mode="json")) == {
        "schema_version",
        "operation",
        "request_fingerprint",
        "system_instructions",
        "json_schema",
        "payload",
        "safe_metadata",
    }
    assert set(request.payload) == {"source_record"}
    assert b"candidate" not in encoded
    assert b"walk_order" not in encoded
    assert b"repair_transaction" not in encoded


def test_source_review_request_tells_role_to_return_only_inner_payload() -> None:
    request = build_source_review_request(envelope())

    instructions = request.system_instructions.lower()
    assert "return only the inner payload" in instructions
    assert "do not author the outer response envelope" in instructions
    assert "json_schema" in instructions


def test_source_audit_request_uses_indexed_proposals_and_only_material_concerns() -> None:
    request = build_source_audit_request(envelope(), indexed())

    assert request.operation is EvaluatorOperationV2.SOURCE_AUDIT
    assert set(request.payload) == {"source_record", "indexed_proposals"}
    assert request.payload["indexed_proposals"] == [
        item.model_dump(mode="json") for item in indexed()
    ]
    assert "only material concerns" in request.system_instructions.lower()
    assert request.json_schema["title"] == "SourceAuditV2"


def test_source_referee_request_carries_every_dispute_in_one_source_only_packet() -> None:
    request = build_source_referee_request(envelope(), disputes())
    encoded = canonical_json_bytes(request.model_dump(mode="json"))

    assert request.operation is EvaluatorOperationV2.SOURCE_REFEREE
    assert set(request.payload) == {"source_record", "material_disputes"}
    assert request.payload["material_disputes"] == [
        item.model_dump(mode="json") for item in disputes()
    ]
    assert b"candidate" not in encoded
    assert request.json_schema["title"] == "SourceRefereeResponseV2"


def test_grade_request_supplies_ids_without_asking_grader_to_create_them() -> None:
    frozen = envelope()
    sealed = baseline(case_fingerprint=frozen.case_fingerprint)
    request = build_grade_request(frozen, sealed, "A", RUBRIC_V2)
    encoded = canonical_json_bytes(request.model_dump(mode="json"))

    assert request.operation is EvaluatorOperationV2.GRADE_REPORT
    requirements = request.payload["requirements"]
    anonymous_report = request.payload["anonymous_report"]
    assert isinstance(requirements, list)
    assert isinstance(requirements[0], dict)
    assert isinstance(anonymous_report, dict)
    assert requirements[0]["requirement_id"] == "REQ-0001"
    assert anonymous_report["anonymous_label"] == "A"
    assert b"comparison-report" not in encoded
    assert b"candidate-report" not in encoded
    assert "assign" not in request.system_instructions.lower()
    assert request.json_schema["title"] == "GradeResponseV2"
    assert set(sealed.model_dump(mode="json")).issubset(request.payload)
    schema_properties = request.json_schema["properties"]
    assert isinstance(schema_properties, dict)
    assert "request_fingerprint" not in schema_properties


def test_built_requests_admit_no_extra_wire_or_rejected_response_fields() -> None:
    request = build_source_review_request(envelope())

    with pytest.raises(ValidationError):
        EvaluatorRequestV2.model_validate(
            {**request.model_dump(mode="json"), "rejected_response": {"detail": "private"}}
        )


@pytest.mark.parametrize("payload", [{"nested": []}, {"text": "x" * (16 * 1024 * 1024)}])
def test_retry_revalidates_cyclic_and_oversized_request_trees(payload: dict[str, object]) -> None:
    if "nested" in payload:
        payload["nested"] = payload
    bypass = EvaluatorRequestV2.model_construct(
        schema_version="2.0",
        operation=EvaluatorOperationV2.SOURCE_REVIEW,
        request_fingerprint="0" * 64,
        system_instructions="Review frozen sources only.",
        json_schema={"type": "object"},
        payload=payload,
        safe_metadata={},
    )

    with pytest.raises((TypeError, ValidationError, ValueError)):
        mechanical_retry_request(bypass, expected_request_fingerprint="0" * 64)


def test_request_fingerprint_is_stable_and_binds_the_complete_packet() -> None:
    first = build_source_audit_request(envelope(), indexed())
    second = build_source_audit_request(envelope(), indexed())

    assert first == second
    assert first.request_fingerprint == sha256_digest(
        canonical_json_bytes(
            first.model_dump(mode="json", exclude={"request_fingerprint"})
        )
    )


def test_source_request_rejects_a_validation_bypassed_envelope() -> None:
    frozen = envelope()
    bypass = CaseEnvelope.model_construct(
        schema_version=frozen.schema_version,
        case=frozen.case,
        assignments=frozen.assignments,
        case_fingerprint="0" * 64,
        seed_fingerprint=frozen.seed_fingerprint,
    )

    with pytest.raises(ValidationError, match="case_fingerprint must match case"):
        build_source_review_request(bypass)


def test_grade_request_rejects_a_validation_bypassed_baseline() -> None:
    sealed = baseline()
    bypass = CanonicalBaselineV2.model_construct(
        schema_version=sealed.schema_version,
        case_fingerprint=sealed.case_fingerprint,
        requirements=sealed.requirements,
        unresolved_dispute_ids=["not-an-engine-id"],
        baseline_fingerprint=sealed.baseline_fingerprint,
    )

    with pytest.raises(ValidationError, match="engine-issued references"):
        build_grade_request(envelope(), bypass, "A", RUBRIC_V2)


def test_grade_request_rejects_a_baseline_from_a_different_frozen_case() -> None:
    first = envelope()
    second_case = first.case.model_copy(update={"question": "What notice is required?"})
    second = freeze_case(second_case, seed_hex="1" * 64)

    with pytest.raises(ValueError, match="baseline must bind the frozen case"):
        build_grade_request(
            second,
            baseline(case_fingerprint=first.case_fingerprint),
            "A",
            RUBRIC_V2,
        )


def test_builders_snapshot_inputs_without_mutating_or_retaining_caller_data() -> None:
    supplied_indexed = indexed()
    before = copy.deepcopy([item.model_dump(mode="json") for item in supplied_indexed])
    request = build_source_audit_request(envelope(), supplied_indexed)

    assert [item.model_dump(mode="json") for item in supplied_indexed] == before
    with pytest.raises(TypeError):
        request.payload["indexed_proposals"][0]["proposal_ref"] = "P9999"  # type: ignore[index]


def test_retry_is_an_identical_fresh_snapshot_without_rejected_response_data() -> None:
    frozen = envelope()
    original = build_grade_request(
        frozen,
        baseline(case_fingerprint=frozen.case_fingerprint),
        "A",
        RUBRIC_V2,
    )
    retry = mechanical_retry_request(
        original,
        expected_request_fingerprint=original.request_fingerprint,
    )
    encoded = canonical_json_bytes(retry.model_dump(mode="json"))

    assert retry == original
    assert retry is not original
    assert b"diagnostic" not in encoded
    assert b"rejected_response" not in encoded
    assert b"validator" not in encoded


def test_retry_rejects_a_model_construct_request_with_a_forged_fingerprint() -> None:
    original = build_source_review_request(envelope())
    bypass = EvaluatorRequestV2.model_construct(
        schema_version=original.schema_version,
        operation=original.operation,
        request_fingerprint="a" * 64,
        system_instructions=original.system_instructions,
        json_schema=original.json_schema,
        payload=original.payload,
        safe_metadata=original.safe_metadata,
    )

    with pytest.raises(ValueError, match="mechanical retry request"):
        mechanical_retry_request(
            bypass,
            expected_request_fingerprint=original.request_fingerprint,
        )


def test_retry_accepts_a_canonical_raw_packet_without_mutating_it() -> None:
    original = build_source_review_request(envelope())
    raw = copy.deepcopy(original.model_dump(mode="json"))
    before = copy.deepcopy(raw)

    retry = mechanical_retry_request(
        raw,
        expected_request_fingerprint=original.request_fingerprint,
    )

    assert raw == before
    assert retry == original
    assert retry is not original


@pytest.mark.parametrize(
    "tamper",
    [
        lambda packet: packet["safe_metadata"].update({"private_data": "private"}),
        lambda packet: packet["safe_metadata"].update({"rejected_response": "private"}),
        lambda packet: packet["payload"].update({"diagnostic": "private"}),
    ],
)
def test_retry_rejects_rebound_private_feedback_in_raw_packets(
    tamper: object,
) -> None:
    original = build_source_review_request(envelope())
    raw = copy.deepcopy(original.model_dump(mode="json"))
    assert callable(tamper)
    tamper(raw)
    provisional = EvaluatorRequestV2.model_validate(
        {**raw, "request_fingerprint": "0" * 64}
    )
    raw["request_fingerprint"] = evaluator_request_fingerprint(provisional)

    with pytest.raises(ValueError, match="mechanical retry request"):
        mechanical_retry_request(
            raw,
            expected_request_fingerprint=original.request_fingerprint,
        )


@pytest.mark.parametrize("expected", ["not-a-fingerprint", "a" * 64])
def test_retry_rejects_malformed_or_wrong_expected_fingerprint(expected: str) -> None:
    original = build_source_review_request(envelope())

    with pytest.raises(ValueError, match="mechanical retry request"):
        mechanical_retry_request(original, expected_request_fingerprint=expected)


def test_retry_rejects_a_rehashed_source_packet_when_the_controller_fingerprint_differs() -> None:
    original = build_source_review_request(envelope())
    raw = copy.deepcopy(original.model_dump(mode="json"))
    source_record = raw["payload"]["source_record"]
    assert isinstance(source_record, dict)
    source_record["question"] = "Different frozen source question."
    raw["safe_metadata"]["source_record_fingerprint"] = sha256_digest(
        canonical_json_bytes(source_record)
    )
    provisional = EvaluatorRequestV2.model_validate(
        {**raw, "request_fingerprint": "0" * 64}
    )
    raw["request_fingerprint"] = evaluator_request_fingerprint(provisional)

    with pytest.raises(ValueError, match="mechanical retry request"):
        mechanical_retry_request(
            raw,
            expected_request_fingerprint=original.request_fingerprint,
        )


def test_retry_rejects_a_rehashed_grade_report_when_the_controller_fingerprint_differs() -> None:
    frozen = envelope()
    original = build_grade_request(
        frozen,
        baseline(case_fingerprint=frozen.case_fingerprint),
        "A",
        RUBRIC_V2,
    )
    raw = copy.deepcopy(original.model_dump(mode="json"))
    report = raw["payload"]["anonymous_report"]
    assert isinstance(report, dict)
    report["report_text"] = "Different report content."
    report["report_hash"] = _sha256(report["report_text"])
    provisional = EvaluatorRequestV2.model_validate(
        {**raw, "request_fingerprint": "0" * 64}
    )
    raw["request_fingerprint"] = evaluator_request_fingerprint(provisional)

    with pytest.raises(ValueError, match="mechanical retry request"):
        mechanical_retry_request(
            raw,
            expected_request_fingerprint=original.request_fingerprint,
        )


def test_retry_rejects_a_stale_grade_report_hash_with_a_matching_expected_fingerprint() -> None:
    frozen = envelope()
    raw = copy.deepcopy(
        build_grade_request(
            frozen,
            baseline(case_fingerprint=frozen.case_fingerprint),
            "A",
            RUBRIC_V2,
        ).model_dump(mode="json")
    )
    report = raw["payload"]["anonymous_report"]
    assert isinstance(report, dict)
    report["report_text"] = "Different report content."
    provisional = EvaluatorRequestV2.model_validate(
        {**raw, "request_fingerprint": "0" * 64}
    )
    raw["request_fingerprint"] = evaluator_request_fingerprint(provisional)

    with pytest.raises(ValueError, match="mechanical retry request"):
        mechanical_retry_request(
            raw,
            expected_request_fingerprint=raw["request_fingerprint"],
        )
