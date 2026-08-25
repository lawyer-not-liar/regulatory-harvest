"""Controller-issued, report-blind evaluation-baseline-v1 request tests."""

from __future__ import annotations

import hashlib

import pytest

from regulatory_harvest.evaluation.attorney_baseline_models import (
    AcceptedBaselineAuditFragmentV1,
    AcceptedBaselineReviewFragmentV1,
    BaselineAuditConcernV1,
    BaselineAuditFragmentV1,
    BaselineDisputeV1,
    BaselineEvaluatorRequestV1,
    BaselineReviewAggregateV1,
    BaselineReviewFragmentV1,
    ImportanceAuditFindingV1,
)
from regulatory_harvest.evaluation.attorney_baseline_requests import (
    BASELINE_COMPILER_CONTRACT_FINGERPRINT_V1,
    BASELINE_COMPILER_CONTRACT_V1,
    build_baseline_source_audit_request_v1,
    build_baseline_source_referee_request_v1,
    build_baseline_source_review_request_v1,
    compiler_contract_fingerprint_v1,
)
from regulatory_harvest.evaluation.attorney_v22_compiler import RUBRIC_V22
from regulatory_harvest.storage import canonical_json_bytes, sha256_digest

EXPECTED_COMPILER_CONTRACT_FINGERPRINT = (
    "c52f1593e710ce191f50ef0751010ffe683e9362fc7044e6970f74c1ec5d80a5"
)
EXPECTED_REQUEST_FINGERPRINTS = (
    "11f41ef4022d06842d5c475cacf7cc748c842c767ef4987fcfe1ce7b793f8511",
    "564eddf5a9ada79b3af1ca0233f8437f6d53397a917e1fe2c9be9d1a817b0627",
    "a875394862a72d93920392ee1690cce96f0c7a78c45b6b0ca781793dffb2bcf6",
)


def _hash(value: object) -> str:
    return sha256_digest(canonical_json_bytes(value))


def _dispute_fingerprint(
    *,
    dispute_id: str,
    target_proposal_ref: str | None,
    reviewer_proposal: object | None,
    auditor_concern: object | None,
    importance_finding: object | None,
) -> str:
    def wire(value: object | None) -> object | None:
        return None if value is None else value.model_dump(mode="json")

    return _hash(
        {
            "dispute_id": dispute_id,
            "target_proposal_ref": target_proposal_ref,
            "reviewer_proposal": wire(reviewer_proposal),
            "auditor_concern": wire(auditor_concern),
            "importance_finding": wire(importance_finding),
        }
    )


def _dispute(
    *,
    dispute_id: str = "DSP-0001",
    target_proposal_ref: str | None = None,
    reviewer_proposal: object | None = None,
    auditor_concern: object | None = None,
    importance_finding: object | None = None,
) -> BaselineDisputeV1:
    return BaselineDisputeV1(
        dispute_id=dispute_id,
        dispute_fingerprint=_dispute_fingerprint(
            dispute_id=dispute_id,
            target_proposal_ref=target_proposal_ref,
            reviewer_proposal=reviewer_proposal,
            auditor_concern=auditor_concern,
            importance_finding=importance_finding,
        ),
        target_proposal_ref=target_proposal_ref,
        reviewer_proposal=reviewer_proposal,
        auditor_concern=auditor_concern,
        importance_finding=importance_finding,
    )


def _semantic_concern(review: BaselineReviewAggregateV1) -> BaselineAuditConcernV1:
    return BaselineAuditConcernV1(
        target_proposal_ref="PR-0001",
        concern_type="incorrect_statement",
        passages=({"source_id": "rule-1", "quote": "must file a notice"},),
        explanation="The proposal needs a narrower statement.",
        correction=review.proposals[0].proposal,
    )


def _importance_finding() -> ImportanceAuditFindingV1:
    return ImportanceAuditFindingV1(
        proposal_ref="PR-0001",
        reviewed_importance="critical",
        reviewed_importance_basis=("legal_bottom_line",),
        importance_rationale="Omission could change the legal bottom line.",
        disposition="agree",
    )


@pytest.fixture
def baseline_input():
    from regulatory_harvest.evaluation.attorney_baseline_models import BaselineInputV1

    source_text = "A covered operator must file a notice."
    client_facts = "The operator is covered."
    value: dict[str, object] = {
        "schema_version": "baseline-input-v1",
        "sources": (
            {
                "source_id": "rule-1",
                "title": "Rule 1",
                "normalized_text": source_text,
                "content_hash": hashlib.sha256(source_text.encode("utf-8")).hexdigest(),
                "jurisdiction": "Example",
                "authority_type": "regulation",
                "source_role": "official_primary",
                "source_quality": "primary",
                "completeness": "complete",
                "language": "en",
            },
        ),
        "source_record_fingerprint": "a" * 64,
        "question": "What must a covered operator do?",
        "jurisdiction": "Example",
        "as_of": "2026-08-24",
        "requested_authorities": (
            {
                "authority_id": "rule-1",
                "title": "Rule 1",
                "jurisdiction": "Example",
                "authority_type": "regulation",
                "source_ids": ["rule-1"],
            },
        ),
        "client_facts": client_facts,
        "client_facts_binding": "sha256:"
        + hashlib.sha256(client_facts.encode("utf-8")).hexdigest(),
        "qualification_root": "b" * 64,
        "qualification_receipt_fingerprint": "c" * 64,
        "qualification_readiness": "ADMITTED",
        "evaluation_rubric_version": "attorney-eval-v2.2",
        "importance_policy_version": "importance-policy-v1",
        "legal_input_fingerprint": "d" * 64,
    }
    policy_bytes = (
        b'{"definitions":{"critical":"omission or material misstatement could change the legal '
        b"bottom line, applicability, operative status, core duty or prohibition, enforcement "
        b'exposure, remedy, or a dispositive deadline.","material":"necessary for a competent '
        b"attorney briefing or implementation decision but not independently outcome-determinative "
        b'under the current scoped question.","supporting":"useful explanatory, contextual, or '
        b"implementation detail whose absence does not materially change the legal answer"
        b' or required next action."},"importance_policy_version":"importance-policy-v1"}'
    )
    rubric_bytes = canonical_json_bytes(RUBRIC_V22.model_dump(mode="json"))
    return BaselineInputV1.model_validate(
        {
            **value,
            "compiler_contract": BASELINE_COMPILER_CONTRACT_V1,
            "compiler_contract_fingerprint": BASELINE_COMPILER_CONTRACT_FINGERPRINT_V1,
            "evaluation_rubric_bytes": rubric_bytes,
            "evaluation_rubric_fingerprint": hashlib.sha256(rubric_bytes).hexdigest(),
            "importance_policy_bytes": policy_bytes,
            "importance_policy_fingerprint": hashlib.sha256(policy_bytes).hexdigest(),
        }
    )


@pytest.fixture
def review() -> BaselineReviewAggregateV1:
    proposal = {
        "statement": "A covered operator must file a notice.",
        "kind": "obligation",
        "importance": "critical",
        "importance_basis": ["legal_bottom_line"],
        "importance_rationale": "Omission could change the legal bottom line.",
        "passages": [{"source_id": "rule-1", "quote": "must file a notice"}],
        "confidence": "clear",
        "substantive_rationale": "The source uses mandatory language.",
    }
    fragment = BaselineReviewFragmentV1(proposals=(proposal,), review_complete=True)
    accepted = AcceptedBaselineReviewFragmentV1(
        fragment_ordinal=1,
        request_fingerprint="1" * 64,
        response_fingerprint="2" * 64,
        payload=fragment,
    )
    return BaselineReviewAggregateV1(
        fragments=(accepted,),
        proposals=({"proposal_ref": "PR-0001", "proposal": proposal},),
        fragment_fingerprints=("3" * 64,),
        aggregate_fingerprint="4" * 64,
    )


@pytest.fixture
def requests(baseline_input, review) -> tuple[BaselineEvaluatorRequestV1, ...]:
    review_request = build_baseline_source_review_request_v1(baseline_input, (), fragment_ordinal=1)
    audit_request = build_baseline_source_audit_request_v1(
        baseline_input, review, (), fragment_ordinal=1
    )
    dispute = _dispute(
        target_proposal_ref="PR-0001",
        reviewer_proposal=review.proposals[0].proposal,
        auditor_concern=_semantic_concern(review),
    )
    referee_request = build_baseline_source_referee_request_v1(baseline_input, dispute)
    return review_request, audit_request, referee_request


def test_compiler_contract_has_a_stable_canonical_fingerprint() -> None:
    assert BASELINE_COMPILER_CONTRACT_FINGERPRINT_V1 == EXPECTED_COMPILER_CONTRACT_FINGERPRINT
    assert (
        compiler_contract_fingerprint_v1(BASELINE_COMPILER_CONTRACT_V1)
        == EXPECTED_COMPILER_CONTRACT_FINGERPRINT
    )
    assert BASELINE_COMPILER_CONTRACT_V1["fragment_maximum"] == 5
    assert BASELINE_COMPILER_CONTRACT_V1["fragments_per_operation_maximum"] == 128
    assert BASELINE_COMPILER_CONTRACT_V1["items_per_operation_maximum"] == 640
    assert len(BASELINE_COMPILER_CONTRACT_V1["evaluation_rubric_fingerprint"]) == 64


def test_review_packet_carries_accepted_history_and_five_item_bound(baseline_input) -> None:
    first = build_baseline_source_review_request_v1(baseline_input, (), fragment_ordinal=1)
    accepted = AcceptedBaselineReviewFragmentV1(
        fragment_ordinal=1,
        request_fingerprint=first.request_fingerprint,
        response_fingerprint="5" * 64,
        payload=BaselineReviewFragmentV1(
            proposals=(
                {
                    "statement": "A covered operator must file a notice.",
                    "kind": "obligation",
                    "importance": "critical",
                    "importance_basis": ["legal_bottom_line"],
                    "importance_rationale": "Omission could change the legal bottom line.",
                    "passages": [{"source_id": "rule-1", "quote": "must file a notice"}],
                    "confidence": "clear",
                    "substantive_rationale": "The source uses mandatory language.",
                },
            ),
            review_complete=False,
        ),
    )
    second = build_baseline_source_review_request_v1(
        baseline_input, (accepted,), fragment_ordinal=2
    )
    assert canonical_json_bytes(second.payload["accepted_history"]) == canonical_json_bytes(
        [accepted.model_dump(mode="json")]
    )
    assert second.payload["max_new_items"] == 5
    assert (
        second.safe_metadata["compiler_contract_fingerprint"]
        == BASELINE_COMPILER_CONTRACT_FINGERPRINT_V1
    )


def test_audit_packet_requires_one_importance_review_per_proposal(baseline_input, review) -> None:
    request = build_baseline_source_audit_request_v1(baseline_input, review, (), fragment_ordinal=1)
    assert request.payload["importance_targets"] == tuple(
        item.proposal_ref for item in review.proposals
    )
    assert request.payload["max_new_items"] == 5


def test_audit_fragment_combines_concerns_and_importance_findings_within_five_items() -> None:
    concern = BaselineAuditConcernV1(
        target_proposal_ref="PR-0001",
        concern_type="ambiguity",
        passages=({"source_id": "rule-1", "quote": "must file a notice"},),
        explanation="The source needs attorney interpretation.",
    )
    accepted = BaselineAuditFragmentV1(
        concerns=(concern, concern, concern, concern),
        importance_findings=(_importance_finding(),),
        audit_complete=False,
    )
    assert len(accepted.concerns) + len(accepted.importance_findings) == 5
    with pytest.raises(ValueError, match="combined item limit"):
        BaselineAuditFragmentV1(
            concerns=(concern, concern, concern, concern, concern),
            importance_findings=(_importance_finding(),),
            audit_complete=False,
        )


def test_baseline_dispute_requires_exactly_one_complete_disagreement_kind(
    review: BaselineReviewAggregateV1,
) -> None:
    semantic = _semantic_concern(review)
    importance = _importance_finding()
    with pytest.raises(ValueError, match="exactly one"):
        _dispute(
            target_proposal_ref="PR-0001",
            reviewer_proposal=review.proposals[0].proposal,
            auditor_concern=semantic,
            importance_finding=importance,
        )
    with pytest.raises(ValueError, match="exactly one"):
        _dispute()
    with pytest.raises(ValueError, match="importance disputes"):
        _dispute(target_proposal_ref="PR-0001", importance_finding=importance)
    with pytest.raises(ValueError, match="semantic disputes"):
        _dispute(target_proposal_ref="PR-0001", auditor_concern=semantic)
    with pytest.raises(ValueError, match="importance disputes"):
        _dispute(
            target_proposal_ref="PR-9999",
            reviewer_proposal=review.proposals[0].proposal,
            importance_finding=importance,
        )
    semantic_dispute = _dispute(
        target_proposal_ref="PR-0001",
        reviewer_proposal=review.proposals[0].proposal,
        auditor_concern=semantic,
    )
    importance_dispute = _dispute(
        target_proposal_ref="PR-0001",
        reviewer_proposal=review.proposals[0].proposal,
        importance_finding=importance,
    )
    assert semantic_dispute.auditor_concern == semantic
    assert importance_dispute.importance_finding == importance


def test_referee_request_refuses_mutated_dispute_alternatives_with_old_fingerprint(
    baseline_input, review
) -> None:
    semantic = _dispute(
        target_proposal_ref="PR-0001",
        reviewer_proposal=review.proposals[0].proposal,
        auditor_concern=_semantic_concern(review),
    )
    importance = _dispute(
        target_proposal_ref="PR-0001",
        reviewer_proposal=review.proposals[0].proposal,
        importance_finding=_importance_finding(),
    )
    mutations = (
        semantic.model_copy(
            update={
                "reviewer_proposal": semantic.reviewer_proposal.model_copy(
                    update={"statement": "A changed obligation."}
                )
            }
        ),
        semantic.model_copy(
            update={
                "auditor_concern": semantic.auditor_concern.model_copy(
                    update={"explanation": "A changed audit explanation."}
                )
            }
        ),
        importance.model_copy(
            update={
                "importance_finding": importance.importance_finding.model_copy(
                    update={
                        "reviewed_importance": "material",
                        "reviewed_importance_basis": ("attorney_briefing",),
                    }
                )
            }
        ),
    )
    for mutation in mutations:
        with pytest.raises(ValueError, match="dispute fingerprint"):
            build_baseline_source_referee_request_v1(baseline_input, mutation)


def test_compiler_contract_cannot_be_mutated_after_fingerprinting() -> None:
    original = canonical_json_bytes(BASELINE_COMPILER_CONTRACT_V1)
    with pytest.raises(TypeError):
        BASELINE_COMPILER_CONTRACT_V1["strict_schema_hashes"]["source_review"] = "tampered"
    with pytest.raises(TypeError):
        BASELINE_COMPILER_CONTRACT_V1["operation_order"].append("tampered")
    assert canonical_json_bytes(BASELINE_COMPILER_CONTRACT_V1) == original
    assert (
        compiler_contract_fingerprint_v1(BASELINE_COMPILER_CONTRACT_V1)
        == BASELINE_COMPILER_CONTRACT_FINGERPRINT_V1
    )


def test_referee_packet_contains_exactly_one_controller_dispute(baseline_input, requests) -> None:
    referee = requests[2]
    assert referee.payload["dispute"]["dispute_id"] == "DSP-0001"
    assert "disputes" not in referee.payload
    assert referee.safe_metadata["dispute_id"] == "DSP-0001"


def test_all_baseline_packets_are_report_blind(
    requests: tuple[BaselineEvaluatorRequestV1, ...],
) -> None:
    encoded = canonical_json_bytes([item.model_dump(mode="json") for item in requests])
    for forbidden in (
        b"report_text",
        b"report_hash",
        b"candidate_id",
        b"anonymous_label",
        b"generation_metadata",
        b"grader",
    ):
        assert forbidden not in encoded
    assert (
        tuple(request.request_fingerprint for request in requests) == EXPECTED_REQUEST_FINGERPRINTS
    )
    for request in requests:
        assert (
            "omission or material misstatement could change the legal bottom line"
            in request.system_instructions
        )
        assert "necessary for a competent attorney briefing" in request.system_instructions
        assert (
            "useful explanatory, contextual, or implementation detail"
            in request.system_instructions
        )
        assert request.request_fingerprint == _hash(
            request.model_copy(update={"request_fingerprint": "0" * 64}).model_dump(mode="json")
        )


def test_request_model_rejects_nested_report_bound_payload() -> None:
    with pytest.raises(ValueError, match="report-bound"):
        BaselineEvaluatorRequestV1(
            operation="baseline_source_review",
            request_fingerprint="0" * 64,
            system_instructions="Source-only.",
            json_schema={},
            payload={"nested": {"report_text": "forbidden"}},
        )


def test_request_model_rejects_report_bound_safe_metadata() -> None:
    with pytest.raises(ValueError, match="report-bound"):
        BaselineEvaluatorRequestV1(
            operation="baseline_source_review",
            request_fingerprint="0" * 64,
            system_instructions="Source-only.",
            json_schema={},
            payload={},
            safe_metadata={"report_hash": "forbidden"},
        )


def test_audit_history_must_match_the_controller_request(baseline_input, review) -> None:
    accepted = AcceptedBaselineAuditFragmentV1(
        fragment_ordinal=1,
        request_fingerprint="a" * 64,
        response_fingerprint="b" * 64,
        payload=BaselineAuditFragmentV1(
            concerns=(),
            importance_findings=(
                {
                    "proposal_ref": "PR-0001",
                    "reviewed_importance": "critical",
                    "reviewed_importance_basis": ["legal_bottom_line"],
                    "importance_rationale": "Omission could change the legal bottom line.",
                    "disposition": "agree",
                },
            ),
            audit_complete=False,
        ),
    )
    with pytest.raises(ValueError, match="accepted source-audit history"):
        build_baseline_source_audit_request_v1(
            baseline_input, review, (accepted,), fragment_ordinal=2
        )
