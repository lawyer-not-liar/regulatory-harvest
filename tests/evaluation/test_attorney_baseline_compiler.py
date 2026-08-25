"""Deterministic compiler tests for report-blind evaluation baselines."""

from __future__ import annotations

import copy
import hashlib
from collections.abc import Callable

import pytest

from regulatory_harvest.evaluation.attorney_baseline_compiler import (
    BaselineCompilationError,
    aggregate_baseline_audit_v1,
    aggregate_baseline_referees_v1,
    aggregate_baseline_review_v1,
    apply_baseline_correction_v1,
    build_baseline_disputes_v1,
    compile_canonical_baseline_v1,
    validate_baseline_correction_v1,
)
from regulatory_harvest.evaluation.attorney_baseline_input import legal_input_fingerprint_v1
from regulatory_harvest.evaluation.attorney_baseline_models import (
    AcceptedBaselineAuditFragmentV1,
    AcceptedBaselineRefereeFragmentV1,
    AcceptedBaselineReviewFragmentV1,
    BaselineAuditFragmentV1,
    BaselineCorrectionActionV1,
    BaselineCorrectionRecordV1,
    BaselineInputV1,
    BaselineRefereeAggregateV1,
    BaselineRefereeDecisionV1,
    BaselineRelationshipV1,
    BaselineRequirementV1,
    BaselineReviewFragmentV1,
)
from regulatory_harvest.evaluation.attorney_baseline_requests import (
    BASELINE_COMPILER_CONTRACT_FINGERPRINT_V1,
    BASELINE_COMPILER_CONTRACT_V1,
    build_baseline_source_audit_request_v1,
    build_baseline_source_review_request_v1,
)
from regulatory_harvest.evaluation.attorney_v22_compiler import RUBRIC_V22
from regulatory_harvest.storage import canonical_json_bytes, sha256_digest


def _proposal(
    statement: str,
    quote: str,
    *,
    source_id: str = "rule-1",
    importance: str = "critical",
    basis: tuple[str, ...] = ("legal_bottom_line",),
    importance_rationale: str = "Omission could change the legal bottom line.",
    dependency: dict[str, str] | None = None,
) -> dict[str, object]:
    return {
        "statement": statement,
        "kind": "obligation",
        "importance": importance,
        "importance_basis": basis,
        "importance_rationale": importance_rationale,
        "passages": ({"source_id": source_id, "quote": quote},),
        "dependency": dependency,
        "confidence": "clear",
        "substantive_rationale": "The source uses mandatory language.",
    }


def _importance(
    proposal_ref: str,
    *,
    importance: str = "critical",
    basis: tuple[str, ...] = ("legal_bottom_line",),
    rationale: str = "Omission could change the legal bottom line.",
    disposition: str = "agree",
) -> dict[str, object]:
    return {
        "proposal_ref": proposal_ref,
        "reviewed_importance": importance,
        "reviewed_importance_basis": basis,
        "importance_rationale": rationale,
        "disposition": disposition,
    }


@pytest.fixture
def baseline_input() -> BaselineInputV1:
    source_text = (
        "Section 1. A covered operator must file a notice. "
        "Section 2. The notice must identify the operator."
    )
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
    client_facts = "The operator is covered."
    payload = {
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
            "compiler_contract": BASELINE_COMPILER_CONTRACT_V1,
            "compiler_contract_fingerprint": BASELINE_COMPILER_CONTRACT_FINGERPRINT_V1,
            "evaluation_rubric_version": "attorney-eval-v2.2",
            "evaluation_rubric_bytes": rubric_bytes,
            "evaluation_rubric_fingerprint": sha256_digest(rubric_bytes),
            "importance_policy_version": "importance-policy-v1",
            "importance_policy_bytes": policy_bytes,
            "importance_policy_fingerprint": sha256_digest(policy_bytes),
            "legal_input_fingerprint": "d" * 64,
        }
    provisional = BaselineInputV1.model_validate(payload)
    payload["legal_input_fingerprint"] = legal_input_fingerprint_v1(provisional)
    return BaselineInputV1.model_validate(payload)


def _review(
    baseline_input: BaselineInputV1,
    proposals: tuple[dict[str, object], ...],
):
    request = build_baseline_source_review_request_v1(baseline_input, (), fragment_ordinal=1)
    fragment = AcceptedBaselineReviewFragmentV1(
        fragment_ordinal=1,
        request_fingerprint=request.request_fingerprint,
        response_fingerprint="1" * 64,
        payload=BaselineReviewFragmentV1(proposals=proposals, review_complete=True),
    )
    return aggregate_baseline_review_v1(baseline_input, (fragment,))


def _audit(
    baseline_input: BaselineInputV1,
    review,
    *,
    concerns: tuple[dict[str, object], ...] = (),
    importance_findings: tuple[dict[str, object], ...] | None = None,
):
    if importance_findings is None:
        importance_findings = tuple(
            _importance(item.proposal_ref) for item in review.proposals
        )
    request = build_baseline_source_audit_request_v1(
        baseline_input, review, (), fragment_ordinal=1
    )
    fragment = AcceptedBaselineAuditFragmentV1(
        fragment_ordinal=1,
        request_fingerprint=request.request_fingerprint,
        response_fingerprint="2" * 64,
        payload=BaselineAuditFragmentV1(
            concerns=concerns,
            importance_findings=importance_findings,
            audit_complete=True,
        ),
    )
    return aggregate_baseline_audit_v1(baseline_input, review, (fragment,))


def _referees(
    baseline_input: BaselineInputV1,
    disputes,
    decision_factory: Callable[[object], BaselineRefereeDecisionV1],
):
    fragments = tuple(
        AcceptedBaselineRefereeFragmentV1(
            dispute_id=dispute.dispute_id,
            dispute_fingerprint=dispute.dispute_fingerprint,
            response_fingerprint=f"{index + 3:x}" * 64,
            decision=decision_factory(dispute),
        )
        for index, dispute in enumerate(disputes)
    )
    return aggregate_baseline_referees_v1(baseline_input, disputes, fragments)


def _empty_referees(baseline_input: BaselineInputV1):
    return aggregate_baseline_referees_v1(baseline_input, (), ())


def test_compiler_assigns_stable_ids_exact_offsets_and_relationships(
    baseline_input: BaselineInputV1,
) -> None:
    review = _review(
        baseline_input,
        (
            _proposal(
                "The notice must identify the operator.",
                "must identify the operator",
                dependency={
                    "relationship": "depends_on",
                    "target_statement": "A covered operator must file a notice.",
                },
            ),
            _proposal(
                "A covered operator must file a notice.",
                "must file a notice",
            ),
        ),
    )
    audit = _audit(baseline_input, review)
    compiled = compile_canonical_baseline_v1(
        baseline_input, review, audit, _empty_referees(baseline_input)
    )

    assert [item.proposal_ref for item in review.proposals] == ["PR-0001", "PR-0002"]
    assert [item.requirement_id for item in compiled.requirements] == ["REQ-0001", "REQ-0002"]
    assert [item.canonical_order for item in compiled.requirements] == [0, 1]
    assert compiled.requirements[0].passages[0].model_dump(mode="json") == {
        "source_id": "rule-1",
        "quote": "must file a notice",
        "start_char": 30,
        "end_char": 48,
    }
    assert compiled.relationships[0].model_dump(mode="json") == {
        "relationship_id": "REL-0001",
        "relationship": "depends_on",
        "source_requirement_id": "REQ-0002",
        "target_requirement_id": "REQ-0001",
    }


def test_canonical_ids_do_not_depend_on_role_response_order(
    baseline_input: BaselineInputV1,
) -> None:
    proposals = (
        _proposal("A covered operator must file a notice.", "must file a notice"),
        _proposal("The notice must identify the operator.", "must identify the operator"),
    )
    left_review = _review(baseline_input, proposals)
    right_review = _review(baseline_input, tuple(reversed(proposals)))
    left_audit = _audit(baseline_input, left_review)
    right_audit = _audit(baseline_input, right_review)

    left = compile_canonical_baseline_v1(
        baseline_input, left_review, left_audit, _empty_referees(baseline_input)
    )
    right = compile_canonical_baseline_v1(
        baseline_input, right_review, right_audit, _empty_referees(baseline_input)
    )
    assert left.requirements == right.requirements
    assert left.relationships == right.relationships


@pytest.mark.parametrize(
    "proposals",
    [
        (
            _proposal("A covered operator must file a notice.", "must file a notice"),
            _proposal("A covered operator must file a notice.", "must file a notice"),
        ),
        (
            _proposal("A covered operator must file a notice.", "must file a notice"),
            _proposal(" A  covered operator must file a notice. ", "must file a notice"),
        ),
    ],
)
def test_review_rejects_duplicate_or_colliding_semantics(
    baseline_input: BaselineInputV1, proposals: tuple[dict[str, object], ...]
) -> None:
    with pytest.raises(BaselineCompilationError, match="BASELINE_REVIEW_SEMANTICS"):
        _review(baseline_input, proposals)


def test_review_rejects_unknown_or_nonexistent_source_passage(
    baseline_input: BaselineInputV1,
) -> None:
    for proposal in (
        _proposal("Unknown source.", "must file a notice", source_id="missing"),
        _proposal("Unknown quote.", "must file a registration"),
    ):
        with pytest.raises(BaselineCompilationError, match="BASELINE_SOURCE_EVIDENCE"):
            _review(baseline_input, (proposal,))


def test_audit_requires_every_proposal_importance_exactly_once(
    baseline_input: BaselineInputV1,
) -> None:
    review = _review(
        baseline_input,
        (
            _proposal("A covered operator must file a notice.", "must file a notice"),
            _proposal("The notice must identify the operator.", "must identify the operator"),
        ),
    )
    for findings in (
        (_importance("PR-0001"),),
        (_importance("PR-0001"), _importance("PR-0001")),
        (_importance("PR-0001"), _importance("PR-9999")),
    ):
        with pytest.raises(BaselineCompilationError, match="BASELINE_AUDIT_IMPORTANCE_COVERAGE"):
            _audit(baseline_input, review, importance_findings=findings)


def test_audit_rejects_disposition_that_silently_conflicts_with_importance(
    baseline_input: BaselineInputV1,
) -> None:
    review = _review(
        baseline_input,
        (_proposal("A covered operator must file a notice.", "must file a notice"),),
    )
    with pytest.raises(BaselineCompilationError, match="BASELINE_AUDIT_IMPORTANCE_DISPOSITION"):
        _audit(
            baseline_input,
            review,
            importance_findings=(
                _importance(
                    "PR-0001",
                    importance="material",
                    basis=("attorney_briefing",),
                    rationale="The rule is necessary for a competent attorney briefing.",
                    disposition="agree",
                ),
            ),
        )


def test_importance_disagreement_cannot_be_compiled_without_referee(
    baseline_input: BaselineInputV1,
) -> None:
    review = _review(
        baseline_input,
        (_proposal("A covered operator must file a notice.", "must file a notice"),),
    )
    audit = _audit(
        baseline_input,
        review,
        importance_findings=(
            _importance(
                "PR-0001",
                importance="material",
                basis=("attorney_briefing",),
                rationale="The rule is necessary for a competent attorney briefing.",
                disposition="correct",
            ),
        ),
    )
    disputes = build_baseline_disputes_v1(baseline_input, review, audit)
    assert [item.dispute_id for item in disputes] == ["DSP-0001"]
    with pytest.raises(BaselineCompilationError, match="BASELINE_REFEREE_COVERAGE"):
        compile_canonical_baseline_v1(
            baseline_input, review, audit, _empty_referees(baseline_input)
        )


@pytest.mark.parametrize(
    ("choice", "expected_statement"),
    [
        ("accept_reviewer", "A covered operator must file a notice."),
        ("accept_auditor", "A covered operator must file an annual notice."),
    ],
)
def test_semantic_referee_accepts_exactly_the_selected_alternative(
    baseline_input: BaselineInputV1, choice: str, expected_statement: str
) -> None:
    reviewer = _proposal("A covered operator must file a notice.", "must file a notice")
    auditor = _proposal("A covered operator must file an annual notice.", "must file a notice")
    review = _review(baseline_input, (reviewer,))
    audit = _audit(
        baseline_input,
        review,
        concerns=(
            {
                "target_proposal_ref": "PR-0001",
                "concern_type": "incorrect_statement",
                "passages": ({"source_id": "rule-1", "quote": "must file a notice"},),
                "explanation": "The proposal omits the annual qualification.",
                "correction": auditor,
            },
        ),
    )
    disputes = build_baseline_disputes_v1(baseline_input, review, audit)
    assert [item.audit_ref for item in audit.concerns] == ["AUD-0001"]
    referees = _referees(
        baseline_input,
        disputes,
        lambda dispute: BaselineRefereeDecisionV1(
            dispute_id=dispute.dispute_id,
            decision=choice,
            passages=({"source_id": "rule-1", "quote": "must file a notice"},),
            importance="critical",
            importance_basis=("legal_bottom_line",),
            importance_rationale="Omission could change the legal bottom line.",
            substantive_rationale="The selected statement best matches the source.",
        ),
    )
    compiled = compile_canonical_baseline_v1(baseline_input, review, audit, referees)
    assert [item.statement for item in compiled.requirements] == [expected_statement]
    assert compiled.contested_requirements == ()


def test_unresolved_semantic_referee_preserves_both_contested_alternatives(
    baseline_input: BaselineInputV1,
) -> None:
    reviewer = _proposal("A covered operator must file a notice.", "must file a notice")
    auditor = _proposal("A covered operator must file an annual notice.", "must file a notice")
    review = _review(baseline_input, (reviewer,))
    audit = _audit(
        baseline_input,
        review,
        concerns=(
            {
                "target_proposal_ref": "PR-0001",
                "concern_type": "ambiguity",
                "passages": ({"source_id": "rule-1", "quote": "must file a notice"},),
                "explanation": "The source could support a narrower annual obligation.",
                "correction": auditor,
            },
        ),
    )
    disputes = build_baseline_disputes_v1(baseline_input, review, audit)
    referees = _referees(
        baseline_input,
        disputes,
        lambda dispute: BaselineRefereeDecisionV1(
            dispute_id=dispute.dispute_id,
            decision="unresolved",
            passages=({"source_id": "rule-1", "quote": "must file a notice"},),
            importance="critical",
            importance_basis=("legal_bottom_line",),
            importance_rationale="Either alternative could change the legal bottom line.",
            substantive_rationale="The retained source does not resolve the frequency.",
        ),
    )
    compiled = compile_canonical_baseline_v1(baseline_input, review, audit, referees)
    assert compiled.requirements == ()
    assert len(compiled.contested_requirements) == 1
    contested = compiled.contested_requirements[0]
    assert contested.reviewer_alternative is not None
    assert contested.auditor_alternative is not None
    assert contested.reviewer_alternative.statement == reviewer["statement"]
    assert contested.auditor_alternative.statement == auditor["statement"]


def test_unresolved_importance_referee_preserves_both_labels_without_favorable_choice(
    baseline_input: BaselineInputV1,
) -> None:
    review = _review(
        baseline_input,
        (_proposal("A covered operator must file a notice.", "must file a notice"),),
    )
    audit = _audit(
        baseline_input,
        review,
        importance_findings=(
            _importance(
                "PR-0001",
                importance="material",
                basis=("attorney_briefing",),
                rationale="The rule is necessary for a competent attorney briefing.",
                disposition="correct",
            ),
        ),
    )
    disputes = build_baseline_disputes_v1(baseline_input, review, audit)
    referees = _referees(
        baseline_input,
        disputes,
        lambda dispute: BaselineRefereeDecisionV1(
            dispute_id=dispute.dispute_id,
            decision="unresolved",
            passages=({"source_id": "rule-1", "quote": "must file a notice"},),
            importance="critical",
            importance_basis=("legal_bottom_line",),
            importance_rationale="The disputed consequence could change the legal bottom line.",
            substantive_rationale="The source does not resolve the consequence of omission.",
        ),
    )
    compiled = compile_canonical_baseline_v1(baseline_input, review, audit, referees)
    contested = compiled.contested_requirements[0]
    assert compiled.requirements == ()
    assert contested.reviewer_alternative is not None
    assert contested.auditor_alternative is not None
    assert contested.reviewer_alternative.importance.value == "critical"
    assert contested.auditor_alternative.importance.value == "material"


def test_semantic_and_importance_disagreements_each_survive_when_both_are_unresolved(
    baseline_input: BaselineInputV1,
) -> None:
    reviewer = _proposal("A covered operator must file a notice.", "must file a notice")
    auditor = _proposal("A covered operator must file an annual notice.", "must file a notice")
    review = _review(baseline_input, (reviewer,))
    audit = _audit(
        baseline_input,
        review,
        concerns=(
            {
                "target_proposal_ref": "PR-0001",
                "concern_type": "incorrect_statement",
                "passages": ({"source_id": "rule-1", "quote": "must file a notice"},),
                "explanation": "The proposal may omit an annual qualification.",
                "correction": auditor,
            },
        ),
        importance_findings=(
            _importance(
                "PR-0001",
                importance="material",
                basis=("attorney_briefing",),
                rationale="The rule is necessary for a competent attorney briefing.",
                disposition="correct",
            ),
        ),
    )
    disputes = build_baseline_disputes_v1(baseline_input, review, audit)
    assert len(disputes) == 2
    referees = _referees(
        baseline_input,
        disputes,
        lambda dispute: BaselineRefereeDecisionV1(
            dispute_id=dispute.dispute_id,
            decision="unresolved",
            passages=({"source_id": "rule-1", "quote": "must file a notice"},),
            importance="critical",
            importance_basis=("legal_bottom_line",),
            importance_rationale="The unresolved consequence could change the legal bottom line.",
            substantive_rationale="The retained source does not resolve this disagreement.",
        ),
    )
    compiled = compile_canonical_baseline_v1(baseline_input, review, audit, referees)
    assert compiled.requirements == ()
    assert len(compiled.contested_requirements) == 2
    assert {
        (
            item.reviewer_alternative.statement if item.reviewer_alternative else None,
            item.auditor_alternative.statement if item.auditor_alternative else None,
            item.auditor_alternative.importance.value if item.auditor_alternative else None,
        )
        for item in compiled.contested_requirements
    } == {
        (
            "A covered operator must file a notice.",
            "A covered operator must file an annual notice.",
            "critical",
        ),
        (
            "A covered operator must file a notice.",
            "A covered operator must file a notice.",
            "material",
        ),
    }


def test_unknown_relationship_target_and_duplicate_edge_fail_closed(
    baseline_input: BaselineInputV1,
) -> None:
    first = _proposal("A covered operator must file a notice.", "must file a notice")
    unknown = _proposal(
        "The notice must identify the operator.",
        "must identify the operator",
        dependency={"relationship": "depends_on", "target_statement": "Missing rule."},
    )
    review = _review(baseline_input, (first, unknown))
    audit = _audit(baseline_input, review)
    with pytest.raises(BaselineCompilationError, match="BASELINE_RELATIONSHIP_ENDPOINT"):
        compile_canonical_baseline_v1(
            baseline_input, review, audit, _empty_referees(baseline_input)
        )


def test_fingerprints_bind_exact_accepted_bytes_and_provenance(
    baseline_input: BaselineInputV1,
) -> None:
    review = _review(
        baseline_input,
        (_proposal("A covered operator must file a notice.", "must file a notice"),),
    )
    audit = _audit(baseline_input, review)
    first = compile_canonical_baseline_v1(
        baseline_input, review, audit, _empty_referees(baseline_input)
    )
    second = compile_canonical_baseline_v1(
        baseline_input, review, audit, _empty_referees(baseline_input)
    )
    assert first.model_dump(mode="json") == second.model_dump(mode="json")
    assert first.provenance.source_review_aggregate_fingerprint == review.aggregate_fingerprint
    assert first.provenance.source_audit_aggregate_fingerprint == audit.aggregate_fingerprint
    assert first.baseline_fingerprint == sha256_digest(
        canonical_json_bytes(
            {
                key: value
                for key, value in first.model_dump(mode="json").items()
                if key != "baseline_fingerprint"
            }
        )
    )


def test_input_or_aggregate_provenance_swap_is_refused(
    baseline_input: BaselineInputV1,
) -> None:
    review = _review(
        baseline_input,
        (_proposal("A covered operator must file a notice.", "must file a notice"),),
    )
    audit = _audit(baseline_input, review)
    swapped_input_payload = copy.deepcopy(baseline_input.model_dump(mode="python"))
    swapped_input_payload["compiler_contract"] = copy.deepcopy(
        baseline_input.model_dump(mode="json")["compiler_contract"]
    )
    swapped_input_payload["legal_input_fingerprint"] = "e" * 64
    swapped_input = BaselineInputV1.model_validate(swapped_input_payload)
    with pytest.raises(BaselineCompilationError, match="BASELINE_INPUT_INVALID"):
        compile_canonical_baseline_v1(
            swapped_input, review, audit, _empty_referees(baseline_input)
        )
    forged_review = review.model_copy(update={"aggregate_fingerprint": "f" * 64})
    with pytest.raises(BaselineCompilationError, match="BASELINE_REVIEW_AGGREGATE"):
        compile_canonical_baseline_v1(
            baseline_input, forged_review, audit, _empty_referees(baseline_input)
        )


def test_raw_construction_bypass_and_generic_referee_rationale_are_refused(
    baseline_input: BaselineInputV1,
) -> None:
    review = _review(
        baseline_input,
        (_proposal("A covered operator must file a notice.", "must file a notice"),),
    )
    audit = _audit(
        baseline_input,
        review,
        importance_findings=(
            _importance(
                "PR-0001",
                importance="material",
                basis=("attorney_briefing",),
                rationale="The rule is necessary for a competent attorney briefing.",
                disposition="correct",
            ),
        ),
    )
    disputes = build_baseline_disputes_v1(baseline_input, review, audit)
    forged_decision = BaselineRefereeDecisionV1.model_construct(
        dispute_id="DSP-0001",
        decision="accept_reviewer",
        passages=({"source_id": "rule-1", "quote": "must file a notice"},),
        importance="critical",
        importance_basis=("legal_bottom_line",),
        importance_rationale="critical",
        substantive_rationale="The reviewer follows the source.",
    )
    forged_fragment = AcceptedBaselineRefereeFragmentV1.model_construct(
        dispute_id="DSP-0001",
        dispute_fingerprint=disputes[0].dispute_fingerprint,
        response_fingerprint="3" * 64,
        decision=forged_decision,
    )
    with pytest.raises(BaselineCompilationError, match="BASELINE_REFEREE_FRAGMENT"):
        aggregate_baseline_referees_v1(baseline_input, disputes, (forged_fragment,))


def test_empty_referee_aggregate_is_not_accepted_by_raw_fingerprint_only(
    baseline_input: BaselineInputV1,
) -> None:
    forged = BaselineRefereeAggregateV1(fragments=(), aggregate_fingerprint="0" * 64)
    review = _review(
        baseline_input,
        (_proposal("A covered operator must file a notice.", "must file a notice"),),
    )
    audit = _audit(baseline_input, review)
    with pytest.raises(BaselineCompilationError, match="BASELINE_REFEREE_AGGREGATE"):
        compile_canonical_baseline_v1(baseline_input, review, audit, forged)


def _prior_baseline(baseline_input: BaselineInputV1):
    review = _review(
        baseline_input,
        (_proposal("A covered operator must file a notice.", "must file a notice"),),
    )
    audit = _audit(baseline_input, review)
    return compile_canonical_baseline_v1(
        baseline_input, review, audit, _empty_referees(baseline_input)
    )


def _correction_requirement(
    baseline_input: BaselineInputV1,
    *,
    requirement_id: str = "REQ-9999",
    statement: str = "The notice must identify the operator.",
    quote: str = "must identify the operator",
) -> BaselineRequirementV1:
    text = baseline_input.sources[0].normalized_text
    start = text.find(quote)
    return BaselineRequirementV1(
        requirement_id=requirement_id,
        canonical_order=999,
        statement=statement,
        kind="obligation",
        importance="material",
        importance_basis=("attorney_briefing",),
        importance_rationale="The detail is necessary for a competent attorney briefing.",
        passages=(
            {
                "source_id": "rule-1",
                "quote": quote,
                "start_char": start,
                "end_char": start + len(quote),
            },
        ),
        confidence="clear",
        substantive_rationale="The source expressly identifies the required content.",
    )


def _correction(
    prior,
    actions: tuple[BaselineCorrectionActionV1 | dict[str, object], ...],
    *,
    prior_root: str = "9" * 64,
    reason: str = "The source review omitted an express notice-content requirement.",
    fingerprint: str | None = None,
) -> BaselineCorrectionRecordV1:
    payload: dict[str, object] = {
        "schema_version": "baseline-correction-v1",
        "prior_baseline_root": prior_root,
        "prior_baseline_fingerprint": prior.baseline_fingerprint,
        "correction_id": "CORR-0001",
        "actions": actions,
        "reason": reason,
        "attorney_approval": {
            "approved_by": "Fictional Reviewing Attorney",
            "approved_at": "2026-08-24T20:00:00-07:00",
            "approval_statement": "I approve this source-bound baseline correction.",
        },
        "correction_fingerprint": "0" * 64,
    }
    provisional = BaselineCorrectionRecordV1.model_validate(payload)
    payload["correction_fingerprint"] = fingerprint or sha256_digest(
        canonical_json_bytes(
            {
                key: value
                for key, value in provisional.model_dump(mode="json").items()
                if key != "correction_fingerprint"
            }
        )
    )
    return BaselineCorrectionRecordV1.model_validate(payload)


def test_correction_creates_new_baseline_without_rewriting_prior(
    baseline_input: BaselineInputV1,
) -> None:
    prior = _prior_baseline(baseline_input)
    before = prior.model_dump(mode="json")
    added = _correction_requirement(baseline_input)
    relationship = BaselineRelationshipV1(
        relationship_id="REL-9999",
        relationship="depends_on",
        source_requirement_id="REQ-9999",
        target_requirement_id="REQ-0001",
    )
    correction = _correction(
        prior,
        (
            {"action": "add_requirement", "requirement": added},
            {"action": "add_relationship", "relationship": relationship},
        ),
    )

    corrected = apply_baseline_correction_v1(
        baseline_input, prior, correction, prior_baseline_root="9" * 64
    )
    assert corrected.prior_baseline_fingerprint == correction.prior_baseline_fingerprint
    assert corrected.correction_record_fingerprint == correction.correction_fingerprint
    assert corrected.baseline_fingerprint != correction.prior_baseline_fingerprint
    assert prior.model_dump(mode="json") == before
    assert corrected.provenance == prior.provenance
    assert [item.requirement_id for item in corrected.requirements] == [
        "REQ-0001",
        "REQ-0002",
    ]
    assert [item.canonical_order for item in corrected.requirements] == [0, 1]
    assert corrected.relationships[0].model_dump(mode="json") == {
        "relationship_id": "REL-0001",
        "relationship": "depends_on",
        "source_requirement_id": "REQ-0002",
        "target_requirement_id": "REQ-0001",
    }


@pytest.mark.parametrize(
    ("prior_root", "fingerprint", "code"),
    [
        ("8" * 64, None, "BASELINE_CORRECTION_PRIOR_ROOT"),
        ("9" * 64, "7" * 64, "BASELINE_CORRECTION_PRIOR_FINGERPRINT"),
    ],
)
def test_correction_requires_exact_prior_root_and_fingerprint(
    baseline_input: BaselineInputV1,
    prior_root: str,
    fingerprint: str | None,
    code: str,
) -> None:
    prior = _prior_baseline(baseline_input)
    action = {"action": "add_requirement", "requirement": _correction_requirement(baseline_input)}
    correction = _correction(prior, (action,))
    if fingerprint is not None:
        raw = correction.model_dump(mode="json")
        raw["prior_baseline_fingerprint"] = fingerprint
        provisional = BaselineCorrectionRecordV1.model_validate(
            {**raw, "correction_fingerprint": "0" * 64}
        )
        raw["correction_fingerprint"] = sha256_digest(
            canonical_json_bytes(
                {
                    key: value
                    for key, value in provisional.model_dump(mode="json").items()
                    if key != "correction_fingerprint"
                }
            )
        )
        correction = BaselineCorrectionRecordV1.model_validate(raw)
    with pytest.raises(BaselineCompilationError, match=code):
        validate_baseline_correction_v1(
            baseline_input, prior, correction, prior_baseline_root=prior_root
        )


def test_correction_refuses_wrong_fingerprint_and_raw_construction_bypass(
    baseline_input: BaselineInputV1,
) -> None:
    prior = _prior_baseline(baseline_input)
    correction = _correction(
        prior,
        ({"action": "add_requirement", "requirement": _correction_requirement(baseline_input)},),
        fingerprint="6" * 64,
    )
    with pytest.raises(BaselineCompilationError, match="BASELINE_CORRECTION_FINGERPRINT"):
        validate_baseline_correction_v1(
            baseline_input, prior, correction, prior_baseline_root="9" * 64
        )

    forged_requirement = _correction_requirement(baseline_input).model_copy(
        update={"importance_rationale": "material"}
    )
    forged_action = BaselineCorrectionActionV1.model_construct(
        action="add_requirement",
        requirement_id=None,
        relationship_id=None,
        requirement=forged_requirement,
        relationship=None,
    )
    forged_record = BaselineCorrectionRecordV1.model_construct(
        **{
            **_correction(
                prior,
                (
                    {
                        "action": "add_requirement",
                        "requirement": _correction_requirement(baseline_input),
                    },
                ),
            ).model_dump(mode="python"),
            "actions": (forged_action,),
        }
    )
    with pytest.raises(BaselineCompilationError, match="BASELINE_CORRECTION_INVALID"):
        validate_baseline_correction_v1(
            baseline_input, prior, forged_record, prior_baseline_root="9" * 64
        )


@pytest.mark.parametrize(
    "mutation",
    [
        {"start_char": 0},
        {"end_char": 99},
        {"quote": "must file a registration", "start_char": 0, "end_char": 24},
        {"source_id": "outside-prior-input"},
    ],
)
def test_correction_evidence_must_match_exact_prior_legal_input(
    baseline_input: BaselineInputV1, mutation: dict[str, object]
) -> None:
    prior = _prior_baseline(baseline_input)
    raw_requirement = _correction_requirement(baseline_input).model_dump(mode="json")
    raw_requirement["passages"][0].update(mutation)
    requirement = BaselineRequirementV1.model_validate(raw_requirement)
    correction = _correction(
        prior, ({"action": "add_requirement", "requirement": requirement},)
    )
    with pytest.raises(BaselineCompilationError, match="BASELINE_CORRECTION_EVIDENCE"):
        apply_baseline_correction_v1(
            baseline_input, prior, correction, prior_baseline_root="9" * 64
        )


def test_correction_remove_requirement_requires_explicit_relationship_removal(
    baseline_input: BaselineInputV1,
) -> None:
    prior = _prior_baseline(baseline_input)
    added = _correction_requirement(baseline_input)
    relationship = BaselineRelationshipV1(
        relationship_id="REL-9999",
        relationship="depends_on",
        source_requirement_id="REQ-9999",
        target_requirement_id="REQ-0001",
    )
    with_relationship = apply_baseline_correction_v1(
        baseline_input,
        prior,
        _correction(
            prior,
            (
                {"action": "add_requirement", "requirement": added},
                {"action": "add_relationship", "relationship": relationship},
            ),
        ),
        prior_baseline_root="9" * 64,
    )
    correction = _correction(
        with_relationship,
        ({"action": "remove_requirement", "requirement_id": "REQ-0002"},),
        prior_root="8" * 64,
    )
    with pytest.raises(BaselineCompilationError, match="BASELINE_CORRECTION_RELATIONSHIP"):
        apply_baseline_correction_v1(
            baseline_input, with_relationship, correction, prior_baseline_root="8" * 64
        )


def test_correction_actions_require_exactly_one_typed_payload(
    baseline_input: BaselineInputV1,
) -> None:
    requirement = _correction_requirement(baseline_input)
    relationship = BaselineRelationshipV1(
        relationship_id="REL-9999",
        relationship="depends_on",
        source_requirement_id="REQ-9999",
        target_requirement_id="REQ-0001",
    )
    with pytest.raises(ValueError, match="mismatched typed payload"):
        BaselineCorrectionActionV1(
            action="add_requirement",
            requirement=requirement,
            relationship=relationship,
        )
    with pytest.raises(ValueError, match="require one replacement"):
        BaselineCorrectionActionV1(action="replace_requirement", requirement_id="REQ-0001")
    with pytest.raises(ValueError, match="omit replacements"):
        BaselineCorrectionActionV1(
            action="remove_relationship",
            relationship_id="REL-0001",
            relationship=relationship,
        )


def test_correction_record_is_versioned_approved_nonblank_and_report_free(
    baseline_input: BaselineInputV1,
) -> None:
    prior = _prior_baseline(baseline_input)
    action = {"action": "add_requirement", "requirement": _correction_requirement(baseline_input)}
    valid = _correction(prior, (action,))
    raw = valid.model_dump(mode="json")
    for mutation in (
        {**raw, "schema_version": "baseline-correction-v2"},
        {**raw, "reason": "   "},
        {**raw, "attorney_approval": {**raw["attorney_approval"], "approved_by": ""}},
        {**raw, "report_text": "A report must never enter correction bytes."},
    ):
        with pytest.raises(ValueError):
            BaselineCorrectionRecordV1.model_validate(mutation)


def test_correction_input_identity_swap_is_refused(
    baseline_input: BaselineInputV1,
) -> None:
    prior = _prior_baseline(baseline_input)
    correction = _correction(
        prior,
        ({"action": "add_requirement", "requirement": _correction_requirement(baseline_input)},),
    )
    raw_input = copy.deepcopy(baseline_input.model_dump(mode="python"))
    raw_input["compiler_contract"] = copy.deepcopy(
        baseline_input.model_dump(mode="json")["compiler_contract"]
    )
    raw_input["legal_input_fingerprint"] = "5" * 64
    swapped = BaselineInputV1.model_validate(raw_input)
    with pytest.raises(BaselineCompilationError, match="BASELINE_INPUT_INVALID"):
        apply_baseline_correction_v1(
            swapped, prior, correction, prior_baseline_root="9" * 64
        )
