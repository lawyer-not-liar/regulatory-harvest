"""Protocol 2.0 model-boundary tests.

These tests prevent a future evaluator role from smuggling canonical mechanics
into a semantic response or from accepting malformed response data.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from regulatory_harvest.evaluation import attorney_v2_models as models
from regulatory_harvest.evaluation.attorney_v2_models import (
    AuditConcernV2,
    CanonicalBaselineV2,
    CanonicalRelationshipV2,
    CanonicalRequirementV2,
    ComparisonDispositionV2,
    ComparisonResultV2,
    EvaluationManifestV2,
    EvaluationRunStateV2,
    EvaluatorOperationV2,
    EvaluatorRequestV2,
    EvaluatorResponseV2,
    GradeResponseV2,
    ImportanceV2,
    IndexedProposalV2,
    MaterialDisputeV2,
    ReconciledGradeV2,
    ReconciledRequirementGradeV2,
    ReportResultV2,
    RequirementKindV2,
    ResolvedPassageV2,
    SemanticPassage,
    SemanticProposal,
    SourceAuditV2,
    SourceRefereeResponseV2,
    SourceReviewV2,
    evaluator_request_fingerprint,
    validate_evaluator_response_v2,
)
from regulatory_harvest.evaluation.attorney_v21_models import EvaluatorResponseV21
from regulatory_harvest.evaluation.attorney_v22_models import EvaluatorResponseV22
from regulatory_harvest.storage import canonical_json_bytes


def valid_semantic_proposal_payload() -> dict[str, object]:
    return {
        "statement": "A covered operator must file the notice.",
        "kind": "obligation",
        "importance": "critical",
        "passages": [{"source_id": "rule-1", "quote": "must file the notice"}],
        "dependency": None,
        "confidence": "clear",
        "rationale": "The operative text states a mandatory filing duty.",
    }


def test_source_review_accepts_semantics_without_canonical_fields() -> None:
    review = SourceReviewV2.model_validate(
        {
            "schema_version": "2.0",
            "proposals": [valid_semantic_proposal_payload()],
        }
    )

    assert review.proposals[0].kind is RequirementKindV2.OBLIGATION
    assert "requirement_id" not in review.model_dump(mode="json")["proposals"][0]


@pytest.mark.parametrize(
    "forbidden",
    ["requirement_id", "walk_order", "fingerprint", "score", "repair_transactions"],
)
def test_semantic_proposal_rejects_canonical_fields(forbidden: str) -> None:
    payload = valid_semantic_proposal_payload()
    payload[forbidden] = "forbidden"

    with pytest.raises(ValidationError):
        SemanticProposal.model_validate(payload)


@pytest.mark.parametrize(
    "payload",
    [
        {"source_id": "", "quote": "must file"},
        {"source_id": "rule-1", "quote": "   "},
        {"source_id": 1, "quote": "must file"},
    ],
)
def test_semantic_passage_rejects_blank_and_coerced_text(payload: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        SemanticPassage.model_validate(payload)


def test_semantic_proposal_rejects_duplicate_passages() -> None:
    payload = valid_semantic_proposal_payload()
    payload["passages"] = [
        {"source_id": "rule-1", "quote": "must file the notice"},
        {"source_id": "rule-1", "quote": "must file the notice"},
    ]

    with pytest.raises(ValidationError, match="unique"):
        SemanticProposal.model_validate(payload)


@pytest.mark.parametrize(
    ("operation", "expected"),
    [
        ("source_review", EvaluatorOperationV2.SOURCE_REVIEW),
        ("source_audit", EvaluatorOperationV2.SOURCE_AUDIT),
        ("source_referee", EvaluatorOperationV2.SOURCE_REFEREE),
        ("grade_report", EvaluatorOperationV2.GRADE_REPORT),
    ],
)
def test_evaluator_operation_accepts_only_the_four_substantive_roles(
    operation: str, expected: EvaluatorOperationV2
) -> None:
    assert EvaluatorOperationV2(operation) is expected


def test_evaluator_operation_rejects_protocol_13_repair_role() -> None:
    with pytest.raises(ValueError):
        EvaluatorOperationV2("repair_ledger")


@pytest.mark.parametrize(
    ("concern_type", "target", "correction", "valid"),
    [
        ("omission", None, valid_semantic_proposal_payload(), True),
        ("incorrect_statement", "P0001", valid_semantic_proposal_payload(), True),
        ("incorrect_evidence", "P0001", valid_semantic_proposal_payload(), True),
        ("incorrect_relationship", "P0001", valid_semantic_proposal_payload(), True),
        ("ambiguity", "P0001", None, True),
        ("omission", "P0001", valid_semantic_proposal_payload(), False),
        ("omission", None, None, False),
        ("incorrect_statement", None, valid_semantic_proposal_payload(), False),
        ("incorrect_statement", "P0001", None, False),
        ("ambiguity", None, None, False),
    ],
)
def test_audit_concern_enforces_target_and_correction_boundary(
    concern_type: str,
    target: str | None,
    correction: dict[str, object] | None,
    valid: bool,
) -> None:
    payload = {
        "target_proposal_ref": target,
        "concern_type": concern_type,
        "passages": [{"source_id": "rule-1", "quote": "must file the notice"}],
        "explanation": "The cited text changes the legal obligation.",
        "correction": correction,
    }

    if valid:
        concern = AuditConcernV2.model_validate(payload)
        assert concern.concern_type == concern_type
    else:
        with pytest.raises(ValidationError):
            AuditConcernV2.model_validate(payload)


def test_grade_response_requires_each_engine_requirement_once() -> None:
    response = GradeResponseV2.model_validate(
        {
            "schema_version": "2.0",
            "anonymous_label": "A",
            "baseline_fingerprint": "a" * 64,
            "requirement_grades": [
                {
                    "requirement_id": "REQ-0001",
                    "disposition": "met",
                    "report_passages": ["The report states the filing obligation."],
                    "rationale": "The report expressly covers the requirement.",
                }
            ],
            "unsupported_assertions": [],
        },
        context={"requirement_ids": {"REQ-0001"}},
    )

    assert response.requirement_grades[0].requirement_id == "REQ-0001"


def test_grade_response_rejects_duplicate_requirement_references() -> None:
    payload = {
        "schema_version": "2.0",
        "anonymous_label": "A",
        "baseline_fingerprint": "a" * 64,
        "requirement_grades": [
            {
                "requirement_id": "REQ-0001",
                "disposition": "met",
                "report_passages": ["The report states the filing obligation."],
                "rationale": "The report expressly covers the requirement.",
            },
            {
                "requirement_id": "REQ-0001",
                "disposition": "not_met",
                "report_passages": [],
                "rationale": "The report does not cover the requirement.",
            },
        ],
        "unsupported_assertions": [],
    }

    with pytest.raises(ValidationError, match="unique"):
        GradeResponseV2.model_validate(payload)


def test_evaluator_request_has_only_the_allowlisted_wire_fields() -> None:
    request = EvaluatorRequestV2.model_validate(
        {
            "schema_version": "2.0",
            "operation": "source_review",
            "request_fingerprint": "b" * 64,
            "system_instructions": "Review the frozen sources only.",
            "json_schema": {"type": "object"},
            "payload": {"sources": []},
            "safe_metadata": {"protocol": "2.0"},
        }
    )

    assert set(request.model_dump(mode="json")) == {
        "schema_version",
        "operation",
        "request_fingerprint",
        "system_instructions",
        "json_schema",
        "payload",
        "safe_metadata",
    }
    with pytest.raises(ValidationError):
        EvaluatorRequestV2.model_validate(
            {**request.model_dump(mode="json"), "response_id": "not-allowed"}
        )


def test_source_audit_has_no_hidden_repair_or_replacement_inventory() -> None:
    audit = SourceAuditV2.model_validate(
        {"schema_version": "2.0", "concerns": []}, context={"proposal_refs": set()}
    )

    assert audit.concerns == []
    with pytest.raises(ValidationError):
        SourceAuditV2.model_validate(
            {
                "schema_version": "2.0",
                "concerns": [],
                "replacement_ledger": [],
            },
            context={"proposal_refs": set()},
        )


def test_source_audit_allows_one_known_target_among_unconcerned_proposals() -> None:
    payload = {
        "schema_version": "2.0",
        "concerns": [
            {
                "target_proposal_ref": "P0001",
                "concern_type": "incorrect_evidence",
                "passages": [{"source_id": "rule-1", "quote": "must file the notice"}],
                "explanation": "The cited passage is incomplete.",
                "correction": valid_semantic_proposal_payload(),
            }
        ],
    }

    audit = SourceAuditV2.model_validate(payload, context={"proposal_refs": {"P0001", "P0002"}})

    assert audit.concerns[0].target_proposal_ref == "P0001"


def test_unsupported_assertion_preserves_declared_importance() -> None:
    response = GradeResponseV2.model_validate(
        {
            "schema_version": "2.0",
            "anonymous_label": "B",
            "baseline_fingerprint": "c" * 64,
            "requirement_grades": [],
            "unsupported_assertions": [
                {
                    "report_passage": "A penalty always applies.",
                    "importance": "material",
                    "rationale": "The baseline contains no such universal penalty.",
                }
            ],
        },
        context={"requirement_ids": set()},
    )

    assert response.unsupported_assertions[0].importance is ImportanceV2.MATERIAL


def request_payload(**updates: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": "2.0",
        "operation": "source_review",
        "request_fingerprint": "d" * 64,
        "system_instructions": "Review frozen sources only.",
        "json_schema": {"type": "object"},
        "payload": {"sources": []},
        "safe_metadata": {"protocol": "2.0"},
    }
    payload.update(updates)
    return payload


def response_payload(**updates: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": "2.0",
        "operation": "source_review",
        "request_fingerprint": "d" * 64,
        "provider_name": "fixture",
        "model_name": "fixture-model",
        "judge_isolation": "scripted_fixture",
        "payload": {"proposals": []},
    }
    payload.update(updates)
    return payload


def versioned_response_payload(
    schema_version: str, operation: str, payload: object
) -> dict[str, object]:
    return {
        "schema_version": schema_version,
        "operation": operation,
        "request_fingerprint": "d" * 64,
        "provider_name": "fixture",
        "model_name": "fixture-model",
        "judge_isolation": "scripted_fixture",
        "payload": payload,
    }


@pytest.mark.parametrize(
    ("model", "schema_version", "operation"),
    [
        (EvaluatorResponseV2, "2.0", "source_review"),
        (EvaluatorResponseV21, "2.1", "source_review"),
        (EvaluatorResponseV22, "2.2", "source_review_fragment"),
    ],
)
@pytest.mark.parametrize(
    ("invalid_payload", "message"),
    [
        ({"value": object()}, "response payload contains a non-JSON value"),
        ({1: "value"}, "response payload contains a non-string object key"),
        ({"value": float("nan")}, "response payload contains a non-finite number"),
    ],
)
def test_shared_payload_validators_retain_invalid_json_taxonomy(
    model: type[EvaluatorResponseV2],
    schema_version: str,
    operation: str,
    invalid_payload: object,
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        model.model_validate(
            versioned_response_payload(schema_version, operation, invalid_payload)
        )


@pytest.mark.parametrize(
    ("model", "schema_version", "operation"),
    [
        (EvaluatorResponseV2, "2.0", "source_review"),
        (EvaluatorResponseV21, "2.1", "source_review"),
        (EvaluatorResponseV22, "2.2", "source_review_fragment"),
    ],
)
@pytest.mark.parametrize("fault_type", [TypeError, ValueError, RecursionError])
def test_shared_payload_validators_expose_post_structure_canonicalizer_fault(
    monkeypatch: pytest.MonkeyPatch,
    model: type[EvaluatorResponseV2],
    schema_version: str,
    operation: str,
    fault_type: type[Exception],
) -> None:
    def fail_canonicalizer(value: object) -> bytes:
        del value
        raise fault_type("injected canonicalizer fault")

    monkeypatch.setattr(models, "canonical_json_bytes", fail_canonicalizer)

    with pytest.raises(RuntimeError, match="canonical JSON"):
        model.model_validate(
            versioned_response_payload(
                schema_version, operation, {"ordinary": ["bounded", "json"]}
            )
        )


def test_request_rejects_cyclic_raw_json_payload_with_stable_error() -> None:
    cyclic: dict[str, object] = {}
    cyclic["self"] = cyclic

    with pytest.raises(ValidationError, match="request payload contains a container cycle"):
        EvaluatorRequestV2.model_validate(request_payload(payload=cyclic))


def test_response_rejects_deep_raw_json_payload_with_stable_error() -> None:
    nested: object = []
    for _ in range(64):
        nested = [nested]

    with pytest.raises(ValidationError, match="response payload exceeds the nesting-depth limit"):
        EvaluatorResponseV2.model_validate(response_payload(payload={"nested": nested}))


def test_request_rejects_oversized_raw_json_payload_with_stable_error() -> None:
    oversized = "x" * (16 * 1024 * 1024)

    with pytest.raises(ValidationError, match="request payload exceeds the size limit"):
        EvaluatorRequestV2.model_validate(request_payload(payload={"text": oversized}))


def test_request_fingerprint_rejects_model_construct_cycle() -> None:
    cyclic: dict[str, object] = {}
    cyclic["self"] = cyclic
    bypass = EvaluatorRequestV2.model_construct(**request_payload(payload=cyclic))

    with pytest.raises(ValueError, match="request payload contains a container cycle"):
        evaluator_request_fingerprint(bypass)


def test_response_validation_rejects_model_construct_cycle() -> None:
    cyclic: dict[str, object] = {}
    cyclic["self"] = cyclic
    bypass = EvaluatorResponseV2.model_construct(**response_payload(payload=cyclic))

    with pytest.raises(ValueError, match="response payload contains a container cycle"):
        validate_evaluator_response_v2(bypass)


def test_repeated_acyclic_request_child_is_valid_and_fingerprintable() -> None:
    child = {"source_id": "rule-1"}
    request = EvaluatorRequestV2.model_validate(
        request_payload(payload={"first": child, "second": child})
    )

    assert len(evaluator_request_fingerprint(request)) == 64


def test_source_review_bounds_proposals() -> None:
    payload = valid_semantic_proposal_payload()

    with pytest.raises(ValidationError, match="at most 128"):
        SourceReviewV2.model_validate(
            {"schema_version": "2.0", "proposals": [payload] * 129}
        )


def test_source_audit_requires_engine_reference_context() -> None:
    payload = {
        "schema_version": "2.0",
        "concerns": [
            {
                "target_proposal_ref": "P9999",
                "concern_type": "incorrect_statement",
                "passages": [{"source_id": "rule-1", "quote": "must file the notice"}],
                "explanation": "The statement exceeds the source text.",
                "correction": valid_semantic_proposal_payload(),
            }
        ],
    }

    with pytest.raises(ValidationError, match="validated engine proposal references"):
        SourceAuditV2.model_validate(payload)
    with pytest.raises(ValidationError, match="engine-issued proposal references"):
        SourceAuditV2.model_validate(payload, context={"proposal_refs": {"P0001"}})


def test_empty_source_audit_also_requires_engine_reference_context() -> None:
    with pytest.raises(ValidationError, match="validated engine proposal references"):
        SourceAuditV2.model_validate({"schema_version": "2.0", "concerns": []})


def test_grade_response_requires_engine_reference_context() -> None:
    payload = {
        "schema_version": "2.0",
        "anonymous_label": "A",
        "baseline_fingerprint": "a" * 64,
        "requirement_grades": [
            {
                "requirement_id": "REQ-9999",
                "disposition": "not_met",
                "report_passages": [],
                "rationale": "The report omits the requirement.",
            }
        ],
        "unsupported_assertions": [],
    }

    with pytest.raises(ValidationError, match="validated engine requirement references"):
        GradeResponseV2.model_validate(payload)
    with pytest.raises(ValidationError, match="engine-issued requirement exactly once"):
        GradeResponseV2.model_validate(payload, context={"requirement_ids": {"REQ-0001"}})


def test_reference_bound_helpers_validate_role_outputs_against_engine_artifacts() -> None:
    indexed = (
        IndexedProposalV2(
            proposal_ref="P0001",
            proposal=SemanticProposal.model_validate(valid_semantic_proposal_payload()),
        ),
    )
    audit = SourceAuditV2.validate_for_indexed_proposals(
        {
            "schema_version": "2.0",
            "concerns": [
                {
                    "target_proposal_ref": "P0001",
                    "concern_type": "incorrect_statement",
                    "passages": [{"source_id": "rule-1", "quote": "must file the notice"}],
                    "explanation": "The statement needs correction.",
                    "correction": valid_semantic_proposal_payload(),
                }
            ],
        },
        indexed,
    )
    baseline = CanonicalBaselineV2(
        case_fingerprint="a" * 64,
        requirements=[
            CanonicalRequirementV2(
                requirement_id="REQ-0001",
                canonical_order=0,
                statement="A covered operator must file the notice.",
                kind="obligation",
                importance="critical",
                passages=[
                    ResolvedPassageV2(
                        source_id="rule-1",
                        quote="must file the notice",
                        start_char=0,
                        end_char=20,
                    )
                ],
                confidence="clear",
                rationale="The source uses mandatory language.",
            )
        ],
        baseline_fingerprint="b" * 64,
    )
    grades = GradeResponseV2.validate_for_baseline(
        {
            "schema_version": "2.0",
            "anonymous_label": "A",
            "baseline_fingerprint": "b" * 64,
            "requirement_grades": [
                {
                    "requirement_id": "REQ-0001",
                    "disposition": "met",
                    "report_passages": ["The report covers notice filing."],
                    "rationale": "The filing requirement is stated.",
                }
            ],
            "unsupported_assertions": [],
        },
        baseline,
    )

    assert audit.concerns[0].target_proposal_ref == "P0001"
    assert grades.requirement_grades[0].requirement_id == "REQ-0001"


@pytest.mark.parametrize(
    ("phase", "terminal_status"),
    [
        ("completed", "inconclusive"),
        ("inconclusive", "completed"),
    ],
)
def test_terminal_phase_and_status_must_match_exactly(
    phase: str, terminal_status: str
) -> None:
    state_payload = {
        "schema_version": "2.0",
        "case_fingerprint": "a" * 64,
        "phase": phase,
        "terminal_status": terminal_status,
    }
    manifest_payload = {
        "protocol_version": "2.0",
        "case_fingerprint": "a" * 64,
        "case_envelope_hash": "b" * 64,
        "build_fingerprint": "c" * 64,
        "rubric_fingerprint": "d" * 64,
        "compiler_version": "semantic-compiler-v2",
        "phase": phase,
        "terminal_status": terminal_status,
        "calls": [],
        "artifacts": [],
        "manifest_fingerprint": "e" * 64,
    }

    with pytest.raises(ValidationError, match="must match"):
        EvaluationRunStateV2.model_validate(state_payload)
    with pytest.raises(ValidationError, match="must match"):
        EvaluationManifestV2.model_validate(manifest_payload)


def test_v2_models_are_frozen_against_assignment_bypass() -> None:
    request = EvaluatorRequestV2.model_validate(request_payload())

    with pytest.raises(ValidationError, match="frozen"):
        request.payload = {"tampered": True}  # type: ignore[misc]


def test_source_referee_requires_exact_engine_dispute_context() -> None:
    payload = {
        "schema_version": "2.0",
        "decisions": [
            {
                "dispute_id": "D9999",
                "decision": "accept_reviewer",
                "passages": [{"source_id": "rule-1", "quote": "must file the notice"}],
                "rationale": "The reviewer's statement tracks the source.",
            }
        ],
    }

    with pytest.raises(ValidationError, match="validated engine dispute references"):
        SourceRefereeResponseV2.model_validate(payload)
    with pytest.raises(ValidationError, match="engine-issued dispute exactly once"):
        SourceRefereeResponseV2.model_validate(payload, context={"dispute_ids": {"D0001"}})


def test_source_referee_helper_binds_to_material_disputes() -> None:
    concern = AuditConcernV2.model_validate(
        {
            "target_proposal_ref": "P0001",
            "concern_type": "incorrect_statement",
            "passages": [{"source_id": "rule-1", "quote": "must file the notice"}],
            "explanation": "The statement needs correction.",
            "correction": valid_semantic_proposal_payload(),
        }
    )
    disputes = (
        MaterialDisputeV2(
            dispute_id="D0001",
            target_proposal_ref="P0001",
            reviewer_proposal=SemanticProposal.model_validate(valid_semantic_proposal_payload()),
            audit_concern=concern,
        ),
    )

    response = SourceRefereeResponseV2.validate_for_disputes(
        {
            "schema_version": "2.0",
            "decisions": [
                {
                    "dispute_id": "D0001",
                    "decision": "accept_reviewer",
                    "passages": [{"source_id": "rule-1", "quote": "must file the notice"}],
                    "rationale": "The reviewer is supported by the source.",
                }
            ],
        },
        disputes,
    )

    assert response.decisions[0].dispute_id == "D0001"


def test_grade_helper_rejects_a_stale_baseline_fingerprint() -> None:
    baseline = CanonicalBaselineV2(
        case_fingerprint="a" * 64,
        requirements=[],
        baseline_fingerprint="b" * 64,
    )
    payload = {
        "schema_version": "2.0",
        "anonymous_label": "A",
        "baseline_fingerprint": "c" * 64,
        "requirement_grades": [],
        "unsupported_assertions": [],
    }

    with pytest.raises(ValidationError, match="baseline fingerprint"):
        GradeResponseV2.validate_for_baseline(payload, baseline)


def test_request_and_response_snapshot_nested_json_without_mutating_the_input() -> None:
    request_raw = request_payload(payload={"nested": {"value": "original"}})
    response_raw = response_payload(payload={"nested": {"value": "original"}})
    request = EvaluatorRequestV2.model_validate(request_raw)
    response = EvaluatorResponseV2.model_validate(response_raw)
    request_raw["payload"]["nested"]["value"] = "input-tampered"  # type: ignore[index]
    response_raw["payload"]["nested"]["value"] = "input-tampered"  # type: ignore[index]

    assert request.payload["nested"]["value"] == "original"
    assert response.payload["nested"]["value"] == "original"
    with pytest.raises(TypeError):
        request.payload["nested"]["value"] = "artifact-tampered"  # type: ignore[index]
    with pytest.raises(TypeError):
        response.payload["nested"]["value"] = "artifact-tampered"  # type: ignore[index]


def test_source_review_proposals_are_deeply_immutable() -> None:
    review = SourceReviewV2.model_validate(
        {"schema_version": "2.0", "proposals": [valid_semantic_proposal_payload()]}
    )

    with pytest.raises(TypeError):
        review.proposals.append(review.proposals[0])


def test_response_validation_has_raw_and_validated_instance_parity() -> None:
    raw = response_payload(payload={"nested": {"value": "original"}})
    validated = EvaluatorResponseV2.model_validate(raw)
    raw_result = validate_evaluator_response_v2(raw)
    instance_result = validate_evaluator_response_v2(validated)

    assert raw_result == instance_result == validated
    assert canonical_json_bytes(raw_result.model_dump(mode="json")) == canonical_json_bytes(
        instance_result.model_dump(mode="json")
    )
    with pytest.raises(TypeError):
        instance_result.payload["nested"]["value"] = "tampered"  # type: ignore[index]


def canonical_requirement(identifier: str, order: int) -> CanonicalRequirementV2:
    return CanonicalRequirementV2(
        requirement_id=identifier,
        canonical_order=order,
        statement=f"Requirement {order + 1}.",
        kind="obligation",
        importance="critical",
        passages=[
            ResolvedPassageV2(
                source_id="rule-1",
                quote=f"requirement {order + 1}",
                start_char=order * 20,
                end_char=(order * 20) + 13,
            )
        ],
        confidence="clear",
        rationale="The source uses mandatory language.",
    )


def test_canonical_baseline_preserves_empty_relationship_compatibility() -> None:
    baseline = CanonicalBaselineV2(
        case_fingerprint="a" * 64,
        requirements=[canonical_requirement("REQ-0001", 0)],
        baseline_fingerprint="b" * 64,
    )

    assert baseline.relationships == ()
    assert baseline.model_dump(mode="json")["relationships"] == []

    relationship = CanonicalRelationshipV2(
        relationship_id="REL-0001",
        relationship="depends_on",
        source_requirement_id="REQ-0002",
        target_requirement_id="REQ-0001",
    )
    graph_baseline = CanonicalBaselineV2(
        case_fingerprint="a" * 64,
        requirements=[
            canonical_requirement("REQ-0001", 0),
            canonical_requirement("REQ-0002", 1),
        ],
        relationships=(relationship,),
        baseline_fingerprint="b" * 64,
    )

    assert graph_baseline.relationships == (relationship,)
    assert graph_baseline.model_dump(mode="json")["relationships"] == [
        relationship.model_dump(mode="json")
    ]


@pytest.mark.parametrize(
    ("relationships", "message"),
    [
        (
            [
                {
                    "relationship_id": "REL-0002",
                    "relationship": "depends_on",
                    "source_requirement_id": "REQ-0002",
                    "target_requirement_id": "REQ-0001",
                }
            ],
            "contiguous",
        ),
        (
            [
                {
                    "relationship_id": "REL-0001",
                    "relationship": "depends_on",
                    "source_requirement_id": "REQ-9999",
                    "target_requirement_id": "REQ-0001",
                }
            ],
            "must identify baseline requirements",
        ),
        (
            [
                {
                    "relationship_id": "REL-0001",
                    "relationship": "depends_on",
                    "source_requirement_id": "REQ-0002",
                    "target_requirement_id": "REQ-0001",
                },
                {
                    "relationship_id": "REL-0002",
                    "relationship": "depends_on",
                    "source_requirement_id": "REQ-0002",
                    "target_requirement_id": "REQ-0001",
                },
            ],
            "semantic edges must be unique",
        ),
    ],
)
def test_canonical_baseline_rejects_invalid_relationship_graph(
    relationships: list[dict[str, str]], message: str
) -> None:
    with pytest.raises(ValidationError, match=message):
        CanonicalBaselineV2.model_validate(
            {
                "case_fingerprint": "a" * 64,
                "requirements": [
                    canonical_requirement("REQ-0001", 0).model_dump(mode="json"),
                    canonical_requirement("REQ-0002", 1).model_dump(mode="json"),
                ],
                "relationships": relationships,
                "baseline_fingerprint": "b" * 64,
            }
        )


def grade_snapshot() -> GradeResponseV2:
    return GradeResponseV2.model_validate(
        {
            "schema_version": "2.0",
            "anonymous_label": "A",
            "baseline_fingerprint": "b" * 64,
            "requirement_grades": [],
            "unsupported_assertions": [],
        },
        context={"requirement_ids": set()},
    )


def grade_baseline() -> CanonicalBaselineV2:
    return CanonicalBaselineV2(
        case_fingerprint="a" * 64,
        requirements=[],
        baseline_fingerprint="b" * 64,
    )


def test_reconciled_grade_is_an_aggregate_with_two_frozen_grade_snapshots() -> None:
    snapshot = grade_snapshot()
    snapshots = [snapshot, snapshot]
    reconciliation = ReconciledGradeV2.validate_for_baseline(
        {
            "anonymous_label": "A",
            "disposition": "PASS",
            "reason_codes": [],
            "grader_responses": snapshots,
            "requirement_reconciliations": [
                ReconciledRequirementGradeV2(
                    requirement_id="REQ-0001",
                    disposition="met",
                    report_passages=["The report covers the requirement."],
                    rationale="Both graders agree.",
                    graders_agree=True,
                )
            ],
            "unsupported_assertions": [],
        },
        grade_baseline(),
    )

    assert reconciliation.disposition.value == "PASS"
    assert len(reconciliation.grader_responses) == 2
    assert snapshots == [snapshot, snapshot]
    with pytest.raises((AttributeError, TypeError)):
        reconciliation.grader_responses.append(snapshot)


def test_reconciled_grade_rejects_wrong_snapshot_labels_and_cardinality() -> None:
    snapshot = grade_snapshot()
    wrong_label = GradeResponseV2.model_validate(
        {**snapshot.model_dump(mode="json"), "anonymous_label": "B"},
        context={"requirement_ids": set()},
    )
    payload = {
        "anonymous_label": "A",
        "disposition": "PASS",
        "reason_codes": [],
        "grader_responses": [snapshot.model_dump(mode="json")],
        "requirement_reconciliations": [],
        "unsupported_assertions": [],
    }

    with pytest.raises(ValidationError):
        ReconciledGradeV2.validate_for_baseline(payload, grade_baseline())
    with pytest.raises(ValidationError, match="must use the aggregate label"):
        ReconciledGradeV2.validate_for_baseline(
            {
                **payload,
                "grader_responses": [
                    snapshot.model_dump(mode="json"),
                    wrong_label.model_dump(mode="json"),
                ],
            },
            grade_baseline(),
        )


def test_reconciled_grade_revalidates_raw_and_constructed_grade_snapshots() -> None:
    invalid_raw = {
        "schema_version": "2.0",
        "anonymous_label": "A",
        "baseline_fingerprint": "b" * 64,
        "requirement_grades": [
            {
                "requirement_id": "REQ-9999",
                "disposition": "not_met",
                "report_passages": [],
                "rationale": "The report omits the invented requirement.",
            }
        ],
        "unsupported_assertions": [],
    }
    payload = {
        "anonymous_label": "A",
        "disposition": "INCONCLUSIVE",
        "grader_responses": [invalid_raw, invalid_raw],
    }
    constructed = GradeResponseV2.model_construct(**invalid_raw)

    with pytest.raises(ValidationError, match="engine-issued requirement"):
        ReconciledGradeV2.model_validate(
            payload,
            context={"requirement_ids": set(), "baseline_fingerprint": "b" * 64},
        )
    with pytest.raises(ValidationError, match="engine-issued requirement"):
        ReconciledGradeV2.model_validate(
            {**payload, "grader_responses": [constructed, constructed]},
            context={"requirement_ids": set(), "baseline_fingerprint": "b" * 64},
        )


def test_reconciled_grade_requires_baseline_context_for_typed_snapshots() -> None:
    snapshot = grade_snapshot()

    with pytest.raises(ValidationError, match="validated engine baseline"):
        ReconciledGradeV2(
            anonymous_label="A",
            disposition="PASS",
            grader_responses=(snapshot, snapshot),
        )


def test_report_result_consumes_one_aggregate_reconciliation() -> None:
    snapshot = grade_snapshot()
    reconciliation = ReconciledGradeV2.validate_for_baseline(
        {
            "anonymous_label": "A",
            "disposition": "PASS",
            "reason_codes": ("thresholds_met",),
            "grader_responses": (snapshot, snapshot),
        },
        grade_baseline(),
    )
    result = ReportResultV2(
        anonymous_label="A",
        absolute_disposition="PASS",
        reconciliation=reconciliation,
        critical_recall=1.0,
        weighted_coverage=1.0,
        reason_codes=("thresholds_met",),
        result_fingerprint="d" * 64,
    )

    assert result.reconciliation is reconciliation
    assert result.absolute_disposition is reconciliation.disposition


@pytest.mark.parametrize(
    ("disposition", "winner"),
    [
        ("candidate_win", "A"),
        ("comparator_win", "B"),
        ("tie", None),
        ("neither", None),
        ("inconclusive", None),
    ],
)
def test_comparison_uses_candidate_comparator_values_and_winner_invariants(
    disposition: str, winner: str | None
) -> None:
    result = ComparisonResultV2(
        disposition=disposition,
        winner_label=winner,
        rationale="The deterministic comparison rule applies.",
    )

    assert result.disposition.value == disposition


def test_comparison_rejects_candidate_comparator_winner_mismatch() -> None:
    with pytest.raises(ValidationError, match="candidate_win"):
        ComparisonResultV2(
            disposition=ComparisonDispositionV2.CANDIDATE_WIN,
            winner_label="B",
            rationale="The deterministic comparison rule applies.",
        )
