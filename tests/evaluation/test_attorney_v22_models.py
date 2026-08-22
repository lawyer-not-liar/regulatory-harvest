"""Protocol 2.2 model-boundary tests."""

from __future__ import annotations

import warnings
from collections.abc import Iterator, Mapping
from datetime import date, datetime, time
from enum import StrEnum

import pytest
from pydantic import ValidationError

import regulatory_harvest.evaluation as evaluation
from regulatory_harvest.evaluation import attorney_v22_models as models
from regulatory_harvest.evaluation.attorney_v2_models import (
    CanonicalRequirementV2,
    ComparisonDispositionV2,
    MaterialDisputeV2,
    RequirementGradeV2,
    ResolvedPassageV2,
    SemanticPassage,
    SemanticProposal,
)
from regulatory_harvest.evaluation.attorney_v22_models import (
    AcceptedRefereeFragmentV22,
    AuditConcernV22,
    ComparisonResultV22,
    ContestedGradeFragmentV22,
    ContestedRequirementV22,
    EvaluationCallRecordV22,
    EvaluationManifestV22,
    EvaluationPhaseV22,
    EvaluationRunStateV22,
    EvaluationTerminalStatusV22,
    EvaluatorOperationV22,
    EvaluatorRequestV22,
    EvaluatorResponseV22,
    GraderAggregateV22,
    IndexedAuditConcernV22,
    IndexedProposalV22,
    OrdinaryGradeBatchV22,
    OrdinaryGradeFragmentV22,
    RefereeAggregateV22,
    RefereeDecisionV22,
    RefereeDisputeV22,
    RefereeEvidenceV22,
    RubricV22,
    SensitivityRecordV22,
    SourceAuditAggregateV22,
    SourceAuditFragmentV22,
    SourceReviewFragmentV22,
    _wire_snapshot,
    validate_evaluator_response_v22,
)

HASH = "a" * 64


class _ForeignString(StrEnum):
    PROVIDER = "provider"
    EXPLANATION = "The filing obligation was omitted."


class _HostileDict(dict[str, object]):
    def items(self) -> object:
        warnings.warn("HOSTILE-DICT-SECRET", stacklevel=1)
        raise RuntimeError("HOSTILE-DICT-SECRET")


class _HostileList(list[object]):
    def __iter__(self) -> object:
        warnings.warn("HOSTILE-LIST-SECRET", stacklevel=1)
        raise RuntimeError("HOSTILE-LIST-SECRET")


class _HostileTuple(tuple[object, ...]):
    def __iter__(self) -> object:
        warnings.warn("HOSTILE-TUPLE-SECRET", stacklevel=1)
        raise RuntimeError("HOSTILE-TUPLE-SECRET")


class _HostileKey:
    def __init__(self) -> None:
        self.armed = False

    def __hash__(self) -> int:
        if self.armed:
            warnings.warn("HOSTILE-KEY-SECRET", stacklevel=1)
            raise RuntimeError("HOSTILE-KEY-SECRET")
        return object.__hash__(self)


class _LazyMapping(Mapping[str, object]):
    def __init__(self, size: int) -> None:
        self.size = size
        self.callbacks = 0

    def __getitem__(self, key: str) -> object:
        self.callbacks += 1
        return key

    def __iter__(self) -> Iterator[str]:
        self.callbacks += 1
        return (str(index) for index in range(self.size))

    def __len__(self) -> int:
        self.callbacks += 1
        return self.size


class _HostileMapping(Mapping[str, object]):
    def __init__(self) -> None:
        self.callbacks = 0

    def _fail(self) -> None:
        self.callbacks += 1
        warnings.warn("HOSTILE-MAPPING-SECRET", stacklevel=1)
        raise RuntimeError("HOSTILE-MAPPING-SECRET")

    def __getitem__(self, key: str) -> object:
        self._fail()

    def __iter__(self) -> Iterator[str]:
        self._fail()

    def __len__(self) -> int:
        self._fail()


class _ListMappingHybrid(list[object], Mapping[str, object]):
    def __init__(self) -> None:
        list.__init__(self, ["safe-list-value"])
        self.callbacks = 0

    def _fail(self) -> None:
        self.callbacks += 1
        warnings.warn("HYBRID-MAPPING-SECRET", stacklevel=1)
        raise RuntimeError("HYBRID-MAPPING-SECRET")

    def __getitem__(self, key: object) -> object:
        self._fail()

    def __iter__(self) -> Iterator[str]:
        self._fail()

    def __len__(self) -> int:
        self._fail()


def test_rubric_v22_requires_exact_native_keys_and_strict_scalar_wire_types() -> None:
    valid = {
        "version": "attorney-eval-v2.2",
        "importance_weights": {"critical": 3, "material": 2, "supporting": 1},
        "critical_recall_floor": 1.0,
        "weighted_coverage_floor": 0.9,
        "material_unsupported_assertions_allowed": 1,
    }
    assert RubricV22.model_validate(valid).material_unsupported_assertions_allowed == 1
    for update in (
        {"importance_weights": {"critical": 3, "material": 2}},
        {"importance_weights": {"critical": True, "material": 2, "supporting": 1}},
        {"importance_weights": {"critical": -1, "material": 2, "supporting": 1}},
        {"critical_recall_floor": "1.0"},
        {"weighted_coverage_floor": True},
        {"material_unsupported_assertions_allowed": True},
        {"version": "attorney-eval-v2.1"},
    ):
        with pytest.raises(ValidationError):
            RubricV22.model_validate({**valid, **update})


def _proposal() -> dict[str, object]:
    return {
        "statement": "A covered operator must file a notice.",
        "kind": "obligation",
        "importance": "critical",
        "passages": [{"source_id": "rule-1", "quote": "must file a notice"}],
        "dependency": None,
        "confidence": "clear",
        "rationale": "The source uses mandatory language.",
    }


def _concern() -> dict[str, object]:
    return {
        "target_proposal_ref": None,
        "concern_type": "omission",
        "passages": [{"source_id": "rule-1", "quote": "must file a notice"}],
        "explanation": "The filing obligation was omitted.",
        "correction": _proposal(),
    }


def _call(*, state: str = "pending") -> dict[str, object]:
    values: dict[str, object] = {
        "call_id": "call-1",
        "operation": "source_review_fragment",
        "state": state,
        "attempt": 1,
        "request_artifact_path": "requests/call-1.json",
        "request_fingerprint": HASH,
        "fragment_ordinal": 1,
    }
    if state == "accepted":
        values.update(
            {
                "response_artifact_path": "responses/call-1.json",
                "response_fingerprint": "b" * 64,
                "provider_name": "provider",
                "model_name": "model",
                "judge_isolation": "fresh_context",
            }
        )
    return values


def _manifest(*, calls: list[dict[str, object]] | None = None) -> dict[str, object]:
    return {
        "protocol_version": "2.2",
        "case_fingerprint": HASH,
        "case_envelope_hash": "b" * 64,
        "build_fingerprint": "c" * 64,
        "rubric_fingerprint": "d" * 64,
        "compiler_contract_fingerprint": "e" * 64,
        "compiler_version": "semantic-compiler-v2.2",
        "phase": "source_review",
        "calls": calls if calls is not None else [_call()],
        "artifacts": [],
        "referee_disputes": [],
        "ordinary_grade_batches": [],
        "manifest_fingerprint": "f" * 64,
    }


def test_v22_operation_enum_is_exact() -> None:
    assert {item.value for item in EvaluatorOperationV22} == {
        "source_review_fragment",
        "source_audit_fragment",
        "source_referee_fragment",
        "ordinary_grade_fragment",
        "contested_grade_fragment",
    }


def test_v22_has_no_mechanical_terminal() -> None:
    assert {item.value for item in EvaluationTerminalStatusV22} == {
        "COMPLETED",
        "INCONCLUSIVE",
    }


def test_sensitivity_record_preserves_outcome_determinative_contested_ids() -> None:
    record = SensitivityRecordV22(
        anonymous_label="A",
        baseline_fingerprint="a" * 64,
        reconciliation_fingerprint="b" * 64,
        absolute_disposition="INCONCLUSIVE",
        reason_codes=("OUTCOME_SENSITIVE_BASELINE_DISPUTE",),
        outcome_determinative_contested_ids=("CONT-0001",),
        sensitivity_fingerprint="c" * 64,
    )

    assert record.outcome_determinative_contested_ids == ("CONT-0001",)


def test_v22_comparison_allows_blinding_to_place_the_comparator_at_a() -> None:
    comparison = ComparisonResultV22(
        disposition=ComparisonDispositionV2.COMPARATOR_WIN,
        winner_label="A",
        candidate_label="B",
        comparator_label="A",
        rationale="Only the comparator report passed the rubric.",
    )

    assert comparison.winner_label == comparison.comparator_label == "A"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("candidate_label", "A"),
        ("winner_label", "B"),
        ("disposition", "candidate_win"),
        ("rationale", "Only the candidate report passed the rubric."),
    ],
)
def test_v22_comparison_rejects_tampered_role_winner_disposition_and_rationale(
    field: str, value: str
) -> None:
    raw: dict[str, object] = {
        "disposition": "comparator_win",
        "winner_label": "A",
        "candidate_label": "B",
        "comparator_label": "A",
        "rationale": "Only the comparator report passed the rubric.",
    }
    raw[field] = value

    with pytest.raises(ValidationError):
        ComparisonResultV22.model_validate(raw)


def test_source_fragments_are_limited_to_five_new_items() -> None:
    with pytest.raises(ValidationError, match="at most 5"):
        SourceReviewFragmentV22(
            proposals=tuple(_proposal() for _ in range(6)), review_complete=True
        )
    with pytest.raises(ValidationError, match="at most 5"):
        SourceAuditFragmentV22(concerns=tuple(_concern() for _ in range(6)), audit_complete=True)


@pytest.mark.parametrize(
    ("model", "values"),
    [
        (SourceReviewFragmentV22, {"proposals": (), "review_complete": False}),
        (SourceAuditFragmentV22, {"concerns": (), "audit_complete": False}),
    ],
)
def test_nonfinal_source_fragments_require_new_items(
    model: type[SourceReviewFragmentV22] | type[SourceAuditFragmentV22],
    values: dict[str, object],
) -> None:
    with pytest.raises(ValidationError, match="nonfinal"):
        model.model_validate(values)


def test_final_source_fragments_may_be_empty() -> None:
    assert SourceReviewFragmentV22(proposals=(), review_complete=True).proposals == ()
    assert SourceAuditFragmentV22(concerns=(), audit_complete=True).concerns == ()


def test_source_audit_fragment_rebinds_targets_to_the_compiled_inventory() -> None:
    inventory = (IndexedProposalV22(proposal_ref="P0001", proposal=_proposal()),)
    concern = {
        **_concern(),
        "target_proposal_ref": "P0002",
        "concern_type": "ambiguity",
        "correction": None,
    }
    with pytest.raises(ValueError, match="engine-issued"):
        SourceAuditFragmentV22.validate_for_indexed_proposals(
            {"concerns": [concern], "audit_complete": True}, inventory
        )


def test_manifest_retains_at_most_one_pending_call_and_contract_binding() -> None:
    manifest = EvaluationManifestV22.model_validate(_manifest())
    assert manifest.compiler_contract_fingerprint == "e" * 64
    with pytest.raises(ValidationError, match="at most one pending"):
        EvaluationManifestV22.model_validate(
            _manifest(calls=[_call(), {**_call(), "call_id": "call-2"}])
        )
    with pytest.raises(ValidationError, match="compiler_contract_fingerprint"):
        EvaluationManifestV22.model_validate(
            {
                key: value
                for key, value in _manifest().items()
                if key != "compiler_contract_fingerprint"
            }
        )


def test_terminal_grammar_rejects_mechanical_terminal_and_pending_terminal() -> None:
    with pytest.raises(ValidationError):
        EvaluationRunStateV22.model_validate(
            {
                "schema_version": "2.2",
                "case_fingerprint": HASH,
                "phase": EvaluationPhaseV22.INCONCLUSIVE,
                "terminal_status": "INCONCLUSIVE_MECHANICAL",
            }
        )
    with pytest.raises(ValidationError, match="terminal manifests"):
        EvaluationManifestV22.model_validate(
            {
                **_manifest(),
                "phase": "completed",
                "terminal_status": "COMPLETED",
            }
        )


def test_request_and_response_deep_freeze_nested_payloads() -> None:
    request = EvaluatorRequestV22(
        operation="source_review_fragment",
        request_fingerprint=HASH,
        system_instructions="Review the supplied sources.",
        json_schema={"type": "object"},
        payload={"sources": [{"source_id": "rule-1"}]},
    )
    response = EvaluatorResponseV22(
        operation="source_review_fragment",
        request_fingerprint=HASH,
        provider_name="provider",
        model_name="model",
        judge_isolation="fresh_context",
        payload={"proposals": [_proposal()]},
    )
    with pytest.raises(TypeError):
        request.payload["sources"] = []  # type: ignore[index]
    with pytest.raises(TypeError):
        request.payload["sources"][0]["source_id"] = "other"  # type: ignore[index]
    with pytest.raises(TypeError):
        response.payload["proposals"].append({})  # type: ignore[index,union-attr]


@pytest.mark.parametrize(
    "model,payload",
    [
        (
            SourceReviewFragmentV22,
            {"schema_version": "2.1", "proposals": [], "review_complete": True},
        ),
        (
            EvaluatorRequestV22,
            {
                "schema_version": "2.1",
                "operation": "source_review_fragment",
                "request_fingerprint": HASH,
                "system_instructions": "Review sources.",
                "json_schema": {},
                "payload": {},
            },
        ),
    ],
)
def test_v22_rejects_serialized_21_wrappers(
    model: type[object], payload: dict[str, object]
) -> None:
    with pytest.raises(ValidationError):
        model.model_validate(payload)  # type: ignore[attr-defined]


def test_v22_audit_concern_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError, match="extra"):
        AuditConcernV22.model_validate({**_concern(), "schema_version": "2.1"})


def test_call_record_allows_only_one_initial_or_clarification_attempt() -> None:
    assert EvaluationCallRecordV22.model_validate(_call()).attempt == 1
    with pytest.raises(ValidationError):
        EvaluationCallRecordV22.model_validate({**_call(), "attempt": 3})


def _constructed_referee_fragment(dispute_id: str = "D0001") -> AcceptedRefereeFragmentV22:
    return AcceptedRefereeFragmentV22.model_construct(
        case_fingerprint=HASH,
        dispute_id=dispute_id,
        dispute_fingerprint="b" * 64,
        decision=RefereeDecisionV22.model_construct(
            schema_version="2.2",
            decision="accept_reviewer",
            unresolved_reason=None,
            evidence_refs=("EVID-0001",),
            rationale="The evidence supports the review.",
        ),
        response_fingerprint="c" * 64,
    )


def _constructed_ordinary_fragment(
    *, batch_ref: str = "GB-A-1-0001", requirement_count: int = 1
) -> OrdinaryGradeFragmentV22:
    return OrdinaryGradeFragmentV22.model_construct(
        schema_version="2.2",
        anonymous_label="A",
        grader_lane=1,
        batch_ref=batch_ref,
        baseline_fingerprint=HASH,
        report_fingerprint="b" * 64,
        requirement_grades=tuple(
            RequirementGradeV2(
                requirement_id=f"REQ-{index:04d}",
                disposition="met",
                report_passages=["The report addresses the requirement."],
                rationale="The report addresses the requirement.",
            )
            for index in range(1, requirement_count + 1)
        ),
        rationale="The batch is assessed.",
    )


def test_sealed_source_audit_revalidates_raw_typed_and_constructed_targets() -> None:
    inventory = (IndexedProposalV22(proposal_ref="P0001", proposal=_proposal()),)
    invalid = SourceAuditAggregateV22.model_construct(
        concerns=(
            {
                "concern_ref": "C0001",
                "concern": {
                    **_concern(),
                    "target_proposal_ref": "P9999",
                    "concern_type": "ambiguity",
                    "correction": None,
                },
            },
        ),
        fragment_fingerprints=(HASH,),
        aggregate_fingerprint="b" * 64,
    )
    for value in (invalid.__dict__, invalid, invalid):
        with pytest.raises(ValueError, match="engine-issued"):
            SourceAuditAggregateV22.validate_for_indexed_proposals(value, inventory)


def test_referee_and_grade_bindings_restore_unissued_constructed_references() -> None:
    with pytest.raises(ValueError, match="dispute"):
        RefereeAggregateV22.validate_for_disputes(
            {"fragments": [_constructed_referee_fragment("D9999")], "aggregate_fingerprint": HASH},
            (),
        )

    batch = OrdinaryGradeBatchV22(batch_ref="GB-A-1-0001", requirement_ids=("REQ-0001",))
    with pytest.raises(ValueError, match="batch"):
        OrdinaryGradeFragmentV22.validate_for_batch(
            _constructed_ordinary_fragment(batch_ref="GB-A-1-0002"), batch
        )

    requirement = ContestedRequirementV22.model_construct(contested_requirement_id="CONT-0001")
    with pytest.raises(ValueError, match="contested"):
        ContestedGradeFragmentV22.validate_for_requirement(
            ContestedGradeFragmentV22.model_construct(contested_requirement_id="CONT-9999"),
            requirement,
        )


def test_referee_and_grader_aggregates_enforce_global_fragment_and_item_ceilings() -> None:
    with pytest.raises(ValidationError, match="at most 128"):
        RefereeAggregateV22(
            fragments=tuple(_constructed_referee_fragment() for _ in range(129)),
            aggregate_fingerprint=HASH,
        )
    with pytest.raises(ValidationError, match="at most 128"):
        GraderAggregateV22(
            anonymous_label="A",
            grader_lane=1,
            baseline_fingerprint=HASH,
            report_fingerprint="b" * 64,
            ordinary_fragments=tuple(_constructed_ordinary_fragment() for _ in range(129)),
            contested_fragments=(),
            aggregate_fingerprint="c" * 64,
        )
    with pytest.raises(ValueError, match="640"):
        GraderAggregateV22.validate_for_inventories(
            GraderAggregateV22.model_construct(
                anonymous_label="A",
                grader_lane=1,
                baseline_fingerprint=HASH,
                report_fingerprint="b" * 64,
                ordinary_fragments=(_constructed_ordinary_fragment(requirement_count=641),),
                contested_fragments=(),
                aggregate_fingerprint="c" * 64,
            ),
            (),
            (),
        )


def test_package_exports_complete_v22_public_model_surface() -> None:
    required = {
        "PROTOCOL_V22",
        "AcceptedRefereeFragmentV22",
        "AcceptedSourceAuditFragmentV22",
        "AcceptedSourceReviewFragmentV22",
        "AmbiguityDispositionV22",
        "AuditConcernV22",
        "CanonicalBaselineV22",
        "ComparisonResultV22",
        "ContestedAlternativeGradeV22",
        "ContestedDispositionV22",
        "ContestedGradeFragmentV22",
        "ContestedGradeFragmentRequestPayloadV22",
        "ContestedRequirementV22",
        "EvaluationCallRecordV22",
        "EvaluationManifestV22",
        "EvaluationPhaseV22",
        "EvaluationResultV22",
        "EvaluationRunStateV22",
        "EvaluationTerminalStatusV22",
        "EvaluatorOperationV22",
        "EvaluatorRequestV22",
        "EvaluatorResponseV22",
        "GraderAggregateV22",
        "IndexedAuditConcernV22",
        "IndexedProposalV22",
        "OrdinaryGradeBatchV22",
        "OrdinaryGradeFragmentV22",
        "ReconciledGradeV22",
        "RefereeAggregateV22",
        "RefereeDecisionV22",
        "RefereeDisputeV22",
        "RefereeEvidenceV22",
        "RefereeFragmentRequestPayloadV22",
        "RefereeUnresolvedReasonV22",
        "ReportResultV22",
        "RubricV22",
        "SensitivityRecordV22",
        "SourceAuditAggregateV22",
        "SourceAuditFragmentV22",
        "SourceReviewAggregateV22",
        "SourceReviewFragmentV22",
        "build_comparison_result_v22",
    }
    assert required <= set(evaluation.__all__)
    assert all(hasattr(evaluation, name) for name in required)


def test_sealed_boundaries_rebuild_constructed_earlier_protocol_models() -> None:
    invalid_passage = SemanticPassage.model_construct(source_id=" ", quote=" ")
    invalid_audit = SourceAuditAggregateV22.model_construct(
        concerns=(
            IndexedAuditConcernV22.model_construct(
                concern_ref="C0001",
                concern=AuditConcernV22.model_construct(
                    target_proposal_ref=None,
                    concern_type="omission",
                    passages=(invalid_passage,),
                    explanation="The review omitted a requirement.",
                    correction=SemanticProposal.model_validate(_proposal()),
                ),
            ),
        ),
        fragment_fingerprints=(HASH,),
        aggregate_fingerprint="b" * 64,
    )
    with pytest.raises(ValueError, match=r"invalid|blank"):
        SourceAuditAggregateV22.validate_for_indexed_proposals(invalid_audit, ())

    invalid_evidence = RefereeEvidenceV22.model_construct(
        evidence_ref="EVID-0001",
        passage=ResolvedPassageV2.model_construct(
            source_id=" ", quote=" ", start_char=-1, end_char=0
        ),
    )
    invalid_dispute = RefereeDisputeV22.model_construct(
        case_fingerprint=HASH,
        dispute_fingerprint="b" * 64,
        dispute_id="D0001",
        material_dispute=MaterialDisputeV2.model_construct(dispute_id="D0001"),
        evidence=(invalid_evidence,),
    )
    with pytest.raises(ValueError, match=r"invalid|blank"):
        RefereeAggregateV22.validate_for_disputes(
            {
                "fragments": [_constructed_referee_fragment()],
                "aggregate_fingerprint": "c" * 64,
            },
            (invalid_dispute,),
        )

    invalid_grade = RequirementGradeV2.model_construct(
        requirement_id="REQ-0001",
        disposition="bogus",
        report_passages=[" "],
        rationale=" ",
        omission=None,
    )
    invalid_ordinary = _constructed_ordinary_fragment()
    object.__setattr__(invalid_ordinary, "requirement_grades", (invalid_grade,))
    batch = OrdinaryGradeBatchV22(batch_ref="GB-A-1-0001", requirement_ids=("REQ-0001",))
    with pytest.raises(ValueError, match=r"invalid|Input should"):
        OrdinaryGradeFragmentV22.validate_for_batch(invalid_ordinary, batch)

    invalid_requirement = ContestedRequirementV22.model_construct(
        contested_requirement_id="CONT-0001",
        reviewer_alternative=CanonicalRequirementV2.model_construct(requirement_id="REQ-0001"),
        auditor_alternative=None,
        unresolved_reason="SOURCE_GAP",
        rationale="The record does not resolve the disagreement.",
        referee_fragment_fingerprint=HASH,
    )
    valid_alternative = {
        "disposition": "met",
        "report_passages": ["The report addresses the requirement."],
        "rationale": "The report addresses the requirement.",
    }
    valid_contested = ContestedGradeFragmentV22.model_construct(
        schema_version="2.2",
        anonymous_label="A",
        grader_lane=1,
        contested_requirement_id="CONT-0001",
        baseline_fingerprint=HASH,
        report_fingerprint="b" * 64,
        reviewer_alternative_grade=valid_alternative,
        auditor_alternative_grade=valid_alternative,
        ambiguity_disposition="acknowledged",
        rationale="The report handles the ambiguity.",
    )
    with pytest.raises(ValueError, match=r"invalid|Field required"):
        ContestedGradeFragmentV22.validate_for_requirement(valid_contested, invalid_requirement)


@pytest.mark.parametrize(
    ("boundary", "value_factory", "context_factory"),
    [
        (
            AuditConcernV22.validate_for_indexed_proposals,
            lambda: AuditConcernV22.model_construct(
                **{**_concern(), "concern_type": "not-a-concern-type"}
            ),
            lambda: (IndexedProposalV22(proposal_ref="P0001", proposal=_proposal()),),
        ),
        (
            SourceAuditFragmentV22.validate_for_indexed_proposals,
            lambda: SourceAuditFragmentV22.model_construct(
                schema_version="2.2",
                concerns=(
                    AuditConcernV22.model_construct(
                        **{**_concern(), "concern_type": "not-a-concern-type"}
                    ),
                ),
                audit_complete=True,
            ),
            lambda: (IndexedProposalV22(proposal_ref="P0001", proposal=_proposal()),),
        ),
        (
            SourceAuditAggregateV22.validate_for_indexed_proposals,
            lambda: SourceAuditAggregateV22.model_construct(
                concerns=(
                    IndexedAuditConcernV22.model_construct(
                        concern_ref="C0001",
                        concern=AuditConcernV22.model_construct(
                            **{**_concern(), "concern_type": "not-a-concern-type"}
                        ),
                    ),
                ),
                fragment_fingerprints=(HASH,),
                aggregate_fingerprint="b" * 64,
            ),
            lambda: (IndexedProposalV22(proposal_ref="P0001", proposal=_proposal()),),
        ),
    ],
    ids=("audit-concern", "audit-fragment", "audit-aggregate"),
)
def test_contextual_audit_boundaries_reject_constructed_invalid_enums(
    boundary: object,
    value_factory: object,
    context_factory: object,
) -> None:
    with pytest.raises(ValueError, match="invalid"):
        boundary(value_factory(), context_factory())  # type: ignore[operator]


def test_contextual_boundaries_reject_cycles_without_exposing_values() -> None:
    cycle: list[object] = []
    cycle.append(cycle)
    fragment = SourceAuditFragmentV22.model_construct(
        schema_version="2.2", concerns=cycle, audit_complete=True
    )
    batch = OrdinaryGradeBatchV22(batch_ref="GB-A-1-0001", requirement_ids=("REQ-0001",))
    ordinary = OrdinaryGradeFragmentV22.model_construct(
        schema_version="2.2",
        anonymous_label="A",
        grader_lane=1,
        batch_ref="GB-A-1-0001",
        baseline_fingerprint=HASH,
        report_fingerprint="b" * 64,
        requirement_grades=cycle,
        rationale="cycle-secret-must-not-leak",
    )

    for call in (
        lambda: SourceAuditFragmentV22.validate_for_indexed_proposals(fragment, ()),
        lambda: OrdinaryGradeFragmentV22.validate_for_batch(ordinary, batch),
    ):
        with pytest.raises((ValueError, ValidationError, RecursionError)) as error:
            call()
        assert "cycle-secret-must-not-leak" not in str(error.value)


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("provider_name", _ForeignString.PROVIDER),
        ("provider_name", date(2026, 8, 19)),
        ("provider_name", time(12, 30)),
        ("provider_name", datetime(2026, 8, 19, 12, 30)),
    ],
    ids=("foreign-enum", "date", "time", "datetime"),
)
def test_response_names_preserve_and_reject_nonstring_scalar_provenance(
    field_name: str, value: object
) -> None:
    response = EvaluatorResponseV22(
        operation="source_review_fragment",
        request_fingerprint=HASH,
        provider_name="provider",
        model_name="model",
        judge_isolation="fresh_context",
        payload={"review_complete": True},
    )
    forged = response.model_construct(**{**response.__dict__, field_name: value})

    with pytest.raises(ValueError, match="evaluator response"):
        validate_evaluator_response_v22(forged)


@pytest.mark.parametrize(
    "invalid",
    [
        {"invalid": "response"},
        EvaluatorResponseV22.model_construct(payload={"invalid": True}),
    ],
    ids=("raw-envelope", "bypass-constructed-model"),
)
def test_response_validation_uses_its_typed_controlled_input_boundary(
    invalid: object,
) -> None:
    """Only invalid supplied response values receive the dedicated safe exception."""
    with pytest.raises(models._EvaluatorResponseValidationErrorV22):
        validate_evaluator_response_v22(invalid)


@pytest.mark.parametrize("fault_type", [TypeError, ValueError, RuntimeError])
@pytest.mark.parametrize("boundary", ["canonicalizer", "model-dump", "same-wire"])
def test_response_validation_does_not_type_engine_faults_as_external_input(
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
    fault_type: type[Exception],
) -> None:
    """Trusted canonicalization, serialization, and comparison faults propagate."""
    response = EvaluatorResponseV22(
        operation="source_review_fragment",
        request_fingerprint=HASH,
        provider_name="provider",
        model_name="model",
        judge_isolation="fresh_context",
        payload={"review_complete": True},
    )

    def fail(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise fault_type(f"injected {boundary} fault")

    if boundary == "canonicalizer":
        monkeypatch.setattr(models, "canonical_json_bytes", fail)
    elif boundary == "model-dump":
        monkeypatch.setattr(models.EvaluatorResponseV22, "model_dump", fail)
    else:
        monkeypatch.setattr(models, "_same_wire_value", fail)

    with pytest.raises(fault_type, match=f"injected {boundary} fault"):
        validate_evaluator_response_v22(response)


def test_contextual_rationale_rejects_unrelated_string_enum() -> None:
    concern = AuditConcernV22.model_construct(
        **{**_concern(), "explanation": _ForeignString.EXPLANATION}
    )
    inventory = (IndexedProposalV22(proposal_ref="P0001", proposal=_proposal()),)

    with pytest.raises(ValueError, match="audit concern"):
        AuditConcernV22.validate_for_indexed_proposals(concern, inventory)


@pytest.mark.parametrize(
    "payload",
    [
        _HostileDict({"safe": "value"}),
        {"safe": _HostileList(["value"])},
        {"safe": _HostileTuple(("value",))},
    ],
    ids=("dict-items", "list-iter", "tuple-iter"),
)
def test_raw_snapshot_bypasses_hostile_container_overrides_without_warnings(
    payload: dict[str, object],
) -> None:
    response = EvaluatorResponseV22.model_construct(
        schema_version="2.2",
        operation="source_review_fragment",
        request_fingerprint=HASH,
        provider_name="provider",
        model_name="model",
        judge_isolation="fresh_context",
        payload=payload,
    )

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        checked = validate_evaluator_response_v22(response)
    assert checked.payload["safe"] == "value" or checked.payload["safe"] == ["value"]


def test_raw_snapshot_contains_hostile_ordinary_exceptions_without_value_leakage() -> None:
    hostile_key = _HostileKey()
    payload = {hostile_key: "secret-value-must-not-leak"}
    hostile_key.armed = True
    response = EvaluatorResponseV22.model_construct(
        schema_version="2.2",
        operation="source_review_fragment",
        request_fingerprint=HASH,
        provider_name="provider",
        model_name="model",
        judge_isolation="fresh_context",
        payload=payload,
    )

    with warnings.catch_warnings(), pytest.raises(
        ValueError, match=r"^evaluator response is invalid$"
    ) as error:
        warnings.simplefilter("error")
        validate_evaluator_response_v22(response)
    assert error.value.__cause__ is None
    assert "HOSTILE-KEY-SECRET" not in str(error.value)
    assert "secret-value-must-not-leak" not in str(error.value)


@pytest.mark.parametrize(
    "mapping",
    [_LazyMapping(100_001), _HostileMapping()],
    ids=("lazy-wide", "hostile"),
)
def test_raw_snapshot_rejects_arbitrary_nested_mappings_without_callbacks(
    mapping: _LazyMapping | _HostileMapping,
) -> None:
    response = EvaluatorResponseV22.model_construct(
        schema_version="2.2",
        operation="source_review_fragment",
        request_fingerprint=HASH,
        provider_name="provider",
        model_name="model",
        judge_isolation="fresh_context",
        payload={"untrusted": mapping},
    )

    with warnings.catch_warnings(), pytest.raises(
        ValueError, match=r"^model wire snapshot is invalid$"
    ) as snapshot_error:
        warnings.simplefilter("error")
        _wire_snapshot({"untrusted": mapping})
    assert snapshot_error.value.__cause__ is None

    with warnings.catch_warnings(), pytest.raises(
        ValueError, match=r"^evaluator response is invalid$"
    ) as error:
        warnings.simplefilter("error")
        validate_evaluator_response_v22(response)
    assert mapping.callbacks == 0
    assert error.value.__cause__ is None
    assert "HOSTILE-MAPPING-SECRET" not in str(error.value)


def test_raw_snapshot_rejects_list_mapping_hybrid_before_sequence_traversal() -> None:
    hybrid = _ListMappingHybrid()
    response = EvaluatorResponseV22.model_construct(
        schema_version="2.2",
        operation="source_review_fragment",
        request_fingerprint=HASH,
        provider_name="provider",
        model_name="model",
        judge_isolation="fresh_context",
        payload={"untrusted": hybrid},
    )

    with warnings.catch_warnings(), pytest.raises(
        ValueError, match=r"^model wire snapshot is invalid$"
    ) as snapshot_error:
        warnings.simplefilter("error")
        _wire_snapshot({"untrusted": hybrid})
    assert snapshot_error.value.__cause__ is None

    with warnings.catch_warnings(), pytest.raises(
        ValueError, match=r"^evaluator response is invalid$"
    ) as error:
        warnings.simplefilter("error")
        validate_evaluator_response_v22(response)
    assert hybrid.callbacks == 0
    assert error.value.__cause__ is None
    assert "HYBRID-MAPPING-SECRET" not in str(error.value)


@pytest.mark.parametrize(
    "payload",
    [
        {"wide": [None] * 100_001},
        {"oversized": "x" * (16 * 1024 * 1024 + 1)},
    ],
    ids=("node-limit", "byte-limit"),
)
def test_raw_snapshot_rejects_oversized_trees_with_generic_errors(
    payload: dict[str, object],
) -> None:
    response = EvaluatorResponseV22.model_construct(
        schema_version="2.2",
        operation="source_review_fragment",
        request_fingerprint=HASH,
        provider_name="provider",
        model_name="model",
        judge_isolation="fresh_context",
        payload=payload,
    )

    with pytest.raises(ValueError, match=r"^evaluator response is invalid$") as error:
        validate_evaluator_response_v22(response)
    assert error.value.__cause__ is None


def test_raw_snapshot_rejects_overdeep_trees_before_recursive_validation() -> None:
    payload: object = "leaf"
    for _ in range(65):
        payload = [payload]
    response = EvaluatorResponseV22.model_construct(
        schema_version="2.2",
        operation="source_review_fragment",
        request_fingerprint=HASH,
        provider_name="provider",
        model_name="model",
        judge_isolation="fresh_context",
        payload={"deep": payload},
    )

    with pytest.raises(ValueError, match=r"^evaluator response is invalid$") as error:
        validate_evaluator_response_v22(response)
    assert error.value.__cause__ is None
