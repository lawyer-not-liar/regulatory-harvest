# ruff: noqa: E501
"""Strict contracts for fragmented evaluator protocol 2.1.

Protocol 2.1 preserves the semantic source-review and source-audit payloads of
Protocol 2.0 while making referee and grader judgments independently sealable.
This module deliberately contains value contracts only; deterministic request,
compilation, storage, and workflow behavior belongs in later modules.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import Field, ValidationInfo, field_validator, model_validator

from .attorney_models import ArtifactRecord
from .attorney_v2_models import (
    AbsoluteDispositionV2,
    AuditConcernV2,
    CanonicalRelationshipV2,
    CanonicalRequirementV2,
    ComparisonResultV2,
    ImportanceV2,
    IndexedProposalV2,
    MaterialDisputeV2,
    RequirementGradeV2,
    ResolvedPassageV2,
    SemanticProposal,
    V2StrictModel,
    _nonblank,
    _optional_nonblank,
    _validate_json_object,
    _validated_json_snapshot,
)

PROTOCOL_V21: Literal["2.1"] = "2.1"
_HASH_PATTERN = r"^[0-9a-f]{64}$"
_DISPUTE_REF_PATTERN = r"^D[0-9]{4}$"
_REQUIREMENT_REF_PATTERN = r"^REQ-[0-9]{4}$"
_EVIDENCE_REF_PATTERN = r"^EVID-[0-9]{4}$"
_BATCH_REF_PATTERN = r"^GB-[AB]-[12]-[0-9]{4}$"
_MAX_ROLE_RESPONSE_ITEMS = 128

Hash = Annotated[str, Field(pattern=_HASH_PATTERN, strict=True)]
DisputeRef = Annotated[str, Field(pattern=_DISPUTE_REF_PATTERN, strict=True)]
RequirementRef = Annotated[str, Field(pattern=_REQUIREMENT_REF_PATTERN, strict=True)]
EvidenceRef = Annotated[str, Field(pattern=_EVIDENCE_REF_PATTERN, strict=True)]
BatchRef = Annotated[str, Field(pattern=_BATCH_REF_PATTERN, strict=True)]


class V21StrictModel(V2StrictModel):
    """Protocol-2.1 contracts share the strict immutable V2 behavior."""


class EvaluatorOperationV21(StrEnum):
    SOURCE_REVIEW = "source_review"
    SOURCE_AUDIT = "source_audit"
    SOURCE_REFEREE_FRAGMENT = "source_referee_fragment"
    ORDINARY_GRADE_FRAGMENT = "ordinary_grade_fragment"
    CONTESTED_GRADE_FRAGMENT = "contested_grade_fragment"


class EvaluationPhaseV21(StrEnum):
    CREATED = "created"
    SOURCE_REVIEW = "source_review"
    SOURCE_AUDIT = "source_audit"
    SOURCE_REFEREE = "source_referee"
    BASELINE_SEALED = "baseline_sealed"
    ORDINARY_GRADING = "ordinary_grading"
    CONTESTED_GRADING = "contested_grading"
    AGGREGATE = "aggregate"
    COMPLETED = "completed"
    INCONCLUSIVE = "inconclusive"
    INCONCLUSIVE_MECHANICAL = "inconclusive_mechanical"


class EvaluationTerminalStatusV21(StrEnum):
    COMPLETED = "COMPLETED"
    INCONCLUSIVE = "INCONCLUSIVE"
    INCONCLUSIVE_MECHANICAL = "INCONCLUSIVE_MECHANICAL"


class RefereeUnresolvedReasonV21(StrEnum):
    SOURCE_AMBIGUITY = "SOURCE_AMBIGUITY"
    SOURCE_CONFLICT = "SOURCE_CONFLICT"
    SOURCE_GAP = "SOURCE_GAP"
    BOTH_POSITIONS_UNSUPPORTED = "BOTH_POSITIONS_UNSUPPORTED"


class ContestedDispositionV21(StrEnum):
    MET = "met"
    PARTIALLY_MET = "partially_met"
    NOT_MET = "not_met"
    UNCERTAIN = "uncertain"


class AmbiguityDispositionV21(StrEnum):
    ACKNOWLEDGED = "acknowledged"
    OVERSTATED = "overstated"
    OMITTED = "omitted"
    UNCERTAIN = "uncertain"


_BATCH_REF = re.compile(r"^GB-([AB])-([12])-[0-9]{4}$")
_OUTCOME_SENSITIVE_REASON = "OUTCOME_SENSITIVE_BASELINE_DISPUTE"
_BASELINE_INSUFFICIENT_REASON = "BASELINE_EVIDENCE_INSUFFICIENT"


def _validate_batch_binding(batch_ref: str, anonymous_label: str, grader_lane: int) -> None:
    match = _BATCH_REF.fullmatch(batch_ref)
    if match is None or match.group(1) != anonymous_label or int(match.group(2)) != grader_lane:
        raise ValueError("batch reference must bind its anonymous label and grader lane")


class SourceReviewV21(V21StrictModel):
    """Protocol-2.1 wrapper with the unchanged source-review semantics."""

    schema_version: Literal["2.1"] = PROTOCOL_V21
    proposals: list[SemanticProposal] = Field(max_length=_MAX_ROLE_RESPONSE_ITEMS)


class SourceAuditV21(V21StrictModel):
    """Protocol-2.1 wrapper with the unchanged source-audit semantics."""

    schema_version: Literal["2.1"] = PROTOCOL_V21
    concerns: list[AuditConcernV2] = Field(max_length=_MAX_ROLE_RESPONSE_ITEMS)

    @model_validator(mode="after")
    def validate_known_targets(self, info: ValidationInfo) -> Self:
        targets = {
            concern.target_proposal_ref
            for concern in self.concerns
            if concern.target_proposal_ref is not None
        }
        context = info.context
        if context is None or "proposal_refs" not in context:
            raise ValueError("validated engine proposal references are required")
        expected = context["proposal_refs"]
        if not isinstance(expected, (set, frozenset, list, tuple)) or any(
            type(item) is not str for item in expected
        ):
            raise ValueError("proposal_refs validation context is invalid")
        if not targets.issubset(set(expected)):
            raise ValueError("audit concerns must target only engine-issued proposal references")
        return self

    @classmethod
    def validate_for_indexed_proposals(
        cls, value: object, indexed: tuple[IndexedProposalV2, ...]
    ) -> Self:
        proposal_refs = [proposal.proposal_ref for proposal in indexed]
        if len(proposal_refs) != len(set(proposal_refs)):
            raise ValueError("indexed proposals must use unique proposal references")
        return cls.model_validate(value, context={"proposal_refs": set(proposal_refs)})


class EvaluatorRequestV21(V21StrictModel):
    schema_version: Literal["2.1"] = PROTOCOL_V21
    operation: EvaluatorOperationV21
    request_fingerprint: Hash
    system_instructions: str = Field(strict=True)
    json_schema: dict[str, object]
    payload: dict[str, object]
    safe_metadata: dict[str, str] = Field(default_factory=dict)

    _validate_instructions = field_validator("system_instructions")(_nonblank)

    @field_validator("json_schema", mode="before")
    @classmethod
    def validate_json_schema_tree(cls, value: object) -> object:
        return _validate_json_object(value, location="request json_schema")

    @field_validator("payload", mode="before")
    @classmethod
    def validate_payload_tree(cls, value: object) -> object:
        return _validate_json_object(value, location="request payload")

    @model_validator(mode="after")
    def validate_operation_payload(self) -> Self:
        if self.operation is EvaluatorOperationV21.SOURCE_REFEREE_FRAGMENT:
            RefereeFragmentRequestPayloadV21.model_validate(self.payload)
        elif self.operation is EvaluatorOperationV21.CONTESTED_GRADE_FRAGMENT:
            ContestedGradeFragmentRequestPayloadV21.model_validate(self.payload)
        return self


class EvaluatorResponseV21(V21StrictModel):
    schema_version: Literal["2.1"] = PROTOCOL_V21
    operation: EvaluatorOperationV21
    request_fingerprint: Hash
    provider_name: str = Field(strict=True)
    model_name: str = Field(strict=True)
    judge_isolation: Literal["fresh_context", "scripted_fixture"]
    payload: dict[str, object]

    _validate_names = field_validator("provider_name", "model_name")(_nonblank)

    @field_validator("payload", mode="before")
    @classmethod
    def validate_payload_tree(cls, value: object) -> object:
        return _validate_json_object(value, location="response payload")

    @model_validator(mode="after")
    def validate_fragment_lane_shape(self) -> Self:
        if self.operation in {
            EvaluatorOperationV21.ORDINARY_GRADE_FRAGMENT,
            EvaluatorOperationV21.CONTESTED_GRADE_FRAGMENT,
        }:
            lane = self.payload.get("grader_lane")
            if type(lane) is not int or lane not in {1, 2}:
                raise ValueError("grade-fragment payload must use grader lane 1 or 2")
        return self


class RefereeEvidenceV21(V21StrictModel):
    evidence_ref: EvidenceRef
    passage: ResolvedPassageV2


class RefereeDisputeV21(V21StrictModel):
    """One controller-issued material dispute and its resolved evidence packet."""

    case_fingerprint: Hash
    dispute_fingerprint: Hash
    dispute_id: DisputeRef
    material_dispute: MaterialDisputeV2
    evidence: tuple[RefereeEvidenceV21, ...] = Field(
        min_length=1, max_length=_MAX_ROLE_RESPONSE_ITEMS
    )

    @model_validator(mode="after")
    def validate_dispute_binding(self) -> Self:
        if self.material_dispute.dispute_id != self.dispute_id:
            raise ValueError("referee dispute ID must match the material dispute")
        refs = [item.evidence_ref for item in self.evidence]
        if len(refs) != len(set(refs)):
            raise ValueError("referee evidence references must be unique")
        return self


class RefereeFragmentRequestPayloadV21(V21StrictModel):
    """The complete controller packet for one and only one referee decision."""

    material_disputes: tuple[RefereeDisputeV21, ...] = Field(min_length=1, max_length=1)


def _referee_decision_wire_snapshot(value: object) -> object:
    """Return raw decision fields so model_construct values are revalidated."""
    if isinstance(value, RefereeDecisionV21):
        return dict(value.__dict__)
    return value


def _accepted_referee_fragment_wire_snapshot(value: object) -> object:
    """Return complete raw fragment fields so nested models cannot retain bypasses."""
    if isinstance(value, AcceptedRefereeFragmentV21):
        payload = dict(value.__dict__)
        payload["decision"] = _referee_decision_wire_snapshot(value.decision)
        return payload
    return value


class RefereeDecisionV21(V21StrictModel):
    schema_version: Literal["2.1"] = PROTOCOL_V21
    decision: Literal["accept_reviewer", "accept_auditor", "unresolved"]
    unresolved_reason: RefereeUnresolvedReasonV21 | None = None
    evidence_refs: tuple[EvidenceRef, ...] = Field(
        min_length=1, max_length=_MAX_ROLE_RESPONSE_ITEMS
    )
    rationale: str = Field(strict=True)

    _validate_rationale = field_validator("rationale")(_nonblank)

    @model_validator(mode="after")
    def validate_decision(self, info: ValidationInfo) -> Self:
        if self.decision == "unresolved":
            if self.unresolved_reason is None:
                raise ValueError("unresolved decisions require one unresolved reason")
        elif self.unresolved_reason is not None:
            raise ValueError("accepted decisions must not include an unresolved reason")
        if len(self.evidence_refs) != len(set(self.evidence_refs)):
            raise ValueError("referee evidence references must be unique")
        context = info.context
        if context is None or "evidence_refs" not in context:
            raise ValueError("validated controller evidence inventory is required")
        allowed = context["evidence_refs"]
        if not isinstance(allowed, (set, frozenset, list, tuple)) or any(
            type(item) is not str for item in allowed
        ):
            raise ValueError("evidence_refs validation context is invalid")
        if not set(self.evidence_refs).issubset(set(allowed)):
            raise ValueError("referee evidence references must be controller-issued")
        return self

    @classmethod
    def validate_for_dispute(cls, value: object, dispute: RefereeDisputeV21) -> Self:
        try:
            return cls.model_validate(
                _referee_decision_wire_snapshot(value),
                context={"evidence_refs": {item.evidence_ref for item in dispute.evidence}},
            )
        except RecursionError as error:
            raise ValueError("referee decision is invalid") from error


class AcceptedRefereeFragmentV21(V21StrictModel):
    case_fingerprint: Hash
    dispute_id: DisputeRef
    dispute_fingerprint: Hash
    decision: RefereeDecisionV21
    response_fingerprint: Hash

    @model_validator(mode="after")
    def validate_dispute_binding(self, info: ValidationInfo) -> Self:
        context = info.context
        if context is None or "referee_dispute" not in context:
            raise ValueError("validated controller referee dispute is required")
        dispute = context["referee_dispute"]
        if not isinstance(dispute, RefereeDisputeV21):
            raise ValueError("referee_dispute validation context is invalid")
        if self.dispute_id != dispute.dispute_id:
            raise ValueError("accepted referee fragment must bind its supplied dispute")
        if self.case_fingerprint != dispute.case_fingerprint:
            raise ValueError("accepted referee fragment must bind its case fingerprint")
        if self.dispute_fingerprint != dispute.dispute_fingerprint:
            raise ValueError("accepted referee fragment must bind its dispute fingerprint")
        allowed = {item.evidence_ref for item in dispute.evidence}
        if not set(self.decision.evidence_refs).issubset(allowed):
            raise ValueError("accepted referee fragment must bind controller evidence")
        return self

    @classmethod
    def validate_for_dispute(cls, value: object, dispute: RefereeDisputeV21) -> Self:
        try:
            checked_dispute = RefereeDisputeV21.model_validate(dict(dispute.__dict__))
            return cls.model_validate(
                _accepted_referee_fragment_wire_snapshot(value),
                context={
                    "referee_dispute": checked_dispute,
                    "evidence_refs": {
                        item.evidence_ref for item in checked_dispute.evidence
                    },
                },
            )
        except RecursionError as error:
            raise ValueError("accepted referee fragment is invalid") from error


class RefereeAggregateV21(V21StrictModel):
    fragments: tuple[AcceptedRefereeFragmentV21, ...]
    aggregate_fingerprint: Hash

    @field_validator("fragments")
    @classmethod
    def validate_unique_disputes(
        cls, values: tuple[AcceptedRefereeFragmentV21, ...]
    ) -> tuple[AcceptedRefereeFragmentV21, ...]:
        ids = [item.dispute_id for item in values]
        if len(ids) != len(set(ids)):
            raise ValueError("accepted referee fragments must use unique dispute IDs")
        return values

    @classmethod
    def validate_for_disputes(
        cls, value: object, disputes: tuple[RefereeDisputeV21, ...]
    ) -> Self:
        """Rebind every aggregate fragment to its ordered controller dispute."""
        if isinstance(value, cls):
            payload = dict(value.__dict__)
        elif type(value) is dict:
            payload = value
        else:
            raise ValueError("referee aggregate must be an object")
        if set(payload) != {"fragments", "aggregate_fingerprint"}:
            raise ValueError("referee aggregate must contain only its strict wire fields")
        raw_fragments = payload["fragments"]
        if not isinstance(raw_fragments, (list, tuple)):
            raise ValueError("referee aggregate fragments must be an ordered sequence")
        if not isinstance(disputes, tuple) or any(
            not isinstance(dispute, RefereeDisputeV21) for dispute in disputes
        ):
            raise ValueError("referee dispute inventory is invalid")
        try:
            checked_disputes = tuple(
                RefereeDisputeV21.model_validate(dict(dispute.__dict__))
                for dispute in disputes
            )
        except (RecursionError, TypeError) as error:
            raise ValueError("referee dispute inventory is invalid") from error
        dispute_ids = [dispute.dispute_id for dispute in checked_disputes]
        if len(dispute_ids) != len(set(dispute_ids)):
            raise ValueError("referee dispute inventory must use unique dispute IDs")
        if len(raw_fragments) != len(checked_disputes):
            raise ValueError("referee aggregate fragment coverage does not match disputes")
        fingerprint = payload["aggregate_fingerprint"]
        if type(fingerprint) is not str or re.fullmatch(_HASH_PATTERN, fingerprint) is None:
            raise ValueError("referee aggregate fingerprint is invalid")
        fragments = tuple(
            AcceptedRefereeFragmentV21.validate_for_dispute(fragment, dispute)
            for fragment, dispute in zip(raw_fragments, checked_disputes, strict=True)
        )
        return cls.model_construct(fragments=fragments, aggregate_fingerprint=fingerprint)


class ContestedRequirementV21(V21StrictModel):
    contested_requirement_id: str = Field(strict=True)
    reviewer_alternative: CanonicalRequirementV2 | None = None
    auditor_alternative: CanonicalRequirementV2 | None = None
    unresolved_reason: RefereeUnresolvedReasonV21
    rationale: str = Field(strict=True)
    referee_fragment_fingerprint: Hash

    _validate_id = field_validator("contested_requirement_id")(_nonblank)
    _validate_rationale = field_validator("rationale")(_nonblank)

    @model_validator(mode="after")
    def validate_alternatives(self) -> Self:
        if self.reviewer_alternative is None and self.auditor_alternative is None:
            raise ValueError("contested requirements require at least one supported alternative")
        return self


class ContestedGradeFragmentRequestPayloadV21(V21StrictModel):
    """The complete controller packet for one contested grading judgment."""

    anonymous_label: Literal["A", "B"]
    grader_lane: Literal[1, 2]
    baseline_fingerprint: Hash
    contested_requirement: ContestedRequirementV21
    report_text: str = Field(strict=True)
    report_fingerprint: Hash
    source_context: dict[str, object]
    rubric: dict[str, object]

    _validate_report_text = field_validator("report_text")(_nonblank)

    @field_validator("source_context", "rubric", mode="before")
    @classmethod
    def validate_context_tree(cls, value: object) -> object:
        if not hasattr(value, "items"):
            raise ValueError("grade request context must be an object")
        return value


class CanonicalBaselineV21(V21StrictModel):
    schema_version: Literal["2.1"] = PROTOCOL_V21
    case_fingerprint: Hash
    requirements: tuple[CanonicalRequirementV2, ...]
    relationships: tuple[CanonicalRelationshipV2, ...] = ()
    contested_requirements: tuple[ContestedRequirementV21, ...] = ()
    baseline_fingerprint: Hash

    @model_validator(mode="after")
    def validate_baseline(self) -> Self:
        requirement_ids = [item.requirement_id for item in self.requirements]
        orders = [item.canonical_order for item in self.requirements]
        if len(requirement_ids) != len(set(requirement_ids)):
            raise ValueError("canonical requirement IDs must be unique")
        if orders != list(range(len(orders))):
            raise ValueError("canonical requirements must use contiguous zero-based order")
        contested_ids = [item.contested_requirement_id for item in self.contested_requirements]
        if len(contested_ids) != len(set(contested_ids)):
            raise ValueError("contested requirement IDs must be unique")
        relationship_ids = [item.relationship_id for item in self.relationships]
        expected_relationship_ids = [
            f"REL-{index:04d}" for index in range(1, len(relationship_ids) + 1)
        ]
        if relationship_ids != expected_relationship_ids:
            raise ValueError("canonical relationships must use contiguous REL IDs in order")
        known = set(requirement_ids)
        if any(
            item.source_requirement_id not in known or item.target_requirement_id not in known
            for item in self.relationships
        ):
            raise ValueError("canonical relationships must identify common baseline requirements")
        return self


class OrdinaryGradeBatchV21(V21StrictModel):
    batch_ref: BatchRef
    requirement_ids: tuple[RequirementRef, ...] = Field(min_length=1, max_length=5)

    @field_validator("requirement_ids")
    @classmethod
    def validate_requirement_ids(
        cls, values: tuple[RequirementRef, ...]
    ) -> tuple[RequirementRef, ...]:
        if len(values) != len(set(values)):
            raise ValueError("ordinary grade batch requirement IDs must be unique")
        return values


class OrdinaryGradeFragmentV21(V21StrictModel):
    schema_version: Literal["2.1"] = PROTOCOL_V21
    anonymous_label: Literal["A", "B"]
    grader_lane: Literal[1, 2]
    batch_ref: BatchRef
    baseline_fingerprint: Hash
    report_fingerprint: Hash
    requirement_grades: tuple[RequirementGradeV2, ...] = Field(min_length=1, max_length=5)
    rationale: str = Field(strict=True)

    _validate_rationale = field_validator("rationale")(_nonblank)

    @model_validator(mode="after")
    def validate_requirement_grades(self, info: ValidationInfo) -> Self:
        _validate_batch_binding(self.batch_ref, self.anonymous_label, self.grader_lane)
        ids = [item.requirement_id for item in self.requirement_grades]
        if len(ids) != len(set(ids)):
            raise ValueError("ordinary grade fragments must use unique requirement IDs")
        context = info.context
        if context is None or "ordinary_grade_batches" not in context:
            raise ValueError("validated controller ordinary batch inventory is required")
        batches = context["ordinary_grade_batches"]
        if not isinstance(batches, (list, tuple)) or any(
            not isinstance(item, OrdinaryGradeBatchV21) for item in batches
        ):
            raise ValueError("ordinary_grade_batches validation context is invalid")
        matching = [item for item in batches if item.batch_ref == self.batch_ref]
        if len(matching) != 1:
            raise ValueError(
                "ordinary grade fragment batch is absent from the controller inventory"
            )
        if tuple(ids) != matching[0].requirement_ids:
            raise ValueError("ordinary grade fragment must cover its batch exactly once in order")
        return self

    @classmethod
    def validate_for_batch(cls, value: object, batch: OrdinaryGradeBatchV21) -> Self:
        return cls.model_validate(value, context={"ordinary_grade_batches": (batch,)})


class ContestedAlternativeGradeV21(V21StrictModel):
    disposition: ContestedDispositionV21
    report_passages: tuple[str, ...] = Field(max_length=_MAX_ROLE_RESPONSE_ITEMS)
    rationale: str = Field(strict=True)

    _validate_rationale = field_validator("rationale")(_nonblank)
    _validate_passages = field_validator("report_passages")(
        lambda values: tuple(_nonblank(item) for item in values)
    )


class ContestedGradeFragmentV21(V21StrictModel):
    schema_version: Literal["2.1"] = PROTOCOL_V21
    anonymous_label: Literal["A", "B"]
    grader_lane: Literal[1, 2]
    contested_requirement_id: str = Field(strict=True)
    baseline_fingerprint: Hash
    report_fingerprint: Hash
    reviewer_alternative_grade: ContestedAlternativeGradeV21
    auditor_alternative_grade: ContestedAlternativeGradeV21
    ambiguity_disposition: AmbiguityDispositionV21
    rationale: str = Field(strict=True)

    _validate_id = field_validator("contested_requirement_id")(_nonblank)
    _validate_rationale = field_validator("rationale")(_nonblank)

    @model_validator(mode="after")
    def validate_contested_inventory(self, info: ValidationInfo) -> Self:
        context = info.context
        if context is None or "contested_requirements" not in context:
            raise ValueError("validated controller contested requirement inventory is required")
        requirements = context["contested_requirements"]
        if not isinstance(requirements, (list, tuple)) or any(
            not isinstance(item, ContestedRequirementV21) for item in requirements
        ):
            raise ValueError("contested_requirements validation context is invalid")
        if sum(
            item.contested_requirement_id == self.contested_requirement_id for item in requirements
        ) != 1:
            raise ValueError(
                "contested grade fragment must bind one controller contested requirement"
            )
        return self

    @classmethod
    def validate_for_requirement(
        cls, value: object, requirement: ContestedRequirementV21
    ) -> Self:
        return cls.model_validate(value, context={"contested_requirements": (requirement,)})


class GraderAggregateV21(V21StrictModel):
    anonymous_label: Literal["A", "B"]
    grader_lane: Literal[1, 2]
    baseline_fingerprint: Hash
    report_fingerprint: Hash
    ordinary_fragments: tuple[OrdinaryGradeFragmentV21, ...]
    contested_fragments: tuple[ContestedGradeFragmentV21, ...]
    aggregate_fingerprint: Hash

    @model_validator(mode="after")
    def validate_aggregate_bindings(self, info: ValidationInfo) -> Self:
        context = info.context
        if (
            context is None
            or "ordinary_grade_batches" not in context
            or "contested_requirements" not in context
        ):
            raise ValueError("validated controller grade inventories are required")
        batches = context["ordinary_grade_batches"]
        contested_requirements = context["contested_requirements"]
        if not isinstance(batches, (list, tuple)) or any(
            not isinstance(item, OrdinaryGradeBatchV21) for item in batches
        ):
            raise ValueError("ordinary_grade_batches validation context is invalid")
        if not isinstance(contested_requirements, (list, tuple)) or any(
            not isinstance(item, ContestedRequirementV21) for item in contested_requirements
        ):
            raise ValueError("contested_requirements validation context is invalid")
        ordinary_refs = [item.batch_ref for item in self.ordinary_fragments]
        contested_ids = [item.contested_requirement_id for item in self.contested_fragments]
        if len(ordinary_refs) != len(set(ordinary_refs)):
            raise ValueError("grader aggregate must use unique ordinary batch references")
        if len(contested_ids) != len(set(contested_ids)):
            raise ValueError("grader aggregate must use unique contested requirement IDs")
        if tuple(ordinary_refs) != tuple(item.batch_ref for item in batches):
            raise ValueError("grader aggregate must cover the exact ordinary batch inventory")
        if tuple(contested_ids) != tuple(
            item.contested_requirement_id for item in contested_requirements
        ):
            raise ValueError(
                "grader aggregate must cover the exact contested requirement inventory"
            )
        for fragment in self.ordinary_fragments:
            if (
                fragment.anonymous_label != self.anonymous_label
                or fragment.grader_lane != self.grader_lane
                or fragment.baseline_fingerprint != self.baseline_fingerprint
                or fragment.report_fingerprint != self.report_fingerprint
            ):
                raise ValueError(
                    "grader fragments must use their aggregate label, lane, and bindings"
                )
        for contested_fragment in self.contested_fragments:
            if (
                contested_fragment.anonymous_label != self.anonymous_label
                or contested_fragment.grader_lane != self.grader_lane
                or contested_fragment.baseline_fingerprint != self.baseline_fingerprint
                or contested_fragment.report_fingerprint != self.report_fingerprint
            ):
                raise ValueError(
                    "grader fragments must use their aggregate label, lane, and bindings"
                )
        return self

    @classmethod
    def validate_for_inventories(
        cls,
        value: object,
        ordinary_grade_batches: tuple[OrdinaryGradeBatchV21, ...],
        contested_requirements: tuple[ContestedRequirementV21, ...],
    ) -> Self:
        return cls.model_validate(
            value,
            context={
                "ordinary_grade_batches": ordinary_grade_batches,
                "contested_requirements": contested_requirements,
            },
        )


class ReconciledGradeV21(V21StrictModel):
    anonymous_label: Literal["A", "B"]
    absolute_disposition: AbsoluteDispositionV2
    reason_codes: tuple[str, ...] = ()
    grader_aggregates: tuple[GraderAggregateV21, GraderAggregateV21]
    reconciliation_fingerprint: Hash

    @field_validator("reason_codes")
    @classmethod
    def validate_reason_codes(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(not item.strip() for item in values) or len(values) != len(set(values)):
            raise ValueError("reason codes must be unique nonblank strings")
        return values

    @model_validator(mode="after")
    def validate_lanes(self) -> Self:
        first, second = self.grader_aggregates
        if (
            first.anonymous_label != self.anonymous_label
            or second.anonymous_label != self.anonymous_label
        ):
            raise ValueError("grader aggregates must use the reconciliation label")
        if (first.grader_lane, second.grader_lane) != (1, 2):
            raise ValueError("reconciled grades require canonical grader lanes 1 then 2")
        if (
            first.baseline_fingerprint != second.baseline_fingerprint
            or first.report_fingerprint != second.report_fingerprint
        ):
            raise ValueError("grader aggregates must share one baseline and report binding")
        return self

    @classmethod
    def validate_for_inventories(
        cls,
        value: object,
        ordinary_grade_batches: tuple[OrdinaryGradeBatchV21, ...],
        contested_requirements: tuple[ContestedRequirementV21, ...],
    ) -> Self:
        if isinstance(value, cls):
            payload = dict(value.__dict__)
        elif type(value) is dict:
            payload = dict(value)
        else:
            raise ValueError("reconciled grade must be an object")
        label = payload.get("anonymous_label")
        raw_aggregates = payload.get("grader_aggregates")
        if label not in {"A", "B"} or not isinstance(raw_aggregates, (list, tuple)):
            raise ValueError("reconciled grade inventory binding is invalid")
        if not isinstance(ordinary_grade_batches, tuple) or any(
            not isinstance(item, OrdinaryGradeBatchV21) for item in ordinary_grade_batches
        ) or len(raw_aggregates) != 2:
            raise ValueError("reconciled grade inventories are invalid")
        try:
            checked_batches = tuple(
                OrdinaryGradeBatchV21.model_validate(item.model_dump(mode="json", warnings="error"))
                for item in ordinary_grade_batches
            )
            refs = [item.batch_ref for item in checked_batches]
            ids = [requirement_id for item in checked_batches for requirement_id in item.requirement_ids]
            if len(refs) != len(set(refs)) or len(ids) != len(set(ids)):
                raise ValueError("ordinary batch partition is invalid")
            checked_aggregates = tuple(
                _validated_reconciliation_aggregate(
                    aggregate, label, checked_batches, contested_requirements
                )
                for aggregate in raw_aggregates
            )
        except (AttributeError, KeyError, TypeError, ValueError) as error:
            raise ValueError("reconciled grade inventories are invalid") from error
        try:
            disposition = AbsoluteDispositionV2(payload["absolute_disposition"])
            reasons = tuple(payload.get("reason_codes", ()))
            fingerprint = payload["reconciliation_fingerprint"]
            if (
                any(type(reason) is not str or not reason.strip() for reason in reasons)
                or len(reasons) != len(set(reasons))
                or type(fingerprint) is not str
                or re.fullmatch(_HASH_PATTERN, fingerprint) is None
            ):
                raise ValueError("reconciled grade fields are invalid")
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("reconciled grade fields are invalid") from error
        if (checked_aggregates[0].grader_lane, checked_aggregates[1].grader_lane) != (1, 2):
            raise ValueError("reconciled grades require canonical grader lanes 1 then 2")
        if (
            checked_aggregates[0].baseline_fingerprint != checked_aggregates[1].baseline_fingerprint
            or checked_aggregates[0].report_fingerprint != checked_aggregates[1].report_fingerprint
        ):
            raise ValueError("grader aggregates must share one baseline and report binding")
        return cls.model_construct(
            anonymous_label=label,
            absolute_disposition=disposition,
            reason_codes=reasons,
            grader_aggregates=checked_aggregates,
            reconciliation_fingerprint=fingerprint,
        )


def _lane_batches(
    batches: tuple[OrdinaryGradeBatchV21, ...], label: Literal["A", "B"], lane: Literal[1, 2]
) -> tuple[OrdinaryGradeBatchV21, ...]:
    return tuple(
        OrdinaryGradeBatchV21(
            batch_ref=f"GB-{label}-{lane}-{index:04d}", requirement_ids=batch.requirement_ids
        )
        for index, batch in enumerate(batches, start=1)
    )


def _validated_reconciliation_aggregate(
    value: object,
    label: Literal["A", "B"],
    batches: tuple[OrdinaryGradeBatchV21, ...],
    contested_requirements: tuple[ContestedRequirementV21, ...],
) -> GraderAggregateV21:
    if isinstance(value, GraderAggregateV21):
        payload = value.model_dump(mode="json", warnings="error")
    elif type(value) is dict:
        payload = value
    else:
        raise ValueError("grader aggregate is invalid")
    if payload.get("anonymous_label") != label or payload.get("grader_lane") not in {1, 2}:
        raise ValueError("grader aggregate label or lane is invalid")
    lane = payload["grader_lane"]
    assert lane in {1, 2}
    return GraderAggregateV21.validate_for_inventories(
        payload, _lane_batches(batches, label, lane), contested_requirements
    )


class RubricV21(V21StrictModel):
    version: Literal["attorney-eval-v2.1"]
    importance_weights: dict[ImportanceV2, int]
    critical_recall_floor: float = Field(ge=0.0, le=1.0, allow_inf_nan=False)
    weighted_coverage_floor: float = Field(ge=0.0, le=1.0, allow_inf_nan=False)
    material_unsupported_assertions_allowed: Literal[0]

    @field_validator("importance_weights")
    @classmethod
    def validate_weights(cls, values: dict[ImportanceV2, int]) -> dict[ImportanceV2, int]:
        if set(values) != set(ImportanceV2) or any(
            type(value) is not int or value < 0 for value in values.values()
        ):
            raise ValueError(
                "rubric importance weights must cover every importance with nonnegative integers"
            )
        return values


class SensitivityRecordV21(V21StrictModel):
    anonymous_label: Literal["A", "B"]
    baseline_fingerprint: Hash
    reconciliation_fingerprint: Hash
    absolute_disposition: AbsoluteDispositionV2
    reason_codes: tuple[str, ...] = ()
    outcome_determinative_contested_ids: tuple[str, ...] = ()
    sensitivity_fingerprint: Hash

    @field_validator("reason_codes", "outcome_determinative_contested_ids")
    @classmethod
    def validate_unique_nonblank(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(not item.strip() for item in values) or len(values) != len(set(values)):
            raise ValueError("sensitivity values must be unique nonblank strings")
        return values

    @model_validator(mode="after")
    def validate_inconclusive_evidence(self) -> Self:
        sensitivity_reasons = {
            _OUTCOME_SENSITIVE_REASON,
            _BASELINE_INSUFFICIENT_REASON,
        }
        if self.absolute_disposition is AbsoluteDispositionV2.INCONCLUSIVE:
            reasons = set(self.reason_codes)
            if len(reasons & sensitivity_reasons) != 1:
                raise ValueError(
                    "inconclusive sensitivity requires one approved sensitivity reason"
                )
            if (
                _OUTCOME_SENSITIVE_REASON in reasons
                and not self.outcome_determinative_contested_ids
            ):
                raise ValueError(
                    "outcome-sensitive inconclusive requires contested requirement evidence"
                )
            if (
                _BASELINE_INSUFFICIENT_REASON in reasons
                and self.outcome_determinative_contested_ids
            ):
                raise ValueError(
                    "baseline-insufficient inconclusive must not claim outcome determinants"
                )
        elif self.outcome_determinative_contested_ids:
            raise ValueError("only inconclusive sensitivity may identify outcome determinants")
        elif set(self.reason_codes) & sensitivity_reasons:
            raise ValueError("conclusive sensitivity must not include inconclusive reason codes")
        return self


class EvaluationCallRecordV21(V21StrictModel):
    call_id: str = Field(strict=True)
    operation: EvaluatorOperationV21
    state: Literal["pending", "accepted"]
    attempt: Literal[1, 2]
    request_artifact_path: str = Field(strict=True)
    request_fingerprint: Hash
    response_artifact_path: str | None = Field(default=None, strict=True)
    response_fingerprint: Hash | None = None
    provider_name: str | None = Field(default=None, strict=True)
    model_name: str | None = Field(default=None, strict=True)
    judge_isolation: Literal["fresh_context", "scripted_fixture"] | None = None
    anonymous_label: Literal["A", "B"] | None = None
    grader_lane: Literal[1, 2] | None = None
    dispute_id: DisputeRef | None = None
    batch_ref: BatchRef | None = None
    contested_requirement_id: str | None = Field(default=None, strict=True)

    _validate_call_id = field_validator("call_id", "request_artifact_path")(_nonblank)
    _validate_optional_names = field_validator(
        "response_artifact_path", "provider_name", "model_name", "contested_requirement_id"
    )(_optional_nonblank)

    @model_validator(mode="after")
    def validate_call_record(self, info: ValidationInfo) -> Self:
        provenance = (
            self.response_artifact_path,
            self.response_fingerprint,
            self.provider_name,
            self.model_name,
            self.judge_isolation,
        )
        if self.state == "pending" and any(value is not None for value in provenance):
            raise ValueError("pending calls must omit response provenance")
        if self.state == "accepted" and any(value is None for value in provenance):
            raise ValueError("accepted calls require complete response provenance")
        grade_operations = {
            EvaluatorOperationV21.ORDINARY_GRADE_FRAGMENT,
            EvaluatorOperationV21.CONTESTED_GRADE_FRAGMENT,
        }
        if self.operation in grade_operations:
            if self.anonymous_label is None or self.grader_lane is None:
                raise ValueError("grade fragment calls require a report label and grader lane")
        elif self.anonymous_label is not None or self.grader_lane is not None:
            raise ValueError("only grade fragment calls may carry report labels or grader lanes")
        if self.operation is EvaluatorOperationV21.SOURCE_REFEREE_FRAGMENT:
            if (
                self.dispute_id is None
                or self.batch_ref is not None
                or self.contested_requirement_id is not None
            ):
                raise ValueError("referee fragment calls require exactly one dispute ID")
        elif self.dispute_id is not None:
            raise ValueError("only referee fragment calls may carry a dispute ID")
        if self.operation is EvaluatorOperationV21.ORDINARY_GRADE_FRAGMENT:
            if self.batch_ref is None or self.contested_requirement_id is not None:
                raise ValueError(
                    "ordinary grade fragment calls require exactly one batch reference"
                )
            assert self.anonymous_label is not None
            assert self.grader_lane is not None
            _validate_batch_binding(self.batch_ref, self.anonymous_label, self.grader_lane)
            context = info.context
            if context is None or "ordinary_grade_batches" not in context:
                raise ValueError("validated controller ordinary batch inventory is required")
            batches = context["ordinary_grade_batches"]
            if not isinstance(batches, (list, tuple)) or any(
                not isinstance(item, OrdinaryGradeBatchV21) for item in batches
            ):
                raise ValueError("ordinary_grade_batches validation context is invalid")
            if sum(item.batch_ref == self.batch_ref for item in batches) != 1:
                raise ValueError(
                    "ordinary grade call batch is absent from the controller inventory"
                )
        elif self.batch_ref is not None:
            raise ValueError("only ordinary grade fragment calls may carry a batch reference")
        if self.operation is EvaluatorOperationV21.CONTESTED_GRADE_FRAGMENT:
            if self.contested_requirement_id is None:
                raise ValueError(
                    "contested grade fragment calls require exactly one contested requirement"
                )
            context = info.context
            if context is None or "contested_requirements" not in context:
                raise ValueError("validated controller contested requirement inventory is required")
            requirements = context["contested_requirements"]
            if not isinstance(requirements, (list, tuple)) or any(
                not isinstance(item, ContestedRequirementV21) for item in requirements
            ):
                raise ValueError("contested_requirements validation context is invalid")
            if sum(
                item.contested_requirement_id == self.contested_requirement_id
                for item in requirements
            ) != 1:
                raise ValueError(
                    "contested grade call requirement is absent from the controller inventory"
                )
        elif self.contested_requirement_id is not None:
            raise ValueError(
                "only contested grade fragment calls may carry a contested requirement"
            )
        return self

    @classmethod
    def validate_for_inventories(
        cls,
        value: object,
        ordinary_grade_batches: tuple[OrdinaryGradeBatchV21, ...],
        contested_requirements: tuple[ContestedRequirementV21, ...],
    ) -> Self:
        return cls.model_validate(
            value,
            context={
                "ordinary_grade_batches": ordinary_grade_batches,
                "contested_requirements": contested_requirements,
            },
        )


class EvaluationManifestV21(V21StrictModel):
    protocol_version: Literal["2.1"] = PROTOCOL_V21
    case_fingerprint: Hash
    case_envelope_hash: Hash
    build_fingerprint: Hash
    rubric_fingerprint: Hash
    compiler_version: Literal["semantic-compiler-v2.1"]
    baseline_fingerprint: Hash | None = None
    referee_aggregate_fingerprint: Hash | None = None
    grader_aggregate_fingerprints: tuple[Hash, ...] = ()
    sensitivity_fingerprints: tuple[Hash, ...] = ()
    result_hash: Hash | None = None
    phase: EvaluationPhaseV21
    terminal_status: EvaluationTerminalStatusV21 | None = None
    calls: tuple[EvaluationCallRecordV21, ...]
    artifacts: tuple[ArtifactRecord, ...]
    referee_disputes: tuple[RefereeDisputeV21, ...]
    ordinary_grade_batches: tuple[OrdinaryGradeBatchV21, ...]
    manifest_fingerprint: Hash

    @model_validator(mode="after")
    def validate_manifest(self) -> Self:
        pending = [call for call in self.calls if call.state == "pending"]
        if len(pending) > 1:
            raise ValueError("a manifest may retain at most one pending request")
        call_ids = [call.call_id for call in self.calls]
        if len(call_ids) != len(set(call_ids)):
            raise ValueError("call IDs must be unique")
        artifact_paths = [artifact.artifact_path for artifact in self.artifacts]
        if artifact_paths != sorted(artifact_paths) or len(artifact_paths) != len(
            set(artifact_paths)
        ):
            raise ValueError("artifacts must be uniquely path-sorted")
        disputes = [item.dispute_id for item in self.referee_disputes]
        batches = [item.batch_ref for item in self.ordinary_grade_batches]
        if len(disputes) != len(set(disputes)) or len(batches) != len(set(batches)):
            raise ValueError("manifest fragment inventories must be unique")
        expected = {
            EvaluationPhaseV21.COMPLETED: EvaluationTerminalStatusV21.COMPLETED,
            EvaluationPhaseV21.INCONCLUSIVE: EvaluationTerminalStatusV21.INCONCLUSIVE,
            EvaluationPhaseV21.INCONCLUSIVE_MECHANICAL: (
                EvaluationTerminalStatusV21.INCONCLUSIVE_MECHANICAL
            ),
        }.get(self.phase)
        if self.terminal_status is not expected:
            raise ValueError("terminal phase and status must match exactly")
        if expected is not None and pending:
            raise ValueError("terminal manifests must not retain a pending request")
        return self


class EvaluationRunStateV21(V21StrictModel):
    schema_version: Literal["2.1"] = PROTOCOL_V21
    case_fingerprint: Hash
    phase: EvaluationPhaseV21
    current_call_id: str | None = Field(default=None, strict=True)
    terminal_status: EvaluationTerminalStatusV21 | None = None
    manifest_fingerprint: Hash | None = None

    _validate_call_id = field_validator("current_call_id")(_optional_nonblank)

    @model_validator(mode="after")
    def validate_terminal_state(self) -> Self:
        expected = {
            EvaluationPhaseV21.COMPLETED: EvaluationTerminalStatusV21.COMPLETED,
            EvaluationPhaseV21.INCONCLUSIVE: EvaluationTerminalStatusV21.INCONCLUSIVE,
            EvaluationPhaseV21.INCONCLUSIVE_MECHANICAL: (
                EvaluationTerminalStatusV21.INCONCLUSIVE_MECHANICAL
            ),
        }.get(self.phase)
        if self.terminal_status is not expected:
            raise ValueError("terminal phase and status must match exactly")
        if expected is not None and self.current_call_id is not None:
            raise ValueError("terminal state must not retain a current call")
        return self


class ReportResultV21(V21StrictModel):
    anonymous_label: Literal["A", "B"]
    reconciliation: ReconciledGradeV21
    sensitivity: SensitivityRecordV21
    result_fingerprint: Hash

    @model_validator(mode="after")
    def validate_report_bindings(self) -> Self:
        if (
            self.reconciliation.anonymous_label != self.anonymous_label
            or self.sensitivity.anonymous_label != self.anonymous_label
        ):
            raise ValueError("report result records must use the report label")
        if self.reconciliation.absolute_disposition is not self.sensitivity.absolute_disposition:
            raise ValueError("report result disposition must match sensitivity")
        first, _ = self.reconciliation.grader_aggregates
        if self.sensitivity.baseline_fingerprint != first.baseline_fingerprint:
            raise ValueError("report sensitivity must bind the reconciled baseline")
        if (
            self.sensitivity.reconciliation_fingerprint
            != self.reconciliation.reconciliation_fingerprint
        ):
            raise ValueError("report sensitivity must bind the reconciliation")
        return self


class EvaluationResultV21(V21StrictModel):
    schema_version: Literal["2.1"] = PROTOCOL_V21
    rubric: RubricV21
    baseline: CanonicalBaselineV21
    reports: tuple[ReportResultV21, ...]
    comparison: ComparisonResultV2 | None = None
    terminal_status: EvaluationTerminalStatusV21
    result_fingerprint: Hash

    @model_validator(mode="after")
    def validate_reports(self) -> Self:
        labels = [item.anonymous_label for item in self.reports]
        if labels not in ([], ["A"], ["A", "B"]):
            raise ValueError("reports must use unique fixed order A or A, B")
        if self.terminal_status is EvaluationTerminalStatusV21.COMPLETED and not self.reports:
            raise ValueError("completed results require at least one report")
        if self.terminal_status is EvaluationTerminalStatusV21.INCONCLUSIVE and (
            not self.reports
            or any(
                report.sensitivity.absolute_disposition is not AbsoluteDispositionV2.INCONCLUSIVE
                for report in self.reports
            )
        ):
            raise ValueError("substantive inconclusive requires sensitivity-backed report evidence")
        if (self.comparison is not None) != (labels == ["A", "B"]):
            raise ValueError("comparison requires exactly two reports")
        return self


def validate_evaluator_request_v21(value: object) -> EvaluatorRequestV21:
    """Safely revalidate a raw or bypass-constructed request before issuing it."""
    if isinstance(value, EvaluatorRequestV21):
        payload = dict(value.__dict__)
        payload["json_schema"] = _validated_json_snapshot(
            value.json_schema, location="request json_schema"
        )
        payload["payload"] = _validated_json_snapshot(value.payload, location="request payload")
    elif type(value) is dict:
        payload = value
    else:
        raise ValueError("evaluator request must be an object")
    try:
        return EvaluatorRequestV21.model_validate(payload)
    except (TypeError, ValueError) as error:
        raise ValueError("evaluator request is invalid") from error


def validate_evaluator_response_v21(value: object) -> EvaluatorResponseV21:
    """Safely revalidate a raw or bypass-constructed response before consuming it."""
    if isinstance(value, EvaluatorResponseV21):
        payload = dict(value.__dict__)
        payload["payload"] = _validated_json_snapshot(value.payload, location="response payload")
    elif type(value) is dict:
        payload = value
    else:
        raise ValueError("evaluator response must be an object")
    try:
        return EvaluatorResponseV21.model_validate(payload)
    except (TypeError, ValueError) as error:
        raise ValueError("evaluator response is invalid") from error
