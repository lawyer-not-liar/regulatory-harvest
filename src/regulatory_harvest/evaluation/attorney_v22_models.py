"""Strict persisted contracts for recoverable evaluator protocol 2.2.

This module deliberately contains value contracts only.  Draft parsing,
deterministic compilation, requests, storage, and workflow transitions belong
to their dedicated Protocol 2.2 modules.  It reuses semantic vocabulary from
earlier protocols, but no serialized Protocol 2.0 or 2.1 envelope.
"""

from __future__ import annotations

import re
import warnings
from collections.abc import Mapping
from datetime import date, datetime, time
from enum import Enum, StrEnum
from typing import Annotated, Literal, Self, TypeVar, cast

from pydantic import (
    BaseModel,
    Field,
    ValidationError,
    ValidationInfo,
    field_validator,
    model_validator,
)

from regulatory_harvest.storage import canonical_json_bytes

from .attorney_models import ArtifactRecord
from .attorney_v2_models import (
    AbsoluteDispositionV2,
    CanonicalRelationshipV2,
    CanonicalRequirementV2,
    ComparisonDispositionV2,
    ImportanceV2,
    MaterialDisputeV2,
    RequirementGradeV2,
    ResolvedPassageV2,
    SemanticPassage,
    SemanticProposal,
    V2StrictModel,
    _nonblank,
    _optional_nonblank,
    _unique_passages,
    _validate_json_object,
)

PROTOCOL_V22: Literal["2.2"] = "2.2"
_HASH_PATTERN = r"^[0-9a-f]{64}$"
_PROPOSAL_REF_PATTERN = r"^P[0-9]{4}$"
_CONCERN_REF_PATTERN = r"^C[0-9]{4}$"
_DISPUTE_REF_PATTERN = r"^D[0-9]{4}$"
_REQUIREMENT_REF_PATTERN = r"^REQ-[0-9]{4}$"
_EVIDENCE_REF_PATTERN = r"^EVID-[0-9]{4}$"
_BATCH_REF_PATTERN = r"^GB-[AB]-[12]-[0-9]{4}$"
_MAX_FRAGMENT_ITEMS = 5
_MAX_FRAGMENTS = 128
_MAX_COMPILED_ITEMS = 640
_MAX_WIRE_BYTES = 16 * 1024 * 1024
_MAX_WIRE_DEPTH = 64
_MAX_WIRE_NODES = 100_000

Hash = Annotated[str, Field(pattern=_HASH_PATTERN, strict=True)]
ProposalRef = Annotated[str, Field(pattern=_PROPOSAL_REF_PATTERN, strict=True)]
ConcernRef = Annotated[str, Field(pattern=_CONCERN_REF_PATTERN, strict=True)]
DisputeRef = Annotated[str, Field(pattern=_DISPUTE_REF_PATTERN, strict=True)]
RequirementRef = Annotated[str, Field(pattern=_REQUIREMENT_REF_PATTERN, strict=True)]
EvidenceRef = Annotated[str, Field(pattern=_EVIDENCE_REF_PATTERN, strict=True)]
BatchRef = Annotated[str, Field(pattern=_BATCH_REF_PATTERN, strict=True)]


_ModelT = TypeVar("_ModelT", bound=BaseModel)


class _EvaluatorResponseValidationErrorV22(ValueError):
    """A supplied evaluator response failed the controlled input boundary."""


def _wire_snapshot_inner(
    value: object,
    active: set[int],
    *,
    budget: list[int],
    depth: int,
) -> object:
    """Return one bounded raw view without normalizing scalar provenance."""
    budget[0] += 1
    if budget[0] > _MAX_WIRE_NODES or depth > _MAX_WIRE_DEPTH:
        raise ValueError("model wire snapshot exceeds resource limits")
    if type(value) is str:
        budget[1] += len(value.encode("utf-8"))
    elif type(value) is bytes:
        budget[1] += len(value)
    else:
        budget[1] += 1
    if budget[1] > _MAX_WIRE_BYTES:
        raise ValueError("model wire snapshot exceeds resource limits")
    if isinstance(value, Mapping) and not isinstance(value, dict):
        raise ValueError("model wire snapshot requires a built-in mapping")
    if isinstance(value, BaseModel):
        identity = id(value)
        if identity in active:
            raise ValueError("model wire snapshot contains a cycle")
        active.add(identity)
        try:
            state = object.__getattribute__(value, "__dict__")
            return {
                key: _wire_snapshot_inner(
                    item,
                    active,
                    budget=budget,
                    depth=depth + 1,
                )
                for key, item in dict.items(state)
            }
        finally:
            active.remove(identity)
    if isinstance(value, (tuple, list)):
        identity = id(value)
        if identity in active:
            raise ValueError("model wire snapshot contains a cycle")
        active.add(identity)
        try:
            iterator = (
                tuple.__iter__(value) if isinstance(value, tuple) else list.__iter__(value)
            )
            return [
                _wire_snapshot_inner(item, active, budget=budget, depth=depth + 1)
                for item in iterator
            ]
        finally:
            active.remove(identity)
    if isinstance(value, dict):
        identity = id(value)
        if identity in active:
            raise ValueError("model wire snapshot contains a cycle")
        active.add(identity)
        try:
            result: dict[object, object] = {}
            for key, item in dict.items(value):
                wire_key = _wire_snapshot_inner(
                    key, active, budget=budget, depth=depth + 1
                )
                if wire_key in result:
                    raise ValueError("model wire snapshot contains duplicate keys")
                result[wire_key] = _wire_snapshot_inner(
                    item, active, budget=budget, depth=depth + 1
                )
            return result
        finally:
            active.remove(identity)
    return value


def _wire_snapshot(value: object) -> object:
    """Contain warnings and ordinary failures from one untrusted raw traversal."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            return _wire_snapshot_inner(value, set(), budget=[0, 0], depth=1)
    except Exception:
        raise ValueError("model wire snapshot is invalid") from None


def _json_key(value: object) -> object:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, (datetime, date, time)):
        return value.isoformat()
    return value


def _same_wire_value(raw: object, checked: object, serialized: object) -> bool:
    """Require exact supplied scalar provenance against one strict result."""
    if isinstance(raw, dict) and isinstance(checked, dict) and isinstance(serialized, dict):
        for raw_key, raw_value in dict.items(raw):
            if type(raw_key) is str:
                if raw_key not in serialized:
                    return False
                matching = [key for key in checked if _json_key(key) == raw_key]
            else:
                matching = [
                    key
                    for key in checked
                    if type(key) is type(raw_key) and key == raw_key
                ]
            if len(matching) != 1:
                return False
            checked_key = matching[0]
            json_key = _json_key(checked_key)
            if json_key not in serialized or not _same_wire_value(
                raw_value, checked[checked_key], serialized[json_key]
            ):
                return False
        return True
    if isinstance(raw, list) and isinstance(checked, list) and isinstance(serialized, list):
        return len(raw) == len(checked) == len(serialized) and all(
            _same_wire_value(left, middle, right)
            for left, middle, right in zip(raw, checked, serialized, strict=True)
        )
    if isinstance(raw, (Enum, datetime, date, time)):
        return type(raw) is type(checked) and raw == checked
    return type(raw) is type(serialized) and raw == serialized


def _strict_rehydrate_v22(
    model: type[_ModelT],
    value: object,
    *,
    context: dict[str, object] | None = None,
    location: str,
) -> _ModelT:
    """Rebuild one model from raw state and reject any scalar coercion or cycle."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            raw = _wire_snapshot(value)
            if not isinstance(raw, dict):
                raise ValueError
            checked = model.model_validate(raw, context=context)
            checked_raw = _wire_snapshot(checked)
            serialized = checked.model_dump(mode="json", warnings="error")
            if len(canonical_json_bytes(serialized)) > _MAX_WIRE_BYTES:
                raise ValueError
            if not _same_wire_value(raw, checked_raw, serialized):
                raise ValueError
            return checked
    except Exception:
        raise ValueError(f"{location} is invalid") from None


def _checked_indexed_proposals(
    indexed: tuple[IndexedProposalV22, ...],
) -> tuple[IndexedProposalV22, ...]:
    try:
        checked = tuple(
            _strict_rehydrate_v22(
                IndexedProposalV22, item, location="indexed proposal inventory"
            )
            for item in indexed
        )
    except (TypeError, ValidationError, ValueError, RecursionError) as error:
        raise ValueError("indexed proposal inventory is invalid") from error
    refs = [item.proposal_ref for item in checked]
    if len(refs) != len(set(refs)):
        raise ValueError("indexed proposals must use unique proposal references")
    return checked


class V22StrictModel(V2StrictModel):
    """Closed, frozen values whose serialized protocol is exactly 2.2."""


class _FragmentOrdinalV22(V22StrictModel):
    fragment_ordinal: int = Field(strict=True, ge=1, le=_MAX_FRAGMENTS)


class _GradeCoordinateV22(V22StrictModel):
    anonymous_label: Literal["A", "B"]
    grader_lane: Literal[1, 2]


class _SourceContextV22(V22StrictModel):
    values: dict[str, str] = Field(min_length=1, max_length=_MAX_COMPILED_ITEMS)

    @field_validator("values")
    @classmethod
    def validate_nonblank_entries(cls, values: dict[str, str]) -> dict[str, str]:
        if any(not key.strip() or not value.strip() for key, value in values.items()):
            raise ValueError("source context entries must not be blank")
        return values


def _strict_fragment_ordinal_v22(value: object) -> int:
    return _strict_rehydrate_v22(
        _FragmentOrdinalV22,
        {"fragment_ordinal": value},
        location="fragment ordinal",
    ).fragment_ordinal


def _strict_grade_coordinate_v22(
    anonymous_label: object, grader_lane: object
) -> tuple[Literal["A", "B"], Literal[1, 2]]:
    checked = _strict_rehydrate_v22(
        _GradeCoordinateV22,
        {"anonymous_label": anonymous_label, "grader_lane": grader_lane},
        location="grade coordinate",
    )
    return checked.anonymous_label, checked.grader_lane


def _strict_source_context_v22(value: object) -> dict[str, str]:
    checked = _strict_rehydrate_v22(
        _SourceContextV22,
        {"values": value},
        location="source context",
    )
    return {key: item for key, item in dict.items(checked.values)}


class EvaluatorOperationV22(StrEnum):
    SOURCE_REVIEW_FRAGMENT = "source_review_fragment"
    SOURCE_AUDIT_FRAGMENT = "source_audit_fragment"
    SOURCE_REFEREE_FRAGMENT = "source_referee_fragment"
    ORDINARY_GRADE_FRAGMENT = "ordinary_grade_fragment"
    CONTESTED_GRADE_FRAGMENT = "contested_grade_fragment"


class EvaluationPhaseV22(StrEnum):
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


class EvaluationTerminalStatusV22(StrEnum):
    COMPLETED = "COMPLETED"
    INCONCLUSIVE = "INCONCLUSIVE"


class RefereeUnresolvedReasonV22(StrEnum):
    SOURCE_AMBIGUITY = "SOURCE_AMBIGUITY"
    SOURCE_CONFLICT = "SOURCE_CONFLICT"
    SOURCE_GAP = "SOURCE_GAP"
    BOTH_POSITIONS_UNSUPPORTED = "BOTH_POSITIONS_UNSUPPORTED"


class ContestedDispositionV22(StrEnum):
    MET = "met"
    PARTIALLY_MET = "partially_met"
    NOT_MET = "not_met"
    UNCERTAIN = "uncertain"


class AmbiguityDispositionV22(StrEnum):
    ACKNOWLEDGED = "acknowledged"
    OVERSTATED = "overstated"
    OMITTED = "omitted"
    UNCERTAIN = "uncertain"


class IndexedProposalV22(V22StrictModel):
    proposal_ref: ProposalRef
    proposal: SemanticProposal


class AuditConcernV22(V22StrictModel):
    """Strict controller-bound source-audit concern, without a protocol wrapper."""

    target_proposal_ref: ProposalRef | None = None
    concern_type: Literal[
        "omission",
        "incorrect_statement",
        "incorrect_evidence",
        "incorrect_relationship",
        "ambiguity",
    ]
    passages: tuple[SemanticPassage, ...] = Field(min_length=1, max_length=_MAX_FRAGMENT_ITEMS)
    explanation: str = Field(strict=True)
    correction: SemanticProposal | None = None

    _validate_explanation = field_validator("explanation")(_nonblank)

    _validate_passages = field_validator("passages")(_unique_passages)

    @model_validator(mode="after")
    def validate_target_and_correction(self) -> Self:
        if self.concern_type == "omission":
            if self.target_proposal_ref is not None or self.correction is None:
                raise ValueError("omission concerns require no target and one correction")
        elif self.concern_type in {
            "incorrect_statement",
            "incorrect_evidence",
            "incorrect_relationship",
        }:
            if self.target_proposal_ref is None or self.correction is None:
                raise ValueError("incorrect concerns require one target and one correction")
        elif self.target_proposal_ref is None:
            raise ValueError("ambiguity concerns require one target")
        return self

    @classmethod
    def validate_for_indexed_proposals(
        cls, value: object, indexed: tuple[IndexedProposalV22, ...]
    ) -> Self:
        checked_indexed = _checked_indexed_proposals(indexed)
        try:
            checked = _strict_rehydrate_v22(cls, value, location="audit concern")
        except (TypeError, ValidationError, ValueError, RecursionError) as error:
            raise ValueError("audit concern is invalid") from error
        if checked.target_proposal_ref is not None and checked.target_proposal_ref not in {
            item.proposal_ref for item in checked_indexed
        }:
            raise ValueError("audit concerns must target only engine-issued proposal references")
        return checked


class IndexedAuditConcernV22(V22StrictModel):
    concern_ref: ConcernRef
    concern: AuditConcernV22


class SourceReviewFragmentV22(V22StrictModel):
    schema_version: Literal["2.2"] = PROTOCOL_V22
    proposals: tuple[SemanticProposal, ...] = Field(max_length=_MAX_FRAGMENT_ITEMS)
    review_complete: bool

    @model_validator(mode="after")
    def validate_progress(self) -> Self:
        if not self.review_complete and not self.proposals:
            raise ValueError("nonfinal source-review fragments require at least one new proposal")
        return self


class SourceAuditFragmentV22(V22StrictModel):
    schema_version: Literal["2.2"] = PROTOCOL_V22
    concerns: tuple[AuditConcernV22, ...] = Field(max_length=_MAX_FRAGMENT_ITEMS)
    audit_complete: bool

    @model_validator(mode="after")
    def validate_progress(self) -> Self:
        if not self.audit_complete and not self.concerns:
            raise ValueError("nonfinal source-audit fragments require at least one new concern")
        return self

    @classmethod
    def validate_for_indexed_proposals(
        cls, value: object, indexed: tuple[IndexedProposalV22, ...]
    ) -> Self:
        checked_indexed = _checked_indexed_proposals(indexed)
        raw = _wire_snapshot(value)
        if not isinstance(raw, dict):
            raise ValueError("source-audit fragment is invalid")
        raw_concerns = raw.get("concerns")
        if not isinstance(raw_concerns, (list, tuple)):
            raise ValueError("source-audit fragment concerns are invalid")
        checked_concerns = tuple(
            AuditConcernV22.validate_for_indexed_proposals(concern, checked_indexed)
            for concern in raw_concerns
        )
        return _strict_rehydrate_v22(
            cls,
            {**raw, "concerns": checked_concerns},
            location="source-audit fragment",
        )


class AcceptedSourceReviewFragmentV22(V22StrictModel):
    fragment_ordinal: int = Field(ge=1, le=_MAX_FRAGMENTS)
    request_fingerprint: Hash
    response_fingerprint: Hash
    payload: SourceReviewFragmentV22


class AcceptedSourceAuditFragmentV22(V22StrictModel):
    fragment_ordinal: int = Field(ge=1, le=_MAX_FRAGMENTS)
    request_fingerprint: Hash
    response_fingerprint: Hash
    payload: SourceAuditFragmentV22


class SourceReviewAggregateV22(V22StrictModel):
    fragments: tuple[AcceptedSourceReviewFragmentV22, ...] = Field(
        min_length=1, max_length=_MAX_FRAGMENTS
    )
    proposals: tuple[IndexedProposalV22, ...] = Field(max_length=_MAX_COMPILED_ITEMS)
    fragment_fingerprints: tuple[Hash, ...] = Field(max_length=_MAX_FRAGMENTS)
    aggregate_fingerprint: Hash

    @model_validator(mode="after")
    def validate_inventory(self) -> Self:
        refs = [item.proposal_ref for item in self.proposals]
        if len(refs) != len(set(refs)):
            raise ValueError("source-review aggregate proposal references must be unique")
        if len(self.fragment_fingerprints) != len(set(self.fragment_fingerprints)):
            raise ValueError("source-review aggregate fragment fingerprints must be unique")
        return self


class SourceAuditAggregateV22(V22StrictModel):
    fragments: tuple[AcceptedSourceAuditFragmentV22, ...] = Field(
        min_length=1, max_length=_MAX_FRAGMENTS
    )
    concerns: tuple[IndexedAuditConcernV22, ...] = Field(max_length=_MAX_COMPILED_ITEMS)
    fragment_fingerprints: tuple[Hash, ...] = Field(max_length=_MAX_FRAGMENTS)
    aggregate_fingerprint: Hash

    @model_validator(mode="after")
    def validate_inventory(self) -> Self:
        refs = [item.concern_ref for item in self.concerns]
        if len(refs) != len(set(refs)):
            raise ValueError("source-audit aggregate concern references must be unique")
        if len(self.fragment_fingerprints) != len(set(self.fragment_fingerprints)):
            raise ValueError("source-audit aggregate fragment fingerprints must be unique")
        return self

    @classmethod
    def validate_for_indexed_proposals(
        cls, value: object, indexed: tuple[IndexedProposalV22, ...]
    ) -> Self:
        checked_indexed = _checked_indexed_proposals(indexed)
        raw = _wire_snapshot(value)
        if not isinstance(raw, dict):
            raise ValueError("source-audit aggregate is invalid")
        raw_concerns = raw.get("concerns")
        if not isinstance(raw_concerns, (list, tuple)):
            raise ValueError("source-audit aggregate concerns are invalid")
        checked_concerns = []
        for item in raw_concerns:
            if not isinstance(item, dict):
                raise ValueError("source-audit aggregate concern is invalid")
            concern = AuditConcernV22.validate_for_indexed_proposals(
                item.get("concern"), checked_indexed
            )
            checked_concerns.append(
                _strict_rehydrate_v22(
                    IndexedAuditConcernV22,
                    {**item, "concern": concern},
                    location="indexed audit concern",
                )
            )
        return _strict_rehydrate_v22(
            cls,
            {**raw, "concerns": tuple(checked_concerns)},
            location="source-audit aggregate",
        )


class EvaluatorRequestV22(V22StrictModel):
    schema_version: Literal["2.2"] = PROTOCOL_V22
    operation: EvaluatorOperationV22
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


class EvaluatorResponseV22(V22StrictModel):
    schema_version: Literal["2.2"] = PROTOCOL_V22
    operation: EvaluatorOperationV22
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


class RefereeEvidenceV22(V22StrictModel):
    evidence_ref: EvidenceRef
    passage: ResolvedPassageV2


class RefereeDisputeV22(V22StrictModel):
    case_fingerprint: Hash
    dispute_fingerprint: Hash
    dispute_id: DisputeRef
    material_dispute: MaterialDisputeV2
    evidence: tuple[RefereeEvidenceV22, ...] = Field(min_length=1, max_length=_MAX_FRAGMENTS)

    @model_validator(mode="after")
    def validate_dispute_binding(self) -> Self:
        if self.material_dispute.dispute_id != self.dispute_id:
            raise ValueError("referee dispute ID must match the material dispute")
        refs = [item.evidence_ref for item in self.evidence]
        if len(refs) != len(set(refs)):
            raise ValueError("referee evidence references must be unique")
        return self


class RefereeFragmentRequestPayloadV22(V22StrictModel):
    material_disputes: tuple[RefereeDisputeV22, ...] = Field(min_length=1, max_length=1)


class RefereeDecisionV22(V22StrictModel):
    schema_version: Literal["2.2"] = PROTOCOL_V22
    decision: Literal["accept_reviewer", "accept_auditor", "unresolved"]
    unresolved_reason: RefereeUnresolvedReasonV22 | None = None
    evidence_refs: tuple[EvidenceRef, ...] = Field(min_length=1, max_length=_MAX_FRAGMENTS)
    rationale: str = Field(strict=True)

    _validate_rationale = field_validator("rationale")(_nonblank)

    @model_validator(mode="after")
    def validate_decision(self, info: ValidationInfo) -> Self:
        if (self.decision == "unresolved") != (self.unresolved_reason is not None):
            raise ValueError("unresolved decisions require one unresolved reason")
        if len(self.evidence_refs) != len(set(self.evidence_refs)):
            raise ValueError("referee evidence references must be unique")
        context = info.context
        if context is None or "evidence_refs" not in context:
            raise ValueError("validated controller evidence inventory is required")
        allowed = context["evidence_refs"]
        if not isinstance(allowed, (set, frozenset, tuple, list)) or any(
            type(item) is not str for item in allowed
        ):
            raise ValueError("evidence_refs validation context is invalid")
        if not set(self.evidence_refs).issubset(set(allowed)):
            raise ValueError("referee evidence must use only controller-issued references")
        return self

    @classmethod
    def validate_for_evidence(cls, value: object, evidence: tuple[RefereeEvidenceV22, ...]) -> Self:
        try:
            checked_evidence = tuple(
                _strict_rehydrate_v22(
                    RefereeEvidenceV22, item, location="referee evidence inventory"
                )
                for item in evidence
            )
        except (TypeError, ValidationError, ValueError, RecursionError) as error:
            raise ValueError("referee evidence inventory is invalid") from error
        refs = [item.evidence_ref for item in checked_evidence]
        if len(refs) != len(set(refs)):
            raise ValueError("referee evidence inventory must use unique references")
        try:
            return _strict_rehydrate_v22(
                cls,
                value,
                context={"evidence_refs": set(refs)},
                location="referee decision",
            )
        except (TypeError, ValidationError, ValueError, RecursionError) as error:
            raise ValueError("referee decision is invalid") from error


class AcceptedRefereeFragmentV22(V22StrictModel):
    case_fingerprint: Hash
    dispute_id: DisputeRef
    dispute_fingerprint: Hash
    decision: RefereeDecisionV22
    response_fingerprint: Hash

    @classmethod
    def validate_for_dispute(cls, value: object, dispute: RefereeDisputeV22) -> Self:
        try:
            checked_dispute = _strict_rehydrate_v22(
                RefereeDisputeV22, dispute, location="referee dispute"
            )
            raw = _wire_snapshot(value)
        except (TypeError, ValidationError, ValueError, RecursionError) as error:
            raise ValueError("referee fragment is invalid") from error
        if not isinstance(raw, dict):
            raise ValueError("referee fragment is invalid")
        decision = RefereeDecisionV22.validate_for_evidence(
            raw.get("decision"), checked_dispute.evidence
        )
        try:
            checked = _strict_rehydrate_v22(
                cls,
                {**raw, "decision": decision},
                context={"evidence_refs": {item.evidence_ref for item in checked_dispute.evidence}},
                location="referee fragment",
            )
        except (TypeError, ValidationError, ValueError, RecursionError) as error:
            raise ValueError("referee fragment is invalid") from error
        if checked.case_fingerprint != checked_dispute.case_fingerprint:
            raise ValueError("referee fragment case fingerprint must match its dispute")
        if checked.dispute_id != checked_dispute.dispute_id:
            raise ValueError("referee fragment dispute ID must match its dispute")
        if checked.dispute_fingerprint != checked_dispute.dispute_fingerprint:
            raise ValueError("referee fragment dispute fingerprint must match its dispute")
        return checked


class RefereeAggregateV22(V22StrictModel):
    fragments: tuple[AcceptedRefereeFragmentV22, ...] = Field(max_length=_MAX_FRAGMENTS)
    aggregate_fingerprint: Hash

    @classmethod
    def validate_for_disputes(cls, value: object, disputes: tuple[RefereeDisputeV22, ...]) -> Self:
        try:
            checked_disputes = tuple(
                _strict_rehydrate_v22(
                    RefereeDisputeV22, item, location="referee dispute inventory"
                )
                for item in disputes
            )
            raw = _wire_snapshot(value)
        except (TypeError, ValidationError, ValueError, RecursionError) as error:
            raise ValueError("referee dispute inventory is invalid") from error
        if not isinstance(raw, dict) or not isinstance(raw.get("fragments"), (list, tuple)):
            raise ValueError("referee aggregate is invalid")
        ids = [item.dispute_id for item in checked_disputes]
        if len(ids) != len(set(ids)):
            raise ValueError("referee dispute inventory must use unique dispute IDs")
        raw_fragments = raw["fragments"]
        if len(raw_fragments) > _MAX_FRAGMENTS:
            raise ValueError("referee aggregate may contain at most 128 fragments")
        if len(raw_fragments) != len(checked_disputes):
            raise ValueError("referee aggregate fragment coverage does not match disputes")
        fragments = tuple(
            AcceptedRefereeFragmentV22.validate_for_dispute(fragment, dispute)
            for fragment, dispute in zip(raw_fragments, checked_disputes, strict=True)
        )
        evidence_refs = {
            evidence.evidence_ref for dispute in checked_disputes for evidence in dispute.evidence
        }
        return _strict_rehydrate_v22(
            cls,
            {**raw, "fragments": fragments},
            context={"evidence_refs": evidence_refs},
            location="referee aggregate",
        )


class ContestedRequirementV22(V22StrictModel):
    contested_requirement_id: str = Field(strict=True)
    reviewer_alternative: CanonicalRequirementV2 | None = None
    auditor_alternative: CanonicalRequirementV2 | None = None
    unresolved_reason: RefereeUnresolvedReasonV22
    rationale: str = Field(strict=True)
    referee_fragment_fingerprint: Hash

    _validate_id = field_validator("contested_requirement_id")(_nonblank)
    _validate_rationale = field_validator("rationale")(_nonblank)

    @model_validator(mode="after")
    def validate_alternatives(self) -> Self:
        if self.reviewer_alternative is None and self.auditor_alternative is None:
            raise ValueError("contested requirements require at least one alternative")
        return self


class ContestedGradeFragmentRequestPayloadV22(V22StrictModel):
    anonymous_label: Literal["A", "B"]
    grader_lane: Literal[1, 2]
    baseline_fingerprint: Hash
    report_text: str = Field(strict=True)
    report_fingerprint: Hash
    source_context: dict[str, str]
    rubric: dict[str, object]
    contested_requirement: ContestedRequirementV22

    _validate_report_text = field_validator("report_text")(_nonblank)


class CanonicalBaselineV22(V22StrictModel):
    schema_version: Literal["2.2"] = PROTOCOL_V22
    case_fingerprint: Hash
    requirements: tuple[CanonicalRequirementV2, ...]
    relationships: tuple[CanonicalRelationshipV2, ...] = ()
    contested_requirements: tuple[ContestedRequirementV22, ...] = ()
    baseline_fingerprint: Hash

    @model_validator(mode="after")
    def validate_baseline(self) -> Self:
        requirement_ids = [item.requirement_id for item in self.requirements]
        orders = [item.canonical_order for item in self.requirements]
        if len(requirement_ids) != len(set(requirement_ids)) or orders != list(range(len(orders))):
            raise ValueError("canonical requirements must use unique contiguous zero-based order")
        contested_ids = [item.contested_requirement_id for item in self.contested_requirements]
        if len(contested_ids) != len(set(contested_ids)):
            raise ValueError("contested requirement IDs must be unique")
        relationship_ids = [item.relationship_id for item in self.relationships]
        if relationship_ids != [
            f"REL-{index:04d}" for index in range(1, len(relationship_ids) + 1)
        ]:
            raise ValueError("canonical relationships must use contiguous REL IDs in order")
        known = set(requirement_ids)
        if any(
            item.source_requirement_id not in known or item.target_requirement_id not in known
            for item in self.relationships
        ):
            raise ValueError("canonical relationships must identify common baseline requirements")
        return self


class OrdinaryGradeBatchV22(V22StrictModel):
    batch_ref: BatchRef
    requirement_ids: tuple[RequirementRef, ...] = Field(
        min_length=1, max_length=_MAX_FRAGMENT_ITEMS
    )

    @field_validator("requirement_ids")
    @classmethod
    def validate_requirement_ids(
        cls, values: tuple[RequirementRef, ...]
    ) -> tuple[RequirementRef, ...]:
        if len(values) != len(set(values)):
            raise ValueError("ordinary grade batch requirement IDs must be unique")
        return values


def _validate_batch_binding(batch_ref: str, anonymous_label: str, grader_lane: int) -> None:
    match = re.fullmatch(r"^GB-([AB])-([12])-[0-9]{4}$", batch_ref)
    if match is None or match.group(1) != anonymous_label or int(match.group(2)) != grader_lane:
        raise ValueError("batch reference must bind its anonymous label and grader lane")


class OrdinaryGradeFragmentV22(V22StrictModel):
    schema_version: Literal["2.2"] = PROTOCOL_V22
    anonymous_label: Literal["A", "B"]
    grader_lane: Literal[1, 2]
    batch_ref: BatchRef
    baseline_fingerprint: Hash
    report_fingerprint: Hash
    requirement_grades: tuple[RequirementGradeV2, ...] = Field(
        min_length=1, max_length=_MAX_FRAGMENT_ITEMS
    )
    rationale: str = Field(strict=True)

    _validate_rationale = field_validator("rationale")(_nonblank)

    @model_validator(mode="after")
    def validate_requirement_grades(self, info: ValidationInfo) -> Self:
        _validate_batch_binding(self.batch_ref, self.anonymous_label, self.grader_lane)
        if any(not isinstance(item, RequirementGradeV2) for item in self.requirement_grades):
            raise ValueError("ordinary grade fragment requirement grades are invalid")
        ids = [item.requirement_id for item in self.requirement_grades]
        if len(ids) != len(set(ids)):
            raise ValueError("ordinary grade fragments must use unique requirement IDs")
        context = info.context
        if context is None or "ordinary_grade_batches" not in context:
            return self
        batches = context["ordinary_grade_batches"]
        if not isinstance(batches, (list, tuple)) or any(
            not isinstance(item, OrdinaryGradeBatchV22) for item in batches
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
    def validate_for_batch(cls, value: object, batch: OrdinaryGradeBatchV22) -> Self:
        try:
            checked_batch = _strict_rehydrate_v22(
                OrdinaryGradeBatchV22, batch, location="ordinary grade batch"
            )
            return _strict_rehydrate_v22(
                cls,
                value,
                context={"ordinary_grade_batches": (checked_batch,)},
                location="ordinary grade fragment batch",
            )
        except (TypeError, ValidationError, ValueError, RecursionError) as error:
            raise ValueError(str(error)) from error


class ContestedAlternativeGradeV22(V22StrictModel):
    disposition: ContestedDispositionV22
    report_passages: tuple[str, ...] = Field(max_length=_MAX_FRAGMENTS)
    rationale: str = Field(strict=True)

    _validate_rationale = field_validator("rationale")(_nonblank)
    _validate_passages = field_validator("report_passages")(
        lambda values: tuple(_nonblank(item) for item in values)
    )


class ContestedGradeFragmentV22(V22StrictModel):
    schema_version: Literal["2.2"] = PROTOCOL_V22
    anonymous_label: Literal["A", "B"]
    grader_lane: Literal[1, 2]
    contested_requirement_id: str = Field(strict=True)
    baseline_fingerprint: Hash
    report_fingerprint: Hash
    reviewer_alternative_grade: ContestedAlternativeGradeV22
    auditor_alternative_grade: ContestedAlternativeGradeV22
    ambiguity_disposition: AmbiguityDispositionV22
    rationale: str = Field(strict=True)

    _validate_id = field_validator("contested_requirement_id")(_nonblank)
    _validate_rationale = field_validator("rationale")(_nonblank)

    @model_validator(mode="after")
    def validate_contested_inventory(self, info: ValidationInfo) -> Self:
        context = info.context
        if context is None or "contested_requirements" not in context:
            return self
        requirements = context["contested_requirements"]
        if not isinstance(requirements, (list, tuple)) or any(
            not isinstance(item, ContestedRequirementV22) for item in requirements
        ):
            raise ValueError("contested_requirements validation context is invalid")
        if (
            sum(
                item.contested_requirement_id == self.contested_requirement_id
                for item in requirements
            )
            != 1
        ):
            raise ValueError(
                "contested grade fragment must bind one controller contested requirement"
            )
        return self

    @classmethod
    def validate_for_requirement(cls, value: object, requirement: ContestedRequirementV22) -> Self:
        try:
            checked_requirement = _strict_rehydrate_v22(
                ContestedRequirementV22,
                requirement,
                location="contested requirement",
            )
            return _strict_rehydrate_v22(
                cls,
                value,
                context={"contested_requirements": (checked_requirement,)},
                location="contested grade fragment",
            )
        except (TypeError, ValidationError, ValueError, RecursionError) as error:
            raise ValueError(str(error)) from error


class GraderAggregateV22(V22StrictModel):
    anonymous_label: Literal["A", "B"]
    grader_lane: Literal[1, 2]
    baseline_fingerprint: Hash
    report_fingerprint: Hash
    ordinary_fragments: tuple[OrdinaryGradeFragmentV22, ...] = Field(max_length=_MAX_FRAGMENTS)
    contested_fragments: tuple[ContestedGradeFragmentV22, ...] = Field(max_length=_MAX_FRAGMENTS)
    aggregate_fingerprint: Hash

    @model_validator(mode="after")
    def validate_aggregate_bindings(self, info: ValidationInfo) -> Self:
        context = info.context
        inventories = None if context is None else context.get("grade_inventories")
        if isinstance(inventories, dict):
            inventory = inventories.get((self.anonymous_label, self.grader_lane))
            if isinstance(inventory, tuple) and len(inventory) == 2:
                context = {
                    "ordinary_grade_batches": inventory[0],
                    "contested_requirements": inventory[1],
                }
        if (
            context is None
            or "ordinary_grade_batches" not in context
            or "contested_requirements" not in context
        ):
            raise ValueError("validated controller grade inventories are required")
        batches = context["ordinary_grade_batches"]
        contested_requirements = context["contested_requirements"]
        if not isinstance(batches, (list, tuple)) or any(
            not isinstance(item, OrdinaryGradeBatchV22) for item in batches
        ):
            raise ValueError("ordinary_grade_batches validation context is invalid")
        if not isinstance(contested_requirements, (list, tuple)) or any(
            not isinstance(item, ContestedRequirementV22) for item in contested_requirements
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
        ordinary_grade_batches: tuple[OrdinaryGradeBatchV22, ...],
        contested_requirements: tuple[ContestedRequirementV22, ...],
    ) -> Self:
        try:
            batches = tuple(
                _strict_rehydrate_v22(
                    OrdinaryGradeBatchV22, item, location="ordinary grade inventory"
                )
                for item in ordinary_grade_batches
            )
            requirements = tuple(
                _strict_rehydrate_v22(
                    ContestedRequirementV22, item, location="contested requirement inventory"
                )
                for item in contested_requirements
            )
            raw = _wire_snapshot(value)
        except (TypeError, ValidationError, ValueError, RecursionError) as error:
            raise ValueError("grader aggregate inventories are invalid") from error
        if not isinstance(raw, dict):
            raise ValueError("grader aggregate is invalid")
        batch_refs = [item.batch_ref for item in batches]
        batch_items = [item for batch in batches for item in batch.requirement_ids]
        if (
            len(batches) > _MAX_FRAGMENTS
            or len(batch_refs) != len(set(batch_refs))
            or len(batch_items) > _MAX_COMPILED_ITEMS
            or len(batch_items) != len(set(batch_items))
        ):
            raise ValueError("ordinary grade inventory exceeds 640 compiled items or is invalid")
        ordinary = raw.get("ordinary_fragments", ())
        if not isinstance(ordinary, (list, tuple)):
            raise ValueError("ordinary grade fragments are invalid")
        raw_item_count = sum(
            len(item.get("requirement_grades", ())) for item in ordinary if isinstance(item, dict)
        )
        if raw_item_count > _MAX_COMPILED_ITEMS:
            raise ValueError("ordinary grade aggregate may contain at most 640 compiled items")
        return _strict_rehydrate_v22(
            cls,
            raw,
            context={
                "ordinary_grade_batches": batches,
                "contested_requirements": requirements,
            },
            location="grader aggregate",
        )


class ReconciledGradeV22(V22StrictModel):
    anonymous_label: Literal["A", "B"]
    absolute_disposition: AbsoluteDispositionV2
    reason_codes: tuple[str, ...] = ()
    grader_aggregates: tuple[GraderAggregateV22, GraderAggregateV22]
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
        if (first.anonymous_label, second.anonymous_label) != (
            self.anonymous_label,
            self.anonymous_label,
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
    def validate_for_baseline(cls, value: object, baseline: CanonicalBaselineV22) -> Self:
        try:
            checked = _strict_rehydrate_v22(
                CanonicalBaselineV22, baseline, location="canonical baseline"
            )
            raw = _wire_snapshot(value)
            if not isinstance(raw, dict):
                raise ValueError("reconciliation is invalid")
            inventories = {
                (label, lane): (
                    tuple(
                        OrdinaryGradeBatchV22(
                            batch_ref=f"GB-{label}-{lane}-{index // _MAX_FRAGMENT_ITEMS + 1:04d}",
                            requirement_ids=tuple(
                                item.requirement_id
                                for item in checked.requirements[
                                    index : index + _MAX_FRAGMENT_ITEMS
                                ]
                            ),
                        )
                        for index in range(0, len(checked.requirements), _MAX_FRAGMENT_ITEMS)
                    ),
                    checked.contested_requirements,
                )
                for label in ("A", "B")
                for lane in (1, 2)
            }
            return _strict_rehydrate_v22(
                cls,
                raw,
                context={"grade_inventories": inventories},
                location="reconciliation",
            )
        except (TypeError, ValidationError, ValueError, RecursionError) as error:
            raise ValueError("reconciliation is invalid") from error


class RubricV22(V22StrictModel):
    version: Literal["attorney-eval-v2.2"]
    importance_weights: dict[ImportanceV2, Annotated[int, Field(strict=True, ge=0)]]
    critical_recall_floor: float = Field(ge=0, le=1, strict=True)
    weighted_coverage_floor: float = Field(ge=0, le=1, strict=True)
    material_unsupported_assertions_allowed: int = Field(ge=0, strict=True)

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

    @field_validator("critical_recall_floor", "weighted_coverage_floor", mode="before")
    @classmethod
    def validate_float_thresholds(cls, value: object) -> object:
        if type(value) is not float:
            raise ValueError("rubric thresholds must be strict floats")
        return value

    @field_validator("material_unsupported_assertions_allowed", mode="before")
    @classmethod
    def validate_allowance(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("rubric allowance must be a strict integer")
        return value


class SensitivityRecordV22(V22StrictModel):
    anonymous_label: Literal["A", "B"]
    baseline_fingerprint: Hash
    reconciliation_fingerprint: Hash
    absolute_disposition: AbsoluteDispositionV2
    reason_codes: tuple[str, ...]
    outcome_determinative_contested_ids: tuple[str, ...] = ()
    sensitivity_fingerprint: Hash

    @field_validator("outcome_determinative_contested_ids")
    @classmethod
    def validate_contested_ids(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(not item.strip() for item in values) or len(values) != len(set(values)):
            raise ValueError("outcome-determinative contested IDs must be unique nonblank strings")
        return values


class EvaluationCallRecordV22(V22StrictModel):
    call_id: str = Field(strict=True)
    operation: EvaluatorOperationV22
    state: Literal["pending", "accepted"]
    attempt: Literal[1, 2]
    request_artifact_path: str = Field(strict=True)
    request_fingerprint: Hash
    response_artifact_path: str | None = Field(default=None, strict=True)
    response_fingerprint: Hash | None = None
    provider_name: str | None = Field(default=None, strict=True)
    model_name: str | None = Field(default=None, strict=True)
    judge_isolation: Literal["fresh_context", "scripted_fixture"] | None = None
    fragment_ordinal: int | None = Field(default=None, ge=1, le=_MAX_FRAGMENTS)
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
    def validate_call_record(self) -> Self:
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
        source_operations = {
            EvaluatorOperationV22.SOURCE_REVIEW_FRAGMENT,
            EvaluatorOperationV22.SOURCE_AUDIT_FRAGMENT,
        }
        if self.operation in source_operations:
            if self.fragment_ordinal is None:
                raise ValueError("source fragment calls require a fragment ordinal")
        elif self.fragment_ordinal is not None:
            raise ValueError("only source fragment calls may carry a fragment ordinal")
        grade_operations = {
            EvaluatorOperationV22.ORDINARY_GRADE_FRAGMENT,
            EvaluatorOperationV22.CONTESTED_GRADE_FRAGMENT,
        }
        if self.operation in grade_operations:
            if self.anonymous_label is None or self.grader_lane is None:
                raise ValueError("grade fragment calls require a report label and grader lane")
        elif self.anonymous_label is not None or self.grader_lane is not None:
            raise ValueError("only grade fragment calls may carry report labels or grader lanes")
        if self.operation is EvaluatorOperationV22.SOURCE_REFEREE_FRAGMENT:
            if self.dispute_id is None:
                raise ValueError("referee fragment calls require exactly one dispute ID")
        elif self.dispute_id is not None:
            raise ValueError("only referee fragment calls may carry a dispute ID")
        if self.operation is EvaluatorOperationV22.ORDINARY_GRADE_FRAGMENT:
            if self.batch_ref is None:
                raise ValueError(
                    "ordinary grade fragment calls require exactly one batch reference"
                )
            assert self.anonymous_label is not None and self.grader_lane is not None
            _validate_batch_binding(self.batch_ref, self.anonymous_label, self.grader_lane)
        elif self.batch_ref is not None:
            raise ValueError("only ordinary grade fragment calls may carry a batch reference")
        if self.operation is EvaluatorOperationV22.CONTESTED_GRADE_FRAGMENT:
            if self.contested_requirement_id is None:
                raise ValueError(
                    "contested grade fragment calls require exactly one contested requirement"
                )
        elif self.contested_requirement_id is not None:
            raise ValueError(
                "only contested grade fragment calls may carry a contested requirement"
            )
        return self


class EvaluationManifestV22(V22StrictModel):
    protocol_version: Literal["2.2"] = PROTOCOL_V22
    case_fingerprint: Hash
    case_envelope_hash: Hash
    build_fingerprint: Hash
    rubric_fingerprint: Hash
    compiler_contract_fingerprint: Hash
    compiler_version: Literal["semantic-compiler-v2.2"]
    source_review_aggregate_fingerprint: Hash | None = None
    source_audit_aggregate_fingerprint: Hash | None = None
    referee_aggregate_fingerprint: Hash | None = None
    baseline_fingerprint: Hash | None = None
    grader_aggregate_fingerprints: tuple[Hash, ...] = ()
    sensitivity_fingerprints: tuple[Hash, ...] = ()
    result_hash: Hash | None = None
    phase: EvaluationPhaseV22
    terminal_status: EvaluationTerminalStatusV22 | None = None
    calls: tuple[EvaluationCallRecordV22, ...]
    artifacts: tuple[ArtifactRecord, ...]
    referee_disputes: tuple[RefereeDisputeV22, ...]
    ordinary_grade_batches: tuple[OrdinaryGradeBatchV22, ...]
    manifest_fingerprint: Hash

    @model_validator(mode="after")
    def validate_manifest(self) -> Self:
        pending = [call for call in self.calls if call.state == "pending"]
        if len(pending) > 1:
            raise ValueError("a manifest may retain at most one pending request")
        call_ids = [call.call_id for call in self.calls]
        if len(call_ids) != len(set(call_ids)):
            raise ValueError("call IDs must be unique")
        paths = [artifact.artifact_path for artifact in self.artifacts]
        if paths != sorted(paths) or len(paths) != len(set(paths)):
            raise ValueError("artifacts must be uniquely path-sorted")
        for operation in (
            EvaluatorOperationV22.SOURCE_REVIEW_FRAGMENT,
            EvaluatorOperationV22.SOURCE_AUDIT_FRAGMENT,
        ):
            ordinals = [call.fragment_ordinal for call in self.calls if call.operation is operation]
            if ordinals != list(range(1, len(ordinals) + 1)):
                raise ValueError("source fragment call ordinals must be contiguous and ordered")
        expected = {
            EvaluationPhaseV22.COMPLETED: EvaluationTerminalStatusV22.COMPLETED,
            EvaluationPhaseV22.INCONCLUSIVE: EvaluationTerminalStatusV22.INCONCLUSIVE,
        }.get(self.phase)
        if self.terminal_status is not expected:
            raise ValueError("terminal phase and status must match exactly")
        if expected is not None and pending:
            raise ValueError("terminal manifests must not retain a pending request")
        return self


class EvaluationRunStateV22(V22StrictModel):
    schema_version: Literal["2.2"] = PROTOCOL_V22
    case_fingerprint: Hash
    phase: EvaluationPhaseV22
    current_call_id: str | None = Field(default=None, strict=True)
    terminal_status: EvaluationTerminalStatusV22 | None = None
    manifest_fingerprint: Hash | None = None

    _validate_call_id = field_validator("current_call_id")(_optional_nonblank)

    @model_validator(mode="after")
    def validate_terminal_state(self) -> Self:
        expected = {
            EvaluationPhaseV22.COMPLETED: EvaluationTerminalStatusV22.COMPLETED,
            EvaluationPhaseV22.INCONCLUSIVE: EvaluationTerminalStatusV22.INCONCLUSIVE,
        }.get(self.phase)
        if self.terminal_status is not expected:
            raise ValueError("terminal phase and status must match exactly")
        if expected is not None and self.current_call_id is not None:
            raise ValueError("terminal state must not retain a current call")
        return self


class ReportResultV22(V22StrictModel):
    anonymous_label: Literal["A", "B"]
    reconciliation: ReconciledGradeV22
    sensitivity: SensitivityRecordV22
    result_fingerprint: Hash


class ComparisonResultV22(V22StrictModel):
    """Role-bound comparison whose labels come from the frozen blind assignment."""

    disposition: ComparisonDispositionV2
    winner_label: Literal["A", "B"] | None = None
    candidate_label: Literal["A", "B"]
    comparator_label: Literal["A", "B"]
    rationale: str = Field(strict=True)

    _validate_rationale = field_validator("rationale")(_nonblank)

    @model_validator(mode="after")
    def validate_role_binding(self) -> Self:
        if {self.candidate_label, self.comparator_label} != {"A", "B"}:
            raise ValueError("comparison roles must bind distinct labels A and B")
        expected_winner = {
            ComparisonDispositionV2.CANDIDATE_WIN: self.candidate_label,
            ComparisonDispositionV2.COMPARATOR_WIN: self.comparator_label,
        }.get(self.disposition)
        if self.winner_label != expected_winner:
            raise ValueError("comparison winner must match the role-bound disposition")
        expected_rationale = {
            ComparisonDispositionV2.CANDIDATE_WIN: "Only the candidate report passed the rubric.",
            ComparisonDispositionV2.COMPARATOR_WIN: (
                "Only the comparator report passed the rubric."
            ),
            ComparisonDispositionV2.TIE: "Both reports passed the rubric.",
            ComparisonDispositionV2.NEITHER: "Neither report passed the rubric.",
            ComparisonDispositionV2.INCONCLUSIVE: "At least one report is inconclusive.",
        }[self.disposition]
        if self.rationale != expected_rationale:
            raise ValueError("comparison rationale must match its disposition")
        return self


def build_comparison_result_v22(
    *,
    candidate_label: Literal["A", "B"],
    comparator_label: Literal["A", "B"],
    dispositions: Mapping[Literal["A", "B"], AbsoluteDispositionV2],
) -> ComparisonResultV22:
    """Build the sole canonical comparison for two role-bound blind labels."""
    if {candidate_label, comparator_label} != {"A", "B"}:
        raise ValueError("comparison roles must bind distinct labels A and B")
    if set(dispositions) != {"A", "B"} or any(
        not isinstance(item, AbsoluteDispositionV2) for item in dispositions.values()
    ):
        raise ValueError("comparison dispositions must bind exact labels A and B")
    if AbsoluteDispositionV2.INCONCLUSIVE in dispositions.values():
        return ComparisonResultV22(
            disposition=ComparisonDispositionV2.INCONCLUSIVE,
            candidate_label=candidate_label,
            comparator_label=comparator_label,
            rationale="At least one report is inconclusive.",
        )
    passing = tuple(
        label for label in ("A", "B") if dispositions[label] is AbsoluteDispositionV2.PASS
    )
    if len(passing) == 1:
        winner = cast(Literal["A", "B"], passing[0])
        candidate_wins = winner == candidate_label
        return ComparisonResultV22(
            disposition=(
                ComparisonDispositionV2.CANDIDATE_WIN
                if candidate_wins
                else ComparisonDispositionV2.COMPARATOR_WIN
            ),
            winner_label=winner,
            candidate_label=candidate_label,
            comparator_label=comparator_label,
            rationale=(
                "Only the candidate report passed the rubric."
                if candidate_wins
                else "Only the comparator report passed the rubric."
            ),
        )
    return ComparisonResultV22(
        disposition=(
            ComparisonDispositionV2.TIE if passing else ComparisonDispositionV2.NEITHER
        ),
        candidate_label=candidate_label,
        comparator_label=comparator_label,
        rationale=(
            "Both reports passed the rubric." if passing else "Neither report passed the rubric."
        ),
    )


class EvaluationResultV22(V22StrictModel):
    schema_version: Literal["2.2"] = PROTOCOL_V22
    rubric: RubricV22
    baseline: CanonicalBaselineV22
    reports: tuple[ReportResultV22, ...]
    comparison: ComparisonResultV22 | None = None
    terminal_status: EvaluationTerminalStatusV22
    result_fingerprint: Hash

    @model_validator(mode="after")
    def validate_reports(self) -> Self:
        labels = [item.anonymous_label for item in self.reports]
        if labels not in ([], ["A"], ["A", "B"]):
            raise ValueError("reports must use unique fixed order A or A, B")
        if self.terminal_status is EvaluationTerminalStatusV22.COMPLETED and not self.reports:
            raise ValueError("completed results require at least one report")
        if self.terminal_status is EvaluationTerminalStatusV22.INCONCLUSIVE and not self.reports:
            raise ValueError("substantive inconclusive requires report evidence")
        if (self.comparison is not None) != (labels == ["A", "B"]):
            raise ValueError("comparison requires exactly two reports")
        return self


def validate_evaluator_request_v22(value: object) -> EvaluatorRequestV22:
    """Safely revalidate a raw or bypass-constructed request before issuing it."""
    if not isinstance(value, (EvaluatorRequestV22, dict)):
        raise ValueError("evaluator request must be an object")
    return _strict_rehydrate_v22(
        EvaluatorRequestV22, value, location="evaluator request"
    )


def _strict_response_v22(value: object) -> EvaluatorResponseV22:
    """Validate untrusted response shape before trusted wire work can fail."""
    try:
        raw = _wire_snapshot(value)
    except ValueError:
        raise _EvaluatorResponseValidationErrorV22(
            "evaluator response is invalid"
        ) from None
    if not isinstance(raw, dict):
        raise _EvaluatorResponseValidationErrorV22(
            "evaluator response is invalid"
        ) from None
    try:
        checked = EvaluatorResponseV22.model_validate(raw)
    except ValidationError:
        raise _EvaluatorResponseValidationErrorV22(
            "evaluator response is invalid"
        ) from None

    checked_raw = _wire_snapshot(checked)
    serialized = checked.model_dump(mode="json", warnings="error")
    if len(canonical_json_bytes(serialized)) > _MAX_WIRE_BYTES:
        raise _EvaluatorResponseValidationErrorV22(
            "evaluator response is invalid"
        ) from None
    if not _same_wire_value(raw, checked_raw, serialized):
        raise _EvaluatorResponseValidationErrorV22(
            "evaluator response is invalid"
        ) from None
    return checked


def validate_evaluator_response_v22(value: object) -> EvaluatorResponseV22:
    """Safely revalidate a raw or bypass-constructed response before consuming it."""
    if not isinstance(value, (EvaluatorResponseV22, dict)):
        raise _EvaluatorResponseValidationErrorV22(
            "evaluator response is invalid"
        ) from None
    return _strict_response_v22(value)
