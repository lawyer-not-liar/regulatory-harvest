"""Strict, report-blind contracts for evaluation-baseline-v1."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from regulatory_harvest.models.base import StrictModel
from regulatory_harvest.storage import sha256_digest

from .attorney_models import ArtifactRecord, EvaluationSource, RequestedAuthority
from .attorney_v2_models import (
    RequirementKindV2,
    ResolvedPassageV2,
    SemanticDependency,
    SemanticPassage,
)

BASELINE_PROTOCOL_V1: Literal["evaluation-baseline-v1"] = "evaluation-baseline-v1"
_HASH_PATTERN = r"^[0-9a-f]{64}$"
_PROPOSAL_REF_PATTERN = r"^PR-[0-9]{4}$"
_AUDIT_REF_PATTERN = r"^AUD-[0-9]{4}$"
_DISPUTE_REF_PATTERN = r"^DSP-[0-9]{4}$"
_REQUIREMENT_REF_PATTERN = r"^REQ-[0-9]{4}$"
_RELATIONSHIP_REF_PATTERN = r"^REL-[0-9]{4}$"
_MAX_FRAGMENT_ITEMS = 5
_MAX_FRAGMENTS = 128
_MAX_COMPILED_ITEMS = 640
_GENERIC_RATIONALES = frozenset(
    {"critical", "material", "supporting", "important", "self evident", "as labeled"}
)

Hash = Annotated[str, Field(pattern=_HASH_PATTERN, strict=True)]
ProposalRef = Annotated[str, Field(pattern=_PROPOSAL_REF_PATTERN, strict=True)]
AuditRef = Annotated[str, Field(pattern=_AUDIT_REF_PATTERN, strict=True)]
DisputeRef = Annotated[str, Field(pattern=_DISPUTE_REF_PATTERN, strict=True)]
RequirementRef = Annotated[str, Field(pattern=_REQUIREMENT_REF_PATTERN, strict=True)]
RelationshipRef = Annotated[str, Field(pattern=_RELATIONSHIP_REF_PATTERN, strict=True)]


def _nonblank(value: str) -> str:
    checked = value.strip()
    if not checked:
        raise ValueError("value must not be blank")
    return checked


def _optional_nonblank(value: str | None) -> str | None:
    return None if value is None else _nonblank(value)


def _wire_snapshot(value: object) -> object:
    """Rebuild raw model state so ``model_construct`` cannot skip validation."""
    if isinstance(value, BaseModel):
        raw = dict(object.__getattribute__(value, "__dict__"))
        extra = object.__getattribute__(value, "__pydantic_extra__")
        if extra:
            raw.update(extra)
        return {key: _wire_snapshot(item) for key, item in raw.items()}
    if type(value) is dict:
        return {key: _wire_snapshot(item) for key, item in value.items()}
    if type(value) is list:
        return [_wire_snapshot(item) for item in value]
    if type(value) is tuple:
        return tuple(_wire_snapshot(item) for item in value)
    return value


class _FrozenDict(dict[str, object]):
    @staticmethod
    def _immutable(*_: object, **__: object) -> None:
        raise TypeError("evaluation-baseline-v1 values are immutable")

    __setitem__ = _immutable
    __delitem__ = _immutable
    __ior__ = _immutable  # type: ignore[assignment]
    clear = _immutable
    pop = _immutable
    popitem = _immutable  # type: ignore[assignment]
    setdefault = _immutable
    update = _immutable


def _deep_freeze(value: object) -> object:
    if type(value) is dict:
        return _FrozenDict({key: _deep_freeze(item) for key, item in value.items()})
    if type(value) is list:
        return tuple(_deep_freeze(item) for item in value)
    if type(value) is tuple:
        return tuple(_deep_freeze(item) for item in value)
    return value


class BaselineStrictModel(StrictModel):
    """Immutable, closed values which rehydrate raw Pydantic state before validation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    @model_validator(mode="before")
    @classmethod
    def rehydrate_raw_model_state(cls, value: object) -> object:
        return _wire_snapshot(value)

    @model_validator(mode="after")
    def freeze_nested_values(self) -> Self:
        for field_name in type(self).model_fields:
            value = getattr(self, field_name)
            frozen = _deep_freeze(value)
            if frozen is not value:
                object.__setattr__(self, field_name, frozen)
        return self


class BaselineImportanceV1(StrEnum):
    CRITICAL = "critical"
    MATERIAL = "material"
    SUPPORTING = "supporting"


class ImportanceBasisV1(StrEnum):
    LEGAL_BOTTOM_LINE = "legal_bottom_line"
    APPLICABILITY = "applicability"
    OPERATIVE_STATUS = "operative_status"
    CORE_DUTY_OR_PROHIBITION = "core_duty_or_prohibition"
    ENFORCEMENT_EXPOSURE = "enforcement_exposure"
    REMEDY = "remedy"
    DISPOSITIVE_DEADLINE = "dispositive_deadline"
    ATTORNEY_BRIEFING = "attorney_briefing"
    IMPLEMENTATION_DECISION = "implementation_decision"
    EXPLANATORY_CONTEXT = "explanatory_context"
    IMPLEMENTATION_DETAIL = "implementation_detail"


_ALLOWED_IMPORTANCE_BASES: dict[BaselineImportanceV1, frozenset[ImportanceBasisV1]] = {
    BaselineImportanceV1.CRITICAL: frozenset(
        {
            ImportanceBasisV1.LEGAL_BOTTOM_LINE,
            ImportanceBasisV1.APPLICABILITY,
            ImportanceBasisV1.OPERATIVE_STATUS,
            ImportanceBasisV1.CORE_DUTY_OR_PROHIBITION,
            ImportanceBasisV1.ENFORCEMENT_EXPOSURE,
            ImportanceBasisV1.REMEDY,
            ImportanceBasisV1.DISPOSITIVE_DEADLINE,
        }
    ),
    BaselineImportanceV1.MATERIAL: frozenset(
        {ImportanceBasisV1.ATTORNEY_BRIEFING, ImportanceBasisV1.IMPLEMENTATION_DECISION}
    ),
    BaselineImportanceV1.SUPPORTING: frozenset(
        {ImportanceBasisV1.EXPLANATORY_CONTEXT, ImportanceBasisV1.IMPLEMENTATION_DETAIL}
    ),
}


def _generic_rationale(value: str) -> bool:
    return value.casefold().strip(". !") in _GENERIC_RATIONALES


def validate_importance_rationale_v1(
    importance: BaselineImportanceV1,
    basis: tuple[ImportanceBasisV1, ...],
    rationale: str,
) -> str:
    """Reject mismatched bases and empty labels without inferring legal meaning."""
    checked = _nonblank(rationale)
    if not set(basis).issubset(_ALLOWED_IMPORTANCE_BASES[importance]):
        raise ValueError("importance basis does not belong to the selected definition")
    if _generic_rationale(checked):
        raise ValueError(
            "importance rationale must state the legal consequence under the selected definition"
        )
    return checked


class BaselineOperationV1(StrEnum):
    SOURCE_REVIEW = "baseline_source_review"
    SOURCE_AUDIT = "baseline_source_audit"
    SOURCE_REFEREE = "baseline_source_referee"


class BaselinePhaseV1(StrEnum):
    CREATED = "created"
    SOURCE_REVIEW = "source_review"
    SOURCE_AUDIT = "source_audit"
    SOURCE_REFEREE = "source_referee"
    BASELINE_SEALED = "baseline_sealed"
    COMPLETED = "completed"
    INCONCLUSIVE = "inconclusive"


class BaselineInputV1(BaselineStrictModel):
    """The complete legal input; it intentionally has no candidate or report surface."""

    schema_version: Literal["baseline-input-v1"]
    sources: tuple[EvaluationSource, ...] = Field(min_length=1, max_length=_MAX_COMPILED_ITEMS)
    source_record_fingerprint: Hash
    question: str = Field(strict=True)
    jurisdiction: str = Field(strict=True)
    as_of: str = Field(strict=True)
    requested_authorities: tuple[RequestedAuthority, ...] = Field(min_length=1)
    client_facts: str | None = Field(strict=True)
    client_facts_binding: str = Field(strict=True)
    qualification_root: Hash
    qualification_receipt_fingerprint: Hash
    qualification_readiness: Literal["ADMITTED"]
    compiler_contract: dict[str, object]
    compiler_contract_fingerprint: Hash
    evaluation_rubric_version: str = Field(strict=True)
    evaluation_rubric_bytes: bytes = Field(strict=True)
    evaluation_rubric_fingerprint: Hash
    importance_policy_version: Literal["importance-policy-v1"]
    importance_policy_bytes: bytes = Field(strict=True)
    importance_policy_fingerprint: Hash
    legal_input_fingerprint: Hash

    _validate_text = field_validator(
        "question", "jurisdiction", "as_of", "evaluation_rubric_version"
    )(_nonblank)

    @field_validator("sources", mode="before")
    @classmethod
    def validate_sources_from_raw_values(cls, value: object) -> tuple[EvaluationSource, ...]:
        if not isinstance(value, (tuple, list)):
            raise ValueError("sources must be a tuple")
        return tuple(EvaluationSource.model_validate(_wire_snapshot(item)) for item in value)

    @field_validator("requested_authorities", mode="before")
    @classmethod
    def validate_authorities_from_raw_values(cls, value: object) -> tuple[RequestedAuthority, ...]:
        if not isinstance(value, (tuple, list)):
            raise ValueError("requested_authorities must be a tuple")
        return tuple(RequestedAuthority.model_validate(_wire_snapshot(item)) for item in value)

    @model_validator(mode="after")
    def validate_bindings(self) -> Self:
        if self.client_facts is None:
            if self.client_facts_binding != "explicit-null":
                raise ValueError("client facts without bytes require explicit-null binding")
        else:
            expected = f"sha256:{sha256_digest(self.client_facts.encode('utf-8'))}"
            if self.client_facts_binding != expected:
                raise ValueError("client facts binding must match the exact UTF-8 bytes")
        source_ids = {source.source_id for source in self.sources}
        if any(
            not set(authority.source_ids).issubset(source_ids)
            for authority in self.requested_authorities
        ):
            raise ValueError("requested authorities must reference only baseline input sources")
        return self


class BaselineProposalV1(BaselineStrictModel):
    statement: str = Field(strict=True)
    kind: RequirementKindV2
    importance: BaselineImportanceV1
    importance_basis: tuple[ImportanceBasisV1, ...] = Field(min_length=1)
    importance_rationale: str = Field(strict=True)
    passages: tuple[SemanticPassage, ...] = Field(min_length=1, max_length=_MAX_FRAGMENT_ITEMS)
    dependency: SemanticDependency | None = None
    confidence: Literal["clear", "ambiguous", "unresolved"]
    substantive_rationale: str = Field(strict=True)

    _validate_text = field_validator("statement", "substantive_rationale")(_nonblank)

    @model_validator(mode="after")
    def validate_importance(self) -> Self:
        checked = validate_importance_rationale_v1(
            self.importance, self.importance_basis, self.importance_rationale
        )
        object.__setattr__(self, "importance_rationale", checked)
        return self


class IndexedBaselineProposalV1(BaselineStrictModel):
    proposal_ref: ProposalRef
    proposal: BaselineProposalV1


class BaselineReviewFragmentV1(BaselineStrictModel):
    schema_version: Literal["evaluation-baseline-v1"] = BASELINE_PROTOCOL_V1
    proposals: tuple[BaselineProposalV1, ...] = Field(max_length=_MAX_FRAGMENT_ITEMS)
    review_complete: bool

    @model_validator(mode="after")
    def validate_progress(self) -> Self:
        if not self.review_complete and not self.proposals:
            raise ValueError("nonfinal source-review fragments require at least one proposal")
        return self


class AcceptedBaselineReviewFragmentV1(BaselineStrictModel):
    fragment_ordinal: int = Field(ge=1, le=_MAX_FRAGMENTS, strict=True)
    request_fingerprint: Hash
    response_fingerprint: Hash
    payload: BaselineReviewFragmentV1


class BaselineReviewAggregateV1(BaselineStrictModel):
    fragments: tuple[AcceptedBaselineReviewFragmentV1, ...] = Field(
        min_length=1, max_length=_MAX_FRAGMENTS
    )
    proposals: tuple[IndexedBaselineProposalV1, ...] = Field(max_length=_MAX_COMPILED_ITEMS)
    fragment_fingerprints: tuple[Hash, ...] = Field(max_length=_MAX_FRAGMENTS)
    aggregate_fingerprint: Hash

    @model_validator(mode="after")
    def validate_inventory(self) -> Self:
        refs = [item.proposal_ref for item in self.proposals]
        if len(refs) != len(set(refs)):
            raise ValueError("baseline review proposal references must be unique")
        if len(self.fragment_fingerprints) != len(set(self.fragment_fingerprints)):
            raise ValueError("baseline review fragment fingerprints must be unique")
        return self


class ImportanceAuditFindingV1(BaselineStrictModel):
    proposal_ref: ProposalRef
    reviewed_importance: BaselineImportanceV1
    reviewed_importance_basis: tuple[ImportanceBasisV1, ...] = Field(min_length=1)
    importance_rationale: str = Field(strict=True)
    disposition: Literal["agree", "correct"]

    @model_validator(mode="after")
    def validate_importance(self) -> Self:
        checked = validate_importance_rationale_v1(
            self.reviewed_importance, self.reviewed_importance_basis, self.importance_rationale
        )
        object.__setattr__(self, "importance_rationale", checked)
        return self


class BaselineAuditConcernV1(BaselineStrictModel):
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
    correction: BaselineProposalV1 | None = None

    _validate_explanation = field_validator("explanation")(_nonblank)

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


class BaselineAuditFragmentV1(BaselineStrictModel):
    schema_version: Literal["evaluation-baseline-v1"] = BASELINE_PROTOCOL_V1
    concerns: tuple[BaselineAuditConcernV1, ...] = Field(max_length=_MAX_FRAGMENT_ITEMS)
    importance_findings: tuple[ImportanceAuditFindingV1, ...] = Field(
        max_length=_MAX_FRAGMENT_ITEMS
    )
    audit_complete: bool

    @model_validator(mode="after")
    def validate_progress(self) -> Self:
        if not self.audit_complete and not (self.concerns or self.importance_findings):
            raise ValueError("nonfinal source-audit fragments require at least one finding")
        return self


class AcceptedBaselineAuditFragmentV1(BaselineStrictModel):
    fragment_ordinal: int = Field(ge=1, le=_MAX_FRAGMENTS, strict=True)
    request_fingerprint: Hash
    response_fingerprint: Hash
    payload: BaselineAuditFragmentV1


class BaselineAuditAggregateV1(BaselineStrictModel):
    fragments: tuple[AcceptedBaselineAuditFragmentV1, ...] = Field(
        min_length=1, max_length=_MAX_FRAGMENTS
    )
    concerns: tuple[BaselineAuditConcernV1, ...] = Field(max_length=_MAX_COMPILED_ITEMS)
    importance_findings: tuple[ImportanceAuditFindingV1, ...] = Field(
        max_length=_MAX_COMPILED_ITEMS
    )
    fragment_fingerprints: tuple[Hash, ...] = Field(max_length=_MAX_FRAGMENTS)
    aggregate_fingerprint: Hash


class BaselineDisputeV1(BaselineStrictModel):
    dispute_id: DisputeRef
    dispute_fingerprint: Hash
    target_proposal_ref: ProposalRef | None = None
    reviewer_proposal: BaselineProposalV1 | None = None
    auditor_concern: BaselineAuditConcernV1 | None = None
    importance_finding: ImportanceAuditFindingV1 | None = None

    @model_validator(mode="after")
    def validate_alternatives(self) -> Self:
        if self.auditor_concern is None and self.importance_finding is None:
            raise ValueError("baseline disputes require an auditor alternative")
        return self


class BaselineRefereeDecisionV1(BaselineStrictModel):
    dispute_id: DisputeRef
    decision: Literal["accept_reviewer", "accept_auditor", "unresolved"]
    passages: tuple[SemanticPassage, ...] = Field(min_length=1, max_length=_MAX_FRAGMENT_ITEMS)
    importance: BaselineImportanceV1
    importance_basis: tuple[ImportanceBasisV1, ...] = Field(min_length=1)
    importance_rationale: str = Field(strict=True)
    substantive_rationale: str = Field(strict=True)

    _validate_substantive_rationale = field_validator("substantive_rationale")(_nonblank)

    @model_validator(mode="after")
    def validate_importance(self) -> Self:
        checked = validate_importance_rationale_v1(
            self.importance, self.importance_basis, self.importance_rationale
        )
        object.__setattr__(self, "importance_rationale", checked)
        return self


class AcceptedBaselineRefereeFragmentV1(BaselineStrictModel):
    dispute_id: DisputeRef
    dispute_fingerprint: Hash
    response_fingerprint: Hash
    decision: BaselineRefereeDecisionV1

    @model_validator(mode="after")
    def validate_binding(self) -> Self:
        if self.decision.dispute_id != self.dispute_id:
            raise ValueError("referee decision ID must match its dispute")
        return self


class BaselineRefereeAggregateV1(BaselineStrictModel):
    fragments: tuple[AcceptedBaselineRefereeFragmentV1, ...] = Field(max_length=_MAX_COMPILED_ITEMS)
    aggregate_fingerprint: Hash


class BaselineEvaluatorRequestV1(BaselineStrictModel):
    schema_version: Literal["evaluation-baseline-v1"] = BASELINE_PROTOCOL_V1
    operation: BaselineOperationV1
    request_fingerprint: Hash
    system_instructions: str = Field(strict=True)
    json_schema: dict[str, object]
    payload: dict[str, object]
    safe_metadata: dict[str, str] = Field(default_factory=dict)

    _validate_instructions = field_validator("system_instructions")(_nonblank)


class BaselineEvaluatorResponseV1(BaselineStrictModel):
    schema_version: Literal["evaluation-baseline-v1"] = BASELINE_PROTOCOL_V1
    operation: BaselineOperationV1
    request_fingerprint: Hash
    provider_name: str = Field(strict=True)
    model_name: str = Field(strict=True)
    judge_isolation: Literal["fresh_context", "scripted_fixture"]
    payload: dict[str, object]

    _validate_names = field_validator("provider_name", "model_name")(_nonblank)


class BaselineRequirementV1(BaselineStrictModel):
    requirement_id: RequirementRef
    canonical_order: int = Field(ge=0, strict=True)
    statement: str = Field(strict=True)
    kind: RequirementKindV2
    importance: BaselineImportanceV1
    importance_basis: tuple[ImportanceBasisV1, ...] = Field(min_length=1)
    importance_rationale: str = Field(strict=True)
    passages: tuple[ResolvedPassageV2, ...] = Field(min_length=1)
    dependency: SemanticDependency | None = None
    confidence: Literal["clear", "ambiguous", "unresolved"]
    substantive_rationale: str = Field(strict=True)

    _validate_text = field_validator("statement", "substantive_rationale")(_nonblank)

    @model_validator(mode="after")
    def validate_importance(self) -> Self:
        checked = validate_importance_rationale_v1(
            self.importance, self.importance_basis, self.importance_rationale
        )
        object.__setattr__(self, "importance_rationale", checked)
        return self


class BaselineRelationshipV1(BaselineStrictModel):
    relationship_id: RelationshipRef
    relationship: Literal["depends_on", "exception_to", "defines", "enforced_by"]
    source_requirement_id: RequirementRef
    target_requirement_id: RequirementRef


class ContestedBaselineRequirementV1(BaselineStrictModel):
    contested_requirement_id: str = Field(pattern=r"^CONT-[0-9]{4}$", strict=True)
    reviewer_alternative: BaselineRequirementV1 | None = None
    auditor_alternative: BaselineRequirementV1 | None = None
    unresolved_reason: Literal[
        "SOURCE_AMBIGUITY", "SOURCE_CONFLICT", "SOURCE_GAP", "BOTH_POSITIONS_UNSUPPORTED"
    ]
    importance: BaselineImportanceV1
    importance_basis: tuple[ImportanceBasisV1, ...] = Field(min_length=1)
    importance_rationale: str = Field(strict=True)
    substantive_rationale: str = Field(strict=True)
    referee_fragment_fingerprint: Hash

    _validate_substantive_rationale = field_validator("substantive_rationale")(_nonblank)

    @model_validator(mode="after")
    def validate_contest(self) -> Self:
        if self.reviewer_alternative is None and self.auditor_alternative is None:
            raise ValueError("contested requirements require at least one alternative")
        checked = validate_importance_rationale_v1(
            self.importance, self.importance_basis, self.importance_rationale
        )
        object.__setattr__(self, "importance_rationale", checked)
        return self


class BaselineProvenanceV1(BaselineStrictModel):
    legal_input_fingerprint: Hash
    source_review_aggregate_fingerprint: Hash
    source_audit_aggregate_fingerprint: Hash
    source_referee_aggregate_fingerprint: Hash
    importance_policy_fingerprint: Hash
    compiler_contract_fingerprint: Hash


class CanonicalBaselineV1(BaselineStrictModel):
    protocol_version: Literal["evaluation-baseline-v1"] = BASELINE_PROTOCOL_V1
    legal_input_fingerprint: Hash
    requirements: tuple[BaselineRequirementV1, ...]
    relationships: tuple[BaselineRelationshipV1, ...] = ()
    contested_requirements: tuple[ContestedBaselineRequirementV1, ...] = ()
    provenance: BaselineProvenanceV1
    prior_baseline_fingerprint: Hash | None = None
    correction_record_fingerprint: Hash | None = None
    baseline_fingerprint: Hash

    @model_validator(mode="after")
    def validate_baseline(self) -> Self:
        requirement_ids = [item.requirement_id for item in self.requirements]
        orders = [item.canonical_order for item in self.requirements]
        if len(requirement_ids) != len(set(requirement_ids)) or orders != list(range(len(orders))):
            raise ValueError("canonical requirements must use unique contiguous zero-based order")
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
            raise ValueError("canonical relationships must identify baseline requirements")
        edges = [
            (item.relationship, item.source_requirement_id, item.target_requirement_id)
            for item in self.relationships
        ]
        if len(edges) != len(set(edges)):
            raise ValueError("canonical relationship semantic edges must be unique")
        if self.provenance.legal_input_fingerprint != self.legal_input_fingerprint:
            raise ValueError("baseline provenance must bind the legal input")
        return self


class BaselineCorrectionActionV1(BaselineStrictModel):
    action: Literal[
        "add_requirement",
        "replace_requirement",
        "remove_requirement",
        "add_relationship",
        "replace_relationship",
        "remove_relationship",
    ]
    requirement_id: RequirementRef | None = None
    relationship_id: RelationshipRef | None = None
    requirement: BaselineRequirementV1 | None = None
    relationship: BaselineRelationshipV1 | None = None

    @model_validator(mode="after")
    def validate_action_payload(self) -> Self:
        requirement_actions = {"add_requirement", "replace_requirement", "remove_requirement"}
        replacement_required = {
            "add_requirement",
            "replace_requirement",
            "add_relationship",
            "replace_relationship",
        }
        is_requirement = self.action in requirement_actions
        if is_requirement != (self.relationship_id is None and self.relationship is None):
            raise ValueError("correction action has a mismatched typed payload")
        if not is_requirement != (self.requirement_id is None and self.requirement is None):
            raise ValueError("correction action has a mismatched typed payload")
        if self.action in replacement_required and (
            self.requirement is None and self.relationship is None
        ):
            raise ValueError("correction replacement actions require one replacement")
        if self.action not in replacement_required and (
            self.requirement is not None or self.relationship is not None
        ):
            raise ValueError("correction removal actions must omit replacements")
        return self


class BaselineCorrectionRecordV1(BaselineStrictModel):
    schema_version: Literal["baseline-correction-v1"]
    prior_baseline_root: Hash
    prior_baseline_fingerprint: Hash
    correction_id: str = Field(pattern=r"^CORR-[0-9]{4}$", strict=True)
    actions: tuple[BaselineCorrectionActionV1, ...] = Field(min_length=1)
    reason: str = Field(strict=True)
    attorney_approval: dict[str, str]
    correction_fingerprint: Hash

    _validate_reason = field_validator("reason")(_nonblank)

    @field_validator("attorney_approval")
    @classmethod
    def validate_approval(cls, value: dict[str, str]) -> dict[str, str]:
        if set(value) != {"approved_by", "approved_at", "approval_statement"}:
            raise ValueError("attorney approval has an unexpected shape")
        if any(type(item) is not str or not item.strip() for item in value.values()):
            raise ValueError("attorney approval values must be nonblank strings")
        return value


class BaselineManifestV1(BaselineStrictModel):
    protocol_version: Literal["evaluation-baseline-v1"] = BASELINE_PROTOCOL_V1
    legal_input_fingerprint: Hash
    baseline_fingerprint: Hash | None = None
    phase: BaselinePhaseV1
    terminal_status: Literal["COMPLETED", "INCONCLUSIVE"] | None = None
    artifacts: tuple[ArtifactRecord, ...]
    manifest_fingerprint: Hash


class BaselineRunStateV1(BaselineStrictModel):
    schema_version: Literal["evaluation-baseline-v1"] = BASELINE_PROTOCOL_V1
    legal_input_fingerprint: Hash
    phase: BaselinePhaseV1
    current_call_id: str | None = Field(default=None, strict=True)
    terminal_status: Literal["COMPLETED", "INCONCLUSIVE"] | None = None
    manifest_fingerprint: Hash | None = None

    _validate_call = field_validator("current_call_id")(_optional_nonblank)


class BaselineReuseDecisionV1(BaselineStrictModel):
    reusable: bool
    reason_codes: tuple[str, ...] = ()

    @field_validator("reason_codes")
    @classmethod
    def validate_reason_codes(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        checked = tuple(_nonblank(value) for value in values)
        if checked != tuple(sorted(set(checked))):
            raise ValueError("reuse reason codes must be sorted and unique")
        return checked

    @model_validator(mode="after")
    def validate_reuse_result(self) -> Self:
        if self.reusable != (not self.reason_codes):
            raise ValueError("reuse decisions must use reasons exactly when reuse is refused")
        return self


class BaselineVerificationV1(BaselineStrictModel):
    valid: bool
    issues: tuple[str, ...] = ()

    @field_validator("issues")
    @classmethod
    def validate_issues(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        checked = tuple(_nonblank(value) for value in values)
        if checked != tuple(sorted(set(checked))):
            raise ValueError("verification issues must be sorted and unique")
        return checked

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        if self.valid != (not self.issues):
            raise ValueError("verification must contain issues exactly when invalid")
        return self


def strict_baseline_model_v1(
    model: type[BaselineStrictModel], value: object
) -> BaselineStrictModel:
    """Revalidate an untrusted baseline value without accepting constructed instances."""
    try:
        return model.model_validate(_wire_snapshot(value))
    except (TypeError, ValidationError, ValueError, RecursionError) as error:
        raise ValueError("baseline model is invalid") from error
