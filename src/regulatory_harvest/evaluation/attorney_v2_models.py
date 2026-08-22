"""Strict, semantic-first contracts for simplified evaluator protocol 2.0.

The models in this module deliberately distinguish LLM-authored semantic
responses from deterministic canonical artifacts.  Protocol roles may state
what the sources say; only deterministic code may allocate canonical IDs,
ordering, fingerprints, or scores.
"""

from __future__ import annotations

import hashlib
import math
import re
from enum import StrEnum
from typing import Literal, Self, cast

from pydantic import (
    ConfigDict,
    Field,
    SkipValidation,
    ValidationInfo,
    field_validator,
    model_validator,
)

from regulatory_harvest.models.base import StrictModel
from regulatory_harvest.storage import canonical_json_bytes

from .attorney_models import ArtifactRecord

PROTOCOL_V2: Literal["2.0"] = "2.0"
_HASH_PATTERN = r"^[0-9a-f]{64}$"
_PROPOSAL_REF_PATTERN = r"^P[0-9]{4}$"
_DISPUTE_REF_PATTERN = r"^D[0-9]{4}$"
_REQUIREMENT_REF_PATTERN = r"^REQ-[0-9]{4}$"
_RELATIONSHIP_REF_PATTERN = r"^REL-[0-9]{4}$"
_MAX_JSON_BYTES = 16 * 1024 * 1024
_MAX_JSON_DEPTH = 64
_MAX_ROLE_RESPONSE_ITEMS = 128


class _CanonicalJsonEngineErrorV2(RuntimeError):
    """Canonical serialization failed after the JSON tree was proven valid."""


class V2StrictModel(StrictModel):
    """Strict immutable behavior limited to protocol-2.0 contracts."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    @model_validator(mode="after")
    def freeze_nested_values(self) -> Self:
        for field_name in type(self).model_fields:
            value = getattr(self, field_name)
            frozen = _deep_freeze(value)
            if frozen is not value:
                object.__setattr__(self, field_name, frozen)
        return self


class EvaluatorOperationV2(StrEnum):
    SOURCE_REVIEW = "source_review"
    SOURCE_AUDIT = "source_audit"
    SOURCE_REFEREE = "source_referee"
    GRADE_REPORT = "grade_report"


class EvaluationPhaseV2(StrEnum):
    CREATED = "created"
    SOURCE_REVIEW = "source_review"
    SOURCE_AUDIT = "source_audit"
    SOURCE_REFEREE = "source_referee"
    BASELINE_SEALED = "baseline_sealed"
    GRADE_REPORT = "grade_report"
    AGGREGATE = "aggregate"
    COMPLETED = "completed"
    INCONCLUSIVE = "inconclusive"


class EvaluationTerminalStatusV2(StrEnum):
    COMPLETED = "completed"
    INCONCLUSIVE = "inconclusive"


class AbsoluteDispositionV2(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"


class ComparisonDispositionV2(StrEnum):
    CANDIDATE_WIN = "candidate_win"
    COMPARATOR_WIN = "comparator_win"
    TIE = "tie"
    NEITHER = "neither"
    INCONCLUSIVE = "inconclusive"


class RequirementKindV2(StrEnum):
    OBLIGATION = "obligation"
    PROHIBITION = "prohibition"
    PERMISSION = "permission"
    EXCEPTION = "exception"
    DEFINITION = "definition"
    DEADLINE = "deadline"
    ENFORCEMENT = "enforcement"
    GAP = "gap"


class ImportanceV2(StrEnum):
    CRITICAL = "critical"
    MATERIAL = "material"
    SUPPORTING = "supporting"


def _nonblank(value: str) -> str:
    if not value.strip():
        raise ValueError("value must not be blank")
    return value


def _optional_nonblank(value: str | None) -> str | None:
    return None if value is None else _nonblank(value)


class _FrozenJsonDict(dict[str, object]):
    """A JSON-object snapshot that retains ordinary JSON serialization behavior."""

    @staticmethod
    def _immutable(*_: object, **__: object) -> None:
        raise TypeError("protocol-2.0 JSON snapshots are immutable")

    __setitem__ = _immutable
    __delitem__ = _immutable
    __ior__ = _immutable  # type: ignore[assignment]
    clear = _immutable
    pop = _immutable
    popitem = _immutable  # type: ignore[assignment]
    setdefault = _immutable
    update = _immutable


class _FrozenJsonList(list[object]):
    """A JSON-array snapshot that keeps list-shaped wire serialization."""

    @staticmethod
    def _immutable(*_: object, **__: object) -> None:
        raise TypeError("protocol-2.0 JSON snapshots are immutable")

    __setitem__ = _immutable
    __delitem__ = _immutable
    __iadd__ = _immutable  # type: ignore[assignment]
    __imul__ = _immutable  # type: ignore[assignment]
    append = _immutable
    clear = _immutable
    extend = _immutable
    insert = _immutable
    pop = _immutable
    remove = _immutable
    reverse = _immutable
    sort = _immutable


def _deep_freeze(value: object) -> object:
    if type(value) is dict:
        return _FrozenJsonDict({key: _deep_freeze(item) for key, item in value.items()})
    if type(value) is list:
        return _FrozenJsonList([_deep_freeze(item) for item in value])
    if type(value) is tuple:
        return tuple(_deep_freeze(item) for item in value)
    return value


def _thaw_json(value: object) -> object:
    if isinstance(value, dict):
        return {key: _thaw_json(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_thaw_json(item) for item in value]
    return value


def _validated_json_snapshot(value: object, *, location: str) -> object:
    if type(value) is dict:
        _validate_json_object(value, location=location)
        return _thaw_json(value)
    if isinstance(value, _FrozenJsonDict):
        snapshot = _thaw_json(value)
        _validate_json_object(snapshot, location=location)
        return snapshot
    return _validate_json_object(value, location=location)


def _validate_json_tree(value: object, *, location: str) -> None:
    """Reject non-JSON, cyclic, over-deep, or oversized untrusted trees."""
    pending: list[tuple[object, int, bool]] = [(value, 1, False)]
    active: set[int] = set()
    while pending:
        current, depth, exiting = pending.pop()
        if depth > _MAX_JSON_DEPTH:
            raise ValueError(f"{location} exceeds the nesting-depth limit")
        if current is None or type(current) in {str, bool, int}:
            continue
        if type(current) is float:
            if not math.isfinite(current):
                raise ValueError(f"{location} contains a non-finite number")
            continue
        if type(current) not in {dict, list}:
            raise ValueError(f"{location} contains a non-JSON value")
        identity = id(current)
        if exiting:
            active.remove(identity)
            continue
        if identity in active:
            raise ValueError(f"{location} contains a container cycle")
        active.add(identity)
        pending.append((current, depth, True))
        if type(current) is dict:
            mapping = cast(dict[object, object], current)
            if any(type(key) is not str for key in mapping):
                raise ValueError(f"{location} contains a non-string object key")
            pending.extend((child, depth + 1, False) for child in mapping.values())
        else:
            pending.extend((child, depth + 1, False) for child in cast(list[object], current))
    try:
        encoded = canonical_json_bytes(value)
    except (TypeError, ValueError, RecursionError) as error:
        raise _CanonicalJsonEngineErrorV2(
            f"{location} canonical JSON serialization failed"
        ) from error
    if len(encoded) > _MAX_JSON_BYTES:
        raise ValueError(f"{location} exceeds the size limit")


def _validate_json_object(value: object, *, location: str) -> object:
    if type(value) is not dict:
        raise ValueError(f"{location} must be an object")
    _validate_json_tree(value, location=location)
    return value


def _unique_passages(passages: list[SemanticPassage]) -> list[SemanticPassage]:
    identities = [(passage.source_id, passage.quote) for passage in passages]
    if len(identities) != len(set(identities)):
        raise ValueError("passages must be unique")
    return passages


def _validate_known_refs(
    actual: set[str],
    info: ValidationInfo,
    *,
    context_key: str,
    message: str,
    allow_subset: bool = False,
    required: bool = False,
    required_message: str | None = None,
) -> None:
    context = info.context
    if context is None or context_key not in context:
        if required:
            raise ValueError(required_message or "validated engine references are required")
        return
    expected = context[context_key]
    if not isinstance(expected, (set, frozenset, list, tuple)) or any(
        not isinstance(item, str) for item in expected
    ):
        raise ValueError(f"{context_key} validation context is invalid")
    expected_refs = set(expected)
    valid = actual.issubset(expected_refs) if allow_subset else actual == expected_refs
    if not valid:
        raise ValueError(message)


class SemanticPassage(V2StrictModel):
    source_id: str = Field(strict=True)
    quote: str = Field(strict=True)

    _validate_text = field_validator("source_id", "quote")(_nonblank)


class SemanticDependency(V2StrictModel):
    relationship: Literal["depends_on", "exception_to", "defines", "enforced_by"]
    target_statement: str = Field(strict=True)

    _validate_target = field_validator("target_statement")(_nonblank)


class SemanticProposal(V2StrictModel):
    statement: str = Field(strict=True)
    kind: RequirementKindV2
    importance: ImportanceV2
    passages: list[SemanticPassage] = Field(min_length=1, max_length=_MAX_ROLE_RESPONSE_ITEMS)
    dependency: SemanticDependency | None = None
    confidence: Literal["clear", "ambiguous", "unresolved"]
    rationale: str = Field(strict=True)

    _validate_text = field_validator("statement", "rationale")(_nonblank)
    _validate_passages = field_validator("passages")(_unique_passages)


class SourceReviewV2(V2StrictModel):
    schema_version: Literal["2.0"] = PROTOCOL_V2
    proposals: list[SemanticProposal] = Field(max_length=_MAX_ROLE_RESPONSE_ITEMS)


class IndexedProposalV2(V2StrictModel):
    proposal_ref: str = Field(pattern=_PROPOSAL_REF_PATTERN, strict=True)
    proposal: SemanticProposal


class AuditConcernV2(V2StrictModel):
    target_proposal_ref: str | None = Field(
        default=None, pattern=_PROPOSAL_REF_PATTERN, strict=True
    )
    concern_type: Literal[
        "omission",
        "incorrect_statement",
        "incorrect_evidence",
        "incorrect_relationship",
        "ambiguity",
    ]
    passages: list[SemanticPassage] = Field(min_length=1, max_length=_MAX_ROLE_RESPONSE_ITEMS)
    explanation: str = Field(strict=True)
    correction: SemanticProposal | None = None

    _validate_passages = field_validator("passages")(_unique_passages)
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


class SourceAuditV2(V2StrictModel):
    schema_version: Literal["2.0"] = PROTOCOL_V2
    concerns: list[AuditConcernV2] = Field(max_length=_MAX_ROLE_RESPONSE_ITEMS)

    @model_validator(mode="after")
    def validate_known_targets(self, info: ValidationInfo) -> Self:
        targets = {
            concern.target_proposal_ref
            for concern in self.concerns
            if concern.target_proposal_ref is not None
        }
        _validate_known_refs(
            targets,
            info,
            context_key="proposal_refs",
            message="audit concerns must target only engine-issued proposal references",
            allow_subset=True,
            required=True,
            required_message="validated engine proposal references are required",
        )
        return self

    @classmethod
    def validate_for_indexed_proposals(
        cls, value: object, indexed: tuple[IndexedProposalV2, ...]
    ) -> Self:
        """Validate an audit against the engine's request-local proposal inventory."""
        proposal_refs = [proposal.proposal_ref for proposal in indexed]
        if len(proposal_refs) != len(set(proposal_refs)):
            raise ValueError("indexed proposals must use unique proposal references")
        return cls.model_validate(value, context={"proposal_refs": set(proposal_refs)})


class MaterialDisputeV2(V2StrictModel):
    dispute_id: str = Field(pattern=_DISPUTE_REF_PATTERN, strict=True)
    target_proposal_ref: str | None = Field(
        default=None, pattern=_PROPOSAL_REF_PATTERN, strict=True
    )
    reviewer_proposal: SemanticProposal | None = None
    audit_concern: AuditConcernV2

    @model_validator(mode="after")
    def validate_dispute_target(self) -> Self:
        if self.target_proposal_ref != self.audit_concern.target_proposal_ref:
            raise ValueError("dispute target must match its audit concern target")
        return self


class SourceRefereeDecisionV2(V2StrictModel):
    dispute_id: str = Field(pattern=_DISPUTE_REF_PATTERN, strict=True)
    decision: Literal["accept_reviewer", "accept_auditor", "unresolved"]
    passages: list[SemanticPassage] = Field(min_length=1, max_length=_MAX_ROLE_RESPONSE_ITEMS)
    rationale: str = Field(strict=True)

    _validate_passages = field_validator("passages")(_unique_passages)
    _validate_rationale = field_validator("rationale")(_nonblank)


class SourceRefereeResponseV2(V2StrictModel):
    schema_version: Literal["2.0"] = PROTOCOL_V2
    decisions: list[SourceRefereeDecisionV2] = Field(max_length=_MAX_ROLE_RESPONSE_ITEMS)

    @model_validator(mode="after")
    def validate_known_disputes(self, info: ValidationInfo) -> Self:
        dispute_ids = [decision.dispute_id for decision in self.decisions]
        if len(dispute_ids) != len(set(dispute_ids)):
            raise ValueError("referee decisions must use unique dispute IDs")
        _validate_known_refs(
            set(dispute_ids),
            info,
            context_key="dispute_ids",
            message="referee decisions must cover every engine-issued dispute exactly once",
            required=True,
            required_message="validated engine dispute references are required",
        )
        return self

    @classmethod
    def validate_for_disputes(
        cls, value: object, disputes: tuple[MaterialDisputeV2, ...]
    ) -> Self:
        """Validate a referee response against the engine's exact dispute inventory."""
        dispute_ids = [dispute.dispute_id for dispute in disputes]
        if len(dispute_ids) != len(set(dispute_ids)):
            raise ValueError("material disputes must use unique dispute IDs")
        return cls.model_validate(value, context={"dispute_ids": set(dispute_ids)})


class ResolvedPassageV2(V2StrictModel):
    source_id: str = Field(strict=True)
    quote: str = Field(strict=True)
    start_char: int = Field(ge=0, strict=True)
    end_char: int = Field(gt=0, strict=True)

    _validate_text = field_validator("source_id", "quote")(_nonblank)

    @model_validator(mode="after")
    def validate_offsets(self) -> Self:
        if self.end_char <= self.start_char:
            raise ValueError("end_char must be greater than start_char")
        return self


class CanonicalRequirementV2(V2StrictModel):
    requirement_id: str = Field(pattern=_REQUIREMENT_REF_PATTERN, strict=True)
    canonical_order: int = Field(ge=0, strict=True)
    statement: str = Field(strict=True)
    kind: RequirementKindV2
    importance: ImportanceV2
    passages: list[ResolvedPassageV2] = Field(min_length=1)
    dependency: SemanticDependency | None = None
    confidence: Literal["clear", "ambiguous", "unresolved"]
    rationale: str = Field(strict=True)

    _validate_text = field_validator("statement", "rationale")(_nonblank)


class CanonicalRelationshipV2(V2StrictModel):
    """An engine-issued semantic edge between two canonical requirements."""

    relationship_id: str = Field(pattern=_RELATIONSHIP_REF_PATTERN, strict=True)
    relationship: Literal["depends_on", "exception_to", "defines", "enforced_by"]
    source_requirement_id: str = Field(pattern=_REQUIREMENT_REF_PATTERN, strict=True)
    target_requirement_id: str = Field(pattern=_REQUIREMENT_REF_PATTERN, strict=True)


class CanonicalBaselineV2(V2StrictModel):
    schema_version: Literal["2.0"] = PROTOCOL_V2
    case_fingerprint: str = Field(pattern=_HASH_PATTERN, strict=True)
    requirements: list[CanonicalRequirementV2]
    relationships: tuple[CanonicalRelationshipV2, ...] = ()
    unresolved_dispute_ids: list[str] = Field(default_factory=list)
    baseline_fingerprint: str = Field(pattern=_HASH_PATTERN, strict=True)

    @field_validator("unresolved_dispute_ids")
    @classmethod
    def validate_dispute_ids(cls, values: list[str]) -> list[str]:
        if any(re.fullmatch(_DISPUTE_REF_PATTERN, value) is None for value in values):
            raise ValueError("unresolved dispute IDs must be engine-issued references")
        if len(values) != len(set(values)):
            raise ValueError("unresolved dispute IDs must be unique")
        return values

    @model_validator(mode="after")
    def validate_requirements(self) -> Self:
        ids = [requirement.requirement_id for requirement in self.requirements]
        orders = [requirement.canonical_order for requirement in self.requirements]
        if len(ids) != len(set(ids)):
            raise ValueError("canonical requirement IDs must be unique")
        if orders != list(range(len(orders))):
            raise ValueError("canonical requirements must use contiguous zero-based order")
        relationship_ids = [relationship.relationship_id for relationship in self.relationships]
        expected_relationship_ids = [
            f"REL-{index:04d}" for index in range(1, len(relationship_ids) + 1)
        ]
        if relationship_ids != expected_relationship_ids:
            raise ValueError("canonical relationships must use unique contiguous REL IDs in order")
        requirement_ids = set(ids)
        if any(
            relationship.source_requirement_id not in requirement_ids
            or relationship.target_requirement_id not in requirement_ids
            for relationship in self.relationships
        ):
            raise ValueError("canonical relationships must identify baseline requirements")
        semantic_edges = [
            (
                relationship.relationship,
                relationship.source_requirement_id,
                relationship.target_requirement_id,
            )
            for relationship in self.relationships
        ]
        if len(semantic_edges) != len(set(semantic_edges)):
            raise ValueError("canonical relationship semantic edges must be unique")
        return self


class RequirementGradeV2(V2StrictModel):
    requirement_id: str = Field(pattern=_REQUIREMENT_REF_PATTERN, strict=True)
    disposition: Literal["met", "partially_met", "not_met", "uncertain"]
    report_passages: list[str] = Field(max_length=_MAX_ROLE_RESPONSE_ITEMS)
    rationale: str = Field(strict=True)
    omission: str | None = Field(default=None, strict=True)

    _validate_rationale = field_validator("rationale")(_nonblank)
    _validate_passages = field_validator("report_passages")(
        lambda values: [_nonblank(value) for value in values]
    )
    _validate_omission = field_validator("omission")(_optional_nonblank)


class UnsupportedAssertionV2(V2StrictModel):
    report_passage: str = Field(strict=True)
    importance: ImportanceV2
    rationale: str = Field(strict=True)

    _validate_text = field_validator("report_passage", "rationale")(_nonblank)


class GradeResponseV2(V2StrictModel):
    schema_version: Literal["2.0"] = PROTOCOL_V2
    anonymous_label: Literal["A", "B"]
    baseline_fingerprint: str = Field(pattern=_HASH_PATTERN, strict=True)
    requirement_grades: list[RequirementGradeV2] = Field(max_length=_MAX_ROLE_RESPONSE_ITEMS)
    unsupported_assertions: list[UnsupportedAssertionV2] = Field(
        max_length=_MAX_ROLE_RESPONSE_ITEMS
    )
    baseline_defect: str | None = Field(default=None, strict=True)

    _validate_baseline_defect = field_validator("baseline_defect")(_optional_nonblank)

    @model_validator(mode="after")
    def validate_requirement_coverage(self, info: ValidationInfo) -> Self:
        requirement_ids = [grade.requirement_id for grade in self.requirement_grades]
        if len(requirement_ids) != len(set(requirement_ids)):
            raise ValueError("requirement grades must use unique requirement IDs")
        _validate_known_refs(
            set(requirement_ids),
            info,
            context_key="requirement_ids",
            message="grade response must cover every engine-issued requirement exactly once",
            required=True,
            required_message="validated engine requirement references are required",
        )
        context = info.context
        if context is not None and "baseline_fingerprint" in context:
            expected_fingerprint = context["baseline_fingerprint"]
            if expected_fingerprint != self.baseline_fingerprint:
                raise ValueError("baseline fingerprint must match baseline")
        return self

    @classmethod
    def validate_for_baseline(cls, value: object, baseline: CanonicalBaselineV2) -> Self:
        """Validate a grader response against the sealed canonical baseline."""
        response = cls.model_validate(
            value,
            context={
                "requirement_ids": {item.requirement_id for item in baseline.requirements},
                "baseline_fingerprint": baseline.baseline_fingerprint,
            },
        )
        return response


class ReconciledRequirementGradeV2(V2StrictModel):
    requirement_id: str = Field(pattern=_REQUIREMENT_REF_PATTERN, strict=True)
    disposition: Literal["met", "partially_met", "not_met", "uncertain"]
    report_passages: list[str]
    rationale: str = Field(strict=True)
    graders_agree: bool

    _validate_passages = field_validator("report_passages")(
        lambda values: [_nonblank(value) for value in values]
    )
    _validate_rationale = field_validator("rationale")(_nonblank)


class ReconciledGradeV2(V2StrictModel):
    """The deterministic aggregate of the two blinded grading observations."""

    anonymous_label: Literal["A", "B"]
    disposition: AbsoluteDispositionV2
    reason_codes: tuple[str, ...] = ()
    grader_responses: tuple[SkipValidation[GradeResponseV2], SkipValidation[GradeResponseV2]]
    requirement_reconciliations: tuple[ReconciledRequirementGradeV2, ...] = ()
    unsupported_assertions: tuple[UnsupportedAssertionV2, ...] = ()

    @field_validator("reason_codes")
    @classmethod
    def validate_reason_codes(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(not isinstance(value, str) or not value.strip() for value in values):
            raise ValueError("reason codes must be nonblank strings")
        if len(values) != len(set(values)):
            raise ValueError("reason codes must be unique")
        return values

    @field_validator("grader_responses", mode="before")
    @classmethod
    def validate_grader_response_snapshots(
        cls, value: object, info: ValidationInfo
    ) -> object:
        """Revalidate every snapshot against the baseline-bound reference context."""
        context = info.context
        if (
            not isinstance(context, dict)
            or "requirement_ids" not in context
            or "baseline_fingerprint" not in context
        ):
            raise ValueError("validated engine baseline references are required")
        if not isinstance(value, (list, tuple)):
            return value
        return tuple(
            GradeResponseV2.model_validate(
                dict(response.__dict__) if isinstance(response, GradeResponseV2) else response,
                context=context,
            )
            for response in value
        )

    @classmethod
    def validate_for_baseline(cls, value: object, baseline: CanonicalBaselineV2) -> Self:
        """Validate reconciliation snapshots against one sealed canonical baseline."""
        sealed_baseline = CanonicalBaselineV2.model_validate(dict(baseline.__dict__))
        return cls.model_validate(
            value,
            context={
                "requirement_ids": {
                    requirement.requirement_id for requirement in sealed_baseline.requirements
                },
                "baseline_fingerprint": sealed_baseline.baseline_fingerprint,
            },
        )

    @model_validator(mode="after")
    def validate_reconciliation(self) -> Self:
        if any(
            response.anonymous_label != self.anonymous_label
            for response in self.grader_responses
        ):
            raise ValueError("grader responses must use the aggregate label")
        fingerprints = {response.baseline_fingerprint for response in self.grader_responses}
        if len(fingerprints) != 1:
            raise ValueError("grader responses must share one baseline fingerprint")
        requirement_ids = [
            reconciliation.requirement_id
            for reconciliation in self.requirement_reconciliations
        ]
        if len(requirement_ids) != len(set(requirement_ids)):
            raise ValueError("reconciled requirement grades must use unique requirement IDs")
        assertion_ids = [
            (assertion.report_passage, assertion.importance)
            for assertion in self.unsupported_assertions
        ]
        if len(assertion_ids) != len(set(assertion_ids)):
            raise ValueError("reconciled unsupported assertions must be unique")
        return self


class RubricV2(V2StrictModel):
    version: Literal["attorney-eval-v2"]
    importance_weights: dict[ImportanceV2, int]
    critical_recall_floor: float = Field(ge=0.0, le=1.0, allow_inf_nan=False)
    weighted_coverage_floor: float = Field(ge=0.0, le=1.0, allow_inf_nan=False)
    material_unsupported_assertions_allowed: Literal[0]


class ReportResultV2(V2StrictModel):
    anonymous_label: Literal["A", "B"]
    absolute_disposition: AbsoluteDispositionV2
    reconciliation: ReconciledGradeV2
    critical_recall: float = Field(ge=0.0, le=1.0, allow_inf_nan=False)
    weighted_coverage: float = Field(ge=0.0, le=1.0, allow_inf_nan=False)
    reason_codes: tuple[str, ...] = ()
    result_fingerprint: str = Field(pattern=_HASH_PATTERN, strict=True)

    @model_validator(mode="after")
    def validate_reconciliation_result(self) -> Self:
        if self.reconciliation.anonymous_label != self.anonymous_label:
            raise ValueError("report result must use its reconciliation label")
        if self.reconciliation.disposition is not self.absolute_disposition:
            raise ValueError("report result disposition must match its reconciliation")
        if self.reason_codes != self.reconciliation.reason_codes:
            raise ValueError("report result reason codes must match its reconciliation")
        return self


class ComparisonResultV2(V2StrictModel):
    disposition: ComparisonDispositionV2
    winner_label: Literal["A", "B"] | None = None
    rationale: str = Field(strict=True)

    _validate_rationale = field_validator("rationale")(_nonblank)

    @model_validator(mode="after")
    def validate_winner(self) -> Self:
        if (
            self.disposition is ComparisonDispositionV2.CANDIDATE_WIN
            and self.winner_label != "A"
        ):
            raise ValueError("candidate_win comparisons require winner label A")
        if (
            self.disposition is ComparisonDispositionV2.COMPARATOR_WIN
            and self.winner_label != "B"
        ):
            raise ValueError("comparator_win comparisons require winner label B")
        if (
            self.disposition
            in {
                ComparisonDispositionV2.TIE,
                ComparisonDispositionV2.NEITHER,
                ComparisonDispositionV2.INCONCLUSIVE,
            }
            and self.winner_label is not None
        ):
            raise ValueError("tie, neither, and inconclusive comparisons must omit a winner")
        return self


class EvaluationResultV2(V2StrictModel):
    schema_version: Literal["2.0"] = PROTOCOL_V2
    rubric: RubricV2
    baseline: CanonicalBaselineV2
    reports: list[ReportResultV2]
    comparison: ComparisonResultV2 | None = None
    result_fingerprint: str = Field(pattern=_HASH_PATTERN, strict=True)

    @model_validator(mode="after")
    def validate_report_labels(self) -> Self:
        labels = [report.anonymous_label for report in self.reports]
        if labels not in (["A"], ["A", "B"]):
            raise ValueError("reports must use unique fixed order A or A, B")
        if (self.comparison is not None) != (labels == ["A", "B"]):
            raise ValueError("comparison requires exactly two reports")
        return self


class EvaluationCallRecordV2(V2StrictModel):
    call_id: str = Field(strict=True)
    operation: EvaluatorOperationV2
    anonymous_label: Literal["A", "B"] | None = None
    state: Literal["pending", "accepted"]
    request_artifact_path: str = Field(strict=True)
    request_fingerprint: str = Field(pattern=_HASH_PATTERN, strict=True)
    response_artifact_path: str | None = Field(default=None, strict=True)
    response_fingerprint: str | None = Field(default=None, pattern=_HASH_PATTERN, strict=True)
    provider_name: str | None = Field(default=None, strict=True)
    model_name: str | None = Field(default=None, strict=True)
    judge_isolation: Literal["fresh_context", "scripted_fixture"] | None = None

    _validate_call_id = field_validator("call_id")(_nonblank)
    _validate_request_path = field_validator("request_artifact_path")(_nonblank)
    _validate_optional_names = field_validator(
        "response_artifact_path", "provider_name", "model_name"
    )(_optional_nonblank)

    @model_validator(mode="after")
    def validate_call_state(self) -> Self:
        if self.operation is EvaluatorOperationV2.GRADE_REPORT:
            if self.anonymous_label is None:
                raise ValueError("grade_report calls require an anonymous label")
        elif self.anonymous_label is not None:
            raise ValueError("only grade_report calls may carry an anonymous label")
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
        return self


class EvaluatorRequestV2(V2StrictModel):
    schema_version: Literal["2.0"] = PROTOCOL_V2
    operation: EvaluatorOperationV2
    request_fingerprint: str = Field(pattern=_HASH_PATTERN, strict=True)
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


class EvaluatorResponseV2(V2StrictModel):
    schema_version: Literal["2.0"] = PROTOCOL_V2
    operation: EvaluatorOperationV2
    request_fingerprint: str = Field(pattern=_HASH_PATTERN, strict=True)
    provider_name: str = Field(strict=True)
    model_name: str = Field(strict=True)
    judge_isolation: Literal["fresh_context", "scripted_fixture"]
    payload: dict[str, object]

    _validate_names = field_validator("provider_name", "model_name")(_nonblank)

    @field_validator("payload", mode="before")
    @classmethod
    def validate_payload_tree(cls, value: object) -> object:
        return _validate_json_object(value, location="response payload")


class EvaluationManifestV2(V2StrictModel):
    protocol_version: Literal["2.0"] = PROTOCOL_V2
    case_fingerprint: str = Field(pattern=_HASH_PATTERN, strict=True)
    case_envelope_hash: str = Field(pattern=_HASH_PATTERN, strict=True)
    build_fingerprint: str = Field(pattern=_HASH_PATTERN, strict=True)
    rubric_fingerprint: str = Field(pattern=_HASH_PATTERN, strict=True)
    compiler_version: Literal["semantic-compiler-v2"]
    baseline_fingerprint: str | None = Field(default=None, pattern=_HASH_PATTERN, strict=True)
    result_hash: str | None = Field(default=None, pattern=_HASH_PATTERN, strict=True)
    phase: EvaluationPhaseV2
    terminal_status: EvaluationTerminalStatusV2 | None = None
    calls: list[EvaluationCallRecordV2]
    artifacts: list[ArtifactRecord]
    manifest_fingerprint: str = Field(pattern=_HASH_PATTERN, strict=True)

    @model_validator(mode="after")
    def validate_manifest(self) -> Self:
        pending_calls = [call for call in self.calls if call.state == "pending"]
        if len(pending_calls) > 1:
            raise ValueError("a manifest may retain at most one pending request")
        call_ids = [call.call_id for call in self.calls]
        if len(call_ids) != len(set(call_ids)):
            raise ValueError("call IDs must be unique")
        artifact_paths = [artifact.artifact_path for artifact in self.artifacts]
        if artifact_paths != sorted(artifact_paths) or len(artifact_paths) != len(
            set(artifact_paths)
        ):
            raise ValueError("artifacts must be uniquely path-sorted")
        terminal = self.phase in {EvaluationPhaseV2.COMPLETED, EvaluationPhaseV2.INCONCLUSIVE}
        expected_terminal_status = {
            EvaluationPhaseV2.COMPLETED: EvaluationTerminalStatusV2.COMPLETED,
            EvaluationPhaseV2.INCONCLUSIVE: EvaluationTerminalStatusV2.INCONCLUSIVE,
        }.get(self.phase)
        if self.terminal_status is not expected_terminal_status:
            raise ValueError("terminal phase and status must match exactly")
        if terminal and pending_calls:
            raise ValueError("terminal manifests must not retain a pending request")
        return self


class EvaluationRunStateV2(V2StrictModel):
    schema_version: Literal["2.0"] = PROTOCOL_V2
    case_fingerprint: str = Field(pattern=_HASH_PATTERN, strict=True)
    phase: EvaluationPhaseV2
    current_call_id: str | None = Field(default=None, strict=True)
    terminal_status: EvaluationTerminalStatusV2 | None = None
    manifest_fingerprint: str | None = Field(default=None, pattern=_HASH_PATTERN, strict=True)

    _validate_call_id = field_validator("current_call_id")(_optional_nonblank)

    @model_validator(mode="after")
    def validate_terminal_state(self) -> Self:
        terminal = self.phase in {EvaluationPhaseV2.COMPLETED, EvaluationPhaseV2.INCONCLUSIVE}
        expected_terminal_status = {
            EvaluationPhaseV2.COMPLETED: EvaluationTerminalStatusV2.COMPLETED,
            EvaluationPhaseV2.INCONCLUSIVE: EvaluationTerminalStatusV2.INCONCLUSIVE,
        }.get(self.phase)
        if self.terminal_status is not expected_terminal_status:
            raise ValueError("terminal phase and status must match exactly")
        if terminal and self.current_call_id is not None:
            raise ValueError("terminal state must not retain a current call")
        return self


class CompletedEvaluationV2(V2StrictModel):
    manifest: EvaluationManifestV2
    result: EvaluationResultV2
    state: EvaluationRunStateV2

    @model_validator(mode="after")
    def validate_completion(self) -> Self:
        if self.manifest.terminal_status is not EvaluationTerminalStatusV2.COMPLETED:
            raise ValueError("completed evaluation requires a completed manifest")
        if self.state.terminal_status is not EvaluationTerminalStatusV2.COMPLETED:
            raise ValueError("completed evaluation requires a completed state")
        if self.manifest.result_hash != self.result.result_fingerprint:
            raise ValueError("completed evaluation result must match manifest result hash")
        return self


def evaluator_request_fingerprint(request: EvaluatorRequestV2) -> str:
    """Return the standard SHA-256 binding for an evaluator request payload."""
    json_schema = _validated_json_snapshot(request.json_schema, location="request json_schema")
    request_payload = _validated_json_snapshot(request.payload, location="request payload")
    payload = request.model_dump(mode="json", exclude={"request_fingerprint"})
    payload["json_schema"] = json_schema
    payload["payload"] = request_payload
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def validate_evaluator_response_v2(value: object) -> EvaluatorResponseV2:
    """Safely revalidate a raw or bypass-constructed response before consuming it."""
    if isinstance(value, EvaluatorResponseV2):
        payload = dict(value.__dict__)
        payload["payload"] = _validated_json_snapshot(
            value.payload, location="response payload"
        )
    elif type(value) is dict:
        payload = value
    else:
        raise ValueError("evaluator response must be an object")
    try:
        return EvaluatorResponseV2.model_validate(payload)
    except (TypeError, ValueError) as error:
        raise ValueError("evaluator response is invalid") from error
