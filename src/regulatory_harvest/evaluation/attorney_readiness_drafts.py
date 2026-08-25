"""Bounded, request-local compilation of delivery-readiness evaluator drafts.

Drafts are ephemeral controller inputs.  This module validates substantive
evaluator prose and request-local references, then constructs the strict
controller-owned response envelope.  Rejected draft bytes are never persisted.
"""

from __future__ import annotations

import json
import math
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated, Literal, TypeAlias, cast

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from regulatory_harvest.storage import canonical_json_bytes, sha256_digest

from . import attorney_readiness_requests as request_builders
from .attorney_baseline_models import (
    BaselineImportanceV1,
    GradeableBaselineProjectionV1,
)
from .attorney_readiness_models import (
    BaselineLockedContestedGradeV1,
    BaselineLockedGradeFragmentV1,
    BaselineLockedGraderAggregateV1,
    FollowUpCodeV1,
    GapVisibilityV1,
    GenerationValidationBindingV1,
    OwnerRoleV1,
    RationaleKindV1,
    ReadinessEvaluatorRequestV1,
    ReadinessEvaluatorResponseV1,
    ReadinessOperationV1,
    SafetyFindingKindV1,
    SafetyFindingProposalV1,
    SafetyGapAssessmentV1,
    SafetyGapCandidateV1,
    SafetyLaneResponseV1,
    SafetyRefereeDecisionV1,
    _FrozenDict,
    load_readiness_rubric_v1,
)
from .attorney_v2_models import RequirementGradeV2

_MAX_DRAFT_BYTES = 262_144
_MAX_DRAFT_DEPTH = 64
_MAX_DRAFT_NODES = 20_000
_MAX_DRAFT_ITEMS = 640
_MAX_PROVENANCE_TEXT = 128
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_EVIDENCE_TOKEN_RE = re.compile(
    r"(?:SOURCE-[0-9]{6}|BASELINE-(?:REQ|CONT)-[0-9]{4}|"
    r"PREREQUISITE-(?:CURRENTNESS|COMPLETENESS|LANGUAGE)-"
    r"[A-Za-z0-9][A-Za-z0-9._:-]*|PREREQUISITE-CLIENT-FACTS)"
)
_PRIVATE_PATH_RE = re.compile(
    r"(?i)(?:file:/|[A-Z]:[\\/]|\\\\|/(?:Applications|Library|System|Users|Volumes|"
    r"etc|home|opt|private|root|tmp|usr|var)(?:/|$))"
)
_CONSEQUENCES = (
    "legal conclusion",
    "applicability",
    "implementation decision",
    "deadline",
    "enforcement exposure",
    "attorney follow up",
)
_RESOLUTION_OUTCOMES = (
    "evidence",
    "fact",
    "legal judgment",
    "report correction",
    "correct the report",
)
_RESOLUTION_ACTIONS = (
    "verify",
    "obtain",
    "confirm",
    "correct",
    "revise",
    "establish",
    "resolve",
    "document",
)
_SPECIFICITY_TERMS = frozenset(
    {
        "report",
        "treatment",
        "evidence",
        "source",
        "fact",
        "conflict",
        "ambiguity",
        "ambiguous",
        "currentness",
        "language",
        "missing",
        "omission",
        "assertion",
        "limitation",
        "interpretation",
        "authority",
        "requirement",
        "gap",
        "dependency",
        "support",
        "establish",
        "disclose",
    }
)
_REPORT_CONTENT_FINDINGS = frozenset(
    {
        SafetyFindingKindV1.MATERIAL_UNSUPPORTED_ASSERTION,
        SafetyFindingKindV1.BASELINE_CONTRADICTION,
        SafetyFindingKindV1.MISLEADING_CURRENTNESS_OR_AUTHORITY,
    }
)
_NORMALIZED_DUPLICATES = "DRAFT_NORMALIZED_DUPLICATES"


class ReadinessDraftReasonCodeV1(StrEnum):
    """Public-safe reasons a fresh draft needs clarification."""

    DRAFT_INVALID = "DRAFT_INVALID"
    DRAFT_TOO_LARGE = "DRAFT_TOO_LARGE"
    DRAFT_DEPTH_EXCEEDED = "DRAFT_DEPTH_EXCEEDED"
    DRAFT_NODE_LIMIT_EXCEEDED = "DRAFT_NODE_LIMIT_EXCEEDED"
    ITEM_LIMIT_EXCEEDED = "ITEM_LIMIT_EXCEEDED"
    OPERATION_MISMATCH = "OPERATION_MISMATCH"
    COVERAGE_INVALID = "COVERAGE_INVALID"
    EVIDENCE_NOT_FOUND = "EVIDENCE_NOT_FOUND"
    EVIDENCE_AMBIGUOUS = "EVIDENCE_AMBIGUOUS"
    REFERENCE_UNKNOWN = "REFERENCE_UNKNOWN"
    CONFLICTING_ITEMS = "CONFLICTING_ITEMS"
    RATIONALE_MISSING = "RATIONALE_MISSING"
    RATIONALE_GENERIC = "RATIONALE_GENERIC"
    RATIONALE_EVIDENCE_UNBOUND = "RATIONALE_EVIDENCE_UNBOUND"
    RATIONALE_CONSEQUENCE_MISSING = "RATIONALE_CONSEQUENCE_MISSING"
    RESOLUTION_TEST_INVALID = "RESOLUTION_TEST_INVALID"
    CRITICAL_VISIBILITY_INVALID = "CRITICAL_VISIBILITY_INVALID"
    CRITICAL_OWNER_INVALID = "CRITICAL_OWNER_INVALID"
    REPORT_PASSAGE_REQUIRED = "REPORT_PASSAGE_REQUIRED"


@dataclass(frozen=True)
class ReadinessEvaluatorProvenanceV1:
    """Controller-supplied, truthful evaluator provenance."""

    provider_name: str
    model_name: str
    judge_isolation: Literal["fresh_context", "scripted_fixture"]

    def __post_init__(self) -> None:
        for value in (self.provider_name, self.model_name):
            if (
                type(value) is not str
                or not value
                or value != value.strip()
                or len(value.encode("utf-8")) > _MAX_PROVENANCE_TEXT
            ):
                raise ValueError("readiness evaluator provenance must be bounded exact text")
        if type(self.judge_isolation) is not str or self.judge_isolation not in {
            "fresh_context",
            "scripted_fixture",
        }:
            raise ValueError("readiness evaluator isolation is invalid")


@dataclass(frozen=True)
class ReadinessEvaluatorDraftPromptV1:
    """One fresh prompt; rejected draft content is intentionally absent."""

    request: ReadinessEvaluatorRequestV1
    attempt: Literal[1, 2]
    clarification_codes: tuple[ReadinessDraftReasonCodeV1, ...] = ()

    def __post_init__(self) -> None:
        if type(self.attempt) is not int or self.attempt not in {1, 2}:
            raise ValueError("readiness draft attempt must be the native integer 1 or 2")
        if type(self.clarification_codes) is not tuple or any(
            type(item) is not ReadinessDraftReasonCodeV1 for item in self.clarification_codes
        ):
            raise ValueError("readiness clarification codes must be an exact tuple")
        if len(self.clarification_codes) != len(set(self.clarification_codes)):
            raise ValueError("readiness clarification codes must be unique")
        if (self.attempt == 1) != (not self.clarification_codes):
            raise ValueError("only a second attempt carries clarification codes")
        _strict_request(self.request)


@dataclass(frozen=True)
class CompiledReadinessDraftV1:
    response: ReadinessEvaluatorResponseV1
    normalization_codes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if type(self.response) is not ReadinessEvaluatorResponseV1:
            raise ValueError("compiled readiness response must be exact")
        if type(self.normalization_codes) is not tuple or any(
            type(item) is not str or not item for item in self.normalization_codes
        ):
            raise ValueError("readiness normalization codes must be exact")
        unique = tuple(dict.fromkeys(self.normalization_codes))
        object.__setattr__(self, "normalization_codes", unique)


@dataclass(frozen=True)
class NeedsReadinessClarificationV1:
    reason_codes: tuple[ReadinessDraftReasonCodeV1, ...]

    def __post_init__(self) -> None:
        if type(self.reason_codes) is not tuple or any(
            type(item) is not ReadinessDraftReasonCodeV1 for item in self.reason_codes
        ):
            raise ValueError("readiness clarification reasons must be exact")
        unique = tuple(dict.fromkeys(self.reason_codes))
        if not unique:
            raise ValueError("readiness clarification requires one reason")
        object.__setattr__(self, "reason_codes", unique)


@dataclass(frozen=True)
class ReadinessEngineDefectV1:
    reason_code: Literal[
        "READINESS_COMPILER_INVARIANT",
        "READINESS_COMPILER_PREFLIGHT_DISAGREEMENT",
    ]

    def __post_init__(self) -> None:
        if type(self.reason_code) is not str or self.reason_code not in {
            "READINESS_COMPILER_INVARIANT",
            "READINESS_COMPILER_PREFLIGHT_DISAGREEMENT",
        }:
            raise ValueError("readiness engine defect code is invalid")


ReadinessDraftCompileOutcomeV1: TypeAlias = (
    CompiledReadinessDraftV1 | NeedsReadinessClarificationV1 | ReadinessEngineDefectV1
)


class _DraftModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


_Disposition = Literal["met", "partially_met", "not_met", "uncertain"]


class _RequirementGradeDraftV1(_DraftModel):
    requirement_id: str
    disposition: _Disposition
    report_passages: Annotated[list[str], Field(max_length=_MAX_DRAFT_ITEMS)]
    rationale: str
    omission: str | None


class _OrdinaryGradeDraftV1(_DraftModel):
    requirement_grades: Annotated[
        list[_RequirementGradeDraftV1], Field(max_length=_MAX_DRAFT_ITEMS)
    ]
    rationale: str


class _ContestedGradeDraftV1(_DraftModel):
    contested_requirement_id: str
    reviewer_alternative_disposition: _Disposition
    auditor_alternative_disposition: _Disposition
    reviewer_report_passages: Annotated[list[str], Field(max_length=_MAX_DRAFT_ITEMS)]
    auditor_report_passages: Annotated[list[str], Field(max_length=_MAX_DRAFT_ITEMS)]
    reviewer_rationale: str
    auditor_rationale: str
    ambiguity_disposition: Literal["acknowledged", "overstated", "omitted", "uncertain"]
    rationale: str


class _SafetyGapAssessmentDraftV1(_DraftModel):
    candidate_id: str
    shortfall_description: str
    rationale_kind: Literal[
        "REPORT_OMISSION",
        "REPORT_PARTIAL_TREATMENT",
        "SOURCE_ABSENT",
        "SOURCE_AMBIGUOUS",
        "SOURCE_CONFLICT",
        "CURRENTNESS_NOT_ESTABLISHED",
        "APPLICABILITY_FACT_MISSING",
        "LANGUAGE_LIMITATION",
        "CONTESTED_INTERPRETATION",
        "UNSUPPORTED_ASSERTION",
        "SAFETY_REVIEW_FINDING",
    ]
    why_unresolved: str
    why_it_matters: str
    evidence_refs: Annotated[list[str], Field(max_length=_MAX_DRAFT_ITEMS)]
    report_passages: Annotated[list[str], Field(max_length=_MAX_DRAFT_ITEMS)]
    disclosure_location: str | None
    visibility: Literal["prominent", "visible", "hidden"]
    blocking_code: str | None
    follow_up_code: Literal[
        "VERIFY_PRIMARY_AUTHORITY",
        "CONFIRM_CURRENTNESS",
        "RESOLVE_APPLICABILITY_FACT",
        "OBTAIN_OUTSIDE_COUNSEL_ANALYSIS",
        "EXPAND_REQUIREMENT_ANALYSIS",
        "CORRECT_UNSUPPORTED_ASSERTION",
        "RESOLVE_LANGUAGE_LIMITATION",
        "RESOLVE_CONTESTED_INTERPRETATION",
    ]
    resolution_test: str
    owner_role: Literal["reviewing_attorney", "outside_counsel", "research_operator"]


class _SafetyFindingDraftV1(_DraftModel):
    finding_kind: Literal[
        "MATERIAL_UNSUPPORTED_ASSERTION",
        "BASELINE_CONTRADICTION",
        "HIDDEN_OR_UNDERSTATED_LIMITATION",
        "UNDISCLOSED_DISPOSITIVE_CLIENT_FACT",
        "MISLEADING_CURRENTNESS_OR_AUTHORITY",
        "UNDISCLOSED_GRADER_GAP",
    ]
    subject_id: str
    report_passages: Annotated[list[str], Field(max_length=_MAX_DRAFT_ITEMS)]
    shortfall_description: str
    rationale_kind: Literal[
        "REPORT_OMISSION",
        "REPORT_PARTIAL_TREATMENT",
        "SOURCE_ABSENT",
        "SOURCE_AMBIGUOUS",
        "SOURCE_CONFLICT",
        "CURRENTNESS_NOT_ESTABLISHED",
        "APPLICABILITY_FACT_MISSING",
        "LANGUAGE_LIMITATION",
        "CONTESTED_INTERPRETATION",
        "UNSUPPORTED_ASSERTION",
        "SAFETY_REVIEW_FINDING",
    ]
    why_unresolved: str
    why_it_matters: str
    evidence_refs: Annotated[list[str], Field(max_length=_MAX_DRAFT_ITEMS)]
    disclosure_location: str | None
    visibility: Literal["prominent", "visible", "hidden"]
    blocking_code: str | None
    follow_up_code: Literal[
        "VERIFY_PRIMARY_AUTHORITY",
        "CONFIRM_CURRENTNESS",
        "RESOLVE_APPLICABILITY_FACT",
        "OBTAIN_OUTSIDE_COUNSEL_ANALYSIS",
        "EXPAND_REQUIREMENT_ANALYSIS",
        "CORRECT_UNSUPPORTED_ASSERTION",
        "RESOLVE_LANGUAGE_LIMITATION",
        "RESOLVE_CONTESTED_INTERPRETATION",
    ]
    resolution_test: str
    owner_role: Literal["reviewing_attorney", "outside_counsel", "research_operator"]


class _SafetyLaneDraftV1(_DraftModel):
    candidate_assessments: Annotated[
        list[_SafetyGapAssessmentDraftV1], Field(max_length=_MAX_DRAFT_ITEMS)
    ]
    finding_proposals: Annotated[list[_SafetyFindingDraftV1], Field(max_length=_MAX_DRAFT_ITEMS)]


class _SafetyRefereeDraftV1(_DraftModel):
    dispute_id: str
    disposition: Literal["lane_1", "lane_2", "blocking", "unresolved"]
    rationale: str
    evidence_refs: Annotated[list[str], Field(max_length=_MAX_DRAFT_ITEMS)]


_ParsedDraftV1: TypeAlias = (
    _OrdinaryGradeDraftV1 | _ContestedGradeDraftV1 | _SafetyLaneDraftV1 | _SafetyRefereeDraftV1
)


class _Clarification(ValueError):
    def __init__(self, *reason_codes: ReadinessDraftReasonCodeV1) -> None:
        super().__init__("readiness draft needs clarification")
        self.reason_codes = tuple(dict.fromkeys(reason_codes))


class _ControllerInvariant(ValueError):
    pass


@dataclass(frozen=True)
class _CheckedRequest:
    request: ReadinessEvaluatorRequestV1
    raw: dict[str, object]


def _preflight_json_tree(value: object) -> None:
    nodes = 0
    wire_bytes = 0
    active: set[int] = set()

    def add_wire_bytes(size: int) -> None:
        nonlocal wire_bytes
        wire_bytes += size
        if wire_bytes > _MAX_DRAFT_BYTES:
            raise _Clarification(ReadinessDraftReasonCodeV1.DRAFT_TOO_LARGE)

    def add_json_string(value: str) -> None:
        add_wire_bytes(2)
        for character in value:
            codepoint = ord(character)
            if character in {'"', "\\", "\b", "\f", "\n", "\r", "\t"}:
                size = 2
            elif codepoint < 0x20:
                size = 6
            elif codepoint <= 0x7F:
                size = 1
            elif codepoint <= 0x7FF:
                size = 2
            elif 0xD800 <= codepoint <= 0xDFFF:
                raise _Clarification(ReadinessDraftReasonCodeV1.DRAFT_INVALID)
            elif codepoint <= 0xFFFF:
                size = 3
            else:
                size = 4
            add_wire_bytes(size)

    def visit(item: object, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > _MAX_DRAFT_NODES:
            raise _Clarification(ReadinessDraftReasonCodeV1.DRAFT_NODE_LIMIT_EXCEEDED)
        if depth > _MAX_DRAFT_DEPTH:
            raise _Clarification(ReadinessDraftReasonCodeV1.DRAFT_DEPTH_EXCEEDED)
        if item is None:
            add_wire_bytes(4)
            return
        if type(item) is bool:
            add_wire_bytes(4 if item else 5)
            return
        if type(item) is int:
            add_wire_bytes(len(str(item)))
            return
        if type(item) is str:
            add_json_string(item)
            return
        if type(item) is float:
            if not math.isfinite(item):
                raise _Clarification(ReadinessDraftReasonCodeV1.DRAFT_INVALID)
            add_wire_bytes(len(json.dumps(item)))
            return
        if type(item) not in {dict, list}:
            raise _Clarification(ReadinessDraftReasonCodeV1.DRAFT_INVALID)
        identity = id(item)
        if identity in active:
            raise _Clarification(ReadinessDraftReasonCodeV1.DRAFT_INVALID)
        active.add(identity)
        try:
            if type(item) is dict:
                mapping = cast(dict[object, object], item)
                add_wire_bytes(2 + max(0, len(mapping) - 1))
                for key, child in mapping.items():
                    if type(key) is not str:
                        raise _Clarification(ReadinessDraftReasonCodeV1.DRAFT_INVALID)
                    nodes += 1
                    if nodes > _MAX_DRAFT_NODES:
                        raise _Clarification(ReadinessDraftReasonCodeV1.DRAFT_NODE_LIMIT_EXCEEDED)
                    add_json_string(key)
                    add_wire_bytes(1)
                    visit(child, depth + 1)
            else:
                sequence = cast(list[object], item)
                add_wire_bytes(2 + max(0, len(sequence) - 1))
                for child in sequence:
                    visit(child, depth + 1)
        finally:
            active.remove(identity)

    visit(value, 0)


def _duplicate_rejecting_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate draft JSON key")
        result[key] = value
    return result


def _bounded_json_object(value: object) -> dict[str, object]:
    try:
        if type(value) is bytes:
            data = value
            if len(data) > _MAX_DRAFT_BYTES:
                raise _Clarification(ReadinessDraftReasonCodeV1.DRAFT_TOO_LARGE)
            value = data.decode("utf-8")
        if type(value) is str:
            text = value
            if len(text.encode("utf-8")) > _MAX_DRAFT_BYTES:
                raise _Clarification(ReadinessDraftReasonCodeV1.DRAFT_TOO_LARGE)
            value = json.loads(
                text,
                object_pairs_hook=_duplicate_rejecting_object,
                parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid number")),
            )
        _preflight_json_tree(value)
        if type(value) is not dict:
            raise _Clarification(ReadinessDraftReasonCodeV1.DRAFT_INVALID)
        encoded = canonical_json_bytes(value)
        if len(encoded) > _MAX_DRAFT_BYTES:
            raise _Clarification(ReadinessDraftReasonCodeV1.DRAFT_TOO_LARGE)
        decoded = json.loads(encoded, object_pairs_hook=_duplicate_rejecting_object)
        if type(decoded) is not dict:
            raise _Clarification(ReadinessDraftReasonCodeV1.DRAFT_INVALID)
        return cast(dict[str, object], decoded)
    except _Clarification:
        raise
    except (RecursionError, TypeError, UnicodeDecodeError, ValueError, json.JSONDecodeError):
        raise _Clarification(ReadinessDraftReasonCodeV1.DRAFT_INVALID) from None


def _schema_key(operation: ReadinessOperationV1, raw: dict[str, object]) -> str:
    if operation is ReadinessOperationV1.BASELINE_LOCKED_GRADE:
        return "ordinary_grade"
    if operation is ReadinessOperationV1.BASELINE_LOCKED_CONTESTED_GRADE:
        return "contested_grade"
    if operation is ReadinessOperationV1.SAFETY_REVIEW:
        return "safety_lane"
    payload = cast(dict[str, object], raw["payload"])
    return f"safety_referee:{payload['dispute_kind']}"


def _exact_payload_keys(operation: ReadinessOperationV1) -> frozenset[str]:
    common = {
        "stable_baseline",
        "grade_target_fingerprint",
        "baseline_fingerprint",
        "report_text",
        "report_hash",
        "report_passage_allowlist",
        "retained_scoring_contract",
        "retained_scoring_contract_fingerprint",
        "strict_equivalent_scoring_fingerprint",
    }
    if operation is ReadinessOperationV1.BASELINE_LOCKED_GRADE:
        return frozenset(common | {"controller_lane_id", "lane", "batch_ref", "requirements"})
    if operation is ReadinessOperationV1.BASELINE_LOCKED_CONTESTED_GRADE:
        return frozenset(common | {"controller_lane_id", "lane", "contested_requirement"})
    if operation is ReadinessOperationV1.SAFETY_REVIEW:
        return frozenset(
            {
                "controller_safety_lane_id",
                "lane",
                "stable_baseline",
                "grade_target_fingerprint",
                "baseline_fingerprint",
                "grader_lanes",
                "report_text",
                "report_hash",
                "report_passage_allowlist",
                "source_record",
                "qualification_limits",
                "client_fact_boundary",
                "generation_validation",
                "readiness_rubric",
                "strict_equivalent_scoring_fingerprint",
                "gap_candidates",
                "evidence_handles",
            }
        )
    return frozenset(
        {
            "controller_referee_id",
            "dispute_id",
            "canonical_order",
            "dispute_kind",
            "subject_identity",
            "lane_1_choice",
            "lane_2_choice",
            "evidence_refs",
            "grade_target_fingerprint",
            "baseline_fingerprint",
            "report_hash",
            "disputed_report_passages",
            "evidence_handles",
        }
    )


def _request_allowlist(payload: dict[str, object]) -> tuple[str, ...]:
    report = payload.get("report_text")
    values = payload.get("report_passage_allowlist")
    if (
        type(report) is not str
        or type(values) is not list
        or any(type(item) is not str for item in cast(list[object], values))
    ):
        raise _ControllerInvariant("request report-passage inventory is invalid")
    expected = request_builders._report_passage_allowlist(report)
    if cast(list[str], values) != expected:
        raise _ControllerInvariant("request report-passage inventory is invalid")
    return tuple(expected)


def _request_evidence_refs(payload: dict[str, object]) -> tuple[str, ...]:
    handles = payload.get("evidence_handles")
    if type(handles) is not list:
        raise _ControllerInvariant("request evidence-handle inventory is invalid")
    refs: list[str] = []
    for handle in cast(list[object], handles):
        if (
            type(handle) is not dict
            or type(cast(dict[str, object], handle).get("evidence_ref")) is not str
        ):
            raise _ControllerInvariant("request evidence-handle inventory is invalid")
        ref = cast(str, cast(dict[str, object], handle)["evidence_ref"])
        if ref in refs:
            raise _ControllerInvariant("request evidence-handle inventory is invalid")
        refs.append(ref)
    return tuple(refs)


def _expected_schema_and_instruction(
    operation: ReadinessOperationV1,
    payload: dict[str, object],
) -> tuple[dict[str, object], str]:
    if operation is ReadinessOperationV1.BASELINE_LOCKED_GRADE:
        allowlist = _request_allowlist(payload)
        requirements = payload.get("requirements")
        if type(requirements) is not list or not 1 <= len(requirements) <= 5:
            raise _ControllerInvariant("ordinary request coverage is invalid")
        ids: list[str] = []
        for item in cast(list[object], requirements):
            if (
                type(item) is not dict
                or type(cast(dict[str, object], item).get("requirement")) is not dict
            ):
                raise _ControllerInvariant("ordinary request coverage is invalid")
            identifier = cast(dict[str, object], cast(dict[str, object], item)["requirement"]).get(
                "requirement_id"
            )
            if type(identifier) is not str or identifier in ids:
                raise _ControllerInvariant("ordinary request coverage is invalid")
            ids.append(identifier)
        return (
            request_builders._grade_response_schema_for_ids(ids, allowlist),
            request_builders._ORDINARY_GRADE_SYSTEM,
        )
    if operation is ReadinessOperationV1.BASELINE_LOCKED_CONTESTED_GRADE:
        allowlist = _request_allowlist(payload)
        contest = payload.get("contested_requirement")
        if (
            type(contest) is not dict
            or type(cast(dict[str, object], contest).get("contested_requirement")) is not dict
        ):
            raise _ControllerInvariant("contested request coverage is invalid")
        identifier = cast(
            dict[str, object], cast(dict[str, object], contest)["contested_requirement"]
        ).get("contested_requirement_id")
        if type(identifier) is not str:
            raise _ControllerInvariant("contested request coverage is invalid")
        return (
            request_builders._contested_response_schema(identifier, allowlist),
            request_builders._CONTESTED_GRADE_SYSTEM,
        )
    if operation is ReadinessOperationV1.SAFETY_REVIEW:
        allowlist = _request_allowlist(payload)
        refs = _request_evidence_refs(payload)
        candidates_raw = payload.get("gap_candidates")
        if type(candidates_raw) is not list:
            raise _ControllerInvariant("safety candidate inventory is invalid")
        try:
            candidates = tuple(
                SafetyGapCandidateV1.model_validate(item)
                for item in cast(list[object], candidates_raw)
            )
        except (TypeError, ValidationError, ValueError) as error:
            raise _ControllerInvariant("safety candidate inventory is invalid") from error
        candidate_ids = tuple(item.candidate_id for item in candidates)
        if candidate_ids != tuple(f"GC-{index:04d}" for index in range(1, len(candidate_ids) + 1)):
            raise _ControllerInvariant("safety candidate inventory is invalid")
        return (
            request_builders._safety_response_schema(candidates, refs, allowlist),
            request_builders._SAFETY_SYSTEM,
        )
    refs_raw = payload.get("evidence_refs")
    if type(refs_raw) is not list or any(
        type(item) is not str for item in cast(list[object], refs_raw)
    ):
        raise _ControllerInvariant("referee evidence inventory is invalid")
    refs = tuple(cast(list[str], refs_raw))
    if len(refs) != len(set(refs)) or not set(refs).issubset(_request_evidence_refs(payload)):
        raise _ControllerInvariant("referee evidence inventory is invalid")
    dispute_id = payload.get("dispute_id")
    dispute_kind = payload.get("dispute_kind")
    if type(dispute_id) is not str or type(dispute_kind) is not str:
        raise _ControllerInvariant("referee dispute identity is invalid")
    return (
        request_builders._referee_response_schema(dispute_id, refs),
        request_builders._referee_system(dispute_kind),
    )


def _sealed_fingerprint_valid(value: object, field: str) -> bool:
    if type(value) is not dict:
        return False
    raw = cast(dict[str, object], value)
    fingerprint = raw.get(field)
    descriptor = {key: item for key, item in raw.items() if key != field}
    return type(fingerprint) is str and fingerprint == sha256_digest(
        canonical_json_bytes(descriptor)
    )


def _verified_baseline(payload: dict[str, object]) -> GradeableBaselineProjectionV1:
    raw = payload.get("stable_baseline")
    if type(raw) is not dict:
        raise _ControllerInvariant("request stable baseline is invalid")
    try:
        candidate = dict(cast(dict[str, object], raw))
        baseline_input_raw = candidate.get("baseline_input")
        if type(baseline_input_raw) is not dict:
            raise ValueError
        baseline_input = dict(cast(dict[str, object], baseline_input_raw))
        for field in ("evaluation_rubric_bytes", "importance_policy_bytes"):
            value = baseline_input.get(field)
            if type(value) is not str:
                raise ValueError
            baseline_input[field] = value.encode("utf-8")
        candidate["baseline_input"] = baseline_input
        baseline = GradeableBaselineProjectionV1.model_validate(candidate)
        if canonical_json_bytes(baseline.model_dump(mode="json", warnings="error")) != (
            canonical_json_bytes(raw)
        ):
            raise ValueError
    except (AttributeError, TypeError, ValidationError, ValueError) as error:
        raise _ControllerInvariant("request stable baseline is invalid") from error
    return baseline


def _validate_safety_evidence_packet(
    payload: dict[str, object],
    baseline: GradeableBaselineProjectionV1,
    *,
    report_hash: str,
) -> list[tuple[str, str, tuple[str, ...]]]:
    source_record = payload.get("source_record")
    expected_sources = [item.model_dump(mode="json") for item in baseline.baseline_input.sources]
    if type(source_record) is not list or canonical_json_bytes(source_record) != (
        canonical_json_bytes(expected_sources)
    ):
        raise _ControllerInvariant("safety source record is invalid")
    source_by_id = {
        item.source_id: item.model_dump(mode="json") for item in baseline.baseline_input.sources
    }
    source_refs = {
        source_id: f"SOURCE-{index:06d}" for index, source_id in enumerate(source_by_id, 1)
    }
    expected_handles: list[dict[str, object]] = [
        {
            "evidence_ref": source_refs[item.source_id],
            "evidence_kind": "source",
            "evidence": item.model_dump(mode="json"),
        }
        for item in baseline.baseline_input.sources
    ]
    expected_handles.extend(
        {
            "evidence_ref": f"BASELINE-{item.requirement.requirement_id}",
            "evidence_kind": "baseline_requirement",
            "evidence": item.model_dump(mode="json"),
        }
        for item in baseline.requirements
    )
    expected_handles.extend(
        {
            "evidence_ref": (f"BASELINE-{item.contested_requirement.contested_requirement_id}"),
            "evidence_kind": "contested_requirement",
            "evidence": item.model_dump(mode="json"),
        }
        for item in baseline.contested_requirements
    )

    qualification = payload.get("qualification_limits")
    if type(qualification) is not dict:
        raise _ControllerInvariant("safety qualification evidence is invalid")
    limits = cast(dict[str, object], qualification)
    if limits.get("source_record_fingerprint") != (baseline.binding.source_record_fingerprint):
        raise _ControllerInvariant("safety qualification evidence is invalid")
    grouped: dict[tuple[str, str], list[tuple[str, object, bool]]] = {}
    prerequisites: list[tuple[str, str, tuple[str, ...]]] = []
    checks = limits.get("admission_checks")
    if type(checks) is not list:
        raise _ControllerInvariant("safety qualification evidence is invalid")
    for raw_check in cast(list[object], checks):
        if type(raw_check) is not dict:
            raise _ControllerInvariant("safety qualification evidence is invalid")
        check = cast(dict[str, object], raw_check)
        code = check.get("code")
        satisfied = check.get("satisfied")
        material = check.get("material")
        source_ids = check.get("source_ids")
        if (
            type(code) is not str
            or code not in request_builders._CHECK_PREREQUISITE_KIND
            or type(satisfied) is not bool
            or type(material) is not bool
            or type(check.get("rationale")) is not str
            or type(source_ids) is not list
            or len(source_ids) != len(set(cast(list[object], source_ids)))
            or any(type(item) is not str or item not in source_by_id for item in source_ids)
        ):
            raise _ControllerInvariant("safety qualification evidence is invalid")
        if not satisfied:
            kind = request_builders._CHECK_PREREQUISITE_KIND[code]
            for source_id in cast(list[str], source_ids):
                grouped.setdefault((kind, source_id), []).append(
                    ("qualification_admission_check", check, material)
                )
    treatments = limits.get("language_treatments")
    if type(treatments) is not list:
        raise _ControllerInvariant("safety qualification evidence is invalid")
    for raw_treatment in cast(list[object], treatments):
        if type(raw_treatment) is not dict:
            raise _ControllerInvariant("safety qualification evidence is invalid")
        treatment = cast(dict[str, object], raw_treatment)
        treatment_sources = treatment.get("sources")
        limitation_status = treatment.get("limitation_status")
        if (
            limitation_status not in {"DECLARED", "NOT_DECLARED"}
            or type(treatment_sources) is not list
            or type(treatment.get("method")) is not str
            or type(treatment.get("rationale")) is not str
        ):
            raise _ControllerInvariant("safety qualification evidence is invalid")
        for raw_source in cast(list[object], treatment_sources):
            if type(raw_source) is not dict:
                raise _ControllerInvariant("safety qualification evidence is invalid")
            source = cast(dict[str, object], raw_source)
            treatment_source_id = source.get("source_id")
            if type(treatment_source_id) is not str:
                raise _ControllerInvariant("safety qualification evidence is invalid")
            expected_source = source_by_id.get(treatment_source_id)
            if (
                expected_source is None
                or source.get("content_hash") != expected_source["content_hash"]
                or source.get("language") != expected_source["language"]
            ):
                raise _ControllerInvariant("safety qualification evidence is invalid")
            if limitation_status == "DECLARED":
                grouped.setdefault(("LANGUAGE", treatment_source_id), []).append(
                    ("qualification_language_treatment", treatment, True)
                )
    for source_id in source_by_id:
        for kind in request_builders._PREREQUISITE_KIND_ORDER:
            items = grouped.get((kind, source_id))
            if not items:
                continue
            if len(items) == 1:
                evidence_kind, evidence, material = items[0]
            else:
                evidence_kind = "qualification_prerequisite_evidence"
                material = any(item_material for _, _, item_material in items)
                evidence = [
                    {"evidence_kind": item_kind, "evidence": item_evidence}
                    for item_kind, item_evidence, _ in items
                ]
            expected_handles.append(
                {
                    "evidence_ref": f"PREREQUISITE-{kind}-{source_id}",
                    "evidence_kind": evidence_kind,
                    "subject_id": f"{kind}:{source_id}",
                    "evidence": evidence,
                }
            )
            prerequisites.append(
                (
                    f"{kind}:{source_id}",
                    "critical" if material else "material",
                    (source_refs[source_id], f"PREREQUISITE-{kind}-{source_id}"),
                )
            )

    facts = baseline.baseline_input.client_facts
    facts_hash = None if facts is None else sha256_digest(facts.encode("utf-8"))
    expected_boundary = {
        "client_facts": facts,
        "client_facts_binding": baseline.baseline_input.client_facts_binding,
        "client_facts_hash": facts_hash,
    }
    if canonical_json_bytes(payload.get("client_fact_boundary")) != canonical_json_bytes(
        expected_boundary
    ):
        raise _ControllerInvariant("safety client-fact boundary is invalid")
    if facts is None:
        expected_handles.append(
            {
                "evidence_ref": "PREREQUISITE-CLIENT-FACTS",
                "evidence_kind": "client_fact_boundary",
                "evidence": expected_boundary,
            }
        )
        prerequisites.append(("CLIENT_FACTS", "critical", ("PREREQUISITE-CLIENT-FACTS",)))
    if canonical_json_bytes(payload.get("evidence_handles")) != canonical_json_bytes(
        expected_handles
    ):
        raise _ControllerInvariant("safety evidence-handle inventory is invalid")
    try:
        generation = GenerationValidationBindingV1.model_validate(
            payload.get("generation_validation")
        )
    except (TypeError, ValidationError, ValueError) as error:
        raise _ControllerInvariant("safety generation validation is invalid") from error
    if generation.report_hash != report_hash:
        raise _ControllerInvariant("safety generation validation is invalid")
    if canonical_json_bytes(payload.get("readiness_rubric")) != canonical_json_bytes(
        load_readiness_rubric_v1().model_dump(mode="json")
    ):
        raise _ControllerInvariant("safety readiness rubric is invalid")
    return prerequisites


def _ordered_evidence_refs(
    leading_ref: str,
    passage_sources: tuple[str, ...],
    source_refs: dict[str, str],
) -> list[str]:
    refs = [leading_ref]
    for source_id in passage_sources:
        ref = source_refs.get(source_id)
        if ref is None:
            raise _ControllerInvariant("baseline passage source is invalid")
        if ref not in refs:
            refs.append(ref)
    return refs


def _validate_exact_safety_candidates(
    raw_candidates: object,
    baseline: GradeableBaselineProjectionV1,
    lanes: tuple[BaselineLockedGraderAggregateV1, BaselineLockedGraderAggregateV1],
    prerequisites: list[tuple[str, str, tuple[str, ...]]],
    *,
    report_hash: str,
) -> None:
    if type(raw_candidates) is not list:
        raise _ControllerInvariant("safety candidate inventory is invalid")
    source_refs = {
        item.source_id: f"SOURCE-{index:06d}"
        for index, item in enumerate(baseline.baseline_input.sources, 1)
    }
    pending: list[dict[str, object]] = []
    lane_grade_maps = [
        {item.requirement_id: str(item.disposition) for item in lane.requirement_grades}
        for lane in lanes
    ]
    for item in baseline.requirements:
        requirement = item.requirement
        first = lane_grade_maps[0][requirement.requirement_id]
        second = lane_grade_maps[1][requirement.requirement_id]
        is_gap = requirement.kind.value == "gap"
        if not is_gap and first == second == "met":
            continue
        pending.append(
            {
                "origin": "baseline_gap" if is_gap else "requirement",
                "subject_id": requirement.requirement_id,
                "importance": requirement.importance.value,
                "lane_1_disposition": first,
                "lane_2_disposition": second,
                "evidence_refs": _ordered_evidence_refs(
                    f"BASELINE-{requirement.requirement_id}",
                    tuple(passage.source_id for passage in requirement.passages),
                    source_refs,
                ),
            }
        )
    disposition_rank = {"uncertain": 0, "not_met": 1, "partially_met": 2, "met": 3}
    lane_contest_maps = [
        {item.contested_requirement_id: item for item in lane.contested_grades} for lane in lanes
    ]
    for contested_item in baseline.contested_requirements:
        contest = contested_item.contested_requirement
        lane_values: list[str] = []
        for lane_map in lane_contest_maps:
            grade = lane_map[contest.contested_requirement_id]
            choices = (
                str(grade.reviewer_alternative_disposition),
                str(grade.auditor_alternative_disposition),
            )
            lane_values.append(min(choices, key=disposition_rank.__getitem__))
        passage_sources: list[str] = []
        for alternative in (contest.reviewer_alternative, contest.auditor_alternative):
            if alternative is not None:
                passage_sources.extend(passage.source_id for passage in alternative.passages)
        pending.append(
            {
                "origin": "contested_requirement",
                "subject_id": contest.contested_requirement_id,
                "importance": contest.importance.value,
                "lane_1_disposition": lane_values[0],
                "lane_2_disposition": lane_values[1],
                "evidence_refs": _ordered_evidence_refs(
                    f"BASELINE-{contest.contested_requirement_id}",
                    tuple(passage_sources),
                    source_refs,
                ),
            }
        )
    pending.extend(
        {
            "origin": "prerequisite",
            "subject_id": subject_id,
            "importance": importance,
            "lane_1_disposition": None,
            "lane_2_disposition": None,
            "evidence_refs": list(evidence_refs),
        }
        for subject_id, importance, evidence_refs in prerequisites
    )
    expected: list[dict[str, object]] = []
    for index, pending_item in enumerate(pending, 1):
        descriptor = {
            "origin": pending_item["origin"],
            "subject_id": pending_item["subject_id"],
            "lane_1_disposition": pending_item["lane_1_disposition"],
            "lane_2_disposition": pending_item["lane_2_disposition"],
            "baseline_fingerprint": baseline.binding.baseline_fingerprint,
            "report_hash": report_hash,
            "evidence_refs": pending_item["evidence_refs"],
        }
        expected.append(
            {
                "candidate_id": f"GC-{index:04d}",
                "canonical_order": index - 1,
                **descriptor,
                "importance": pending_item["importance"],
                "candidate_fingerprint": sha256_digest(canonical_json_bytes(descriptor)),
            }
        )
    if canonical_json_bytes(raw_candidates) != canonical_json_bytes(expected):
        raise _ControllerInvariant("safety candidate inventory is invalid")


def _validate_common_request_bindings(
    operation: ReadinessOperationV1,
    payload: dict[str, object],
) -> None:
    if operation is ReadinessOperationV1.SAFETY_REFEREE:
        for field in (
            "grade_target_fingerprint",
            "baseline_fingerprint",
            "report_hash",
        ):
            value = payload.get(field)
            if type(value) is not str or _HASH_RE.fullmatch(value) is None:
                raise _ControllerInvariant("referee request binding is invalid")
        dispute_id = payload.get("dispute_id")
        order = payload.get("canonical_order")
        if (
            type(dispute_id) is not str
            or type(order) is not int
            or dispute_id != f"SD-{order + 1:04d}"
            or payload.get("controller_referee_id") != f"safety-referee-{dispute_id}"
        ):
            raise _ControllerInvariant("referee request identity is invalid")
        return
    report = payload.get("report_text")
    report_hash = payload.get("report_hash")
    baseline_raw = payload.get("stable_baseline")
    if (
        type(report) is not str
        or type(report_hash) is not str
        or sha256_digest(report.encode("utf-8")) != report_hash
        or type(baseline_raw) is not dict
        or type(cast(dict[str, object], baseline_raw).get("binding")) is not dict
    ):
        raise _ControllerInvariant("request report or baseline binding is invalid")
    baseline = _verified_baseline(payload)
    if baseline.binding.grade_target_fingerprint != payload.get(
        "grade_target_fingerprint"
    ) or baseline.binding.baseline_fingerprint != payload.get("baseline_fingerprint"):
        raise _ControllerInvariant("request grade-target binding is invalid")
    if operation in {
        ReadinessOperationV1.BASELINE_LOCKED_GRADE,
        ReadinessOperationV1.BASELINE_LOCKED_CONTESTED_GRADE,
    }:
        contract = payload.get("retained_scoring_contract")
        contract_fingerprint = payload.get("retained_scoring_contract_fingerprint")
        if (
            type(contract) is not dict
            or type(contract_fingerprint) is not str
            or sha256_digest(canonical_json_bytes(contract)) != contract_fingerprint
            or payload.get("strict_equivalent_scoring_fingerprint")
            != request_builders.READINESS_STRICT_EQUIVALENT_SCORING_FINGERPRINT_V1
        ):
            raise _ControllerInvariant("request scoring binding is invalid")
        lane = payload.get("lane")
        if type(lane) is not int or lane not in {1, 2}:
            raise _ControllerInvariant("grade request lane is invalid")
        if operation is ReadinessOperationV1.BASELINE_LOCKED_GRADE:
            batch_ref = payload.get("batch_ref")
            match = (
                None
                if type(batch_ref) is not str
                else re.fullmatch(r"GB-([12])-([0-9]{4})", batch_ref)
            )
            batch_size = request_builders.READINESS_COMPILER_CONTRACT_V1.get("ordinary_batch_size")
            if match is None or type(batch_size) is not int:
                raise _ControllerInvariant("ordinary request identity is invalid")
            batch_ordinal = int(match.group(2))
            start = (batch_ordinal - 1) * batch_size
            expected_requirements = baseline.requirements[start : start + batch_size]
            issued = payload.get("requirements")
            if (
                match.group(1) != str(lane)
                or batch_ordinal < 1
                or not expected_requirements
                or type(issued) is not list
                or canonical_json_bytes(issued)
                != canonical_json_bytes(
                    [item.model_dump(mode="json") for item in expected_requirements]
                )
                or payload.get("controller_lane_id") != f"grade-lane-{lane}-{batch_ref}"
            ):
                raise _ControllerInvariant("ordinary request identity is invalid")
        else:
            contest = payload.get("contested_requirement")
            if type(contest) is not dict:
                raise _ControllerInvariant("contested request identity is invalid")
            inner = cast(dict[str, object], contest).get("contested_requirement")
            identifier = (
                None
                if type(inner) is not dict
                else cast(dict[str, object], inner).get("contested_requirement_id")
            )
            matches = [
                item
                for item in baseline.contested_requirements
                if item.contested_requirement.contested_requirement_id == identifier
            ]
            if (
                len(matches) != 1
                or canonical_json_bytes(contest)
                != canonical_json_bytes(matches[0].model_dump(mode="json"))
                or payload.get("controller_lane_id") != f"contested-grade-lane-{lane}-{identifier}"
            ):
                raise _ControllerInvariant("contested request identity is invalid")
        return
    if (
        payload.get("strict_equivalent_scoring_fingerprint")
        != request_builders.READINESS_STRICT_EQUIVALENT_SCORING_FINGERPRINT_V1
    ):
        raise _ControllerInvariant("safety scoring binding is invalid")
    safety_lane = payload.get("lane")
    if (
        type(safety_lane) is not int
        or safety_lane not in {1, 2}
        or payload.get("controller_safety_lane_id") != f"safety-lane-{safety_lane}"
    ):
        raise _ControllerInvariant("safety request identity is invalid")
    prerequisites = _validate_safety_evidence_packet(payload, baseline, report_hash=report_hash)
    handles = set(_request_evidence_refs(payload))
    lanes = payload.get("grader_lanes")
    if type(lanes) is not list or len(lanes) != 2:
        raise _ControllerInvariant("safety grader lanes are invalid")
    checked_lanes: list[BaselineLockedGraderAggregateV1] = []
    for expected_lane, lane_raw in enumerate(cast(list[object], lanes), 1):
        if type(lane_raw) is not dict:
            raise _ControllerInvariant("safety grader lanes are invalid")
        try:
            aggregate = BaselineLockedGraderAggregateV1.model_validate(lane_raw)
            if canonical_json_bytes(aggregate.model_dump(mode="json")) != (
                canonical_json_bytes(lane_raw)
            ):
                raise ValueError
        except (TypeError, ValidationError, ValueError) as error:
            raise _ControllerInvariant("safety grader lanes are invalid") from error
        lane = cast(dict[str, object], lane_raw)
        if (
            aggregate.lane != expected_lane
            or aggregate.grade_target_fingerprint != payload.get("grade_target_fingerprint")
            or aggregate.baseline_fingerprint != payload.get("baseline_fingerprint")
            or aggregate.report_hash != report_hash
            or tuple(item.requirement_id for item in aggregate.requirement_grades)
            != tuple(item.requirement.requirement_id for item in baseline.requirements)
            or tuple(item.contested_requirement_id for item in aggregate.contested_grades)
            != tuple(
                item.contested_requirement.contested_requirement_id
                for item in baseline.contested_requirements
            )
            or not _sealed_fingerprint_valid(lane, "aggregate_fingerprint")
        ):
            raise _ControllerInvariant("safety grader lanes are invalid")
        for fragment in aggregate.ordinary_fragments:
            if not _sealed_fingerprint_valid(
                fragment.model_dump(mode="json"), "fragment_fingerprint"
            ):
                raise _ControllerInvariant("safety grader fragment is invalid")
        for grade in aggregate.contested_grades:
            if not _sealed_fingerprint_valid(grade.model_dump(mode="json"), "grade_fingerprint"):
                raise _ControllerInvariant("safety contested grade is invalid")
        checked_lanes.append(aggregate)
    if len(checked_lanes) != 2:
        raise _ControllerInvariant("safety grader lanes are invalid")
    _validate_exact_safety_candidates(
        payload.get("gap_candidates"),
        baseline,
        (checked_lanes[0], checked_lanes[1]),
        prerequisites,
        report_hash=report_hash,
    )
    candidate_refs = {
        ref
        for candidate in cast(list[dict[str, object]], payload["gap_candidates"])
        for ref in cast(list[str], candidate["evidence_refs"])
    }
    if not candidate_refs.issubset(handles):
        raise _ControllerInvariant("safety candidate inventory is invalid")


def _strict_request(request: object) -> _CheckedRequest:
    if type(request) is not ReadinessEvaluatorRequestV1:
        raise _ControllerInvariant("request type is invalid")
    exact = request
    if type(exact.json_schema) is not _FrozenDict or type(exact.payload) is not _FrozenDict:
        raise _ControllerInvariant("request provenance is invalid")
    try:
        raw = exact.model_dump(mode="json", warnings="error")
        checked = ReadinessEvaluatorRequestV1.model_validate(raw)
    except (AttributeError, TypeError, ValidationError, ValueError) as error:
        raise _ControllerInvariant("request wire is invalid") from error
    descriptor = dict(raw)
    fingerprint = descriptor.pop("request_fingerprint", None)
    if fingerprint != sha256_digest(canonical_json_bytes(descriptor)):
        raise _ControllerInvariant("request fingerprint is invalid")
    payload = raw.get("payload")
    if type(payload) is not dict or set(cast(dict[str, object], payload)) != _exact_payload_keys(
        checked.operation
    ):
        raise _ControllerInvariant("request payload is invalid")
    expected_schema, expected_instruction = _expected_schema_and_instruction(
        checked.operation, cast(dict[str, object], payload)
    )
    _validate_common_request_bindings(checked.operation, cast(dict[str, object], payload))
    if (
        canonical_json_bytes(raw.get("json_schema")) != canonical_json_bytes(expected_schema)
        or raw.get("system_instructions") != expected_instruction
    ):
        raise _ControllerInvariant("request compiler contract is invalid")
    contract = request_builders.READINESS_COMPILER_CONTRACT_V1
    key = _schema_key(checked.operation, raw)
    response_contracts = contract["response_contracts"]
    instructions = contract["instructions"]
    if (
        not isinstance(response_contracts, Mapping)
        or not isinstance(instructions, Mapping)
        or key not in response_contracts
        or key not in instructions
    ):
        raise _ControllerInvariant("request compiler descriptor is invalid")
    return _CheckedRequest(checked, cast(dict[str, object], raw))


def _strict_provenance(value: object) -> ReadinessEvaluatorProvenanceV1:
    if type(value) is not ReadinessEvaluatorProvenanceV1:
        raise _ControllerInvariant("evaluator provenance type is invalid")
    checked = value
    try:
        rebuilt = ReadinessEvaluatorProvenanceV1(
            checked.provider_name,
            checked.model_name,
            checked.judge_isolation,
        )
    except (TypeError, ValueError) as error:
        raise _ControllerInvariant("evaluator provenance is invalid") from error
    if any(_PRIVATE_PATH_RE.search(item) for item in (rebuilt.provider_name, rebuilt.model_name)):
        raise _ControllerInvariant("evaluator provenance is not public-safe")
    return rebuilt


_TOP_LEVEL_SHAPES = {
    ReadinessOperationV1.BASELINE_LOCKED_GRADE: frozenset({"requirement_grades", "rationale"}),
    ReadinessOperationV1.BASELINE_LOCKED_CONTESTED_GRADE: frozenset(
        {
            "contested_requirement_id",
            "reviewer_alternative_disposition",
            "auditor_alternative_disposition",
            "reviewer_report_passages",
            "auditor_report_passages",
            "reviewer_rationale",
            "auditor_rationale",
            "ambiguity_disposition",
            "rationale",
        }
    ),
    ReadinessOperationV1.SAFETY_REVIEW: frozenset({"candidate_assessments", "finding_proposals"}),
    ReadinessOperationV1.SAFETY_REFEREE: frozenset(
        {"dispute_id", "disposition", "rationale", "evidence_refs"}
    ),
}


def _parse_draft(operation: ReadinessOperationV1, draft: object) -> _ParsedDraftV1:
    raw = _bounded_json_object(draft)
    keys = frozenset(raw)
    if keys != _TOP_LEVEL_SHAPES[operation] and keys in set(_TOP_LEVEL_SHAPES.values()):
        raise _Clarification(ReadinessDraftReasonCodeV1.OPERATION_MISMATCH)
    if operation is ReadinessOperationV1.SAFETY_REVIEW:
        for inventory_name in ("candidate_assessments", "finding_proposals"):
            inventory = raw.get(inventory_name)
            if type(inventory) is list:
                for item in cast(list[object], inventory):
                    if type(item) is not dict:
                        continue
                    for field in (
                        "shortfall_description",
                        "why_unresolved",
                        "why_it_matters",
                        "resolution_test",
                    ):
                        value = cast(dict[str, object], item).get(field)
                        if type(value) is not str or not value.strip():
                            raise _Clarification(ReadinessDraftReasonCodeV1.RATIONALE_MISSING)
    try:
        if operation is ReadinessOperationV1.BASELINE_LOCKED_GRADE:
            return _OrdinaryGradeDraftV1.model_validate(raw)
        if operation is ReadinessOperationV1.BASELINE_LOCKED_CONTESTED_GRADE:
            return _ContestedGradeDraftV1.model_validate(raw)
        if operation is ReadinessOperationV1.SAFETY_REVIEW:
            return _SafetyLaneDraftV1.model_validate(raw)
        return _SafetyRefereeDraftV1.model_validate(raw)
    except ValidationError as error:
        text = str(error).lower()
        if "too_long" in text or "at most 640" in text:
            raise _Clarification(ReadinessDraftReasonCodeV1.ITEM_LIMIT_EXCEEDED) from None
        raise _Clarification(ReadinessDraftReasonCodeV1.DRAFT_INVALID) from None


def _exact_prose(value: str, *, rationale: bool = False) -> str:
    if type(value) is not str or not value.strip():
        raise _Clarification(ReadinessDraftReasonCodeV1.RATIONALE_MISSING)
    if value != value.strip():
        raise _Clarification(ReadinessDraftReasonCodeV1.DRAFT_INVALID)
    if rationale and _is_generic(value):
        raise _Clarification(ReadinessDraftReasonCodeV1.RATIONALE_GENERIC)
    return value


def _generic_key(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).casefold().replace("_", " ")
    normalized = "".join(character if character.isalnum() else " " for character in normalized)
    words = normalized.split()
    if words == ["more", "research", "is", "needed"]:
        words.remove("is")
    return " ".join(words)


def _is_generic(value: str) -> bool:
    key = _generic_key(value)
    generic = {_generic_key(item) for item in load_readiness_rubric_v1().generic_rationales}
    generic.update(
        {
            "met",
            "partially met",
            "not met",
            "uncertain",
            "pass",
            "fail",
            "inconclusive",
        }
    )
    return key in generic or re.fullmatch(r"[0-9]+(?: [0-9]+)?", key) is not None


def _has_concrete_substance(value: str) -> bool:
    words = _generic_key(value).split()
    return len(words) >= 5 and any(item in _SPECIFICITY_TERMS for item in words)


def _deduplicate_strings(
    values: list[str],
    *,
    allowed: tuple[str, ...],
    missing_reason: ReadinessDraftReasonCodeV1,
) -> tuple[tuple[str, ...], bool]:
    result: list[str] = []
    for value in values:
        if type(value) is not str or not value.strip():
            raise _Clarification(ReadinessDraftReasonCodeV1.DRAFT_INVALID)
        if value not in allowed:
            raise _Clarification(missing_reason)
        if value != value.strip():
            raise _Clarification(ReadinessDraftReasonCodeV1.DRAFT_INVALID)
        if value not in result:
            result.append(value)
    return tuple(result), len(result) != len(values)


def _deduplicate_evidence(
    values: list[str],
    *,
    allowed: tuple[str, ...],
) -> tuple[tuple[str, ...], bool]:
    return _deduplicate_strings(
        values,
        allowed=allowed,
        missing_reason=ReadinessDraftReasonCodeV1.REFERENCE_UNKNOWN,
    )


def _validate_rationale(
    *,
    shortfall_description: str,
    rationale_kind: RationaleKindV1,
    why_unresolved: str,
    why_it_matters: str,
    evidence_refs: tuple[str, ...],
    all_evidence_refs: tuple[str, ...],
    resolution_test: str,
) -> tuple[str, ...]:
    shortfall = _exact_prose(shortfall_description, rationale=True)
    unresolved = _exact_prose(why_unresolved, rationale=True)
    matters = _exact_prose(why_it_matters, rationale=True)
    resolution = _exact_prose(resolution_test, rationale=True)
    if not _has_concrete_substance(shortfall) or not _has_concrete_substance(unresolved):
        raise _Clarification(ReadinessDraftReasonCodeV1.RATIONALE_GENERIC)
    if _generic_key(unresolved) in {
        _generic_key(shortfall),
        _generic_key(rationale_kind.value),
    }:
        raise _Clarification(ReadinessDraftReasonCodeV1.RATIONALE_GENERIC)
    normalized_matters = _generic_key(matters)
    if not any(item in normalized_matters for item in _CONSEQUENCES):
        raise _Clarification(ReadinessDraftReasonCodeV1.RATIONALE_CONSEQUENCE_MISSING)
    mentioned = tuple(_EVIDENCE_TOKEN_RE.findall(matters))
    remainder = matters
    for value in mentioned:
        remainder = remainder.replace(value, " ")
    for consequence in (
        "legal_conclusion",
        "legal conclusion",
        "applicability",
        "implementation_decision",
        "implementation decision",
        "deadline",
        "enforcement_exposure",
        "enforcement exposure",
        "attorney_follow_up",
        "attorney follow up",
    ):
        remainder = remainder.casefold().replace(consequence, " ")
    if len(_generic_key(remainder).split()) < 3:
        raise _Clarification(ReadinessDraftReasonCodeV1.RATIONALE_GENERIC)
    if any(item not in all_evidence_refs for item in mentioned):
        raise _Clarification(ReadinessDraftReasonCodeV1.REFERENCE_UNKNOWN)
    if not mentioned or not any(item in evidence_refs for item in mentioned):
        raise _Clarification(ReadinessDraftReasonCodeV1.RATIONALE_EVIDENCE_UNBOUND)
    normalized_resolution = _generic_key(resolution)
    if not any(item in normalized_resolution for item in _RESOLUTION_OUTCOMES) or not any(
        item in normalized_resolution for item in _RESOLUTION_ACTIONS
    ):
        raise _Clarification(ReadinessDraftReasonCodeV1.RESOLUTION_TEST_INVALID)
    return mentioned


def _seal(
    model_type: type[BaseModel], fingerprint_field: str, values: dict[str, object]
) -> BaseModel:
    descriptor = dict(values)
    fingerprint = sha256_digest(canonical_json_bytes(descriptor))
    return model_type.model_validate({**descriptor, fingerprint_field: fingerprint})


def _compile_ordinary(
    checked: _CheckedRequest,
    draft: _OrdinaryGradeDraftV1,
) -> tuple[dict[str, object], tuple[str, ...]]:
    payload = cast(dict[str, object], checked.raw["payload"])
    requirements = cast(list[dict[str, object]], payload["requirements"])
    identifiers = tuple(
        cast(str, cast(dict[str, object], item["requirement"])["requirement_id"])
        for item in requirements
    )
    allowlist = _request_allowlist(payload)
    compiled_by_id: dict[str, dict[str, object]] = {}
    observed: list[str] = []
    normalized = False
    for grade in draft.requirement_grades:
        if grade.requirement_id not in identifiers:
            raise _Clarification(ReadinessDraftReasonCodeV1.COVERAGE_INVALID)
        passages, removed = _deduplicate_strings(
            grade.report_passages,
            allowed=allowlist,
            missing_reason=ReadinessDraftReasonCodeV1.EVIDENCE_NOT_FOUND,
        )
        normalized = normalized or removed
        rationale = _exact_prose(grade.rationale)
        omission = None if grade.omission is None else _exact_prose(grade.omission)
        strict = RequirementGradeV2(
            requirement_id=grade.requirement_id,
            disposition=grade.disposition,
            report_passages=list(passages),
            rationale=rationale,
            omission=omission,
        )
        raw = strict.model_dump(mode="json")
        prior = compiled_by_id.get(grade.requirement_id)
        if prior is not None:
            if canonical_json_bytes(prior) != canonical_json_bytes(raw):
                raise _Clarification(ReadinessDraftReasonCodeV1.CONFLICTING_ITEMS)
            normalized = True
            continue
        compiled_by_id[grade.requirement_id] = raw
        observed.append(grade.requirement_id)
    if tuple(observed) != identifiers:
        raise _Clarification(ReadinessDraftReasonCodeV1.COVERAGE_INVALID)
    values = {
        "protocol_version": "delivery-readiness-v1",
        "lane": payload["lane"],
        "batch_ref": payload["batch_ref"],
        "grade_target_fingerprint": payload["grade_target_fingerprint"],
        "baseline_fingerprint": payload["baseline_fingerprint"],
        "report_hash": payload["report_hash"],
        "strict_equivalent_scoring_contract_fingerprint": payload[
            "retained_scoring_contract_fingerprint"
        ],
        "requirement_grades": [compiled_by_id[item] for item in identifiers],
        "rationale": _exact_prose(draft.rationale),
    }
    strict_fragment = cast(
        BaselineLockedGradeFragmentV1,
        _seal(BaselineLockedGradeFragmentV1, "fragment_fingerprint", values),
    )
    codes = (_NORMALIZED_DUPLICATES,) if normalized else ()
    return strict_fragment.model_dump(mode="json"), codes


def _compile_contested(
    checked: _CheckedRequest,
    draft: _ContestedGradeDraftV1,
) -> tuple[dict[str, object], tuple[str, ...]]:
    payload = cast(dict[str, object], checked.raw["payload"])
    contest = cast(dict[str, object], payload["contested_requirement"])
    identifier = cast(
        str, cast(dict[str, object], contest["contested_requirement"])["contested_requirement_id"]
    )
    if draft.contested_requirement_id != identifier:
        raise _Clarification(ReadinessDraftReasonCodeV1.COVERAGE_INVALID)
    allowlist = _request_allowlist(payload)
    reviewer, reviewer_removed = _deduplicate_strings(
        draft.reviewer_report_passages,
        allowed=allowlist,
        missing_reason=ReadinessDraftReasonCodeV1.EVIDENCE_NOT_FOUND,
    )
    auditor, auditor_removed = _deduplicate_strings(
        draft.auditor_report_passages,
        allowed=allowlist,
        missing_reason=ReadinessDraftReasonCodeV1.EVIDENCE_NOT_FOUND,
    )
    values = {
        "protocol_version": "delivery-readiness-v1",
        "lane": payload["lane"],
        "contested_requirement_id": identifier,
        "grade_target_fingerprint": payload["grade_target_fingerprint"],
        "baseline_fingerprint": payload["baseline_fingerprint"],
        "report_hash": payload["report_hash"],
        "strict_equivalent_scoring_contract_fingerprint": payload[
            "retained_scoring_contract_fingerprint"
        ],
        "reviewer_alternative_disposition": draft.reviewer_alternative_disposition,
        "auditor_alternative_disposition": draft.auditor_alternative_disposition,
        "reviewer_report_passages": list(reviewer),
        "auditor_report_passages": list(auditor),
        "reviewer_rationale": _exact_prose(draft.reviewer_rationale),
        "auditor_rationale": _exact_prose(draft.auditor_rationale),
        "ambiguity_disposition": draft.ambiguity_disposition,
        "rationale": _exact_prose(draft.rationale),
    }
    strict_grade = cast(
        BaselineLockedContestedGradeV1,
        _seal(BaselineLockedContestedGradeV1, "grade_fingerprint", values),
    )
    codes = (_NORMALIZED_DUPLICATES,) if reviewer_removed or auditor_removed else ()
    return strict_grade.model_dump(mode="json"), codes


def _candidate_map(payload: dict[str, object]) -> dict[str, SafetyGapCandidateV1]:
    raw = cast(list[object], payload["gap_candidates"])
    candidates = tuple(SafetyGapCandidateV1.model_validate(item) for item in raw)
    return {item.candidate_id: item for item in candidates}


def _validate_rationale_evidence_kind(
    rationale_kind: RationaleKindV1,
    evidence_refs: tuple[str, ...],
    *,
    scoped_refs: tuple[str, ...] | None = None,
    mentioned_refs: tuple[str, ...],
) -> None:
    required_prefixes: tuple[str, ...] | None
    if rationale_kind in {
        RationaleKindV1.SOURCE_ABSENT,
        RationaleKindV1.SOURCE_AMBIGUOUS,
        RationaleKindV1.SOURCE_CONFLICT,
    }:
        required_prefixes = ("SOURCE-",)
    elif rationale_kind is RationaleKindV1.CURRENTNESS_NOT_ESTABLISHED:
        required_prefixes = ("PREREQUISITE-CURRENTNESS-",)
    elif rationale_kind is RationaleKindV1.LANGUAGE_LIMITATION:
        required_prefixes = ("PREREQUISITE-LANGUAGE-",)
    elif rationale_kind is RationaleKindV1.APPLICABILITY_FACT_MISSING:
        required_prefixes = ("PREREQUISITE-CLIENT-FACTS",)
    else:
        required_prefixes = None
    scoped = set(evidence_refs if scoped_refs is None else scoped_refs)
    if required_prefixes is not None and not any(
        ref in scoped and ref in mentioned_refs and ref.startswith(required_prefixes)
        for ref in evidence_refs
    ):
        raise _Clarification(ReadinessDraftReasonCodeV1.RATIONALE_EVIDENCE_UNBOUND)


def _compile_assessment(
    item: _SafetyGapAssessmentDraftV1,
    candidate: SafetyGapCandidateV1,
    *,
    all_refs: tuple[str, ...],
    allowlist: tuple[str, ...],
) -> tuple[SafetyGapAssessmentV1, bool]:
    refs, ref_removed = _deduplicate_evidence(item.evidence_refs, allowed=all_refs)
    passages, passage_removed = _deduplicate_strings(
        item.report_passages,
        allowed=allowlist,
        missing_reason=ReadinessDraftReasonCodeV1.EVIDENCE_NOT_FOUND,
    )
    rationale_kind = RationaleKindV1(item.rationale_kind)
    mentioned_refs = _validate_rationale(
        shortfall_description=item.shortfall_description,
        rationale_kind=rationale_kind,
        why_unresolved=item.why_unresolved,
        why_it_matters=item.why_it_matters,
        evidence_refs=refs,
        all_evidence_refs=all_refs,
        resolution_test=item.resolution_test,
    )
    _validate_rationale_evidence_kind(
        rationale_kind,
        refs,
        scoped_refs=candidate.evidence_refs,
        mentioned_refs=mentioned_refs,
    )
    if not set(refs).intersection(candidate.evidence_refs):
        raise _Clarification(ReadinessDraftReasonCodeV1.RATIONALE_EVIDENCE_UNBOUND)
    if candidate.importance is BaselineImportanceV1.CRITICAL:
        if item.visibility != GapVisibilityV1.PROMINENT.value:
            raise _Clarification(ReadinessDraftReasonCodeV1.CRITICAL_VISIBILITY_INVALID)
        if item.owner_role not in {
            OwnerRoleV1.REVIEWING_ATTORNEY.value,
            OwnerRoleV1.OUTSIDE_COUNSEL.value,
        }:
            raise _Clarification(ReadinessDraftReasonCodeV1.CRITICAL_OWNER_INVALID)
    strict = SafetyGapAssessmentV1(
        candidate_id=candidate.candidate_id,
        shortfall_description=_exact_prose(item.shortfall_description),
        rationale_kind=rationale_kind,
        why_unresolved=_exact_prose(item.why_unresolved),
        why_it_matters=_exact_prose(item.why_it_matters),
        evidence_refs=refs,
        report_passages=passages,
        disclosure_location=(
            None if item.disclosure_location is None else _exact_prose(item.disclosure_location)
        ),
        visibility=GapVisibilityV1(item.visibility),
        blocking_code=(None if item.blocking_code is None else _exact_prose(item.blocking_code)),
        follow_up_code=FollowUpCodeV1(item.follow_up_code),
        resolution_test=_exact_prose(item.resolution_test),
        owner_role=OwnerRoleV1(item.owner_role),
    )
    return strict, ref_removed or passage_removed


def _compile_finding(
    item: _SafetyFindingDraftV1,
    *,
    all_refs: tuple[str, ...],
    allowlist: tuple[str, ...],
) -> tuple[SafetyFindingProposalV1, bool]:
    refs, ref_removed = _deduplicate_evidence(item.evidence_refs, allowed=all_refs)
    passages, passage_removed = _deduplicate_strings(
        item.report_passages,
        allowed=allowlist,
        missing_reason=ReadinessDraftReasonCodeV1.EVIDENCE_NOT_FOUND,
    )
    finding_kind = SafetyFindingKindV1(item.finding_kind)
    if finding_kind in _REPORT_CONTENT_FINDINGS and not passages:
        raise _Clarification(ReadinessDraftReasonCodeV1.REPORT_PASSAGE_REQUIRED)
    rationale_kind = RationaleKindV1(item.rationale_kind)
    mentioned_refs = _validate_rationale(
        shortfall_description=item.shortfall_description,
        rationale_kind=rationale_kind,
        why_unresolved=item.why_unresolved,
        why_it_matters=item.why_it_matters,
        evidence_refs=refs,
        all_evidence_refs=all_refs,
        resolution_test=item.resolution_test,
    )
    _validate_rationale_evidence_kind(
        rationale_kind,
        refs,
        mentioned_refs=mentioned_refs,
    )
    if (
        item.blocking_code is not None
        and item.blocking_code not in load_readiness_rubric_v1().blocking_codes
    ):
        raise _Clarification(ReadinessDraftReasonCodeV1.REFERENCE_UNKNOWN)
    if item.blocking_code is not None or finding_kind in _REPORT_CONTENT_FINDINGS:
        if item.visibility != GapVisibilityV1.PROMINENT.value:
            raise _Clarification(ReadinessDraftReasonCodeV1.CRITICAL_VISIBILITY_INVALID)
        if item.owner_role not in {
            OwnerRoleV1.REVIEWING_ATTORNEY.value,
            OwnerRoleV1.OUTSIDE_COUNSEL.value,
        }:
            raise _Clarification(ReadinessDraftReasonCodeV1.CRITICAL_OWNER_INVALID)
    strict = SafetyFindingProposalV1(
        finding_kind=finding_kind,
        subject_id=_exact_prose(item.subject_id),
        report_passages=passages,
        shortfall_description=_exact_prose(item.shortfall_description),
        rationale_kind=rationale_kind,
        why_unresolved=_exact_prose(item.why_unresolved),
        why_it_matters=_exact_prose(item.why_it_matters),
        evidence_refs=refs,
        disclosure_location=(
            None if item.disclosure_location is None else _exact_prose(item.disclosure_location)
        ),
        visibility=GapVisibilityV1(item.visibility),
        blocking_code=(None if item.blocking_code is None else _exact_prose(item.blocking_code)),
        follow_up_code=FollowUpCodeV1(item.follow_up_code),
        resolution_test=_exact_prose(item.resolution_test),
        owner_role=OwnerRoleV1(item.owner_role),
    )
    return strict, ref_removed or passage_removed


def _compile_safety(
    checked: _CheckedRequest,
    draft: _SafetyLaneDraftV1,
) -> tuple[dict[str, object], tuple[str, ...]]:
    payload = cast(dict[str, object], checked.raw["payload"])
    candidates = _candidate_map(payload)
    expected_ids = tuple(candidates)
    all_refs = _request_evidence_refs(payload)
    allowlist = _request_allowlist(payload)
    assessments: dict[str, SafetyGapAssessmentV1] = {}
    observed: list[str] = []
    normalized = False
    for item in draft.candidate_assessments:
        candidate = candidates.get(item.candidate_id)
        if candidate is None:
            raise _Clarification(ReadinessDraftReasonCodeV1.COVERAGE_INVALID)
        strict, removed = _compile_assessment(
            item,
            candidate,
            all_refs=all_refs,
            allowlist=allowlist,
        )
        prior = assessments.get(item.candidate_id)
        if prior is not None:
            if canonical_json_bytes(prior) != canonical_json_bytes(strict):
                raise _Clarification(ReadinessDraftReasonCodeV1.CONFLICTING_ITEMS)
            normalized = True
            continue
        assessments[item.candidate_id] = strict
        observed.append(item.candidate_id)
        normalized = normalized or removed
    if tuple(observed) != expected_ids:
        raise _Clarification(ReadinessDraftReasonCodeV1.COVERAGE_INVALID)
    findings: dict[tuple[SafetyFindingKindV1, str], SafetyFindingProposalV1] = {}
    finding_order: list[tuple[SafetyFindingKindV1, str]] = []
    for finding_item in draft.finding_proposals:
        strict_finding, removed = _compile_finding(
            finding_item,
            all_refs=all_refs,
            allowlist=allowlist,
        )
        identity = (strict_finding.finding_kind, strict_finding.subject_id)
        prior_finding = findings.get(identity)
        if prior_finding is not None:
            if canonical_json_bytes(prior_finding) != canonical_json_bytes(strict_finding):
                raise _Clarification(ReadinessDraftReasonCodeV1.CONFLICTING_ITEMS)
            normalized = True
            continue
        findings[identity] = strict_finding
        finding_order.append(identity)
        normalized = normalized or removed
    lane = payload.get("lane")
    if type(lane) is not int or lane not in {1, 2}:
        raise _ControllerInvariant("safety lane is invalid")
    strict_lane = SafetyLaneResponseV1(
        lane=cast(Literal[1, 2], lane),
        candidate_assessments=tuple(assessments[item] for item in expected_ids),
        finding_proposals=tuple(findings[item] for item in finding_order),
    )
    return strict_lane.model_dump(mode="json"), ((_NORMALIZED_DUPLICATES,) if normalized else ())


def _compile_referee(
    checked: _CheckedRequest,
    draft: _SafetyRefereeDraftV1,
) -> tuple[dict[str, object], tuple[str, ...]]:
    payload = cast(dict[str, object], checked.raw["payload"])
    if draft.dispute_id != payload.get("dispute_id"):
        raise _Clarification(ReadinessDraftReasonCodeV1.COVERAGE_INVALID)
    allowed = tuple(cast(list[str], payload["evidence_refs"]))
    refs, removed = _deduplicate_evidence(draft.evidence_refs, allowed=allowed)
    rationale = _exact_prose(draft.rationale, rationale=True)
    if allowed and not refs:
        raise _Clarification(ReadinessDraftReasonCodeV1.RATIONALE_EVIDENCE_UNBOUND)
    strict = SafetyRefereeDecisionV1(
        dispute_id=draft.dispute_id,
        disposition=draft.disposition,
        rationale=rationale,
        evidence_refs=refs,
    )
    return strict.model_dump(mode="json"), ((_NORMALIZED_DUPLICATES,) if removed else ())


def _compile_payload(
    checked: _CheckedRequest,
    parsed: _ParsedDraftV1,
) -> tuple[dict[str, object], tuple[str, ...]]:
    operation = checked.request.operation
    if operation is ReadinessOperationV1.BASELINE_LOCKED_GRADE:
        if type(parsed) is not _OrdinaryGradeDraftV1:
            raise _ControllerInvariant("ordinary draft dispatch is invalid")
        return _compile_ordinary(checked, parsed)
    if operation is ReadinessOperationV1.BASELINE_LOCKED_CONTESTED_GRADE:
        if type(parsed) is not _ContestedGradeDraftV1:
            raise _ControllerInvariant("contested draft dispatch is invalid")
        return _compile_contested(checked, parsed)
    if operation is ReadinessOperationV1.SAFETY_REVIEW:
        if type(parsed) is not _SafetyLaneDraftV1:
            raise _ControllerInvariant("safety draft dispatch is invalid")
        return _compile_safety(checked, parsed)
    if type(parsed) is not _SafetyRefereeDraftV1:
        raise _ControllerInvariant("referee draft dispatch is invalid")
    return _compile_referee(checked, parsed)


def compile_readiness_draft_v1(
    request: ReadinessEvaluatorRequestV1,
    draft: object,
    provenance: ReadinessEvaluatorProvenanceV1,
) -> ReadinessDraftCompileOutcomeV1:
    """Compile one untrusted draft into a strict controller-owned response."""
    try:
        checked = _strict_request(request)
        checked_provenance = _strict_provenance(provenance)
    except (
        _ControllerInvariant,
        AttributeError,
        KeyError,
        TypeError,
        ValidationError,
        ValueError,
        RecursionError,
        UnicodeError,
    ):
        return ReadinessEngineDefectV1("READINESS_COMPILER_INVARIANT")
    try:
        parsed = _parse_draft(checked.request.operation, draft)
        payload, normalization_codes = _compile_payload(checked, parsed)
    except _Clarification as error:
        return NeedsReadinessClarificationV1(error.reason_codes)
    except (AttributeError, KeyError, TypeError, ValidationError, ValueError, RecursionError):
        return ReadinessEngineDefectV1("READINESS_COMPILER_INVARIANT")
    try:
        response = ReadinessEvaluatorResponseV1(
            operation=checked.request.operation,
            request_fingerprint=checked.request.request_fingerprint,
            provider_name=checked_provenance.provider_name,
            model_name=checked_provenance.model_name,
            judge_isolation=checked_provenance.judge_isolation,
            payload=payload,
        )
    except (TypeError, ValidationError, ValueError, RecursionError):
        return ReadinessEngineDefectV1("READINESS_COMPILER_PREFLIGHT_DISAGREEMENT")
    return CompiledReadinessDraftV1(response, normalization_codes)


__all__ = [
    "CompiledReadinessDraftV1",
    "NeedsReadinessClarificationV1",
    "ReadinessDraftCompileOutcomeV1",
    "ReadinessDraftReasonCodeV1",
    "ReadinessEngineDefectV1",
    "ReadinessEvaluatorDraftPromptV1",
    "ReadinessEvaluatorProvenanceV1",
    "compile_readiness_draft_v1",
]
