"""Bounded semantic-draft parsing and compilation for evaluator protocol 2.2.

Drafts are deliberately short-lived controller inputs.  They are never a
persisted response: this module resolves only request-local evidence and builds
the strict response envelope owned by the controller.
"""

from __future__ import annotations

import json
import re
import warnings
from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated, Literal, TypeAlias

from pydantic import Field, ValidationError, field_validator, model_validator

from regulatory_harvest.storage import canonical_json_bytes

from .attorney_v2_models import (
    SemanticPassage,
    SemanticProposal,
    V2StrictModel,
    _nonblank,
    _optional_nonblank,
)
from .attorney_v22_models import (
    AuditConcernV22,
    ContestedAlternativeGradeV22,
    ContestedGradeFragmentV22,
    EvaluatorOperationV22,
    EvaluatorRequestV22,
    EvaluatorResponseV22,
    IndexedProposalV22,
    OrdinaryGradeFragmentV22,
    RefereeDecisionV22,
    RefereeEvidenceV22,
    SourceAuditFragmentV22,
    SourceReviewFragmentV22,
    _strict_rehydrate_v22,
)

_MAX_DRAFT_BYTES = 262_144
_WHITESPACE = re.compile(r"\s+")
_LocalOrdinalV22 = Annotated[int, Field(strict=True, ge=1)]
_ENUM_ALIASES: dict[str, frozenset[str]] = {
    "kind": frozenset(
        {
            "obligation",
            "prohibition",
            "permission",
            "exception",
            "definition",
            "deadline",
            "enforcement",
            "gap",
        }
    ),
    "importance": frozenset({"critical", "material", "supporting"}),
    "confidence": frozenset({"clear", "ambiguous", "unresolved"}),
    "decision": frozenset({"accept_reviewer", "accept_auditor", "unresolved"}),
    "disposition": frozenset({"met", "partially_met", "not_met", "uncertain"}),
    "ambiguity_disposition": frozenset({"acknowledged", "overstated", "omitted", "uncertain"}),
}


class DraftReasonCodeV22(StrEnum):
    """Public-safe reasons a draft needs a fresh semantic clarification."""

    DRAFT_INVALID = "DRAFT_INVALID"
    DRAFT_TOO_LARGE = "DRAFT_TOO_LARGE"
    EVIDENCE_NOT_FOUND = "EVIDENCE_NOT_FOUND"
    EVIDENCE_AMBIGUOUS = "EVIDENCE_AMBIGUOUS"
    REFERENCE_UNKNOWN = "REFERENCE_UNKNOWN"
    SUBSTANCE_MISSING = "SUBSTANCE_MISSING"
    ITEM_LIMIT_EXCEEDED = "ITEM_LIMIT_EXCEEDED"
    CONFLICTING_ITEMS = "CONFLICTING_ITEMS"


@dataclass(frozen=True)
class EvaluatorProvenanceV22:
    """Controller-supplied, truthful evaluator provenance."""

    provider_name: str
    model_name: str
    judge_isolation: Literal["fresh_context", "scripted_fixture"]

    def __post_init__(self) -> None:
        if not isinstance(self.provider_name, str) or not self.provider_name.strip():
            raise ValueError("provider_name must be nonblank")
        if not isinstance(self.model_name, str) or not self.model_name.strip():
            raise ValueError("model_name must be nonblank")


@dataclass(frozen=True)
class EvaluatorDraftPromptV22:
    """One safe draft prompt; rejected draft content is intentionally absent."""

    request: EvaluatorRequestV22
    attempt: Literal[1, 2]
    clarification_codes: tuple[DraftReasonCodeV22, ...] = ()


@dataclass(frozen=True)
class CompiledDraftV22:
    response: EvaluatorResponseV22
    normalization_codes: tuple[str, ...] = ()


@dataclass(frozen=True)
class NeedsClarificationV22:
    reason_codes: tuple[DraftReasonCodeV22, ...]


@dataclass(frozen=True)
class EngineDefectV22:
    reason_code: Literal["COMPILER_INVARIANT", "COMPILER_PREFLIGHT_DISAGREEMENT"]


DraftCompileOutcomeV22: TypeAlias = CompiledDraftV22 | NeedsClarificationV22 | EngineDefectV22


class _DependencyDraftV22(V2StrictModel):
    relationship: Literal["depends_on", "exception_to", "defines", "enforced_by"]
    target_ordinal: _LocalOrdinalV22


class _ProposalDraftV22(V2StrictModel):
    statement: str
    kind: Literal[
        "obligation",
        "prohibition",
        "permission",
        "exception",
        "definition",
        "deadline",
        "enforcement",
        "gap",
    ]
    importance: Literal["critical", "material", "supporting"]
    passages: tuple[SemanticPassage, ...] = Field(min_length=1, max_length=5)
    dependency: _DependencyDraftV22 | None = None
    confidence: Literal["clear", "ambiguous", "unresolved"]
    rationale: str

    _validate_text = field_validator("statement", "rationale")(_nonblank)

    @field_validator("passages")
    @classmethod
    def reject_duplicate_passages(
        cls, values: tuple[SemanticPassage, ...]
    ) -> tuple[SemanticPassage, ...]:
        if len(values) != len(set(values)):
            raise ValueError("draft proposal passages must be unique")
        return values


class _SourceReviewDraftV22(V2StrictModel):
    proposals: tuple[_ProposalDraftV22, ...] = Field(max_length=5)
    review_complete: bool

    @model_validator(mode="after")
    def validate_progress(self) -> _SourceReviewDraftV22:
        if not self.review_complete and not self.proposals:
            raise ValueError("nonfinal source-review drafts require one proposal")
        return self


class _AuditConcernDraftV22(V2StrictModel):
    target_proposal_ordinal: _LocalOrdinalV22 | None = None
    concern_type: Literal[
        "omission",
        "incorrect_statement",
        "incorrect_evidence",
        "incorrect_relationship",
        "ambiguity",
    ]
    passages: tuple[SemanticPassage, ...] = Field(min_length=1, max_length=5)
    explanation: str
    correction: _ProposalDraftV22 | None = None

    _validate_explanation = field_validator("explanation")(_nonblank)

    @field_validator("passages")
    @classmethod
    def reject_duplicate_passages(
        cls, values: tuple[SemanticPassage, ...]
    ) -> tuple[SemanticPassage, ...]:
        if len(values) != len(set(values)):
            raise ValueError("draft audit passages must be unique")
        return values


class _SourceAuditDraftV22(V2StrictModel):
    concerns: tuple[_AuditConcernDraftV22, ...] = Field(max_length=5)
    audit_complete: bool

    @model_validator(mode="after")
    def validate_progress(self) -> _SourceAuditDraftV22:
        if not self.audit_complete and not self.concerns:
            raise ValueError("nonfinal source-audit drafts require one concern")
        return self


class _RefereeDraftV22(V2StrictModel):
    decision: Literal["accept_reviewer", "accept_auditor", "unresolved"]
    unresolved_reason: Literal[
        "SOURCE_AMBIGUITY", "SOURCE_CONFLICT", "SOURCE_GAP", "BOTH_POSITIONS_UNSUPPORTED"
    ] | None = None
    evidence_ordinals: tuple[_LocalOrdinalV22, ...] = Field(min_length=1, max_length=5)
    rationale: str

    _validate_rationale = field_validator("rationale")(_nonblank)

    @model_validator(mode="after")
    def validate_unresolved_reason(self) -> _RefereeDraftV22:
        if (self.decision == "unresolved") != (self.unresolved_reason is not None):
            raise ValueError("unresolved decisions require one unresolved reason")
        return self


class _RequirementGradeDraftV22(V2StrictModel):
    requirement_ordinal: _LocalOrdinalV22
    disposition: Literal["met", "partially_met", "not_met", "uncertain"]
    report_passages: tuple[str, ...] = Field(max_length=5)
    rationale: str
    omission: str | None = None

    _validate_rationale = field_validator("rationale")(_nonblank)
    _validate_omission = field_validator("omission")(_optional_nonblank)


class _OrdinaryGradeDraftV22(V2StrictModel):
    requirement_grades: tuple[_RequirementGradeDraftV22, ...] = Field(min_length=1, max_length=5)
    rationale: str

    _validate_rationale = field_validator("rationale")(_nonblank)


class _ContestedGradeDraftV22(V2StrictModel):
    reviewer_alternative_grade: ContestedAlternativeGradeV22
    auditor_alternative_grade: ContestedAlternativeGradeV22
    ambiguity_disposition: Literal["acknowledged", "overstated", "omitted", "uncertain"]
    rationale: str

    _validate_rationale = field_validator("rationale")(_nonblank)


_ParsedDraftV22: TypeAlias = (
    _SourceReviewDraftV22
    | _SourceAuditDraftV22
    | _RefereeDraftV22
    | _OrdinaryGradeDraftV22
    | _ContestedGradeDraftV22
)


class _DraftNeedsClarificationV22(ValueError):
    def __init__(self, *reason_codes: DraftReasonCodeV22) -> None:
        super().__init__("draft needs clarification")
        self.reason_codes = reason_codes


class _ControllerInvariantV22(ValueError):
    """A controller-owned request or compiled strict value was inconsistent."""


def _reason_codes(error: BaseException) -> tuple[DraftReasonCodeV22, ...]:
    text = str(error).lower()
    if "too large" in text:
        return (DraftReasonCodeV22.DRAFT_TOO_LARGE,)
    if "at most 5" in text or "max_length" in text:
        return (DraftReasonCodeV22.ITEM_LIMIT_EXCEEDED,)
    if "field required" in text or "nonblank" in text or "string should have" in text:
        return (DraftReasonCodeV22.SUBSTANCE_MISSING,)
    return (DraftReasonCodeV22.DRAFT_INVALID,)


def _bounded_json_object(value: object) -> dict[str, object]:
    def reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError("draft JSON contains duplicate object keys")
            result[key] = item
        return result

    if isinstance(value, bytes):
        if len(value) > _MAX_DRAFT_BYTES:
            raise ValueError("draft is too large")
        value = value.decode("utf-8")
    if isinstance(value, str):
        if len(value.encode("utf-8")) > _MAX_DRAFT_BYTES:
            raise ValueError("draft is too large")
        value = json.loads(value, object_pairs_hook=reject_duplicate_pairs)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            encoded = canonical_json_bytes(value)
    except Exception:
        raise ValueError("draft is not bounded JSON") from None
    if len(encoded) > _MAX_DRAFT_BYTES:
        raise ValueError("draft is too large")
    decoded = json.loads(encoded, object_pairs_hook=reject_duplicate_pairs)
    if type(decoded) is not dict:
        raise TypeError("draft must be one JSON object")
    return decoded


def _trim_prose(value: object, *, quoted: bool = False) -> object:
    if isinstance(value, dict):
        return {
            key: _trim_prose(item, quoted=(key in {"quote", "report_passages"}))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_trim_prose(item, quoted=quoted) for item in value]
    if isinstance(value, str) and not quoted:
        return value.strip()
    return value


def _normalize_enum_aliases(value: object) -> object:
    if isinstance(value, dict):
        result: dict[str, object] = {}
        for key, item in value.items():
            if key in _ENUM_ALIASES and isinstance(item, str):
                candidate = item.casefold()
                result[key] = candidate if candidate in _ENUM_ALIASES[key] else item
            else:
                result[key] = _normalize_enum_aliases(item)
        return result
    if isinstance(value, list):
        return [_normalize_enum_aliases(item) for item in value]
    return value


def _parse_operation_draft_v22(operation: EvaluatorOperationV22, draft: object) -> _ParsedDraftV22:
    raw = _normalize_enum_aliases(_trim_prose(_bounded_json_object(draft)))
    if operation is EvaluatorOperationV22.SOURCE_REVIEW_FRAGMENT:
        return _SourceReviewDraftV22.model_validate(raw)
    if operation is EvaluatorOperationV22.SOURCE_AUDIT_FRAGMENT:
        return _SourceAuditDraftV22.model_validate(raw)
    if operation is EvaluatorOperationV22.SOURCE_REFEREE_FRAGMENT:
        return _RefereeDraftV22.model_validate(raw)
    if operation is EvaluatorOperationV22.ORDINARY_GRADE_FRAGMENT:
        return _OrdinaryGradeDraftV22.model_validate(raw)
    if operation is EvaluatorOperationV22.CONTESTED_GRADE_FRAGMENT:
        return _ContestedGradeDraftV22.model_validate(raw)
    raise ValueError("unknown evaluator draft operation")


def parse_evaluator_draft_v22(
    request: EvaluatorRequestV22, draft: object
) -> _ParsedDraftV22:
    """Parse an evaluator draft without constructing an accepted response."""
    checked_request = _strict_request_v22(request)
    return _parse_operation_draft_v22(checked_request.operation, draft)


def _strict_request_v22(request: object) -> EvaluatorRequestV22:
    """Revalidate raw request wire data before dispatching an operation."""
    if not isinstance(request, EvaluatorRequestV22):
        raise _ControllerInvariantV22("request is not a strict evaluator request")
    try:
        raw = request.model_dump(mode="json", warnings="error")
        return EvaluatorRequestV22.model_validate(raw)
    except Exception as error:
        raise _ControllerInvariantV22("request wire representation is invalid") from error


def _source_texts(request: EvaluatorRequestV22) -> dict[str, str]:
    record = request.payload.get("source_record")
    if not isinstance(record, dict) or not isinstance(record.get("sources"), list):
        raise _ControllerInvariantV22("source-record request payload is invalid")
    texts: dict[str, str] = {}
    for source in record["sources"]:
        if not isinstance(source, dict):
            raise _ControllerInvariantV22("source-record request payload is invalid")
        source_id = source.get("source_id")
        text = source.get("normalized_text")
        if type(source_id) is not str or type(text) is not str or source_id in texts:
            raise _ControllerInvariantV22("source-record request payload is invalid")
        texts[source_id] = text
    return texts


def _resolve_quote(source_id: str, quote: str, source_texts: dict[str, str]) -> tuple[str, bool]:
    text = source_texts.get(source_id)
    if text is None:
        raise _DraftNeedsClarificationV22(DraftReasonCodeV22.REFERENCE_UNKNOWN)
    exact = [match.start() for match in re.finditer(re.escape(quote), text)]
    if len(exact) == 1:
        return quote, False
    if len(exact) > 1:
        raise _DraftNeedsClarificationV22(DraftReasonCodeV22.EVIDENCE_AMBIGUOUS)
    pieces = _WHITESPACE.split(quote)
    normalized_pattern = r"\s+".join(re.escape(piece) for piece in pieces)
    matches = [
        match.group(1)
        for match in re.finditer(f"(?=({normalized_pattern}))", text)
    ]
    if len(matches) == 1:
        return matches[0], True
    if len(matches) > 1:
        raise _DraftNeedsClarificationV22(DraftReasonCodeV22.EVIDENCE_AMBIGUOUS)
    raise _DraftNeedsClarificationV22(DraftReasonCodeV22.EVIDENCE_NOT_FOUND)


def _resolve_passages(
    values: tuple[SemanticPassage, ...], source_texts: dict[str, str]
) -> tuple[list[dict[str, str]], bool, bool]:
    """Bind passages and remove only duplicates made byte-identical by binding."""
    passages: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    evidence_normalized = False
    duplicate_removed = False
    for passage in values:
        quote, changed = _resolve_quote(passage.source_id, passage.quote, source_texts)
        key = (passage.source_id, quote)
        evidence_normalized = evidence_normalized or changed
        if key in seen:
            duplicate_removed = True
            continue
        seen.add(key)
        passages.append({"source_id": passage.source_id, "quote": quote})
    return passages, evidence_normalized, duplicate_removed


def _controller_proposal_inventory(
    inventory: object,
    *,
    location: str,
    source_texts: dict[str, str] | None = None,
) -> tuple[tuple[str, str], ...]:
    if not isinstance(inventory, list):
        raise _ControllerInvariantV22(f"{location} proposal inventory is invalid")
    entries: list[tuple[str, str]] = []
    seen_proposals: set[bytes] = set()
    for ordinal, item in enumerate(inventory, 1):
        if not isinstance(item, dict):
            raise _ControllerInvariantV22(f"{location} proposal inventory is invalid")
        try:
            if location == "source-review":
                if "proposal_ref" in item or "proposal" in item:
                    indexed = _strict_rehydrate_v22(
                        IndexedProposalV22,
                        item,
                        location="source-review indexed accepted proposal",
                    )
                    if indexed.proposal_ref != f"P{ordinal:04d}":
                        raise ValueError("source-review accepted proposal order is invalid")
                    proposal = indexed.proposal
                else:
                    proposal = _strict_rehydrate_v22(
                        SemanticProposal,
                        item,
                        location="source-review accepted proposal",
                    )
                if source_texts is None:
                    raise ValueError("source-review evidence context is missing")
                encoded = canonical_json_bytes(proposal.model_dump(mode="json"))
                if encoded in seen_proposals:
                    raise ValueError("source-review accepted proposal is duplicated")
                seen_proposals.add(encoded)
                for passage in proposal.passages:
                    if passage.source_id not in source_texts:
                        raise ValueError("source-review accepted evidence is cross-case")
                    resolved, changed = _resolve_quote(
                        passage.source_id, passage.quote, source_texts
                    )
                    if changed or resolved != passage.quote:
                        raise ValueError("source-review accepted evidence is not exact")
                entries.append((f"P{ordinal:04d}", proposal.statement))
                continue
            checked = _strict_rehydrate_v22(
                IndexedProposalV22,
                item,
                location="source-audit indexed proposal",
            )
        except Exception as error:
            raise _ControllerInvariantV22(f"{location} proposal inventory is invalid") from error
        entries.append((checked.proposal_ref, checked.proposal.statement))
    refs = [ref for ref, _ in entries]
    if len(refs) != len(set(refs)):
        raise _ControllerInvariantV22(f"{location} proposal inventory is invalid")
    return tuple(entries)


def _resolved_proposal(
    proposal: _ProposalDraftV22,
    source_texts: dict[str, str],
    dependency_inventory: tuple[tuple[str, str], ...],
) -> tuple[dict[str, object], bool, bool]:
    raw = proposal.model_dump(mode="json")
    passages, normalized, duplicate_removed = _resolve_passages(proposal.passages, source_texts)
    raw["passages"] = passages
    if proposal.dependency is not None:
        ordinal = proposal.dependency.target_ordinal
        if ordinal > len(dependency_inventory):
            raise _DraftNeedsClarificationV22(DraftReasonCodeV22.REFERENCE_UNKNOWN)
        raw["dependency"] = {
            "relationship": proposal.dependency.relationship,
            "target_statement": dependency_inventory[ordinal - 1][1],
        }
    return raw, normalized, duplicate_removed


def _compile_source_review(
    request: EvaluatorRequestV22, draft: _SourceReviewDraftV22
) -> tuple[dict[str, object], tuple[str, ...]]:
    source_texts = _source_texts(request)
    dependencies = _controller_proposal_inventory(
        request.payload.get("accepted_proposals", []),
        location="source-review",
        source_texts=source_texts,
    )
    proposals: list[dict[str, object]] = []
    seen: dict[str, bytes] = {}
    normalized = False
    duplicate_removed = False
    for proposal in draft.proposals:
        compiled, changed, passage_duplicates = _resolved_proposal(
            proposal, source_texts, dependencies
        )
        identity = str(compiled["statement"])
        encoded = canonical_json_bytes(compiled)
        prior = seen.get(identity)
        if prior is not None and prior != encoded:
            raise _DraftNeedsClarificationV22(DraftReasonCodeV22.CONFLICTING_ITEMS)
        if prior is None:
            seen[identity] = encoded
            proposals.append(compiled)
        else:
            duplicate_removed = True
        normalized = normalized or changed
        duplicate_removed = duplicate_removed or passage_duplicates
    payload = SourceReviewFragmentV22(
        proposals=tuple(SemanticProposal.model_validate(item) for item in proposals),
        review_complete=draft.review_complete,
    ).model_dump(mode="json")
    codes = ["DRAFT_NORMALIZED_EVIDENCE_WHITESPACE"] if normalized else []
    if duplicate_removed:
        codes.append("DRAFT_NORMALIZED_DUPLICATES")
    return payload, tuple(codes)


def _compile_source_audit(
    request: EvaluatorRequestV22, draft: _SourceAuditDraftV22
) -> tuple[dict[str, object], tuple[str, ...]]:
    source_texts = _source_texts(request)
    inventory = request.payload.get("indexed_proposals")
    if not isinstance(inventory, list):
        raise _ControllerInvariantV22("source-audit proposal inventory is invalid")
    refs: list[str] = []
    for item in inventory:
        if not isinstance(item, dict) or type(item.get("proposal_ref")) is not str:
            raise _ControllerInvariantV22("source-audit proposal inventory is invalid")
        refs.append(item["proposal_ref"])
    if len(refs) != len(set(refs)):
        raise _ControllerInvariantV22("source-audit proposal inventory is invalid")
    dependency_inventory = _controller_proposal_inventory(inventory, location="source-audit")
    concerns: list[dict[str, object]] = []
    seen: dict[tuple[str | None, str, tuple[tuple[str, str], ...], str | None], bytes] = {}
    evidence_normalized = False
    duplicate_removed = False
    for concern in draft.concerns:
        target = None
        if concern.target_proposal_ordinal is not None:
            index = concern.target_proposal_ordinal - 1
            if index >= len(refs):
                raise _DraftNeedsClarificationV22(DraftReasonCodeV22.REFERENCE_UNKNOWN)
            target = refs[index]
        if concern.concern_type == "omission":
            if target is not None or concern.correction is None:
                raise _DraftNeedsClarificationV22(DraftReasonCodeV22.SUBSTANCE_MISSING)
        elif concern.concern_type == "ambiguity":
            if target is None or concern.correction is not None:
                raise _DraftNeedsClarificationV22(DraftReasonCodeV22.SUBSTANCE_MISSING)
        elif target is None or concern.correction is None:
            raise _DraftNeedsClarificationV22(DraftReasonCodeV22.SUBSTANCE_MISSING)
        passages, changed, passage_duplicates = _resolve_passages(concern.passages, source_texts)
        evidence_normalized = evidence_normalized or changed
        duplicate_removed = duplicate_removed or passage_duplicates
        correction: dict[str, object] | None = None
        if concern.correction is not None:
            correction, changed, correction_duplicates = _resolved_proposal(
                concern.correction, source_texts, dependency_inventory
            )
            evidence_normalized = evidence_normalized or changed
            duplicate_removed = duplicate_removed or correction_duplicates
        compiled: dict[str, object] = {
            "target_proposal_ref": target,
            "concern_type": concern.concern_type,
            "passages": passages,
            "explanation": concern.explanation,
            "correction": correction,
        }
        passage_key = tuple((passage["source_id"], passage["quote"]) for passage in passages)
        correction_statement = None if correction is None else str(correction["statement"])
        identity = (target, concern.concern_type, passage_key, correction_statement)
        encoded = canonical_json_bytes(compiled)
        prior = seen.get(identity)
        if prior is not None and prior != encoded:
            raise _DraftNeedsClarificationV22(DraftReasonCodeV22.CONFLICTING_ITEMS)
        if prior is None:
            seen[identity] = encoded
            concerns.append(compiled)
        else:
            duplicate_removed = True
    payload = SourceAuditFragmentV22(
        concerns=tuple(AuditConcernV22.model_validate(item) for item in concerns),
        audit_complete=draft.audit_complete,
    ).model_dump(mode="json")
    codes = ["DRAFT_NORMALIZED_EVIDENCE_WHITESPACE"] if evidence_normalized else []
    if duplicate_removed:
        codes.append("DRAFT_NORMALIZED_DUPLICATES")
    return payload, tuple(codes)


def _compile_referee(
    request: EvaluatorRequestV22, draft: _RefereeDraftV22
) -> tuple[dict[str, object], tuple[str, ...]]:
    disputes = request.payload.get("material_disputes")
    if not isinstance(disputes, list) or len(disputes) != 1 or not isinstance(disputes[0], dict):
        raise _ControllerInvariantV22("source-referee dispute inventory is invalid")
    evidence = disputes[0].get("evidence")
    if not isinstance(evidence, list):
        raise _ControllerInvariantV22("source-referee dispute inventory is invalid")
    refs: list[str] = []
    for item in evidence:
        if not isinstance(item, dict) or type(item.get("evidence_ref")) is not str:
            raise _ControllerInvariantV22("source-referee dispute inventory is invalid")
        refs.append(item["evidence_ref"])
    selected: list[str] = []
    normalized = False
    for ordinal in draft.evidence_ordinals:
        if ordinal > len(refs):
            raise _DraftNeedsClarificationV22(DraftReasonCodeV22.REFERENCE_UNKNOWN)
        selected_ref = refs[ordinal - 1]
        if selected_ref in selected:
            normalized = True
            continue
        selected.append(selected_ref)
    strict = RefereeDecisionV22.validate_for_evidence(
        {
            "decision": draft.decision,
            "unresolved_reason": draft.unresolved_reason,
            "evidence_refs": selected,
            "rationale": draft.rationale,
        },
        tuple(RefereeEvidenceV22.model_validate(item) for item in evidence),
    )
    return strict.model_dump(mode="json"), (("DRAFT_NORMALIZED_DUPLICATES",) if normalized else ())


def _resolve_report_passages(
    values: tuple[str, ...], request: EvaluatorRequestV22
) -> tuple[tuple[str, ...], bool]:
    report = request.payload.get("report_text")
    if type(report) is not str or not report.strip():
        raise _ControllerInvariantV22("grade request report text is invalid")
    resolved: list[str] = []
    duplicate_removed = False
    for value in values:
        occurrences = [match.start() for match in re.finditer(re.escape(value), report)]
        if not occurrences:
            raise _DraftNeedsClarificationV22(DraftReasonCodeV22.EVIDENCE_NOT_FOUND)
        if len(occurrences) > 1:
            raise _DraftNeedsClarificationV22(DraftReasonCodeV22.EVIDENCE_AMBIGUOUS)
        if value in resolved:
            duplicate_removed = True
        else:
            resolved.append(value)
    return tuple(resolved), duplicate_removed


def _compile_ordinary_grade(
    request: EvaluatorRequestV22, draft: _OrdinaryGradeDraftV22
) -> tuple[dict[str, object], tuple[str, ...]]:
    requirements = request.payload.get("requirements")
    if not isinstance(requirements, list):
        raise _ControllerInvariantV22("ordinary-grade requirement inventory is invalid")
    identifiers = [
        item.get("requirement_id") if isinstance(item, dict) else None
        for item in requirements
    ]
    if any(type(item) is not str for item in identifiers):
        raise _ControllerInvariantV22("ordinary-grade requirement inventory is invalid")
    if not identifiers or len(identifiers) > 5 or len(identifiers) != len(set(identifiers)):
        raise _ControllerInvariantV22("ordinary-grade requirement inventory is invalid")
    grades_by_ordinal: dict[int, dict[str, object]] = {}
    normalized = False
    duplicate_report_passage = False
    for grade in draft.requirement_grades:
        index = grade.requirement_ordinal - 1
        if index >= len(identifiers):
            raise _DraftNeedsClarificationV22(DraftReasonCodeV22.REFERENCE_UNKNOWN)
        compiled = {**grade.model_dump(mode="json"), "requirement_id": identifiers[index]}
        compiled.pop("requirement_ordinal")
        passages, duplicate_removed = _resolve_report_passages(grade.report_passages, request)
        compiled["report_passages"] = list(passages)
        duplicate_report_passage = duplicate_report_passage or duplicate_removed
        prior = grades_by_ordinal.get(grade.requirement_ordinal)
        if prior is not None:
            if canonical_json_bytes(prior) != canonical_json_bytes(compiled):
                raise _DraftNeedsClarificationV22(DraftReasonCodeV22.CONFLICTING_ITEMS)
            normalized = True
            continue
        grades_by_ordinal[grade.requirement_ordinal] = compiled
    if tuple(sorted(grades_by_ordinal)) != tuple(range(1, len(identifiers) + 1)):
        raise _DraftNeedsClarificationV22(DraftReasonCodeV22.REFERENCE_UNKNOWN)
    grades = [grades_by_ordinal[index] for index in range(1, len(identifiers) + 1)]
    required = {
        "anonymous_label",
        "grader_lane",
        "batch_ref",
        "baseline_fingerprint",
        "report_fingerprint",
    }
    if not required.issubset(request.payload):
        raise _ControllerInvariantV22("ordinary-grade request payload is invalid")
    strict = OrdinaryGradeFragmentV22.model_validate(
        {
            **{key: request.payload[key] for key in required},
            "requirement_grades": grades,
            "rationale": draft.rationale,
        }
    )
    return strict.model_dump(mode="json"), (
        ("DRAFT_NORMALIZED_DUPLICATES",)
        if normalized or duplicate_report_passage
        else ()
    )


def _compile_contested_grade(
    request: EvaluatorRequestV22, draft: _ContestedGradeDraftV22
) -> tuple[dict[str, object], tuple[str, ...]]:
    contested = request.payload.get("contested_requirement")
    if (
        not isinstance(contested, dict)
        or type(contested.get("contested_requirement_id")) is not str
    ):
        raise _ControllerInvariantV22("contested-grade request payload is invalid")
    required = {"anonymous_label", "grader_lane", "baseline_fingerprint", "report_fingerprint"}
    if not required.issubset(request.payload):
        raise _ControllerInvariantV22("contested-grade request payload is invalid")
    reviewer = draft.reviewer_alternative_grade.model_dump(mode="json")
    reviewer_passages, reviewer_duplicates = _resolve_report_passages(
        draft.reviewer_alternative_grade.report_passages, request
    )
    reviewer["report_passages"] = list(reviewer_passages)
    auditor = draft.auditor_alternative_grade.model_dump(mode="json")
    auditor_passages, auditor_duplicates = _resolve_report_passages(
        draft.auditor_alternative_grade.report_passages, request
    )
    auditor["report_passages"] = list(auditor_passages)
    strict = ContestedGradeFragmentV22.model_validate(
        {
            **{key: request.payload[key] for key in required},
            "contested_requirement_id": contested["contested_requirement_id"],
            "reviewer_alternative_grade": reviewer,
            "auditor_alternative_grade": auditor,
            "ambiguity_disposition": draft.ambiguity_disposition,
            "rationale": draft.rationale,
        }
    )
    return strict.model_dump(mode="json"), (
        ("DRAFT_NORMALIZED_DUPLICATES",)
        if reviewer_duplicates or auditor_duplicates
        else ()
    )


def _compile_operation_payload_v22(
    request: EvaluatorRequestV22, parsed: _ParsedDraftV22
) -> tuple[dict[str, object], tuple[str, ...]]:
    if request.operation is EvaluatorOperationV22.SOURCE_REVIEW_FRAGMENT:
        if not isinstance(parsed, _SourceReviewDraftV22):
            raise _ControllerInvariantV22("source-review dispatch is invalid")
        return _compile_source_review(request, parsed)
    if request.operation is EvaluatorOperationV22.SOURCE_AUDIT_FRAGMENT:
        if not isinstance(parsed, _SourceAuditDraftV22):
            raise _ControllerInvariantV22("source-audit dispatch is invalid")
        return _compile_source_audit(request, parsed)
    if request.operation is EvaluatorOperationV22.SOURCE_REFEREE_FRAGMENT:
        if not isinstance(parsed, _RefereeDraftV22):
            raise _ControllerInvariantV22("source-referee dispatch is invalid")
        return _compile_referee(request, parsed)
    if request.operation is EvaluatorOperationV22.ORDINARY_GRADE_FRAGMENT:
        if not isinstance(parsed, _OrdinaryGradeDraftV22):
            raise _ControllerInvariantV22("ordinary-grade dispatch is invalid")
        return _compile_ordinary_grade(request, parsed)
    if request.operation is EvaluatorOperationV22.CONTESTED_GRADE_FRAGMENT:
        if not isinstance(parsed, _ContestedGradeDraftV22):
            raise _ControllerInvariantV22("contested-grade dispatch is invalid")
        return _compile_contested_grade(request, parsed)
    raise _ControllerInvariantV22("unknown evaluator operation")


def compile_evaluator_draft_v22(
    request: EvaluatorRequestV22,
    draft: object,
    provenance: EvaluatorProvenanceV22,
) -> DraftCompileOutcomeV22:
    """Compile one untrusted semantic draft into a strict controller response."""
    try:
        checked_request = _strict_request_v22(request)
    except _ControllerInvariantV22:
        return EngineDefectV22("COMPILER_INVARIANT")
    try:
        parsed = _parse_operation_draft_v22(checked_request.operation, draft)
    except Exception as error:
        return NeedsClarificationV22(_reason_codes(error))
    try:
        payload, normalization_codes = _compile_operation_payload_v22(checked_request, parsed)
    except _DraftNeedsClarificationV22 as error:
        return NeedsClarificationV22(tuple(sorted(set(error.reason_codes))))
    except Exception:
        return EngineDefectV22("COMPILER_INVARIANT")
    try:
        response = EvaluatorResponseV22(
            operation=checked_request.operation,
            request_fingerprint=checked_request.request_fingerprint,
            provider_name=provenance.provider_name,
            model_name=provenance.model_name,
            judge_isolation=provenance.judge_isolation,
            payload=payload,
        )
    except (TypeError, ValidationError, ValueError, RecursionError):
        return EngineDefectV22("COMPILER_INVARIANT")
    return CompiledDraftV22(response, tuple(sorted(set(normalization_codes))))
