"""Deterministically compile protocol-2.0 semantic evaluation proposals."""

from __future__ import annotations

import hashlib
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass

from pydantic import BaseModel

from regulatory_harvest.storage import canonical_json_bytes

from .attorney_models import CaseEnvelope
from .attorney_v2_models import (
    CanonicalBaselineV2,
    CanonicalRelationshipV2,
    CanonicalRequirementV2,
    IndexedProposalV2,
    MaterialDisputeV2,
    ResolvedPassageV2,
    SemanticPassage,
    SemanticProposal,
    SourceAuditV2,
    SourceRefereeResponseV2,
    SourceReviewV2,
)


class CompilationError(ValueError):
    """A bounded, public-safe semantic-baseline compilation diagnostic."""


@dataclass(frozen=True)
class _ResolvedProposal:
    proposal: SemanticProposal
    passages: tuple[ResolvedPassageV2, ...]
    canonical_bytes: bytes


def _model_json(value: BaseModel) -> dict[str, object]:
    """Serialize untrusted model instances without downgrading warnings to output."""
    return value.model_dump(mode="json", warnings="error")


def _all_occurrences(text: str, quote: str) -> Iterable[int]:
    start = text.find(quote)
    while start != -1:
        yield start
        start = text.find(quote, start + 1)


def resolve_exact_passage(source_text: str, passage: SemanticPassage) -> ResolvedPassageV2:
    """Resolve one unique verbatim passage without accepting role-authored offsets."""
    try:
        if type(source_text) is not str:
            raise ValueError("source text must be a string")
        validated_passage = SemanticPassage.model_validate(_model_json(passage))
    except Exception as error:
        raise CompilationError("INPUT_INVALID") from error
    starts = tuple(_all_occurrences(source_text, validated_passage.quote))
    if not starts:
        raise CompilationError("PASSAGE_NOT_FOUND")
    if len(starts) != 1:
        raise CompilationError("PASSAGE_AMBIGUOUS")
    start = starts[0]
    return ResolvedPassageV2(
        source_id=validated_passage.source_id,
        start_char=start,
        end_char=start + len(validated_passage.quote),
        quote=validated_passage.quote,
    )


def index_review(review: SourceReviewV2) -> tuple[IndexedProposalV2, ...]:
    """Assign request-local proposal references before any semantic decision."""
    try:
        validated_review = SourceReviewV2.model_validate(_model_json(review))
        return tuple(
            IndexedProposalV2(proposal_ref=f"P{index:04d}", proposal=proposal)
            for index, proposal in enumerate(validated_review.proposals, start=1)
        )
    except Exception as error:
        raise CompilationError("INPUT_INVALID") from error


def material_disputes(
    review: SourceReviewV2, audit: SourceAuditV2
) -> tuple[MaterialDisputeV2, ...]:
    """Turn every audit concern into one engine-issued material dispute."""
    try:
        validated_review = SourceReviewV2.model_validate(_model_json(review))
        indexed = index_review(validated_review)
        validated_audit = SourceAuditV2.validate_for_indexed_proposals(_model_json(audit), indexed)
    except Exception as error:
        raise CompilationError("INPUT_INVALID") from error
    proposal_by_ref = {item.proposal_ref: item.proposal for item in indexed}
    return tuple(
        MaterialDisputeV2(
            dispute_id=f"D{index:04d}",
            target_proposal_ref=concern.target_proposal_ref,
            reviewer_proposal=(
                None
                if concern.target_proposal_ref is None
                else proposal_by_ref[concern.target_proposal_ref]
            ),
            audit_concern=concern,
        )
        for index, concern in enumerate(validated_audit.concerns, start=1)
    )


def _normalise_statement(value: str) -> str:
    return unicodedata.normalize("NFC", " ".join(value.split()))


def _validate_envelope(envelope: CaseEnvelope) -> CaseEnvelope:
    try:
        return CaseEnvelope.model_validate(_model_json(envelope))
    except Exception as error:
        raise CompilationError("INPUT_INVALID") from error


def _validate_inputs(
    review: SourceReviewV2,
    audit: SourceAuditV2,
    referee: SourceRefereeResponseV2 | None,
) -> tuple[
    SourceReviewV2,
    SourceAuditV2,
    tuple[IndexedProposalV2, ...],
    tuple[MaterialDisputeV2, ...],
    SourceRefereeResponseV2 | None,
]:
    try:
        validated_review = SourceReviewV2.model_validate(_model_json(review))
        indexed = index_review(validated_review)
        validated_audit = SourceAuditV2.validate_for_indexed_proposals(_model_json(audit), indexed)
        disputes = material_disputes(validated_review, validated_audit)
        if disputes and referee is None:
            raise CompilationError("REFEREE_REQUIRED")
        if not disputes and referee is not None:
            raise CompilationError("REFEREE_UNEXPECTED")
        validated_referee = None
        if referee is not None:
            validated_referee = SourceRefereeResponseV2.validate_for_disputes(
                _model_json(referee), disputes
            )
    except CompilationError:
        raise
    except Exception as error:
        raise CompilationError("INPUT_INVALID") from error
    return validated_review, validated_audit, indexed, disputes, validated_referee


def _source_texts(envelope: CaseEnvelope) -> dict[str, str]:
    return {source.source_id: source.normalized_text for source in envelope.case.sources}


def _resolve_passage(source_texts: dict[str, str], passage: SemanticPassage) -> ResolvedPassageV2:
    try:
        return resolve_exact_passage(source_texts[passage.source_id], passage)
    except KeyError as error:
        raise CompilationError("SOURCE_UNKNOWN") from error


def _resolve_passages(
    source_texts: dict[str, str], passages: Iterable[SemanticPassage]
) -> tuple[ResolvedPassageV2, ...]:
    return tuple(
        sorted(
            (_resolve_passage(source_texts, passage) for passage in passages),
            key=lambda passage: (
                passage.source_id,
                passage.start_char,
                passage.end_char,
                passage.quote,
            ),
        )
    )


def _resolved_proposal_bytes(
    proposal: SemanticProposal, passages: tuple[ResolvedPassageV2, ...]
) -> bytes:
    return canonical_json_bytes(
        {
            "statement": proposal.statement,
            "kind": proposal.kind,
            "importance": proposal.importance,
            "passages": [passage.model_dump(mode="json") for passage in passages],
            "dependency": (
                None if proposal.dependency is None else proposal.dependency.model_dump(mode="json")
            ),
            "confidence": proposal.confidence,
            "rationale": proposal.rationale,
        }
    )


def _resolve_proposal(
    source_texts: dict[str, str], proposal: SemanticProposal
) -> _ResolvedProposal:
    passages = _resolve_passages(source_texts, proposal.passages)
    return _ResolvedProposal(
        proposal=proposal,
        passages=passages,
        canonical_bytes=_resolved_proposal_bytes(proposal, passages),
    )


def _validate_all_evidence(
    source_texts: dict[str, str],
    review: SourceReviewV2,
    audit: SourceAuditV2,
    referee: SourceRefereeResponseV2 | None,
) -> None:
    for proposal in review.proposals:
        _resolve_passages(source_texts, proposal.passages)
    for concern in audit.concerns:
        _resolve_passages(source_texts, concern.passages)
        if concern.correction is not None:
            _resolve_passages(source_texts, concern.correction.passages)
    if referee is not None:
        for decision in referee.decisions:
            _resolve_passages(source_texts, decision.passages)


def _apply_referee_choices(
    indexed: tuple[IndexedProposalV2, ...],
    disputes: tuple[MaterialDisputeV2, ...],
    referee: SourceRefereeResponseV2 | None,
) -> tuple[tuple[SemanticProposal, ...], tuple[str, ...]]:
    if not disputes:
        return tuple(item.proposal for item in indexed), ()
    if referee is None:
        raise CompilationError("REFEREE_REQUIRED")
    decisions = {decision.dispute_id: decision for decision in referee.decisions}
    replacements: dict[str, SemanticProposal] = {}
    accepted_omissions: list[SemanticProposal] = []
    unresolved: list[str] = []
    for dispute in disputes:
        concern = dispute.audit_concern
        decision = decisions[dispute.dispute_id]
        if decision.decision == "unresolved":
            unresolved.append(dispute.dispute_id)
            continue
        if (
            decision.decision == "accept_auditor"
            and concern.concern_type == "ambiguity"
            and concern.correction is None
        ):
            unresolved.append(dispute.dispute_id)
            continue
        if decision.decision != "accept_auditor" or concern.correction is None:
            continue
        if concern.target_proposal_ref is None:
            accepted_omissions.append(concern.correction)
            continue
        if concern.target_proposal_ref in replacements:
            raise CompilationError("AUDIT_CONFLICT")
        replacements[concern.target_proposal_ref] = concern.correction
    accepted = [replacements.get(item.proposal_ref, item.proposal) for item in indexed]
    accepted.extend(accepted_omissions)
    return tuple(accepted), tuple(unresolved)


def _canonical_requirement_sort_key(
    resolved: _ResolvedProposal,
) -> tuple[str, int, int, str, str, str]:
    first = resolved.passages[0]
    return (
        first.source_id,
        first.start_char,
        first.end_char,
        resolved.proposal.kind.value,
        _normalise_statement(resolved.proposal.statement),
        hashlib.sha256(resolved.canonical_bytes).hexdigest(),
    )


def _ensure_unique_resolved_proposals(resolved: list[_ResolvedProposal]) -> None:
    seen: set[bytes] = set()
    for item in resolved:
        if item.canonical_bytes in seen:
            raise CompilationError("DUPLICATE_ACCEPTED_PROPOSAL")
        seen.add(item.canonical_bytes)


def _assign_requirement_ids(
    ordered: list[_ResolvedProposal],
) -> tuple[CanonicalRequirementV2, ...]:
    return tuple(
        CanonicalRequirementV2(
            requirement_id=f"REQ-{index:04d}",
            canonical_order=index - 1,
            statement=item.proposal.statement,
            kind=item.proposal.kind,
            importance=item.proposal.importance,
            passages=list(item.passages),
            dependency=item.proposal.dependency,
            confidence=item.proposal.confidence,
            rationale=item.proposal.rationale,
        )
        for index, item in enumerate(ordered, start=1)
    )


def _compile_relationships(
    requirements: tuple[CanonicalRequirementV2, ...],
) -> tuple[CanonicalRelationshipV2, ...]:
    by_statement: dict[str, list[CanonicalRequirementV2]] = {}
    for requirement in requirements:
        by_statement.setdefault(_normalise_statement(requirement.statement), []).append(requirement)
    relationships: list[CanonicalRelationshipV2] = []
    for requirement in requirements:
        dependency = requirement.dependency
        if dependency is None:
            continue
        targets = by_statement.get(_normalise_statement(dependency.target_statement), [])
        if len(targets) != 1:
            raise CompilationError("DEPENDENCY_TARGET_UNRESOLVED")
        target = targets[0]
        if target.requirement_id == requirement.requirement_id:
            raise CompilationError("DEPENDENCY_SELF_REFERENCE")
        relationships.append(
            CanonicalRelationshipV2(
                relationship_id=f"REL-{len(relationships) + 1:04d}",
                relationship=dependency.relationship,
                source_requirement_id=requirement.requirement_id,
                target_requirement_id=target.requirement_id,
            )
        )
    return tuple(relationships)


def _seal_baseline(
    case_fingerprint: str,
    requirements: tuple[CanonicalRequirementV2, ...],
    relationships: tuple[CanonicalRelationshipV2, ...],
    unresolved_dispute_ids: tuple[str, ...],
) -> CanonicalBaselineV2:
    payload = {
        "schema_version": "2.0",
        "case_fingerprint": case_fingerprint,
        "requirements": [requirement.model_dump(mode="json") for requirement in requirements],
        "relationships": [relationship.model_dump(mode="json") for relationship in relationships],
        "unresolved_dispute_ids": list(unresolved_dispute_ids),
    }
    fingerprint = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    return CanonicalBaselineV2(
        case_fingerprint=case_fingerprint,
        requirements=list(requirements),
        relationships=relationships,
        unresolved_dispute_ids=list(unresolved_dispute_ids),
        baseline_fingerprint=fingerprint,
    )


def compile_baseline(
    envelope: CaseEnvelope,
    review: SourceReviewV2,
    audit: SourceAuditV2,
    referee: SourceRefereeResponseV2 | None,
) -> CanonicalBaselineV2:
    """Compile source-only semantic responses into a sealed canonical baseline."""
    validated_envelope = _validate_envelope(envelope)
    validated_review, validated_audit, indexed, disputes, validated_referee = _validate_inputs(
        review, audit, referee
    )
    source_texts = _source_texts(validated_envelope)
    _validate_all_evidence(source_texts, validated_review, validated_audit, validated_referee)
    accepted, unresolved = _apply_referee_choices(indexed, disputes, validated_referee)
    resolved = [_resolve_proposal(source_texts, proposal) for proposal in accepted]
    _ensure_unique_resolved_proposals(resolved)
    ordered = sorted(resolved, key=_canonical_requirement_sort_key)
    requirements = _assign_requirement_ids(ordered)
    relationships = _compile_relationships(requirements)
    return _seal_baseline(
        validated_envelope.case_fingerprint,
        requirements,
        relationships,
        unresolved,
    )
