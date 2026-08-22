"""Deterministic source-referee compilation for evaluator protocol 2.1."""

from __future__ import annotations

import hashlib
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass

from pydantic import BaseModel

from regulatory_harvest.storage import canonical_json_bytes

from .attorney_models import CaseEnvelope
from .attorney_v2_compiler import (
    CompilationError,
    index_review,
    material_disputes,
    resolve_exact_passage,
)
from .attorney_v2_models import (
    CanonicalRelationshipV2,
    CanonicalRequirementV2,
    IndexedProposalV2,
    MaterialDisputeV2,
    ResolvedPassageV2,
    SemanticPassage,
    SemanticProposal,
    SourceAuditV2,
    SourceReviewV2,
)
from .attorney_v21_models import (
    AcceptedRefereeFragmentV21,
    CanonicalBaselineV21,
    ContestedRequirementV21,
    RefereeAggregateV21,
    RefereeDisputeV21,
    RefereeEvidenceV21,
    SourceAuditV21,
    SourceReviewV21,
)


@dataclass(frozen=True)
class _ResolvedProposal:
    proposal: SemanticProposal
    passages: tuple[ResolvedPassageV2, ...]
    canonical_bytes: bytes


def _model_json(value: BaseModel) -> dict[str, object]:
    return value.model_dump(mode="json", warnings="error")


def _validated_envelope(envelope: CaseEnvelope) -> CaseEnvelope:
    try:
        return CaseEnvelope.model_validate(_model_json(envelope))
    except Exception as error:
        raise CompilationError("INPUT_INVALID") from error


def _v2_semantic_snapshots(
    review: SourceReviewV21, audit: SourceAuditV21
) -> tuple[SourceReviewV2, SourceAuditV2]:
    """Validate V2-equivalent source semantics without asking evaluators to adapt them."""
    try:
        checked_review = SourceReviewV21.model_validate(_model_json(review))
        v2_review = SourceReviewV2.model_validate(
            {"schema_version": "2.0", "proposals": _model_json(checked_review)["proposals"]}
        )
        indexed = index_review(v2_review)
        checked_audit = SourceAuditV21.validate_for_indexed_proposals(
            _model_json(audit), indexed
        )
        v2_audit = SourceAuditV2.validate_for_indexed_proposals(
            {"schema_version": "2.0", "concerns": _model_json(checked_audit)["concerns"]},
            indexed,
        )
        return v2_review, v2_audit
    except CompilationError:
        raise
    except Exception as error:
        raise CompilationError("INPUT_INVALID") from error


def _source_texts(envelope: CaseEnvelope) -> dict[str, str]:
    return {source.source_id: source.normalized_text for source in envelope.case.sources}


def _resolve_passage(
    source_texts: dict[str, str], passage: SemanticPassage
) -> ResolvedPassageV2:
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
            key=lambda item: (item.source_id, item.start_char, item.end_char, item.quote),
        )
    )


def _validate_all_source_passages(
    source_texts: dict[str, str], review: SourceReviewV2, audit: SourceAuditV2
) -> None:
    for proposal in review.proposals:
        _resolve_passages(source_texts, proposal.passages)
    for concern in audit.concerns:
        _resolve_passages(source_texts, concern.passages)
        if concern.correction is not None:
            _resolve_passages(source_texts, concern.correction.passages)


def _dispute_passages(
    source_texts: dict[str, str], dispute: MaterialDisputeV2
) -> tuple[ResolvedPassageV2, ...]:
    passages: list[ResolvedPassageV2] = []
    if dispute.reviewer_proposal is not None:
        passages.extend(_resolve_passages(source_texts, dispute.reviewer_proposal.passages))
    passages.extend(_resolve_passages(source_texts, dispute.audit_concern.passages))
    if dispute.audit_concern.correction is not None:
        passages.extend(_resolve_passages(source_texts, dispute.audit_concern.correction.passages))
    unique = {
        (item.source_id, item.start_char, item.end_char, item.quote): item for item in passages
    }
    return tuple(
        sorted(
            unique.values(),
            key=lambda item: (item.source_id, item.start_char, item.end_char, item.quote),
        )
    )


def _dispute_fingerprint(
    case_fingerprint: str,
    dispute: MaterialDisputeV2,
    evidence: tuple[RefereeEvidenceV21, ...],
) -> str:
    return hashlib.sha256(
        canonical_json_bytes(
            {
                "schema_version": "2.1",
                "case_fingerprint": case_fingerprint,
                "dispute_id": dispute.dispute_id,
                "material_dispute": dispute.model_dump(mode="json"),
                "evidence": [item.model_dump(mode="json") for item in evidence],
            }
        )
    ).hexdigest()


def build_referee_disputes(
    envelope: CaseEnvelope,
    review: SourceReviewV21,
    audit: SourceAuditV21,
) -> tuple[RefereeDisputeV21, ...]:
    """Create stable, evidence-complete, one-dispute referee inventories."""
    validated_envelope = _validated_envelope(envelope)
    v2_review, v2_audit = _v2_semantic_snapshots(review, audit)
    disputes = material_disputes(v2_review, v2_audit)
    source_texts = _source_texts(validated_envelope)
    _validate_all_source_passages(source_texts, v2_review, v2_audit)
    resolved = [(dispute, _dispute_passages(source_texts, dispute)) for dispute in disputes]
    ordered_evidence = sorted(
        (
            (
                passage.source_id,
                passage.start_char,
                passage.end_char,
                passage.quote,
                dispute.dispute_id,
                passage,
            )
            for dispute, passages in resolved
            for passage in passages
        ),
        key=lambda item: item[:-1],
    )
    references = {
        (dispute_id, source_id, start, end, quote): f"EVID-{index:04d}"
        for index, (source_id, start, end, quote, dispute_id, _) in enumerate(
            ordered_evidence, start=1
        )
    }
    result: list[RefereeDisputeV21] = []
    for dispute, passages in resolved:
        evidence = tuple(
                RefereeEvidenceV21(
                    evidence_ref=references[
                        (
                            dispute.dispute_id,
                            passage.source_id,
                            passage.start_char,
                            passage.end_char,
                            passage.quote,
                        )
                    ],
                    passage=passage,
                )
                for passage in passages
            )
        result.append(
            RefereeDisputeV21(
                case_fingerprint=validated_envelope.case_fingerprint,
                dispute_fingerprint=_dispute_fingerprint(
                    validated_envelope.case_fingerprint, dispute, evidence
                ),
                dispute_id=dispute.dispute_id,
                material_dispute=dispute,
                evidence=evidence,
            )
        )
    return tuple(result)


def validate_referee_fragment(
    dispute: RefereeDisputeV21,
    decision: object,
    *,
    response_fingerprint: str,
) -> AcceptedRefereeFragmentV21:
    """Bind one accepted inner referee decision to its controller-issued dispute."""
    try:
        checked_dispute = RefereeDisputeV21.model_validate(_model_json(dispute))
        return AcceptedRefereeFragmentV21.validate_for_dispute(
            {
                "dispute_id": checked_dispute.dispute_id,
                "case_fingerprint": checked_dispute.case_fingerprint,
                "dispute_fingerprint": checked_dispute.dispute_fingerprint,
                "decision": decision,
                "response_fingerprint": response_fingerprint,
            },
            checked_dispute,
        )
    except Exception as error:
        raise CompilationError("REFEREE_FRAGMENT_INVALID") from error


def _aggregate_fingerprint(
    disputes: tuple[RefereeDisputeV21, ...], fragments: tuple[AcceptedRefereeFragmentV21, ...]
) -> str:
    return hashlib.sha256(
        canonical_json_bytes(
            {
                "schema_version": "2.1",
                "disputes": [item.model_dump(mode="json") for item in disputes],
                "fragments": [item.model_dump(mode="json") for item in fragments],
            }
        )
    ).hexdigest()


def aggregate_referee_decisions(
    disputes: tuple[RefereeDisputeV21, ...],
    fragments: tuple[AcceptedRefereeFragmentV21, ...],
) -> RefereeAggregateV21:
    """Seal exact, ordered, controller-bound referee fragments."""
    try:
        checked_disputes = tuple(
            RefereeDisputeV21.model_validate(_model_json(item)) for item in disputes
        )
        if tuple(item.dispute_id for item in checked_disputes) != tuple(
            item.dispute_id for item in fragments
        ):
            raise CompilationError("REFEREE_FRAGMENT_COVERAGE_INVALID")
        checked_fragments = tuple(
            AcceptedRefereeFragmentV21.validate_for_dispute(_model_json(fragment), dispute)
            for dispute, fragment in zip(checked_disputes, fragments, strict=True)
        )
        return RefereeAggregateV21.validate_for_disputes(
            {
                "fragments": [item.model_dump(mode="json") for item in checked_fragments],
                "aggregate_fingerprint": _aggregate_fingerprint(
                    checked_disputes, checked_fragments
                ),
            },
            checked_disputes,
        )
    except CompilationError:
        raise
    except Exception as error:
        raise CompilationError("REFEREE_FRAGMENT_INVALID") from error


def _proposal_bytes(proposal: SemanticProposal, passages: tuple[ResolvedPassageV2, ...]) -> bytes:
    return canonical_json_bytes(
        {
            "statement": proposal.statement,
            "kind": proposal.kind,
            "importance": proposal.importance,
            "passages": [item.model_dump(mode="json") for item in passages],
            "dependency": (
                None
                if proposal.dependency is None
                else proposal.dependency.model_dump(mode="json")
            ),
            "confidence": proposal.confidence,
            "rationale": proposal.rationale,
        }
    )


def _resolve_proposal(
    source_texts: dict[str, str], proposal: SemanticProposal
) -> _ResolvedProposal:
    passages = _resolve_passages(source_texts, proposal.passages)
    return _ResolvedProposal(proposal, passages, _proposal_bytes(proposal, passages))


def _normalise_statement(value: str) -> str:
    return unicodedata.normalize("NFC", " ".join(value.split()))


def _requirement_sort_key(item: _ResolvedProposal) -> tuple[str, int, int, str, str, str]:
    first = item.passages[0]
    return (
        first.source_id,
        first.start_char,
        first.end_char,
        item.proposal.kind.value,
        _normalise_statement(item.proposal.statement),
        hashlib.sha256(item.canonical_bytes).hexdigest(),
    )


def _canonical_requirement(
    item: _ResolvedProposal, requirement_id: str, canonical_order: int
) -> CanonicalRequirementV2:
    return CanonicalRequirementV2(
        requirement_id=requirement_id,
        canonical_order=canonical_order,
        statement=item.proposal.statement,
        kind=item.proposal.kind,
        importance=item.proposal.importance,
        passages=list(item.passages),
        dependency=item.proposal.dependency,
        confidence=item.proposal.confidence,
        rationale=item.proposal.rationale,
    )


def _common_requirements(
    source_texts: dict[str, str], proposals: Iterable[SemanticProposal]
) -> tuple[CanonicalRequirementV2, ...]:
    resolved = [_resolve_proposal(source_texts, proposal) for proposal in proposals]
    if len({item.canonical_bytes for item in resolved}) != len(resolved):
        raise CompilationError("DUPLICATE_ACCEPTED_PROPOSAL")
    return tuple(
        _canonical_requirement(item, f"REQ-{index:04d}", index - 1)
        for index, item in enumerate(sorted(resolved, key=_requirement_sort_key), start=1)
    )


def _relationships(
    requirements: tuple[CanonicalRequirementV2, ...],
    contested_requirements: tuple[ContestedRequirementV21, ...],
) -> tuple[CanonicalRelationshipV2, ...]:
    by_statement: dict[str, list[CanonicalRequirementV2]] = {}
    for requirement in requirements:
        by_statement.setdefault(_normalise_statement(requirement.statement), []).append(requirement)
    contested_by_statement: dict[str, list[CanonicalRequirementV2]] = {}
    for contested in contested_requirements:
        for alternative in (contested.reviewer_alternative, contested.auditor_alternative):
            if alternative is not None:
                contested_by_statement.setdefault(
                    _normalise_statement(alternative.statement), []
                ).append(alternative)
    relationships: list[CanonicalRelationshipV2] = []
    for requirement in requirements:
        dependency = requirement.dependency
        if dependency is None:
            continue
        target_key = _normalise_statement(dependency.target_statement)
        common_targets = by_statement.get(target_key, [])
        contested_targets = contested_by_statement.get(target_key, [])
        if len(common_targets) + len(contested_targets) != 1:
            raise CompilationError("DEPENDENCY_TARGET_UNRESOLVED")
        if not common_targets:
            continue
        target = common_targets[0]
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


def _contested_requirement(
    source_texts: dict[str, str],
    dispute: MaterialDisputeV2,
    fragment: AcceptedRefereeFragmentV21,
    index: int,
) -> ContestedRequirementV21:
    unresolved_reason = fragment.decision.unresolved_reason
    if unresolved_reason is None:
        raise CompilationError("REFEREE_FRAGMENT_INVALID")
    reviewer = (
        None
        if dispute.reviewer_proposal is None
        else _canonical_requirement(
            _resolve_proposal(source_texts, dispute.reviewer_proposal), "REQ-0001", 0
        )
    )
    correction = dispute.audit_concern.correction
    auditor = (
        None
        if correction is None
        else _canonical_requirement(_resolve_proposal(source_texts, correction), "REQ-0002", 1)
    )
    return ContestedRequirementV21(
        contested_requirement_id=f"CONT-{index:04d}",
        reviewer_alternative=reviewer,
        auditor_alternative=auditor,
        unresolved_reason=unresolved_reason,
        rationale=fragment.decision.rationale,
        referee_fragment_fingerprint=fragment.response_fingerprint,
    )


def _apply_fragmented_decisions(
    source_texts: dict[str, str],
    indexed: tuple[IndexedProposalV2, ...],
    disputes: tuple[MaterialDisputeV2, ...],
    aggregate: RefereeAggregateV21,
) -> tuple[tuple[SemanticProposal, ...], tuple[ContestedRequirementV21, ...]]:
    decisions = {item.dispute_id: item for item in aggregate.fragments}
    replacements: dict[str, SemanticProposal] = {}
    accepted_omissions: list[SemanticProposal] = []
    contested: list[ContestedRequirementV21] = []
    contested_targets: set[str] = set()
    auditor_omissions: set[str] = set()
    for dispute in disputes:
        fragment = decisions[dispute.dispute_id]
        concern = dispute.audit_concern
        if fragment.decision.decision == "unresolved":
            if dispute.target_proposal_ref is not None:
                contested_targets.add(dispute.target_proposal_ref)
            contested.append(
                _contested_requirement(source_texts, dispute, fragment, len(contested) + 1)
            )
            continue
        if fragment.decision.decision != "accept_auditor":
            continue
        if concern.correction is None:
            if concern.target_proposal_ref is None:
                raise CompilationError("AUDITOR_ALTERNATIVE_MISSING")
            auditor_omissions.add(concern.target_proposal_ref)
            continue
        if concern.target_proposal_ref is None:
            accepted_omissions.append(concern.correction)
            continue
        if concern.target_proposal_ref in replacements:
            raise CompilationError("AUDIT_CONFLICT")
        replacements[concern.target_proposal_ref] = concern.correction
    common = [
        replacements.get(item.proposal_ref, item.proposal)
        for item in indexed
        if item.proposal_ref not in contested_targets | auditor_omissions
    ]
    common.extend(accepted_omissions)
    return tuple(common), tuple(contested)


def _seal_baseline(
    envelope: CaseEnvelope,
    requirements: tuple[CanonicalRequirementV2, ...],
    relationships: tuple[CanonicalRelationshipV2, ...],
    contested: tuple[ContestedRequirementV21, ...],
) -> CanonicalBaselineV21:
    fingerprint_payload: dict[str, object] = {
        "schema_version": "2.1",
        "case_fingerprint": envelope.case_fingerprint,
        "requirements": [item.model_dump(mode="json") for item in requirements],
        "relationships": [item.model_dump(mode="json") for item in relationships],
        "contested_requirements": [item.model_dump(mode="json") for item in contested],
    }
    return CanonicalBaselineV21(
        schema_version="2.1",
        case_fingerprint=envelope.case_fingerprint,
        requirements=requirements,
        relationships=relationships,
        contested_requirements=contested,
        baseline_fingerprint=hashlib.sha256(
            canonical_json_bytes(fingerprint_payload)
        ).hexdigest(),
    )


def compile_baseline_v21(
    envelope: CaseEnvelope,
    review: SourceReviewV21,
    audit: SourceAuditV21,
    aggregate: RefereeAggregateV21,
) -> CanonicalBaselineV21:
    """Compile accepted fragment decisions without choosing unresolved alternatives."""
    validated_envelope = _validated_envelope(envelope)
    v2_review, v2_audit = _v2_semantic_snapshots(review, audit)
    disputes = build_referee_disputes(validated_envelope, review, audit)
    try:
        checked_aggregate = RefereeAggregateV21.validate_for_disputes(
            aggregate, disputes
        )
    except Exception as error:
        raise CompilationError("REFEREE_FRAGMENT_INVALID") from error
    sealed = aggregate_referee_decisions(disputes, checked_aggregate.fragments)
    if checked_aggregate.aggregate_fingerprint != sealed.aggregate_fingerprint:
        raise CompilationError("REFEREE_AGGREGATE_INVALID")
    indexed = index_review(v2_review)
    material = material_disputes(v2_review, v2_audit)
    source_texts = _source_texts(validated_envelope)
    common, contested = _apply_fragmented_decisions(source_texts, indexed, material, sealed)
    requirements = _common_requirements(source_texts, common)
    return _seal_baseline(
        validated_envelope,
        requirements,
        _relationships(requirements, contested),
        contested,
    )
