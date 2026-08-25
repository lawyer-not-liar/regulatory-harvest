"""Strict deterministic compilation for report-blind evaluation baselines."""

from __future__ import annotations

import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass, replace
from typing import Literal, cast

from regulatory_harvest.storage import canonical_json_bytes, sha256_digest

from .attorney_baseline_input import legal_input_fingerprint_v1
from .attorney_baseline_models import (
    AcceptedBaselineAuditFragmentV1,
    AcceptedBaselineRefereeFragmentV1,
    AcceptedBaselineReviewFragmentV1,
    BaselineAuditAggregateV1,
    BaselineAuditConcernV1,
    BaselineCorrectionActionV1,
    BaselineCorrectionRecordV1,
    BaselineDisputeV1,
    BaselineImportanceV1,
    BaselineInputV1,
    BaselineProposalV1,
    BaselineProvenanceV1,
    BaselineRefereeAggregateV1,
    BaselineRefereeDecisionV1,
    BaselineRelationshipV1,
    BaselineRequirementV1,
    BaselineReviewAggregateV1,
    CanonicalBaselineV1,
    ContestedBaselineRequirementV1,
    ImportanceAuditFindingV1,
    ImportanceBasisV1,
    IndexedBaselineAuditConcernV1,
    IndexedBaselineProposalV1,
    strict_baseline_model_v1,
)
from .attorney_baseline_requests import (
    BASELINE_COMPILER_CONTRACT_FINGERPRINT_V1,
    _validate_baseline_input,
    build_baseline_source_audit_request_v1,
    build_baseline_source_review_request_v1,
)
from .attorney_v2_models import ResolvedPassageV2, SemanticPassage

_MAX_FRAGMENTS = 128
_MAX_ITEMS = 640


class BaselineCompilationError(ValueError):
    """A bounded compiler refusal which never includes source or report text."""


@dataclass(frozen=True)
class _ResolvedProposal:
    proposal: BaselineProposalV1
    passages: tuple[ResolvedPassageV2, ...]
    canonical_bytes: bytes


@dataclass(frozen=True)
class _Contest:
    target_proposal_ref: str | None
    reviewer: BaselineProposalV1 | None
    auditor: BaselineProposalV1 | None
    decision: BaselineRefereeDecisionV1
    response_fingerprint: str
    reason: Literal[
        "SOURCE_AMBIGUITY",
        "SOURCE_CONFLICT",
        "SOURCE_GAP",
        "BOTH_POSITIONS_UNSUPPORTED",
    ]


def _hash(value: object) -> str:
    return sha256_digest(canonical_json_bytes(value))


def _normalise_statement(value: str) -> str:
    return unicodedata.normalize("NFC", " ".join(value.split()))


def _checked_input(value: BaselineInputV1) -> BaselineInputV1:
    try:
        rehydrated = cast(
            BaselineInputV1,
            strict_baseline_model_v1(BaselineInputV1, value),
        )
        checked = _validate_baseline_input(rehydrated)
        if checked.legal_input_fingerprint != legal_input_fingerprint_v1(checked):
            raise ValueError
        return checked
    except Exception:
        raise BaselineCompilationError("BASELINE_INPUT_INVALID") from None


def _strict_tuple(value: object, *, code: str) -> tuple[object, ...]:
    if type(value) is not tuple:
        raise BaselineCompilationError(code)
    return tuple(tuple.__iter__(value))


def _source_texts(baseline_input: BaselineInputV1) -> dict[str, str]:
    return {source.source_id: source.normalized_text for source in baseline_input.sources}


def _resolve_passage(
    source_texts: dict[str, str], passage: SemanticPassage
) -> ResolvedPassageV2:
    try:
        checked = SemanticPassage.model_validate(passage)
        text = source_texts[checked.source_id]
        start = text.find(checked.quote)
        if start < 0:
            raise ValueError
        return ResolvedPassageV2(
            source_id=checked.source_id,
            quote=checked.quote,
            start_char=start,
            end_char=start + len(checked.quote),
        )
    except Exception:
        raise BaselineCompilationError("BASELINE_SOURCE_EVIDENCE") from None


def _resolve_passages(
    source_texts: dict[str, str], passages: Iterable[SemanticPassage]
) -> tuple[ResolvedPassageV2, ...]:
    resolved = tuple(
        sorted(
            (_resolve_passage(source_texts, passage) for passage in passages),
            key=lambda item: (item.source_id, item.start_char, item.end_char, item.quote),
        )
    )
    identities = tuple(
        (item.source_id, item.start_char, item.end_char, item.quote) for item in resolved
    )
    if len(identities) != len(set(identities)):
        raise BaselineCompilationError("BASELINE_SOURCE_EVIDENCE")
    return resolved


def _resolved_proposal(
    source_texts: dict[str, str], proposal: BaselineProposalV1
) -> _ResolvedProposal:
    passages = _resolve_passages(source_texts, proposal.passages)
    payload = proposal.model_dump(mode="json")
    payload["passages"] = [item.model_dump(mode="json") for item in passages]
    return _ResolvedProposal(proposal, passages, canonical_json_bytes(payload))


def _proposal_key(value: _ResolvedProposal) -> tuple[object, ...]:
    first = value.passages[0]
    return (
        first.source_id,
        first.start_char,
        first.end_char,
        value.proposal.kind.value,
        _normalise_statement(value.proposal.statement),
        sha256_digest(value.canonical_bytes),
    )


def _validate_proposal_semantics(values: list[_ResolvedProposal], *, code: str) -> None:
    identities: dict[str, bytes] = {}
    for value in values:
        identity = _normalise_statement(value.proposal.statement)
        if identity in identities:
            raise BaselineCompilationError(code)
        identities[identity] = value.canonical_bytes


def _review_fragments(
    baseline_input: BaselineInputV1,
    fragments: tuple[AcceptedBaselineReviewFragmentV1, ...],
) -> tuple[AcceptedBaselineReviewFragmentV1, ...]:
    try:
        raw_items = _strict_tuple(fragments, code="BASELINE_REVIEW_FRAGMENT")
        checked = tuple(
            cast(
                AcceptedBaselineReviewFragmentV1,
                strict_baseline_model_v1(AcceptedBaselineReviewFragmentV1, item),
            )
            for item in raw_items
        )
    except BaselineCompilationError:
        raise
    except Exception:
        raise BaselineCompilationError("BASELINE_REVIEW_FRAGMENT") from None
    if (
        not checked
        or len(checked) > _MAX_FRAGMENTS
        or [item.fragment_ordinal for item in checked] != list(range(1, len(checked) + 1))
        or not checked[-1].payload.review_complete
        or any(item.payload.review_complete for item in checked[:-1])
        or len({item.response_fingerprint for item in checked}) != len(checked)
        or sum(len(item.payload.proposals) for item in checked) > _MAX_ITEMS
    ):
        raise BaselineCompilationError("BASELINE_REVIEW_FRAGMENT")
    prior: tuple[AcceptedBaselineReviewFragmentV1, ...] = ()
    for item in checked:
        try:
            request = build_baseline_source_review_request_v1(
                baseline_input, prior, fragment_ordinal=item.fragment_ordinal
            )
        except Exception:
            raise BaselineCompilationError("BASELINE_REVIEW_FRAGMENT") from None
        if request.request_fingerprint != item.request_fingerprint:
            raise BaselineCompilationError("BASELINE_REVIEW_FRAGMENT")
        prior += (item,)
    return checked


def aggregate_baseline_review_v1(
    baseline_input: BaselineInputV1,
    fragments: tuple[AcceptedBaselineReviewFragmentV1, ...],
) -> BaselineReviewAggregateV1:
    """Strictly aggregate accepted source-review bytes into controller IDs."""
    checked_input = _checked_input(baseline_input)
    checked_fragments = _review_fragments(checked_input, fragments)
    source_texts = _source_texts(checked_input)
    resolved = [
        _resolved_proposal(source_texts, proposal)
        for fragment in checked_fragments
        for proposal in fragment.payload.proposals
    ]
    _validate_proposal_semantics(resolved, code="BASELINE_REVIEW_SEMANTICS")
    ordered = sorted(resolved, key=_proposal_key)
    indexed = tuple(
        IndexedBaselineProposalV1(proposal_ref=f"PR-{index:04d}", proposal=item.proposal)
        for index, item in enumerate(ordered, 1)
    )
    fragment_fingerprints = tuple(item.response_fingerprint for item in checked_fragments)
    fingerprint = _hash(
        {
            "legal_input_fingerprint": checked_input.legal_input_fingerprint,
            "fragments": [item.model_dump(mode="json") for item in checked_fragments],
            "proposals": [item.model_dump(mode="json") for item in indexed],
            "fragment_fingerprints": fragment_fingerprints,
        }
    )
    return BaselineReviewAggregateV1(
        fragments=checked_fragments,
        proposals=indexed,
        fragment_fingerprints=fragment_fingerprints,
        aggregate_fingerprint=fingerprint,
    )


def _verified_review(
    baseline_input: BaselineInputV1, value: BaselineReviewAggregateV1
) -> BaselineReviewAggregateV1:
    try:
        checked = cast(
            BaselineReviewAggregateV1,
            strict_baseline_model_v1(BaselineReviewAggregateV1, value),
        )
        expected = aggregate_baseline_review_v1(baseline_input, checked.fragments)
        if checked != expected:
            raise ValueError
        return expected
    except Exception:
        raise BaselineCompilationError("BASELINE_REVIEW_AGGREGATE") from None


def _audit_fragments(
    baseline_input: BaselineInputV1,
    review: BaselineReviewAggregateV1,
    fragments: tuple[AcceptedBaselineAuditFragmentV1, ...],
) -> tuple[AcceptedBaselineAuditFragmentV1, ...]:
    try:
        raw_items = _strict_tuple(fragments, code="BASELINE_AUDIT_FRAGMENT")
        checked = tuple(
            cast(
                AcceptedBaselineAuditFragmentV1,
                strict_baseline_model_v1(AcceptedBaselineAuditFragmentV1, item),
            )
            for item in raw_items
        )
    except BaselineCompilationError:
        raise
    except Exception:
        raise BaselineCompilationError("BASELINE_AUDIT_FRAGMENT") from None
    if (
        not checked
        or len(checked) > _MAX_FRAGMENTS
        or [item.fragment_ordinal for item in checked] != list(range(1, len(checked) + 1))
        or not checked[-1].payload.audit_complete
        or any(item.payload.audit_complete for item in checked[:-1])
        or len({item.response_fingerprint for item in checked}) != len(checked)
        or sum(
            len(item.payload.concerns) + len(item.payload.importance_findings)
            for item in checked
        )
        > _MAX_ITEMS
    ):
        raise BaselineCompilationError("BASELINE_AUDIT_FRAGMENT")
    prior: tuple[AcceptedBaselineAuditFragmentV1, ...] = ()
    for item in checked:
        try:
            request = build_baseline_source_audit_request_v1(
                baseline_input,
                review,
                prior,
                fragment_ordinal=item.fragment_ordinal,
            )
        except Exception:
            raise BaselineCompilationError("BASELINE_AUDIT_FRAGMENT") from None
        if request.request_fingerprint != item.request_fingerprint:
            raise BaselineCompilationError("BASELINE_AUDIT_FRAGMENT")
        prior += (item,)
    return checked


def _concern_key(
    source_texts: dict[str, str], concern: BaselineAuditConcernV1
) -> tuple[object, ...]:
    passages = _resolve_passages(source_texts, concern.passages)
    correction = (
        None
        if concern.correction is None
        else _resolved_proposal(source_texts, concern.correction).canonical_bytes
    )
    return (
        concern.target_proposal_ref or "",
        concern.concern_type,
        tuple(item.model_dump_json() for item in passages),
        correction or b"",
        concern.explanation,
    )


def aggregate_baseline_audit_v1(
    baseline_input: BaselineInputV1,
    review: BaselineReviewAggregateV1,
    fragments: tuple[AcceptedBaselineAuditFragmentV1, ...],
) -> BaselineAuditAggregateV1:
    """Aggregate source-audit bytes and enforce exact importance coverage."""
    checked_input = _checked_input(baseline_input)
    checked_review = _verified_review(checked_input, review)
    checked_fragments = _audit_fragments(checked_input, checked_review, fragments)
    source_texts = _source_texts(checked_input)
    proposal_by_ref = {item.proposal_ref: item.proposal for item in checked_review.proposals}
    concerns = [concern for item in checked_fragments for concern in item.payload.concerns]
    targeted: set[str] = set()
    omission_statements: set[str] = set()
    for concern in concerns:
        _resolve_passages(source_texts, concern.passages)
        if concern.target_proposal_ref is not None:
            if concern.target_proposal_ref not in proposal_by_ref:
                raise BaselineCompilationError("BASELINE_AUDIT_REFERENCE")
            if concern.target_proposal_ref in targeted:
                raise BaselineCompilationError("BASELINE_AUDIT_SEMANTICS")
            targeted.add(concern.target_proposal_ref)
        if concern.correction is not None:
            resolved = _resolved_proposal(source_texts, concern.correction)
            identity = _normalise_statement(resolved.proposal.statement)
            if concern.target_proposal_ref is None:
                if identity in omission_statements or identity in {
                    _normalise_statement(item.proposal.statement)
                    for item in checked_review.proposals
                }:
                    raise BaselineCompilationError("BASELINE_AUDIT_SEMANTICS")
                omission_statements.add(identity)
    ordered_concerns = tuple(sorted(concerns, key=lambda item: _concern_key(source_texts, item)))
    indexed_concerns = tuple(
        IndexedBaselineAuditConcernV1(audit_ref=f"AUD-{index:04d}", concern=item)
        for index, item in enumerate(ordered_concerns, 1)
    )
    findings = [
        finding for item in checked_fragments for finding in item.payload.importance_findings
    ]
    targets = [item.proposal_ref for item in checked_review.proposals]
    found = [item.proposal_ref for item in findings]
    if sorted(found) != sorted(targets) or len(found) != len(set(found)):
        raise BaselineCompilationError("BASELINE_AUDIT_IMPORTANCE_COVERAGE")
    for finding in findings:
        proposal = proposal_by_ref[finding.proposal_ref]
        agrees = (
            finding.reviewed_importance == proposal.importance
            and finding.reviewed_importance_basis == proposal.importance_basis
        )
        if agrees != (finding.disposition == "agree"):
            raise BaselineCompilationError("BASELINE_AUDIT_IMPORTANCE_DISPOSITION")
    ordered_findings = tuple(sorted(findings, key=lambda item: item.proposal_ref))
    fragment_fingerprints = tuple(item.response_fingerprint for item in checked_fragments)
    fingerprint = _hash(
        {
            "legal_input_fingerprint": checked_input.legal_input_fingerprint,
            "review_aggregate_fingerprint": checked_review.aggregate_fingerprint,
            "fragments": [item.model_dump(mode="json") for item in checked_fragments],
            "concerns": [item.model_dump(mode="json") for item in indexed_concerns],
            "importance_findings": [item.model_dump(mode="json") for item in ordered_findings],
            "fragment_fingerprints": fragment_fingerprints,
        }
    )
    return BaselineAuditAggregateV1(
        fragments=checked_fragments,
        concerns=indexed_concerns,
        importance_findings=ordered_findings,
        fragment_fingerprints=fragment_fingerprints,
        aggregate_fingerprint=fingerprint,
    )


def _verified_audit(
    baseline_input: BaselineInputV1,
    review: BaselineReviewAggregateV1,
    value: BaselineAuditAggregateV1,
) -> BaselineAuditAggregateV1:
    try:
        checked = cast(
            BaselineAuditAggregateV1,
            strict_baseline_model_v1(BaselineAuditAggregateV1, value),
        )
        expected = aggregate_baseline_audit_v1(baseline_input, review, checked.fragments)
        if checked != expected:
            raise ValueError
        return expected
    except Exception:
        raise BaselineCompilationError("BASELINE_AUDIT_AGGREGATE") from None


def _dispute_fingerprint(
    dispute_id: str,
    target_proposal_ref: str | None,
    reviewer_proposal: BaselineProposalV1 | None,
    auditor_concern: BaselineAuditConcernV1 | None,
    importance_finding: ImportanceAuditFindingV1 | None,
) -> str:
    return _hash(
        {
            "dispute_id": dispute_id,
            "target_proposal_ref": target_proposal_ref,
            "reviewer_proposal": (
                None if reviewer_proposal is None else reviewer_proposal.model_dump(mode="json")
            ),
            "auditor_concern": (
                None if auditor_concern is None else auditor_concern.model_dump(mode="json")
            ),
            "importance_finding": (
                None
                if importance_finding is None
                else importance_finding.model_dump(mode="json")
            ),
        }
    )


def build_baseline_disputes_v1(
    baseline_input: BaselineInputV1,
    review: BaselineReviewAggregateV1,
    audit: BaselineAuditAggregateV1,
) -> tuple[BaselineDisputeV1, ...]:
    """Issue one deterministic dispute for every semantic or importance disagreement."""
    checked_input = _checked_input(baseline_input)
    checked_review = _verified_review(checked_input, review)
    checked_audit = _verified_audit(checked_input, checked_review, audit)
    proposal_by_ref = {item.proposal_ref: item.proposal for item in checked_review.proposals}
    logical: list[
        tuple[
            str | None,
            BaselineProposalV1 | None,
            BaselineAuditConcernV1 | None,
            ImportanceAuditFindingV1 | None,
        ]
    ] = []
    for indexed in checked_audit.concerns:
        concern = indexed.concern
        logical.append(
            (
                concern.target_proposal_ref,
                (
                    None
                    if concern.target_proposal_ref is None
                    else proposal_by_ref[concern.target_proposal_ref]
                ),
                concern,
                None,
            )
        )
    for finding in checked_audit.importance_findings:
        proposal = proposal_by_ref[finding.proposal_ref]
        if (
            finding.reviewed_importance != proposal.importance
            or finding.reviewed_importance_basis != proposal.importance_basis
        ):
            logical.append((finding.proposal_ref, proposal, None, finding))
    logical.sort(
        key=lambda item: canonical_json_bytes(
            {
                "target": item[0],
                "reviewer": None if item[1] is None else item[1].model_dump(mode="json"),
                "concern": None if item[2] is None else item[2].model_dump(mode="json"),
                "importance": None if item[3] is None else item[3].model_dump(mode="json"),
            }
        )
    )
    result = []
    for index, (target, reviewer, audit_concern, importance) in enumerate(logical, 1):
        dispute_id = f"DSP-{index:04d}"
        result.append(
            BaselineDisputeV1(
                dispute_id=dispute_id,
                dispute_fingerprint=_dispute_fingerprint(
                    dispute_id, target, reviewer, audit_concern, importance
                ),
                target_proposal_ref=target,
                reviewer_proposal=reviewer,
                auditor_concern=audit_concern,
                importance_finding=importance,
            )
        )
    return tuple(result)


def _selected_importance(
    dispute: BaselineDisputeV1,
) -> tuple[BaselineImportanceV1, tuple[ImportanceBasisV1, ...]] | None:
    reviewer = dispute.reviewer_proposal
    decision = None
    if reviewer is not None:
        decision = (reviewer.importance, reviewer.importance_basis)
    return decision


def _validate_baseline_referee_choice_v1(
    baseline_input: BaselineInputV1,
    dispute: BaselineDisputeV1,
    decision: BaselineRefereeDecisionV1,
) -> None:
    _resolve_passages(_source_texts(baseline_input), decision.passages)
    if decision.decision == "accept_reviewer":
        expected = _selected_importance(dispute)
    elif dispute.importance_finding is not None:
        finding = dispute.importance_finding
        expected = (finding.reviewed_importance, finding.reviewed_importance_basis)
    elif dispute.auditor_concern is not None and dispute.auditor_concern.correction is not None:
        correction = dispute.auditor_concern.correction
        expected = (correction.importance, correction.importance_basis)
    else:
        expected = None
    if decision.decision == "unresolved" and dispute.importance_finding is not None:
        reviewer_importance = _selected_importance(dispute)
        finding = dispute.importance_finding
        alternatives = {
            reviewer_importance,
            (finding.reviewed_importance, finding.reviewed_importance_basis),
        }
        if (decision.importance, decision.importance_basis) not in alternatives:
            raise BaselineCompilationError("BASELINE_REFEREE_DECISION")
    if decision.decision != "unresolved" and (
        expected is None
        or decision.importance != expected[0]
        or decision.importance_basis != expected[1]
    ):
        raise BaselineCompilationError("BASELINE_REFEREE_DECISION")


def aggregate_baseline_referees_v1(
    baseline_input: BaselineInputV1,
    disputes: tuple[BaselineDisputeV1, ...],
    fragments: tuple[AcceptedBaselineRefereeFragmentV1, ...],
) -> BaselineRefereeAggregateV1:
    """Strictly bind exactly one accepted referee fragment to every dispute."""
    checked_input = _checked_input(baseline_input)
    try:
        raw_disputes = _strict_tuple(disputes, code="BASELINE_REFEREE_FRAGMENT")
        checked_disputes = tuple(
            cast(BaselineDisputeV1, strict_baseline_model_v1(BaselineDisputeV1, item))
            for item in raw_disputes
        )
        raw_fragments = _strict_tuple(fragments, code="BASELINE_REFEREE_FRAGMENT")
        checked_fragments = tuple(
            cast(
                AcceptedBaselineRefereeFragmentV1,
                strict_baseline_model_v1(AcceptedBaselineRefereeFragmentV1, item),
            )
            for item in raw_fragments
        )
    except BaselineCompilationError:
        raise
    except Exception:
        raise BaselineCompilationError("BASELINE_REFEREE_FRAGMENT") from None
    expected_ids = [f"DSP-{index:04d}" for index in range(1, len(checked_disputes) + 1)]
    if [item.dispute_id for item in checked_disputes] != expected_ids:
        raise BaselineCompilationError("BASELINE_REFEREE_FRAGMENT")
    by_id = {item.dispute_id: item for item in checked_fragments}
    if len(by_id) != len(checked_fragments) or set(by_id) != set(expected_ids):
        raise BaselineCompilationError("BASELINE_REFEREE_COVERAGE")
    ordered = tuple(by_id[item] for item in expected_ids)
    for dispute, fragment in zip(checked_disputes, ordered, strict=True):
        if fragment.dispute_fingerprint != dispute.dispute_fingerprint:
            raise BaselineCompilationError("BASELINE_REFEREE_FRAGMENT")
        _validate_baseline_referee_choice_v1(
            checked_input, dispute, fragment.decision
        )
    aggregate_fingerprint = _hash(
        {
            "legal_input_fingerprint": checked_input.legal_input_fingerprint,
            "disputes": [item.model_dump(mode="json") for item in checked_disputes],
            "fragments": [item.model_dump(mode="json") for item in ordered],
        }
    )
    return BaselineRefereeAggregateV1(
        fragments=ordered,
        aggregate_fingerprint=aggregate_fingerprint,
    )


def _proposal_with_importance(
    proposal: BaselineProposalV1,
    decision: BaselineRefereeDecisionV1,
) -> BaselineProposalV1:
    raw = proposal.model_dump(mode="json")
    raw.update(
        {
            "importance": decision.importance,
            "importance_basis": decision.importance_basis,
            "importance_rationale": decision.importance_rationale,
        }
    )
    return BaselineProposalV1.model_validate(raw)


def _proposal_with_audited_importance(
    proposal: BaselineProposalV1,
    finding: ImportanceAuditFindingV1,
    decision: BaselineRefereeDecisionV1,
) -> BaselineProposalV1:
    raw = proposal.model_dump(mode="json")
    raw.update(
        {
            "importance": finding.reviewed_importance,
            "importance_basis": finding.reviewed_importance_basis,
            "importance_rationale": decision.importance_rationale,
        }
    )
    return BaselineProposalV1.model_validate(raw)


def _requirement(
    resolved: _ResolvedProposal,
    *,
    requirement_id: str,
    canonical_order: int,
) -> BaselineRequirementV1:
    proposal = resolved.proposal
    return BaselineRequirementV1(
        requirement_id=requirement_id,
        canonical_order=canonical_order,
        statement=proposal.statement,
        kind=proposal.kind,
        importance=proposal.importance,
        importance_basis=proposal.importance_basis,
        importance_rationale=proposal.importance_rationale,
        passages=resolved.passages,
        dependency=proposal.dependency,
        confidence=proposal.confidence,
        substantive_rationale=proposal.substantive_rationale,
    )


def _requirement_alternatives(
    requirements: tuple[BaselineRequirementV1, ...],
    contested: tuple[ContestedBaselineRequirementV1, ...],
) -> tuple[BaselineRequirementV1, ...]:
    return (
        *requirements,
        *(
            alternative
            for item in contested
            for alternative in (item.reviewer_alternative, item.auditor_alternative)
            if alternative is not None
        ),
    )


def _dependency_edges(
    requirements: tuple[BaselineRequirementV1, ...],
    contested: tuple[ContestedBaselineRequirementV1, ...],
) -> set[
    tuple[
        Literal["depends_on", "exception_to", "defines", "enforced_by"],
        str,
        str,
    ]
]:
    alternatives = _requirement_alternatives(requirements, contested)
    by_statement: dict[str, set[str]] = {}
    for item in alternatives:
        by_statement.setdefault(_normalise_statement(item.statement), set()).add(
            item.requirement_id
        )
    edges: list[
        tuple[
            Literal["depends_on", "exception_to", "defines", "enforced_by"],
            str,
            str,
        ]
    ] = []
    for requirement in alternatives:
        dependency = requirement.dependency
        if dependency is None:
            continue
        targets = by_statement.get(_normalise_statement(dependency.target_statement), set())
        if len(targets) != 1:
            raise BaselineCompilationError("BASELINE_RELATIONSHIP_ENDPOINT")
        target = next(iter(targets))
        if target == requirement.requirement_id:
            raise BaselineCompilationError("BASELINE_RELATIONSHIP_SELF_REFERENCE")
        edges.append((dependency.relationship, requirement.requirement_id, target))
    return set(edges)


def _relationships(
    requirements: tuple[BaselineRequirementV1, ...],
    contested: tuple[ContestedBaselineRequirementV1, ...],
) -> tuple[BaselineRelationshipV1, ...]:
    ordered = sorted(_dependency_edges(requirements, contested))
    return tuple(
        BaselineRelationshipV1(
            relationship_id=f"REL-{index:04d}",
            relationship=edge[0],
            source_requirement_id=edge[1],
            target_requirement_id=edge[2],
        )
        for index, edge in enumerate(ordered, 1)
    )


def _validate_relationship_inventory(
    requirements: tuple[BaselineRequirementV1, ...],
    contested: tuple[ContestedBaselineRequirementV1, ...],
    relationships: tuple[BaselineRelationshipV1, ...],
) -> None:
    known = {
        item.requirement_id
        for item in _requirement_alternatives(requirements, contested)
    }
    actual = {
        (item.relationship, item.source_requirement_id, item.target_requirement_id)
        for item in relationships
    }
    if len(actual) != len(relationships) or any(
        item.source_requirement_id not in known
        or item.target_requirement_id not in known
        for item in relationships
    ):
        raise BaselineCompilationError("BASELINE_RELATIONSHIP_ENDPOINT")
    if any(
        item.source_requirement_id == item.target_requirement_id
        for item in relationships
    ):
        raise BaselineCompilationError("BASELINE_RELATIONSHIP_SELF_REFERENCE")
    if not _dependency_edges(requirements, contested).issubset(actual):
        raise BaselineCompilationError("BASELINE_RELATIONSHIP_DEPENDENCY")


def _contest_requirement(
    source_texts: dict[str, str],
    contest: _Contest,
    *,
    index: int,
    order: int,
) -> ContestedBaselineRequirementV1:
    requirement_id = f"REQ-{order + 1:04d}"

    def alternative(proposal: BaselineProposalV1 | None) -> BaselineRequirementV1 | None:
        if proposal is None:
            return None
        return _requirement(
            _resolved_proposal(source_texts, proposal),
            requirement_id=requirement_id,
            canonical_order=order,
        )

    return ContestedBaselineRequirementV1(
        contested_requirement_id=f"CONT-{index:04d}",
        reviewer_alternative=alternative(contest.reviewer),
        auditor_alternative=alternative(contest.auditor),
        unresolved_reason=contest.reason,
        importance=contest.decision.importance,
        importance_basis=contest.decision.importance_basis,
        importance_rationale=contest.decision.importance_rationale,
        substantive_rationale=contest.decision.substantive_rationale,
        referee_fragment_fingerprint=contest.response_fingerprint,
    )


def _baseline_fingerprint(value: CanonicalBaselineV1) -> str:
    return _hash(
        {
            key: item
            for key, item in value.model_dump(mode="json").items()
            if key != "baseline_fingerprint"
        }
    )


def compile_canonical_baseline_v1(
    baseline_input: BaselineInputV1,
    review: BaselineReviewAggregateV1,
    audit: BaselineAuditAggregateV1,
    referees: BaselineRefereeAggregateV1,
) -> CanonicalBaselineV1:
    """Compile one canonical report-independent baseline from exact accepted bytes."""
    checked_input = _checked_input(baseline_input)
    checked_review = _verified_review(checked_input, review)
    checked_audit = _verified_audit(checked_input, checked_review, audit)
    disputes = build_baseline_disputes_v1(checked_input, checked_review, checked_audit)
    try:
        checked_referees = cast(
            BaselineRefereeAggregateV1,
            strict_baseline_model_v1(BaselineRefereeAggregateV1, referees),
        )
        expected_referees = aggregate_baseline_referees_v1(
            checked_input, disputes, checked_referees.fragments
        )
        if checked_referees != expected_referees:
            raise ValueError
    except BaselineCompilationError:
        raise
    except Exception:
        raise BaselineCompilationError("BASELINE_REFEREE_AGGREGATE") from None
    decisions = {
        item.dispute_id: item for item in checked_referees.fragments
    }
    ordinary: dict[str, BaselineProposalV1] = {
        item.proposal_ref: item.proposal for item in checked_review.proposals
    }
    additions: list[BaselineProposalV1] = []
    contests: list[_Contest] = []
    semantic_targets: set[str] = set()
    for dispute in disputes:
        if dispute.auditor_concern is None:
            continue
        fragment = decisions[dispute.dispute_id]
        decision = fragment.decision
        concern = dispute.auditor_concern
        target = dispute.target_proposal_ref
        if target is not None:
            semantic_targets.add(target)
        if decision.decision == "unresolved":
            if target is not None:
                ordinary.pop(target, None)
            contests.append(
                _Contest(
                    target,
                    dispute.reviewer_proposal,
                    concern.correction,
                    decision,
                    fragment.response_fingerprint,
                    (
                        "SOURCE_AMBIGUITY"
                        if concern.concern_type == "ambiguity"
                        else "SOURCE_GAP"
                        if concern.concern_type == "omission"
                        else "SOURCE_CONFLICT"
                    ),
                )
            )
        elif decision.decision == "accept_auditor":
            if concern.correction is None:
                raise BaselineCompilationError("BASELINE_REFEREE_DECISION")
            selected = _proposal_with_importance(concern.correction, decision)
            if target is None:
                additions.append(selected)
            else:
                ordinary[target] = selected
        elif target is not None:
            ordinary[target] = _proposal_with_importance(ordinary[target], decision)
    for dispute in disputes:
        finding = dispute.importance_finding
        if finding is None:
            continue
        fragment = decisions[dispute.dispute_id]
        decision = fragment.decision
        target = cast(str, dispute.target_proposal_ref)
        current = ordinary.get(target)
        reviewer = current or dispute.reviewer_proposal
        if decision.decision == "unresolved":
            if reviewer is None:
                raise BaselineCompilationError("BASELINE_DISPUTE_RECONCILIATION")
            ordinary.pop(target, None)
            contests.append(
                _Contest(
                    target,
                    reviewer,
                    _proposal_with_audited_importance(reviewer, finding, decision),
                    decision,
                    fragment.response_fingerprint,
                    "SOURCE_AMBIGUITY",
                )
            )
        elif current is not None:
            if decision.decision == "accept_auditor":
                ordinary[target] = _proposal_with_audited_importance(
                    current, finding, decision
                )
            else:
                ordinary[target] = _proposal_with_importance(current, decision)
        elif target in semantic_targets:
            updated: list[_Contest] = []
            matched = False
            for contest in contests:
                if contest.target_proposal_ref != target or contest.reviewer is None:
                    updated.append(contest)
                    continue
                matched = True
                reviewer_alternative = (
                    _proposal_with_audited_importance(
                        contest.reviewer, finding, decision
                    )
                    if decision.decision == "accept_auditor"
                    else _proposal_with_importance(contest.reviewer, decision)
                )
                updated.append(replace(contest, reviewer=reviewer_alternative))
            if not matched:
                raise BaselineCompilationError("BASELINE_DISPUTE_RECONCILIATION")
            contests = updated
    source_texts = _source_texts(checked_input)
    resolved = [
        _resolved_proposal(source_texts, proposal)
        for proposal in (*ordinary.values(), *additions)
    ]
    _validate_proposal_semantics(resolved, code="BASELINE_COMPILED_SEMANTICS")
    ordered = sorted(resolved, key=_proposal_key)
    requirements = tuple(
        _requirement(item, requirement_id=f"REQ-{index:04d}", canonical_order=index - 1)
        for index, item in enumerate(ordered, 1)
    )
    contest_order = sorted(
        contests,
        key=lambda item: canonical_json_bytes(
            {
                "reviewer": (
                    None if item.reviewer is None else item.reviewer.model_dump(mode="json")
                ),
                "auditor": (
                    None if item.auditor is None else item.auditor.model_dump(mode="json")
                ),
                "response_fingerprint": item.response_fingerprint,
            }
        ),
    )
    contested = tuple(
        _contest_requirement(
            source_texts,
            item,
            index=index,
            order=len(requirements) + index - 1,
        )
        for index, item in enumerate(contest_order, 1)
    )
    relationships = _relationships(requirements, contested)
    _validate_relationship_inventory(requirements, contested, relationships)
    provenance = BaselineProvenanceV1(
        legal_input_fingerprint=checked_input.legal_input_fingerprint,
        source_review_aggregate_fingerprint=checked_review.aggregate_fingerprint,
        source_audit_aggregate_fingerprint=checked_audit.aggregate_fingerprint,
        source_referee_aggregate_fingerprint=checked_referees.aggregate_fingerprint,
        importance_policy_fingerprint=checked_input.importance_policy_fingerprint,
        compiler_contract_fingerprint=BASELINE_COMPILER_CONTRACT_FINGERPRINT_V1,
    )
    provisional = CanonicalBaselineV1(
        legal_input_fingerprint=checked_input.legal_input_fingerprint,
        requirements=requirements,
        relationships=relationships,
        contested_requirements=contested,
        provenance=provenance,
        baseline_fingerprint="0" * 64,
    )
    raw = provisional.model_dump(mode="json")
    raw["baseline_fingerprint"] = _baseline_fingerprint(provisional)
    return cast(
        CanonicalBaselineV1,
        strict_baseline_model_v1(CanonicalBaselineV1, raw),
    )


def _checked_prior_baseline(
    baseline_input: BaselineInputV1, value: CanonicalBaselineV1
) -> CanonicalBaselineV1:
    try:
        checked = cast(
            CanonicalBaselineV1,
            strict_baseline_model_v1(CanonicalBaselineV1, value),
        )
        if (
            checked.baseline_fingerprint != _baseline_fingerprint(checked)
            or checked.legal_input_fingerprint != baseline_input.legal_input_fingerprint
            or checked.provenance.importance_policy_fingerprint
            != baseline_input.importance_policy_fingerprint
            or checked.provenance.compiler_contract_fingerprint
            != baseline_input.compiler_contract_fingerprint
            or [item.requirement_id for item in checked.requirements]
            != [f"REQ-{index:04d}" for index in range(1, len(checked.requirements) + 1)]
        ):
            raise ValueError
        source_texts = _source_texts(baseline_input)
        for requirement in checked.requirements:
            _validate_resolved_passages(source_texts, requirement.passages)
        for contest in checked.contested_requirements:
            for alternative in (
                contest.reviewer_alternative,
                contest.auditor_alternative,
            ):
                if alternative is not None:
                    _validate_resolved_passages(source_texts, alternative.passages)
        _validate_relationship_inventory(
            checked.requirements,
            checked.contested_requirements,
            checked.relationships,
        )
        return checked
    except BaselineCompilationError:
        raise
    except Exception:
        raise BaselineCompilationError("BASELINE_PRIOR_INVALID") from None


def _validate_resolved_passages(
    source_texts: dict[str, str], passages: Iterable[ResolvedPassageV2]
) -> None:
    identities: list[tuple[str, int, int, str]] = []
    try:
        for passage in passages:
            checked = ResolvedPassageV2.model_validate(passage)
            text = source_texts[checked.source_id]
            if (
                text.find(checked.quote) != checked.start_char
                or text[checked.start_char : checked.end_char] != checked.quote
                or checked.end_char != checked.start_char + len(checked.quote)
            ):
                raise ValueError
            identities.append(
                (
                    checked.source_id,
                    checked.start_char,
                    checked.end_char,
                    checked.quote,
                )
            )
    except Exception:
        raise BaselineCompilationError("BASELINE_CORRECTION_EVIDENCE") from None
    if len(identities) != len(set(identities)):
        raise BaselineCompilationError("BASELINE_CORRECTION_EVIDENCE")


def _correction_fingerprint(value: BaselineCorrectionRecordV1) -> str:
    return _hash(
        {
            key: item
            for key, item in value.model_dump(mode="json").items()
            if key != "correction_fingerprint"
        }
    )


def validate_baseline_correction_v1(
    baseline_input: BaselineInputV1,
    prior_baseline: CanonicalBaselineV1,
    correction: BaselineCorrectionRecordV1,
    *,
    prior_baseline_root: str,
) -> BaselineCorrectionRecordV1:
    """Validate a report-free correction against explicit prior root and baseline bindings."""
    checked_input = _checked_input(baseline_input)
    checked_prior = _checked_prior_baseline(checked_input, prior_baseline)
    try:
        checked = cast(
            BaselineCorrectionRecordV1,
            strict_baseline_model_v1(BaselineCorrectionRecordV1, correction),
        )
    except Exception:
        raise BaselineCompilationError("BASELINE_CORRECTION_INVALID") from None
    if type(prior_baseline_root) is not str or checked.prior_baseline_root != prior_baseline_root:
        raise BaselineCompilationError("BASELINE_CORRECTION_PRIOR_ROOT")
    if checked.prior_baseline_fingerprint != checked_prior.baseline_fingerprint:
        raise BaselineCompilationError("BASELINE_CORRECTION_PRIOR_FINGERPRINT")
    if checked.correction_fingerprint != _correction_fingerprint(checked):
        raise BaselineCompilationError("BASELINE_CORRECTION_FINGERPRINT")
    source_texts = _source_texts(checked_input)
    for action in checked.actions:
        if action.requirement is not None:
            _validate_resolved_passages(source_texts, action.requirement.passages)
    return checked


def _fresh_requirement(value: BaselineRequirementV1) -> BaselineRequirementV1:
    return BaselineRequirementV1.model_validate(value.model_dump(mode="json"))


def _fresh_relationship(value: BaselineRelationshipV1) -> BaselineRelationshipV1:
    return BaselineRelationshipV1.model_validate(value.model_dump(mode="json"))


def _fresh_contested(
    value: ContestedBaselineRequirementV1,
) -> ContestedBaselineRequirementV1:
    return ContestedBaselineRequirementV1.model_validate(value.model_dump(mode="json"))


def _renumber_requirement(
    value: BaselineRequirementV1 | None,
    *,
    requirement_id: str,
    canonical_order: int,
) -> BaselineRequirementV1 | None:
    if value is None:
        return None
    return BaselineRequirementV1.model_validate(
        {
            **value.model_dump(mode="json"),
            "requirement_id": requirement_id,
            "canonical_order": canonical_order,
        }
    )


def _apply_requirement_actions(
    requirements: dict[str, BaselineRequirementV1],
    actions: tuple[BaselineCorrectionActionV1, ...],
    *,
    reserved_requirement_ids: set[str],
) -> None:
    touched: set[str] = set()
    for action in actions:
        if action.action not in {
            "add_requirement",
            "replace_requirement",
            "remove_requirement",
        }:
            continue
        replacement = action.requirement
        if action.action == "add_requirement":
            assert replacement is not None
            identifier = replacement.requirement_id
            if (
                identifier in requirements
                or identifier in reserved_requirement_ids
                or identifier in touched
            ):
                raise BaselineCompilationError("BASELINE_CORRECTION_REQUIREMENT")
            requirements[identifier] = _fresh_requirement(replacement)
            touched.add(identifier)
            continue
        identifier = cast(str, action.requirement_id)
        if identifier in touched or identifier not in requirements:
            raise BaselineCompilationError("BASELINE_CORRECTION_REQUIREMENT")
        touched.add(identifier)
        if action.action == "remove_requirement":
            del requirements[identifier]
            continue
        assert replacement is not None
        if replacement.requirement_id != identifier:
            raise BaselineCompilationError("BASELINE_CORRECTION_REQUIREMENT")
        requirements[identifier] = _fresh_requirement(replacement)


def _apply_relationship_actions(
    relationships: dict[str, BaselineRelationshipV1],
    actions: tuple[BaselineCorrectionActionV1, ...],
) -> None:
    touched: set[str] = set()
    for action in actions:
        if action.action not in {
            "add_relationship",
            "replace_relationship",
            "remove_relationship",
        }:
            continue
        replacement = action.relationship
        if action.action == "add_relationship":
            assert replacement is not None
            identifier = replacement.relationship_id
            if identifier in relationships or identifier in touched:
                raise BaselineCompilationError("BASELINE_CORRECTION_RELATIONSHIP")
            relationships[identifier] = _fresh_relationship(replacement)
            touched.add(identifier)
            continue
        identifier = cast(str, action.relationship_id)
        if identifier in touched or identifier not in relationships:
            raise BaselineCompilationError("BASELINE_CORRECTION_RELATIONSHIP")
        touched.add(identifier)
        if action.action == "remove_relationship":
            del relationships[identifier]
            continue
        assert replacement is not None
        if replacement.relationship_id != identifier:
            raise BaselineCompilationError("BASELINE_CORRECTION_RELATIONSHIP")
        relationships[identifier] = _fresh_relationship(replacement)


def _corrected_requirement_key(value: BaselineRequirementV1) -> tuple[object, ...]:
    first = value.passages[0]
    raw = value.model_dump(mode="json")
    raw.pop("requirement_id")
    raw.pop("canonical_order")
    return (
        first.source_id,
        first.start_char,
        first.end_char,
        value.kind.value,
        _normalise_statement(value.statement),
        _hash(raw),
    )


def apply_baseline_correction_v1(
    baseline_input: BaselineInputV1,
    prior_baseline: CanonicalBaselineV1,
    correction: BaselineCorrectionRecordV1,
    *,
    prior_baseline_root: str,
) -> CanonicalBaselineV1:
    """Apply a strict correction to a fresh value and return a newly fingerprinted baseline."""
    checked_input = _checked_input(baseline_input)
    checked_prior = _checked_prior_baseline(checked_input, prior_baseline)
    checked_correction = validate_baseline_correction_v1(
        checked_input,
        checked_prior,
        correction,
        prior_baseline_root=prior_baseline_root,
    )
    requirements = {
        item.requirement_id: _fresh_requirement(item) for item in checked_prior.requirements
    }
    relationships = {
        item.relationship_id: _fresh_relationship(item)
        for item in checked_prior.relationships
    }
    contested = tuple(_fresh_contested(item) for item in checked_prior.contested_requirements)
    contested_requirement_ids = {
        alternative.requirement_id
        for item in contested
        for alternative in (item.reviewer_alternative, item.auditor_alternative)
        if alternative is not None
    }
    _apply_requirement_actions(
        requirements,
        checked_correction.actions,
        reserved_requirement_ids=contested_requirement_ids,
    )
    _apply_relationship_actions(relationships, checked_correction.actions)
    source_texts = _source_texts(checked_input)
    statements: set[str] = set()
    for requirement in requirements.values():
        _validate_resolved_passages(source_texts, requirement.passages)
        identity = _normalise_statement(requirement.statement)
        if identity in statements:
            raise BaselineCompilationError("BASELINE_CORRECTION_REQUIREMENT")
        statements.add(identity)
    known = set(requirements).union(
        alternative.requirement_id
        for item in contested
        for alternative in (item.reviewer_alternative, item.auditor_alternative)
        if alternative is not None
    )
    if any(
        relationship.source_requirement_id not in known
        or relationship.target_requirement_id not in known
        for relationship in relationships.values()
    ):
        raise BaselineCompilationError("BASELINE_CORRECTION_RELATIONSHIP")
    ordered_requirements = sorted(requirements.values(), key=_corrected_requirement_key)
    identifier_map = {
        item.requirement_id: f"REQ-{index:04d}"
        for index, item in enumerate(ordered_requirements, 1)
    }
    canonical_requirements = tuple(
        BaselineRequirementV1.model_validate(
            {
                **item.model_dump(mode="json"),
                "requirement_id": identifier_map[item.requirement_id],
                "canonical_order": index - 1,
            }
        )
        for index, item in enumerate(ordered_requirements, 1)
    )
    canonical_contested: list[ContestedBaselineRequirementV1] = []
    for index, item in enumerate(contested, 1):
        alternatives = tuple(
            alternative
            for alternative in (item.reviewer_alternative, item.auditor_alternative)
            if alternative is not None
        )
        old_ids = {alternative.requirement_id for alternative in alternatives}
        if len(old_ids) != 1:
            raise BaselineCompilationError("BASELINE_CORRECTION_REQUIREMENT")
        old_id = next(iter(old_ids))
        new_id = f"REQ-{len(canonical_requirements) + index:04d}"
        new_order = len(canonical_requirements) + index - 1
        identifier_map[old_id] = new_id

        canonical_contested.append(
            ContestedBaselineRequirementV1.model_validate(
                {
                    **item.model_dump(mode="json"),
                    "contested_requirement_id": f"CONT-{index:04d}",
                    "reviewer_alternative": _renumber_requirement(
                        item.reviewer_alternative,
                        requirement_id=new_id,
                        canonical_order=new_order,
                    ),
                    "auditor_alternative": _renumber_requirement(
                        item.auditor_alternative,
                        requirement_id=new_id,
                        canonical_order=new_order,
                    ),
                }
            )
        )
    edges = sorted(
        (
            item.relationship,
            identifier_map[item.source_requirement_id],
            identifier_map[item.target_requirement_id],
        )
        for item in relationships.values()
    )
    if len(edges) != len(set(edges)):
        raise BaselineCompilationError("BASELINE_CORRECTION_RELATIONSHIP")
    canonical_relationships = tuple(
        BaselineRelationshipV1(
            relationship_id=f"REL-{index:04d}",
            relationship=edge[0],
            source_requirement_id=edge[1],
            target_requirement_id=edge[2],
        )
        for index, edge in enumerate(edges, 1)
    )
    contested_requirements = tuple(canonical_contested)
    _validate_relationship_inventory(
        canonical_requirements,
        contested_requirements,
        canonical_relationships,
    )
    provisional = CanonicalBaselineV1(
        legal_input_fingerprint=checked_input.legal_input_fingerprint,
        requirements=canonical_requirements,
        relationships=canonical_relationships,
        contested_requirements=contested_requirements,
        provenance=BaselineProvenanceV1.model_validate(
            checked_prior.provenance.model_dump(mode="json")
        ),
        prior_baseline_fingerprint=checked_prior.baseline_fingerprint,
        correction_record_fingerprint=checked_correction.correction_fingerprint,
        baseline_fingerprint="0" * 64,
    )
    raw = provisional.model_dump(mode="json")
    raw["baseline_fingerprint"] = _baseline_fingerprint(provisional)
    result = cast(
        CanonicalBaselineV1,
        strict_baseline_model_v1(CanonicalBaselineV1, raw),
    )
    if result.baseline_fingerprint == checked_prior.baseline_fingerprint:
        raise BaselineCompilationError("BASELINE_CORRECTION_FINGERPRINT")
    return result
