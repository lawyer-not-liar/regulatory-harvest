"""Deterministic Protocol 2.2 fragment aggregation and semantic reconstruction."""

from __future__ import annotations

import hashlib
from typing import Literal

from regulatory_harvest.storage import canonical_json_bytes

from .attorney_models import CaseEnvelope
from .attorney_v2_compiler import CompilationError, index_review, resolve_exact_passage
from .attorney_v2_models import (
    AbsoluteDispositionV2,
    ImportanceV2,
    MaterialDisputeV2,
    ResolvedPassageV2,
    SemanticProposal,
    SourceReviewV2,
)
from .attorney_v21_compiler import (
    aggregate_referee_decisions as _aggregate_v21,
)
from .attorney_v21_compiler import (
    build_referee_disputes as _disputes_v21,
)
from .attorney_v21_compiler import (
    compile_baseline_v21 as _baseline_v21,
)
from .attorney_v21_compiler import (
    validate_referee_fragment as _fragment_v21,
)
from .attorney_v21_models import RefereeDisputeV21, SourceAuditV21, SourceReviewV21
from .attorney_v21_rubric import (
    RUBRIC_V21,
    RubricValidationError,
)
from .attorney_v22_models import (
    AcceptedRefereeFragmentV22,
    AcceptedSourceAuditFragmentV22,
    AcceptedSourceReviewFragmentV22,
    AuditConcernV22,
    CanonicalBaselineV22,
    ContestedGradeFragmentV22,
    GraderAggregateV22,
    IndexedAuditConcernV22,
    IndexedProposalV22,
    OrdinaryGradeBatchV22,
    OrdinaryGradeFragmentV22,
    ReconciledGradeV22,
    RefereeAggregateV22,
    RefereeDecisionV22,
    RefereeDisputeV22,
    RefereeEvidenceV22,
    RubricV22,
    SensitivityRecordV22,
    SourceAuditAggregateV22,
    SourceAuditFragmentV22,
    SourceReviewAggregateV22,
    _strict_grade_coordinate_v22,
    _strict_rehydrate_v22,
    _wire_snapshot,
)
from .attorney_v22_requests import (
    _audit_history,
    _review_history,
    _verified_source_request_context_v22,
    _VerifiedSourceRequestContextV22,
)

RUBRIC_V22 = RubricV22(
    version="attorney-eval-v2.2",
    importance_weights=RUBRIC_V21.importance_weights,
    critical_recall_floor=RUBRIC_V21.critical_recall_floor,
    weighted_coverage_floor=RUBRIC_V21.weighted_coverage_floor,
    material_unsupported_assertions_allowed=RUBRIC_V21.material_unsupported_assertions_allowed,
)


def _hash(value: object) -> str:
    digest = hashlib.sha256(canonical_json_bytes(value))
    return digest.hexdigest()


def _validated_referee_dispute_v22(dispute: RefereeDisputeV22) -> RefereeDisputeV22:
    return _strict_rehydrate_v22(
        RefereeDisputeV22, dispute, location="referee dispute"
    )


def _referee_dispute_fingerprint_from_validated_v22(
    checked: RefereeDisputeV22,
) -> str:
    return _hash(
        {
            "schema_version": "2.2",
            "case_fingerprint": checked.case_fingerprint,
            "dispute_id": checked.dispute_id,
            "material_dispute": checked.material_dispute.model_dump(mode="json"),
            "evidence": [item.model_dump(mode="json") for item in checked.evidence],
        }
    )


def referee_dispute_fingerprint_v22(dispute: RefereeDisputeV22) -> str:
    return _referee_dispute_fingerprint_from_validated_v22(
        _validated_referee_dispute_v22(dispute)
    )


def _validated_canonical_baseline_v22(value: object) -> CanonicalBaselineV22:
    return _strict_rehydrate_v22(
        CanonicalBaselineV22, value, location="canonical baseline"
    )


def _canonical_baseline_fingerprint_from_validated_v22(
    checked: CanonicalBaselineV22,
) -> str:
    checked_payload = checked.model_dump(mode="json")
    payload = {
        key: item
        for key, item in checked_payload.items()
        if key != "baseline_fingerprint"
    }
    return _hash(payload)


def verify_canonical_baseline_v22(value: object) -> CanonicalBaselineV22:
    """Raw-wire rebuild and seal the complete canonical V2.2 baseline."""
    try:
        checked = _validated_canonical_baseline_v22(value)
        if checked.baseline_fingerprint != (
            _canonical_baseline_fingerprint_from_validated_v22(checked)
        ):
            raise ValueError("baseline fingerprint is invalid")
        return checked
    except Exception as error:
        raise RubricValidationError("BASELINE_INVALID") from error


def _canonical_dispute_passages_v22(
    source_texts: dict[str, str], dispute: MaterialDisputeV2
) -> tuple[ResolvedPassageV2, ...]:
    passages = []
    if dispute.reviewer_proposal is not None:
        passages.extend(dispute.reviewer_proposal.passages)
    passages.extend(dispute.audit_concern.passages)
    if dispute.audit_concern.correction is not None:
        passages.extend(dispute.audit_concern.correction.passages)
    resolved = [
        resolve_exact_passage(source_texts[item.source_id], item) for item in passages
    ]
    unique = {
        (item.source_id, item.start_char, item.end_char, item.quote): item for item in resolved
    }
    return tuple(sorted(unique.values(), key=lambda item: (
        item.source_id, item.start_char, item.end_char, item.quote
    )))


def canonical_referee_disputes_v22(
    envelope: CaseEnvelope, material_disputes: tuple[MaterialDisputeV2, ...]
) -> tuple[RefereeDisputeV22, ...]:
    """Construct the sole canonical V2.2 referee/evidence inventory from materials."""
    try:
        checked_envelope = _strict_rehydrate_v22(
            CaseEnvelope, envelope, location="frozen case envelope"
        )
        disputes = tuple(
            _strict_rehydrate_v22(
                MaterialDisputeV2, item, location="material dispute inventory"
            )
            for item in material_disputes
        )
        if [item.dispute_id for item in disputes] != [
            f"D{index:04d}" for index in range(1, len(disputes) + 1)
        ]:
            raise ValueError("material dispute inventory is invalid")
        source_texts = {
            source.source_id: source.normalized_text for source in checked_envelope.case.sources
        }
        resolved = [
            (dispute, _canonical_dispute_passages_v22(source_texts, dispute))
            for dispute in disputes
        ]
        ordered = sorted(
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
            for index, (source_id, start, end, quote, dispute_id, _) in enumerate(ordered, 1)
        }
        result = []
        for dispute, passages in resolved:
            provisional = RefereeDisputeV22(
                case_fingerprint=checked_envelope.case_fingerprint,
                dispute_fingerprint="0" * 64,
                dispute_id=dispute.dispute_id,
                material_dispute=dispute,
                evidence=tuple(
                    RefereeEvidenceV22(
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
                ),
            )
            result.append(
                provisional.model_copy(
                    update={"dispute_fingerprint": referee_dispute_fingerprint_v22(provisional)}
                )
            )
        return tuple(result)
    except Exception as error:
        raise CompilationError("REFEREE_DISPUTE_INVALID") from error


def _semantic_identity(value: SemanticProposal | AuditConcernV22) -> object:
    """Use meaning-bearing local identity; nonidentical duplicates are conflicts."""
    separator = " "
    if isinstance(value, SemanticProposal):
        return ("proposal", separator.join(value.statement.split()))
    passages = tuple(sorted((item.source_id, item.quote) for item in value.passages))
    correction = (
        None
        if value.correction is None
        else separator.join(value.correction.statement.split())
    )
    return ("concern", value.target_proposal_ref, value.concern_type, passages, correction)


def _review_fragments(
    value: tuple[AcceptedSourceReviewFragmentV22, ...],
) -> tuple[AcceptedSourceReviewFragmentV22, ...]:
    try:
        checked = tuple(
            _strict_rehydrate_v22(
                AcceptedSourceReviewFragmentV22,
                item,
                location="source-review fragment",
            )
            for item in value
        )
    except Exception as error:
        raise ValueError("source-review fragments are invalid") from error
    if (
        not checked
        or len(checked) > 128
        or [item.fragment_ordinal for item in checked] != list(range(1, len(checked) + 1))
        or not checked[-1].payload.review_complete
        or any(item.payload.review_complete for item in checked[:-1])
    ):
        raise ValueError("source-review fragment sequence is invalid")
    if (
        len({item.response_fingerprint for item in checked}) != len(checked)
        or sum(len(item.payload.proposals) for item in checked) > 640
    ):
        raise ValueError("source-review fragment bounds are invalid")
    return checked


def aggregate_source_review_fragments_v22(
    fragments: tuple[AcceptedSourceReviewFragmentV22, ...],
) -> SourceReviewAggregateV22:
    checked = _review_fragments(fragments)
    proposals = [proposal for fragment in checked for proposal in fragment.payload.proposals]
    _validate_source_fragment_semantics_v22(
        tuple(proposals), kind="source-review proposal"
    )
    indexed = tuple(
        IndexedProposalV22(proposal_ref=f"P{index:04d}", proposal=item)
        for index, item in enumerate(proposals, 1)
    )
    fps = tuple(item.response_fingerprint for item in checked)
    payload = {
        "schema_version": "2.2",
        "fragments": [item.model_dump(mode="json") for item in checked],
        "proposals": [item.model_dump(mode="json") for item in indexed],
    }
    return SourceReviewAggregateV22(
        fragments=checked,
        proposals=indexed,
        fragment_fingerprints=fps,
        aggregate_fingerprint=_hash(payload),
    )


def _audit_fragments(
    review: SourceReviewAggregateV22, value: tuple[AcceptedSourceAuditFragmentV22, ...]
) -> tuple[AcceptedSourceAuditFragmentV22, ...]:
    try:
        sealed = _strict_rehydrate_v22(
            SourceReviewAggregateV22,
            review,
            location="source-review aggregate",
        )
        checked_items = []
        for item in value:
            raw = _wire_snapshot(item)
            if not isinstance(raw, dict):
                raise ValueError
            payload = SourceAuditFragmentV22.validate_for_indexed_proposals(
                raw.get("payload"), sealed.proposals
            )
            checked_items.append(
                _strict_rehydrate_v22(
                    AcceptedSourceAuditFragmentV22,
                    {**raw, "payload": payload},
                    location="source-audit fragment",
                )
            )
        checked = tuple(checked_items)
    except Exception as error:
        raise ValueError("source-audit fragments are invalid") from error
    if (
        not checked
        or len(checked) > 128
        or [item.fragment_ordinal for item in checked] != list(range(1, len(checked) + 1))
        or not checked[-1].payload.audit_complete
        or any(item.payload.audit_complete for item in checked[:-1])
    ):
        raise ValueError("source-audit fragment sequence is invalid")
    if (
        len({item.response_fingerprint for item in checked}) != len(checked)
        or sum(len(item.payload.concerns) for item in checked) > 640
    ):
        raise ValueError("source-audit fragment bounds are invalid")
    return checked


def aggregate_source_audit_fragments_v22(
    review: SourceReviewAggregateV22, fragments: tuple[AcceptedSourceAuditFragmentV22, ...]
) -> SourceAuditAggregateV22:
    checked = _audit_fragments(review, fragments)
    concerns = [concern for fragment in checked for concern in fragment.payload.concerns]
    _validate_source_fragment_semantics_v22(
        tuple(concerns), kind="source-audit concern"
    )
    indexed = tuple(
        IndexedAuditConcernV22(concern_ref=f"C{index:04d}", concern=item)
        for index, item in enumerate(concerns, 1)
    )
    fps = tuple(item.response_fingerprint for item in checked)
    return SourceAuditAggregateV22(
        fragments=checked,
        concerns=indexed,
        fragment_fingerprints=fps,
        aggregate_fingerprint=_hash(
            {
                "schema_version": "2.2",
                "review": review.aggregate_fingerprint,
                "fragments": [item.model_dump(mode="json") for item in checked],
                "concerns": [item.model_dump(mode="json") for item in indexed],
            }
        ),
    )


def _verify_source_review_aggregate_with_context_v22(
    context: _VerifiedSourceRequestContextV22,
    value: object,
) -> SourceReviewAggregateV22:
    checked = _strict_rehydrate_v22(
        SourceReviewAggregateV22, value, location="source-review aggregate"
    )
    fragments = _review_history(context, checked.fragments, complete=True)
    source_texts = {
        source.source_id: source.normalized_text
        for source in context.envelope.case.sources
    }
    for fragment in fragments:
        for proposal in fragment.payload.proposals:
            for passage in proposal.passages:
                resolve_exact_passage(source_texts[passage.source_id], passage)
    expected = aggregate_source_review_fragments_v22(fragments)
    if checked != expected:
        raise ValueError
    return expected


def verify_source_review_aggregate_v22(
    envelope: CaseEnvelope, value: object
) -> SourceReviewAggregateV22:
    """Rebuild one review aggregate from its exact case-bound request history."""
    try:
        context = _verified_source_request_context_v22(envelope)
        return _verify_source_review_aggregate_with_context_v22(context, value)
    except Exception:
        raise CompilationError("SOURCE_REVIEW_AGGREGATE_INVALID") from None


def verify_source_audit_aggregate_v22(
    envelope: CaseEnvelope,
    review: SourceReviewAggregateV22,
    value: object,
) -> SourceAuditAggregateV22:
    """Rebuild one audit aggregate from its exact review-bound request history."""
    try:
        context = _verified_source_request_context_v22(envelope)
        checked_review = _verify_source_review_aggregate_with_context_v22(
            context, review
        )
        return _verify_source_audit_aggregate_with_context_v22(
            context, checked_review, value
        )
    except Exception:
        raise CompilationError("SOURCE_AUDIT_AGGREGATE_INVALID") from None


def _verify_source_audit_aggregate_with_context_v22(
    context: _VerifiedSourceRequestContextV22,
    review: SourceReviewAggregateV22,
    value: object,
) -> SourceAuditAggregateV22:
    checked = SourceAuditAggregateV22.validate_for_indexed_proposals(
        value, review.proposals
    )
    fragments = _audit_history(context, review, checked.fragments, complete=True)
    source_texts = {
        source.source_id: source.normalized_text
        for source in context.envelope.case.sources
    }
    for fragment in fragments:
        for concern in fragment.payload.concerns:
            proposals = (() if concern.correction is None else (concern.correction,))
            passages = (
                *concern.passages,
                *(passage for proposal in proposals for passage in proposal.passages),
            )
            for passage in passages:
                resolve_exact_passage(source_texts[passage.source_id], passage)
    expected = aggregate_source_audit_fragments_v22(review, fragments)
    if checked != expected:
        raise ValueError
    return expected


def _v21_inputs(
    review: SourceReviewAggregateV22, audit: SourceAuditAggregateV22
) -> tuple[SourceReviewV21, SourceAuditV21]:
    try:
        review = _strict_rehydrate_v22(
            SourceReviewAggregateV22, review, location="source-review aggregate"
        )
        audit = SourceAuditAggregateV22.validate_for_indexed_proposals(
            audit, review.proposals
        )
        r = SourceReviewV21(
            schema_version="2.1",
            proposals=[item.proposal for item in review.proposals],
        )
        indexed = index_review(SourceReviewV2(schema_version="2.0", proposals=r.proposals))
        # Legitimate post-validation conversion: the controller has validated
        # the native V2.2 inventory before constructing temporary V2.1 values.
        legacy_audit = {
            "schema_version": "2.1",
            "concerns": [item.concern.model_dump(mode="json") for item in audit.concerns],
        }
        a = SourceAuditV21.validate_for_indexed_proposals(
            legacy_audit,
            indexed,
        )
        return r, a
    except Exception as error:
        raise CompilationError("INPUT_INVALID") from error


def _verified_source_aggregates_v22(
    envelope: CaseEnvelope,
    review: SourceReviewAggregateV22,
    audit: SourceAuditAggregateV22,
) -> tuple[CaseEnvelope, SourceReviewAggregateV22, SourceAuditAggregateV22]:
    context = _verified_source_request_context_v22(envelope)
    try:
        checked_review = _verify_source_review_aggregate_with_context_v22(
            context, review
        )
    except Exception:
        raise CompilationError("SOURCE_REVIEW_AGGREGATE_INVALID") from None
    try:
        checked_audit = _verify_source_audit_aggregate_with_context_v22(
            context, checked_review, audit
        )
    except Exception:
        raise CompilationError("SOURCE_AUDIT_AGGREGATE_INVALID") from None
    return context.envelope, checked_review, checked_audit


def _referee_disputes_from_verified_sources_v22(
    envelope: CaseEnvelope,
    review: SourceReviewAggregateV22,
    audit: SourceAuditAggregateV22,
) -> tuple[RefereeDisputeV22, ...]:
    r, a = _v21_inputs(review, audit)
    return canonical_referee_disputes_v22(
        envelope, tuple(item.material_dispute for item in _disputes_v21(envelope, r, a))
    )


def build_referee_disputes_v22(
    envelope: CaseEnvelope, review: SourceReviewAggregateV22, audit: SourceAuditAggregateV22
) -> tuple[RefereeDisputeV22, ...]:
    envelope, review, audit = _verified_source_aggregates_v22(
        envelope, review, audit
    )
    return _referee_disputes_from_verified_sources_v22(envelope, review, audit)


def validate_referee_fragment_v22(
    dispute: RefereeDisputeV22, decision: object, *, response_fingerprint: str
) -> AcceptedRefereeFragmentV22:
    try:
        checked = _strict_rehydrate_v22(
            RefereeDisputeV22, dispute, location="referee dispute"
        )
        if checked.dispute_fingerprint != referee_dispute_fingerprint_v22(checked):
            raise ValueError("referee dispute fingerprint is invalid")
        decision_raw = _wire_snapshot(decision)
        if not isinstance(decision_raw, dict):
            raise ValueError("referee decision is invalid")
        decision_raw.setdefault("schema_version", "2.2")
        checked_decision = RefereeDecisionV22.validate_for_evidence(
            decision_raw, checked.evidence
        )
        # Legitimate post-validation conversion: the native dispute is strict
        # before it is translated into the temporary V2.1 compiler shape.
        legacy_raw = checked.model_dump(mode="json")
        legacy_raw["dispute_fingerprint"] = "0" * 64
        legacy = RefereeDisputeV21.model_validate(legacy_raw)
        legacy_decision = checked_decision.model_dump(mode="json")
        legacy_decision["schema_version"] = "2.1"
        _fragment_v21(
            legacy,
            legacy_decision,
            response_fingerprint=response_fingerprint,
        )
        return AcceptedRefereeFragmentV22.validate_for_dispute(
            {
                "case_fingerprint": checked.case_fingerprint,
                "dispute_id": checked.dispute_id,
                "dispute_fingerprint": checked.dispute_fingerprint,
                "decision": checked_decision,
                "response_fingerprint": response_fingerprint,
            },
            checked,
        )
    except Exception as error:
        raise CompilationError("REFEREE_FRAGMENT_INVALID") from error


def aggregate_referee_decisions_v22(
    disputes: tuple[RefereeDisputeV22, ...], fragments: tuple[AcceptedRefereeFragmentV22, ...]
) -> RefereeAggregateV22:
    if not disputes and fragments:
        raise CompilationError("REFEREE_FRAGMENT_COVERAGE_INVALID")
    if not disputes:
        return RefereeAggregateV22(
            fragments=(),
            aggregate_fingerprint=_hash({"schema_version": "2.2", "disputes": [], "fragments": []}),
        )
    try:
        checked_disputes = tuple(
            _strict_rehydrate_v22(
                RefereeDisputeV22, item, location="referee dispute inventory"
            )
            for item in disputes
        )
        if any(
            item.dispute_fingerprint != referee_dispute_fingerprint_v22(item)
            for item in checked_disputes
        ):
            raise ValueError
    except Exception as error:
        raise CompilationError("REFEREE_DISPUTE_INVALID") from error
    try:
        checked = tuple(
            AcceptedRefereeFragmentV22.validate_for_dispute(item, dispute)
            for dispute, item in zip(checked_disputes, fragments, strict=True)
        )
        if tuple(item.dispute_id for item in checked_disputes) != tuple(
            item.dispute_id for item in checked
        ):
            raise ValueError
        payload = {
            "schema_version": "2.2",
            "disputes": [item.model_dump(mode="json") for item in checked_disputes],
            "fragments": [item.model_dump(mode="json") for item in checked],
        }
        # Legitimate post-validation conversion: exact checked fragments are
        # serialized only to construct the controller-owned aggregate output.
        aggregate_raw = {
            "fragments": [item.model_dump(mode="json") for item in checked],
            "aggregate_fingerprint": _hash(payload),
        }
        return RefereeAggregateV22.validate_for_disputes(
            aggregate_raw,
            checked_disputes,
        )
    except Exception as error:
        raise CompilationError("REFEREE_FRAGMENT_INVALID") from error


def compile_baseline_v22(
    envelope: CaseEnvelope,
    review: SourceReviewAggregateV22,
    audit: SourceAuditAggregateV22,
    aggregate: RefereeAggregateV22,
) -> CanonicalBaselineV22:
    envelope, review, audit = _verified_source_aggregates_v22(
        envelope, review, audit
    )
    r, a = _v21_inputs(review, audit)
    disputes = _referee_disputes_from_verified_sources_v22(envelope, review, audit)
    try:
        checked_aggregate = RefereeAggregateV22.validate_for_disputes(
            aggregate, disputes
        )
        expected = aggregate_referee_decisions_v22(disputes, checked_aggregate.fragments)
        if checked_aggregate.aggregate_fingerprint != expected.aggregate_fingerprint:
            raise ValueError("referee aggregate fingerprint is invalid")
        legacy_disputes = _disputes_v21(envelope, r, a)
        legacy_fragments = tuple(
            _fragment_v21(
                legacy,
                {**item.decision.model_dump(mode="json"), "schema_version": "2.1"},
                response_fingerprint=item.response_fingerprint,
            )
            for legacy, item in zip(legacy_disputes, checked_aggregate.fragments, strict=True)
        )
        legacy_aggregate = _aggregate_v21(legacy_disputes, legacy_fragments)
        legacy = _baseline_v21(envelope, r, a, legacy_aggregate)
        # Legitimate post-validation conversion: this explicit V2.1 value is
        # upgraded and then raw-wire rehydrated before it can leave the boundary.
        raw = legacy.model_dump(mode="json")
        raw["schema_version"] = "2.2"
        raw["contested_requirements"] = [
            item.model_dump(mode="json") for item in legacy.contested_requirements
        ]
        payload = {key: value for key, value in raw.items() if key != "baseline_fingerprint"}
        raw["baseline_fingerprint"] = _hash(payload)
        return verify_canonical_baseline_v22(raw)
    except Exception as error:
        raise CompilationError("REFEREE_FRAGMENT_INVALID") from error


def ordinary_grade_batches_v22(
    baseline: CanonicalBaselineV22, anonymous_label: Literal["A", "B"], grader_lane: Literal[1, 2]
) -> tuple[OrdinaryGradeBatchV22, ...]:
    anonymous_label, grader_lane = _strict_grade_coordinate_v22(
        anonymous_label, grader_lane
    )
    sealed = verify_canonical_baseline_v22(baseline)
    if len(sealed.requirements) > 640:
        raise RubricValidationError("ORDINARY_GRADE_ITEM_LIMIT_EXCEEDED")
    return tuple(
        OrdinaryGradeBatchV22(
            batch_ref=f"GB-{anonymous_label}-{grader_lane}-{index // 5 + 1:04d}",
            requirement_ids=tuple(
                item.requirement_id for item in sealed.requirements[index : index + 5]
            ),
        )
        for index in range(0, len(sealed.requirements), 5)
    )


def validate_grade_fragment_v22(
    baseline: CanonicalBaselineV22, fragment: object, report_text: str
) -> OrdinaryGradeFragmentV22 | ContestedGradeFragmentV22:
    """Strictly bind a v2.2 grade fragment to its exact batch and report passages."""
    try:
        sealed = verify_canonical_baseline_v22(baseline)
        if not isinstance(report_text, str):
            raise ValueError("report text is invalid")
        raw = _wire_snapshot(fragment)
        if not isinstance(raw, dict):
            raise ValueError("grade fragment is invalid")
        report_digest = hashlib.sha256(report_text.encode("utf-8"))
        fingerprint = report_digest.hexdigest()
        if "batch_ref" in raw:
            label, lane = _strict_grade_coordinate_v22(
                raw.get("anonymous_label"), raw.get("grader_lane")
            )
            result: OrdinaryGradeFragmentV22 | ContestedGradeFragmentV22 = (
                OrdinaryGradeFragmentV22.validate_for_batch(
                    raw,
                    ordinary_grade_batches_v22(sealed, label, lane)[
                        next(
                            index
                            for index, batch in enumerate(
                                ordinary_grade_batches_v22(sealed, label, lane)
                            )
                            if batch.batch_ref == raw["batch_ref"]
                        )
                    ],
                )
            )
            assert isinstance(result, OrdinaryGradeFragmentV22)
            passages = [
                passage for grade in result.requirement_grades for passage in grade.report_passages
            ]
        else:
            identifier = raw.get("contested_requirement_id")
            requirement = next(
                item
                for item in sealed.contested_requirements
                if item.contested_requirement_id == identifier
            )
            result = ContestedGradeFragmentV22.validate_for_requirement(raw, requirement)
            passages = [
                passage
                for alternative in (
                    result.reviewer_alternative_grade,
                    result.auditor_alternative_grade,
                )
                for passage in alternative.report_passages
            ]
        if (
            result.baseline_fingerprint != sealed.baseline_fingerprint
            or result.report_fingerprint != fingerprint
        ):
            raise ValueError("grade binding is invalid")
        if any(report_text.count(passage) != 1 for passage in passages):
            raise ValueError("grade report passage is invalid")
        return result
    except Exception as error:
        raise RubricValidationError("GRADE_FRAGMENT_INVALID") from error


def aggregate_grader_lane_v22(
    baseline: CanonicalBaselineV22,
    anonymous_label: Literal["A", "B"],
    grader_lane: Literal[1, 2],
    ordinary_fragments: tuple[OrdinaryGradeFragmentV22, ...],
    contested_fragments: tuple[ContestedGradeFragmentV22, ...],
) -> GraderAggregateV22:
    anonymous_label, grader_lane = _strict_grade_coordinate_v22(
        anonymous_label, grader_lane
    )
    baseline = verify_canonical_baseline_v22(baseline)
    batches = ordinary_grade_batches_v22(baseline, anonymous_label, grader_lane)
    if (batches and not ordinary_fragments) or (
        baseline.contested_requirements and not contested_fragments
    ):
        raise RubricValidationError("GRADE_FRAGMENT_COVERAGE_INVALID")
    if len(ordinary_fragments) != len(batches) or len(contested_fragments) != len(
        baseline.contested_requirements
    ):
        raise RubricValidationError("GRADE_FRAGMENT_COVERAGE_INVALID")
    try:
        checked_ordinary = tuple(
            OrdinaryGradeFragmentV22.validate_for_batch(item, batch)
            for item, batch in zip(ordinary_fragments, batches, strict=True)
        )
        checked_contested = tuple(
            ContestedGradeFragmentV22.validate_for_requirement(item, requirement)
            for item, requirement in zip(
                contested_fragments, baseline.contested_requirements, strict=True
            )
        )
    except Exception as error:
        raise RubricValidationError("GRADE_FRAGMENT_INVALID") from error
    reports = {item.report_fingerprint for item in checked_ordinary}
    reports.update(item.report_fingerprint for item in checked_contested)
    if len(reports) != 1:
        raise RubricValidationError("GRADE_FRAGMENT_COVERAGE_INVALID")
    payload = {
        "anonymous_label": anonymous_label,
        "grader_lane": grader_lane,
        "baseline_fingerprint": baseline.baseline_fingerprint,
        "report_fingerprint": next(iter(reports)),
        "ordinary_fragments": checked_ordinary,
        "contested_fragments": checked_contested,
    }
    return GraderAggregateV22.validate_for_inventories(
        {**payload, "aggregate_fingerprint": _hash(payload)},
        batches,
        baseline.contested_requirements,
    )


def _verified_grader_aggregate(
    baseline: CanonicalBaselineV22, aggregate: GraderAggregateV22
) -> GraderAggregateV22:
    baseline = verify_canonical_baseline_v22(baseline)
    raw = _wire_snapshot(aggregate)
    if not isinstance(raw, dict):
        raise RubricValidationError("GRADE_AGGREGATE_INVALID")
    try:
        anonymous_label, grader_lane = _strict_grade_coordinate_v22(
            raw.get("anonymous_label"), raw.get("grader_lane")
        )
    except ValueError as error:
        raise RubricValidationError("GRADE_AGGREGATE_INVALID") from error
    checked = GraderAggregateV22.validate_for_inventories(
        raw,
        ordinary_grade_batches_v22(baseline, anonymous_label, grader_lane),
        baseline.contested_requirements,
    )
    payload = {
        "anonymous_label": checked.anonymous_label,
        "grader_lane": checked.grader_lane,
        "baseline_fingerprint": checked.baseline_fingerprint,
        "report_fingerprint": checked.report_fingerprint,
        "ordinary_fragments": checked.ordinary_fragments,
        "contested_fragments": checked.contested_fragments,
    }
    if (
        checked.aggregate_fingerprint != _hash(payload)
        or checked.baseline_fingerprint != baseline.baseline_fingerprint
    ):
        raise RubricValidationError("GRADE_AGGREGATE_INVALID")
    return checked


def _strict_rubric(value: object) -> RubricV22:
    """Reconstruct the exact native rubric, including model_construct bypasses."""
    if not isinstance(value, RubricV22):
        raise RubricValidationError("RUBRIC_INVALID")
    try:
        return _strict_rehydrate_v22(RubricV22, value, location="rubric")
    except Exception as error:
        raise RubricValidationError("RUBRIC_INVALID") from error


def _score_v22(
    dispositions: list[tuple[ImportanceV2, str]], rubric: RubricV22
) -> tuple[AbsoluteDispositionV2, tuple[str, ...]]:
    if any(disposition == "uncertain" for _, disposition in dispositions):
        return AbsoluteDispositionV2.INCONCLUSIVE, ("GRADE_UNCERTAIN",)
    credit = {"met": 1.0, "partially_met": 0.5, "not_met": 0.0}
    total = sum(rubric.importance_weights[importance] for importance, _ in dispositions)
    credited = sum(
        rubric.importance_weights[importance] * credit[disposition]
        for importance, disposition in dispositions
    )
    critical = [
        credit[disposition]
        for importance, disposition in dispositions
        if importance is ImportanceV2.CRITICAL
    ]
    reasons: list[str] = []
    if (sum(critical) / len(critical) if critical else 1.0) < rubric.critical_recall_floor:
        reasons.append("CRITICAL_RECALL_BELOW_FLOOR")
    if total and credited / total < rubric.weighted_coverage_floor:
        reasons.append("WEIGHTED_COVERAGE_BELOW_FLOOR")
    return (AbsoluteDispositionV2.FAIL if reasons else AbsoluteDispositionV2.PASS, tuple(reasons))


def _ordinary_observations_v22(
    baseline: CanonicalBaselineV22, aggregate: GraderAggregateV22
) -> list[tuple[ImportanceV2, str]]:
    grades = {
        grade.requirement_id: grade
        for fragment in aggregate.ordinary_fragments
        for grade in fragment.requirement_grades
    }
    return [
        (item.importance, grades[item.requirement_id].disposition)
        for item in baseline.requirements
    ]


def _same_observations_v22(first: GraderAggregateV22, second: GraderAggregateV22) -> bool:
    def view(aggregate: GraderAggregateV22) -> tuple[object, ...]:
        return tuple(
            tuple(
                (grade.requirement_id, grade.disposition, grade.report_passages)
                for grade in fragment.requirement_grades
            )
            for fragment in aggregate.ordinary_fragments
        ) + tuple(
            (
                fragment.contested_requirement_id,
                fragment.reviewer_alternative_grade.disposition,
                fragment.auditor_alternative_grade.disposition,
                fragment.ambiguity_disposition,
            )
            for fragment in aggregate.contested_fragments
        )

    return view(first) == view(second)


def reconcile_grader_lanes_v22(
    baseline: CanonicalBaselineV22,
    first: GraderAggregateV22,
    second: GraderAggregateV22,
    rubric: RubricV22 = RUBRIC_V22,
) -> ReconciledGradeV22:
    try:
        baseline = verify_canonical_baseline_v22(baseline)
        rubric = _strict_rubric(rubric)
        first = _verified_grader_aggregate(baseline, first)
        second = _verified_grader_aggregate(baseline, second)
        if (
            first.anonymous_label != second.anonymous_label
            or (first.grader_lane, second.grader_lane) != (1, 2)
            or first.baseline_fingerprint != baseline.baseline_fingerprint
            or second.baseline_fingerprint != baseline.baseline_fingerprint
            or first.report_fingerprint != second.report_fingerprint
        ):
            raise ValueError("grader aggregates do not bind the same canonical context")
        disposition, reasons = _score_v22(_ordinary_observations_v22(baseline, first), rubric)
        if not _same_observations_v22(first, second):
            disposition, reasons = AbsoluteDispositionV2.INCONCLUSIVE, ("GRADER_DISAGREEMENT",)
        # Legitimate post-validation conversion: both aggregates are strict and
        # serialized only to build their controller-owned reconciliation.
        raw: dict[str, object] = {
            "anonymous_label": first.anonymous_label,
            "absolute_disposition": disposition,
            "reason_codes": reasons,
            "grader_aggregates": [first.model_dump(mode="json"), second.model_dump(mode="json")],
        }
        raw["reconciliation_fingerprint"] = _hash(raw)
        return ReconciledGradeV22.validate_for_baseline(raw, baseline)
    except Exception as error:
        raise RubricValidationError("RECONCILIATION_INVALID") from error


def evaluate_outcome_sensitivity_v22(
    baseline: CanonicalBaselineV22,
    reconciliation: ReconciledGradeV22,
    rubric: RubricV22 = RUBRIC_V22,
) -> SensitivityRecordV22:
    try:
        rubric = _strict_rubric(rubric)
        baseline = verify_canonical_baseline_v22(baseline)
        reconciliation = ReconciledGradeV22.validate_for_baseline(reconciliation, baseline)
        for aggregate in reconciliation.grader_aggregates:
            _verified_grader_aggregate(baseline, aggregate)
        expected = reconcile_grader_lanes_v22(
            baseline,
            reconciliation.grader_aggregates[0],
            reconciliation.grader_aggregates[1],
            rubric,
        )
        if reconciliation != expected:
            raise RubricValidationError("RECONCILIATION_INVALID")
        first = reconciliation.grader_aggregates[0]
        ordinary = _ordinary_observations_v22(baseline, first)
        contested = {
            item.contested_requirement_id: item for item in first.contested_fragments
        }
        reviewer_world = list(ordinary)
        auditor_world = list(ordinary)
        differing_alternatives: list[str] = []
        disposition: AbsoluteDispositionV2
        reasons: tuple[str, ...]
        for item in baseline.contested_requirements:
            grade = contested[item.contested_requirement_id]
            reviewer_observation = (
                None
                if item.reviewer_alternative is None
                else (
                    item.reviewer_alternative.importance,
                    grade.reviewer_alternative_grade.disposition,
                )
            )
            auditor_observation = (
                None
                if item.auditor_alternative is None
                else (
                    item.auditor_alternative.importance,
                    grade.auditor_alternative_grade.disposition,
                )
            )
            if reviewer_observation is not None:
                reviewer_world.append(reviewer_observation)
            if auditor_observation is not None:
                auditor_world.append(auditor_observation)
            if reviewer_observation != auditor_observation:
                differing_alternatives.append(item.contested_requirement_id)
        reviewer_disposition, reviewer_reasons = _score_v22(reviewer_world, rubric)
        auditor_disposition, auditor_reasons = _score_v22(auditor_world, rubric)
        changing: tuple[str, ...] = ()
        if reconciliation.absolute_disposition is AbsoluteDispositionV2.INCONCLUSIVE:
            disposition, reasons = reconciliation.absolute_disposition, reconciliation.reason_codes
        elif (
            reviewer_disposition is AbsoluteDispositionV2.INCONCLUSIVE
            or auditor_disposition is AbsoluteDispositionV2.INCONCLUSIVE
        ):
            disposition, reasons = (
                AbsoluteDispositionV2.INCONCLUSIVE,
                ("BASELINE_EVIDENCE_INSUFFICIENT",),
            )
        elif reviewer_disposition is not auditor_disposition:
            changing = tuple(differing_alternatives)
            disposition, reasons = (
                AbsoluteDispositionV2.INCONCLUSIVE,
                ("OUTCOME_SENSITIVE_BASELINE_DISPUTE",),
            )
        else:
            disposition = reviewer_disposition
            reasons = tuple(sorted(set((*reviewer_reasons, *auditor_reasons))))
        raw: dict[str, object] = {
            "anonymous_label": reconciliation.anonymous_label,
            "baseline_fingerprint": baseline.baseline_fingerprint,
            "reconciliation_fingerprint": reconciliation.reconciliation_fingerprint,
            "absolute_disposition": disposition,
            "reason_codes": reasons,
            "outcome_determinative_contested_ids": changing,
        }
        raw["sensitivity_fingerprint"] = _hash(raw)
        return SensitivityRecordV22.model_validate(raw)
    except Exception as error:
        raise RubricValidationError("RECONCILIATION_INVALID") from error


def _validate_source_fragment_semantics_v22(
    values: tuple[SemanticProposal | AuditConcernV22, ...],
    *,
    kind: Literal["source-review proposal", "source-audit concern"],
) -> None:
    """Reject duplicate or conflicting meaning across the complete fragment prefix."""
    seen: dict[object, bytes] = {}
    for value in values:
        identity = _semantic_identity(value)
        encoded = canonical_json_bytes(value.model_dump(mode="json"))
        if identity in seen:
            if seen[identity] != encoded:
                raise _SourceFragmentSemanticResponseErrorV22(
                    f"conflicting accepted {kind}"
                )
            raise _SourceFragmentSemanticResponseErrorV22(
                f"duplicate accepted {kind}"
            )
        seen[identity] = encoded


class _SourceFragmentSemanticResponseErrorV22(ValueError):
    """Controlled duplicate/conflict refusal caused by one external fragment."""
