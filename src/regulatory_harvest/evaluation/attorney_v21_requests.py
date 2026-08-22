# ruff: noqa: E501
"""Immutable request packets for evaluator protocol 2.1 source adjudication."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Literal, cast

from regulatory_harvest.storage import canonical_json_bytes, sha256_digest

from .attorney_admission import build_source_record
from .attorney_models import CaseEnvelope
from .attorney_v2_compiler import index_review, resolve_exact_passage
from .attorney_v2_models import IndexedProposalV2, SemanticPassage, SourceReviewV2
from .attorney_v21_compiler import _dispute_fingerprint
from .attorney_v21_models import (
    CanonicalBaselineV21,
    ContestedGradeFragmentV21,
    ContestedRequirementV21,
    EvaluatorOperationV21,
    EvaluatorRequestV21,
    OrdinaryGradeBatchV21,
    OrdinaryGradeFragmentV21,
    RefereeDecisionV21,
    RefereeDisputeV21,
    RefereeFragmentRequestPayloadV21,
    SourceAuditV21,
    SourceReviewV21,
)
from .attorney_v21_rubric import RUBRIC_V21, ordinary_grade_batches

_HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_SOURCE_RECORD_KEYS = frozenset(
    {
        "schema_version", "mode", "question", "jurisdiction", "as_of",
        "requested_authorities", "sources",
    }
)
_SOURCE_REVIEW_INSTRUCTIONS = (
    "Review the supplied frozen source record. Identify the legal requirements, "
    "exceptions, dependencies, ambiguities, and evidence that are material to the evaluation. "
    "Return only the required semantic proposals."
)
_SOURCE_AUDIT_INSTRUCTIONS = (
    "Audit the supplied semantic proposals against the frozen source record. Return only "
    "material concerns with source-grounded corrections where required."
)
_SOURCE_REFEREE_INSTRUCTIONS = (
    "Resolve the one supplied material dispute using only its controller-resolved evidence. "
    "Return the required source-grounded decision and rationale."
)
_ORDINARY_GRADE_INSTRUCTIONS = (
    "Grade only the supplied canonical requirement subset against the supplied report and source context. "
    "Resolve every report passage exactly and return only the bounded grade fragment."
)
_CONTESTED_GRADE_INSTRUCTIONS = (
    "Grade both supplied alternatives for exactly one contested requirement against the supplied report and "
    "source context. Return only the isolated contested grade fragment."
)
_INNER_PAYLOAD_INSTRUCTIONS = (
    " Return only the inner payload as one canonical JSON object conforming exactly to "
    "json_schema. Do not author the outer response envelope; the controller supplies "
    "operation, request_fingerprint, provider_name, model_name, judge_isolation, and the "
    "outer schema_version."
)


def _snapshot(value: object, *, location: str) -> dict[str, object]:
    try:
        result = json.loads(canonical_json_bytes(value))
    except (TypeError, ValueError, RecursionError) as error:
        raise ValueError(f"{location} cannot be represented as canonical JSON") from error
    if type(result) is not dict:
        raise ValueError(f"{location} must be an object")
    return cast(dict[str, object], result)


def _fingerprint(request: EvaluatorRequestV21) -> str:
    return hashlib.sha256(
        canonical_json_bytes(request.model_dump(mode="json", exclude={"request_fingerprint"}))
    ).hexdigest()


def _new_request(
    operation: EvaluatorOperationV21,
    *,
    system_instructions: str,
    json_schema: dict[str, object],
    payload: dict[str, object],
    safe_metadata: dict[str, str],
) -> EvaluatorRequestV21:
    provisional = EvaluatorRequestV21.model_validate(
        {
            "schema_version": "2.1",
            "operation": operation.value,
            "request_fingerprint": "0" * 64,
            "system_instructions": system_instructions + _INNER_PAYLOAD_INSTRUCTIONS,
            "json_schema": _snapshot(json_schema, location="response schema"),
            "payload": _snapshot(payload, location="request payload"),
            "safe_metadata": dict(safe_metadata),
        }
    )
    return EvaluatorRequestV21.model_validate(
        {**provisional.model_dump(mode="json"), "request_fingerprint": _fingerprint(provisional)}
    )


def _frozen_source_record(envelope: CaseEnvelope) -> tuple[dict[str, object], str]:
    validated = CaseEnvelope.model_validate(envelope.model_dump(mode="json"))
    record = _snapshot(build_source_record(validated.case), location="source record")
    return record, sha256_digest(canonical_json_bytes(record))


def _source_metadata(source_record_fingerprint: str) -> dict[str, str]:
    return {"record_scope": "source-only", "source_record_fingerprint": source_record_fingerprint}


def build_source_review_request_v21(envelope: CaseEnvelope) -> EvaluatorRequestV21:
    """Build a 2.1 source-review request with unchanged semantic fields."""
    record, record_fingerprint = _frozen_source_record(envelope)
    return _new_request(
        EvaluatorOperationV21.SOURCE_REVIEW,
        system_instructions=_SOURCE_REVIEW_INSTRUCTIONS,
        json_schema=SourceReviewV21.model_json_schema(),
        payload={"source_record": record},
        safe_metadata=_source_metadata(record_fingerprint),
    )


def _v2_review(review: SourceReviewV21) -> SourceReviewV2:
    checked = SourceReviewV21.model_validate(review.model_dump(mode="json", warnings="error"))
    return SourceReviewV2.model_validate(
        {"schema_version": "2.0", "proposals": checked.model_dump(mode="json")["proposals"]}
    )


def build_source_audit_request_v21(
    envelope: CaseEnvelope,
    review: SourceReviewV21 | tuple[IndexedProposalV2, ...],
) -> EvaluatorRequestV21:
    """Build a 2.1 source-audit request over controller-indexed review proposals."""
    record, record_fingerprint = _frozen_source_record(envelope)
    indexed = index_review(_v2_review(review)) if isinstance(review, SourceReviewV21) else review
    try:
        indexed = tuple(
            IndexedProposalV2.model_validate(item.model_dump(mode="json")) for item in indexed
        )
    except (AttributeError, TypeError, ValueError) as error:
        raise ValueError("indexed proposals are invalid") from error
    payload = [item.model_dump(mode="json") for item in indexed]
    return _new_request(
        EvaluatorOperationV21.SOURCE_AUDIT,
        system_instructions=_SOURCE_AUDIT_INSTRUCTIONS,
        json_schema=SourceAuditV21.model_json_schema(),
        payload={"source_record": record, "indexed_proposals": payload},
        safe_metadata=_source_metadata(record_fingerprint),
    )


def _checked_controller_disputes(
    envelope: CaseEnvelope,
    controller_disputes: tuple[RefereeDisputeV21, ...],
) -> tuple[RefereeDisputeV21, ...]:
    if not isinstance(controller_disputes, tuple) or not controller_disputes:
        raise ValueError("controller dispute inventory is invalid")
    if any(not isinstance(item, RefereeDisputeV21) for item in controller_disputes):
        raise ValueError("controller dispute inventory is invalid")
    try:
        disputes = tuple(
            RefereeDisputeV21.model_validate(item.model_dump(mode="json"))
            for item in controller_disputes
        )
    except (TypeError, ValueError) as error:
        raise ValueError("controller dispute inventory is invalid") from error
    if [item.dispute_id for item in disputes] != [
        f"D{index:04d}" for index in range(1, len(disputes) + 1)
    ]:
        raise ValueError("controller dispute inventory is invalid")
    source_texts = {source.source_id: source.normalized_text for source in envelope.case.sources}
    evidence_entries: list[tuple[str, int, int, str, str]] = []
    try:
        for dispute in disputes:
            if dispute.case_fingerprint != envelope.case_fingerprint:
                raise ValueError("dispute case fingerprint differs from the frozen envelope")
            passage_keys = [
                (
                    evidence.passage.source_id,
                    evidence.passage.start_char,
                    evidence.passage.end_char,
                    evidence.passage.quote,
                )
                for evidence in dispute.evidence
            ]
            if passage_keys != sorted(passage_keys) or len(passage_keys) != len(set(passage_keys)):
                raise ValueError("dispute evidence is not canonical")
            for evidence in dispute.evidence:
                resolved = resolve_exact_passage(
                    source_texts[evidence.passage.source_id],
                    SemanticPassage(
                        source_id=evidence.passage.source_id,
                        quote=evidence.passage.quote,
                    ),
                )
                if resolved != evidence.passage:
                    raise ValueError("dispute evidence differs from frozen source text")
                evidence_entries.append(
                    (
                        evidence.passage.source_id,
                        evidence.passage.start_char,
                        evidence.passage.end_char,
                        evidence.passage.quote,
                        dispute.dispute_id,
                    )
                )
            if dispute.dispute_fingerprint != _dispute_fingerprint(
                envelope.case_fingerprint, dispute.material_dispute, dispute.evidence
            ):
                raise ValueError("dispute fingerprint is not canonical")
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("controller dispute inventory is invalid") from error
    expected_refs = {
        (dispute_id, source_id, start, end, quote): f"EVID-{index:04d}"
        for index, (source_id, start, end, quote, dispute_id) in enumerate(
            sorted(evidence_entries), start=1
        )
    }
    actual_refs = [evidence.evidence_ref for dispute in disputes for evidence in dispute.evidence]
    if len(actual_refs) != len(set(actual_refs)):
        raise ValueError("controller dispute inventory is invalid")
    if any(
        evidence.evidence_ref
        != expected_refs[
            (
                dispute.dispute_id,
                evidence.passage.source_id,
                evidence.passage.start_char,
                evidence.passage.end_char,
                evidence.passage.quote,
            )
        ]
        for dispute in disputes
        for evidence in dispute.evidence
    ):
        raise ValueError("controller dispute inventory is invalid")
    return disputes


def build_source_referee_fragment_request(
    envelope: CaseEnvelope,
    dispute: RefereeDisputeV21,
    *,
    controller_disputes: tuple[RefereeDisputeV21, ...],
) -> EvaluatorRequestV21:
    """Build the evidence-complete, one-dispute source-referee request."""
    validated_envelope = CaseEnvelope.model_validate(envelope.model_dump(mode="json"))
    if not isinstance(dispute, RefereeDisputeV21):
        raise ValueError("referee dispute must be a strict controller model")
    checked_dispute = RefereeDisputeV21.model_validate(dispute.model_dump(mode="json"))
    if checked_dispute.case_fingerprint != validated_envelope.case_fingerprint:
        raise ValueError("referee dispute must bind the frozen case")
    source_texts = {
        source.source_id: source.normalized_text for source in validated_envelope.case.sources
    }
    try:
        for evidence in checked_dispute.evidence:
            resolved = resolve_exact_passage(
                source_texts[evidence.passage.source_id],
                SemanticPassage(
                    source_id=evidence.passage.source_id,
                    quote=evidence.passage.quote,
                ),
            )
            if resolved != evidence.passage:
                raise ValueError("resolved evidence differs from the supplied passage")
        expected_dispute_fingerprint = _dispute_fingerprint(
            validated_envelope.case_fingerprint,
            checked_dispute.material_dispute,
            checked_dispute.evidence,
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("referee dispute must match frozen evidence") from error
    if checked_dispute.dispute_fingerprint != expected_dispute_fingerprint:
        raise ValueError("referee dispute must match frozen evidence")
    checked_inventory = _checked_controller_disputes(validated_envelope, controller_disputes)
    matches = [item for item in checked_inventory if item.dispute_id == checked_dispute.dispute_id]
    if len(matches) != 1 or checked_dispute != matches[0]:
        raise ValueError("selected referee dispute must match controller inventory")
    return _new_request(
        EvaluatorOperationV21.SOURCE_REFEREE_FRAGMENT,
        system_instructions=_SOURCE_REFEREE_INSTRUCTIONS,
        json_schema=RefereeDecisionV21.model_json_schema(),
        payload={"material_disputes": [checked_dispute.model_dump(mode="json")]},
        safe_metadata={
            "record_scope": "one-source-referee-dispute",
            "case_fingerprint": validated_envelope.case_fingerprint,
            "dispute_id": checked_dispute.dispute_id,
            "dispute_fingerprint": checked_dispute.dispute_fingerprint,
        },
    )


def _grade_payload_context(
    report_text: str, source_context: dict[str, object], rubric: object
) -> dict[str, object]:
    if not isinstance(report_text, str) or not report_text.strip():
        raise ValueError("report text is invalid")
    report_fingerprint = hashlib.sha256(report_text.encode("utf-8")).hexdigest()
    return {
        "report_text": report_text,
        "report_fingerprint": report_fingerprint,
        "source_context": _snapshot(source_context, location="source context"),
        "rubric": _snapshot(rubric, location="rubric"),
    }


def build_ordinary_grade_request_v21(
    baseline: CanonicalBaselineV21,
    batch: OrdinaryGradeBatchV21,
    anonymous_label: str,
    grader_lane: int,
    report_text: str,
    source_context: dict[str, object],
    rubric: object = RUBRIC_V21,
) -> EvaluatorRequestV21:
    """Build one sealed ordinary-grade request of at most five requirements."""
    if anonymous_label not in {"A", "B"} or grader_lane not in {1, 2}:
        raise ValueError("grade lane is invalid")
    sealed = CanonicalBaselineV21.model_validate(baseline.model_dump(mode="json", warnings="error"))
    batches = ordinary_grade_batches(
        sealed, cast(Literal["A", "B"], anonymous_label), cast(Literal[1, 2], grader_lane)
    )
    checked_batch = OrdinaryGradeBatchV21.model_validate(batch.model_dump(mode="json", warnings="error"))
    if sum(item == checked_batch for item in batches) != 1:
        raise ValueError("ordinary grade batch is absent from the controller inventory")
    requirements = {item.requirement_id: item for item in sealed.requirements}
    return _new_request(
        EvaluatorOperationV21.ORDINARY_GRADE_FRAGMENT,
        system_instructions=_ORDINARY_GRADE_INSTRUCTIONS,
        json_schema=OrdinaryGradeFragmentV21.model_json_schema(),
        payload={
            "anonymous_label": anonymous_label, "grader_lane": grader_lane,
            "batch_ref": checked_batch.batch_ref, "baseline_fingerprint": sealed.baseline_fingerprint,
            "requirements": [requirements[item].model_dump(mode="json") for item in checked_batch.requirement_ids],
            **_grade_payload_context(report_text, source_context, rubric),
        },
        safe_metadata={"record_scope": "one-ordinary-grade-batch", "baseline_fingerprint": sealed.baseline_fingerprint, "batch_ref": checked_batch.batch_ref},
    )


def build_contested_grade_request_v21(
    baseline: CanonicalBaselineV21,
    contested_requirement: ContestedRequirementV21,
    anonymous_label: str,
    grader_lane: int,
    report_text: str,
    source_context: dict[str, object],
    rubric: object = RUBRIC_V21,
) -> EvaluatorRequestV21:
    """Build one sealed contested-grade request with both alternatives retained."""
    if anonymous_label not in {"A", "B"} or grader_lane not in {1, 2}:
        raise ValueError("grade lane is invalid")
    sealed = CanonicalBaselineV21.model_validate(baseline.model_dump(mode="json", warnings="error"))
    checked = ContestedRequirementV21.model_validate(contested_requirement.model_dump(mode="json", warnings="error"))
    if sum(item == checked for item in sealed.contested_requirements) != 1:
        raise ValueError("contested requirement is absent from the controller inventory")
    return _new_request(
        EvaluatorOperationV21.CONTESTED_GRADE_FRAGMENT,
        system_instructions=_CONTESTED_GRADE_INSTRUCTIONS,
        json_schema=ContestedGradeFragmentV21.model_json_schema(),
        payload={
            "anonymous_label": anonymous_label, "grader_lane": grader_lane,
            "baseline_fingerprint": sealed.baseline_fingerprint,
            "contested_requirement": checked.model_dump(mode="json"),
            **_grade_payload_context(report_text, source_context, rubric),
        },
        safe_metadata={"record_scope": "one-contested-grade-requirement", "baseline_fingerprint": sealed.baseline_fingerprint, "contested_requirement_id": checked.contested_requirement_id},
    )


def _retry_failure() -> ValueError:
    return ValueError("mechanical retry request is invalid")


def _retry_source_record(payload: dict[str, object]) -> str:
    record = payload.get("source_record")
    if not isinstance(record, dict) or set(record) != _SOURCE_RECORD_KEYS:
        raise _retry_failure()
    try:
        return sha256_digest(canonical_json_bytes(record))
    except (TypeError, ValueError, RecursionError) as error:
        raise _retry_failure() from error


def _validate_retry_contract(request: EvaluatorRequestV21) -> None:
    if request.operation is EvaluatorOperationV21.SOURCE_REVIEW:
        if set(request.payload) != {"source_record"}:
            raise _retry_failure()
        record_fingerprint = _retry_source_record(request.payload)
        expected_schema = SourceReviewV21.model_json_schema()
        expected_instructions = _SOURCE_REVIEW_INSTRUCTIONS + _INNER_PAYLOAD_INSTRUCTIONS
        if (
            request.json_schema != expected_schema
            or request.system_instructions != expected_instructions
        ):
            raise _retry_failure()
        if request.safe_metadata != _source_metadata(record_fingerprint):
            raise _retry_failure()
    elif request.operation is EvaluatorOperationV21.SOURCE_AUDIT:
        if set(request.payload) != {"source_record", "indexed_proposals"}:
            raise _retry_failure()
        record_fingerprint = _retry_source_record(request.payload)
        indexed = request.payload["indexed_proposals"]
        if not isinstance(indexed, list):
            raise _retry_failure()
        try:
            for proposal in indexed:
                IndexedProposalV2.model_validate(proposal)
        except (TypeError, ValueError) as error:
            raise _retry_failure() from error
        if (
            request.json_schema != SourceAuditV21.model_json_schema()
            or request.system_instructions
            != _SOURCE_AUDIT_INSTRUCTIONS + _INNER_PAYLOAD_INSTRUCTIONS
            or request.safe_metadata != _source_metadata(record_fingerprint)
        ):
            raise _retry_failure()
    elif request.operation is EvaluatorOperationV21.SOURCE_REFEREE_FRAGMENT:
        if set(request.payload) != {"material_disputes"}:
            raise _retry_failure()
        try:
            packet = RefereeFragmentRequestPayloadV21.model_validate(request.payload)
        except (TypeError, ValueError) as error:
            raise _retry_failure() from error
        dispute = packet.material_disputes[0]
        expected_metadata = {
            "record_scope": "one-source-referee-dispute",
            "case_fingerprint": request.safe_metadata.get("case_fingerprint", ""),
            "dispute_id": dispute.dispute_id,
            "dispute_fingerprint": dispute.dispute_fingerprint,
        }
        if (
            _HASH_PATTERN.fullmatch(expected_metadata["case_fingerprint"]) is None
            or request.safe_metadata != expected_metadata
            or request.json_schema != RefereeDecisionV21.model_json_schema()
            or request.system_instructions
            != _SOURCE_REFEREE_INSTRUCTIONS + _INNER_PAYLOAD_INSTRUCTIONS
        ):
            raise _retry_failure()
    else:
        raise _retry_failure()


def mechanical_retry_request_v21(
    request: object, *, expected_request_fingerprint: str
) -> EvaluatorRequestV21:
    """Reconstruct one approved packet without feeding back rejected response content.

    The manifest alone advances attempt identity; this function preserves the exact
    payload and schema for that controller-issued retry binding.
    """
    try:
        if type(expected_request_fingerprint) is not str or _HASH_PATTERN.fullmatch(
            expected_request_fingerprint
        ) is None:
            raise _retry_failure()
        raw = (
            request.model_dump(mode="json")
            if isinstance(request, EvaluatorRequestV21)
            else request
        )
        if type(raw) is not dict:
            raise _retry_failure()
        snapshot = EvaluatorRequestV21.model_validate(raw)
        canonical_fingerprint = _fingerprint(snapshot)
        if (
            snapshot.request_fingerprint != canonical_fingerprint
            or expected_request_fingerprint != canonical_fingerprint
        ):
            raise _retry_failure()
        _validate_retry_contract(snapshot)
        return EvaluatorRequestV21.model_validate(snapshot.model_dump(mode="json"))
    except (RecursionError, TypeError, ValueError) as error:
        if isinstance(error, ValueError) and str(error) == "mechanical retry request is invalid":
            raise
        raise _retry_failure() from error
