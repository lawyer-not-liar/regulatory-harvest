"""Narrow, immutable request packets for semantic evaluator protocol 2.0."""

from __future__ import annotations

import json
import re
from typing import Literal, cast

from regulatory_harvest.storage import canonical_json_bytes, sha256_digest

from .attorney_admission import build_source_record
from .attorney_models import CandidateReport, CaseEnvelope
from .attorney_v2_models import (
    CanonicalBaselineV2,
    EvaluatorOperationV2,
    EvaluatorRequestV2,
    GradeResponseV2,
    IndexedProposalV2,
    MaterialDisputeV2,
    RubricV2,
    SourceAuditV2,
    SourceRefereeResponseV2,
    SourceReviewV2,
    evaluator_request_fingerprint,
)

_SOURCE_RECORD_KEYS = frozenset(
    {
        "schema_version",
        "mode",
        "question",
        "jurisdiction",
        "as_of",
        "requested_authorities",
        "sources",
    }
)
_HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_SOURCE_REVIEW_INSTRUCTIONS = (
    "Review the supplied frozen source record. Identify the legal requirements, "
    "exceptions, dependencies, ambiguities, and evidence that are material to the "
    "evaluation. Return only the required semantic proposals."
)
_SOURCE_AUDIT_INSTRUCTIONS = (
    "Audit the supplied semantic proposals against the frozen source record. "
    "Return only material concerns with source-grounded corrections where required."
)
_SOURCE_REFEREE_INSTRUCTIONS = (
    "Resolve each supplied material dispute using the frozen source record. "
    "Return the required source-grounded decisions and rationales."
)
_GRADE_INSTRUCTIONS = (
    "Assess exactly one anonymous report against the supplied sealed baseline and "
    "rubric. Evaluate every supplied requirement and identify any material unsupported "
    "assertion or baseline defect. Return only the required grading judgment."
)
_INNER_PAYLOAD_INSTRUCTIONS = (
    " Return only the inner payload as one canonical JSON object conforming exactly "
    "to json_schema. Do not author the outer response envelope; the controller supplies "
    "operation, request_fingerprint, provider_name, model_name, judge_isolation, and the "
    "outer schema_version."
)


def _role_instructions(instructions: str) -> str:
    return instructions + _INNER_PAYLOAD_INSTRUCTIONS


def _json_snapshot(value: object, *, location: str) -> dict[str, object]:
    """Copy a typed payload into ordinary canonical JSON without retaining caller data."""
    try:
        snapshot = json.loads(canonical_json_bytes(value))
    except (TypeError, ValueError) as error:
        raise ValueError(f"{location} cannot be represented as canonical JSON") from error
    if type(snapshot) is not dict:
        raise ValueError(f"{location} must be an object")
    return cast(dict[str, object], snapshot)


def _frozen_source_record(envelope: CaseEnvelope) -> tuple[dict[str, object], str]:
    validated = CaseEnvelope.model_validate(envelope.model_dump(mode="json"))
    source_record = _json_snapshot(build_source_record(validated.case), location="source record")
    return source_record, sha256_digest(canonical_json_bytes(source_record))


def _new_request(
    operation: EvaluatorOperationV2,
    *,
    system_instructions: str,
    json_schema: dict[str, object],
    payload: dict[str, object],
    safe_metadata: dict[str, str],
) -> EvaluatorRequestV2:
    provisional = EvaluatorRequestV2.model_validate(
        {
            "schema_version": "2.0",
            "operation": operation.value,
            "request_fingerprint": "0" * 64,
            "system_instructions": _role_instructions(system_instructions),
            "json_schema": _json_snapshot(json_schema, location="response schema"),
            "payload": _json_snapshot(payload, location="request payload"),
            "safe_metadata": dict(safe_metadata),
        }
    )
    return EvaluatorRequestV2.model_validate(
        {
            **provisional.model_dump(mode="json"),
            "request_fingerprint": evaluator_request_fingerprint(provisional),
        }
    )


def _source_metadata(source_record_fingerprint: str) -> dict[str, str]:
    return {
        "record_scope": "source-only",
        "source_record_fingerprint": source_record_fingerprint,
    }


def build_source_review_request(envelope: CaseEnvelope) -> EvaluatorRequestV2:
    """Build the source-only semantic-review request from a frozen case envelope."""
    source_record, source_record_fingerprint = _frozen_source_record(envelope)
    return _new_request(
        EvaluatorOperationV2.SOURCE_REVIEW,
        system_instructions=_SOURCE_REVIEW_INSTRUCTIONS,
        json_schema=SourceReviewV2.model_json_schema(),
        payload={"source_record": source_record},
        safe_metadata=_source_metadata(source_record_fingerprint),
    )


def build_source_audit_request(
    envelope: CaseEnvelope,
    indexed: tuple[IndexedProposalV2, ...],
) -> EvaluatorRequestV2:
    """Build one source-only material audit over engine-indexed review proposals."""
    source_record, source_record_fingerprint = _frozen_source_record(envelope)
    indexed_payload = [
        IndexedProposalV2.model_validate(item.model_dump(mode="json")).model_dump(mode="json")
        for item in indexed
    ]
    return _new_request(
        EvaluatorOperationV2.SOURCE_AUDIT,
        system_instructions=_SOURCE_AUDIT_INSTRUCTIONS,
        json_schema=SourceAuditV2.model_json_schema(),
        payload={"source_record": source_record, "indexed_proposals": indexed_payload},
        safe_metadata=_source_metadata(source_record_fingerprint),
    )


def build_source_referee_request(
    envelope: CaseEnvelope,
    disputes: tuple[MaterialDisputeV2, ...],
) -> EvaluatorRequestV2:
    """Build one bounded source-only referee request containing every material dispute."""
    source_record, source_record_fingerprint = _frozen_source_record(envelope)
    dispute_payload = [
        MaterialDisputeV2.model_validate(item.model_dump(mode="json")).model_dump(mode="json")
        for item in disputes
    ]
    return _new_request(
        EvaluatorOperationV2.SOURCE_REFEREE,
        system_instructions=_SOURCE_REFEREE_INSTRUCTIONS,
        json_schema=SourceRefereeResponseV2.model_json_schema(),
        payload={"source_record": source_record, "material_disputes": dispute_payload},
        safe_metadata=_source_metadata(source_record_fingerprint),
    )


def _report_for_label(envelope: CaseEnvelope, label: Literal["A", "B"]) -> CandidateReport:
    candidate_id = next(
        (
            assignment.candidate_id
            for assignment in envelope.assignments
            if assignment.anonymous_label == label
        ),
        None,
    )
    if candidate_id is None:
        raise ValueError("anonymous report label is not assigned in the frozen envelope")
    report = next(
        (
            candidate
            for candidate in envelope.case.candidates
            if candidate.candidate_id == candidate_id
        ),
        None,
    )
    if report is None:
        raise ValueError("anonymous report assignment does not resolve to a frozen report")
    return report


def build_grade_request(
    envelope: CaseEnvelope,
    baseline: CanonicalBaselineV2,
    label: Literal["A", "B"],
    rubric: RubricV2,
) -> EvaluatorRequestV2:
    """Build one blind grading request against the complete sealed baseline."""
    validated_envelope = CaseEnvelope.model_validate(envelope.model_dump(mode="json"))
    validated_baseline = CanonicalBaselineV2.model_validate(baseline.model_dump(mode="json"))
    validated_rubric = RubricV2.model_validate(rubric.model_dump(mode="json"))
    if validated_baseline.case_fingerprint != validated_envelope.case_fingerprint:
        raise ValueError("baseline must bind the frozen case")
    report = _report_for_label(validated_envelope, label)
    baseline_payload = validated_baseline.model_dump(mode="json")
    rubric_payload = validated_rubric.model_dump(mode="json")
    report_payload = {
        "anonymous_label": label,
        "report_hash": report.report_hash,
        "report_text": report.report_text,
    }
    _validate_anonymous_report(report_payload)
    payload = {
        "anonymous_report": report_payload,
        **baseline_payload,
        "rubric": rubric_payload,
    }
    return _new_request(
        EvaluatorOperationV2.GRADE_REPORT,
        system_instructions=_GRADE_INSTRUCTIONS,
        json_schema=GradeResponseV2.model_json_schema(),
        payload=payload,
        safe_metadata={
            "record_scope": "one-anonymous-report",
            "anonymous_label": label,
            "baseline_fingerprint": validated_baseline.baseline_fingerprint,
            "rubric_fingerprint": sha256_digest(canonical_json_bytes(rubric_payload)),
        },
    )


def _retry_failure() -> ValueError:
    return ValueError("mechanical retry request is invalid")


def _validate_anonymous_report(value: object) -> dict[str, object]:
    if (
        not isinstance(value, dict)
        or set(value) != {"anonymous_label", "report_hash", "report_text"}
        or value["anonymous_label"] not in {"A", "B"}
        or type(value["report_hash"]) is not str
        or type(value["report_text"]) is not str
    ):
        raise _retry_failure()
    report_hash = value["report_hash"]
    report_text = value["report_text"]
    if (
        _HASH_PATTERN.fullmatch(report_hash) is None
        or not report_text.replace("\ufeff", "").strip()
        or report_hash != sha256_digest(report_text.encode("utf-8"))
    ):
        raise _retry_failure()
    return value


def _retry_source_record(payload: dict[str, object]) -> tuple[dict[str, object], str]:
    source_record = payload.get("source_record")
    if not isinstance(source_record, dict) or set(source_record) != _SOURCE_RECORD_KEYS:
        raise _retry_failure()
    try:
        return source_record, sha256_digest(canonical_json_bytes(source_record))
    except (TypeError, ValueError, RecursionError) as error:
        raise _retry_failure() from error


def _validate_source_retry(
    request: EvaluatorRequestV2,
    *,
    payload_keys: frozenset[str],
    instructions: str,
    response_schema: dict[str, object],
) -> None:
    if (
        set(request.payload) != payload_keys
        or request.system_instructions != instructions
        or request.json_schema != response_schema
    ):
        raise _retry_failure()
    _, source_record_fingerprint = _retry_source_record(request.payload)
    if request.safe_metadata != _source_metadata(source_record_fingerprint):
        raise _retry_failure()


def _validate_grade_retry(request: EvaluatorRequestV2) -> None:
    baseline_fields = set(CanonicalBaselineV2.model_fields)
    expected_keys = baseline_fields | {"anonymous_report", "rubric"}
    if (
        set(request.payload) != expected_keys
        or request.system_instructions != _role_instructions(_GRADE_INSTRUCTIONS)
        or request.json_schema != GradeResponseV2.model_json_schema()
    ):
        raise _retry_failure()
    try:
        baseline = CanonicalBaselineV2.model_validate(
            {field: request.payload[field] for field in baseline_fields}
        )
        rubric = RubricV2.model_validate(request.payload["rubric"])
        report = _validate_anonymous_report(request.payload["anonymous_report"])
    except (KeyError, TypeError, ValueError) as error:
        raise _retry_failure() from error
    expected_metadata = {
        "record_scope": "one-anonymous-report",
        "anonymous_label": cast(str, report["anonymous_label"]),
        "baseline_fingerprint": baseline.baseline_fingerprint,
        "rubric_fingerprint": sha256_digest(canonical_json_bytes(rubric.model_dump(mode="json"))),
    }
    if request.safe_metadata != expected_metadata:
        raise _retry_failure()


def _validate_retry_contract(request: EvaluatorRequestV2) -> None:
    if request.operation is EvaluatorOperationV2.SOURCE_REVIEW:
        _validate_source_retry(
            request,
            payload_keys=frozenset({"source_record"}),
            instructions=_role_instructions(_SOURCE_REVIEW_INSTRUCTIONS),
            response_schema=SourceReviewV2.model_json_schema(),
        )
    elif request.operation is EvaluatorOperationV2.SOURCE_AUDIT:
        _validate_source_retry(
            request,
            payload_keys=frozenset({"source_record", "indexed_proposals"}),
            instructions=_role_instructions(_SOURCE_AUDIT_INSTRUCTIONS),
            response_schema=SourceAuditV2.model_json_schema(),
        )
        indexed = request.payload["indexed_proposals"]
        if not isinstance(indexed, list):
            raise _retry_failure()
        try:
            for item in indexed:
                IndexedProposalV2.model_validate(item)
        except (TypeError, ValueError) as error:
            raise _retry_failure() from error
    elif request.operation is EvaluatorOperationV2.SOURCE_REFEREE:
        _validate_source_retry(
            request,
            payload_keys=frozenset({"source_record", "material_disputes"}),
            instructions=_role_instructions(_SOURCE_REFEREE_INSTRUCTIONS),
            response_schema=SourceRefereeResponseV2.model_json_schema(),
        )
        disputes = request.payload["material_disputes"]
        if not isinstance(disputes, list):
            raise _retry_failure()
        try:
            for item in disputes:
                MaterialDisputeV2.model_validate(item)
        except (TypeError, ValueError) as error:
            raise _retry_failure() from error
    elif request.operation is EvaluatorOperationV2.GRADE_REPORT:
        _validate_grade_retry(request)
    else:  # pragma: no cover - closed enum guarded by request revalidation
        raise _retry_failure()


def mechanical_retry_request(
    request: object,
    *,
    expected_request_fingerprint: str,
) -> EvaluatorRequestV2:
    """Revalidate one approved packet without adding mechanical failure feedback."""
    try:
        if (
            type(expected_request_fingerprint) is not str
            or _HASH_PATTERN.fullmatch(expected_request_fingerprint) is None
        ):
            raise _retry_failure()
        raw = (
            request.model_dump(mode="json")
            if isinstance(request, EvaluatorRequestV2)
            else request
        )
        if type(raw) is not dict:
            raise _retry_failure()
        snapshot = EvaluatorRequestV2.model_validate(raw)
        canonical_fingerprint = evaluator_request_fingerprint(snapshot)
        if (
            snapshot.request_fingerprint != canonical_fingerprint
            or expected_request_fingerprint != canonical_fingerprint
        ):
            raise _retry_failure()
        _validate_retry_contract(snapshot)
        return EvaluatorRequestV2.model_validate(snapshot.model_dump(mode="json"))
    except (RecursionError, TypeError, ValueError) as error:
        if isinstance(error, ValueError) and str(error) == "mechanical retry request is invalid":
            raise
        raise _retry_failure() from error
