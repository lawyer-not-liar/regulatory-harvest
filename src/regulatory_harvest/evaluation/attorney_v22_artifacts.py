"""Atomic storage and complete replay verification for evaluator protocol 2.2."""

from __future__ import annotations

import json
import math
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Literal, cast

from pydantic import BaseModel, ValidationError

from regulatory_harvest.storage import canonical_json_bytes, sha256_digest

from .attorney_artifacts import (
    EvaluationIntegrityError,
    EvaluationVerification,
    RunStorage,
    _AtomicWriteOwnershipError,
    _NodeIdentity,
    _same_filesystem_object,
    open_evaluation_storage,
)
from .attorney_models import ArtifactRecord, CaseEnvelope
from .attorney_v2_compiler import CompilationError
from .attorney_v2_models import AbsoluteDispositionV2
from .attorney_v21_rubric import RubricValidationError
from .attorney_v22_compiler import (
    aggregate_grader_lane_v22,
    aggregate_referee_decisions_v22,
    aggregate_source_audit_fragments_v22,
    aggregate_source_review_fragments_v22,
    build_referee_disputes_v22,
    compile_baseline_v22,
    evaluate_outcome_sensitivity_v22,
    ordinary_grade_batches_v22,
    reconcile_grader_lanes_v22,
    validate_grade_fragment_v22,
    validate_referee_fragment_v22,
)
from .attorney_v22_models import (
    AcceptedRefereeFragmentV22,
    AcceptedSourceAuditFragmentV22,
    AcceptedSourceReviewFragmentV22,
    CanonicalBaselineV22,
    ComparisonResultV22,
    ContestedGradeFragmentV22,
    ContestedRequirementV22,
    EvaluationCallRecordV22,
    EvaluationManifestV22,
    EvaluationPhaseV22,
    EvaluationResultV22,
    EvaluationTerminalStatusV22,
    EvaluatorOperationV22,
    EvaluatorRequestV22,
    EvaluatorResponseV22,
    GraderAggregateV22,
    IndexedProposalV22,
    OrdinaryGradeBatchV22,
    OrdinaryGradeFragmentV22,
    ReconciledGradeV22,
    RefereeDisputeV22,
    ReportResultV22,
    RubricV22,
    SensitivityRecordV22,
    SourceAuditAggregateV22,
    SourceAuditFragmentV22,
    SourceReviewAggregateV22,
    SourceReviewFragmentV22,
    _strict_rehydrate_v22,
    build_comparison_result_v22,
    validate_evaluator_request_v22,
    validate_evaluator_response_v22,
)
from .attorney_v22_requests import (
    COMPILER_CONTRACT_FINGERPRINT_V22,
    build_contested_grade_request_v22,
    build_ordinary_grade_request_v22,
    build_source_audit_fragment_request_v22,
    build_source_referee_fragment_request_v22,
    build_source_review_fragment_request_v22,
)

V22_MANIFEST_PATH = "run-manifest.json"
V22_CASE_PATH = "inputs/case.json"
V22_BUILD_PATH = "inputs/build.json"
V22_RUBRIC_PATH = "rubric.json"
V22_BASELINE_PATH = "baseline.json"
V22_REFEREE_AGGREGATE_PATH = "aggregates/referee.json"
V22_RESULT_PATH = "result.json"
_MAX_JSON_BYTES = 16 * 1024 * 1024
_MAX_JSON_DEPTH = 64


@dataclass(frozen=True)
class V22ResponsePreflight:
    """A write-free response admission result with public-safe diagnostics."""

    valid: bool
    diagnostics: tuple[str, ...] = ()


@dataclass(frozen=True)
class VerifiedV22Context:
    """One immutable protocol-2.2 context derived from a single verified replay."""

    manifest: EvaluationManifestV22
    result: EvaluationResultV22 | None
    case_envelope_bytes: bytes
    rubric: RubricV22
    baseline: CanonicalBaselineV22 | None
    source_context: Mapping[str, str]

    def load_case_envelope(self) -> CaseEnvelope:
        """Return a fresh typed copy without rereading the run or caller input."""
        return CaseEnvelope.model_validate_json(self.case_envelope_bytes)


@dataclass(frozen=True)
class _Step:
    operation: EvaluatorOperationV22
    fragment_ordinal: int | None = None
    anonymous_label: Literal["A", "B"] | None = None
    grader_lane: Literal[1, 2] | None = None
    dispute_id: str | None = None
    batch_ref: str | None = None
    contested_requirement_id: str | None = None


@dataclass(frozen=True)
class _Replay:
    manifest: EvaluationManifestV22
    result: EvaluationResultV22 | None
    envelope: CaseEnvelope
    case_envelope_bytes: bytes
    rubric: RubricV22
    baseline: CanonicalBaselineV22 | None
    requests: dict[str, EvaluatorRequestV22]
    responses: dict[str, EvaluatorResponseV22]


def _error(code: str) -> EvaluationIntegrityError:
    return EvaluationIntegrityError(f"EVALUATOR_V22_{code}")


def _ordinary_json(value: object, *, location: str) -> None:
    pending: list[tuple[object, int]] = [(value, 1)]
    while pending:
        current, depth = pending.pop()
        if depth > _MAX_JSON_DEPTH:
            raise _error(f"JSON_DEPTH:{location}")
        if current is None or type(current) in {str, bool, int}:
            continue
        if type(current) is float:
            if not math.isfinite(current):
                raise _error(f"JSON_NONFINITE:{location}")
            continue
        if type(current) is dict:
            mapping = cast(dict[object, object], current)
            if any(type(key) is not str for key in mapping):
                raise _error(f"JSON_KEY:{location}")
            pending.extend((item, depth + 1) for item in mapping.values())
            continue
        if type(current) is list:
            pending.extend((item, depth + 1) for item in cast(list[object], current))
            continue
        raise _error(f"JSON_TYPE:{location}")


def _parse_canonical_json(data: bytes, *, location: str) -> object:
    if type(data) is not bytes or len(data) > _MAX_JSON_BYTES:
        raise _error(f"JSON_SIZE:{location}")
    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=lambda pairs: _unique_json_object(pairs, location=location),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as error:
        raise _error(f"JSON_MALFORMED:{location}") from error
    _ordinary_json(value, location=location)
    try:
        canonical = canonical_json_bytes(value)
    except (TypeError, ValueError, RecursionError) as error:
        raise _error(f"JSON_MALFORMED:{location}") from error
    if canonical != data:
        raise _error(f"JSON_NONCANONICAL:{location}")
    return value


def _unique_json_object(
    pairs: list[tuple[str, object]], *, location: str
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key in {location}")
        result[key] = value
    return result


def _canonical_model(
    value: BaseModel,
    model_type: type[BaseModel],
    *,
    location: str,
    context: Mapping[str, object] | None = None,
) -> BaseModel:
    try:
        snapshot = _strict_rehydrate_v22(
            model_type,
            value,
            context=None if context is None else dict(context),
            location=location,
        )
        encoded = canonical_json_bytes(snapshot.model_dump(mode="json", warnings="error"))
    except (
        AttributeError,
        TypeError,
        ValidationError,
        ValueError,
        RecursionError,
    ) as error:
        raise _error(f"MODEL_INVALID:{location}") from error
    _parse_canonical_json(encoded, location=location)
    return snapshot


def _model_from_file(
    data: bytes,
    model_type: type[BaseModel],
    *,
    location: str,
    context: Mapping[str, object] | None = None,
) -> BaseModel:
    payload = _parse_canonical_json(data, location=location)
    try:
        return _strict_rehydrate_v22(
            model_type,
            payload,
            context=None if context is None else dict(context),
            location=location,
        )
    except (TypeError, ValidationError, ValueError, RecursionError) as error:
        raise _error(f"MODEL_INVALID:{location}") from error


def _artifact_record(path: str, data: bytes) -> ArtifactRecord:
    try:
        return ArtifactRecord(artifact_path=path, artifact_hash=sha256_digest(data))
    except (TypeError, ValidationError, ValueError) as error:
        raise _error("ARTIFACT_PATH") from error


def _snapshot_files(files: Mapping[str, bytes]) -> dict[str, bytes]:
    if not isinstance(files, Mapping):
        raise _error("FILES_INVALID")
    snapshot: dict[str, bytes] = {}
    for path, data in files.items():
        if type(path) is not str or type(data) is not bytes or path == V22_MANIFEST_PATH:
            raise _error("FILES_INVALID")
        if len(data) > _MAX_JSON_BYTES:
            raise _error(f"JSON_SIZE:{path}")
        _artifact_record(path, data)
        if path.endswith(".json"):
            _parse_canonical_json(data, location=path)
        snapshot[path] = data
    return snapshot


def _manifest_context(
    batches: tuple[OrdinaryGradeBatchV22, ...],
    baseline: CanonicalBaselineV22 | None,
) -> dict[str, object]:
    return {
        "ordinary_grade_batches": batches,
        "contested_requirements": () if baseline is None else baseline.contested_requirements,
    }


def _baseline_from_files(files: Mapping[str, bytes]) -> CanonicalBaselineV22 | None:
    data = files.get(V22_BASELINE_PATH)
    if data is None:
        return None
    return cast(
        CanonicalBaselineV22,
        _model_from_file(data, CanonicalBaselineV22, location=V22_BASELINE_PATH),
    )


def _manifest_from_bytes(
    data: bytes, *, baseline: CanonicalBaselineV22 | None
) -> EvaluationManifestV22:
    payload = _parse_canonical_json(data, location=V22_MANIFEST_PATH)
    if type(payload) is not dict:
        raise _error("MANIFEST_INVALID")
    raw = cast(dict[str, object], payload)
    if raw.get("protocol_version") != "2.2":
        raise _error("PROTOCOL")
    raw_batches = raw.get("ordinary_grade_batches")
    if not isinstance(raw_batches, list):
        raise _error("MANIFEST_INVALID")
    try:
        batches = tuple(
            _strict_rehydrate_v22(
                OrdinaryGradeBatchV22,
                item,
                location="manifest ordinary grade batch",
            )
            for item in raw_batches
        )
    except (TypeError, ValidationError, ValueError) as error:
        raise _error("MANIFEST_INVALID") from error
    context = _manifest_context(batches, baseline)
    try:
        manifest = _strict_rehydrate_v22(
            EvaluationManifestV22,
            raw,
            context=context,
            location=V22_MANIFEST_PATH,
        )
    except (TypeError, ValidationError, ValueError, RecursionError) as error:
        raise _error(f"MODEL_INVALID:{V22_MANIFEST_PATH}") from error
    return cast(
        EvaluationManifestV22,
        _canonical_model(
            manifest,
            EvaluationManifestV22,
            location=V22_MANIFEST_PATH,
            context=context,
        ),
    )


def _manifest_fingerprint(manifest: EvaluationManifestV22) -> str:
    payload = manifest.model_dump(mode="json", exclude={"manifest_fingerprint"})
    return sha256_digest(canonical_json_bytes(payload))


def _manifest_bytes(
    manifest: EvaluationManifestV22,
    *,
    baseline: CanonicalBaselineV22 | None,
) -> tuple[EvaluationManifestV22, bytes]:
    snapshot = cast(
        EvaluationManifestV22,
        _canonical_model(
            manifest,
            EvaluationManifestV22,
            location=V22_MANIFEST_PATH,
            context=_manifest_context(manifest.ordinary_grade_batches, baseline),
        ),
    )
    if snapshot.manifest_fingerprint != _manifest_fingerprint(snapshot):
        raise _error("MANIFEST_FINGERPRINT")
    return snapshot, canonical_json_bytes(snapshot.model_dump(mode="json"))


def _with_inventory(
    manifest: EvaluationManifestV22, files: Mapping[str, bytes]
) -> EvaluationManifestV22:
    baseline = _baseline_from_files(files)
    validated = cast(
        EvaluationManifestV22,
        _canonical_model(
            manifest,
            EvaluationManifestV22,
            location="manifest input",
            context=_manifest_context(manifest.ordinary_grade_batches, baseline),
        ),
    )
    inventory = tuple(
        sorted(
            (_artifact_record(path, data) for path, data in files.items()),
            key=lambda item: item.artifact_path,
        )
    )
    candidate = validated.model_copy(
        update={"artifacts": inventory, "manifest_fingerprint": "0" * 64}
    )
    committed = candidate.model_copy(
        update={"manifest_fingerprint": _manifest_fingerprint(candidate)}
    )
    return cast(
        EvaluationManifestV22,
        _canonical_model(
            committed,
            EvaluationManifestV22,
            location="manifest inventory",
            context=_manifest_context(committed.ordinary_grade_batches, baseline),
        ),
    )


def _request_fingerprint(request: EvaluatorRequestV22) -> str:
    return sha256_digest(
        canonical_json_bytes(request.model_dump(mode="json", exclude={"request_fingerprint"}))
    )


def _labels(envelope: CaseEnvelope) -> tuple[Literal["A", "B"], ...]:
    labels = tuple(item.anonymous_label for item in envelope.assignments)
    if labels not in (("A",), ("A", "B")):
        raise _error("CASE_BUILD_BINDING")
    return cast(tuple[Literal["A", "B"], ...], labels)


def _report_text(envelope: CaseEnvelope, label: Literal["A", "B"]) -> str:
    assignments = [item for item in envelope.assignments if item.anonymous_label == label]
    if len(assignments) != 1:
        raise _error("CASE_BUILD_BINDING")
    candidates = [
        item
        for item in envelope.case.candidates
        if item.candidate_id == assignments[0].candidate_id
    ]
    if len(candidates) != 1:
        raise _error("CASE_BUILD_BINDING")
    report = candidates[0]
    if sha256_digest(report.report_text.encode("utf-8")) != report.report_hash:
        raise _error("CASE_BUILD_BINDING")
    return report.report_text


def _source_context(envelope: CaseEnvelope) -> dict[str, str]:
    return {source.source_id: source.normalized_text for source in envelope.case.sources}


def _step_from_call(call: EvaluationCallRecordV22) -> _Step:
    return _Step(
        operation=call.operation,
        fragment_ordinal=call.fragment_ordinal,
        anonymous_label=call.anonymous_label,
        grader_lane=call.grader_lane,
        dispute_id=call.dispute_id,
        batch_ref=call.batch_ref,
        contested_requirement_id=call.contested_requirement_id,
    )


def _controller_call_stem(call: EvaluationCallRecordV22) -> str:
    if call.operation is EvaluatorOperationV22.SOURCE_REVIEW_FRAGMENT:
        return f"source-review-{cast(int, call.fragment_ordinal):04d}"
    if call.operation is EvaluatorOperationV22.SOURCE_AUDIT_FRAGMENT:
        return f"source-audit-{cast(int, call.fragment_ordinal):04d}"
    if call.operation is EvaluatorOperationV22.SOURCE_REFEREE_FRAGMENT:
        return f"referee-{cast(str, call.dispute_id)}"
    if call.operation is EvaluatorOperationV22.ORDINARY_GRADE_FRAGMENT:
        return f"grade-{cast(str, call.batch_ref)}"
    if call.operation is EvaluatorOperationV22.CONTESTED_GRADE_FRAGMENT:
        return (
            f"grade-contested-{cast(str, call.anonymous_label)}-"
            f"{cast(int, call.grader_lane)}-"
            f"{cast(str, call.contested_requirement_id)}"
        )
    raise _error("CALL_HISTORY")


def _validate_controller_call_identity(call: EvaluationCallRecordV22) -> None:
    stem = _controller_call_stem(call)
    expected_response = f"responses/{stem}.json" if call.state == "accepted" else None
    if (
        call.call_id != stem
        or call.request_artifact_path != f"requests/{stem}.json"
        or call.response_artifact_path != expected_response
    ):
        raise _error("CALL_HISTORY")


def _grade_steps(
    batches: tuple[OrdinaryGradeBatchV22, ...],
    contested: tuple[ContestedRequirementV22, ...],
    labels: tuple[Literal["A", "B"], ...],
) -> tuple[_Step, ...]:
    return tuple(
        step
        for label in labels
        for lane in cast(tuple[Literal[1, 2], ...], (1, 2))
        for step in (
            *(
                _Step(
                    EvaluatorOperationV22.ORDINARY_GRADE_FRAGMENT,
                    anonymous_label=label,
                    grader_lane=lane,
                    batch_ref=batch.batch_ref,
                )
                for batch in batches
                if batch.batch_ref.startswith(f"GB-{label}-{lane}-")
            ),
            *(
                _Step(
                    EvaluatorOperationV22.CONTESTED_GRADE_FRAGMENT,
                    anonymous_label=label,
                    grader_lane=lane,
                    contested_requirement_id=item.contested_requirement_id,
                )
                for item in contested
            ),
        )
    )


def _expected_batches(
    baseline: CanonicalBaselineV22,
    labels: tuple[Literal["A", "B"], ...],
) -> tuple[OrdinaryGradeBatchV22, ...]:
    return tuple(
        batch
        for label in labels
        for lane in cast(tuple[Literal[1, 2], ...], (1, 2))
        for batch in ordinary_grade_batches_v22(baseline, label, lane)
    )


def _comparison(
    envelope: CaseEnvelope,
    sensitivities: tuple[SensitivityRecordV22, ...],
) -> ComparisonResultV22 | None:
    if len(sensitivities) == 1:
        return None
    roles = {candidate.candidate_id: candidate.role.value for candidate in envelope.case.candidates}
    labels = {
        roles[assignment.candidate_id]: assignment.anonymous_label
        for assignment in envelope.assignments
    }
    if set(labels) != {"candidate", "comparator"}:
        raise _error("COMPARISON_ROLES")
    return build_comparison_result_v22(
        candidate_label=labels["candidate"],
        comparator_label=labels["comparator"],
        dispositions={
            item.anonymous_label: item.absolute_disposition
            for item in sensitivities
        },
    )


def _baseline_is_empty(baseline: CanonicalBaselineV22) -> bool:
    return not baseline.requirements and not baseline.contested_requirements


def _empty_lane_aggregate(
    baseline: CanonicalBaselineV22,
    envelope: CaseEnvelope,
    label: Literal["A", "B"],
    lane: Literal[1, 2],
) -> GraderAggregateV22:
    payload: dict[str, object] = {
        "anonymous_label": label,
        "grader_lane": lane,
        "baseline_fingerprint": baseline.baseline_fingerprint,
        "report_fingerprint": sha256_digest(_report_text(envelope, label).encode("utf-8")),
        "ordinary_fragments": [],
        "contested_fragments": [],
    }
    return GraderAggregateV22.validate_for_inventories(
        {**payload, "aggregate_fingerprint": sha256_digest(canonical_json_bytes(payload))},
        (),
        (),
    )


def _empty_baseline_sensitivity(
    baseline: CanonicalBaselineV22,
    reconciliation: ReconciledGradeV22,
) -> SensitivityRecordV22:
    payload: dict[str, object] = {
        "anonymous_label": reconciliation.anonymous_label,
        "baseline_fingerprint": baseline.baseline_fingerprint,
        "reconciliation_fingerprint": reconciliation.reconciliation_fingerprint,
        "absolute_disposition": AbsoluteDispositionV2.INCONCLUSIVE.value,
        "reason_codes": ["BASELINE_EVIDENCE_INSUFFICIENT"],
        "outcome_determinative_contested_ids": [],
    }
    return SensitivityRecordV22.model_validate(
        {**payload, "sensitivity_fingerprint": sha256_digest(canonical_json_bytes(payload))}
    )


def _expected_v22_request(
    call: EvaluationCallRecordV22,
    *,
    envelope: CaseEnvelope,
    review_fragments: tuple[AcceptedSourceReviewFragmentV22, ...],
    audit_fragments: tuple[AcceptedSourceAuditFragmentV22, ...],
    review: SourceReviewAggregateV22 | None,
    disputes: tuple[RefereeDisputeV22, ...],
    referee_count: int,
    grade_count: int,
    baseline: CanonicalBaselineV22 | None,
    rubric: RubricV22,
    batches: tuple[OrdinaryGradeBatchV22, ...],
) -> EvaluatorRequestV22:
    """Rebuild the exact next controller request from accepted wire history."""
    try:
        if review is None:
            if call.operation is not EvaluatorOperationV22.SOURCE_REVIEW_FRAGMENT:
                raise ValueError("source review is pending")
            return build_source_review_fragment_request_v22(
                envelope, review_fragments, fragment_ordinal=cast(int, call.fragment_ordinal)
            )
        if not audit_fragments or not audit_fragments[-1].payload.audit_complete:
            if call.operation is not EvaluatorOperationV22.SOURCE_AUDIT_FRAGMENT:
                raise ValueError("source audit is pending")
            return build_source_audit_fragment_request_v22(
                envelope, review, audit_fragments, fragment_ordinal=cast(int, call.fragment_ordinal)
            )
        if referee_count < len(disputes):
            dispute = disputes[referee_count]
            if (
                call.operation is not EvaluatorOperationV22.SOURCE_REFEREE_FRAGMENT
                or call.dispute_id != dispute.dispute_id
            ):
                raise ValueError("source referee binding")
            return build_source_referee_fragment_request_v22(
                envelope, dispute, controller_disputes=disputes
            )
        if baseline is None or call.anonymous_label is None or call.grader_lane is None:
            raise ValueError("grade context unavailable")
        grade_steps = _grade_steps(
            batches,
            baseline.contested_requirements,
            _labels(envelope),
        )
        if grade_count >= len(grade_steps) or _step_from_call(call) != grade_steps[grade_count]:
            raise ValueError("grade call order is invalid")
        report_text = _report_text(envelope, call.anonymous_label)
        if call.operation is EvaluatorOperationV22.ORDINARY_GRADE_FRAGMENT:
            batch = next(item for item in batches if item.batch_ref == call.batch_ref)
            return build_ordinary_grade_request_v22(
                baseline,
                batch,
                call.anonymous_label,
                call.grader_lane,
                report_text,
                _source_context(envelope),
                rubric,
            )
        if call.operation is EvaluatorOperationV22.CONTESTED_GRADE_FRAGMENT:
            requirement = next(
                item
                for item in baseline.contested_requirements
                if item.contested_requirement_id == call.contested_requirement_id
            )
            return build_contested_grade_request_v22(
                baseline,
                requirement,
                call.anonymous_label,
                call.grader_lane,
                report_text,
                _source_context(envelope),
                rubric,
            )
        raise ValueError("unknown evaluator operation")
    except (CompilationError, RubricValidationError, StopIteration, TypeError, ValueError) as error:
        raise _error("CALL_REQUEST_BINDING") from error


def _v22_fragment_payload(
    call: EvaluationCallRecordV22,
    response: EvaluatorResponseV22,
    request: EvaluatorRequestV22,
    envelope: CaseEnvelope,
    disputes: tuple[RefereeDisputeV22, ...],
    baseline: CanonicalBaselineV22 | None,
) -> object:
    """Validate one accepted response in the exact context of its request."""
    try:
        if call.operation is EvaluatorOperationV22.SOURCE_REVIEW_FRAGMENT:
            return _strict_rehydrate_v22(
                SourceReviewFragmentV22,
                response.payload,
                location="source-review response payload",
            )
        if call.operation is EvaluatorOperationV22.SOURCE_AUDIT_FRAGMENT:
            indexed = request.payload.get("indexed_proposals")
            if not isinstance(indexed, list):
                raise ValueError("missing controller proposal inventory")
            proposals = tuple(IndexedProposalV22.model_validate(item) for item in indexed)
            return SourceAuditFragmentV22.validate_for_indexed_proposals(
                response.payload, proposals
            )
        if call.operation is EvaluatorOperationV22.SOURCE_REFEREE_FRAGMENT:
            dispute = next(item for item in disputes if item.dispute_id == call.dispute_id)
            return validate_referee_fragment_v22(
                dispute,
                response.payload,
                response_fingerprint=sha256_digest(
                    canonical_json_bytes(response.model_dump(mode="json"))
                ),
            )
        if baseline is None or call.anonymous_label is None:
            raise ValueError("grade context unavailable")
        return validate_grade_fragment_v22(
            baseline, response.payload, _report_text(envelope, call.anonymous_label)
        )
    except (
        CompilationError,
        RubricValidationError,
        StopIteration,
        TypeError,
        ValidationError,
        ValueError,
    ) as error:
        raise _error("CALL_RESPONSE_BINDING") from error


def _verify_v22_snapshot(manifest: EvaluationManifestV22, files: Mapping[str, bytes]) -> _Replay:
    """Replay protocol 2.2 from frozen inputs and accepted response bytes only."""
    try:
        envelope = cast(
            CaseEnvelope,
            _model_from_file(files[V22_CASE_PATH], CaseEnvelope, location=V22_CASE_PATH),
        )
        build = _parse_canonical_json(files[V22_BUILD_PATH], location=V22_BUILD_PATH)
        rubric = cast(
            RubricV22, _model_from_file(files[V22_RUBRIC_PATH], RubricV22, location=V22_RUBRIC_PATH)
        )
    except (KeyError, EvaluationIntegrityError) as error:
        raise _error("CASE_BUILD_BINDING") from error
    if (
        type(build) is not dict
        or sha256_digest(files[V22_CASE_PATH]) != manifest.case_envelope_hash
        or sha256_digest(files[V22_BUILD_PATH]) != manifest.build_fingerprint
        or sha256_digest(files[V22_RUBRIC_PATH]) != manifest.rubric_fingerprint
        or envelope.case_fingerprint != manifest.case_fingerprint
    ):
        raise _error("CASE_BUILD_BINDING")
    if manifest.compiler_contract_fingerprint != COMPILER_CONTRACT_FINGERPRINT_V22:
        raise _error("COMPILER_CONTRACT")
    labels = _labels(envelope)
    baseline = _baseline_from_files(files)
    requests: dict[str, EvaluatorRequestV22] = {}
    responses: dict[str, EvaluatorResponseV22] = {}
    request_paths: set[str] = set()
    response_paths: set[str] = set()
    for call in manifest.calls:
        _validate_controller_call_identity(call)
        if call.request_artifact_path in request_paths:
            raise _error("CALL_HISTORY")
        request_paths.add(call.request_artifact_path)
        try:
            request = cast(
                EvaluatorRequestV22,
                _model_from_file(
                    files[call.request_artifact_path],
                    EvaluatorRequestV22,
                    location=call.request_artifact_path,
                ),
            )
            request = validate_evaluator_request_v22(request)
        except (KeyError, ValueError) as error:
            raise _error("CALL_REQUEST_BINDING") from error
        if (
            request.operation is not call.operation
            or request.request_fingerprint != call.request_fingerprint
            or _request_fingerprint(request) != call.request_fingerprint
        ):
            raise _error("CALL_REQUEST_BINDING")
        requests[call.call_id] = request
        if call.state == "accepted":
            if call.response_artifact_path is None or call.response_fingerprint is None:
                raise _error("CALL_RESPONSE_MISSING")
            if call.response_artifact_path in response_paths:
                raise _error("CALL_HISTORY")
            response_paths.add(call.response_artifact_path)
            try:
                data = files[call.response_artifact_path]
                response = cast(
                    EvaluatorResponseV22,
                    _model_from_file(
                        data, EvaluatorResponseV22, location=call.response_artifact_path
                    ),
                )
                response = validate_evaluator_response_v22(response)
            except (KeyError, ValueError) as error:
                raise _error("CALL_RESPONSE_BINDING") from error
            if sha256_digest(data) != call.response_fingerprint or (
                response.operation is not call.operation
                or response.request_fingerprint != call.request_fingerprint
                or response.provider_name != call.provider_name
                or response.model_name != call.model_name
                or response.judge_isolation is not call.judge_isolation
            ):
                raise _error("CALL_RESPONSE_BINDING")
            responses[call.call_id] = response
    accepted = tuple(item for item in manifest.calls if item.state == "accepted")
    pending = tuple(item for item in manifest.calls if item.state == "pending")
    if manifest.calls != (*accepted, *pending) or len(pending) > 1:
        raise _error("CALL_HISTORY")
    review_fragments: list[AcceptedSourceReviewFragmentV22] = []
    audit_fragments: list[AcceptedSourceAuditFragmentV22] = []
    review: SourceReviewAggregateV22 | None = None
    audit: SourceAuditAggregateV22 | None = None
    disputes: tuple[RefereeDisputeV22, ...] = ()
    referee_fragments: list[AcceptedRefereeFragmentV22] = []
    grade_fragments: dict[_Step, OrdinaryGradeFragmentV22 | ContestedGradeFragmentV22] = {}
    for call in accepted:
        expected = _expected_v22_request(
            call,
            envelope=envelope,
            review_fragments=tuple(review_fragments),
            audit_fragments=tuple(audit_fragments),
            review=review,
            disputes=disputes,
            referee_count=len(referee_fragments),
            grade_count=len(grade_fragments),
            baseline=baseline,
            rubric=rubric,
            batches=manifest.ordinary_grade_batches,
        )
        if files[call.request_artifact_path] != canonical_json_bytes(
            expected.model_dump(mode="json", warnings="error")
        ):
            raise _error("CALL_REQUEST_BINDING")
        payload = _v22_fragment_payload(
            call, responses[call.call_id], expected, envelope, disputes, baseline
        )
        if call.operation is EvaluatorOperationV22.SOURCE_REVIEW_FRAGMENT:
            review_fragments.append(
                AcceptedSourceReviewFragmentV22(
                    fragment_ordinal=cast(int, call.fragment_ordinal),
                    request_fingerprint=call.request_fingerprint,
                    response_fingerprint=cast(str, call.response_fingerprint),
                    payload=cast(SourceReviewFragmentV22, payload),
                )
            )
            if review_fragments[-1].payload.review_complete:
                review = aggregate_source_review_fragments_v22(tuple(review_fragments))
        elif call.operation is EvaluatorOperationV22.SOURCE_AUDIT_FRAGMENT:
            audit_fragments.append(
                AcceptedSourceAuditFragmentV22(
                    fragment_ordinal=cast(int, call.fragment_ordinal),
                    request_fingerprint=call.request_fingerprint,
                    response_fingerprint=cast(str, call.response_fingerprint),
                    payload=cast(SourceAuditFragmentV22, payload),
                )
            )
            if audit_fragments[-1].payload.audit_complete:
                if review is None:
                    raise _error("SOURCE_AUDIT")
                audit = aggregate_source_audit_fragments_v22(review, tuple(audit_fragments))
                disputes = build_referee_disputes_v22(envelope, review, audit)
        elif call.operation is EvaluatorOperationV22.SOURCE_REFEREE_FRAGMENT:
            referee_fragments.append(cast(AcceptedRefereeFragmentV22, payload))
        else:
            grade_fragments[_step_from_call(call)] = cast(
                OrdinaryGradeFragmentV22 | ContestedGradeFragmentV22, payload
            )
    if pending:
        call = pending[0]
        expected = _expected_v22_request(
            call,
            envelope=envelope,
            review_fragments=tuple(review_fragments),
            audit_fragments=tuple(audit_fragments),
            review=review,
            disputes=disputes,
            referee_count=len(referee_fragments),
            grade_count=len(grade_fragments),
            baseline=baseline,
            rubric=rubric,
            batches=manifest.ordinary_grade_batches,
        )
        if files[call.request_artifact_path] != canonical_json_bytes(
            expected.model_dump(mode="json", warnings="error")
        ):
            raise _error("CALL_REQUEST_BINDING")
    bound = {V22_CASE_PATH, V22_BUILD_PATH, V22_RUBRIC_PATH, *request_paths, *response_paths}
    if review is not None:
        path = "aggregates/source-review.json"
        if (
            files.get(path) != canonical_json_bytes(review.model_dump(mode="json"))
            or manifest.source_review_aggregate_fingerprint != review.aggregate_fingerprint
        ):
            raise _error("SOURCE_REVIEW_AGGREGATE")
        bound.add(path)
    elif manifest.source_review_aggregate_fingerprint is not None:
        raise _error("SOURCE_REVIEW_AGGREGATE")
    if audit is not None:
        path = "aggregates/source-audit.json"
        if (
            files.get(path) != canonical_json_bytes(audit.model_dump(mode="json"))
            or manifest.source_audit_aggregate_fingerprint != audit.aggregate_fingerprint
        ):
            raise _error("SOURCE_AUDIT_AGGREGATE")
        bound.add(path)
    elif manifest.source_audit_aggregate_fingerprint is not None:
        raise _error("SOURCE_AUDIT_AGGREGATE")
    if audit is None:
        if (
            manifest.referee_disputes
            or manifest.referee_aggregate_fingerprint is not None
            or baseline is not None
        ):
            raise _error("REFEREE_INVENTORY")
    elif manifest.referee_disputes != disputes:
        raise _error("REFEREE_INVENTORY")
    source_done = audit is not None and len(referee_fragments) == len(disputes)
    if source_done:
        expected_referee = aggregate_referee_decisions_v22(disputes, tuple(referee_fragments))
        if (
            files.get(V22_REFEREE_AGGREGATE_PATH)
            != canonical_json_bytes(expected_referee.model_dump(mode="json"))
            or manifest.referee_aggregate_fingerprint != expected_referee.aggregate_fingerprint
        ):
            raise _error("REFEREE_AGGREGATE")
        bound.add(V22_REFEREE_AGGREGATE_PATH)
        if review is None or audit is None or baseline is None:
            raise _error("BASELINE_FINGERPRINT")
        expected_baseline = compile_baseline_v22(envelope, review, audit, expected_referee)
        if (
            baseline != expected_baseline
            or manifest.baseline_fingerprint != expected_baseline.baseline_fingerprint
        ):
            raise _error("BASELINE_FINGERPRINT")
        bound.add(V22_BASELINE_PATH)
    elif baseline is not None or manifest.baseline_fingerprint is not None:
        raise _error("BASELINE_UNEXPECTED")
    if baseline is not None:
        batches = _expected_batches(baseline, labels)
        if manifest.ordinary_grade_batches != batches:
            raise _error("GRADE_BATCH_INVENTORY")
    elif manifest.ordinary_grade_batches:
        raise _error("GRADE_BATCH_INVENTORY")
    expected_aggregate_fingerprints: list[str] = []
    expected_sensitivity_fingerprints: list[str] = []
    reconciliations: list[ReconciledGradeV22] = []
    sensitivities: list[SensitivityRecordV22] = []
    if (
        baseline is not None
        and source_done
        and _baseline_is_empty(baseline)
        and manifest.terminal_status is None
    ):
        raise _error("CALL_HISTORY")
    if baseline is not None and source_done:
        for label in labels:
            lane_values: list[GraderAggregateV22] = []
            for lane in cast(tuple[Literal[1, 2], ...], (1, 2)):
                lane_batches = ordinary_grade_batches_v22(baseline, label, lane)
                ordinary_steps = tuple(
                    _Step(
                        EvaluatorOperationV22.ORDINARY_GRADE_FRAGMENT,
                        anonymous_label=label,
                        grader_lane=lane,
                        batch_ref=batch.batch_ref,
                    )
                    for batch in lane_batches
                )
                contested_steps = tuple(
                    _Step(
                        EvaluatorOperationV22.CONTESTED_GRADE_FRAGMENT,
                        anonymous_label=label,
                        grader_lane=lane,
                        contested_requirement_id=item.contested_requirement_id,
                    )
                    for item in baseline.contested_requirements
                )
                steps = (*ordinary_steps, *contested_steps)
                present = [item for item in steps if item in grade_fragments]
                path = f"aggregates/grade-{label}-{lane}.json"
                if present and len(present) != len(steps):
                    if path in files:
                        raise _error("GRADER_AGGREGATE_PARTIAL")
                    continue
                if not steps:
                    aggregate = _empty_lane_aggregate(
                        baseline, envelope, label, lane
                    )
                    if files.get(path) != canonical_json_bytes(
                        aggregate.model_dump(mode="json")
                    ):
                        raise _error("GRADER_AGGREGATE")
                    bound.add(path)
                    lane_values.append(aggregate)
                    expected_aggregate_fingerprints.append(
                        aggregate.aggregate_fingerprint
                    )
                    continue
                if not present:
                    continue
                try:
                    aggregate = aggregate_grader_lane_v22(
                        baseline,
                        label,
                        lane,
                        tuple(
                            cast(OrdinaryGradeFragmentV22, grade_fragments[item])
                            for item in ordinary_steps
                        ),
                        tuple(
                            cast(ContestedGradeFragmentV22, grade_fragments[item])
                            for item in contested_steps
                        ),
                    )
                except (RubricValidationError, TypeError, ValueError) as error:
                    raise _error("GRADER_AGGREGATE") from error
                if files.get(path) != canonical_json_bytes(aggregate.model_dump(mode="json")):
                    raise _error("GRADER_AGGREGATE")
                bound.add(path)
                lane_values.append(aggregate)
                expected_aggregate_fingerprints.append(aggregate.aggregate_fingerprint)
            if len(lane_values) == 2:
                try:
                    reconciliation = reconcile_grader_lanes_v22(
                        baseline, lane_values[0], lane_values[1], rubric
                    )
                    sensitivity = evaluate_outcome_sensitivity_v22(baseline, reconciliation, rubric)
                    if _baseline_is_empty(baseline):
                        sensitivity = _empty_baseline_sensitivity(
                            baseline, reconciliation
                        )
                except (RubricValidationError, TypeError, ValueError) as error:
                    raise _error("SENSITIVITY") from error
                path = f"sensitivities/{label}.json"
                if files.get(path) != canonical_json_bytes(sensitivity.model_dump(mode="json")):
                    raise _error("SENSITIVITY")
                bound.add(path)
                reconciliations.append(reconciliation)
                sensitivities.append(sensitivity)
                expected_sensitivity_fingerprints.append(sensitivity.sensitivity_fingerprint)
    if tuple(expected_aggregate_fingerprints) != manifest.grader_aggregate_fingerprints:
        raise _error("GRADER_AGGREGATE")
    if tuple(expected_sensitivity_fingerprints) != manifest.sensitivity_fingerprints:
        raise _error("SENSITIVITY")
    terminal = manifest.terminal_status
    result: EvaluationResultV22 | None = None
    if terminal in {
        EvaluationTerminalStatusV22.COMPLETED,
        EvaluationTerminalStatusV22.INCONCLUSIVE,
    }:
        if baseline is None or len(sensitivities) != len(labels):
            raise _error("RESULT_REQUIRED")
        expected_reports: list[ReportResultV22] = []
        for label, reconciliation, sensitivity in zip(
            labels, reconciliations, sensitivities, strict=True
        ):
            report_payload: dict[str, object] = {
                "anonymous_label": label,
                "reconciliation": reconciliation.model_dump(mode="json"),
                "sensitivity": sensitivity.model_dump(mode="json"),
            }
            expected_reports.append(
                ReportResultV22(
                    anonymous_label=label,
                    reconciliation=reconciliation,
                    sensitivity=sensitivity,
                    result_fingerprint=sha256_digest(canonical_json_bytes(report_payload)),
                )
            )
        expected_terminal = (
            EvaluationTerminalStatusV22.INCONCLUSIVE
            if any(
                item.absolute_disposition is AbsoluteDispositionV2.INCONCLUSIVE
                for item in sensitivities
            )
            else EvaluationTerminalStatusV22.COMPLETED
        )
        if terminal is not expected_terminal:
            raise _error("RESULT_TERMINAL")
        comparison = _comparison(envelope, tuple(sensitivities))
        result_payload: dict[str, object] = {
            "schema_version": "2.2",
            "rubric": rubric.model_dump(mode="json"),
            "baseline": baseline.model_dump(mode="json"),
            "reports": [item.model_dump(mode="json") for item in expected_reports],
            "comparison": (None if comparison is None else comparison.model_dump(mode="json")),
            "terminal_status": terminal.value,
        }
        result = EvaluationResultV22(
            schema_version="2.2",
            rubric=rubric,
            baseline=baseline,
            reports=tuple(expected_reports),
            comparison=comparison,
            terminal_status=terminal,
            result_fingerprint=sha256_digest(canonical_json_bytes(result_payload)),
        )
        try:
            stored_result = files[V22_RESULT_PATH]
            _parse_canonical_json(stored_result, location=V22_RESULT_PATH)
        except (KeyError, EvaluationIntegrityError) as error:
            raise _error("RESULT_REQUIRED") from error
        if (
            stored_result != canonical_json_bytes(result.model_dump(mode="json", warnings="error"))
            or manifest.result_hash != result.result_fingerprint
        ):
            raise _error("RESULT_BINDING")
        bound.add(V22_RESULT_PATH)
    elif manifest.result_hash is not None or V22_RESULT_PATH in files:
        raise _error("RESULT_TERMINAL")
    extras = set(files) - bound
    if extras:
        if any(path == V22_RESULT_PATH or path.startswith("results/") for path in extras):
            raise _error("RESULT_UNBOUND")
        if any(path.startswith("responses/") for path in extras):
            raise _error("UNBOUND_RESPONSE")
        if any(path.startswith("requests/") for path in extras):
            raise _error("UNBOUND_REQUEST")
        raise _error("UNBOUND_ARTIFACT")
    if pending:
        phase_by_operation = {
            EvaluatorOperationV22.SOURCE_REVIEW_FRAGMENT: EvaluationPhaseV22.SOURCE_REVIEW,
            EvaluatorOperationV22.SOURCE_AUDIT_FRAGMENT: EvaluationPhaseV22.SOURCE_AUDIT,
            EvaluatorOperationV22.SOURCE_REFEREE_FRAGMENT: EvaluationPhaseV22.SOURCE_REFEREE,
            EvaluatorOperationV22.ORDINARY_GRADE_FRAGMENT: EvaluationPhaseV22.ORDINARY_GRADING,
            EvaluatorOperationV22.CONTESTED_GRADE_FRAGMENT: EvaluationPhaseV22.CONTESTED_GRADING,
        }
        if manifest.phase is not phase_by_operation[pending[0].operation]:
            raise _error("CALL_HISTORY")
    elif terminal is not None:
        expected_phase = (
            EvaluationPhaseV22.INCONCLUSIVE
            if terminal is EvaluationTerminalStatusV22.INCONCLUSIVE
            else EvaluationPhaseV22.COMPLETED
        )
        if manifest.phase is not expected_phase:
            raise _error("CALL_HISTORY")
    elif not accepted:
        if manifest.phase is not EvaluationPhaseV22.CREATED:
            raise _error("CALL_HISTORY")
    else:
        grade_steps = (
            ()
            if baseline is None
            else _grade_steps(
                manifest.ordinary_grade_batches,
                baseline.contested_requirements,
                labels,
            )
        )
        nonterminal_phase: EvaluationPhaseV22 | None = (
            EvaluationPhaseV22.BASELINE_SEALED
            if source_done and not grade_fragments and grade_steps
            else EvaluationPhaseV22.AGGREGATE
            if source_done and len(grade_fragments) == len(grade_steps)
            else None
        )
        if nonterminal_phase is None or manifest.phase is not nonterminal_phase:
            raise _error("CALL_HISTORY")
    return _Replay(
        manifest, result, envelope, files[V22_CASE_PATH], rubric, baseline, requests, responses
    )


def _verify_or_raise(storage: RunStorage) -> _Replay:
    storage.assert_root_identity()
    initial_inventory = storage.scan_inventory()
    paths = {path for path in initial_inventory if not path.endswith("/")}
    if V22_MANIFEST_PATH not in paths:
        raise _error("MANIFEST_MISSING")
    provisional_files: dict[str, bytes] = {}
    baseline_data = storage.read_optional_artifact(V22_BASELINE_PATH, max_bytes=_MAX_JSON_BYTES)
    baseline = None
    if baseline_data is not None:
        provisional_files[V22_BASELINE_PATH] = baseline_data
        baseline = _baseline_from_files(provisional_files)
    manifest = _manifest_from_bytes(
        storage.read_artifact(V22_MANIFEST_PATH, max_bytes=_MAX_JSON_BYTES),
        baseline=baseline,
    )
    if manifest.manifest_fingerprint != _manifest_fingerprint(manifest):
        raise _error("MANIFEST_FINGERPRINT")
    expected = {artifact.artifact_path for artifact in manifest.artifacts} | {V22_MANIFEST_PATH}
    expected_inventory = set(expected)
    for path in expected:
        parent = Path(path).parent
        while parent != Path("."):
            expected_inventory.add(f"{parent.as_posix()}/")
            parent = parent.parent
    if set(initial_inventory) != expected_inventory:
        raise _error("INVENTORY")
    files: dict[str, bytes] = {}
    for artifact in manifest.artifacts:
        data = storage.read_artifact(artifact.artifact_path, max_bytes=_MAX_JSON_BYTES)
        if sha256_digest(data) != artifact.artifact_hash:
            raise _error("ARTIFACT_HASH")
        if artifact.artifact_path.endswith(".json"):
            _parse_canonical_json(data, location=artifact.artifact_path)
        files[artifact.artifact_path] = data
    replay = _verify_v22_snapshot(manifest, files)
    if storage.scan_inventory() != initial_inventory:
        raise _error("INVENTORY_CHANGED")
    storage.assert_root_identity()
    return replay


def _call_identity(call: EvaluationCallRecordV22) -> dict[str, object]:
    return call.model_dump(
        mode="python",
        exclude={
            "state",
            "attempt",
            "response_artifact_path",
            "response_fingerprint",
            "provider_name",
            "model_name",
            "judge_isolation",
        },
    )


def _validate_successor_transition(
    previous: EvaluationManifestV22,
    successor: EvaluationManifestV22,
) -> None:
    """Require one monotonic transition without rewriting accepted history."""
    previous_accepted = tuple(call for call in previous.calls if call.state == "accepted")
    if successor.calls[: len(previous_accepted)] != previous_accepted:
        raise EvaluationIntegrityError("EVALUATOR_V22_STALE_TRANSITION")
    previous_pending = tuple(call for call in previous.calls if call.state == "pending")
    if not previous_pending:
        suffix = successor.calls[len(previous_accepted) :]
        if len(suffix) > 1 or (suffix and suffix[0].state != "pending"):
            raise EvaluationIntegrityError("EVALUATOR_V22_STALE_TRANSITION")
        return
    index = len(previous_accepted)
    if len(successor.calls) <= index:
        raise EvaluationIntegrityError("EVALUATOR_V22_STALE_TRANSITION")
    before = previous_pending[0]
    after = successor.calls[index]
    if _call_identity(after) != _call_identity(before):
        raise EvaluationIntegrityError("EVALUATOR_V22_STALE_TRANSITION")
    if after.state == "accepted":
        if after.attempt != before.attempt:
            raise EvaluationIntegrityError("EVALUATOR_V22_STALE_TRANSITION")
        suffix = successor.calls[index + 1 :]
        if len(suffix) > 1 or (suffix and suffix[0].state != "pending"):
            raise EvaluationIntegrityError("EVALUATOR_V22_STALE_TRANSITION")
    elif (
        len(successor.calls) != index + 1
        or after.attempt < before.attempt
        or after.attempt > before.attempt + 1
    ):
        raise EvaluationIntegrityError("EVALUATOR_V22_STALE_TRANSITION")


def _commit_with_rollback(
    storage: RunStorage,
    files: Mapping[str, bytes],
    successor: EvaluationManifestV22,
    *,
    expected_manifest_fingerprint: str | None = None,
) -> EvaluationManifestV22:
    snapshot_files = _snapshot_files(files)
    existing = storage.scan_files()
    inherited_files: dict[str, bytes] = {}
    prior_manifest_bytes: bytes | None = None
    prior_manifest: EvaluationManifestV22 | None = None
    if existing:
        replay = _verify_or_raise(storage)
        prior_manifest = replay.manifest
        if (
            expected_manifest_fingerprint is not None
            and replay.manifest.manifest_fingerprint != expected_manifest_fingerprint
        ):
            raise EvaluationIntegrityError("EVALUATOR_V22_STALE_TRANSITION")
        for artifact in replay.manifest.artifacts:
            inherited_files[artifact.artifact_path] = storage.read_artifact(
                artifact.artifact_path, max_bytes=_MAX_JSON_BYTES
            )
        prior_manifest_bytes = storage.read_artifact(V22_MANIFEST_PATH, max_bytes=_MAX_JSON_BYTES)
    for path, data in snapshot_files.items():
        if path in inherited_files and inherited_files[path] != data:
            raise _error("IMMUTABLE_ARTIFACT")
    all_files = {**inherited_files, **snapshot_files}
    committed = _with_inventory(successor, all_files)
    if prior_manifest is not None:
        _validate_successor_transition(prior_manifest, committed)
    baseline = _baseline_from_files(all_files)
    _, manifest_bytes = _manifest_bytes(committed, baseline=baseline)
    _verify_v22_snapshot(committed, all_files)
    storage.assert_root_identity()
    created: list[tuple[str, bytes, _NodeIdentity]] = []
    manifest_installed = False
    manifest_identity: _NodeIdentity | None = None
    try:
        for path in sorted(snapshot_files):
            try:
                created_now = storage.atomic_write(path, snapshot_files[path], mutable=False)
            except BaseException as error:
                receipt = storage.atomic_write_receipt(path)
                identity = (
                    error.identity
                    if isinstance(error, _AtomicWriteOwnershipError)
                    else None if receipt is None else receipt.identity
                )
                created_visible = (
                    error.created
                    if isinstance(error, _AtomicWriteOwnershipError)
                    else receipt is not None and receipt.created
                )
                if created_visible:
                    if identity is None:
                        raise _error("ROLLBACK_FAILED") from error
                    created.append((path, snapshot_files[path], identity))
                raise
            if created_now:
                receipt = storage.atomic_write_receipt(path)
                if (
                    receipt is None
                    or not receipt.created
                    or receipt.identity is None
                ):
                    raise _error("ROLLBACK_FAILED")
                created.append((path, snapshot_files[path], receipt.identity))
        if any(
            storage.read_artifact(path, max_bytes=_MAX_JSON_BYTES) != data
            for path, data in snapshot_files.items()
        ):
            raise EvaluationIntegrityError("EVALUATOR_V22_STALE_TRANSITION")
        if existing:
            if any(
                storage.read_artifact(path, max_bytes=_MAX_JSON_BYTES) != data
                for path, data in inherited_files.items()
            ):
                raise EvaluationIntegrityError("EVALUATOR_V22_STALE_TRANSITION")
            current_bytes = storage.read_artifact(V22_MANIFEST_PATH, max_bytes=_MAX_JSON_BYTES)
            current_baseline = _baseline_from_files(inherited_files)
            current = _manifest_from_bytes(current_bytes, baseline=current_baseline)
            if current.manifest_fingerprint != _manifest_fingerprint(current):
                raise _error("MANIFEST_FINGERPRINT")
            if (
                expected_manifest_fingerprint is not None
                and current.manifest_fingerprint != expected_manifest_fingerprint
            ):
                raise EvaluationIntegrityError("EVALUATOR_V22_STALE_TRANSITION")
        try:
            manifest_installed = storage.atomic_write(
                V22_MANIFEST_PATH, manifest_bytes, mutable=bool(existing)
            )
            receipt = storage.atomic_write_receipt(V22_MANIFEST_PATH)
            if manifest_installed:
                manifest_identity = None if receipt is None else receipt.identity
                if manifest_identity is None:
                    raise _error("ROLLBACK_FAILED")
        except BaseException as error:
            receipt = storage.atomic_write_receipt(V22_MANIFEST_PATH)
            visible = (
                error.created or error.replaced
                if isinstance(error, _AtomicWriteOwnershipError)
                else receipt is not None and (receipt.created or receipt.replaced)
            )
            if visible:
                manifest_installed = True
                manifest_identity = (
                    error.identity
                    if isinstance(error, _AtomicWriteOwnershipError)
                    else None if receipt is None else receipt.identity
                )
                if manifest_identity is None:
                    manifest_identity = None if receipt is None else receipt.identity
            raise
        installed = _verify_or_raise(storage)
        if installed.manifest != committed:
            raise EvaluationIntegrityError("EVALUATOR_V22_STALE_TRANSITION")
    except BaseException as error:
        cleanup_error: BaseException | None = None
        restored_manifest = False
        try:
            observed_manifest = storage.read_optional_artifact_with_identity(
                V22_MANIFEST_PATH, max_bytes=_MAX_JSON_BYTES
            )
            if prior_manifest_bytes is None:
                if (
                    manifest_installed
                    and manifest_identity is not None
                    and observed_manifest is not None
                    and observed_manifest[0] == manifest_bytes
                    and _same_filesystem_object(
                        observed_manifest[1], manifest_identity
                    )
                ):
                    storage.remove_artifact(
                        V22_MANIFEST_PATH,
                        expected_identity=manifest_identity,
                        expected_data=manifest_bytes,
                    )
                    restored_manifest = True
                elif manifest_installed:
                    raise _error("ROLLBACK_FAILED")
            elif (
                manifest_installed
                and manifest_identity is not None
                and observed_manifest is not None
                and observed_manifest[0] == manifest_bytes
                and _same_filesystem_object(observed_manifest[1], manifest_identity)
            ):
                storage.replace_artifact_if_owned(
                    V22_MANIFEST_PATH,
                    prior_manifest_bytes,
                    owned_identity=manifest_identity,
                    owned_data=manifest_bytes,
                )
                if (
                    storage.read_artifact(V22_MANIFEST_PATH, max_bytes=_MAX_JSON_BYTES)
                    != prior_manifest_bytes
                ):
                    raise _error("ROLLBACK_FAILED")
                restored_manifest = True
            elif observed_manifest is None or observed_manifest[0] != prior_manifest_bytes:
                raise _error("ROLLBACK_FAILED")
        except BaseException as cleanup:
            cleanup_error = cleanup
        for path, data, identity in reversed(created):
            try:
                storage.remove_artifact(
                    path,
                    expected_identity=identity,
                    expected_data=data,
                )
            except BaseException as cleanup:
                cleanup_error = cleanup
        if restored_manifest and prior_manifest_bytes is not None:
            try:
                expected_prior = {
                    **inherited_files,
                    V22_MANIFEST_PATH: prior_manifest_bytes,
                }
                if storage.scan_files() != set(expected_prior) or any(
                    storage.read_artifact(path, max_bytes=_MAX_JSON_BYTES) != data
                    for path, data in expected_prior.items()
                ):
                    raise _error("ROLLBACK_FAILED")
            except BaseException as cleanup:
                cleanup_error = cleanup
        if cleanup_error is not None:
            raise _error("ROLLBACK_FAILED") from cleanup_error
        raise error
    storage.assert_root_identity()
    return committed


def initialize_v22_run_storage(
    run_dir: Path,
    manifest: EvaluationManifestV22,
    files: Mapping[str, bytes],
) -> EvaluationManifestV22:
    """Create one empty run root and atomically expose its verified first state."""
    with open_evaluation_storage(run_dir, initialize=True) as storage:
        return _commit_with_rollback(storage, files, manifest)


def commit_v22_transition(
    run_dir: Path,
    expected_manifest_fingerprint: str,
    files: Mapping[str, bytes],
    successor: EvaluationManifestV22,
) -> None:
    """Commit one verified successor iff the current manifest root still matches."""
    with open_evaluation_storage(run_dir) as storage:
        current = _verify_or_raise(storage).manifest
        if current.manifest_fingerprint != expected_manifest_fingerprint:
            raise EvaluationIntegrityError("EVALUATOR_V22_STALE_TRANSITION")
        _commit_with_rollback(
            storage,
            files,
            successor,
            expected_manifest_fingerprint=expected_manifest_fingerprint,
        )


def preflight_v22_response(run_dir: Path, call_id: str, response: object) -> V22ResponsePreflight:
    """Validate one pending response without accepting or persisting any bytes."""
    try:
        with open_evaluation_storage(run_dir) as storage:
            replay = _verify_or_raise(storage)
            pending = [
                call
                for call in replay.manifest.calls
                if call.call_id == call_id and call.state == "pending"
            ]
            if len(pending) != 1:
                raise _error("PENDING_CALL")
            validated = validate_evaluator_response_v22(response)
            call = pending[0]
            if (
                validated.operation is not call.operation
                or validated.request_fingerprint != call.request_fingerprint
            ):
                raise _error("RESPONSE_BINDING")
            _v22_fragment_payload(
                call,
                validated,
                replay.requests[call.call_id],
                replay.envelope,
                replay.manifest.referee_disputes,
                replay.baseline,
            )
            storage.assert_root_identity()
    except (
        EvaluationIntegrityError,
        CompilationError,
        RubricValidationError,
        TypeError,
        ValidationError,
        ValueError,
        RecursionError,
    ):
        return V22ResponsePreflight(False, ("MECHANICAL_RESPONSE_INVALID",))
    return V22ResponsePreflight(True)


def verify_v22_run(run_dir: Path) -> EvaluationVerification:
    """Verify the exact v2.2 inventory, history, bindings, and retained root."""
    try:
        with open_evaluation_storage(run_dir) as storage:
            replay = _verify_or_raise(storage)
            storage.assert_root_identity()
    except (
        EvaluationIntegrityError,
        OSError,
        TypeError,
        ValidationError,
        ValueError,
        RecursionError,
    ) as error:
        return EvaluationVerification(False, (str(error),), None)
    return EvaluationVerification(True, (), replay.manifest.manifest_fingerprint)


def load_verified_v22_run(
    run_dir: Path,
) -> tuple[EvaluationManifestV22, EvaluationResultV22 | None]:
    """Return protocol-2.2 snapshots only after complete no-follow replay."""
    with open_evaluation_storage(run_dir) as storage:
        replay = _verify_or_raise(storage)
        storage.assert_root_identity()
        return replay.manifest, replay.result


def load_verified_v22_context(run_dir: Path) -> VerifiedV22Context:
    """Return one immutable execution context from one complete verified replay."""
    with open_evaluation_storage(run_dir) as storage:
        replay = _verify_or_raise(storage)
        storage.assert_root_identity()
        return VerifiedV22Context(
            manifest=replay.manifest,
            result=replay.result,
            case_envelope_bytes=replay.case_envelope_bytes,
            rubric=replay.rubric,
            baseline=replay.baseline,
            source_context=MappingProxyType(
                {
                    source.source_id: source.normalized_text
                    for source in replay.envelope.case.sources
                }
            ),
        )
