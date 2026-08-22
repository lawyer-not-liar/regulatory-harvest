"""Atomic storage and complete replay verification for evaluator protocol 2.1."""

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
    open_evaluation_storage,
)
from .attorney_models import ArtifactRecord, CaseEnvelope
from .attorney_v2_compiler import CompilationError
from .attorney_v2_models import (
    AbsoluteDispositionV2,
    ComparisonDispositionV2,
    ComparisonResultV2,
    IndexedProposalV2,
)
from .attorney_v21_compiler import (
    aggregate_referee_decisions,
    build_referee_disputes,
    compile_baseline_v21,
    validate_referee_fragment,
)
from .attorney_v21_models import (
    AcceptedRefereeFragmentV21,
    CanonicalBaselineV21,
    ContestedGradeFragmentV21,
    ContestedRequirementV21,
    EvaluationCallRecordV21,
    EvaluationManifestV21,
    EvaluationPhaseV21,
    EvaluationResultV21,
    EvaluationTerminalStatusV21,
    EvaluatorOperationV21,
    EvaluatorRequestV21,
    EvaluatorResponseV21,
    GraderAggregateV21,
    OrdinaryGradeBatchV21,
    OrdinaryGradeFragmentV21,
    RefereeAggregateV21,
    RefereeDecisionV21,
    RefereeDisputeV21,
    ReportResultV21,
    RubricV21,
    SensitivityRecordV21,
    SourceAuditV21,
    SourceReviewV21,
    validate_evaluator_request_v21,
    validate_evaluator_response_v21,
)
from .attorney_v21_requests import (
    build_contested_grade_request_v21,
    build_ordinary_grade_request_v21,
    build_source_audit_request_v21,
    build_source_referee_fragment_request,
    build_source_review_request_v21,
)
from .attorney_v21_rubric import (
    RubricValidationError,
    aggregate_grader_lane,
    evaluate_outcome_sensitivity,
    ordinary_grade_batches,
    reconcile_grader_lanes,
    validate_grade_fragment_v21,
)

V21_MANIFEST_PATH = "run-manifest.json"
V21_CASE_PATH = "inputs/case.json"
V21_BUILD_PATH = "inputs/build.json"
V21_RUBRIC_PATH = "rubric.json"
V21_BASELINE_PATH = "baseline.json"
V21_REFEREE_AGGREGATE_PATH = "aggregates/referee.json"
V21_RESULT_PATH = "result.json"
_MAX_JSON_BYTES = 16 * 1024 * 1024
_MAX_JSON_DEPTH = 64


@dataclass(frozen=True)
class V21ResponsePreflight:
    """A write-free response admission result with public-safe diagnostics."""

    valid: bool
    diagnostics: tuple[str, ...] = ()


@dataclass(frozen=True)
class VerifiedV21Context:
    """One immutable protocol-2.1 context derived from a single verified replay."""

    manifest: EvaluationManifestV21
    result: EvaluationResultV21 | None
    case_envelope_bytes: bytes
    rubric: RubricV21
    baseline: CanonicalBaselineV21 | None
    source_context: Mapping[str, str]

    def load_case_envelope(self) -> CaseEnvelope:
        """Return a fresh typed copy without rereading the run or caller input."""
        return CaseEnvelope.model_validate_json(self.case_envelope_bytes)


@dataclass(frozen=True)
class _Step:
    operation: EvaluatorOperationV21
    anonymous_label: Literal["A", "B"] | None = None
    grader_lane: Literal[1, 2] | None = None
    dispute_id: str | None = None
    batch_ref: str | None = None
    contested_requirement_id: str | None = None


@dataclass(frozen=True)
class _Replay:
    manifest: EvaluationManifestV21
    result: EvaluationResultV21 | None
    envelope: CaseEnvelope
    case_envelope_bytes: bytes
    rubric: RubricV21
    baseline: CanonicalBaselineV21 | None
    requests: dict[str, EvaluatorRequestV21]
    responses: dict[str, EvaluatorResponseV21]


def _error(code: str) -> EvaluationIntegrityError:
    return EvaluationIntegrityError(f"EVALUATOR_V21_{code}")


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
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise _error(f"JSON_MALFORMED:{location}") from error
    _ordinary_json(value, location=location)
    try:
        canonical = canonical_json_bytes(value)
    except (TypeError, ValueError, RecursionError) as error:
        raise _error(f"JSON_MALFORMED:{location}") from error
    if canonical != data:
        raise _error(f"JSON_NONCANONICAL:{location}")
    return value


def _canonical_model(
    value: BaseModel,
    model_type: type[BaseModel],
    *,
    location: str,
    context: Mapping[str, object] | None = None,
) -> BaseModel:
    try:
        python_payload = value.model_dump(mode="python", warnings="error")
        strict_snapshot = model_type.model_validate(
            python_payload, strict=True, context=context
        )
        payload = strict_snapshot.model_dump(mode="json", warnings="error")
        snapshot = model_type.model_validate(payload, context=context)
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
        model = model_type.model_validate(payload, context=context)
    except (TypeError, ValidationError, ValueError, RecursionError) as error:
        raise _error(f"MODEL_INVALID:{location}") from error
    return _canonical_model(
        model,
        model_type,
        location=location,
        context=context,
    )


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
        if type(path) is not str or type(data) is not bytes or path == V21_MANIFEST_PATH:
            raise _error("FILES_INVALID")
        if len(data) > _MAX_JSON_BYTES:
            raise _error(f"JSON_SIZE:{path}")
        _artifact_record(path, data)
        if path.endswith(".json"):
            _parse_canonical_json(data, location=path)
        snapshot[path] = data
    return snapshot


def _manifest_context(
    batches: tuple[OrdinaryGradeBatchV21, ...],
    baseline: CanonicalBaselineV21 | None,
) -> dict[str, object]:
    return {
        "ordinary_grade_batches": batches,
        "contested_requirements": ()
        if baseline is None
        else baseline.contested_requirements,
    }


def _baseline_from_files(files: Mapping[str, bytes]) -> CanonicalBaselineV21 | None:
    data = files.get(V21_BASELINE_PATH)
    if data is None:
        return None
    return cast(
        CanonicalBaselineV21,
        _model_from_file(data, CanonicalBaselineV21, location=V21_BASELINE_PATH),
    )


def _manifest_from_bytes(
    data: bytes, *, baseline: CanonicalBaselineV21 | None
) -> EvaluationManifestV21:
    payload = _parse_canonical_json(data, location=V21_MANIFEST_PATH)
    if type(payload) is not dict:
        raise _error("MANIFEST_INVALID")
    raw = cast(dict[str, object], payload)
    if raw.get("protocol_version") != "2.1":
        raise _error("PROTOCOL")
    raw_batches = raw.get("ordinary_grade_batches")
    if not isinstance(raw_batches, list):
        raise _error("MANIFEST_INVALID")
    try:
        batches = tuple(OrdinaryGradeBatchV21.model_validate(item) for item in raw_batches)
    except (TypeError, ValidationError, ValueError) as error:
        raise _error("MANIFEST_INVALID") from error
    context = _manifest_context(batches, baseline)
    try:
        manifest = EvaluationManifestV21.model_validate(raw, context=context)
    except (TypeError, ValidationError, ValueError, RecursionError) as error:
        raise _error(f"MODEL_INVALID:{V21_MANIFEST_PATH}") from error
    return cast(
        EvaluationManifestV21,
        _canonical_model(
            manifest,
            EvaluationManifestV21,
            location=V21_MANIFEST_PATH,
            context=context,
        ),
    )


def _manifest_fingerprint(manifest: EvaluationManifestV21) -> str:
    payload = manifest.model_dump(mode="json", exclude={"manifest_fingerprint"})
    return sha256_digest(canonical_json_bytes(payload))


def _manifest_bytes(
    manifest: EvaluationManifestV21,
    *,
    baseline: CanonicalBaselineV21 | None,
) -> tuple[EvaluationManifestV21, bytes]:
    snapshot = cast(
        EvaluationManifestV21,
        _canonical_model(
            manifest,
            EvaluationManifestV21,
            location=V21_MANIFEST_PATH,
            context=_manifest_context(manifest.ordinary_grade_batches, baseline),
        ),
    )
    if snapshot.manifest_fingerprint != _manifest_fingerprint(snapshot):
        raise _error("MANIFEST_FINGERPRINT")
    return snapshot, canonical_json_bytes(snapshot.model_dump(mode="json"))


def _with_inventory(
    manifest: EvaluationManifestV21, files: Mapping[str, bytes]
) -> EvaluationManifestV21:
    baseline = _baseline_from_files(files)
    validated = cast(
        EvaluationManifestV21,
        _canonical_model(
            manifest,
            EvaluationManifestV21,
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
        EvaluationManifestV21,
        _canonical_model(
            committed,
            EvaluationManifestV21,
            location="manifest inventory",
            context=_manifest_context(committed.ordinary_grade_batches, baseline),
        ),
    )


def _request_fingerprint(request: EvaluatorRequestV21) -> str:
    return sha256_digest(
        canonical_json_bytes(
            request.model_dump(mode="json", exclude={"request_fingerprint"})
        )
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


def _source_context(envelope: CaseEnvelope) -> dict[str, object]:
    return {source.source_id: source.normalized_text for source in envelope.case.sources}


def _step_from_call(call: EvaluationCallRecordV21) -> _Step:
    return _Step(
        operation=call.operation,
        anonymous_label=call.anonymous_label,
        grader_lane=call.grader_lane,
        dispute_id=call.dispute_id,
        batch_ref=call.batch_ref,
        contested_requirement_id=call.contested_requirement_id,
    )


def _grade_steps(
    batches: tuple[OrdinaryGradeBatchV21, ...],
    contested: tuple[ContestedRequirementV21, ...],
    labels: tuple[Literal["A", "B"], ...],
) -> tuple[_Step, ...]:
    return tuple(
        step
        for label in labels
        for lane in cast(tuple[Literal[1, 2], ...], (1, 2))
        for step in (
            *(
                _Step(
                    EvaluatorOperationV21.ORDINARY_GRADE_FRAGMENT,
                    anonymous_label=label,
                    grader_lane=lane,
                    batch_ref=batch.batch_ref,
                )
                for batch in batches
                if batch.batch_ref.startswith(f"GB-{label}-{lane}-")
            ),
            *(
                _Step(
                    EvaluatorOperationV21.CONTESTED_GRADE_FRAGMENT,
                    anonymous_label=label,
                    grader_lane=lane,
                    contested_requirement_id=item.contested_requirement_id,
                )
                for item in contested
            ),
        )
    )


def _expected_batches(
    baseline: CanonicalBaselineV21,
    labels: tuple[Literal["A", "B"], ...],
) -> tuple[OrdinaryGradeBatchV21, ...]:
    return tuple(
        batch
        for label in labels
        for lane in cast(tuple[Literal[1, 2], ...], (1, 2))
        for batch in ordinary_grade_batches(baseline, label, lane)
    )


def _expected_phase(
    manifest: EvaluationManifestV21,
    *,
    accepted_count: int,
    pending: bool,
    referee_end: int,
    total: int,
) -> None:
    if manifest.phase is EvaluationPhaseV21.INCONCLUSIVE_MECHANICAL:
        if pending or accepted_count >= total:
            raise _error("CALL_HISTORY")
        return
    if manifest.phase is EvaluationPhaseV21.CREATED:
        valid = accepted_count == 0 and not pending
    elif manifest.phase is EvaluationPhaseV21.SOURCE_REVIEW:
        valid = accepted_count == 0 and pending
    elif manifest.phase is EvaluationPhaseV21.SOURCE_AUDIT:
        valid = accepted_count == 1 and pending
    elif manifest.phase is EvaluationPhaseV21.SOURCE_REFEREE:
        valid = 2 <= accepted_count < referee_end and pending
    elif manifest.phase is EvaluationPhaseV21.BASELINE_SEALED:
        valid = accepted_count == referee_end and not pending
    elif manifest.phase in {
        EvaluationPhaseV21.ORDINARY_GRADING,
        EvaluationPhaseV21.CONTESTED_GRADING,
    }:
        expected = (
            EvaluatorOperationV21.ORDINARY_GRADE_FRAGMENT
            if manifest.phase is EvaluationPhaseV21.ORDINARY_GRADING
            else EvaluatorOperationV21.CONTESTED_GRADE_FRAGMENT
        )
        valid = (
            referee_end <= accepted_count < total
            and pending
            and bool(manifest.calls)
            and manifest.calls[-1].operation is expected
        )
    elif manifest.phase in {
        EvaluationPhaseV21.AGGREGATE,
        EvaluationPhaseV21.COMPLETED,
        EvaluationPhaseV21.INCONCLUSIVE,
    }:
        valid = accepted_count == total and not pending
    else:
        valid = False
    if not valid:
        raise _error("CALL_HISTORY")


def _expected_request(
    step: _Step,
    *,
    envelope: CaseEnvelope,
    review: SourceReviewV21 | None,
    disputes: tuple[RefereeDisputeV21, ...],
    baseline: CanonicalBaselineV21 | None,
    rubric: RubricV21,
    batches: tuple[OrdinaryGradeBatchV21, ...],
) -> EvaluatorRequestV21:
    try:
        if step.operation is EvaluatorOperationV21.SOURCE_REVIEW:
            return build_source_review_request_v21(envelope)
        if step.operation is EvaluatorOperationV21.SOURCE_AUDIT:
            if review is None:
                raise ValueError("review unavailable")
            return build_source_audit_request_v21(envelope, review)
        if step.operation is EvaluatorOperationV21.SOURCE_REFEREE_FRAGMENT:
            referee_matches = [
                item for item in disputes if item.dispute_id == step.dispute_id
            ]
            if len(referee_matches) != 1:
                raise ValueError("dispute unavailable")
            return build_source_referee_fragment_request(
                envelope,
                referee_matches[0],
                controller_disputes=disputes,
            )
        if baseline is None or step.anonymous_label is None or step.grader_lane is None:
            raise ValueError("grade context unavailable")
        report_text = _report_text(envelope, step.anonymous_label)
        if step.operation is EvaluatorOperationV21.ORDINARY_GRADE_FRAGMENT:
            batch_matches = [item for item in batches if item.batch_ref == step.batch_ref]
            if len(batch_matches) != 1:
                raise ValueError("batch unavailable")
            return build_ordinary_grade_request_v21(
                baseline,
                batch_matches[0],
                step.anonymous_label,
                step.grader_lane,
                report_text,
                _source_context(envelope),
                rubric,
            )
        requirement_matches = [
            item
            for item in baseline.contested_requirements
            if item.contested_requirement_id == step.contested_requirement_id
        ]
        if len(requirement_matches) != 1:
            raise ValueError("contested requirement unavailable")
        return build_contested_grade_request_v21(
            baseline,
            requirement_matches[0],
            step.anonymous_label,
            step.grader_lane,
            report_text,
            _source_context(envelope),
            rubric,
        )
    except (CompilationError, RubricValidationError, TypeError, ValueError) as error:
        raise _error("CALL_REQUEST_BINDING") from error


def _audit_payload(
    payload: object, request: EvaluatorRequestV21
) -> SourceAuditV21:
    indexed = request.payload.get("indexed_proposals")
    if not isinstance(indexed, list):
        raise _error("CALL_RESPONSE_BINDING")
    try:
        proposals = tuple(IndexedProposalV2.model_validate(item) for item in indexed)
        return SourceAuditV21.validate_for_indexed_proposals(payload, proposals)
    except (TypeError, ValidationError, ValueError, RecursionError) as error:
        raise _error("CALL_RESPONSE_BINDING") from error


def _validate_response_payload(
    step: _Step,
    response: EvaluatorResponseV21,
    *,
    request: EvaluatorRequestV21,
    envelope: CaseEnvelope,
    disputes: tuple[RefereeDisputeV21, ...],
    baseline: CanonicalBaselineV21 | None,
) -> object:
    try:
        if step.operation is EvaluatorOperationV21.SOURCE_REVIEW:
            return SourceReviewV21.model_validate(response.payload)
        if step.operation is EvaluatorOperationV21.SOURCE_AUDIT:
            return _audit_payload(response.payload, request)
        if step.operation is EvaluatorOperationV21.SOURCE_REFEREE_FRAGMENT:
            matches = [item for item in disputes if item.dispute_id == step.dispute_id]
            if len(matches) != 1:
                raise ValueError("dispute unavailable")
            decision = RefereeDecisionV21.validate_for_dispute(
                response.payload, matches[0]
            )
            return validate_referee_fragment(
                matches[0],
                decision,
                response_fingerprint=sha256_digest(
                    canonical_json_bytes(response.model_dump(mode="json"))
                ),
            )
        if baseline is None or step.anonymous_label is None:
            raise ValueError("grade context unavailable")
        fragment = validate_grade_fragment_v21(
            baseline,
            response.payload,
            _report_text(envelope, step.anonymous_label),
        )
        if step.operation is EvaluatorOperationV21.ORDINARY_GRADE_FRAGMENT:
            if not isinstance(fragment, OrdinaryGradeFragmentV21) or (
                fragment.anonymous_label,
                fragment.grader_lane,
                fragment.batch_ref,
            ) != (step.anonymous_label, step.grader_lane, step.batch_ref):
                raise _error("CALL_RESPONSE_BINDING")
        elif not isinstance(fragment, ContestedGradeFragmentV21) or (
            fragment.anonymous_label,
            fragment.grader_lane,
            fragment.contested_requirement_id,
        ) != (
            step.anonymous_label,
            step.grader_lane,
            step.contested_requirement_id,
        ):
            raise _error("CALL_RESPONSE_BINDING")
        return fragment
    except EvaluationIntegrityError:
        raise
    except (
        CompilationError,
        RubricValidationError,
        TypeError,
        ValidationError,
        ValueError,
        RecursionError,
    ) as error:
        raise _error("CALL_RESPONSE_BINDING") from error


def _comparison(
    sensitivities: tuple[SensitivityRecordV21, ...]
) -> ComparisonResultV2 | None:
    if len(sensitivities) == 1:
        return None
    first, second = sensitivities
    if (
        first.absolute_disposition is AbsoluteDispositionV2.INCONCLUSIVE
        or second.absolute_disposition is AbsoluteDispositionV2.INCONCLUSIVE
    ):
        return ComparisonResultV2(
            disposition=ComparisonDispositionV2.INCONCLUSIVE,
            rationale="At least one report is inconclusive.",
        )
    if (
        first.absolute_disposition is AbsoluteDispositionV2.PASS
        and second.absolute_disposition is AbsoluteDispositionV2.FAIL
    ):
        return ComparisonResultV2(
            disposition=ComparisonDispositionV2.CANDIDATE_WIN,
            winner_label="A",
            rationale="Only the candidate report passed the rubric.",
        )
    if (
        first.absolute_disposition is AbsoluteDispositionV2.FAIL
        and second.absolute_disposition is AbsoluteDispositionV2.PASS
    ):
        return ComparisonResultV2(
            disposition=ComparisonDispositionV2.COMPARATOR_WIN,
            winner_label="B",
            rationale="Only the comparator report passed the rubric.",
        )
    if first.absolute_disposition is AbsoluteDispositionV2.FAIL:
        return ComparisonResultV2(
            disposition=ComparisonDispositionV2.NEITHER,
            rationale="Neither report passed the rubric.",
        )
    return ComparisonResultV2(
        disposition=ComparisonDispositionV2.TIE,
        rationale="Both reports passed the rubric.",
    )


def _verify_snapshot(
    manifest: EvaluationManifestV21,
    files: Mapping[str, bytes],
) -> _Replay:
    try:
        envelope = cast(
            CaseEnvelope,
            _model_from_file(files[V21_CASE_PATH], CaseEnvelope, location=V21_CASE_PATH),
        )
        build = _parse_canonical_json(files[V21_BUILD_PATH], location=V21_BUILD_PATH)
        rubric = cast(
            RubricV21,
            _model_from_file(
                files[V21_RUBRIC_PATH], RubricV21, location=V21_RUBRIC_PATH
            ),
        )
    except (KeyError, EvaluationIntegrityError) as error:
        raise _error("CASE_BUILD_BINDING") from error
    if (
        sha256_digest(files[V21_CASE_PATH]) != manifest.case_envelope_hash
        or envelope.case_fingerprint != manifest.case_fingerprint
        or type(build) is not dict
        or sha256_digest(files[V21_BUILD_PATH]) != manifest.build_fingerprint
        or sha256_digest(files[V21_RUBRIC_PATH]) != manifest.rubric_fingerprint
    ):
        raise _error("CASE_BUILD_BINDING")
    labels = _labels(envelope)
    baseline = _baseline_from_files(files)
    context = _manifest_context(manifest.ordinary_grade_batches, baseline)
    manifest = cast(
        EvaluationManifestV21,
        _canonical_model(
            manifest,
            EvaluationManifestV21,
            location=V21_MANIFEST_PATH,
            context=context,
        ),
    )
    if manifest.protocol_version != "2.1":
        raise _error("PROTOCOL")

    requests: dict[str, EvaluatorRequestV21] = {}
    responses: dict[str, EvaluatorResponseV21] = {}
    request_paths: set[str] = set()
    response_paths: set[str] = set()
    for call in manifest.calls:
        if call.request_artifact_path in request_paths:
            raise _error("CALL_HISTORY")
        request_paths.add(call.request_artifact_path)
        try:
            request = cast(
                EvaluatorRequestV21,
                _model_from_file(
                    files[call.request_artifact_path],
                    EvaluatorRequestV21,
                    location=call.request_artifact_path,
                ),
            )
        except KeyError as error:
            raise _error("CALL_REQUEST_MISSING") from error
        try:
            request = validate_evaluator_request_v21(request)
        except ValueError as error:
            raise _error("CALL_REQUEST_BINDING") from error
        if (
            request.operation is not call.operation
            or request.request_fingerprint != call.request_fingerprint
            or _request_fingerprint(request) != call.request_fingerprint
        ):
            raise _error("CALL_REQUEST_BINDING")
        requests[call.call_id] = request
        if call.state == "pending":
            continue
        if call.response_artifact_path is None or call.response_fingerprint is None:
            raise _error("CALL_RESPONSE_MISSING")
        if call.response_artifact_path in response_paths:
            raise _error("CALL_HISTORY")
        response_paths.add(call.response_artifact_path)
        try:
            response_data = files[call.response_artifact_path]
        except KeyError as error:
            raise _error("CALL_RESPONSE_MISSING") from error
        if sha256_digest(response_data) != call.response_fingerprint:
            raise _error("CALL_RESPONSE_HASH")
        response = cast(
            EvaluatorResponseV21,
            _model_from_file(
                response_data,
                EvaluatorResponseV21,
                location=call.response_artifact_path,
            ),
        )
        try:
            response = validate_evaluator_response_v21(response)
        except ValueError as error:
            raise _error("CALL_RESPONSE_BINDING") from error
        if (
            response.operation is not call.operation
            or response.request_fingerprint != call.request_fingerprint
            or response.provider_name != call.provider_name
            or response.model_name != call.model_name
            or response.judge_isolation is not call.judge_isolation
        ):
            raise _error("CALL_RESPONSE_BINDING")
        responses[call.call_id] = response

    accepted = tuple(call for call in manifest.calls if call.state == "accepted")
    pending_calls = tuple(call for call in manifest.calls if call.state == "pending")
    if manifest.calls != (*accepted, *pending_calls) or len(pending_calls) > 1:
        raise _error("CALL_HISTORY")

    review: SourceReviewV21 | None = None
    audit: SourceAuditV21 | None = None
    reconstructed_disputes: tuple[RefereeDisputeV21, ...] = ()
    referee_fragments: list[AcceptedRefereeFragmentV21] = []
    accepted_grade_fragments: dict[
        _Step, OrdinaryGradeFragmentV21 | ContestedGradeFragmentV21
    ] = {}
    for call in accepted:
        step = _step_from_call(call)
        expected_request = _expected_request(
            step,
            envelope=envelope,
            review=review,
            disputes=reconstructed_disputes,
            baseline=baseline,
            rubric=rubric,
            batches=manifest.ordinary_grade_batches,
        )
        if requests[call.call_id] != expected_request:
            raise _error("CALL_REQUEST_BINDING")
        payload = _validate_response_payload(
            step,
            responses[call.call_id],
            request=requests[call.call_id],
            envelope=envelope,
            disputes=reconstructed_disputes,
            baseline=baseline,
        )
        if step.operation is EvaluatorOperationV21.SOURCE_REVIEW:
            review = cast(SourceReviewV21, payload)
        elif step.operation is EvaluatorOperationV21.SOURCE_AUDIT:
            audit = cast(SourceAuditV21, payload)
            assert review is not None
            try:
                reconstructed_disputes = build_referee_disputes(envelope, review, audit)
            except (CompilationError, TypeError, ValueError) as error:
                raise _error("REFEREE_INVENTORY") from error
        elif step.operation is EvaluatorOperationV21.SOURCE_REFEREE_FRAGMENT:
            referee_fragments.append(cast(AcceptedRefereeFragmentV21, payload))
        else:
            accepted_grade_fragments[step] = cast(
                OrdinaryGradeFragmentV21 | ContestedGradeFragmentV21, payload
            )

    if audit is None:
        if manifest.referee_disputes:
            raise _error("REFEREE_INVENTORY")
    elif manifest.referee_disputes != reconstructed_disputes:
        raise _error("REFEREE_INVENTORY")

    source_steps = (
        _Step(EvaluatorOperationV21.SOURCE_REVIEW),
        _Step(EvaluatorOperationV21.SOURCE_AUDIT),
        *(
            _Step(
                EvaluatorOperationV21.SOURCE_REFEREE_FRAGMENT,
                dispute_id=item.dispute_id,
            )
            for item in reconstructed_disputes
        ),
    )
    expected_batches: tuple[OrdinaryGradeBatchV21, ...] = ()
    grade_steps: tuple[_Step, ...] = ()
    if baseline is not None:
        expected_batches = _expected_batches(baseline, labels)
        if manifest.ordinary_grade_batches != expected_batches:
            raise _error("GRADE_BATCH_INVENTORY")
        grade_steps = _grade_steps(
            expected_batches, baseline.contested_requirements, labels
        )
    elif manifest.ordinary_grade_batches:
        raise _error("GRADE_BATCH_INVENTORY")
    expected_steps = (*source_steps, *grade_steps)
    if tuple(_step_from_call(call) for call in manifest.calls) != expected_steps[
        : len(manifest.calls)
    ]:
        raise _error("CALL_HISTORY")
    if len(manifest.calls) > len(expected_steps):
        raise _error("CALL_HISTORY")
    accepted_count = len(accepted)
    pending = bool(pending_calls)
    referee_end = len(source_steps)
    _expected_phase(
        manifest,
        accepted_count=accepted_count,
        pending=pending,
        referee_end=referee_end,
        total=len(expected_steps),
    )

    if pending_calls:
        pending_call = pending_calls[0]
        expected = _expected_request(
            _step_from_call(pending_call),
            envelope=envelope,
            review=review,
            disputes=reconstructed_disputes,
            baseline=baseline,
            rubric=rubric,
            batches=manifest.ordinary_grade_batches,
        )
        if requests[pending_call.call_id] != expected:
            raise _error("CALL_REQUEST_BINDING")

    bound = {
        V21_CASE_PATH,
        V21_BUILD_PATH,
        V21_RUBRIC_PATH,
        *request_paths,
        *response_paths,
    }
    orphan_requests = [
        path
        for path in files
        if path.startswith("requests/") and path not in request_paths
    ]
    orphan_responses = [
        path
        for path in files
        if path.startswith("responses/") and path not in response_paths
    ]
    if orphan_responses:
        raise _error("UNBOUND_RESPONSE")
    if manifest.phase is EvaluationPhaseV21.INCONCLUSIVE_MECHANICAL:
        if len(orphan_requests) != 1 or accepted_count >= len(expected_steps):
            raise _error("UNBOUND_REQUEST")
        orphan_path = orphan_requests[0]
        request = cast(
            EvaluatorRequestV21,
            _model_from_file(
                files[orphan_path], EvaluatorRequestV21, location=orphan_path
            ),
        )
        expected = _expected_request(
            expected_steps[accepted_count],
            envelope=envelope,
            review=review,
            disputes=reconstructed_disputes,
            baseline=baseline,
            rubric=rubric,
            batches=manifest.ordinary_grade_batches,
        )
        if (
            request != expected
            or request.request_fingerprint != _request_fingerprint(request)
        ):
            raise _error("UNBOUND_REQUEST")
        bound.add(orphan_path)
    elif orphan_requests:
        raise _error("UNBOUND_REQUEST")

    source_complete = accepted_count >= referee_end
    referee_aggregate: RefereeAggregateV21 | None = None
    if source_complete:
        if len(referee_fragments) != len(reconstructed_disputes):
            raise _error("REFEREE_AGGREGATE")
        try:
            expected_referee = aggregate_referee_decisions(
                reconstructed_disputes,
                tuple(referee_fragments),
            )
            referee_aggregate = RefereeAggregateV21.validate_for_disputes(
                _parse_canonical_json(
                    files[V21_REFEREE_AGGREGATE_PATH],
                    location=V21_REFEREE_AGGREGATE_PATH,
                ),
                reconstructed_disputes,
            )
        except (KeyError, CompilationError, TypeError, ValueError) as error:
            raise _error("REFEREE_AGGREGATE") from error
        if (
            referee_aggregate != expected_referee
            or manifest.referee_aggregate_fingerprint
            != expected_referee.aggregate_fingerprint
        ):
            raise _error("REFEREE_AGGREGATE")
        bound.add(V21_REFEREE_AGGREGATE_PATH)
        if review is None or audit is None or baseline is None:
            raise _error("BASELINE_FINGERPRINT")
        try:
            expected_baseline = compile_baseline_v21(
                envelope, review, audit, expected_referee
            )
        except CompilationError as error:
            raise _error("BASELINE_FINGERPRINT") from error
        if (
            baseline != expected_baseline
            or manifest.baseline_fingerprint != expected_baseline.baseline_fingerprint
        ):
            raise _error("BASELINE_FINGERPRINT")
        bound.add(V21_BASELINE_PATH)
    elif any(
        value is not None
        for value in (
            manifest.referee_aggregate_fingerprint,
            manifest.baseline_fingerprint,
        )
    ) or V21_REFEREE_AGGREGATE_PATH in files or V21_BASELINE_PATH in files:
        raise _error("BASELINE_UNEXPECTED")

    lane_aggregates: list[GraderAggregateV21] = []
    reconciliations = []
    sensitivities: list[SensitivityRecordV21] = []
    expected_aggregate_fingerprints: list[str] = []
    expected_sensitivity_fingerprints: list[str] = []
    if baseline is not None and source_complete:
        for label in labels:
            label_aggregates: list[GraderAggregateV21] = []
            for lane in cast(tuple[Literal[1, 2], ...], (1, 2)):
                lane_batches = ordinary_grade_batches(baseline, label, lane)
                ordinary_steps = tuple(
                    _Step(
                        EvaluatorOperationV21.ORDINARY_GRADE_FRAGMENT,
                        anonymous_label=label,
                        grader_lane=lane,
                        batch_ref=item.batch_ref,
                    )
                    for item in lane_batches
                )
                contested_steps = tuple(
                    _Step(
                        EvaluatorOperationV21.CONTESTED_GRADE_FRAGMENT,
                        anonymous_label=label,
                        grader_lane=lane,
                        contested_requirement_id=item.contested_requirement_id,
                    )
                    for item in baseline.contested_requirements
                )
                lane_steps = (*ordinary_steps, *contested_steps)
                if lane_steps and all(step in accepted_grade_fragments for step in lane_steps):
                    try:
                        expected_aggregate = aggregate_grader_lane(
                            baseline,
                            label,
                            lane,
                            tuple(
                                cast(
                                    OrdinaryGradeFragmentV21,
                                    accepted_grade_fragments[step],
                                )
                                for step in ordinary_steps
                            ),
                            tuple(
                                cast(
                                    ContestedGradeFragmentV21,
                                    accepted_grade_fragments[step],
                                )
                                for step in contested_steps
                            ),
                        )
                        path = f"aggregates/grade-{label}-{lane}.json"
                        stored = cast(
                            GraderAggregateV21,
                            _model_from_file(
                                files[path],
                                GraderAggregateV21,
                                location=path,
                                context={
                                    "ordinary_grade_batches": lane_batches,
                                    "contested_requirements": baseline.contested_requirements,
                                },
                            ),
                        )
                    except (
                        KeyError,
                        RubricValidationError,
                        EvaluationIntegrityError,
                    ) as error:
                        raise _error("GRADER_AGGREGATE") from error
                    if stored != expected_aggregate:
                        raise _error("GRADER_AGGREGATE")
                    label_aggregates.append(expected_aggregate)
                    lane_aggregates.append(expected_aggregate)
                    expected_aggregate_fingerprints.append(
                        expected_aggregate.aggregate_fingerprint
                    )
                    bound.add(path)
                elif any(step in accepted_grade_fragments for step in lane_steps):
                    path = f"aggregates/grade-{label}-{lane}.json"
                    if path in files:
                        raise _error("GRADER_AGGREGATE_PARTIAL")
            if len(label_aggregates) == 2:
                try:
                    reconciliation = reconcile_grader_lanes(
                        baseline,
                        label_aggregates[0],
                        label_aggregates[1],
                        rubric,
                    )
                    expected_sensitivity = evaluate_outcome_sensitivity(
                        baseline, reconciliation, rubric
                    )
                    path = f"sensitivities/{label}.json"
                    stored_sensitivity = cast(
                        SensitivityRecordV21,
                        _model_from_file(
                            files[path], SensitivityRecordV21, location=path
                        ),
                    )
                except (
                    KeyError,
                    RubricValidationError,
                    EvaluationIntegrityError,
                ) as error:
                    raise _error("SENSITIVITY") from error
                if stored_sensitivity != expected_sensitivity:
                    raise _error("SENSITIVITY")
                reconciliations.append(reconciliation)
                sensitivities.append(expected_sensitivity)
                expected_sensitivity_fingerprints.append(
                    expected_sensitivity.sensitivity_fingerprint
                )
                bound.add(path)
    if tuple(expected_aggregate_fingerprints) != manifest.grader_aggregate_fingerprints:
        raise _error("GRADER_AGGREGATE")
    if tuple(expected_sensitivity_fingerprints) != manifest.sensitivity_fingerprints:
        raise _error("SENSITIVITY")

    terminal = manifest.terminal_status
    result: EvaluationResultV21 | None = None
    if terminal in {
        EvaluationTerminalStatusV21.COMPLETED,
        EvaluationTerminalStatusV21.INCONCLUSIVE,
    }:
        if baseline is None or len(sensitivities) != len(labels):
            raise _error("RESULT_REQUIRED")
        expected_reports: list[ReportResultV21] = []
        for label, reconciliation, sensitivity in zip(
            labels, reconciliations, sensitivities, strict=True
        ):
            report_payload: dict[str, object] = {
                "anonymous_label": label,
                "reconciliation": reconciliation.model_dump(mode="json"),
                "sensitivity": sensitivity.model_dump(mode="json"),
            }
            expected_reports.append(
                ReportResultV21(
                    anonymous_label=label,
                    reconciliation=reconciliation,
                    sensitivity=sensitivity,
                    result_fingerprint=sha256_digest(
                        canonical_json_bytes(report_payload)
                    ),
                )
            )
        expected_terminal = (
            EvaluationTerminalStatusV21.INCONCLUSIVE
            if any(
                item.absolute_disposition is AbsoluteDispositionV2.INCONCLUSIVE
                for item in sensitivities
            )
            else EvaluationTerminalStatusV21.COMPLETED
        )
        if terminal is not expected_terminal:
            raise _error("RESULT_TERMINAL")
        comparison = _comparison(tuple(sensitivities))
        result_payload: dict[str, object] = {
            "schema_version": "2.1",
            "rubric": rubric.model_dump(mode="json"),
            "baseline": baseline.model_dump(mode="json"),
            "reports": [item.model_dump(mode="json") for item in expected_reports],
            "comparison": None
            if comparison is None
            else comparison.model_dump(mode="json"),
            "terminal_status": terminal.value,
        }
        result = EvaluationResultV21(
            schema_version="2.1",
            rubric=rubric,
            baseline=baseline,
            reports=tuple(expected_reports),
            comparison=comparison,
            terminal_status=terminal,
            result_fingerprint=sha256_digest(canonical_json_bytes(result_payload)),
        )
        try:
            stored_result = files[V21_RESULT_PATH]
            _parse_canonical_json(stored_result, location=V21_RESULT_PATH)
        except (KeyError, EvaluationIntegrityError) as error:
            raise _error("RESULT_REQUIRED") from error
        if (
            stored_result
            != canonical_json_bytes(result.model_dump(mode="json", warnings="error"))
            or manifest.result_hash != result.result_fingerprint
        ):
            raise _error("RESULT_BINDING")
        bound.add(V21_RESULT_PATH)
    elif manifest.result_hash is not None or V21_RESULT_PATH in files:
        raise _error("RESULT_TERMINAL")

    if manifest.phase is EvaluationPhaseV21.INCONCLUSIVE_MECHANICAL:
        try:
            terminal_reason = files["terminal-reason.json"]
        except KeyError as error:
            raise _error("TERMINAL_REASON") from error
        if _parse_canonical_json(
            terminal_reason, location="terminal-reason.json"
        ) != {"reason": "MECHANICAL_RESPONSE_INVALID"}:
            raise _error("TERMINAL_REASON")
        bound.add("terminal-reason.json")

    extras = set(files) - bound
    if extras:
        if any(path == V21_RESULT_PATH or path.startswith("results/") for path in extras):
            raise _error("RESULT_UNBOUND")
        if any(path.startswith("responses/") for path in extras):
            raise _error("UNBOUND_RESPONSE")
        if any(path.startswith("requests/") for path in extras):
            raise _error("UNBOUND_REQUEST")
        raise _error("UNBOUND_ARTIFACT")
    return _Replay(
        manifest,
        result,
        envelope,
        files[V21_CASE_PATH],
        rubric,
        baseline,
        requests,
        responses,
    )


def _verify_or_raise(storage: RunStorage) -> _Replay:
    storage.assert_root_identity()
    initial_inventory = storage.scan_inventory()
    paths = {path for path in initial_inventory if not path.endswith("/")}
    if V21_MANIFEST_PATH not in paths:
        raise _error("MANIFEST_MISSING")
    provisional_files: dict[str, bytes] = {}
    baseline_data = storage.read_optional_artifact(
        V21_BASELINE_PATH, max_bytes=_MAX_JSON_BYTES
    )
    baseline = None
    if baseline_data is not None:
        provisional_files[V21_BASELINE_PATH] = baseline_data
        baseline = _baseline_from_files(provisional_files)
    manifest = _manifest_from_bytes(
        storage.read_artifact(V21_MANIFEST_PATH, max_bytes=_MAX_JSON_BYTES),
        baseline=baseline,
    )
    if manifest.manifest_fingerprint != _manifest_fingerprint(manifest):
        raise _error("MANIFEST_FINGERPRINT")
    expected = {artifact.artifact_path for artifact in manifest.artifacts} | {
        V21_MANIFEST_PATH
    }
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
        data = storage.read_artifact(
            artifact.artifact_path, max_bytes=_MAX_JSON_BYTES
        )
        if sha256_digest(data) != artifact.artifact_hash:
            raise _error("ARTIFACT_HASH")
        if artifact.artifact_path.endswith(".json"):
            _parse_canonical_json(data, location=artifact.artifact_path)
        files[artifact.artifact_path] = data
    replay = _verify_snapshot(manifest, files)
    if storage.scan_inventory() != initial_inventory:
        raise _error("INVENTORY_CHANGED")
    storage.assert_root_identity()
    return replay


def _commit_with_rollback(
    storage: RunStorage,
    files: Mapping[str, bytes],
    successor: EvaluationManifestV21,
    *,
    expected_manifest_fingerprint: str | None = None,
) -> EvaluationManifestV21:
    snapshot_files = _snapshot_files(files)
    existing = storage.scan_files()
    inherited_files: dict[str, bytes] = {}
    prior_manifest_bytes: bytes | None = None
    if existing:
        replay = _verify_or_raise(storage)
        if (
            expected_manifest_fingerprint is not None
            and replay.manifest.manifest_fingerprint
            != expected_manifest_fingerprint
        ):
            raise EvaluationIntegrityError("EVALUATOR_V21_STALE_TRANSITION")
        for artifact in replay.manifest.artifacts:
            inherited_files[artifact.artifact_path] = storage.read_artifact(
                artifact.artifact_path, max_bytes=_MAX_JSON_BYTES
            )
        prior_manifest_bytes = storage.read_artifact(
            V21_MANIFEST_PATH, max_bytes=_MAX_JSON_BYTES
        )
    for path, data in snapshot_files.items():
        if path in inherited_files and inherited_files[path] != data:
            raise _error("IMMUTABLE_ARTIFACT")
    all_files = {**inherited_files, **snapshot_files}
    committed = _with_inventory(successor, all_files)
    baseline = _baseline_from_files(all_files)
    _, manifest_bytes = _manifest_bytes(committed, baseline=baseline)
    _verify_snapshot(committed, all_files)
    storage.assert_root_identity()
    created: list[str] = []
    try:
        for path in sorted(snapshot_files):
            try:
                created_now = storage.atomic_write(
                    path, snapshot_files[path], mutable=False
                )
            except _AtomicWriteOwnershipError as error:
                if error.created:
                    created.append(path)
                raise
            if created_now:
                created.append(path)
        if any(
            storage.read_artifact(path, max_bytes=_MAX_JSON_BYTES) != data
            for path, data in snapshot_files.items()
        ):
            raise EvaluationIntegrityError("EVALUATOR_V21_STALE_TRANSITION")
        if existing:
            if any(
                storage.read_artifact(path, max_bytes=_MAX_JSON_BYTES) != data
                for path, data in inherited_files.items()
            ):
                raise EvaluationIntegrityError("EVALUATOR_V21_STALE_TRANSITION")
            current_bytes = storage.read_artifact(
                V21_MANIFEST_PATH, max_bytes=_MAX_JSON_BYTES
            )
            current_baseline = _baseline_from_files(inherited_files)
            current = _manifest_from_bytes(current_bytes, baseline=current_baseline)
            if current.manifest_fingerprint != _manifest_fingerprint(current):
                raise _error("MANIFEST_FINGERPRINT")
            if (
                expected_manifest_fingerprint is not None
                and current.manifest_fingerprint
                != expected_manifest_fingerprint
            ):
                raise EvaluationIntegrityError("EVALUATOR_V21_STALE_TRANSITION")
        storage.atomic_write(V21_MANIFEST_PATH, manifest_bytes, mutable=bool(existing))
    except BaseException as error:
        cleanup_error: BaseException | None = None
        restored_manifest = False
        try:
            observed_manifest = storage.read_optional_artifact(
                V21_MANIFEST_PATH, max_bytes=_MAX_JSON_BYTES
            )
            if prior_manifest_bytes is None:
                if observed_manifest == manifest_bytes:
                    storage.remove_artifact(V21_MANIFEST_PATH)
                    restored_manifest = True
                elif observed_manifest is not None:
                    raise _error("ROLLBACK_FAILED")
            elif observed_manifest == manifest_bytes:
                storage.atomic_write(
                    V21_MANIFEST_PATH, prior_manifest_bytes, mutable=True
                )
                if (
                    storage.read_artifact(
                        V21_MANIFEST_PATH, max_bytes=_MAX_JSON_BYTES
                    )
                    != prior_manifest_bytes
                ):
                    raise _error("ROLLBACK_FAILED")
                restored_manifest = True
            elif observed_manifest != prior_manifest_bytes:
                raise _error("ROLLBACK_FAILED")
        except BaseException as cleanup:
            cleanup_error = cleanup
        for path in reversed(created):
            try:
                storage.remove_artifact(path)
            except BaseException as cleanup:
                cleanup_error = cleanup
        if restored_manifest and prior_manifest_bytes is not None:
            try:
                expected_prior = {
                    **inherited_files,
                    V21_MANIFEST_PATH: prior_manifest_bytes,
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


def initialize_v21_run_storage(
    run_dir: Path,
    manifest: EvaluationManifestV21,
    files: Mapping[str, bytes],
) -> EvaluationManifestV21:
    """Create one empty run root and atomically expose its verified first state."""
    with open_evaluation_storage(run_dir, initialize=True) as storage:
        return _commit_with_rollback(storage, files, manifest)


def commit_v21_transition(
    run_dir: Path,
    expected_manifest_fingerprint: str,
    files: Mapping[str, bytes],
    successor: EvaluationManifestV21,
) -> None:
    """Commit one verified successor iff the current manifest root still matches."""
    with open_evaluation_storage(run_dir) as storage:
        current = _verify_or_raise(storage).manifest
        if current.manifest_fingerprint != expected_manifest_fingerprint:
            raise EvaluationIntegrityError("EVALUATOR_V21_STALE_TRANSITION")
        _commit_with_rollback(
            storage,
            files,
            successor,
            expected_manifest_fingerprint=expected_manifest_fingerprint,
        )


def preflight_v21_response(
    run_dir: Path, call_id: str, response: object
) -> V21ResponsePreflight:
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
            validated = validate_evaluator_response_v21(response)
            call = pending[0]
            if (
                validated.operation is not call.operation
                or validated.request_fingerprint != call.request_fingerprint
            ):
                raise _error("RESPONSE_BINDING")
            _validate_response_payload(
                _step_from_call(call),
                validated,
                request=replay.requests[call.call_id],
                envelope=replay.envelope,
                disputes=replay.manifest.referee_disputes,
                baseline=replay.baseline,
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
        return V21ResponsePreflight(False, ("MECHANICAL_RESPONSE_INVALID",))
    return V21ResponsePreflight(True)


def verify_v21_run(run_dir: Path) -> EvaluationVerification:
    """Verify the exact v2.1 inventory, history, bindings, and retained root."""
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


def load_verified_v21_run(
    run_dir: Path,
) -> tuple[EvaluationManifestV21, EvaluationResultV21 | None]:
    """Return protocol-2.1 snapshots only after complete no-follow replay."""
    with open_evaluation_storage(run_dir) as storage:
        replay = _verify_or_raise(storage)
        storage.assert_root_identity()
        return replay.manifest, replay.result


def load_verified_v21_context(run_dir: Path) -> VerifiedV21Context:
    """Return one immutable execution context from one complete verified replay."""
    with open_evaluation_storage(run_dir) as storage:
        replay = _verify_or_raise(storage)
        storage.assert_root_identity()
        return VerifiedV21Context(
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
