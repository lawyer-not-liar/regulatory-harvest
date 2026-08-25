"""Immutable candidate-free source-readiness qualification capsules."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import cast

from pydantic import ValidationError

from regulatory_harvest.storage import canonical_json_bytes, sha256_digest

from .attorney_admission import (
    _deterministic_issues,
    _strict_judgment_snapshot,
    adjudicate_source_record,
    build_admission_request,
    build_source_record,
)
from .attorney_artifacts import (
    EvaluationIntegrityError,
    _artifact_record,
    _load_model_bytes,
    _model_bytes,
    _open_run_storage,
    _parse_json_bytes,
    _RunStorage,
)
from .attorney_contract import PREFLIGHT_ISSUE_MESSAGES, safe_preflight_issue
from .attorney_models import (
    ArtifactRecord,
    CaseAdmissionJudgment,
    CaseReadiness,
    EvaluationPreflightIssue,
    EvaluationPreflightResult,
    JudgeOperation,
    JudgeRequest,
    JudgeResponse,
    QualificationCallRecord,
    QualificationCase,
    QualificationManifest,
    QualificationReceipt,
    QualificationState,
    QualificationSubmissionResult,
    QualificationVerification,
    ReadinessStatus,
    model_fingerprint,
)

_NONCE_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_CASE_PATH = "qualification-case.json"
_REQUEST_PATH = "admission-request.json"
_RESPONSE_PATH = "admission-response.json"
_RECEIPT_PATH = "qualification-receipt.json"
_MANIFEST_PATH = "manifest.json"
_RESPONSE_MAX_DEPTH = 64
_QUALIFICATION_SOURCE_METADATA_FIELDS = frozenset(
    {"build_binding", "language_treatments"}
)


@dataclass(frozen=True)
class _QualificationContext:
    manifest: QualificationManifest
    case: QualificationCase
    request: JudgeRequest
    judgment: CaseAdmissionJudgment
    readiness: CaseReadiness
    response: JudgeResponse | None = None
    response_bytes: bytes | None = None


@dataclass(frozen=True)
class VerifiedQualificationContext:
    """One replay-verified typed snapshot of a terminal qualification capsule."""

    manifest: QualificationManifest
    case: QualificationCase
    receipt: QualificationReceipt
    artifact_bytes: Mapping[str, bytes]


def _strict_case(case: QualificationCase) -> QualificationCase:
    try:
        if case.schema_version == "1.0" and (
            _QUALIFICATION_SOURCE_METADATA_FIELDS & case.model_fields_set
        ):
            raise ValueError("schema 1.0 must omit qualification source metadata")
        return QualificationCase.model_validate(case.model_dump(mode="json"))
    except (AttributeError, TypeError, ValidationError, ValueError) as error:
        raise ValueError("qualification case is invalid") from error


def _manifest(
    *,
    nonce_fingerprint: str,
    case_fingerprint: str,
    source_record_fingerprint: str,
    call: QualificationCallRecord,
    artifacts: list[ArtifactRecord],
    status: str,
    receipt_fingerprint: str | None,
) -> QualificationManifest:
    payload = {
        "schema_version": "1.0",
        "nonce_fingerprint": nonce_fingerprint,
        "case_fingerprint": case_fingerprint,
        "source_record_fingerprint": source_record_fingerprint,
        "call": call.model_dump(mode="json"),
        "artifacts": [
            artifact.model_dump(mode="json")
            for artifact in sorted(artifacts, key=lambda item: item.artifact_path)
        ],
        "status": status,
        "receipt_fingerprint": receipt_fingerprint,
        "root_hash": "0" * 64,
    }
    payload["root_hash"] = sha256_digest(
        canonical_json_bytes({key: value for key, value in payload.items() if key != "root_hash"})
    )
    try:
        return QualificationManifest.model_validate(payload)
    except (TypeError, ValidationError, ValueError) as error:
        raise EvaluationIntegrityError("qualification manifest is invalid") from error


def _state(manifest: QualificationManifest) -> QualificationState:
    return QualificationState(
        case_fingerprint=manifest.case_fingerprint,
        source_record_fingerprint=manifest.source_record_fingerprint,
        request_fingerprint=manifest.call.request_fingerprint,
        status=manifest.status,
        receipt_fingerprint=manifest.receipt_fingerprint,
        root_hash=manifest.root_hash,
    )


def _receipt(
    *,
    case_fingerprint: str,
    source_record_fingerprint: str,
    request_fingerprint: str,
    judgment_fingerprint: str,
    readiness: CaseReadiness,
) -> QualificationReceipt:
    payload = {
        "schema_version": "1.0",
        "case_fingerprint": case_fingerprint,
        "source_record_fingerprint": source_record_fingerprint,
        "request_fingerprint": request_fingerprint,
        "judgment_fingerprint": judgment_fingerprint,
        "readiness": readiness.model_dump(mode="json"),
        "receipt_fingerprint": "0" * 64,
    }
    payload["receipt_fingerprint"] = sha256_digest(
        canonical_json_bytes(
            {key: value for key, value in payload.items() if key != "receipt_fingerprint"}
        )
    )
    return QualificationReceipt.model_validate(payload)


def _load_manifest(storage: _RunStorage) -> tuple[QualificationManifest, bytes]:
    manifest_bytes = storage.read_artifact(_MANIFEST_PATH)
    return _load_model_bytes(
        manifest_bytes,
        QualificationManifest,
        location=_MANIFEST_PATH,
    ), manifest_bytes


def _artifacts_by_path(manifest: QualificationManifest) -> dict[str, ArtifactRecord]:
    return {artifact.artifact_path: artifact for artifact in manifest.artifacts}


def _verify_artifact_hashes(
    storage: _RunStorage,
    manifest: QualificationManifest,
) -> dict[str, bytes]:
    expected_files = {artifact.artifact_path for artifact in manifest.artifacts} | {
        _MANIFEST_PATH
    }
    if set(storage.scan_inventory()) != expected_files:
        raise EvaluationIntegrityError("qualification artifact inventory is not allowlisted")
    data: dict[str, bytes] = {}
    for artifact in manifest.artifacts:
        artifact_bytes = storage.read_artifact(artifact.artifact_path)
        if sha256_digest(artifact_bytes) != artifact.artifact_hash:
            raise EvaluationIntegrityError("qualification artifact hash mismatch")
        data[artifact.artifact_path] = artifact_bytes
    return data


def _verify_in_storage(
    storage: _RunStorage,
) -> tuple[
    QualificationManifest,
    QualificationCase,
    JudgeRequest,
    QualificationReceipt | None,
    dict[str, bytes],
]:
    try:
        manifest, manifest_bytes = _load_manifest(storage)
        data = _verify_artifact_hashes(storage, manifest)
        case = _load_model_bytes(
            data[_CASE_PATH],
            QualificationCase,
            location=_CASE_PATH,
        )
        if model_fingerprint(case) != manifest.case_fingerprint:
            raise EvaluationIntegrityError("qualification case fingerprint mismatch")
        expected_request = _qualification_request(case)
        request = _load_model_bytes(
            data[_REQUEST_PATH],
            JudgeRequest,
            location=_REQUEST_PATH,
        )
        _, expected_request_bytes = _model_bytes(expected_request, JudgeRequest)
        if data[_REQUEST_PATH] != expected_request_bytes or request != expected_request:
            raise EvaluationIntegrityError("qualification admission request does not replay")
        source_record_fingerprint = cast(
            str,
            expected_request.payload["source_record_fingerprint"],
        )
        if source_record_fingerprint != manifest.source_record_fingerprint:
            raise EvaluationIntegrityError("qualification source record fingerprint mismatch")
        if (
            manifest.call.request_fingerprint != request.request_fingerprint
            or manifest.call.request_artifact_path != _REQUEST_PATH
        ):
            raise EvaluationIntegrityError("qualification call does not bind its request")

        receipt: QualificationReceipt | None = None
        if manifest.status == "awaiting-judgment":
            expected_manifest = _manifest(
                nonce_fingerprint=manifest.nonce_fingerprint,
                case_fingerprint=manifest.case_fingerprint,
                source_record_fingerprint=manifest.source_record_fingerprint,
                call=manifest.call,
                artifacts=list(manifest.artifacts),
                status=manifest.status,
                receipt_fingerprint=None,
            )
        else:
            if case.schema_version == "1.1":
                response, _ = _load_response_bytes(
                    data[_RESPONSE_PATH],
                    location=_RESPONSE_PATH,
                )
                if (
                    response.operation is not JudgeOperation.ADMIT_CASE
                    or response.request_fingerprint != request.request_fingerprint
                ):
                    raise EvaluationIntegrityError(
                        "qualification response does not bind its request"
                    )
                judgment = _validate_judgment_value(response.payload)
                if judgment.request_fingerprint != request.request_fingerprint:
                    raise EvaluationIntegrityError(
                        "qualification judgment does not bind its request"
                    )
            else:
                judgment = _load_model_bytes(
                    data[_RESPONSE_PATH],
                    CaseAdmissionJudgment,
                    location=_RESPONSE_PATH,
                )
                judgment = _strict_judgment_snapshot(judgment)
            judgment_fingerprint = model_fingerprint(judgment)
            if manifest.call.judgment_fingerprint != judgment_fingerprint:
                raise EvaluationIntegrityError("qualification call does not bind its judgment")
            readiness = adjudicate_source_record(
                case_fingerprint=manifest.case_fingerprint,
                source_ids={source.source_id for source in case.sources},
                deterministic_issues=_deterministic_issues(case),
                request=request,
                judgment=judgment,
            )
            expected_status = (
                "qualified"
                if readiness.status is ReadinessStatus.ADMITTED
                else "case-invalid"
            )
            if manifest.status != expected_status:
                raise EvaluationIntegrityError("qualification terminal status does not replay")
            receipt = _load_model_bytes(
                data[_RECEIPT_PATH],
                QualificationReceipt,
                location=_RECEIPT_PATH,
            )
            expected_receipt = _receipt(
                case_fingerprint=manifest.case_fingerprint,
                source_record_fingerprint=manifest.source_record_fingerprint,
                request_fingerprint=request.request_fingerprint,
                judgment_fingerprint=judgment_fingerprint,
                readiness=readiness,
            )
            if receipt != expected_receipt or manifest.receipt_fingerprint != (
                receipt.receipt_fingerprint
            ):
                raise EvaluationIntegrityError("qualification receipt does not replay")
            expected_manifest = _manifest(
                nonce_fingerprint=manifest.nonce_fingerprint,
                case_fingerprint=manifest.case_fingerprint,
                source_record_fingerprint=manifest.source_record_fingerprint,
                call=manifest.call,
                artifacts=list(manifest.artifacts),
                status=manifest.status,
                receipt_fingerprint=receipt.receipt_fingerprint,
            )
        if manifest != expected_manifest:
            raise EvaluationIntegrityError("qualification root does not replay")
        storage.assert_root_identity()
        return manifest, case, request, receipt, {_MANIFEST_PATH: manifest_bytes, **data}
    except EvaluationIntegrityError:
        raise
    except (KeyError, TypeError, ValidationError, ValueError) as error:
        raise EvaluationIntegrityError("qualification capsule replay failed") from error


def initialize_case_qualification(
    case: QualificationCase,
    output_dir: Path,
    *,
    nonce_hex: str,
) -> QualificationState:
    """Freeze one candidate-free source record and its sole admission request."""
    if not _NONCE_PATTERN.fullmatch(nonce_hex):
        raise ValueError("nonce_hex must be exactly 64 lowercase hexadecimal characters")
    case = _strict_case(case)
    case, case_bytes = _model_bytes(case, QualificationCase)
    request = _qualification_request(case)
    request, request_bytes = _model_bytes(request, JudgeRequest)
    case_fingerprint = model_fingerprint(case)
    source_record_fingerprint = cast(str, request.payload["source_record_fingerprint"])
    call = QualificationCallRecord(
        request_fingerprint=request.request_fingerprint,
        state="pending",
    )
    artifacts = [
        _artifact_record(_CASE_PATH, case_bytes),
        _artifact_record(_REQUEST_PATH, request_bytes),
    ]
    manifest = _manifest(
        nonce_fingerprint=sha256_digest(nonce_hex.encode("ascii")),
        case_fingerprint=case_fingerprint,
        source_record_fingerprint=source_record_fingerprint,
        call=call,
        artifacts=artifacts,
        status="awaiting-judgment",
        receipt_fingerprint=None,
    )
    with _open_run_storage(output_dir, initialize=True) as storage:
        storage.atomic_write(_CASE_PATH, case_bytes, mutable=False)
        storage.atomic_write(_REQUEST_PATH, request_bytes, mutable=False)
        storage.atomic_write(_MANIFEST_PATH, canonical_json_bytes(manifest), mutable=False)
        storage.assert_root_identity()
    return _state(manifest)


def resume_case_qualification(run_dir: Path) -> QualificationState:
    """Replay every qualification artifact before exposing resumable state."""
    with _open_run_storage(run_dir) as storage:
        manifest, _, _, _, _ = _verify_in_storage(storage)
        return _state(manifest)


def next_qualification_request(run_dir: Path) -> JudgeRequest | None:
    """Return the exact pending request or none after qualification is terminal."""
    with _open_run_storage(run_dir) as storage:
        manifest, _, request, _, _ = _verify_in_storage(storage)
        return request if manifest.status == "awaiting-judgment" else None


def _schema_issue() -> EvaluationPreflightIssue:
    return EvaluationPreflightIssue(
        code="EVALUATION_RESPONSE_SCHEMA_INVALID",
        message=PREFLIGHT_ISSUE_MESSAGES["EVALUATION_RESPONSE_SCHEMA_INVALID"],
    )


def _request_mismatch_issue() -> EvaluationPreflightIssue:
    return EvaluationPreflightIssue(
        code="EVALUATION_RESPONSE_REQUEST_MISMATCH",
        message=PREFLIGHT_ISSUE_MESSAGES["EVALUATION_RESPONSE_REQUEST_MISMATCH"],
    )


def _no_pending_issue() -> EvaluationPreflightIssue:
    return EvaluationPreflightIssue(
        code="EVALUATION_NO_PENDING_REQUEST",
        message=PREFLIGHT_ISSUE_MESSAGES["EVALUATION_NO_PENDING_REQUEST"],
    )


def _preflight_result(
    request: JudgeRequest | None,
    issue: EvaluationPreflightIssue | None = None,
) -> EvaluationPreflightResult:
    issues = [] if issue is None else [issue]
    diagnostic_fingerprint = (
        None
        if request is None or issue is None
        else sha256_digest(
            canonical_json_bytes(
                {
                    "issues": [item.model_dump(mode="json") for item in issues],
                    "operation": request.operation.value,
                    "request_fingerprint": request.request_fingerprint,
                }
            )
        )
    )
    return EvaluationPreflightResult(
        ok=issue is None,
        operation=None if request is None else request.operation,
        request_fingerprint=None if request is None else request.request_fingerprint,
        issues=issues,
        diagnostic_fingerprint=diagnostic_fingerprint,
    )


def _validate_judgment_value(value: object) -> CaseAdmissionJudgment:
    if isinstance(value, CaseAdmissionJudgment):
        return _strict_judgment_snapshot(value)
    if type(value) is not dict:
        raise ValueError("qualification judgment must be an object")
    checks = value.get("checks")
    if type(checks) is not list or any(
        type(check) is not dict
        or type(check.get("satisfied")) is not bool
        or type(check.get("material")) is not bool
        for check in checks
    ):
        raise ValueError("qualification checks must retain strict booleans")
    try:
        return _strict_judgment_snapshot(CaseAdmissionJudgment.model_validate(value))
    except (TypeError, ValidationError, ValueError) as error:
        raise ValueError("qualification judgment schema is invalid") from error


def _qualification_response_schema() -> dict[str, object]:
    """Return the existing response envelope with an admission-judgment payload."""
    outer = JudgeResponse.model_json_schema()
    inner = CaseAdmissionJudgment.model_json_schema()
    outer_definitions = outer.setdefault("$defs", {})
    inner_definitions = inner.pop("$defs", {})
    if not isinstance(outer_definitions, dict) or not isinstance(inner_definitions, dict):
        raise EvaluationIntegrityError("qualification response schema is invalid")
    if set(outer_definitions) & set(inner_definitions):
        raise EvaluationIntegrityError("qualification response schema definitions collide")
    outer_definitions.update(inner_definitions)
    properties = outer.get("properties")
    if not isinstance(properties, dict) or "payload" not in properties:
        raise EvaluationIntegrityError("qualification response schema is invalid")
    properties["payload"] = inner
    return outer


def _qualification_request(case: QualificationCase) -> JudgeRequest:
    """Build the legacy request or schema-1.1 envelope-directed request."""
    request = build_admission_request(build_source_record(case))
    if case.schema_version == "1.0":
        return request
    payload = request.model_dump(mode="json")
    payload["json_schema"] = _qualification_response_schema()
    fingerprint_payload = {
        key: value for key, value in payload.items() if key != "request_fingerprint"
    }
    payload["request_fingerprint"] = sha256_digest(
        canonical_json_bytes(fingerprint_payload)
    )
    try:
        return JudgeRequest.model_validate(payload)
    except (TypeError, ValidationError, ValueError) as error:
        raise EvaluationIntegrityError("qualification request is invalid") from error


def _assert_response_depth(value: object) -> None:
    """Bound nested response containers without recursive serialization."""
    root = value.__dict__ if isinstance(value, JudgeResponse) else value
    pending: list[tuple[object, int, bool]] = [(root, 1, False)]
    active: set[int] = set()
    while pending:
        current, depth, exiting = pending.pop()
        if depth > _RESPONSE_MAX_DEPTH:
            raise ValueError("qualification response exceeds the nesting-depth limit")
        if not isinstance(current, (dict, list, tuple)):
            continue
        identity = id(current)
        if exiting:
            active.remove(identity)
            continue
        if identity in active:
            raise ValueError("qualification response contains a container cycle")
        active.add(identity)
        pending.append((current, depth, True))
        children = current.values() if isinstance(current, dict) else current
        pending.extend((item, depth + 1, False) for item in children)


def _validate_response_value(value: object) -> tuple[JudgeResponse, bytes]:
    if isinstance(value, JudgeResponse):
        try:
            return _model_bytes(value, JudgeResponse)
        except (EvaluationIntegrityError, RecursionError) as error:
            raise ValueError("qualification response schema is invalid") from error
    if type(value) is not dict:
        raise ValueError("qualification response must be an object")
    for key in (
        "schema_version",
        "operation",
        "request_fingerprint",
        "provider_name",
        "model_name",
        "judge_isolation",
    ):
        if not isinstance(value.get(key), str):
            raise ValueError("qualification response metadata must use strict strings")
    response_id = value.get("response_id")
    if response_id is not None and type(response_id) is not str:
        raise ValueError("qualification response_id must be a strict string")
    usage = value.get("usage", {})
    if type(usage) is not dict or any(
        type(key) is not str or type(item) is not int for key, item in usage.items()
    ):
        raise ValueError("qualification response usage must contain strict integers")
    if type(value.get("payload")) is not dict:
        raise ValueError("qualification response payload must be an object")
    try:
        submitted_bytes = canonical_json_bytes(value)
        response = JudgeResponse.model_validate(value)
        response, _ = _model_bytes(response, JudgeResponse)
    except (
        EvaluationIntegrityError,
        RecursionError,
        TypeError,
        ValidationError,
        ValueError,
    ) as error:
        raise ValueError("qualification response schema is invalid") from error
    response_payload = response.model_dump(mode="json")
    supplied_snapshot = {key: response_payload[key] for key in value}
    if canonical_json_bytes(supplied_snapshot) != submitted_bytes:
        raise ValueError("qualification response changed during strict validation")
    return response, submitted_bytes


def _load_response_bytes(
    data: bytes,
    *,
    location: str,
) -> tuple[JudgeResponse, bytes]:
    try:
        payload = _parse_json_bytes(data, location=location)
        _assert_response_depth(payload)
        response, response_bytes = _validate_response_value(payload)
    except RecursionError as error:
        raise EvaluationIntegrityError(
            f"{location} is not a valid JudgeResponse"
        ) from error
    except (TypeError, ValueError) as error:
        raise EvaluationIntegrityError(
            f"{location} is not a valid JudgeResponse"
        ) from error
    if response_bytes != data:
        raise EvaluationIntegrityError(f"{location} changed during strict validation")
    return response, response_bytes


def _preflight_in_storage(
    storage: _RunStorage,
    judgment_value: object,
) -> tuple[EvaluationPreflightResult, _QualificationContext | None]:
    manifest, case, request, _, _ = _verify_in_storage(storage)
    if manifest.status != "awaiting-judgment":
        return _preflight_result(None, _no_pending_issue()), None
    response: JudgeResponse | None = None
    response_bytes: bytes | None = None
    if case.schema_version == "1.1":
        try:
            _assert_response_depth(judgment_value)
            response, response_bytes = _validate_response_value(judgment_value)
        except (RecursionError, TypeError, ValueError):
            return _preflight_result(request, _schema_issue()), None
        if (
            response.operation is not JudgeOperation.ADMIT_CASE
            or response.request_fingerprint != request.request_fingerprint
        ):
            return _preflight_result(request, _request_mismatch_issue()), None
        try:
            judgment = _validate_judgment_value(response.payload)
        except (TypeError, ValueError):
            return _preflight_result(request, _schema_issue()), None
    else:
        try:
            judgment = _validate_judgment_value(judgment_value)
        except (TypeError, ValueError):
            return _preflight_result(request, _schema_issue()), None
    if judgment.request_fingerprint != request.request_fingerprint:
        return _preflight_result(request, _request_mismatch_issue()), None
    try:
        readiness = adjudicate_source_record(
            case_fingerprint=manifest.case_fingerprint,
            source_ids={source.source_id for source in case.sources},
            deterministic_issues=_deterministic_issues(case),
            request=request,
            judgment=judgment,
        )
    except (TypeError, ValidationError, ValueError) as error:
        return _preflight_result(request, safe_preflight_issue(error)), None
    return _preflight_result(request), _QualificationContext(
        manifest,
        case,
        request,
        judgment,
        readiness,
        response,
        response_bytes,
    )


def preflight_case_qualification(
    run_dir: Path,
    judgment_value: object,
) -> EvaluationPreflightResult:
    """Validate the sole qualification judgment without changing any capsule byte."""
    with _open_run_storage(run_dir) as storage:
        result, _ = _preflight_in_storage(storage, judgment_value)
        storage.assert_root_identity()
        return result


def _commit_qualification(
    storage: _RunStorage,
    context: _QualificationContext,
) -> QualificationReceipt:
    judgment, legacy_response_bytes = _model_bytes(
        context.judgment,
        CaseAdmissionJudgment,
    )
    if context.case.schema_version == "1.1":
        if context.response is None or context.response_bytes is None:
            raise EvaluationIntegrityError("schema 1.1 qualification response is absent")
        validated_response, response_bytes = _load_response_bytes(
            context.response_bytes,
            location=_RESPONSE_PATH,
        )
        if validated_response != context.response:
            raise EvaluationIntegrityError("qualification response bytes changed after preflight")
    else:
        if context.response is not None or context.response_bytes is not None:
            raise EvaluationIntegrityError("schema 1.0 qualification response is enveloped")
        response_bytes = legacy_response_bytes
    judgment_fingerprint = model_fingerprint(judgment)
    receipt = _receipt(
        case_fingerprint=context.manifest.case_fingerprint,
        source_record_fingerprint=context.manifest.source_record_fingerprint,
        request_fingerprint=context.request.request_fingerprint,
        judgment_fingerprint=judgment_fingerprint,
        readiness=context.readiness,
    )
    receipt, receipt_bytes = _model_bytes(receipt, QualificationReceipt)
    artifacts = [
        *_artifacts_by_path(context.manifest).values(),
        _artifact_record(_RESPONSE_PATH, response_bytes),
        _artifact_record(_RECEIPT_PATH, receipt_bytes),
    ]
    status = (
        "qualified"
        if context.readiness.status is ReadinessStatus.ADMITTED
        else "case-invalid"
    )
    call = QualificationCallRecord(
        request_fingerprint=context.request.request_fingerprint,
        judgment_fingerprint=judgment_fingerprint,
        response_artifact_path="admission-response.json",
        state="completed",
    )
    manifest = _manifest(
        nonce_fingerprint=context.manifest.nonce_fingerprint,
        case_fingerprint=context.manifest.case_fingerprint,
        source_record_fingerprint=context.manifest.source_record_fingerprint,
        call=call,
        artifacts=artifacts,
        status=status,
        receipt_fingerprint=receipt.receipt_fingerprint,
    )
    storage.atomic_write(_RESPONSE_PATH, response_bytes, mutable=False)
    storage.atomic_write(_RECEIPT_PATH, receipt_bytes, mutable=False)
    storage.atomic_write(_MANIFEST_PATH, canonical_json_bytes(manifest), mutable=True)
    storage.assert_root_identity()
    return receipt


def guarded_submit_case_qualification(
    run_dir: Path,
    judgment_value: object,
) -> QualificationSubmissionResult:
    """Commit one qualification judgment only when one-storage preflight accepts it."""
    with _open_run_storage(run_dir) as storage:
        preflight, context = _preflight_in_storage(storage, judgment_value)
        if context is None:
            storage.assert_root_identity()
            return QualificationSubmissionResult(
                accepted=False,
                preflight=preflight,
            )
        receipt = _commit_qualification(storage, context)
        return QualificationSubmissionResult(
            accepted=True,
            preflight=preflight,
            receipt=receipt,
        )


def submit_case_qualification(
    run_dir: Path,
    judgment: CaseAdmissionJudgment | JudgeResponse,
) -> QualificationReceipt:
    """Seal one valid qualification judgment and return its receipt directly."""
    with _open_run_storage(run_dir) as storage:
        preflight, context = _preflight_in_storage(storage, judgment)
        if context is None:
            if preflight.operation is None:
                raise EvaluationIntegrityError("no pending qualification judgment")
            raise ValueError(preflight.issues[0].message)
        return _commit_qualification(storage, context)


def verify_case_qualification(run_dir: Path) -> QualificationVerification:
    """Replay the full capsule and return only a bounded integrity result."""
    try:
        with _open_run_storage(run_dir) as storage:
            manifest, _, _, _, _ = _verify_in_storage(storage)
            return QualificationVerification(
                valid=True,
                root_hash=manifest.root_hash,
            )
    except EvaluationIntegrityError:
        return QualificationVerification(
            valid=False,
            issues=("QUALIFICATION_INTEGRITY_INVALID",),
        )


def load_verified_qualification_context(run_dir: Path) -> VerifiedQualificationContext:
    """Replay once and return the exact terminal artifacts as a typed context."""
    with _open_run_storage(run_dir) as storage:
        manifest, case, _, receipt, artifact_bytes = _verify_in_storage(storage)
        if receipt is None:
            raise EvaluationIntegrityError("qualification capsule is not terminal")
        return VerifiedQualificationContext(
            manifest=manifest,
            case=case,
            receipt=receipt,
            artifact_bytes=MappingProxyType(dict(sorted(artifact_bytes.items()))),
        )
