"""Atomic, verified local artifacts for evaluator protocol 2.0.

This module deliberately reuses the retained descriptor-anchored storage
implementation.  It only defines the protocol-2.0 manifest namespace and
binding checks; it never changes protocol-1.3 persistence or replay rules.
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import cast

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
from .attorney_protocol import detect_evaluation_protocol as detect_evaluation_protocol
from .attorney_v2_models import (
    CanonicalBaselineV2,
    EvaluationManifestV2,
    EvaluationPhaseV2,
    EvaluationResultV2,
    EvaluationTerminalStatusV2,
    EvaluatorOperationV2,
    EvaluatorRequestV2,
    EvaluatorResponseV2,
    RubricV2,
    evaluator_request_fingerprint,
    validate_evaluator_response_v2,
)

V2_MANIFEST_PATH = "run-manifest.json"
V2_CASE_PATH = "inputs/case.json"
V2_BUILD_PATH = "inputs/build.json"
_MAX_JSON_BYTES = 16 * 1024 * 1024
_MAX_JSON_DEPTH = 64
_CallStep = tuple[EvaluatorOperationV2, str | None]
_CallSignature = tuple[_CallStep, ...]


@dataclass(frozen=True)
class V2ResponsePreflight:
    """A write-free response admission result with public-safe diagnostics."""

    valid: bool
    diagnostics: tuple[str, ...] = ()


def _error(code: str) -> EvaluationIntegrityError:
    return EvaluationIntegrityError(f"EVALUATOR_V2_{code}")


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
    except (AttributeError, TypeError, ValidationError, ValueError, RecursionError) as error:
        raise _error(f"MODEL_INVALID:{location}") from error
    parsed = _parse_canonical_json(encoded, location=location)
    try:
        return model_type.model_validate(parsed, context=context)
    except (TypeError, ValidationError, ValueError) as error:
        raise _error(f"MODEL_INVALID:{location}") from error


def _manifest_fingerprint(manifest: EvaluationManifestV2) -> str:
    payload = manifest.model_dump(mode="json", exclude={"manifest_fingerprint"})
    return sha256_digest(canonical_json_bytes(payload))


def _manifest_bytes(manifest: EvaluationManifestV2) -> tuple[EvaluationManifestV2, bytes]:
    snapshot = cast(
        EvaluationManifestV2,
        _canonical_model(manifest, EvaluationManifestV2, location=V2_MANIFEST_PATH),
    )
    expected = _manifest_fingerprint(snapshot)
    if snapshot.manifest_fingerprint != expected:
        raise _error("MANIFEST_FINGERPRINT")
    return snapshot, canonical_json_bytes(snapshot.model_dump(mode="json"))


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
        if type(path) is not str or type(data) is not bytes or path == V2_MANIFEST_PATH:
            raise _error("FILES_INVALID")
        _artifact_record(path, data)
        if path.endswith(".json"):
            _parse_canonical_json(data, location=path)
        snapshot[path] = data
    return snapshot


def _with_inventory(
    manifest: EvaluationManifestV2, files: Mapping[str, bytes]
) -> EvaluationManifestV2:
    validated = cast(
        EvaluationManifestV2,
        _canonical_model(
            manifest,
            EvaluationManifestV2,
            location="manifest input",
        ),
    )
    inventory = sorted(
        (_artifact_record(path, data) for path, data in files.items()),
        key=lambda x: x.artifact_path,
    )
    candidate = validated.model_copy(
        update={"artifacts": inventory, "manifest_fingerprint": "0" * 64}
    )
    fingerprint = _manifest_fingerprint(candidate)
    return cast(
        EvaluationManifestV2,
        _canonical_model(
            candidate.model_copy(update={"manifest_fingerprint": fingerprint}),
            EvaluationManifestV2,
            location="manifest inventory",
        ),
    )


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
    except (TypeError, ValidationError, ValueError) as error:
        raise _error(f"MODEL_INVALID:{location}") from error
    return _canonical_model(model, model_type, location=location, context=context)


def _terminal_orphan_steps(
    manifest: EvaluationManifestV2, files: Mapping[str, bytes]
) -> set[_CallStep]:
    """Return the sole role a terminal mechanical stop may have left on disk."""
    if manifest.phase is not EvaluationPhaseV2.INCONCLUSIVE:
        return set()
    accepted = tuple(
        (call.operation, call.anonymous_label)
        for call in manifest.calls
        if call.state == "accepted"
    )
    review: _CallStep = (EvaluatorOperationV2.SOURCE_REVIEW, None)
    audit: _CallStep = (EvaluatorOperationV2.SOURCE_AUDIT, None)
    referee: _CallStep = (EvaluatorOperationV2.SOURCE_REFEREE, None)
    grade_a: _CallStep = (EvaluatorOperationV2.GRADE_REPORT, "A")
    grade_b: _CallStep = (EvaluatorOperationV2.GRADE_REPORT, "B")
    base = (review, audit)
    referee_base = (*base, referee)
    if accepted == ():
        return {review}
    if accepted == (review,):
        return {audit}
    if accepted == base:
        return {grade_a} if manifest.baseline_fingerprint is not None else {referee}
    if accepted == referee_base:
        return {grade_a}
    for prefix in (base, referee_base):
        if accepted == (*prefix, grade_a):
            return {grade_a}
        if accepted == (*prefix, grade_a, grade_a):
            try:
                envelope = cast(
                    CaseEnvelope,
                    _model_from_file(
                        files[V2_CASE_PATH], CaseEnvelope, location=V2_CASE_PATH
                    ),
                )
            except (KeyError, EvaluationIntegrityError) as error:
                raise _error("CALL_REQUEST_BINDING") from error
            labels = tuple(item.anonymous_label for item in envelope.assignments)
            return {grade_b} if labels == ("A", "B") else set()
        if accepted == (*prefix, grade_a, grade_a, grade_b):
            return {grade_b}
    return set()


def _require_call_bindings(manifest: EvaluationManifestV2, files: Mapping[str, bytes]) -> None:
    request_paths: set[str] = set()
    response_paths: set[str] = set()
    for call in manifest.calls:
        if call.request_artifact_path not in files:
            raise _error("CALL_REQUEST_MISSING")
        request_paths.add(call.request_artifact_path)
        request = cast(
            EvaluatorRequestV2,
            _model_from_file(
                files[call.request_artifact_path],
                EvaluatorRequestV2,
                location=call.request_artifact_path,
            ),
        )
        if (
            request.operation is not call.operation
            or request.request_fingerprint != call.request_fingerprint
            or evaluator_request_fingerprint(request) != call.request_fingerprint
        ):
            raise _error("CALL_REQUEST_BINDING")
        if call.state == "pending":
            continue
        if call.response_artifact_path is None or call.response_fingerprint is None:
            raise _error("CALL_RESPONSE_MISSING")
        if call.response_artifact_path not in files:
            raise _error("CALL_RESPONSE_MISSING")
        response_paths.add(call.response_artifact_path)
        if sha256_digest(files[call.response_artifact_path]) != call.response_fingerprint:
            raise _error("CALL_RESPONSE_HASH")
        response = validate_evaluator_response_v2(
            _model_from_file(
                files[call.response_artifact_path],
                EvaluatorResponseV2,
                location=call.response_artifact_path,
            )
        )
        if (
            response.operation is not call.operation
            or response.request_fingerprint != call.request_fingerprint
            or response.provider_name != call.provider_name
            or response.model_name != call.model_name
            or response.judge_isolation is not call.judge_isolation
        ):
            raise _error("CALL_RESPONSE_BINDING")
    orphan_requests = [
        path for path in files if path.startswith("requests/") and path not in request_paths
    ]
    if orphan_requests:
        if len(orphan_requests) != 1:
            raise _error("UNBOUND_REQUEST")
        path = orphan_requests[0]
        request = cast(
            EvaluatorRequestV2,
            _model_from_file(files[path], EvaluatorRequestV2, location=path),
        )
        if evaluator_request_fingerprint(request) != request.request_fingerprint:
            raise _error("CALL_REQUEST_BINDING")
        label = request.safe_metadata.get("anonymous_label")
        orphan_step = (request.operation, label if type(label) is str else None)
        if orphan_step not in _terminal_orphan_steps(manifest, files):
            raise _error("UNBOUND_REQUEST")
    if any(path.startswith("responses/") and path not in response_paths for path in files):
        raise _error("UNBOUND_RESPONSE")


def _require_phase_consistency(manifest: EvaluationManifestV2) -> None:
    accepted = [call for call in manifest.calls if call.state == "accepted"]
    pending = [call for call in manifest.calls if call.state == "pending"]
    if manifest.calls != [*accepted, *pending]:
        raise _error("CALL_HISTORY")
    accepted_signature = tuple((call.operation, call.anonymous_label) for call in accepted)
    CallStep = tuple[EvaluatorOperationV2, str | None]
    CallSignature = tuple[CallStep, ...]
    bases: tuple[CallSignature, CallSignature] = (
        (
            (EvaluatorOperationV2.SOURCE_REVIEW, None),
            (EvaluatorOperationV2.SOURCE_AUDIT, None),
        ),
        (
            (EvaluatorOperationV2.SOURCE_REVIEW, None),
            (EvaluatorOperationV2.SOURCE_AUDIT, None),
            (EvaluatorOperationV2.SOURCE_REFEREE, None),
        ),
    )
    grade_a: CallStep = (EvaluatorOperationV2.GRADE_REPORT, "A")
    grade_b: CallStep = (EvaluatorOperationV2.GRADE_REPORT, "B")
    grades: tuple[CallSignature, ...] = (
        (),
        (grade_a,),
        (grade_a, grade_a),
        (grade_a, grade_a, grade_b),
        (grade_a, grade_a, grade_b, grade_b),
    )
    mechanical_stops: set[CallSignature] = {(), bases[0][:1]}
    mechanical_stops.update(base + grade for base in bases for grade in grades)
    exact: dict[EvaluationPhaseV2, set[CallSignature]] = {
        EvaluationPhaseV2.SOURCE_REVIEW: {()},
        EvaluationPhaseV2.SOURCE_AUDIT: {bases[0][:1]},
        EvaluationPhaseV2.SOURCE_REFEREE: {bases[0]},
        EvaluationPhaseV2.BASELINE_SEALED: set(bases),
        EvaluationPhaseV2.GRADE_REPORT: {base + grade for base in bases for grade in grades[:-1]},
        EvaluationPhaseV2.AGGREGATE: {
            base + grade for base in bases for grade in (grades[2], grades[4])
        },
        EvaluationPhaseV2.COMPLETED: {
            base + grade for base in bases for grade in (grades[2], grades[4])
        },
        EvaluationPhaseV2.INCONCLUSIVE: mechanical_stops,
    }
    if accepted_signature not in exact[manifest.phase]:
        raise _error("CALL_HISTORY")
    if (
        manifest.phase is EvaluationPhaseV2.INCONCLUSIVE
        and manifest.result_hash is not None
    ):
        raise _error("RESULT_TERMINAL")
    expected_pending: tuple[EvaluatorOperationV2, str | None] | None = {
        EvaluationPhaseV2.SOURCE_REVIEW: (EvaluatorOperationV2.SOURCE_REVIEW, None),
        EvaluationPhaseV2.SOURCE_AUDIT: (EvaluatorOperationV2.SOURCE_AUDIT, None),
        EvaluationPhaseV2.SOURCE_REFEREE: (EvaluatorOperationV2.SOURCE_REFEREE, None),
    }.get(manifest.phase)
    if manifest.phase is EvaluationPhaseV2.GRADE_REPORT:
        grade_count = len(accepted_signature) - (3 if accepted_signature[:3] == bases[1] else 2)
        expected_pending = (
            EvaluatorOperationV2.GRADE_REPORT,
            ("A", "A", "B", "B")[grade_count],
        )
    if expected_pending is None:
        if pending:
            raise _error("CALL_HISTORY")
    elif (
        len(pending) != 1 or (pending[0].operation, pending[0].anonymous_label) != expected_pending
    ):
        raise _error("CALL_HISTORY")


def _expected_baseline_fingerprint(baseline: CanonicalBaselineV2) -> str:
    payload = {
        "schema_version": "2.0",
        "case_fingerprint": baseline.case_fingerprint,
        "requirements": [item.model_dump(mode="json") for item in baseline.requirements],
        "relationships": [item.model_dump(mode="json") for item in baseline.relationships],
        "unresolved_dispute_ids": list(baseline.unresolved_dispute_ids),
    }
    return sha256_digest(canonical_json_bytes(payload))


def _result_validation_context(baseline: CanonicalBaselineV2) -> dict[str, object]:
    return {
        "requirement_ids": {item.requirement_id for item in baseline.requirements},
        "baseline_fingerprint": baseline.baseline_fingerprint,
    }


def _expected_report_result_fingerprint(report: object) -> str:
    payload = cast(BaseModel, report).model_dump(mode="json", exclude={"result_fingerprint"})
    return sha256_digest(canonical_json_bytes(payload))


def _expected_result_fingerprint(result: EvaluationResultV2) -> str:
    payload = result.model_dump(mode="json", exclude={"result_fingerprint"})
    return sha256_digest(canonical_json_bytes(payload))


def _require_result_bindings(
    result: EvaluationResultV2, baseline: CanonicalBaselineV2
) -> None:
    if result.baseline.model_dump(mode="json") != baseline.model_dump(mode="json"):
        raise _error("RESULT_BASELINE_BINDING")
    if result.result_fingerprint != _expected_result_fingerprint(result):
        raise _error("RESULT_FINGERPRINT")
    for report in result.reports:
        if report.result_fingerprint != _expected_report_result_fingerprint(report):
            raise _error("REPORT_FINGERPRINT")
        if any(
            response.anonymous_label != report.anonymous_label
            or response.baseline_fingerprint != baseline.baseline_fingerprint
            for response in report.reconciliation.grader_responses
        ):
            raise _error("RESULT_REPORT_BINDING")


def _require_named_fingerprints(
    manifest: EvaluationManifestV2, files: Mapping[str, bytes]
) -> EvaluationResultV2 | None:
    try:
        case = cast(
            CaseEnvelope,
            _model_from_file(files[V2_CASE_PATH], CaseEnvelope, location=V2_CASE_PATH),
        )
        build = _parse_canonical_json(files[V2_BUILD_PATH], location=V2_BUILD_PATH)
    except (KeyError, EvaluationIntegrityError) as error:
        raise _error("CASE_BUILD_BINDING") from error
    if (
        sha256_digest(files[V2_CASE_PATH]) != manifest.case_envelope_hash
        or case.case_fingerprint != manifest.case_fingerprint
        or type(build) is not dict
        or sha256_digest(files[V2_BUILD_PATH]) != manifest.build_fingerprint
    ):
        raise _error("CASE_BUILD_BINDING")
    rubric_matches: list[RubricV2] = []
    baselines: list[CanonicalBaselineV2] = []
    baseline_matches: list[CanonicalBaselineV2] = []
    for path, data in files.items():
        if not path.endswith(".json"):
            continue
        try:
            rubric = cast(RubricV2, _model_from_file(data, RubricV2, location=path))
        except EvaluationIntegrityError:
            rubric = None
        if rubric is not None and sha256_digest(data) == manifest.rubric_fingerprint:
            rubric_matches.append(rubric)
        try:
            baseline_candidate = cast(
                CanonicalBaselineV2,
                _model_from_file(data, CanonicalBaselineV2, location=path),
            )
        except EvaluationIntegrityError:
            baseline_candidate = None
        if baseline_candidate is not None:
            if (
                baseline_candidate.case_fingerprint != manifest.case_fingerprint
                or baseline_candidate.baseline_fingerprint
                != _expected_baseline_fingerprint(baseline_candidate)
            ):
                raise _error("BASELINE_FINGERPRINT")
            baselines.append(baseline_candidate)
            if manifest.baseline_fingerprint == baseline_candidate.baseline_fingerprint:
                baseline_matches.append(baseline_candidate)
    if len(rubric_matches) != 1:
        raise _error("RUBRIC_FINGERPRINT")
    baseline: CanonicalBaselineV2 | None = None
    if manifest.baseline_fingerprint is None:
        if baselines:
            raise _error("BASELINE_UNEXPECTED")
    elif len(baselines) != 1 or len(baseline_matches) != 1:
        raise _error("BASELINE_FINGERPRINT")
    else:
        baseline = baseline_matches[0]
    results: list[EvaluationResultV2] = []
    result_matches: list[EvaluationResultV2] = []
    for path, data in files.items():
        if not path.endswith(".json"):
            continue
        payload = _parse_canonical_json(data, location=path)
        if not (
            path == "result.json"
            or path.startswith("result-")
            or path.startswith("results/")
            or (
                type(payload) is dict
                and {"rubric", "baseline", "reports", "result_fingerprint"} <= set(payload)
            )
        ):
            continue
        if baseline is None:
            raise _error("RESULT_BASELINE_BINDING")
        try:
            result = cast(
                EvaluationResultV2,
                _model_from_file(
                    data,
                    EvaluationResultV2,
                    location=path,
                    context=_result_validation_context(baseline),
                ),
            )
        except EvaluationIntegrityError:
            raise
        _require_result_bindings(result, baseline)
        results.append(result)
        if manifest.result_hash == result.result_fingerprint:
            result_matches.append(result)
    terminal = manifest.terminal_status
    if terminal is EvaluationTerminalStatusV2.COMPLETED:
        if manifest.result_hash is None or len(results) != 1 or len(result_matches) != 1:
            raise _error("RESULT_REQUIRED")
        result = result_matches[0]
        if result.rubric.model_dump(mode="json") != rubric_matches[0].model_dump(mode="json"):
            raise _error("RESULT_RUBRIC_BINDING")
        return result
    if manifest.result_hash is not None or results:
        raise _error("RESULT_TERMINAL")
    return None


def _verify_or_raise(storage: RunStorage) -> tuple[EvaluationManifestV2, EvaluationResultV2 | None]:
    storage.assert_root_identity()
    initial_inventory = storage.scan_inventory()
    paths = {path for path in initial_inventory if not path.endswith("/")}
    if V2_MANIFEST_PATH not in paths:
        raise _error("MANIFEST_MISSING")
    manifest = cast(
        EvaluationManifestV2,
        _model_from_file(
            storage.read_artifact(V2_MANIFEST_PATH),
            EvaluationManifestV2,
            location=V2_MANIFEST_PATH,
        ),
    )
    if manifest.protocol_version != "2.0":
        raise _error("PROTOCOL")
    expected = {artifact.artifact_path for artifact in manifest.artifacts} | {V2_MANIFEST_PATH}
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
        data = storage.read_artifact(artifact.artifact_path)
        if sha256_digest(data) != artifact.artifact_hash:
            raise _error("ARTIFACT_HASH")
        if artifact.artifact_path.endswith(".json"):
            _parse_canonical_json(data, location=artifact.artifact_path)
        files[artifact.artifact_path] = data
    _require_call_bindings(manifest, files)
    _require_phase_consistency(manifest)
    result = _require_named_fingerprints(manifest, files)
    if storage.scan_inventory() != initial_inventory:
        raise _error("INVENTORY_CHANGED")
    storage.assert_root_identity()
    return manifest, result


def initialize_v2_run_storage(
    run_dir: Path,
    manifest: EvaluationManifestV2,
    files: Mapping[str, bytes],
) -> EvaluationManifestV2:
    """Create one empty run root and atomically expose its verified first state."""
    with open_evaluation_storage(run_dir, initialize=True) as storage:
        return commit_v2_transition(storage, manifest, files)


def commit_v2_transition(
    storage: RunStorage,
    manifest: EvaluationManifestV2,
    files: Mapping[str, bytes],
) -> EvaluationManifestV2:
    """Preflight every byte, then persist immutable artifacts before the manifest root."""
    if not isinstance(storage, RunStorage):
        raise _error("STORAGE")
    snapshot_files = _snapshot_files(files)
    existing = storage.scan_files()
    inherited_files: dict[str, bytes] = {}
    if existing:
        inherited_manifest, _ = _verify_or_raise(storage)
        for artifact in inherited_manifest.artifacts:
            inherited_files[artifact.artifact_path] = storage.read_artifact(artifact.artifact_path)
        if V2_MANIFEST_PATH not in existing:
            raise _error("INVENTORY")
    for path, data in snapshot_files.items():
        if path in inherited_files and inherited_files[path] != data:
            raise _error("IMMUTABLE_ARTIFACT")
    all_files = {**inherited_files, **snapshot_files}
    committed = _with_inventory(manifest, all_files)
    _manifest_bytes(committed)
    _require_call_bindings(committed, all_files)
    _require_phase_consistency(committed)
    _require_named_fingerprints(committed, all_files)
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
        _, manifest_bytes = _manifest_bytes(committed)
        try:
            storage.atomic_write(
                V2_MANIFEST_PATH, manifest_bytes, mutable=bool(existing)
            )
        except _AtomicWriteOwnershipError as error:
            if error.created and not existing:
                created.append(V2_MANIFEST_PATH)
            raise
    except BaseException as error:
        cleanup_error: BaseException | None = None
        for path in reversed(created):
            try:
                storage.remove_artifact(path)
            except BaseException as cleanup:
                cleanup_error = cleanup
        if cleanup_error is not None:
            raise _error("ROLLBACK_FAILED") from cleanup_error
        raise error
    storage.assert_root_identity()
    return committed


def preflight_v2_response(run_dir: Path, call_id: str, response: object) -> V2ResponsePreflight:
    """Validate one pending response without accepting or persisting any bytes."""
    try:
        with open_evaluation_storage(run_dir) as storage:
            manifest, _ = _verify_or_raise(storage)
            pending = [
                call
                for call in manifest.calls
                if call.call_id == call_id and call.state == "pending"
            ]
            if len(pending) != 1:
                raise _error("PENDING_CALL")
            validated = validate_evaluator_response_v2(response)
            call = pending[0]
            if (
                validated.operation is not call.operation
                or validated.request_fingerprint != call.request_fingerprint
            ):
                raise _error("RESPONSE_BINDING")
            storage.assert_root_identity()
    except (EvaluationIntegrityError, TypeError, ValueError, ValidationError):
        return V2ResponsePreflight(False, ("MECHANICAL_RESPONSE_INVALID",))
    return V2ResponsePreflight(True)


def verify_v2_run(run_dir: Path) -> EvaluationVerification:
    """Verify a v2 manifest, exact inventory, bindings, and retained root identity."""
    try:
        with open_evaluation_storage(run_dir) as storage:
            manifest, _ = _verify_or_raise(storage)
            storage.assert_root_identity()
    except (EvaluationIntegrityError, OSError, TypeError, ValidationError, ValueError) as error:
        return EvaluationVerification(False, (str(error),), None)
    return EvaluationVerification(True, (), manifest.manifest_fingerprint)


def load_verified_v2_run(run_dir: Path) -> tuple[EvaluationManifestV2, EvaluationResultV2 | None]:
    """Return v2 snapshots only after a complete no-follow verification pass."""
    with open_evaluation_storage(run_dir) as storage:
        manifest, result = _verify_or_raise(storage)
        storage.assert_root_identity()
        return manifest, result
