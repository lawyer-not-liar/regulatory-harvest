"""Immutable artifact storage and exact replay for delivery-readiness-v1."""

from __future__ import annotations

import json
import math
import os
import threading
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from types import MappingProxyType
from typing import Literal, TypeVar, cast

from pydantic import ValidationError

from regulatory_harvest.storage import canonical_json_bytes, sha256_digest

from .attorney_artifacts import (
    EvaluationIntegrityError,
    RunStorage,
    _AtomicWriteOwnershipError,
    _NodeIdentity,
    _same_filesystem_object,
    open_evaluation_storage,
)
from .attorney_baseline_artifacts import VerifiedBaselineContextV1
from .attorney_baseline_models import (
    BaselineInputV1,
    BaselineManifestV1,
    BaselineStrictModel,
    BaselineVerificationV1,
    CanonicalBaselineV1,
    GradeableBaselineProjectionV1,
    strict_baseline_model_v1,
)
from .attorney_baseline_projection import verify_gradeable_baseline_projection_v1
from .attorney_models import ArtifactRecord
from .attorney_readiness_compiler import (
    aggregate_baseline_locked_grader_lane_v1,
    compile_gap_follow_up_matrix_v1,
    compile_requirement_matrix_v1,
    derive_baseline_locked_strict_equivalent_v1,
    derive_delivery_readiness_v1,
    reconcile_safety_lanes_v1,
)
from .attorney_readiness_drafts import (
    CompiledReadinessDraftV1,
    ReadinessEvaluatorProvenanceV1,
    compile_readiness_draft_v1,
)
from .attorney_readiness_handoff import render_attorney_review_handoff_v1
from .attorney_readiness_inputs import (
    GenerationCapsuleBindingV1,
    QualificationAdmissionCheckV1,
    QualificationAdmissionIssueV1,
    QualificationLanguageSourceV1,
    QualificationLanguageTreatmentV1,
    QualificationLimitsV1,
    QualificationReadinessBindingV1,
    QualificationReceiptReadinessV1,
    QualificationRequestedAuthorityV1,
    VerifiedReadinessInputsV1,
)
from .attorney_readiness_models import (
    BaselineLockedContestedGradeV1,
    BaselineLockedGradeFragmentV1,
    BaselineLockedGraderAggregateV1,
    BaselineLockedStrictEquivalentV1,
    DeliveryReadinessResultV1,
    GapFollowUpMatrixV1,
    ReadinessCallRecordV1,
    ReadinessEvaluatorRequestV1,
    ReadinessEvaluatorResponseV1,
    ReadinessInputV1,
    ReadinessManifestV1,
    ReadinessOperationV1,
    ReadinessPhaseV1,
    ReadinessVerificationV1,
    ReconciledSafetyReviewV1,
    RequirementMatrixV1,
    SafetyDisputeV1,
    SafetyGapCandidateV1,
    SafetyLaneResponseV1,
    SafetyRefereeDecisionV1,
    load_readiness_rubric_v1,
    validate_readiness_evaluator_request_v1,
    validate_readiness_evaluator_response_v1,
    validate_readiness_input_v1,
    validate_readiness_manifest_v1,
    validate_readiness_verification_v1,
)
from .attorney_readiness_requests import (
    build_baseline_locked_contested_grade_request_v1,
    build_baseline_locked_grade_batches_v1,
    build_baseline_locked_grade_request_v1,
    build_gap_candidate_inventory_v1,
    build_safety_disputes_v1,
    build_safety_lane_request_v1,
    build_safety_referee_request_v1,
)

READINESS_MANIFEST_PATH = "readiness-manifest.json"
READINESS_INPUT_PATH = "readiness-input.json"
READINESS_RUBRIC_PATH = "readiness-rubric.json"
READINESS_VERIFICATION_PATH = "readiness-verification.json"
READINESS_RESULT_PATH = "delivery-readiness.json"
GRADER_LANE_1_PATH = "aggregates/grader-lane-1.json"
GRADER_LANE_2_PATH = "aggregates/grader-lane-2.json"
STRICT_EQUIVALENT_PATH = "baseline-locked-strict-equivalent.json"
HISTORICAL_CROSS_CHECK_PATH = "historical-v22-cross-check.json"
SAFETY_REVIEW_PATH = "aggregates/safety-review.json"
REQUIREMENT_MATRIX_PATH = "requirement-matrix.json"
GAP_MATRIX_PATH = "gap-follow-up-matrix.json"
ATTORNEY_HANDOFF_PATH = "attorney-review-handoff.md"

_MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
_MAX_JSON_DEPTH = 64
_LOCKS_GUARD = threading.Lock()
_RUN_LOCKS: dict[tuple[int, int], threading.RLock] = {}
_ModelT = TypeVar("_ModelT", bound=BaselineStrictModel)
ReadinessRootIdentityV1 = tuple[int, int]

_INTERNAL_CHECKS = (
    "baseline_valid",
    "evaluation_valid",
    "generation_valid",
    "integrity_valid",
    "parity_contract_valid",
    "provenance_valid",
    "qualification_valid",
    "readiness_valid",
    "replay_valid",
    "storage_valid",
)


@dataclass(frozen=True)
class ReadinessResponsePreflightV1:
    """One total, write-free response admission result."""

    valid: bool
    diagnostics: tuple[str, ...] = ()


@dataclass(frozen=True)
class VerifiedReadinessContextV1:
    """Detached typed values derived from one exact readiness replay."""

    manifest: ReadinessManifestV1
    inputs: VerifiedReadinessInputsV1
    pending_request: ReadinessEvaluatorRequestV1 | None
    result: DeliveryReadinessResultV1 | None
    verification: ReadinessVerificationV1 | None
    requests: Mapping[str, ReadinessEvaluatorRequestV1]
    responses: Mapping[str, ReadinessEvaluatorResponseV1]
    grader_lanes: (
        tuple[
            BaselineLockedGraderAggregateV1,
            BaselineLockedGraderAggregateV1,
        ]
        | None
    )
    strict_equivalent: BaselineLockedStrictEquivalentV1 | None
    candidates: tuple[SafetyGapCandidateV1, ...] | None
    safety_lanes: tuple[SafetyLaneResponseV1, ...]
    disputes: tuple[SafetyDisputeV1, ...]
    referee_decisions: tuple[SafetyRefereeDecisionV1, ...]
    safety_review: ReconciledSafetyReviewV1 | None
    requirement_matrix: RequirementMatrixV1 | None
    gap_matrix: GapFollowUpMatrixV1 | None
    handoff: bytes | None
    root_identity: ReadinessRootIdentityV1


@dataclass(frozen=True)
class _Replay:
    manifest: ReadinessManifestV1
    inputs: VerifiedReadinessInputsV1
    pending_request: ReadinessEvaluatorRequestV1 | None
    result: DeliveryReadinessResultV1 | None
    verification: ReadinessVerificationV1 | None
    requests: Mapping[str, ReadinessEvaluatorRequestV1]
    responses: Mapping[str, ReadinessEvaluatorResponseV1]
    grader_lanes: (
        tuple[
            BaselineLockedGraderAggregateV1,
            BaselineLockedGraderAggregateV1,
        ]
        | None
    )
    strict_equivalent: BaselineLockedStrictEquivalentV1 | None
    candidates: tuple[SafetyGapCandidateV1, ...] | None
    safety_lanes: tuple[SafetyLaneResponseV1, ...]
    disputes: tuple[SafetyDisputeV1, ...]
    referee_decisions: tuple[SafetyRefereeDecisionV1, ...]
    safety_review: ReconciledSafetyReviewV1 | None
    requirement_matrix: RequirementMatrixV1 | None
    gap_matrix: GapFollowUpMatrixV1 | None
    handoff: bytes | None


def _error(code: str) -> EvaluationIntegrityError:
    return EvaluationIntegrityError(f"READINESS_ARTIFACT_{code}")


def _run_lock_parent(run_dir: Path) -> Path:
    try:
        return Path(os.path.abspath(os.fspath(run_dir))).parent
    except (OSError, TypeError, ValueError) as error:
        raise EvaluationIntegrityError("READINESS_STORAGE_UNSAFE") from error


def _lock_storage_descriptor(storage: RunStorage, *, exclusive: bool) -> None:
    descriptor = getattr(storage, "_root_descriptor", None)
    if os.name != "posix" or type(descriptor) is not int:
        raise EvaluationIntegrityError("READINESS_STORAGE_UNSAFE")
    try:
        import fcntl

        fcntl.flock(descriptor, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
    except (ImportError, NotImplementedError, OSError) as error:
        raise EvaluationIntegrityError("READINESS_STORAGE_UNSAFE") from error


@contextmanager
def _open_locked_storage(
    run_dir: Path,
    *,
    initialize: bool = False,
    exclusive: bool,
) -> Iterator[RunStorage]:
    parent = _run_lock_parent(run_dir)
    try:
        metadata = os.stat(parent, follow_symlinks=False)
        key = (metadata.st_dev, metadata.st_ino)
    except (NotImplementedError, OSError, TypeError, ValueError) as error:
        raise EvaluationIntegrityError("READINESS_STORAGE_UNSAFE") from error
    with _LOCKS_GUARD:
        lock = _RUN_LOCKS.setdefault(key, threading.RLock())
    with lock, open_evaluation_storage(parent) as parent_storage:
        _lock_storage_descriptor(parent_storage, exclusive=exclusive)
        parent_storage.assert_root_identity()
        with open_evaluation_storage(run_dir, initialize=initialize) as storage:
            _lock_storage_descriptor(storage, exclusive=exclusive)
            storage.assert_root_identity()
            yield storage
            storage.assert_root_identity()
        parent_storage.assert_root_identity()


def _storage_root_identity_v1(storage: RunStorage) -> ReadinessRootIdentityV1:
    descriptor = getattr(storage, "_root_descriptor", None)
    if os.name != "posix" or type(descriptor) is not int:
        raise EvaluationIntegrityError("READINESS_STORAGE_UNSAFE")
    try:
        metadata = os.fstat(descriptor)
    except (NotImplementedError, OSError, TypeError, ValueError) as error:
        raise EvaluationIntegrityError("READINESS_STORAGE_UNSAFE") from error
    return metadata.st_dev, metadata.st_ino


def _unique_json_object(pairs: list[tuple[str, object]], *, location: str) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key in {location}")
        result[key] = value
    return result


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
    if type(data) is not bytes or len(data) > _MAX_ARTIFACT_BYTES:
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
        if canonical_json_bytes(value) != data:
            raise _error(f"JSON_NONCANONICAL:{location}")
    except (TypeError, ValueError, RecursionError) as error:
        if isinstance(error, EvaluationIntegrityError):
            raise
        raise _error(f"JSON_MALFORMED:{location}") from error
    return value


def _model_from_file(
    data: bytes,
    validator: object,
    *,
    location: str,
) -> object:
    payload = _parse_canonical_json(data, location=location)
    try:
        checked = validator(payload)  # type: ignore[operator]
        if canonical_json_bytes(checked.model_dump(mode="json", warnings="error")) != data:
            raise ValueError
        return checked
    except (AttributeError, TypeError, ValidationError, ValueError, RecursionError) as error:
        raise _error(f"MODEL_INVALID:{location}") from error


def _artifact_record(path: str, data: bytes) -> ArtifactRecord:
    try:
        return ArtifactRecord(artifact_path=path, artifact_hash=sha256_digest(data))
    except (TypeError, ValidationError, ValueError) as error:
        raise _error("ARTIFACT_PATH") from error


def _strict_baseline_value(
    model_type: type[_ModelT], value: object, *, bytes_fields: tuple[str, ...] = ()
) -> _ModelT:
    raw = value
    if type(raw) is dict and bytes_fields:
        raw = dict(cast(dict[str, object], raw))
        for name in bytes_fields:
            item = raw.get(name)
            if type(item) is not str:
                raise _error("INPUT_BASELINE_CONTEXT")
            raw[name] = item.encode("utf-8")
    try:
        return cast(_ModelT, strict_baseline_model_v1(model_type, raw))
    except (TypeError, ValidationError, ValueError, RecursionError) as error:
        raise _error("INPUT_BASELINE_CONTEXT") from error


def _exact_dict(value: object, keys: tuple[str, ...], *, location: str) -> dict[str, object]:
    if type(value) is not dict:
        raise _error(f"INPUT_SHAPE:{location}")
    mapping = cast(dict[str, object], value)
    if len(mapping) != len(keys) or set(mapping) != set(keys):
        raise _error(f"INPUT_SHAPE:{location}")
    return mapping


def _exact_list(value: object, *, location: str) -> list[object]:
    if type(value) is not list:
        raise _error(f"INPUT_SHAPE:{location}")
    return cast(list[object], value)


def _string_pairs(value: object, *, location: str) -> tuple[tuple[str, str], ...]:
    pairs: list[tuple[str, str]] = []
    for item in _exact_list(value, location=location):
        if (
            type(item) is not list
            or len(item) != 2
            or type(item[0]) is not str
            or type(item[1]) is not str
        ):
            raise _error(f"INPUT_SHAPE:{location}")
        pairs.append((item[0], item[1]))
    return tuple(pairs)


def _qualification_limits_from_wire(value: object) -> QualificationLimitsV1:
    raw = _exact_dict(
        value,
        tuple(field.name for field in fields(QualificationLimitsV1)),
        location="qualification_limits",
    )

    def authority(item: object) -> QualificationRequestedAuthorityV1:
        value_ = _exact_dict(
            item,
            tuple(field.name for field in fields(QualificationRequestedAuthorityV1)),
            location="qualification_authority",
        )
        return QualificationRequestedAuthorityV1(
            authority_id=cast(str, value_["authority_id"]),
            title=cast(str, value_["title"]),
            jurisdiction=cast(str, value_["jurisdiction"]),
            authority_type=cast(str, value_["authority_type"]),
            source_ids=tuple(
                cast(list[str], _exact_list(value_["source_ids"], location="authority_source_ids"))
            ),
        )

    def check(item: object) -> QualificationAdmissionCheckV1:
        value_ = _exact_dict(
            item,
            tuple(field.name for field in fields(QualificationAdmissionCheckV1)),
            location="qualification_check",
        )
        return QualificationAdmissionCheckV1(
            code=value_["code"],  # type: ignore[arg-type]
            satisfied=cast(bool, value_["satisfied"]),
            material=cast(bool, value_["material"]),
            rationale=cast(str, value_["rationale"]),
            source_ids=tuple(
                cast(list[str], _exact_list(value_["source_ids"], location="check_source_ids"))
            ),
        )

    def issue(item: object) -> QualificationAdmissionIssueV1:
        value_ = _exact_dict(
            item,
            tuple(field.name for field in fields(QualificationAdmissionIssueV1)),
            location="qualification_issue",
        )
        return QualificationAdmissionIssueV1(
            code=cast(str, value_["code"]),
            severity=value_["severity"],  # type: ignore[arg-type]
            message=cast(str, value_["message"]),
            related_ids=tuple(
                cast(list[str], _exact_list(value_["related_ids"], location="issue_related_ids"))
            ),
        )

    def treatment(item: object) -> QualificationLanguageTreatmentV1:
        value_ = _exact_dict(
            item,
            tuple(field.name for field in fields(QualificationLanguageTreatmentV1)),
            location="qualification_treatment",
        )
        sources = []
        for source_raw in _exact_list(value_["sources"], location="treatment_sources"):
            source = _exact_dict(
                source_raw,
                tuple(field.name for field in fields(QualificationLanguageSourceV1)),
                location="qualification_language_source",
            )
            sources.append(
                QualificationLanguageSourceV1(
                    source_id=cast(str, source["source_id"]),
                    content_hash=cast(str, source["content_hash"]),
                    language=cast(str, source["language"]),
                )
            )
        return QualificationLanguageTreatmentV1(
            sources=tuple(sources),
            method=cast(str, value_["method"]),
            rationale=cast(str, value_["rationale"]),
            limitation_status=value_["limitation_status"],  # type: ignore[arg-type]
            limitation_text=cast(str | None, value_["limitation_text"]),
        )

    readiness_raw = _exact_dict(
        raw["receipt_readiness"],
        tuple(field.name for field in fields(QualificationReceiptReadinessV1)),
        location="qualification_receipt_readiness",
    )
    return QualificationLimitsV1(
        case_schema_version=raw["case_schema_version"],  # type: ignore[arg-type]
        admission_status=raw["admission_status"],  # type: ignore[arg-type]
        qualification_readiness=raw["qualification_readiness"],  # type: ignore[arg-type]
        qualification_root=cast(str, raw["qualification_root"]),
        qualification_receipt_fingerprint=cast(str, raw["qualification_receipt_fingerprint"]),
        case_fingerprint=cast(str, raw["case_fingerprint"]),
        source_record_fingerprint=cast(str, raw["source_record_fingerprint"]),
        request_fingerprint=cast(str, raw["request_fingerprint"]),
        judgment_fingerprint=cast(str, raw["judgment_fingerprint"]),
        requested_authorities=tuple(
            authority(item)
            for item in _exact_list(
                raw["requested_authorities"], location="qualification_authorities"
            )
        ),
        admission_checks=tuple(
            check(item)
            for item in _exact_list(raw["admission_checks"], location="qualification_checks")
        ),
        admission_issues=tuple(
            issue(item)
            for item in _exact_list(raw["admission_issues"], location="qualification_issues")
        ),
        receipt_readiness=QualificationReceiptReadinessV1(
            status=readiness_raw["status"],  # type: ignore[arg-type]
            issue_codes=tuple(
                cast(
                    list[str],
                    _exact_list(
                        readiness_raw["issue_codes"], location="qualification_receipt_issue_codes"
                    ),
                )
            ),
            rationale=cast(str, readiness_raw["rationale"]),
        ),
        language_treatments=tuple(
            treatment(item)
            for item in _exact_list(raw["language_treatments"], location="qualification_treatments")
        ),
    )


def _persisted_input_bytes(inputs: VerifiedReadinessInputsV1) -> bytes:
    if type(inputs) is not VerifiedReadinessInputsV1:
        raise _error("INPUT_INVALID")
    context = inputs.baseline_context
    payload = {
        "schema_version": "delivery-readiness-input-v1",
        "readiness_input": inputs.readiness_input.model_dump(mode="json", warnings="error"),
        "baseline_context": {
            "manifest": context.manifest.model_dump(mode="json", warnings="error"),
            "baseline_input": context.baseline_input.model_dump(mode="json", warnings="error"),
            "baseline": context.baseline.model_dump(mode="json", warnings="error"),
            "verification": context.verification.model_dump(mode="json", warnings="error"),
        },
        "qualification_binding": asdict(inputs.qualification_binding),
        "qualification_limits": asdict(inputs.qualification_limits),
        "generation_binding": asdict(inputs.generation_binding),
    }
    try:
        data = canonical_json_bytes(payload)
        _parse_canonical_json(data, location=READINESS_INPUT_PATH)
        return data
    except (AttributeError, TypeError, ValidationError, ValueError, RecursionError) as error:
        if isinstance(error, EvaluationIntegrityError):
            raise
        raise _error("INPUT_INVALID") from error


def _inputs_from_file(data: bytes, rubric_bytes: bytes) -> VerifiedReadinessInputsV1:
    payload = _parse_canonical_json(data, location=READINESS_INPUT_PATH)
    raw = _exact_dict(
        payload,
        (
            "baseline_context",
            "generation_binding",
            "qualification_binding",
            "qualification_limits",
            "readiness_input",
            "schema_version",
        ),
        location="persisted_input",
    )
    if raw["schema_version"] != "delivery-readiness-input-v1":
        raise _error("INPUT_VERSION")
    readiness_raw = _exact_dict(
        raw["readiness_input"],
        (
            "generation_capsule_root",
            "generation_validation",
            "grade_target_fingerprint",
            "gradeable_baseline",
            "historical_v22_cross_check",
            "protocol_version",
            "readiness_rubric_fingerprint",
            "report_hash",
            "report_text",
            "strict_equivalent_scoring_contract_fingerprint",
        ),
        location="readiness_input",
    )
    projection_raw = _exact_dict(
        readiness_raw["gradeable_baseline"],
        (
            "baseline_input",
            "baseline_protocol_version",
            "baseline_provenance",
            "binding",
            "contested_requirements",
            "projection_fingerprint",
            "relationships",
            "requirements",
            "schema_version",
        ),
        location="gradeable_baseline",
    )
    projection_payload = dict(projection_raw)
    projection_payload["baseline_input"] = _strict_baseline_value(
        BaselineInputV1,
        projection_raw["baseline_input"],
        bytes_fields=("evaluation_rubric_bytes", "importance_policy_bytes"),
    )
    embedded_projection = GradeableBaselineProjectionV1.model_validate(projection_payload)
    readiness_payload = dict(readiness_raw)
    readiness_payload["gradeable_baseline"] = embedded_projection
    readiness_input = ReadinessInputV1.model_validate(readiness_payload)
    readiness_input = validate_readiness_input_v1(readiness_input)
    context_raw = _exact_dict(
        raw["baseline_context"],
        ("baseline", "baseline_input", "manifest", "verification"),
        location="baseline_context",
    )
    baseline_context = VerifiedBaselineContextV1(
        manifest=_strict_baseline_value(BaselineManifestV1, context_raw["manifest"]),
        baseline_input=_strict_baseline_value(
            BaselineInputV1,
            context_raw["baseline_input"],
            bytes_fields=("evaluation_rubric_bytes", "importance_policy_bytes"),
        ),
        baseline=_strict_baseline_value(CanonicalBaselineV1, context_raw["baseline"]),
        verification=_strict_baseline_value(BaselineVerificationV1, context_raw["verification"]),
    )
    binding_raw = _exact_dict(
        raw["qualification_binding"],
        tuple(field.name for field in fields(QualificationReadinessBindingV1)),
        location="qualification_binding",
    )
    qualification_binding = QualificationReadinessBindingV1(
        qualification_root=cast(str, binding_raw["qualification_root"]),
        qualification_receipt_fingerprint=cast(
            str, binding_raw["qualification_receipt_fingerprint"]
        ),
        qualification_readiness=binding_raw["qualification_readiness"],  # type: ignore[arg-type]
    )
    generation_raw = _exact_dict(
        raw["generation_binding"],
        tuple(field.name for field in fields(GenerationCapsuleBindingV1)),
        location="generation_binding",
    )
    generation_binding = GenerationCapsuleBindingV1(
        capsule_root=cast(str, generation_raw["capsule_root"]),
        capture_fingerprint=cast(str, generation_raw["capture_fingerprint"]),
        request_fingerprint=cast(str, generation_raw["request_fingerprint"]),
        response_fingerprint=cast(str, generation_raw["response_fingerprint"]),
        report_hash=cast(str, generation_raw["report_hash"]),
        source_hashes=_string_pairs(
            generation_raw["source_hashes"], location="generation_source_hashes"
        ),
        client_facts_hash=cast(str | None, generation_raw["client_facts_hash"]),
        generator_artifact_hashes=_string_pairs(
            generation_raw["generator_artifact_hashes"],
            location="generator_artifact_hashes",
        ),
    )
    rubric = load_readiness_rubric_v1()
    if rubric_bytes != canonical_json_bytes(rubric.model_dump(mode="json", warnings="error")):
        raise _error("RUBRIC_BYTES")
    projection = verify_gradeable_baseline_projection_v1(baseline_context, embedded_projection)
    inputs = VerifiedReadinessInputsV1(
        readiness_input=readiness_input,
        baseline_context=baseline_context,
        gradeable_baseline=projection,
        report_text=readiness_input.report_text,
        report_hash=readiness_input.report_hash,
        source_record=projection.baseline_input.sources,
        qualification_binding=qualification_binding,
        qualification_limits=_qualification_limits_from_wire(raw["qualification_limits"]),
        generation_binding=generation_binding,
        generation_validation=readiness_input.generation_validation,
        readiness_rubric=rubric,
        readiness_rubric_bytes=rubric_bytes,
        strict_equivalent_scoring_contract_bytes=projection.baseline_input.evaluation_rubric_bytes,
        historical_v22=readiness_input.historical_v22_cross_check,
    )
    # The request builder's complete receiving boundary authenticates every detached field.
    batches = build_baseline_locked_grade_batches_v1(projection, lane=1)
    if batches:
        build_baseline_locked_grade_request_v1(inputs, batches[0])
    return inputs


def _call_id(request: ReadinessEvaluatorRequestV1) -> str:
    payload = request.payload
    for key in (
        "controller_lane_id",
        "controller_safety_lane_id",
        "controller_referee_id",
    ):
        value = payload.get(key)
        if type(value) is str:
            return value
    raise _error("CALL_ID")


def _pending_call(request: ReadinessEvaluatorRequestV1) -> ReadinessCallRecordV1:
    call_id = _call_id(request)
    lane = request.payload.get("lane")
    dispute_id = request.payload.get("dispute_id")
    checked_lane: Literal[1, 2] | None = lane if lane == 1 or lane == 2 else None
    return ReadinessCallRecordV1(
        call_id=call_id,
        operation=request.operation,
        state="pending",
        attempt=1,
        lane=checked_lane,
        request_artifact_path=f"requests/{call_id}.json",
        request_fingerprint=request.request_fingerprint,
        dispute_id=cast(str | None, dispute_id),
    )


def _manifest_fingerprint(manifest: ReadinessManifestV1) -> str:
    return sha256_digest(
        canonical_json_bytes(
            manifest.model_dump(mode="json", exclude={"manifest_fingerprint", "root_hash"})
        )
    )


def _manifest_root_hash(manifest: ReadinessManifestV1) -> str:
    return sha256_digest(
        canonical_json_bytes(manifest.model_dump(mode="json", exclude={"root_hash"}))
    )


def _with_inventory(
    manifest: ReadinessManifestV1, files: Mapping[str, bytes]
) -> ReadinessManifestV1:
    inventory = tuple(
        sorted(
            (_artifact_record(path, data) for path, data in files.items()),
            key=lambda item: item.artifact_path,
        )
    )
    provisional = manifest.model_copy(
        update={
            "artifacts": inventory,
            "manifest_fingerprint": "0" * 64,
            "root_hash": "0" * 64,
        }
    )
    with_fingerprint = provisional.model_copy(
        update={"manifest_fingerprint": _manifest_fingerprint(provisional)}
    )
    committed = with_fingerprint.model_copy(
        update={"root_hash": _manifest_root_hash(with_fingerprint)}
    )
    return validate_readiness_manifest_v1(committed.model_dump(mode="json", warnings="error"))


def _manifest_bytes(manifest: ReadinessManifestV1) -> bytes:
    checked = validate_readiness_manifest_v1(manifest.model_dump(mode="json", warnings="error"))
    if checked.manifest_fingerprint != _manifest_fingerprint(
        checked
    ) or checked.root_hash != _manifest_root_hash(checked):
        raise _error("MANIFEST_FINGERPRINT")
    return canonical_json_bytes(checked.model_dump(mode="json", warnings="error"))


def _manifest_from_bytes(data: bytes) -> ReadinessManifestV1:
    manifest = cast(
        ReadinessManifestV1,
        _model_from_file(
            data,
            validate_readiness_manifest_v1,
            location=READINESS_MANIFEST_PATH,
        ),
    )
    if manifest.manifest_fingerprint != _manifest_fingerprint(
        manifest
    ) or manifest.root_hash != _manifest_root_hash(manifest):
        raise _error("MANIFEST_FINGERPRINT")
    return manifest


def _graph_fingerprint(files: Mapping[str, bytes]) -> str:
    records = [
        {"artifact_path": path, "artifact_hash": sha256_digest(data)}
        for path, data in sorted(files.items())
        if path != READINESS_VERIFICATION_PATH
    ]
    return sha256_digest(canonical_json_bytes(records))


def _runtime_verification(files: Mapping[str, bytes]) -> ReadinessVerificationV1:
    descriptor = {
        "protocol_version": "delivery-readiness-v1",
        "valid": True,
        "checks": {key: True for key in _INTERNAL_CHECKS},
        "issues": [],
        "graph_fingerprint": _graph_fingerprint(files),
    }
    return ReadinessVerificationV1.model_validate(
        {
            **descriptor,
            "verification_fingerprint": sha256_digest(canonical_json_bytes(descriptor)),
        }
    )


def _first_request(inputs: VerifiedReadinessInputsV1) -> ReadinessEvaluatorRequestV1:
    requests = _grade_requests(inputs)
    if not requests:
        raise _error("EMPTY_GRADE_INVENTORY")
    return requests[0]


def _grade_requests(
    inputs: VerifiedReadinessInputsV1,
) -> tuple[ReadinessEvaluatorRequestV1, ...]:
    requests: list[ReadinessEvaluatorRequestV1] = []
    contests = tuple(
        item.contested_requirement.contested_requirement_id
        for item in inputs.gradeable_baseline.contested_requirements
    )
    for lane in (1, 2):
        batches = build_baseline_locked_grade_batches_v1(inputs.gradeable_baseline, lane=lane)
        requests.extend(build_baseline_locked_grade_request_v1(inputs, batch) for batch in batches)
        requests.extend(
            build_baseline_locked_contested_grade_request_v1(
                inputs,
                lane=lane,
                contested_requirement_id=contest_id,
            )
            for contest_id in contests
        )
    return tuple(requests)


def _draft_from_response(
    response: ReadinessEvaluatorResponseV1,
) -> dict[str, object]:
    payload = cast(
        dict[str, object],
        json.loads(canonical_json_bytes(response.payload)),
    )
    if response.operation is ReadinessOperationV1.BASELINE_LOCKED_GRADE:
        return {
            "requirement_grades": payload["requirement_grades"],
            "rationale": payload["rationale"],
        }
    if response.operation is ReadinessOperationV1.BASELINE_LOCKED_CONTESTED_GRADE:
        controlled = {
            "protocol_version",
            "lane",
            "grade_target_fingerprint",
            "baseline_fingerprint",
            "report_hash",
            "strict_equivalent_scoring_contract_fingerprint",
            "grade_fingerprint",
        }
        return {key: value for key, value in payload.items() if key not in controlled}
    if response.operation is ReadinessOperationV1.SAFETY_REVIEW:
        assessments = []
        for item in cast(list[dict[str, object]], payload["candidate_assessments"]):
            assessments.append(
                {key: value for key, value in item.items() if key != "assessment_fingerprint"}
            )
        findings = []
        for item in cast(list[dict[str, object]], payload["finding_proposals"]):
            findings.append(
                {key: value for key, value in item.items() if key != "finding_fingerprint"}
            )
        return {
            "candidate_assessments": assessments,
            "finding_proposals": findings,
        }
    return payload


def _response_from_file(
    data: bytes,
    request: ReadinessEvaluatorRequestV1,
    *,
    location: str,
) -> ReadinessEvaluatorResponseV1:
    response = cast(
        ReadinessEvaluatorResponseV1,
        _model_from_file(
            data,
            validate_readiness_evaluator_response_v1,
            location=location,
        ),
    )
    if (
        response.operation is not request.operation
        or response.request_fingerprint != request.request_fingerprint
    ):
        raise _error("CALL_RESPONSE_BINDING")
    provenance = ReadinessEvaluatorProvenanceV1(
        provider_name=response.provider_name,
        model_name=response.model_name,
        judge_isolation=response.judge_isolation,
    )
    try:
        compiled = compile_readiness_draft_v1(request, _draft_from_response(response), provenance)
        compiled_bytes = (
            canonical_json_bytes(compiled.response.model_dump(mode="json"))
            if isinstance(compiled, CompiledReadinessDraftV1)
            else None
        )
    except Exception as error:
        raise _error("CALL_RESPONSE_COMPILE") from error
    if (
        not isinstance(compiled, CompiledReadinessDraftV1)
        or compiled.normalization_codes
        or compiled_bytes != data
    ):
        raise _error("CALL_RESPONSE_COMPILE")
    return response


def _verify_readiness_snapshot(
    manifest: ReadinessManifestV1, files: Mapping[str, bytes]
) -> _Replay:
    try:
        input_bytes = files[READINESS_INPUT_PATH]
        rubric_bytes = files[READINESS_RUBRIC_PATH]
    except KeyError as error:
        raise _error("INPUT_REQUIRED") from error
    inputs = _inputs_from_file(input_bytes, rubric_bytes)
    if (
        manifest.grade_target_fingerprint != inputs.readiness_input.grade_target_fingerprint
        or manifest.report_hash != inputs.report_hash
        or manifest.generation_capsule_root != inputs.readiness_input.generation_capsule_root
        or manifest.readiness_rubric_fingerprint
        != inputs.readiness_input.readiness_rubric_fingerprint
        or manifest.strict_equivalent_scoring_contract_fingerprint
        != inputs.readiness_input.strict_equivalent_scoring_contract_fingerprint
    ):
        raise _error("INPUT_BINDING")
    bound = {READINESS_INPUT_PATH, READINESS_RUBRIC_PATH}
    requests: dict[str, ReadinessEvaluatorRequestV1] = {}
    responses: list[ReadinessEvaluatorResponseV1] = []
    response_by_id: dict[str, ReadinessEvaluatorResponseV1] = {}

    def accepted_response(
        index: int, expected: ReadinessEvaluatorRequestV1
    ) -> ReadinessEvaluatorResponseV1:
        call = manifest.accepted_calls[index]
        expected_pending = _pending_call(expected)
        if (
            call.call_id != expected_pending.call_id
            or call.operation is not expected_pending.operation
            or call.lane != expected_pending.lane
            or call.request_artifact_path != expected_pending.request_artifact_path
            or call.request_fingerprint != expected_pending.request_fingerprint
            or call.attempt not in {1, 2}
            or call.dispute_id != expected_pending.dispute_id
            or call.response_artifact_path is None
            or call.response_fingerprint is None
        ):
            raise _error("CALL_HISTORY")
        try:
            request_bytes = files[call.request_artifact_path]
            response_bytes = files[call.response_artifact_path]
        except KeyError as error:
            raise _error("CALL_ARTIFACT_MISSING") from error
        if request_bytes != canonical_json_bytes(expected.model_dump(mode="json")):
            raise _error("CALL_REQUEST_BINDING")
        request = cast(
            ReadinessEvaluatorRequestV1,
            _model_from_file(
                request_bytes,
                validate_readiness_evaluator_request_v1,
                location=call.request_artifact_path,
            ),
        )
        response = _response_from_file(
            response_bytes, expected, location=call.response_artifact_path
        )
        if (
            request != expected
            or sha256_digest(response_bytes) != call.response_fingerprint
            or response.provider_name != call.provider_name
            or response.model_name != call.model_name
            or response.judge_isolation != call.judge_isolation
        ):
            raise _error("CALL_RESPONSE_BINDING")
        requests[call.call_id] = request
        response_by_id[call.call_id] = response
        bound.update((call.request_artifact_path, call.response_artifact_path))
        return response

    grade_requests = _grade_requests(inputs)
    grade_count = len(grade_requests)
    grade_accepted = min(len(manifest.accepted_calls), grade_count)
    for index in range(grade_accepted):
        responses.append(accepted_response(index, grade_requests[index]))

    expected_requests = list(grade_requests)
    strict: BaselineLockedStrictEquivalentV1 | None = None
    grader_lanes: (
        tuple[
            BaselineLockedGraderAggregateV1,
            BaselineLockedGraderAggregateV1,
        ]
        | None
    ) = None
    candidates: tuple[SafetyGapCandidateV1, ...] | None = None
    safety_lanes: tuple[SafetyLaneResponseV1, SafetyLaneResponseV1] | None = None
    observed_safety_lanes: tuple[SafetyLaneResponseV1, ...] = ()
    disputes: tuple[SafetyDisputeV1, ...] = ()
    if grade_accepted == grade_count:
        ordinary: dict[int, list[BaselineLockedGradeFragmentV1]] = {1: [], 2: []}
        contested: dict[int, list[BaselineLockedContestedGradeV1]] = {1: [], 2: []}
        for response in responses:
            lane = cast(int, response.payload["lane"])
            if response.operation is ReadinessOperationV1.BASELINE_LOCKED_GRADE:
                ordinary[lane].append(
                    BaselineLockedGradeFragmentV1.model_validate(response.payload)
                )
            else:
                contested[lane].append(
                    BaselineLockedContestedGradeV1.model_validate(response.payload)
                )
        grader_lanes = (
            aggregate_baseline_locked_grader_lane_v1(
                inputs,
                lane=1,
                ordinary_fragments=tuple(ordinary[1]),
                contested_grades=tuple(contested[1]),
            ),
            aggregate_baseline_locked_grader_lane_v1(
                inputs,
                lane=2,
                ordinary_fragments=tuple(ordinary[2]),
                contested_grades=tuple(contested[2]),
            ),
        )
        for path, expected in zip(
            (GRADER_LANE_1_PATH, GRADER_LANE_2_PATH), grader_lanes, strict=True
        ):
            if files.get(path) != canonical_json_bytes(expected.model_dump(mode="json")):
                raise _error("DERIVED_ARTIFACT")
            bound.add(path)
        strict = derive_baseline_locked_strict_equivalent_v1(
            inputs.gradeable_baseline,
            grader_lanes[0],
            grader_lanes[1],
            inputs.readiness_rubric,
        )
        if files.get(STRICT_EQUIVALENT_PATH) != canonical_json_bytes(
            strict.model_dump(mode="json")
        ):
            raise _error("DERIVED_ARTIFACT")
        bound.add(STRICT_EQUIVALENT_PATH)
        if manifest.baseline_locked_strict_equivalent_fingerprint != (
            strict.strict_equivalent_fingerprint
        ):
            raise _error("DERIVED_BINDING")
        if inputs.historical_v22 is None:
            if HISTORICAL_CROSS_CHECK_PATH in files:
                raise _error("UNBOUND_ARTIFACT")
        else:
            expected_history = canonical_json_bytes(inputs.historical_v22.model_dump(mode="json"))
            if files.get(HISTORICAL_CROSS_CHECK_PATH) != expected_history:
                raise _error("DERIVED_ARTIFACT")
            bound.add(HISTORICAL_CROSS_CHECK_PATH)
        candidates = build_gap_candidate_inventory_v1(inputs, grader_lanes)
        expected_requests.extend(
            build_safety_lane_request_v1(inputs, grader_lanes, candidates, lane=lane)
            for lane in (1, 2)
        )
        for index in range(grade_count, min(len(manifest.accepted_calls), grade_count + 2)):
            responses.append(accepted_response(index, expected_requests[index]))
        observed_safety_lanes = tuple(
            SafetyLaneResponseV1.model_validate(response.payload)
            for response in responses[grade_count : grade_count + 2]
        )
        if len(manifest.accepted_calls) >= grade_count + 2:
            safety_lanes = (
                observed_safety_lanes[0],
                observed_safety_lanes[1],
            )
            disputes = build_safety_disputes_v1(inputs, *safety_lanes)
            expected_requests.extend(
                build_safety_referee_request_v1(inputs, dispute) for dispute in disputes
            )
            for index in range(grade_count + 2, len(manifest.accepted_calls)):
                if index >= len(expected_requests):
                    raise _error("CALL_HISTORY")
                responses.append(accepted_response(index, expected_requests[index]))

    if len(manifest.accepted_calls) > len(expected_requests):
        raise _error("CALL_HISTORY")
    pending_request: ReadinessEvaluatorRequestV1 | None = None
    if manifest.pending_call is not None:
        if len(manifest.accepted_calls) >= len(expected_requests):
            raise _error("CALL_HISTORY")
        pending_expected = expected_requests[len(manifest.accepted_calls)]
        call = manifest.pending_call
        if call != _pending_call(pending_expected):
            raise _error("CALL_HISTORY")
        try:
            stored = files[call.request_artifact_path]
        except KeyError as error:
            raise _error("CALL_REQUEST_MISSING") from error
        request = cast(
            ReadinessEvaluatorRequestV1,
            _model_from_file(
                stored,
                validate_readiness_evaluator_request_v1,
                location=call.request_artifact_path,
            ),
        )
        if request != pending_expected or stored != canonical_json_bytes(
            pending_expected.model_dump(mode="json")
        ):
            raise _error("CALL_REQUEST_BINDING")
        requests[call.call_id] = request
        pending_request = request
        bound.add(call.request_artifact_path)

    expected_phase = ReadinessPhaseV1.BASELINE_LOCKED_GRADE
    if pending_request is not None:
        if pending_request.operation is ReadinessOperationV1.SAFETY_REVIEW:
            expected_phase = ReadinessPhaseV1.SAFETY_REVIEW
        elif pending_request.operation is ReadinessOperationV1.SAFETY_REFEREE:
            expected_phase = ReadinessPhaseV1.SAFETY_REFEREE
    result: DeliveryReadinessResultV1 | None = None
    verification: ReadinessVerificationV1 | None = None
    referee_decisions: tuple[SafetyRefereeDecisionV1, ...] = ()
    safety_review: ReconciledSafetyReviewV1 | None = None
    requirement_matrix: RequirementMatrixV1 | None = None
    gap_matrix: GapFollowUpMatrixV1 | None = None
    handoff: bytes | None = None
    if pending_request is None:
        if len(manifest.accepted_calls) != len(expected_requests) or safety_lanes is None:
            raise _error("PHASE_INVENTORY")
        referee_decisions = tuple(
            SafetyRefereeDecisionV1.model_validate(response.payload)
            for response in responses[grade_count + 2 :]
        )
        assert grader_lanes is not None and strict is not None and candidates is not None
        safety_review = reconcile_safety_lanes_v1(
            inputs, candidates, *safety_lanes, referee_decisions
        )
        requirement_matrix = compile_requirement_matrix_v1(inputs, grader_lanes)
        gap_matrix = compile_gap_follow_up_matrix_v1(inputs, strict, candidates, safety_review)
        result = derive_delivery_readiness_v1(
            inputs,
            strict,
            requirement_matrix,
            gap_matrix,
            safety_review,
            *safety_lanes,
        )
        terminal = {
            SAFETY_REVIEW_PATH: canonical_json_bytes(safety_review.model_dump(mode="json")),
            REQUIREMENT_MATRIX_PATH: canonical_json_bytes(
                requirement_matrix.model_dump(mode="json")
            ),
            GAP_MATRIX_PATH: canonical_json_bytes(gap_matrix.model_dump(mode="json")),
            READINESS_RESULT_PATH: canonical_json_bytes(result.model_dump(mode="json")),
            ATTORNEY_HANDOFF_PATH: render_attorney_review_handoff_v1(
                report_text=inputs.report_text,
                requirement_matrix=requirement_matrix,
                gap_matrix=gap_matrix,
                result=result,
            ),
        }
        handoff = terminal[ATTORNEY_HANDOFF_PATH]
        if any(files.get(path) != data for path, data in terminal.items()):
            raise _error("DERIVED_ARTIFACT")
        bound.update(terminal)
        expected_verification = _runtime_verification(files)
        verification_bytes = files.get(READINESS_VERIFICATION_PATH)
        if verification_bytes != canonical_json_bytes(
            expected_verification.model_dump(mode="json")
        ):
            raise _error("VERIFICATION_ARTIFACT")
        assert isinstance(verification_bytes, bytes)
        verification = cast(
            ReadinessVerificationV1,
            _model_from_file(
                verification_bytes,
                validate_readiness_verification_v1,
                location=READINESS_VERIFICATION_PATH,
            ),
        )
        bound.add(READINESS_VERIFICATION_PATH)
        if (
            manifest.phase is not ReadinessPhaseV1.COMPLETED
            or manifest.terminal_status != "COMPLETED"
            or manifest.safety_review_fingerprint != safety_review.safety_review_fingerprint
            or manifest.requirement_matrix_fingerprint != requirement_matrix.matrix_fingerprint
            or manifest.gap_matrix_fingerprint != gap_matrix.matrix_fingerprint
            or manifest.result_fingerprint != result.result_fingerprint
        ):
            raise _error("DERIVED_BINDING")
    else:
        if manifest.phase is not expected_phase or manifest.terminal_status is not None:
            raise _error("PHASE_INVENTORY")
        if any(
            value is not None
            for value in (
                manifest.safety_review_fingerprint,
                manifest.requirement_matrix_fingerprint,
                manifest.gap_matrix_fingerprint,
                manifest.result_fingerprint,
            )
        ):
            raise _error("PHASE_INVENTORY")
        if (
            grade_accepted < grade_count
            and manifest.baseline_locked_strict_equivalent_fingerprint is not None
        ):
            raise _error("PHASE_INVENTORY")
    if set(files) != bound:
        raise _error("UNBOUND_ARTIFACT")
    return _Replay(
        manifest=manifest,
        inputs=inputs,
        pending_request=pending_request,
        result=result,
        verification=verification,
        requests=MappingProxyType(requests),
        responses=MappingProxyType(response_by_id),
        grader_lanes=grader_lanes,
        strict_equivalent=strict,
        candidates=candidates,
        safety_lanes=observed_safety_lanes,
        disputes=disputes,
        referee_decisions=referee_decisions,
        safety_review=safety_review,
        requirement_matrix=requirement_matrix,
        gap_matrix=gap_matrix,
        handoff=handoff,
    )


def _verify_or_raise(storage: RunStorage) -> _Replay:
    storage.assert_root_identity()
    initial_inventory = storage.scan_inventory()
    if READINESS_MANIFEST_PATH not in initial_inventory:
        raise _error("MANIFEST_MISSING")
    manifest = _manifest_from_bytes(
        storage.read_artifact(READINESS_MANIFEST_PATH, max_bytes=_MAX_ARTIFACT_BYTES)
    )
    expected = {artifact.artifact_path for artifact in manifest.artifacts} | {
        READINESS_MANIFEST_PATH
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
        data = storage.read_artifact(artifact.artifact_path, max_bytes=_MAX_ARTIFACT_BYTES)
        if sha256_digest(data) != artifact.artifact_hash:
            raise _error("ARTIFACT_HASH")
        if artifact.artifact_path.endswith(".json"):
            _parse_canonical_json(data, location=artifact.artifact_path)
        files[artifact.artifact_path] = data
    replay = _verify_readiness_snapshot(manifest, files)
    if storage.scan_inventory() != initial_inventory:
        raise _error("INVENTORY_CHANGED")
    storage.assert_root_identity()
    return replay


def _snapshot_files(files: Mapping[str, bytes]) -> dict[str, bytes]:
    if not isinstance(files, Mapping):
        raise _error("FILES_INVALID")
    result: dict[str, bytes] = {}
    for path, data in files.items():
        if type(path) is not str or type(data) is not bytes or path == READINESS_MANIFEST_PATH:
            raise _error("FILES_INVALID")
        _artifact_record(path, data)
        if path.endswith(".json"):
            _parse_canonical_json(data, location=path)
        result[path] = data
    return result


def _commit_initial(
    storage: RunStorage,
    files: Mapping[str, bytes],
    manifest: ReadinessManifestV1,
) -> ReadinessManifestV1:
    snapshot = _snapshot_files(files)
    if storage.scan_files():
        raise _error("INITIAL_NOT_EMPTY")
    committed = _with_inventory(manifest, snapshot)
    manifest_bytes = _manifest_bytes(committed)
    _verify_readiness_snapshot(committed, snapshot)
    created: list[tuple[str, bytes, _NodeIdentity]] = []
    manifest_identity: _NodeIdentity | None = None
    try:
        for path in sorted(snapshot):
            try:
                created_now = storage.atomic_write(path, snapshot[path], mutable=False)
            except BaseException as error:
                receipt = storage.atomic_write_receipt(path)
                identity = (
                    error.identity
                    if isinstance(error, _AtomicWriteOwnershipError)
                    else None
                    if receipt is None
                    else receipt.identity
                )
                visible = (
                    error.created
                    if isinstance(error, _AtomicWriteOwnershipError)
                    else receipt is not None and receipt.created
                )
                if visible:
                    if identity is None:
                        raise _error("ROLLBACK_FAILED") from error
                    created.append((path, snapshot[path], identity))
                raise
            if created_now:
                receipt = storage.atomic_write_receipt(path)
                if receipt is None or not receipt.created or receipt.identity is None:
                    raise _error("ROLLBACK_FAILED")
                created.append((path, snapshot[path], receipt.identity))
        try:
            installed = storage.atomic_write(READINESS_MANIFEST_PATH, manifest_bytes, mutable=False)
            receipt = storage.atomic_write_receipt(READINESS_MANIFEST_PATH)
            if installed:
                manifest_identity = None if receipt is None else receipt.identity
                if manifest_identity is None:
                    raise _error("ROLLBACK_FAILED")
        except BaseException as error:
            receipt = storage.atomic_write_receipt(READINESS_MANIFEST_PATH)
            visible = (
                error.created
                if isinstance(error, _AtomicWriteOwnershipError)
                else receipt is not None and receipt.created
            )
            if visible:
                manifest_identity = (
                    error.identity
                    if isinstance(error, _AtomicWriteOwnershipError)
                    else None
                    if receipt is None
                    else receipt.identity
                )
            raise
        replay = _verify_or_raise(storage)
        if replay.manifest != committed:
            raise _error("STALE_TRANSITION")
    except BaseException as error:
        cleanup_error: BaseException | None = None
        if manifest_identity is not None:
            try:
                storage.remove_artifact(
                    READINESS_MANIFEST_PATH,
                    expected_identity=manifest_identity,
                    expected_data=manifest_bytes,
                )
            except BaseException as cleanup:
                cleanup_error = cleanup
        for path, data, identity in reversed(created):
            try:
                storage.remove_artifact(path, expected_identity=identity, expected_data=data)
            except BaseException as cleanup:
                cleanup_error = cleanup
        if cleanup_error is not None:
            raise _error("ROLLBACK_FAILED") from cleanup_error
        raise error
    return committed


def _validate_successor_transition(
    previous: ReadinessManifestV1,
    successor: ReadinessManifestV1,
) -> None:
    prior_pending = previous.pending_call
    if (
        previous.terminal_status is not None
        or prior_pending is None
        or successor.grade_target_fingerprint != previous.grade_target_fingerprint
        or successor.report_hash != previous.report_hash
        or successor.generation_capsule_root != previous.generation_capsule_root
        or successor.readiness_rubric_fingerprint != previous.readiness_rubric_fingerprint
        or successor.strict_equivalent_scoring_contract_fingerprint
        != previous.strict_equivalent_scoring_contract_fingerprint
        or successor.accepted_calls[:-1] != previous.accepted_calls
        or not successor.accepted_calls
    ):
        raise EvaluationIntegrityError("READINESS_STALE_TRANSITION")
    accepted = successor.accepted_calls[-1]
    if (
        accepted.call_id != prior_pending.call_id
        or accepted.operation is not prior_pending.operation
        or accepted.lane != prior_pending.lane
        or accepted.request_artifact_path != prior_pending.request_artifact_path
        or accepted.request_fingerprint != prior_pending.request_fingerprint
        or accepted.dispute_id != prior_pending.dispute_id
        or accepted.state != "accepted"
    ):
        raise EvaluationIntegrityError("READINESS_STALE_TRANSITION")


def _commit_transition(
    storage: RunStorage,
    files: Mapping[str, bytes],
    successor: ReadinessManifestV1,
    *,
    expected_manifest_fingerprint: str,
) -> ReadinessManifestV1:
    snapshot = _snapshot_files(files)
    prior = _verify_or_raise(storage)
    previous = prior.manifest
    if previous.manifest_fingerprint != expected_manifest_fingerprint:
        raise EvaluationIntegrityError("READINESS_STALE_TRANSITION")
    inherited = {
        artifact.artifact_path: storage.read_artifact(
            artifact.artifact_path, max_bytes=_MAX_ARTIFACT_BYTES
        )
        for artifact in previous.artifacts
    }
    if set(snapshot) & set(inherited):
        raise _error("IMMUTABLE_ARTIFACT")
    all_files = {**inherited, **snapshot}
    if successor.phase in {ReadinessPhaseV1.COMPLETED, ReadinessPhaseV1.INCONCLUSIVE}:
        if READINESS_VERIFICATION_PATH in snapshot:
            raise _error("VERIFICATION_CONTROLLER_OWNED")
        verification = _runtime_verification(all_files)
        verification_bytes = canonical_json_bytes(verification.model_dump(mode="json"))
        snapshot[READINESS_VERIFICATION_PATH] = verification_bytes
        all_files[READINESS_VERIFICATION_PATH] = verification_bytes
    committed = _with_inventory(successor, all_files)
    _validate_successor_transition(previous, committed)
    _verify_readiness_snapshot(committed, all_files)
    previous_manifest_bytes = storage.read_artifact(
        READINESS_MANIFEST_PATH, max_bytes=_MAX_ARTIFACT_BYTES
    )
    manifest_bytes = _manifest_bytes(committed)
    created: list[tuple[str, bytes, _NodeIdentity]] = []
    manifest_identity: _NodeIdentity | None = None
    manifest_installed = False
    try:
        for path in sorted(snapshot):
            try:
                created_now = storage.atomic_write(path, snapshot[path], mutable=False)
            except BaseException as error:
                receipt = storage.atomic_write_receipt(path)
                identity = (
                    error.identity
                    if isinstance(error, _AtomicWriteOwnershipError)
                    else None
                    if receipt is None
                    else receipt.identity
                )
                visible = (
                    error.created
                    if isinstance(error, _AtomicWriteOwnershipError)
                    else receipt is not None and receipt.created
                )
                if visible:
                    if identity is None:
                        raise _error("ROLLBACK_FAILED") from error
                    created.append((path, snapshot[path], identity))
                raise
            if created_now:
                receipt = storage.atomic_write_receipt(path)
                if receipt is None or receipt.identity is None or not receipt.created:
                    raise _error("ROLLBACK_FAILED")
                created.append((path, snapshot[path], receipt.identity))
        current = _manifest_from_bytes(
            storage.read_artifact(READINESS_MANIFEST_PATH, max_bytes=_MAX_ARTIFACT_BYTES)
        )
        if current.manifest_fingerprint != expected_manifest_fingerprint:
            raise EvaluationIntegrityError("READINESS_STALE_TRANSITION")
        try:
            manifest_installed = storage.atomic_write(
                READINESS_MANIFEST_PATH, manifest_bytes, mutable=True
            )
            receipt = storage.atomic_write_receipt(READINESS_MANIFEST_PATH)
            if manifest_installed:
                manifest_identity = None if receipt is None else receipt.identity
                if manifest_identity is None:
                    raise _error("ROLLBACK_FAILED")
        except BaseException as error:
            receipt = storage.atomic_write_receipt(READINESS_MANIFEST_PATH)
            visible = (
                error.replaced
                if isinstance(error, _AtomicWriteOwnershipError)
                else receipt is not None and receipt.replaced
            )
            if visible:
                manifest_installed = True
                manifest_identity = (
                    error.identity
                    if isinstance(error, _AtomicWriteOwnershipError)
                    else None
                    if receipt is None
                    else receipt.identity
                )
            raise
        installed = _verify_or_raise(storage)
        if installed.manifest != committed:
            raise EvaluationIntegrityError("READINESS_STALE_TRANSITION")
    except BaseException as error:
        cleanup_error: BaseException | None = None
        try:
            observed = storage.read_optional_artifact_with_identity(
                READINESS_MANIFEST_PATH, max_bytes=_MAX_ARTIFACT_BYTES
            )
            if (
                manifest_installed
                and manifest_identity is not None
                and observed is not None
                and observed[0] == manifest_bytes
                and _same_filesystem_object(observed[1], manifest_identity)
            ):
                storage.replace_artifact_if_owned(
                    READINESS_MANIFEST_PATH,
                    previous_manifest_bytes,
                    owned_identity=manifest_identity,
                    owned_data=manifest_bytes,
                )
            elif observed is None or observed[0] != previous_manifest_bytes:
                raise _error("ROLLBACK_FAILED")
        except BaseException as cleanup:
            cleanup_error = cleanup
        for path, data, identity in reversed(created):
            try:
                storage.remove_artifact(path, expected_identity=identity, expected_data=data)
            except BaseException as cleanup:
                cleanup_error = cleanup
        if cleanup_error is not None:
            raise _error("ROLLBACK_FAILED") from cleanup_error
        raise error
    return committed


def commit_readiness_transition_v1(
    run_dir: Path,
    *,
    expected_manifest_fingerprint: str,
    files: Mapping[str, bytes],
    successor: ReadinessManifestV1,
    expected_root_identity: ReadinessRootIdentityV1 | None = None,
) -> ReadinessManifestV1:
    """Append one accepted response and its controller-derived successor state."""
    with _open_locked_storage(run_dir, exclusive=True) as storage:
        if (
            expected_root_identity is not None
            and _storage_root_identity_v1(storage) != expected_root_identity
        ):
            raise EvaluationIntegrityError("READINESS_STORAGE_UNSAFE")
        return _commit_transition(
            storage,
            files,
            successor,
            expected_manifest_fingerprint=expected_manifest_fingerprint,
        )


def preflight_readiness_response_v1(
    run_dir: Path,
    response: object,
) -> ReadinessResponsePreflightV1:
    """Validate the exact pending response without changing any artifact byte."""
    try:
        with _open_locked_storage(run_dir, exclusive=False) as storage:
            replay = _verify_or_raise(storage)
            request = replay.pending_request
            if request is None:
                raise _error("NO_PENDING_CALL")
            raw = response
            if isinstance(response, ReadinessEvaluatorResponseV1):
                raw = response.model_dump(mode="json", warnings="error")
            checked = validate_readiness_evaluator_response_v1(raw)
            data = canonical_json_bytes(checked.model_dump(mode="json"))
            _response_from_file(data, request, location="response-preflight")
            storage.assert_root_identity()
    except Exception:
        return ReadinessResponsePreflightV1(
            valid=False,
            diagnostics=("READINESS_EXTERNAL_RESPONSE_INVALID",),
        )
    return ReadinessResponsePreflightV1(valid=True)


def initialize_readiness_run_storage_v1(
    run_dir: Path,
    inputs: VerifiedReadinessInputsV1,
    first_request: ReadinessEvaluatorRequestV1,
) -> ReadinessManifestV1:
    """Create the separate readiness sibling with one exact pending grade call."""
    input_bytes = _persisted_input_bytes(inputs)
    rubric_bytes = inputs.readiness_rubric_bytes
    expected = _first_request(inputs)
    if type(first_request) is not ReadinessEvaluatorRequestV1 or canonical_json_bytes(
        first_request
    ) != canonical_json_bytes(expected):
        raise _error("CALL_REQUEST_BINDING")
    call = _pending_call(expected)
    manifest = ReadinessManifestV1(
        grade_target_fingerprint=inputs.readiness_input.grade_target_fingerprint,
        report_hash=inputs.report_hash,
        generation_capsule_root=inputs.readiness_input.generation_capsule_root,
        readiness_rubric_fingerprint=inputs.readiness_input.readiness_rubric_fingerprint,
        strict_equivalent_scoring_contract_fingerprint=(
            inputs.readiness_input.strict_equivalent_scoring_contract_fingerprint
        ),
        phase=ReadinessPhaseV1.BASELINE_LOCKED_GRADE,
        pending_call=call,
        artifacts=(),
        root_hash="0" * 64,
        manifest_fingerprint="0" * 64,
    )
    files = {
        READINESS_INPUT_PATH: input_bytes,
        READINESS_RUBRIC_PATH: rubric_bytes,
        call.request_artifact_path: canonical_json_bytes(
            expected.model_dump(mode="json", warnings="error")
        ),
    }
    with _open_locked_storage(run_dir, initialize=True, exclusive=True) as storage:
        return _commit_initial(storage, files, manifest)


def _safe_issue_code(error: BaseException) -> str:
    message = str(error)
    if "MANIFEST" in message:
        return "READINESS_MANIFEST_INVALID"
    if "INVENTORY" in message or "UNBOUND" in message:
        return "READINESS_INVENTORY_INVALID"
    if "JSON" in message or "MODEL" in message or "ARTIFACT_HASH" in message:
        return "READINESS_ARTIFACT_INVALID"
    if message.startswith("READINESS_ARTIFACT_"):
        return "READINESS_SEMANTIC_REPLAY_INVALID"
    return "READINESS_STORAGE_UNSAFE"


def verify_readiness_run_v1(run_dir: Path) -> ReadinessVerificationV1:
    """Return bounded diagnostics after descriptor-anchored semantic replay."""
    try:
        with _open_locked_storage(run_dir, exclusive=False) as storage:
            replay = _verify_or_raise(storage)
            files = {
                artifact.artifact_path: storage.read_artifact(
                    artifact.artifact_path, max_bytes=_MAX_ARTIFACT_BYTES
                )
                for artifact in replay.manifest.artifacts
            }
            storage.assert_root_identity()
    except Exception as error:
        return ReadinessVerificationV1.model_validate(
            {
                "valid": False,
                "checks": {key: False for key in _INTERNAL_CHECKS},
                "issues": (_safe_issue_code(error),),
            }
        )
    return replay.verification or _runtime_verification(files)


def load_verified_readiness_run_v1(
    run_dir: Path,
) -> tuple[ReadinessManifestV1, DeliveryReadinessResultV1 | None]:
    """Load the exact manifest and optional terminal result after replay."""
    with _open_locked_storage(run_dir, exclusive=False) as storage:
        replay = _verify_or_raise(storage)
        storage.assert_root_identity()
        return replay.manifest, replay.result


def load_verified_readiness_context_v1(
    run_dir: Path,
) -> VerifiedReadinessContextV1:
    """Load a detached context without retaining filesystem descriptors or paths."""
    with _open_locked_storage(run_dir, exclusive=False) as storage:
        replay = _verify_or_raise(storage)
        root_identity = _storage_root_identity_v1(storage)
        storage.assert_root_identity()
    return VerifiedReadinessContextV1(
        manifest=replay.manifest,
        inputs=replay.inputs,
        pending_request=replay.pending_request,
        result=replay.result,
        verification=replay.verification,
        requests=MappingProxyType(dict(replay.requests)),
        responses=MappingProxyType(dict(replay.responses)),
        grader_lanes=replay.grader_lanes,
        strict_equivalent=replay.strict_equivalent,
        candidates=replay.candidates,
        safety_lanes=replay.safety_lanes,
        disputes=replay.disputes,
        referee_decisions=replay.referee_decisions,
        safety_review=replay.safety_review,
        requirement_matrix=replay.requirement_matrix,
        gap_matrix=replay.gap_matrix,
        handoff=replay.handoff,
        root_identity=root_identity,
    )


__all__ = [
    "READINESS_INPUT_PATH",
    "READINESS_MANIFEST_PATH",
    "READINESS_RESULT_PATH",
    "READINESS_RUBRIC_PATH",
    "READINESS_VERIFICATION_PATH",
    "ReadinessResponsePreflightV1",
    "ReadinessRootIdentityV1",
    "VerifiedReadinessContextV1",
    "commit_readiness_transition_v1",
    "initialize_readiness_run_storage_v1",
    "load_verified_readiness_context_v1",
    "load_verified_readiness_run_v1",
    "preflight_readiness_response_v1",
    "verify_readiness_run_v1",
]
