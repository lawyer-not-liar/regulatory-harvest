"""Immutable artifact storage and semantic replay for evaluation-baseline-v1."""

from __future__ import annotations

import json
import math
import os
import re
import threading
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import TypeVar, cast

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
from .attorney_baseline_compiler import (
    BaselineCompilationError,
    aggregate_baseline_audit_v1,
    aggregate_baseline_referees_v1,
    aggregate_baseline_review_v1,
    apply_baseline_correction_v1,
    build_baseline_disputes_v1,
    compile_canonical_baseline_v1,
)
from .attorney_baseline_models import (
    AcceptedBaselineAuditFragmentV1,
    AcceptedBaselineRefereeFragmentV1,
    AcceptedBaselineReviewFragmentV1,
    BaselineAuditAggregateV1,
    BaselineAuditFragmentV1,
    BaselineCorrectionRecordV1,
    BaselineDisputeV1,
    BaselineEvaluatorRequestV1,
    BaselineEvaluatorResponseV1,
    BaselineInputV1,
    BaselineManifestV1,
    BaselinePhaseV1,
    BaselineRefereeAggregateV1,
    BaselineRefereeDecisionV1,
    BaselineReviewAggregateV1,
    BaselineReviewFragmentV1,
    BaselineStrictModel,
    BaselineVerificationV1,
    CanonicalBaselineV1,
    strict_baseline_model_v1,
)
from .attorney_baseline_requests import (
    build_baseline_source_audit_request_v1,
    build_baseline_source_referee_request_v1,
    build_baseline_source_review_request_v1,
)
from .attorney_models import ArtifactRecord

BASELINE_MANIFEST_PATH = "baseline-manifest.json"
BASELINE_INPUT_PATH = "baseline-input.json"
BASELINE_REVIEW_PATH = "source-review.json"
BASELINE_AUDIT_PATH = "source-audit.json"
BASELINE_REFEREES_PATH = "source-referees.json"
CANONICAL_BASELINE_PATH = "canonical-baseline.json"
BASELINE_CORRECTION_PATH = "baseline-correction.json"
BASELINE_VERIFICATION_PATH = "baseline-verification.json"

BASELINE_SAFE_ISSUE_CODES = frozenset(
    {
        "BASELINE_ARTIFACT_INVALID",
        "BASELINE_INVENTORY_INVALID",
        "BASELINE_MANIFEST_INVALID",
        "BASELINE_RESULT_REQUIRED",
        "BASELINE_SEMANTIC_REPLAY_INVALID",
        "BASELINE_STORAGE_UNSAFE",
    }
)

_MAX_JSON_BYTES = 16 * 1024 * 1024
_MAX_JSON_DEPTH = 64
_REVIEW_REQUEST_RE = re.compile(r"^requests/source-review-([0-9]{4})\.json$")
_REVIEW_RESPONSE_RE = re.compile(r"^responses/source-review-([0-9]{4})\.json$")
_AUDIT_REQUEST_RE = re.compile(r"^requests/source-audit-([0-9]{4})\.json$")
_AUDIT_RESPONSE_RE = re.compile(r"^responses/source-audit-([0-9]{4})\.json$")
_REFEREE_REQUEST_RE = re.compile(
    r"^requests/source-referee-(DSP-[0-9]{4})\.json$"
)
_REFEREE_RESPONSE_RE = re.compile(
    r"^responses/source-referee-(DSP-[0-9]{4})\.json$"
)

_ModelT = TypeVar("_ModelT", bound=BaselineStrictModel)
_LOCKS_GUARD = threading.Lock()
_RUN_LOCKS: dict[str, threading.RLock] = {}


@dataclass(frozen=True)
class VerifiedBaselineContextV1:
    """The exact four-field downstream context produced by one verified replay."""

    manifest: BaselineManifestV1
    baseline_input: BaselineInputV1
    baseline: CanonicalBaselineV1
    verification: BaselineVerificationV1


@dataclass(frozen=True)
class _Replay:
    manifest: BaselineManifestV1
    baseline_input: BaselineInputV1
    baseline: CanonicalBaselineV1 | None
    verification: BaselineVerificationV1


def _run_lock_key(run_dir: Path) -> str:
    try:
        return os.path.normcase(os.path.abspath(os.fspath(run_dir)))
    except (OSError, TypeError, ValueError) as error:
        raise EvaluationIntegrityError("baseline run path is invalid") from error


@contextmanager
def _run_operation_lock(run_dir: Path) -> Iterator[None]:
    key = _run_lock_key(run_dir)
    with _LOCKS_GUARD:
        lock = _RUN_LOCKS.setdefault(key, threading.RLock())
    with lock:
        yield


def _error(code: str) -> EvaluationIntegrityError:
    return EvaluationIntegrityError(f"BASELINE_ARTIFACT_{code}")


def _unique_json_object(
    pairs: list[tuple[str, object]], *, location: str
) -> dict[str, object]:
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
    if type(data) is not bytes or len(data) > _MAX_JSON_BYTES:
        raise _error(f"JSON_SIZE:{location}")
    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=lambda pairs: _unique_json_object(
                pairs, location=location
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as error:
        raise _error(f"JSON_MALFORMED:{location}") from error
    _ordinary_json(value, location=location)
    try:
        encoded = canonical_json_bytes(value)
    except (TypeError, ValueError, RecursionError) as error:
        raise _error(f"JSON_MALFORMED:{location}") from error
    if encoded != data:
        raise _error(f"JSON_NONCANONICAL:{location}")
    return value


def _model_from_file(
    data: bytes,
    model_type: type[_ModelT],
    *,
    location: str,
) -> _ModelT:
    payload = _parse_canonical_json(data, location=location)
    validation_payload = payload
    if model_type is BaselineInputV1 and type(payload) is dict:
        validation_payload = dict(cast(dict[str, object], payload))
        for field_name in ("evaluation_rubric_bytes", "importance_policy_bytes"):
            field_value = validation_payload.get(field_name)
            if type(field_value) is not str:
                raise _error(f"MODEL_INVALID:{location}")
            validation_payload[field_name] = field_value.encode("utf-8")
    try:
        value = cast(
            _ModelT,
            strict_baseline_model_v1(model_type, validation_payload),
        )
        encoded = canonical_json_bytes(value.model_dump(mode="json", warnings="error"))
    except (TypeError, ValidationError, ValueError, RecursionError) as error:
        raise _error(f"MODEL_INVALID:{location}") from error
    if encoded != data:
        raise _error(f"MODEL_NONCANONICAL:{location}")
    return value


def _canonical_model_bytes(value: _ModelT, model_type: type[_ModelT]) -> tuple[_ModelT, bytes]:
    try:
        checked = cast(_ModelT, strict_baseline_model_v1(model_type, value))
        data = canonical_json_bytes(checked.model_dump(mode="json", warnings="error"))
        _parse_canonical_json(data, location=model_type.__name__)
        round_tripped = _model_from_file(data, model_type, location=model_type.__name__)
    except EvaluationIntegrityError:
        raise
    except (TypeError, ValidationError, ValueError, RecursionError) as error:
        raise _error(f"MODEL_INVALID:{model_type.__name__}") from error
    return round_tripped, data


def _artifact_record(path: str, data: bytes) -> ArtifactRecord:
    try:
        return ArtifactRecord(
            artifact_path=path,
            artifact_hash=sha256_digest(data),
        )
    except (TypeError, ValidationError, ValueError) as error:
        raise _error("ARTIFACT_PATH") from error


def _snapshot_files(files: Mapping[str, bytes]) -> dict[str, bytes]:
    if not isinstance(files, Mapping):
        raise _error("FILES_INVALID")
    result: dict[str, bytes] = {}
    for path, data in files.items():
        if (
            type(path) is not str
            or type(data) is not bytes
            or path == BASELINE_MANIFEST_PATH
            or not path.endswith(".json")
        ):
            raise _error("FILES_INVALID")
        _artifact_record(path, data)
        _parse_canonical_json(data, location=path)
        result[path] = data
    return result


def _manifest_fingerprint(manifest: BaselineManifestV1) -> str:
    return sha256_digest(
        canonical_json_bytes(
            manifest.model_dump(mode="json", exclude={"manifest_fingerprint"})
        )
    )


def _manifest_bytes(manifest: BaselineManifestV1) -> tuple[BaselineManifestV1, bytes]:
    checked, data = _canonical_model_bytes(manifest, BaselineManifestV1)
    if checked.manifest_fingerprint != _manifest_fingerprint(checked):
        raise _error("MANIFEST_FINGERPRINT")
    return checked, data


def _with_inventory(
    manifest: BaselineManifestV1,
    files: Mapping[str, bytes],
) -> BaselineManifestV1:
    checked = cast(
        BaselineManifestV1,
        strict_baseline_model_v1(BaselineManifestV1, manifest),
    )
    inventory = tuple(
        sorted(
            (_artifact_record(path, data) for path, data in files.items()),
            key=lambda item: item.artifact_path,
        )
    )
    provisional = checked.model_copy(
        update={"artifacts": inventory, "manifest_fingerprint": "0" * 64}
    )
    committed = provisional.model_copy(
        update={"manifest_fingerprint": _manifest_fingerprint(provisional)}
    )
    return cast(
        BaselineManifestV1,
        strict_baseline_model_v1(BaselineManifestV1, committed),
    )


def _manifest_from_bytes(data: bytes) -> BaselineManifestV1:
    manifest = _model_from_file(
        data,
        BaselineManifestV1,
        location=BASELINE_MANIFEST_PATH,
    )
    if manifest.manifest_fingerprint != _manifest_fingerprint(manifest):
        raise _error("MANIFEST_FINGERPRINT")
    paths = tuple(item.artifact_path for item in manifest.artifacts)
    if paths != tuple(sorted(set(paths))) or BASELINE_MANIFEST_PATH in paths:
        raise _error("MANIFEST_INVENTORY")
    return manifest


def _indexed_paths(
    files: Mapping[str, bytes],
    pattern: re.Pattern[str],
    *,
    integer: bool,
) -> tuple[int | str, ...]:
    values: list[int | str] = []
    for path in files:
        match = pattern.fullmatch(path)
        if match is not None:
            values.append(int(match.group(1)) if integer else match.group(1))
    return tuple(sorted(values))


def _review_request_path(ordinal: int) -> str:
    return f"requests/source-review-{ordinal:04d}.json"


def _review_response_path(ordinal: int) -> str:
    return f"responses/source-review-{ordinal:04d}.json"


def _audit_request_path(ordinal: int) -> str:
    return f"requests/source-audit-{ordinal:04d}.json"


def _audit_response_path(ordinal: int) -> str:
    return f"responses/source-audit-{ordinal:04d}.json"


def _referee_request_path(dispute_id: str) -> str:
    return f"requests/source-referee-{dispute_id}.json"


def _referee_response_path(dispute_id: str) -> str:
    return f"responses/source-referee-{dispute_id}.json"


def _load_response(
    files: Mapping[str, bytes],
    path: str,
    request: BaselineEvaluatorRequestV1,
) -> tuple[BaselineEvaluatorResponseV1, str]:
    try:
        data = files[path]
    except KeyError as error:
        raise _error("RESPONSE_MISSING") from error
    response = _model_from_file(
        data,
        BaselineEvaluatorResponseV1,
        location=path,
    )
    if (
        response.operation is not request.operation
        or response.request_fingerprint != request.request_fingerprint
    ):
        raise _error("RESPONSE_BINDING")
    return response, sha256_digest(data)


def _replay_review(
    baseline_input: BaselineInputV1,
    files: Mapping[str, bytes],
    bound: set[str],
) -> tuple[BaselineReviewAggregateV1 | None, bool]:
    requests = cast(
        tuple[int, ...],
        _indexed_paths(files, _REVIEW_REQUEST_RE, integer=True),
    )
    responses = cast(
        tuple[int, ...],
        _indexed_paths(files, _REVIEW_RESPONSE_RE, integer=True),
    )
    if requests and requests != tuple(range(1, len(requests) + 1)):
        raise _error("REVIEW_HISTORY")
    if responses != tuple(range(1, len(responses) + 1)) or responses != requests[: len(responses)]:
        raise _error("REVIEW_HISTORY")
    if len(requests) - len(responses) > 1:
        raise _error("REVIEW_HISTORY")
    accepted: list[AcceptedBaselineReviewFragmentV1] = []
    for ordinal in requests:
        request_path = _review_request_path(ordinal)
        expected = build_baseline_source_review_request_v1(
            baseline_input,
            tuple(accepted),
            fragment_ordinal=ordinal,
        )
        expected_bytes = canonical_json_bytes(
            expected.model_dump(mode="json", warnings="error")
        )
        if files[request_path] != expected_bytes:
            raise _error("REVIEW_REQUEST_BINDING")
        bound.add(request_path)
        response_path = _review_response_path(ordinal)
        if ordinal not in responses:
            continue
        response, response_fingerprint = _load_response(files, response_path, expected)
        try:
            payload = cast(
                BaselineReviewFragmentV1,
                strict_baseline_model_v1(BaselineReviewFragmentV1, response.payload),
            )
            fragment = AcceptedBaselineReviewFragmentV1(
                fragment_ordinal=ordinal,
                request_fingerprint=expected.request_fingerprint,
                response_fingerprint=response_fingerprint,
                payload=payload,
            )
        except (TypeError, ValidationError, ValueError, RecursionError) as error:
            raise _error("REVIEW_RESPONSE_BINDING") from error
        accepted.append(fragment)
        bound.add(response_path)
    aggregate: BaselineReviewAggregateV1 | None = None
    if BASELINE_REVIEW_PATH in files:
        if not accepted or len(requests) != len(responses):
            raise _error("REVIEW_AGGREGATE")
        try:
            aggregate = aggregate_baseline_review_v1(
                baseline_input, tuple(accepted)
            )
        except BaselineCompilationError as error:
            raise _error("REVIEW_AGGREGATE") from error
        if files[BASELINE_REVIEW_PATH] != canonical_json_bytes(
            aggregate.model_dump(mode="json", warnings="error")
        ):
            raise _error("REVIEW_AGGREGATE")
        bound.add(BASELINE_REVIEW_PATH)
    elif accepted and accepted[-1].payload.review_complete:
        raise _error("REVIEW_AGGREGATE")
    pending = len(requests) == len(responses) + 1
    return aggregate, pending


def _replay_audit(
    baseline_input: BaselineInputV1,
    review: BaselineReviewAggregateV1,
    files: Mapping[str, bytes],
    bound: set[str],
) -> tuple[BaselineAuditAggregateV1 | None, bool]:
    requests = cast(
        tuple[int, ...],
        _indexed_paths(files, _AUDIT_REQUEST_RE, integer=True),
    )
    responses = cast(
        tuple[int, ...],
        _indexed_paths(files, _AUDIT_RESPONSE_RE, integer=True),
    )
    if requests and requests != tuple(range(1, len(requests) + 1)):
        raise _error("AUDIT_HISTORY")
    if responses != tuple(range(1, len(responses) + 1)) or responses != requests[: len(responses)]:
        raise _error("AUDIT_HISTORY")
    if len(requests) - len(responses) > 1:
        raise _error("AUDIT_HISTORY")
    accepted: list[AcceptedBaselineAuditFragmentV1] = []
    for ordinal in requests:
        request_path = _audit_request_path(ordinal)
        expected = build_baseline_source_audit_request_v1(
            baseline_input,
            review,
            tuple(accepted),
            fragment_ordinal=ordinal,
        )
        if files[request_path] != canonical_json_bytes(
            expected.model_dump(mode="json", warnings="error")
        ):
            raise _error("AUDIT_REQUEST_BINDING")
        bound.add(request_path)
        response_path = _audit_response_path(ordinal)
        if ordinal not in responses:
            continue
        response, response_fingerprint = _load_response(files, response_path, expected)
        try:
            payload = cast(
                BaselineAuditFragmentV1,
                strict_baseline_model_v1(BaselineAuditFragmentV1, response.payload),
            )
            fragment = AcceptedBaselineAuditFragmentV1(
                fragment_ordinal=ordinal,
                request_fingerprint=expected.request_fingerprint,
                response_fingerprint=response_fingerprint,
                payload=payload,
            )
        except (TypeError, ValidationError, ValueError, RecursionError) as error:
            raise _error("AUDIT_RESPONSE_BINDING") from error
        accepted.append(fragment)
        bound.add(response_path)
    aggregate: BaselineAuditAggregateV1 | None = None
    if BASELINE_AUDIT_PATH in files:
        if not accepted or len(requests) != len(responses):
            raise _error("AUDIT_AGGREGATE")
        try:
            aggregate = aggregate_baseline_audit_v1(
                baseline_input,
                review,
                tuple(accepted),
            )
        except BaselineCompilationError as error:
            raise _error("AUDIT_AGGREGATE") from error
        if files[BASELINE_AUDIT_PATH] != canonical_json_bytes(
            aggregate.model_dump(mode="json", warnings="error")
        ):
            raise _error("AUDIT_AGGREGATE")
        bound.add(BASELINE_AUDIT_PATH)
    elif accepted and accepted[-1].payload.audit_complete:
        raise _error("AUDIT_AGGREGATE")
    pending = len(requests) == len(responses) + 1
    return aggregate, pending


def _replay_referees(
    baseline_input: BaselineInputV1,
    disputes: tuple[BaselineDisputeV1, ...],
    files: Mapping[str, bytes],
    bound: set[str],
) -> tuple[BaselineRefereeAggregateV1 | None, bool]:
    request_ids = cast(
        tuple[str, ...],
        _indexed_paths(files, _REFEREE_REQUEST_RE, integer=False),
    )
    response_ids = cast(
        tuple[str, ...],
        _indexed_paths(files, _REFEREE_RESPONSE_RE, integer=False),
    )
    expected_ids = tuple(item.dispute_id for item in disputes)
    if request_ids != expected_ids[: len(request_ids)]:
        raise _error("REFEREE_HISTORY")
    if response_ids != request_ids[: len(response_ids)] or len(request_ids) - len(response_ids) > 1:
        raise _error("REFEREE_HISTORY")
    accepted: list[AcceptedBaselineRefereeFragmentV1] = []
    for dispute in disputes[: len(request_ids)]:
        request_path = _referee_request_path(dispute.dispute_id)
        expected = build_baseline_source_referee_request_v1(baseline_input, dispute)
        if files[request_path] != canonical_json_bytes(
            expected.model_dump(mode="json", warnings="error")
        ):
            raise _error("REFEREE_REQUEST_BINDING")
        bound.add(request_path)
        response_path = _referee_response_path(dispute.dispute_id)
        if dispute.dispute_id not in response_ids:
            continue
        response, response_fingerprint = _load_response(files, response_path, expected)
        try:
            decision = cast(
                BaselineRefereeDecisionV1,
                strict_baseline_model_v1(
                    BaselineRefereeDecisionV1, response.payload
                ),
            )
            fragment = AcceptedBaselineRefereeFragmentV1(
                dispute_id=dispute.dispute_id,
                dispute_fingerprint=dispute.dispute_fingerprint,
                response_fingerprint=response_fingerprint,
                decision=decision,
            )
        except (TypeError, ValidationError, ValueError, RecursionError) as error:
            raise _error("REFEREE_RESPONSE_BINDING") from error
        accepted.append(fragment)
        bound.add(response_path)
    aggregate: BaselineRefereeAggregateV1 | None = None
    if BASELINE_REFEREES_PATH in files:
        if len(request_ids) != len(expected_ids) or len(response_ids) != len(expected_ids):
            raise _error("REFEREE_AGGREGATE")
        try:
            aggregate = aggregate_baseline_referees_v1(
                baseline_input,
                disputes,
                tuple(accepted),
            )
        except BaselineCompilationError as error:
            raise _error("REFEREE_AGGREGATE") from error
        if files[BASELINE_REFEREES_PATH] != canonical_json_bytes(
            aggregate.model_dump(mode="json", warnings="error")
        ):
            raise _error("REFEREE_AGGREGATE")
        bound.add(BASELINE_REFEREES_PATH)
    pending = len(request_ids) == len(response_ids) + 1
    return aggregate, pending


def _phase_requires(
    manifest: BaselineManifestV1,
    *,
    review: BaselineReviewAggregateV1 | None,
    review_pending: bool,
    audit: BaselineAuditAggregateV1 | None,
    audit_pending: bool,
    disputes: tuple[BaselineDisputeV1, ...],
    referees: BaselineRefereeAggregateV1 | None,
    referee_pending: bool,
    baseline: CanonicalBaselineV1 | None,
    has_verification: bool,
) -> None:
    phase = manifest.phase
    terminal = manifest.terminal_status
    if phase is BaselinePhaseV1.CREATED:
        valid = (
            review is None
            and not review_pending
            and audit is None
            and not audit_pending
            and not disputes
            and referees is None
            and not referee_pending
            and baseline is None
            and terminal is None
            and not has_verification
        )
    elif phase is BaselinePhaseV1.SOURCE_REVIEW:
        valid = (
            review is None
            and review_pending
            and audit is None
            and referees is None
            and baseline is None
            and terminal is None
            and not has_verification
        )
    elif phase is BaselinePhaseV1.SOURCE_AUDIT:
        valid = (
            review is not None
            and not review_pending
            and audit is None
            and audit_pending
            and referees is None
            and baseline is None
            and terminal is None
            and not has_verification
        )
    elif phase is BaselinePhaseV1.SOURCE_REFEREE:
        valid = (
            review is not None
            and audit is not None
            and bool(disputes)
            and referees is None
            and referee_pending
            and baseline is None
            and terminal is None
            and not has_verification
        )
    elif phase is BaselinePhaseV1.BASELINE_SEALED:
        valid = (
            review is not None
            and audit is not None
            and referees is not None
            and not referee_pending
            and baseline is not None
            and terminal is None
            and not has_verification
        )
    elif phase is BaselinePhaseV1.COMPLETED:
        valid = (
            review is not None
            and audit is not None
            and referees is not None
            and not referee_pending
            and baseline is not None
            and terminal == "COMPLETED"
            and has_verification
        )
    elif phase is BaselinePhaseV1.INCONCLUSIVE:
        valid = (
            review is not None
            and audit is not None
            and referees is not None
            and not referee_pending
            and baseline is not None
            and terminal == "INCONCLUSIVE"
            and has_verification
        )
    else:
        valid = False
    if not valid:
        raise _error("PHASE_INVENTORY")


def _expected_prior_root(
    baseline_input: BaselineInputV1,
    baseline: CanonicalBaselineV1,
    files: Mapping[str, bytes],
) -> str:
    prior_files = dict(files)
    prior_files.pop(BASELINE_CORRECTION_PATH, None)
    prior_files[CANONICAL_BASELINE_PATH] = canonical_json_bytes(
        baseline.model_dump(mode="json", warnings="error")
    )
    prior_manifest = BaselineManifestV1(
        legal_input_fingerprint=baseline_input.legal_input_fingerprint,
        baseline_fingerprint=baseline.baseline_fingerprint,
        phase=BaselinePhaseV1.COMPLETED,
        terminal_status="COMPLETED",
        artifacts=(),
        manifest_fingerprint="0" * 64,
    )
    return _with_inventory(prior_manifest, prior_files).manifest_fingerprint


def _verify_baseline_snapshot(
    manifest: BaselineManifestV1,
    files: Mapping[str, bytes],
) -> _Replay:
    try:
        baseline_input = _model_from_file(
            files[BASELINE_INPUT_PATH],
            BaselineInputV1,
            location=BASELINE_INPUT_PATH,
        )
    except KeyError as error:
        raise _error("INPUT_REQUIRED") from error
    if manifest.legal_input_fingerprint != baseline_input.legal_input_fingerprint:
        raise _error("INPUT_BINDING")
    bound = {BASELINE_INPUT_PATH}
    try:
        review, review_pending = _replay_review(baseline_input, files, bound)
        audit: BaselineAuditAggregateV1 | None = None
        audit_pending = False
        disputes: tuple[BaselineDisputeV1, ...] = ()
        referees: BaselineRefereeAggregateV1 | None = None
        referee_pending = False
        if review is not None:
            audit, audit_pending = _replay_audit(
                baseline_input, review, files, bound
            )
        if audit is not None:
            assert review is not None
            disputes = build_baseline_disputes_v1(baseline_input, review, audit)
            referees, referee_pending = _replay_referees(
                baseline_input, disputes, files, bound
            )
    except (BaselineCompilationError, KeyError, TypeError, ValueError) as error:
        if isinstance(error, EvaluationIntegrityError):
            raise
        raise _error("ROLE_REPLAY") from error

    baseline: CanonicalBaselineV1 | None = None
    compiled: CanonicalBaselineV1 | None = None
    if referees is not None:
        assert review is not None and audit is not None
        try:
            compiled = compile_canonical_baseline_v1(
                baseline_input, review, audit, referees
            )
        except BaselineCompilationError as error:
            raise _error("BASELINE_REPLAY") from error
    correction: BaselineCorrectionRecordV1 | None = None
    if BASELINE_CORRECTION_PATH in files:
        if compiled is None or BASELINE_VERIFICATION_PATH not in files:
            raise _error("CORRECTION_BINDING")
        correction = _model_from_file(
            files[BASELINE_CORRECTION_PATH],
            BaselineCorrectionRecordV1,
            location=BASELINE_CORRECTION_PATH,
        )
        if correction.prior_baseline_root != _expected_prior_root(
            baseline_input, compiled, files
        ):
            raise _error("CORRECTION_PRIOR_ROOT")
        try:
            compiled = apply_baseline_correction_v1(
                baseline_input,
                compiled,
                correction,
                prior_baseline_root=correction.prior_baseline_root,
            )
        except BaselineCompilationError as error:
            raise _error("CORRECTION_REPLAY") from error
        bound.add(BASELINE_CORRECTION_PATH)
    if CANONICAL_BASELINE_PATH in files:
        if compiled is None:
            raise _error("BASELINE_UNEXPECTED")
        baseline = _model_from_file(
            files[CANONICAL_BASELINE_PATH],
            CanonicalBaselineV1,
            location=CANONICAL_BASELINE_PATH,
        )
        if baseline != compiled or files[CANONICAL_BASELINE_PATH] != canonical_json_bytes(
            compiled.model_dump(mode="json", warnings="error")
        ):
            raise _error("BASELINE_REPLAY")
        bound.add(CANONICAL_BASELINE_PATH)
    elif compiled is not None and BASELINE_REFEREES_PATH in files:
        raise _error("BASELINE_REQUIRED")
    if manifest.baseline_fingerprint != (
        None if baseline is None else baseline.baseline_fingerprint
    ):
        raise _error("BASELINE_BINDING")

    has_verification = BASELINE_VERIFICATION_PATH in files
    verification = BaselineVerificationV1(valid=True)
    if has_verification:
        stored_verification = _model_from_file(
            files[BASELINE_VERIFICATION_PATH],
            BaselineVerificationV1,
            location=BASELINE_VERIFICATION_PATH,
        )
        if stored_verification != verification or files[
            BASELINE_VERIFICATION_PATH
        ] != canonical_json_bytes(verification.model_dump(mode="json")):
            raise _error("VERIFICATION_RECEIPT")
        bound.add(BASELINE_VERIFICATION_PATH)

    _phase_requires(
        manifest,
        review=review,
        review_pending=review_pending,
        audit=audit,
        audit_pending=audit_pending,
        disputes=disputes,
        referees=referees,
        referee_pending=referee_pending,
        baseline=baseline,
        has_verification=has_verification,
    )
    extras = set(files) - bound
    if extras:
        if any(path.startswith("requests/") for path in extras):
            raise _error("UNBOUND_REQUEST")
        if any(path.startswith("responses/") for path in extras):
            raise _error("UNBOUND_RESPONSE")
        raise _error("UNBOUND_ARTIFACT")
    return _Replay(manifest, baseline_input, baseline, verification)


def _verify_or_raise(storage: RunStorage) -> _Replay:
    storage.assert_root_identity()
    initial_inventory = storage.scan_inventory()
    paths = {path for path in initial_inventory if not path.endswith("/")}
    if BASELINE_MANIFEST_PATH not in paths:
        raise _error("MANIFEST_MISSING")
    manifest = _manifest_from_bytes(
        storage.read_artifact(BASELINE_MANIFEST_PATH, max_bytes=_MAX_JSON_BYTES)
    )
    expected = {
        artifact.artifact_path for artifact in manifest.artifacts
    } | {BASELINE_MANIFEST_PATH}
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
        _parse_canonical_json(data, location=artifact.artifact_path)
        files[artifact.artifact_path] = data
    replay = _verify_baseline_snapshot(manifest, files)
    if storage.scan_inventory() != initial_inventory:
        raise _error("INVENTORY_CHANGED")
    storage.assert_root_identity()
    return replay


_PHASE_SUCCESSORS: dict[BaselinePhaseV1, frozenset[BaselinePhaseV1]] = {
    BaselinePhaseV1.CREATED: frozenset({BaselinePhaseV1.SOURCE_REVIEW}),
    BaselinePhaseV1.SOURCE_REVIEW: frozenset(
        {BaselinePhaseV1.SOURCE_REVIEW, BaselinePhaseV1.SOURCE_AUDIT}
    ),
    BaselinePhaseV1.SOURCE_AUDIT: frozenset(
        {
            BaselinePhaseV1.SOURCE_AUDIT,
            BaselinePhaseV1.SOURCE_REFEREE,
            BaselinePhaseV1.BASELINE_SEALED,
        }
    ),
    BaselinePhaseV1.SOURCE_REFEREE: frozenset(
        {BaselinePhaseV1.SOURCE_REFEREE, BaselinePhaseV1.BASELINE_SEALED}
    ),
    BaselinePhaseV1.BASELINE_SEALED: frozenset(
        {BaselinePhaseV1.COMPLETED, BaselinePhaseV1.INCONCLUSIVE}
    ),
    BaselinePhaseV1.COMPLETED: frozenset(),
    BaselinePhaseV1.INCONCLUSIVE: frozenset(),
}


def _validate_successor_transition(
    previous: BaselineManifestV1,
    successor: BaselineManifestV1,
) -> None:
    if (
        successor.legal_input_fingerprint != previous.legal_input_fingerprint
        or successor.phase not in _PHASE_SUCCESSORS[previous.phase]
        or previous.terminal_status is not None
        or (
            previous.baseline_fingerprint is not None
            and successor.baseline_fingerprint != previous.baseline_fingerprint
        )
        or successor.manifest_fingerprint == previous.manifest_fingerprint
    ):
        raise EvaluationIntegrityError("BASELINE_STALE_TRANSITION")


def _commit_with_rollback(
    storage: RunStorage,
    files: Mapping[str, bytes],
    successor: BaselineManifestV1,
    *,
    expected_manifest_fingerprint: str | None = None,
) -> BaselineManifestV1:
    snapshot_files = _snapshot_files(files)
    existing = storage.scan_files()
    inherited_files: dict[str, bytes] = {}
    prior_manifest_bytes: bytes | None = None
    prior_manifest: BaselineManifestV1 | None = None
    if existing:
        replay = _verify_or_raise(storage)
        prior_manifest = replay.manifest
        if (
            expected_manifest_fingerprint is not None
            and prior_manifest.manifest_fingerprint
            != expected_manifest_fingerprint
        ):
            raise EvaluationIntegrityError("BASELINE_STALE_TRANSITION")
        inherited_files = {
            artifact.artifact_path: storage.read_artifact(
                artifact.artifact_path, max_bytes=_MAX_JSON_BYTES
            )
            for artifact in prior_manifest.artifacts
        }
        prior_manifest_bytes = storage.read_artifact(
            BASELINE_MANIFEST_PATH, max_bytes=_MAX_JSON_BYTES
        )
    for path, data in snapshot_files.items():
        if path in inherited_files and inherited_files[path] != data:
            raise _error("IMMUTABLE_ARTIFACT")
    all_files = {**inherited_files, **snapshot_files}
    committed = _with_inventory(successor, all_files)
    if prior_manifest is not None:
        _validate_successor_transition(prior_manifest, committed)
    _, manifest_bytes = _manifest_bytes(committed)
    _verify_baseline_snapshot(committed, all_files)
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
                visible = (
                    error.created
                    if isinstance(error, _AtomicWriteOwnershipError)
                    else receipt is not None and receipt.created
                )
                if visible:
                    if identity is None:
                        raise _error("ROLLBACK_FAILED") from error
                    created.append((path, snapshot_files[path], identity))
                raise
            if created_now:
                receipt = storage.atomic_write_receipt(path)
                if receipt is None or not receipt.created or receipt.identity is None:
                    raise _error("ROLLBACK_FAILED")
                created.append((path, snapshot_files[path], receipt.identity))
        if any(
            storage.read_artifact(path, max_bytes=_MAX_JSON_BYTES) != data
            for path, data in snapshot_files.items()
        ):
            raise EvaluationIntegrityError("BASELINE_STALE_TRANSITION")
        if existing:
            if any(
                storage.read_artifact(path, max_bytes=_MAX_JSON_BYTES) != data
                for path, data in inherited_files.items()
            ):
                raise EvaluationIntegrityError("BASELINE_STALE_TRANSITION")
            current = _manifest_from_bytes(
                storage.read_artifact(
                    BASELINE_MANIFEST_PATH, max_bytes=_MAX_JSON_BYTES
                )
            )
            if (
                expected_manifest_fingerprint is not None
                and current.manifest_fingerprint
                != expected_manifest_fingerprint
            ):
                raise EvaluationIntegrityError("BASELINE_STALE_TRANSITION")
        try:
            manifest_installed = storage.atomic_write(
                BASELINE_MANIFEST_PATH,
                manifest_bytes,
                mutable=bool(existing),
            )
            receipt = storage.atomic_write_receipt(BASELINE_MANIFEST_PATH)
            if manifest_installed:
                manifest_identity = None if receipt is None else receipt.identity
                if manifest_identity is None:
                    raise _error("ROLLBACK_FAILED")
        except BaseException as error:
            receipt = storage.atomic_write_receipt(BASELINE_MANIFEST_PATH)
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
            raise
        installed = _verify_or_raise(storage)
        if installed.manifest != committed:
            raise EvaluationIntegrityError("BASELINE_STALE_TRANSITION")
    except BaseException as error:
        cleanup_error: BaseException | None = None
        restored_manifest = False
        try:
            observed = storage.read_optional_artifact_with_identity(
                BASELINE_MANIFEST_PATH, max_bytes=_MAX_JSON_BYTES
            )
            if prior_manifest_bytes is None:
                if (
                    manifest_installed
                    and manifest_identity is not None
                    and observed is not None
                    and observed[0] == manifest_bytes
                    and _same_filesystem_object(observed[1], manifest_identity)
                ):
                    storage.remove_artifact(
                        BASELINE_MANIFEST_PATH,
                        expected_identity=manifest_identity,
                        expected_data=manifest_bytes,
                    )
                    restored_manifest = True
                elif manifest_installed:
                    raise _error("ROLLBACK_FAILED")
            elif (
                manifest_installed
                and manifest_identity is not None
                and observed is not None
                and observed[0] == manifest_bytes
                and _same_filesystem_object(observed[1], manifest_identity)
            ):
                storage.replace_artifact_if_owned(
                    BASELINE_MANIFEST_PATH,
                    prior_manifest_bytes,
                    owned_identity=manifest_identity,
                    owned_data=manifest_bytes,
                )
                if storage.read_artifact(
                    BASELINE_MANIFEST_PATH, max_bytes=_MAX_JSON_BYTES
                ) != prior_manifest_bytes:
                    raise _error("ROLLBACK_FAILED")
                restored_manifest = True
            elif observed is None or observed[0] != prior_manifest_bytes:
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
                    BASELINE_MANIFEST_PATH: prior_manifest_bytes,
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


def initialize_baseline_storage_v1(
    run_dir: Path,
    manifest: BaselineManifestV1,
    files: Mapping[str, bytes],
) -> BaselineManifestV1:
    """Create an empty baseline root and expose only a replay-valid first state."""
    with (
        _run_operation_lock(run_dir),
        open_evaluation_storage(run_dir, initialize=True) as storage,
    ):
        return _commit_with_rollback(storage, files, manifest)


def commit_baseline_transition_v1(
    run_dir: Path,
    expected_manifest_fingerprint: str,
    files: Mapping[str, bytes],
    successor: BaselineManifestV1,
) -> None:
    """Commit one immutable successor iff the verified current root still matches."""
    with _run_operation_lock(run_dir), open_evaluation_storage(run_dir) as storage:
        current = _verify_or_raise(storage).manifest
        if current.manifest_fingerprint != expected_manifest_fingerprint:
            raise EvaluationIntegrityError("BASELINE_STALE_TRANSITION")
        _commit_with_rollback(
            storage,
            files,
            successor,
            expected_manifest_fingerprint=expected_manifest_fingerprint,
        )


def _safe_issue_code(error: BaseException) -> str:
    message = str(error)
    if message == "BASELINE_RESULT_REQUIRED":
        return "BASELINE_RESULT_REQUIRED"
    if "BASELINE_ARTIFACT_MANIFEST" in message:
        return "BASELINE_MANIFEST_INVALID"
    if any(
        marker in message
        for marker in (
            "BASELINE_ARTIFACT_INVENTORY",
            "BASELINE_ARTIFACT_UNBOUND",
        )
    ):
        return "BASELINE_INVENTORY_INVALID"
    if any(
        marker in message
        for marker in (
            "BASELINE_ARTIFACT_JSON",
            "BASELINE_ARTIFACT_MODEL",
            "BASELINE_ARTIFACT_ARTIFACT",
        )
    ):
        return "BASELINE_ARTIFACT_INVALID"
    if message.startswith("BASELINE_ARTIFACT_"):
        return "BASELINE_SEMANTIC_REPLAY_INVALID"
    return "BASELINE_STORAGE_UNSAFE"


def verify_baseline_run(run_dir: Path) -> BaselineVerificationV1:
    """Return only bounded diagnostics after exact inventory and semantic replay."""
    try:
        with _run_operation_lock(run_dir), open_evaluation_storage(run_dir) as storage:
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
        return BaselineVerificationV1(
            valid=False,
            issues=(_safe_issue_code(error),),
        )
    return replay.verification


def load_verified_baseline_run(run_dir: Path) -> VerifiedBaselineContextV1:
    """Load the exact four-field baseline context from one complete verified replay."""
    with _run_operation_lock(run_dir), open_evaluation_storage(run_dir) as storage:
        replay = _verify_or_raise(storage)
        storage.assert_root_identity()
        if replay.baseline is None or replay.verification.valid is not True:
            raise EvaluationIntegrityError("BASELINE_RESULT_REQUIRED")
        return VerifiedBaselineContextV1(
            manifest=replay.manifest,
            baseline_input=replay.baseline_input,
            baseline=replay.baseline,
            verification=replay.verification,
        )
