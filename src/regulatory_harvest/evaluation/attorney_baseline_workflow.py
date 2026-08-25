"""Recoverable controller for the report-blind evaluation-baseline-v1 lifecycle."""

from __future__ import annotations

import contextlib
import json
import os
import re
import stat
import threading
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol, cast, runtime_checkable

from pydantic import ValidationError

from regulatory_harvest.storage import canonical_json_bytes, sha256_digest

from . import attorney_baseline_artifacts as baseline_artifacts
from .attorney_artifacts import EvaluationIntegrityError, read_evaluation_artifact
from .attorney_baseline_compiler import (
    BaselineCompilationError,
    _validate_baseline_referee_choice_v1,
    aggregate_baseline_audit_v1,
    aggregate_baseline_referees_v1,
    aggregate_baseline_review_v1,
    build_baseline_disputes_v1,
    compile_canonical_baseline_v1,
)
from .attorney_baseline_input import BaselineInputError, build_baseline_input_v1
from .attorney_baseline_models import (
    BASELINE_PROTOCOL_V1,
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
    BaselineOperationV1,
    BaselinePhaseV1,
    BaselineRefereeAggregateV1,
    BaselineRefereeDecisionV1,
    BaselineReviewAggregateV1,
    BaselineReviewFragmentV1,
    BaselineRunStateV1,
    BaselineVerificationV1,
    CanonicalBaselineV1,
    strict_baseline_model_v1,
)
from .attorney_baseline_requests import (
    build_baseline_source_audit_request_v1,
    build_baseline_source_referee_request_v1,
    build_baseline_source_review_request_v1,
)

BASELINE_EXTERNAL_RESPONSE_INVALID = "BASELINE_EXTERNAL_RESPONSE_INVALID"
BASELINE_PROVIDER_FAILURE = "BASELINE_PROVIDER_FAILURE"
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_JSON_BYTES = 16 * 1024 * 1024
_SUBMISSION_LOCKS = tuple(threading.RLock() for _ in range(64))


@dataclass(frozen=True)
class BaselineDraftPromptV1:
    """One fresh bounded role prompt; rejected draft bytes are never retained."""

    request: BaselineEvaluatorRequestV1
    attempt: Literal[1, 2]
    repair_codes: tuple[str, ...] = ()


@runtime_checkable
class BaselineDraftEvaluatorV1(Protocol):
    """Provider-neutral adapter that authors one strict inner role payload."""

    provider_name: str
    model_name: str
    judge_isolation: Literal["fresh_context", "scripted_fixture"]

    async def evaluate_draft(self, prompt: BaselineDraftPromptV1) -> object: ...


@dataclass(frozen=True)
class GuardedBaselineSubmissionResultV1:
    accepted: bool
    issue_codes: tuple[str, ...]
    state: BaselineRunStateV1 | None = None


@dataclass(frozen=True)
class BaselineDriverOutcomeV1:
    state: BaselineRunStateV1
    engine_paused: bool
    pause_reason_codes: tuple[str, ...] = ()
    pending_request: BaselineEvaluatorRequestV1 | None = None
    exit_code: int = 0


@dataclass(frozen=True)
class _VerifiedWorkflowContextV1:
    manifest: BaselineManifestV1
    baseline_input: BaselineInputV1
    baseline: CanonicalBaselineV1 | None
    verification: BaselineVerificationV1 | None
    files: Mapping[str, bytes]
    root_identity: baseline_artifacts.BaselineRootIdentityV1


def _model_bytes(value: object) -> bytes:
    if not hasattr(value, "model_dump"):
        raise TypeError("baseline artifact must be a strict model")
    return canonical_json_bytes(value.model_dump(mode="json", warnings="error"))


def _state_from_manifest_v1(manifest: BaselineManifestV1) -> BaselineRunStateV1:
    pending = manifest.pending_call
    return BaselineRunStateV1(
        legal_input_fingerprint=manifest.legal_input_fingerprint,
        phase=manifest.phase,
        current_call_id=None if pending is None else pending.call_id,
        terminal_status=manifest.terminal_status,
        manifest_fingerprint=manifest.manifest_fingerprint,
    )


def _successor_manifest_v1(
    baseline_input: BaselineInputV1,
    phase: BaselinePhaseV1,
    *,
    terminal_status: Literal["COMPLETED", "INCONCLUSIVE"] | None = None,
) -> BaselineManifestV1:
    return BaselineManifestV1(
        legal_input_fingerprint=baseline_input.legal_input_fingerprint,
        phase=phase,
        terminal_status=terminal_status,
        artifacts=(),
        root_hash="0" * 64,
        manifest_fingerprint="0" * 64,
    )


def _load_verified_baseline_context_v1(run_dir: Path) -> _VerifiedWorkflowContextV1:
    with baseline_artifacts._open_locked_storage(
        run_dir, exclusive=False
    ) as storage:
        root_identity = baseline_artifacts._storage_root_identity_v1(storage)
        replay = baseline_artifacts._verify_or_raise(storage)
        files = {
            artifact.artifact_path: storage.read_artifact(
                artifact.artifact_path, max_bytes=_MAX_JSON_BYTES
            )
            for artifact in replay.manifest.artifacts
        }
        storage.assert_root_identity()
    return _VerifiedWorkflowContextV1(
        manifest=replay.manifest,
        baseline_input=replay.baseline_input,
        baseline=replay.baseline,
        verification=replay.verification,
        files=files,
        root_identity=root_identity,
    )


def _pending_request_from_verified_context_v1(
    context: _VerifiedWorkflowContextV1,
) -> BaselineEvaluatorRequestV1 | None:
    pending = context.manifest.pending_call
    if pending is None:
        return None
    try:
        request = BaselineEvaluatorRequestV1.model_validate_json(
            context.files[pending.request_artifact_path]
        )
    except (KeyError, ValidationError, ValueError) as error:
        raise EvaluationIntegrityError("BASELINE_PENDING_REQUEST_INVALID") from error
    if (
        request.operation is not pending.operation
        or request.request_fingerprint != pending.request_fingerprint
    ):
        raise EvaluationIntegrityError("BASELINE_PENDING_REQUEST_INVALID")
    return request


def _submission_identity(run_dir: Path) -> tuple[int, int]:
    try:
        metadata = os.stat(run_dir, follow_symlinks=False)
    except (NotImplementedError, OSError, TypeError, ValueError) as error:
        raise EvaluationIntegrityError("BASELINE_STORAGE_UNSAFE") from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise EvaluationIntegrityError("BASELINE_STORAGE_UNSAFE")
    return metadata.st_dev, metadata.st_ino


@contextlib.contextmanager
def _submission_guard(run_dir: Path) -> Iterator[None]:
    identity = _submission_identity(run_dir)
    index = int(sha256_digest(f"{identity[0]}:{identity[1]}".encode())[:8], 16) % len(
        _SUBMISSION_LOCKS
    )
    with _SUBMISSION_LOCKS[index]:
        if _submission_identity(run_dir) != identity:
            raise EvaluationIntegrityError("BASELINE_STORAGE_UNSAFE")
        yield
        if _submission_identity(run_dir) != identity:
            raise EvaluationIntegrityError("BASELINE_STORAGE_UNSAFE")


def _load_canonical_correction(path: Path) -> BaselineCorrectionRecordV1:
    try:
        absolute = Path(os.path.abspath(path))
        physical = absolute.resolve(strict=True)
        if absolute != physical or not physical.is_file():
            raise ValueError
        data = read_evaluation_artifact(
            physical.parent, physical.name, max_bytes=_MAX_JSON_BYTES
        )
        raw = json.loads(data.decode("utf-8"))
        if data != canonical_json_bytes(raw):
            raise ValueError
        return BaselineCorrectionRecordV1.model_validate(raw)
    except (
        EvaluationIntegrityError,
        OSError,
        RecursionError,
        TypeError,
        UnicodeDecodeError,
        ValidationError,
        ValueError,
        json.JSONDecodeError,
    ) as error:
        raise ValueError("BASELINE_CORRECTION_INVALID") from error


def _verified_prior_context(
    prior_baseline_path: Path,
    prior_ancestry: tuple[Path, ...],
) -> baseline_artifacts.VerifiedBaselineContextV1:
    try:
        if prior_ancestry:
            return baseline_artifacts.load_verified_baseline_run(
                prior_baseline_path,
                prior_run_dir=prior_ancestry[-1],
                prior_ancestry=prior_ancestry[:-1],
            )
        return baseline_artifacts.load_verified_baseline_run(prior_baseline_path)
    except (EvaluationIntegrityError, OSError, TypeError, ValidationError, ValueError) as error:
        raise EvaluationIntegrityError(
            "BASELINE_CORRECTION_PRIOR_UNVERIFIED"
        ) from error


def initialize_baseline_v1(
    control_input_path: Path,
    output_dir: Path,
    *,
    nonce_hex: str,
    prior_baseline_path: Path | None = None,
    correction_path: Path | None = None,
    prior_ancestry: tuple[Path, ...] = (),
) -> BaselineRunStateV1:
    """Initialize an ordinary role run or a new verified correction sibling."""
    baseline_input = build_baseline_input_v1(control_input_path)
    if type(nonce_hex) is not str or _HASH_RE.fullmatch(nonce_hex) is None:
        raise BaselineInputError("BASELINE_NONCE_INVALID")
    correction_arguments = (prior_baseline_path, correction_path)
    if any(item is None for item in correction_arguments) and any(
        item is not None for item in correction_arguments
    ):
        raise ValueError("BASELINE_CORRECTION_ARGUMENTS")
    if prior_baseline_path is None:
        if prior_ancestry:
            raise ValueError("BASELINE_CORRECTION_ARGUMENTS")
        request = build_baseline_source_review_request_v1(
            baseline_input, (), fragment_ordinal=1
        )
        manifest = _successor_manifest_v1(
            baseline_input, BaselinePhaseV1.SOURCE_REVIEW
        )
        committed = baseline_artifacts.initialize_baseline_storage_v1(
            output_dir,
            manifest,
            {
                baseline_artifacts.BASELINE_INPUT_PATH: _model_bytes(baseline_input),
                "requests/source-review-0001.json": _model_bytes(request),
            },
        )
        return _state_from_manifest_v1(committed)

    assert correction_path is not None
    if type(prior_ancestry) is not tuple or any(
        not isinstance(item, Path) for item in prior_ancestry
    ):
        raise ValueError("BASELINE_CORRECTION_ARGUMENTS")
    prior = _verified_prior_context(prior_baseline_path, prior_ancestry)
    if prior.baseline_input != baseline_input:
        raise ValueError("BASELINE_CORRECTION_LEGAL_INPUT_CHANGED")
    correction = _load_canonical_correction(correction_path)
    committed = baseline_artifacts.initialize_corrected_baseline_storage_v1(
        prior_baseline_path,
        output_dir,
        correction,
        prior_ancestry=prior_ancestry,
    )
    return _state_from_manifest_v1(committed)


def _complete_sealed_baseline_v1(
    run_dir: Path, context: _VerifiedWorkflowContextV1
) -> BaselineRunStateV1:
    if context.manifest.phase is not BaselinePhaseV1.BASELINE_SEALED:
        return _state_from_manifest_v1(context.manifest)
    verification = BaselineVerificationV1(valid=True)
    successor = _successor_manifest_v1(
        context.baseline_input,
        BaselinePhaseV1.COMPLETED,
        terminal_status="COMPLETED",
    )
    baseline_artifacts.commit_baseline_transition_v1(
        run_dir,
        context.manifest.manifest_fingerprint,
        {baseline_artifacts.BASELINE_VERIFICATION_PATH: _model_bytes(verification)},
        successor,
        expected_root_identity=context.root_identity,
    )
    return _state_from_manifest_v1(_load_verified_baseline_context_v1(run_dir).manifest)


def next_baseline_request_v1(run_dir: Path) -> BaselineEvaluatorRequestV1 | None:
    """Return the exact pending request retained by one verified ordinary run."""
    context = _load_verified_baseline_context_v1(run_dir)
    if context.manifest.phase is BaselinePhaseV1.BASELINE_SEALED:
        _complete_sealed_baseline_v1(run_dir, context)
        context = _load_verified_baseline_context_v1(run_dir)
    return _pending_request_from_verified_context_v1(context)


def resume_baseline_v1(run_dir: Path) -> BaselineRunStateV1:
    """Verify and resume a crash-interrupted seal without repeating role work."""
    context = _load_verified_baseline_context_v1(run_dir)
    return _complete_sealed_baseline_v1(run_dir, context)


def _accepted_review_fragments(
    context: _VerifiedWorkflowContextV1,
) -> tuple[AcceptedBaselineReviewFragmentV1, ...]:
    result = []
    for call in context.manifest.accepted_calls:
        if call.operation is not BaselineOperationV1.SOURCE_REVIEW:
            continue
        assert call.response_artifact_path is not None
        response = BaselineEvaluatorResponseV1.model_validate_json(
            context.files[call.response_artifact_path]
        )
        payload = cast(
            BaselineReviewFragmentV1,
            strict_baseline_model_v1(BaselineReviewFragmentV1, response.payload),
        )
        result.append(
            AcceptedBaselineReviewFragmentV1(
                fragment_ordinal=cast(int, call.fragment_ordinal),
                request_fingerprint=call.request_fingerprint,
                response_fingerprint=cast(str, call.response_fingerprint),
                payload=payload,
            )
        )
    return tuple(result)


def _accepted_audit_fragments(
    context: _VerifiedWorkflowContextV1,
) -> tuple[AcceptedBaselineAuditFragmentV1, ...]:
    result = []
    for call in context.manifest.accepted_calls:
        if call.operation is not BaselineOperationV1.SOURCE_AUDIT:
            continue
        assert call.response_artifact_path is not None
        response = BaselineEvaluatorResponseV1.model_validate_json(
            context.files[call.response_artifact_path]
        )
        payload = cast(
            BaselineAuditFragmentV1,
            strict_baseline_model_v1(BaselineAuditFragmentV1, response.payload),
        )
        result.append(
            AcceptedBaselineAuditFragmentV1(
                fragment_ordinal=cast(int, call.fragment_ordinal),
                request_fingerprint=call.request_fingerprint,
                response_fingerprint=cast(str, call.response_fingerprint),
                payload=payload,
            )
        )
    return tuple(result)


def _accepted_referee_fragments(
    context: _VerifiedWorkflowContextV1,
    disputes_by_id: Mapping[str, BaselineDisputeV1],
) -> tuple[AcceptedBaselineRefereeFragmentV1, ...]:
    result = []
    for call in context.manifest.accepted_calls:
        if call.operation is not BaselineOperationV1.SOURCE_REFEREE:
            continue
        assert call.response_artifact_path is not None and call.dispute_id is not None
        response = BaselineEvaluatorResponseV1.model_validate_json(
            context.files[call.response_artifact_path]
        )
        decision = cast(
            BaselineRefereeDecisionV1,
            strict_baseline_model_v1(BaselineRefereeDecisionV1, response.payload),
        )
        dispute = disputes_by_id[call.dispute_id]
        dispute_fingerprint = dispute.dispute_fingerprint
        result.append(
            AcceptedBaselineRefereeFragmentV1(
                dispute_id=call.dispute_id,
                dispute_fingerprint=dispute_fingerprint,
                response_fingerprint=cast(str, call.response_fingerprint),
                decision=decision,
            )
        )
    return tuple(result)


def _aggregate_from_context(
    context: _VerifiedWorkflowContextV1,
    path: str,
    model: type[BaselineReviewAggregateV1] | type[BaselineAuditAggregateV1],
) -> BaselineReviewAggregateV1 | BaselineAuditAggregateV1:
    try:
        return model.model_validate_json(context.files[path])
    except (KeyError, ValidationError, ValueError) as error:
        raise EvaluationIntegrityError("BASELINE_AGGREGATE_INVALID") from error


def _seal_files(
    baseline_input: BaselineInputV1,
    review: BaselineReviewAggregateV1,
    audit: BaselineAuditAggregateV1,
    referees: BaselineRefereeAggregateV1,
) -> tuple[dict[str, bytes], CanonicalBaselineV1]:
    baseline = compile_canonical_baseline_v1(
        baseline_input, review, audit, referees
    )
    return (
        {
            baseline_artifacts.BASELINE_REFEREES_PATH: _model_bytes(referees),
            baseline_artifacts.CANONICAL_BASELINE_PATH: _model_bytes(baseline),
        },
        baseline,
    )


def _advance_baseline_response_v1(
    run_dir: Path,
    context: _VerifiedWorkflowContextV1,
    response: BaselineEvaluatorResponseV1,
) -> BaselineRunStateV1:
    pending = context.manifest.pending_call
    if pending is None:
        raise ValueError(BASELINE_EXTERNAL_RESPONSE_INVALID)
    response_path = f"responses/{pending.call_id}.json"
    response_bytes = _model_bytes(response)
    response_fingerprint = sha256_digest(response_bytes)
    files: dict[str, bytes] = {response_path: response_bytes}
    baseline_input = context.baseline_input

    if pending.operation is BaselineOperationV1.SOURCE_REVIEW:
        review_payload = cast(
            BaselineReviewFragmentV1,
            strict_baseline_model_v1(BaselineReviewFragmentV1, response.payload),
        )
        review_history = (
            *_accepted_review_fragments(context),
            AcceptedBaselineReviewFragmentV1(
                fragment_ordinal=cast(int, pending.fragment_ordinal),
                request_fingerprint=pending.request_fingerprint,
                response_fingerprint=response_fingerprint,
                payload=review_payload,
            ),
        )
        if not review_payload.review_complete:
            request = build_baseline_source_review_request_v1(
                baseline_input,
                review_history,
                fragment_ordinal=len(review_history) + 1,
            )
            files[
                f"requests/source-review-{len(review_history) + 1:04d}.json"
            ] = _model_bytes(request)
            successor = _successor_manifest_v1(
                baseline_input, BaselinePhaseV1.SOURCE_REVIEW
            )
        else:
            review = aggregate_baseline_review_v1(baseline_input, review_history)
            files[baseline_artifacts.BASELINE_REVIEW_PATH] = _model_bytes(review)
            request = build_baseline_source_audit_request_v1(
                baseline_input, review, (), fragment_ordinal=1
            )
            files["requests/source-audit-0001.json"] = _model_bytes(request)
            successor = _successor_manifest_v1(
                baseline_input, BaselinePhaseV1.SOURCE_AUDIT
            )
    else:
        review_value = _aggregate_from_context(
            context,
            baseline_artifacts.BASELINE_REVIEW_PATH,
            BaselineReviewAggregateV1,
        )
        review = cast(BaselineReviewAggregateV1, review_value)
        if pending.operation is BaselineOperationV1.SOURCE_AUDIT:
            audit_payload = cast(
                BaselineAuditFragmentV1,
                strict_baseline_model_v1(BaselineAuditFragmentV1, response.payload),
            )
            audit_history = (
                *_accepted_audit_fragments(context),
                AcceptedBaselineAuditFragmentV1(
                    fragment_ordinal=cast(int, pending.fragment_ordinal),
                    request_fingerprint=pending.request_fingerprint,
                    response_fingerprint=response_fingerprint,
                    payload=audit_payload,
                ),
            )
            if not audit_payload.audit_complete:
                request = build_baseline_source_audit_request_v1(
                    baseline_input,
                    review,
                    audit_history,
                    fragment_ordinal=len(audit_history) + 1,
                )
                files[
                    f"requests/source-audit-{len(audit_history) + 1:04d}.json"
                ] = _model_bytes(request)
                successor = _successor_manifest_v1(
                    baseline_input, BaselinePhaseV1.SOURCE_AUDIT
                )
            else:
                audit = aggregate_baseline_audit_v1(
                    baseline_input, review, audit_history
                )
                files[baseline_artifacts.BASELINE_AUDIT_PATH] = _model_bytes(audit)
                disputes = build_baseline_disputes_v1(baseline_input, review, audit)
                if disputes:
                    request = build_baseline_source_referee_request_v1(
                        baseline_input, disputes[0]
                    )
                    files[
                        f"requests/source-referee-{disputes[0].dispute_id}.json"
                    ] = _model_bytes(request)
                    successor = _successor_manifest_v1(
                        baseline_input, BaselinePhaseV1.SOURCE_REFEREE
                    )
                else:
                    referees = aggregate_baseline_referees_v1(baseline_input, (), ())
                    sealed_files, _ = _seal_files(
                        baseline_input, review, audit, referees
                    )
                    files.update(sealed_files)
                    successor = _successor_manifest_v1(
                        baseline_input, BaselinePhaseV1.BASELINE_SEALED
                    )
        else:
            audit_value = _aggregate_from_context(
                context,
                baseline_artifacts.BASELINE_AUDIT_PATH,
                BaselineAuditAggregateV1,
            )
            audit = cast(BaselineAuditAggregateV1, audit_value)
            disputes = build_baseline_disputes_v1(baseline_input, review, audit)
            by_id = {item.dispute_id: item for item in disputes}
            if pending.dispute_id not in by_id:
                raise EvaluationIntegrityError("BASELINE_PENDING_REQUEST_INVALID")
            decision = cast(
                BaselineRefereeDecisionV1,
                strict_baseline_model_v1(
                    BaselineRefereeDecisionV1, response.payload
                ),
            )
            _validate_baseline_referee_choice_v1(
                baseline_input, by_id[pending.dispute_id], decision
            )
            referee_history = (
                *_accepted_referee_fragments(context, by_id),
                AcceptedBaselineRefereeFragmentV1(
                    dispute_id=pending.dispute_id,
                    dispute_fingerprint=by_id[pending.dispute_id].dispute_fingerprint,
                    response_fingerprint=response_fingerprint,
                    decision=decision,
                ),
            )
            if len(referee_history) < len(disputes):
                next_dispute = disputes[len(referee_history)]
                request = build_baseline_source_referee_request_v1(
                    baseline_input, next_dispute
                )
                files[
                    f"requests/source-referee-{next_dispute.dispute_id}.json"
                ] = _model_bytes(request)
                successor = _successor_manifest_v1(
                    baseline_input, BaselinePhaseV1.SOURCE_REFEREE
                )
            else:
                referees = aggregate_baseline_referees_v1(
                    baseline_input, disputes, referee_history
                )
                sealed_files, _ = _seal_files(
                    baseline_input, review, audit, referees
                )
                files.update(sealed_files)
                successor = _successor_manifest_v1(
                    baseline_input, BaselinePhaseV1.BASELINE_SEALED
                )

    baseline_artifacts.commit_baseline_transition_v1(
        run_dir,
        context.manifest.manifest_fingerprint,
        files,
        successor,
        expected_root_identity=context.root_identity,
    )
    updated = _load_verified_baseline_context_v1(run_dir)
    return _complete_sealed_baseline_v1(run_dir, updated)


def _controller_bound_response_v1(
    request: BaselineEvaluatorRequestV1 | None,
    payload: object,
    *,
    provider_name: str,
    model_name: str,
    judge_isolation: Literal["fresh_context", "scripted_fixture"],
) -> BaselineEvaluatorResponseV1:
    if request is None or type(payload) is not dict:
        raise ValueError(BASELINE_EXTERNAL_RESPONSE_INVALID)
    return BaselineEvaluatorResponseV1(
        operation=request.operation,
        request_fingerprint=request.request_fingerprint,
        provider_name=provider_name,
        model_name=model_name,
        judge_isolation=judge_isolation,
        payload=payload,
    )


def guarded_submit_baseline_response_v1(
    run_dir: Path,
    payload: object,
    *,
    provider_name: str,
    model_name: str,
    judge_isolation: Literal["fresh_context", "scripted_fixture"],
) -> GuardedBaselineSubmissionResultV1:
    """Preflight a controller-bound inner payload and commit only if fully valid."""
    with _submission_guard(run_dir):
        context = _load_verified_baseline_context_v1(run_dir)
        request = _pending_request_from_verified_context_v1(context)
        try:
            response = _controller_bound_response_v1(
                request,
                payload,
                provider_name=provider_name,
                model_name=model_name,
                judge_isolation=judge_isolation,
            )
            state = _advance_baseline_response_v1(run_dir, context, response)
        except EvaluationIntegrityError:
            raise
        except (
            BaselineCompilationError,
            RecursionError,
            TypeError,
            ValidationError,
            ValueError,
        ):
            return GuardedBaselineSubmissionResultV1(
                False, (BASELINE_EXTERNAL_RESPONSE_INVALID,)
            )
        return GuardedBaselineSubmissionResultV1(True, (), state)


def _baseline_status_from_manifest_v1(
    manifest: BaselineManifestV1,
) -> dict[str, object]:
    pending = manifest.pending_call
    return {
        "protocol_version": BASELINE_PROTOCOL_V1,
        "phase": manifest.phase.value,
        "pending_operation": None if pending is None else pending.operation.value,
        "request_fingerprint": None if pending is None else pending.request_fingerprint,
        "legal_input_fingerprint": manifest.legal_input_fingerprint,
        "baseline_fingerprint": manifest.baseline_fingerprint,
        "manifest_fingerprint": manifest.manifest_fingerprint,
        "root_hash": manifest.root_hash,
        "engine_paused": False,
    }


def baseline_status_payload_v1(
    run_dir: Path,
    *,
    prior_baseline_path: Path | None = None,
    prior_ancestry: tuple[Path, ...] = (),
) -> dict[str, object]:
    """Return the allowlisted public status projection without paths or source bytes."""
    if prior_baseline_path is None:
        if prior_ancestry:
            raise ValueError("BASELINE_CORRECTION_ARGUMENTS")
        manifest = _load_verified_baseline_context_v1(run_dir).manifest
    else:
        manifest = baseline_artifacts.load_verified_baseline_run(
            run_dir,
            prior_run_dir=prior_baseline_path,
            prior_ancestry=prior_ancestry,
        ).manifest
    return _baseline_status_from_manifest_v1(manifest)


def _pause_outcome_v1(
    run_dir: Path,
    request: BaselineEvaluatorRequestV1,
    reason: str,
) -> BaselineDriverOutcomeV1:
    return BaselineDriverOutcomeV1(
        state=resume_baseline_v1(run_dir),
        engine_paused=True,
        pause_reason_codes=(reason,),
        pending_request=request,
        exit_code=6,
    )


async def _drive_one_baseline_role_v1(
    run_dir: Path,
    evaluator: BaselineDraftEvaluatorV1,
) -> BaselineDriverOutcomeV1:
    request = next_baseline_request_v1(run_dir)
    if request is None:
        return BaselineDriverOutcomeV1(
            state=resume_baseline_v1(run_dir), engine_paused=False
        )
    repair_codes: tuple[str, ...] = ()
    for attempt in cast(tuple[Literal[1, 2], ...], (1, 2)):
        prompt = BaselineDraftPromptV1(
            request=request,
            attempt=attempt,
            repair_codes=repair_codes,
        )
        try:
            draft = await evaluator.evaluate_draft(prompt)
        except Exception:
            return _pause_outcome_v1(run_dir, request, BASELINE_PROVIDER_FAILURE)
        submitted = guarded_submit_baseline_response_v1(
            run_dir,
            draft,
            provider_name=evaluator.provider_name,
            model_name=evaluator.model_name,
            judge_isolation=evaluator.judge_isolation,
        )
        if submitted.accepted and submitted.state is not None:
            return BaselineDriverOutcomeV1(
                state=submitted.state,
                engine_paused=False,
                pending_request=next_baseline_request_v1(run_dir),
            )
        current = next_baseline_request_v1(run_dir)
        if current is None or current.request_fingerprint != request.request_fingerprint:
            return BaselineDriverOutcomeV1(
                state=resume_baseline_v1(run_dir),
                engine_paused=False,
                pending_request=current,
            )
        if attempt == 1:
            repair_codes = (BASELINE_EXTERNAL_RESPONSE_INVALID,)
            continue
        return _pause_outcome_v1(
            run_dir, request, BASELINE_EXTERNAL_RESPONSE_INVALID
        )
    raise AssertionError("unreachable baseline attempt state")


async def continue_baseline_v1(
    run_dir: Path,
    evaluator: BaselineDraftEvaluatorV1,
    *,
    max_roles: int | None = None,
) -> BaselineDriverOutcomeV1:
    """Resume accepted history and drive fresh roles until completion or engine pause."""
    if not isinstance(evaluator, BaselineDraftEvaluatorV1):
        raise TypeError("evaluator must implement BaselineDraftEvaluatorV1")
    if max_roles is not None and (type(max_roles) is not int or max_roles < 1):
        raise ValueError("max_roles must be a positive integer")
    roles = 0
    while max_roles is None or roles < max_roles:
        state = resume_baseline_v1(run_dir)
        if state.terminal_status is not None:
            return BaselineDriverOutcomeV1(state=state, engine_paused=False)
        outcome = await _drive_one_baseline_role_v1(run_dir, evaluator)
        if outcome.engine_paused:
            return outcome
        roles += 1
    return BaselineDriverOutcomeV1(
        state=resume_baseline_v1(run_dir),
        engine_paused=False,
        pending_request=next_baseline_request_v1(run_dir),
    )
