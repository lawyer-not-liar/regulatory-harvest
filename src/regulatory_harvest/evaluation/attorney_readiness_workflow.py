"""Resumable controller for the opt-in delivery-readiness-v1 lifecycle."""

from __future__ import annotations

import contextlib
import os
import stat
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol, cast, runtime_checkable

from pydantic import ValidationError

from regulatory_harvest.storage import canonical_json_bytes, sha256_digest

from .attorney_artifacts import EvaluationIntegrityError
from .attorney_readiness_artifacts import (
    ATTORNEY_HANDOFF_PATH,
    GAP_MATRIX_PATH,
    GRADER_LANE_1_PATH,
    GRADER_LANE_2_PATH,
    HISTORICAL_CROSS_CHECK_PATH,
    READINESS_RESULT_PATH,
    REQUIREMENT_MATRIX_PATH,
    SAFETY_REVIEW_PATH,
    STRICT_EQUIVALENT_PATH,
    ReadinessResponsePreflightV1,
    VerifiedReadinessContextV1,
    commit_readiness_transition_v1,
    initialize_readiness_run_storage_v1,
    load_verified_readiness_context_v1,
)
from .attorney_readiness_artifacts import (
    preflight_readiness_response_v1 as artifact_preflight_readiness_response_v1,
)
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
    NeedsReadinessClarificationV1,
    ReadinessDraftReasonCodeV1,
    ReadinessEngineDefectV1,
    ReadinessEvaluatorDraftPromptV1,
    ReadinessEvaluatorProvenanceV1,
    compile_readiness_draft_v1,
)
from .attorney_readiness_handoff import render_attorney_review_handoff_v1
from .attorney_readiness_inputs import (
    VerifiedReadinessInputsV1,
    build_verified_readiness_input_v1,
)
from .attorney_readiness_models import (
    BaselineLockedContestedGradeV1,
    BaselineLockedGradeFragmentV1,
    BaselineLockedGraderAggregateV1,
    BaselineLockedStrictEquivalentV1,
    DeliveryReadinessResultV1,
    DeliveryReadinessTierV1,
    ReadinessCallRecordV1,
    ReadinessEvaluatorRequestV1,
    ReadinessEvaluatorResponseV1,
    ReadinessOperationV1,
    ReadinessPhaseV1,
    ReadinessRunStateV1,
    SafetyGapCandidateV1,
    SafetyLaneResponseV1,
    SafetyRefereeDecisionV1,
    validate_readiness_evaluator_response_v1,
)
from .attorney_readiness_requests import (
    build_baseline_locked_contested_grade_request_v1,
    build_baseline_locked_grade_batches_v1,
    build_baseline_locked_grade_request_v1,
    build_gap_candidate_inventory_v1,
    build_safety_disputes_v1,
    build_safety_lane_request_v1,
    build_safety_referee_request_v1,
    readiness_compiler_contract_fingerprint_v1,
)

READINESS_EXTERNAL_RESPONSE_INVALID = "READINESS_EXTERNAL_RESPONSE_INVALID"
READINESS_PROVIDER_FAILURE = "READINESS_PROVIDER_FAILURE"
READINESS_CONTEXT_ISOLATION_INVALID = "READINESS_CONTEXT_ISOLATION_INVALID"
READINESS_COMPILER_PREFLIGHT_DISAGREEMENT = "READINESS_COMPILER_PREFLIGHT_DISAGREEMENT"

_SUBMISSION_LOCKS = tuple(threading.RLock() for _ in range(64))


@runtime_checkable
class ReadinessDraftEvaluatorV1(Protocol):
    async def evaluate_draft(self, prompt: ReadinessEvaluatorDraftPromptV1) -> object: ...


@dataclass(frozen=True)
class ReadinessTelemetryEventV1:
    protocol_version: Literal["delivery-readiness-v1"]
    compiler_contract_fingerprint: str
    scoring_contract_fingerprint: str
    operation: str
    fragment_class: Literal[
        "ordinary_batch", "contested_requirement", "safety_lane", "safety_dispute"
    ]
    lane: Literal[1, 2] | None
    attempt_number: Literal[1, 2]
    normalization_codes: tuple[str, ...] = ()
    clarification_codes: tuple[str, ...] = ()
    pause_count: int = 0
    resume_count: int = 0


@runtime_checkable
class ReadinessTelemetrySinkV1(Protocol):
    def emit(self, event: ReadinessTelemetryEventV1) -> None: ...


@dataclass(frozen=True)
class ReadinessDriverOutcomeV1:
    state: ReadinessRunStateV1
    result: DeliveryReadinessResultV1 | None
    engine_paused: bool
    pause_reason_codes: tuple[str, ...] = ()
    pending_request: ReadinessEvaluatorRequestV1 | None = None
    exit_code: int = 0


@dataclass(frozen=True)
class GuardedReadinessSubmissionResultV1:
    accepted: bool
    preflight: ReadinessResponsePreflightV1
    state: ReadinessRunStateV1 | None = None


class _NoopTelemetrySinkV1:
    def emit(self, event: ReadinessTelemetryEventV1) -> None:
        del event


_NOOP_TELEMETRY = _NoopTelemetrySinkV1()


def _root_identity(run_dir: Path) -> tuple[int, int]:
    try:
        metadata = os.stat(run_dir, follow_symlinks=False)
    except (NotImplementedError, OSError, TypeError, ValueError) as error:
        raise EvaluationIntegrityError("READINESS_STORAGE_UNSAFE") from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise EvaluationIntegrityError("READINESS_STORAGE_UNSAFE")
    return metadata.st_dev, metadata.st_ino


@contextmanager
def _submission_guard(run_dir: Path) -> Iterator[None]:
    identity = _root_identity(run_dir)
    index = int(sha256_digest(f"{identity[0]}:{identity[1]}".encode())[:8], 16) % len(
        _SUBMISSION_LOCKS
    )
    with _SUBMISSION_LOCKS[index]:
        if _root_identity(run_dir) != identity:
            raise EvaluationIntegrityError("READINESS_STORAGE_UNSAFE")
        yield
        if _root_identity(run_dir) != identity:
            raise EvaluationIntegrityError("READINESS_STORAGE_UNSAFE")


def _state(context: VerifiedReadinessContextV1) -> ReadinessRunStateV1:
    pending = context.manifest.pending_call
    return ReadinessRunStateV1(
        grade_target_fingerprint=context.manifest.grade_target_fingerprint,
        report_hash=context.manifest.report_hash,
        phase=context.manifest.phase,
        current_call_id=None if pending is None else pending.call_id,
        terminal_status=context.manifest.terminal_status,
        manifest_fingerprint=context.manifest.manifest_fingerprint,
    )


def _request_identity(
    request: ReadinessEvaluatorRequestV1,
) -> tuple[str, Literal[1, 2] | None, str | None]:
    call_id: object = None
    for key in ("controller_lane_id", "controller_safety_lane_id", "controller_referee_id"):
        value = request.payload.get(key)
        if type(value) is str:
            call_id = value
            break
    if type(call_id) is not str:
        raise EvaluationIntegrityError("READINESS_CALL_ID_INVALID")
    lane = request.payload.get("lane")
    checked_lane: Literal[1, 2] | None = lane if lane in (1, 2) else None
    dispute = request.payload.get("dispute_id")
    return call_id, checked_lane, dispute if type(dispute) is str else None


def _pending_call(request: ReadinessEvaluatorRequestV1) -> ReadinessCallRecordV1:
    call_id, lane, dispute_id = _request_identity(request)
    return ReadinessCallRecordV1(
        call_id=call_id,
        operation=request.operation,
        state="pending",
        attempt=1,
        lane=lane,
        request_artifact_path=f"requests/{call_id}.json",
        request_fingerprint=request.request_fingerprint,
        dispute_id=dispute_id,
    )


def _request_bytes(request: ReadinessEvaluatorRequestV1) -> bytes:
    return canonical_json_bytes(request.model_dump(mode="json", warnings="error"))


def _response_bytes(response: ReadinessEvaluatorResponseV1) -> bytes:
    return canonical_json_bytes(response.model_dump(mode="json", warnings="error"))


def _grade_requests(inputs: VerifiedReadinessInputsV1) -> tuple[ReadinessEvaluatorRequestV1, ...]:
    result: list[ReadinessEvaluatorRequestV1] = []
    contests = tuple(
        item.contested_requirement.contested_requirement_id
        for item in inputs.gradeable_baseline.contested_requirements
    )
    for lane in (1, 2):
        result.extend(
            build_baseline_locked_grade_request_v1(inputs, batch)
            for batch in build_baseline_locked_grade_batches_v1(
                inputs.gradeable_baseline, lane=lane
            )
        )
        result.extend(
            build_baseline_locked_contested_grade_request_v1(
                inputs, lane=lane, contested_requirement_id=contest_id
            )
            for contest_id in contests
        )
    if not result:
        raise EvaluationIntegrityError("READINESS_EMPTY_GRADE_INVENTORY")
    return tuple(result)


def _physical_root(path: Path) -> Path:
    absolute = Path(os.path.abspath(path))
    try:
        physical = absolute.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ValueError("READINESS_INPUT_PATH_INVALID") from error
    if absolute != physical:
        raise ValueError("READINESS_INPUT_PATH_INVALID")
    return physical


def _validate_output_separation(output_dir: Path, roots: tuple[Path, ...]) -> None:
    absolute = Path(os.path.abspath(output_dir))
    try:
        parent = absolute.parent.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ValueError("READINESS_OUTPUT_PATH_INVALID") from error
    if absolute.parent != parent:
        raise ValueError("READINESS_OUTPUT_PATH_INVALID")
    candidate = parent / absolute.name
    for root in roots:
        physical = _physical_root(root)
        if candidate == physical or physical in candidate.parents:
            raise ValueError("READINESS_OUTPUT_OVERLAPS_INPUT")


def initialize_readiness_v1(
    output_dir: Path,
    *,
    baseline_run_dir: Path,
    qualification_run_dir: Path,
    generation_run_dir: Path,
    validation_receipt_path: Path,
    historical_v22_run_dir: Path | None = None,
    historical_anonymous_label: Literal["A", "B"] | None = None,
) -> ReadinessRunStateV1:
    inputs = build_verified_readiness_input_v1(
        baseline_run_dir=baseline_run_dir,
        qualification_run_dir=qualification_run_dir,
        generation_run_dir=generation_run_dir,
        validation_receipt_path=validation_receipt_path,
        historical_v22_run_dir=historical_v22_run_dir,
        historical_anonymous_label=historical_anonymous_label,
    )
    source_roots: tuple[Path, ...] = (
        baseline_run_dir,
        qualification_run_dir,
        generation_run_dir,
    )
    if historical_v22_run_dir is not None:
        source_roots = (*source_roots, historical_v22_run_dir)
    _validate_output_separation(output_dir, source_roots)
    initialize_readiness_run_storage_v1(output_dir, inputs, _grade_requests(inputs)[0])
    return resume_readiness_v1(output_dir)


def next_readiness_request_v1(run_dir: Path) -> ReadinessEvaluatorRequestV1 | None:
    return load_verified_readiness_context_v1(run_dir).pending_request


def resume_readiness_v1(run_dir: Path) -> ReadinessRunStateV1:
    return _state(load_verified_readiness_context_v1(run_dir))


def preflight_readiness_response_v1(
    run_dir: Path, response: object
) -> ReadinessResponsePreflightV1:
    return artifact_preflight_readiness_response_v1(run_dir, response)


def _responses_with(
    context: VerifiedReadinessContextV1, response: ReadinessEvaluatorResponseV1
) -> tuple[ReadinessEvaluatorResponseV1, ...]:
    return (
        *(context.responses[call.call_id] for call in context.manifest.accepted_calls),
        response,
    )


def _grade_products(
    inputs: VerifiedReadinessInputsV1,
    responses: tuple[ReadinessEvaluatorResponseV1, ...],
) -> tuple[
    tuple[BaselineLockedGraderAggregateV1, BaselineLockedGraderAggregateV1],
    BaselineLockedStrictEquivalentV1,
    tuple[SafetyGapCandidateV1, ...],
]:
    ordinary: dict[int, list[BaselineLockedGradeFragmentV1]] = {1: [], 2: []}
    contested: dict[int, list[BaselineLockedContestedGradeV1]] = {1: [], 2: []}
    for response in responses:
        if response.operation is ReadinessOperationV1.BASELINE_LOCKED_GRADE:
            fragment = BaselineLockedGradeFragmentV1.model_validate(response.payload)
            ordinary[fragment.lane].append(fragment)
        elif response.operation is ReadinessOperationV1.BASELINE_LOCKED_CONTESTED_GRADE:
            grade = BaselineLockedContestedGradeV1.model_validate(response.payload)
            contested[grade.lane].append(grade)
    lanes = (
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
    strict = derive_baseline_locked_strict_equivalent_v1(
        inputs.gradeable_baseline, lanes[0], lanes[1], inputs.readiness_rubric
    )
    return lanes, strict, build_gap_candidate_inventory_v1(inputs, lanes)


def _terminal_products(
    inputs: VerifiedReadinessInputsV1,
    lanes: tuple[BaselineLockedGraderAggregateV1, BaselineLockedGraderAggregateV1],
    strict: BaselineLockedStrictEquivalentV1,
    candidates: tuple[SafetyGapCandidateV1, ...],
    safety_lanes: tuple[SafetyLaneResponseV1, SafetyLaneResponseV1],
    decisions: tuple[SafetyRefereeDecisionV1, ...],
) -> tuple[dict[str, bytes], dict[str, object]]:
    safety = reconcile_safety_lanes_v1(inputs, candidates, *safety_lanes, decisions)
    requirement = compile_requirement_matrix_v1(inputs, lanes)
    gap = compile_gap_follow_up_matrix_v1(inputs, strict, candidates, safety)
    result = derive_delivery_readiness_v1(inputs, strict, requirement, gap, safety, *safety_lanes)
    return (
        {
            SAFETY_REVIEW_PATH: canonical_json_bytes(safety.model_dump(mode="json")),
            REQUIREMENT_MATRIX_PATH: canonical_json_bytes(requirement.model_dump(mode="json")),
            GAP_MATRIX_PATH: canonical_json_bytes(gap.model_dump(mode="json")),
            READINESS_RESULT_PATH: canonical_json_bytes(result.model_dump(mode="json")),
            ATTORNEY_HANDOFF_PATH: render_attorney_review_handoff_v1(
                report_text=inputs.report_text,
                requirement_matrix=requirement,
                gap_matrix=gap,
                result=result,
            ),
        },
        {
            "phase": ReadinessPhaseV1.COMPLETED,
            "terminal_status": "COMPLETED",
            "pending_call": None,
            "safety_review_fingerprint": safety.safety_review_fingerprint,
            "requirement_matrix_fingerprint": requirement.matrix_fingerprint,
            "gap_matrix_fingerprint": gap.matrix_fingerprint,
            "result_fingerprint": result.result_fingerprint,
        },
    )


def _advance_response_v1(
    run_dir: Path,
    context: VerifiedReadinessContextV1,
    response: ReadinessEvaluatorResponseV1,
    *,
    attempt: Literal[1, 2],
) -> ReadinessRunStateV1:
    pending = context.manifest.pending_call
    if pending is None or context.pending_request is None:
        raise ValueError(READINESS_EXTERNAL_RESPONSE_INVALID)
    response_bytes = _response_bytes(response)
    accepted = pending.model_copy(
        update={
            "state": "accepted",
            "attempt": attempt,
            "response_artifact_path": f"responses/{pending.call_id}.json",
            "response_fingerprint": sha256_digest(response_bytes),
            "provider_name": response.provider_name,
            "model_name": response.model_name,
            "judge_isolation": response.judge_isolation,
        }
    )
    assert accepted.response_artifact_path is not None
    files = {accepted.response_artifact_path: response_bytes}
    accepted_calls = (*context.manifest.accepted_calls, accepted)
    updates: dict[str, object] = {"accepted_calls": accepted_calls}
    grade_requests = _grade_requests(context.inputs)
    next_request: ReadinessEvaluatorRequestV1 | None = None

    if len(accepted_calls) < len(grade_requests):
        next_request = grade_requests[len(accepted_calls)]
        updates["phase"] = ReadinessPhaseV1.BASELINE_LOCKED_GRADE
    elif len(accepted_calls) == len(grade_requests):
        lanes, strict, candidates = _grade_products(
            context.inputs, _responses_with(context, response)
        )
        files.update(
            {
                GRADER_LANE_1_PATH: canonical_json_bytes(lanes[0].model_dump(mode="json")),
                GRADER_LANE_2_PATH: canonical_json_bytes(lanes[1].model_dump(mode="json")),
                STRICT_EQUIVALENT_PATH: canonical_json_bytes(strict.model_dump(mode="json")),
            }
        )
        if context.inputs.historical_v22 is not None:
            files[HISTORICAL_CROSS_CHECK_PATH] = canonical_json_bytes(
                context.inputs.historical_v22.model_dump(mode="json")
            )
        updates["baseline_locked_strict_equivalent_fingerprint"] = (
            strict.strict_equivalent_fingerprint
        )
        next_request = build_safety_lane_request_v1(context.inputs, lanes, candidates, lane=1)
        updates["phase"] = ReadinessPhaseV1.SAFETY_REVIEW
    else:
        if (
            context.grader_lanes is None
            or context.strict_equivalent is None
            or context.candidates is None
        ):
            raise EvaluationIntegrityError("READINESS_DERIVED_GRADE_REQUIRED")
        safety = list(context.safety_lanes)
        decisions = [
            SafetyRefereeDecisionV1.model_validate(context.responses[call.call_id].payload)
            for call in context.manifest.accepted_calls
            if call.operation is ReadinessOperationV1.SAFETY_REFEREE
        ]
        if response.operation is ReadinessOperationV1.SAFETY_REVIEW:
            safety.append(SafetyLaneResponseV1.model_validate(response.payload))
        elif response.operation is ReadinessOperationV1.SAFETY_REFEREE:
            decisions.append(SafetyRefereeDecisionV1.model_validate(response.payload))
        if len(safety) == 1:
            next_request = build_safety_lane_request_v1(
                context.inputs, context.grader_lanes, context.candidates, lane=2
            )
            updates["phase"] = ReadinessPhaseV1.SAFETY_REVIEW
        elif len(safety) == 2:
            pair = cast(tuple[SafetyLaneResponseV1, SafetyLaneResponseV1], tuple(safety))
            disputes = build_safety_disputes_v1(context.inputs, *pair)
            if len(decisions) < len(disputes):
                next_request = build_safety_referee_request_v1(
                    context.inputs, disputes[len(decisions)]
                )
                updates["phase"] = ReadinessPhaseV1.SAFETY_REFEREE
            else:
                terminal_files, terminal_updates = _terminal_products(
                    context.inputs,
                    context.grader_lanes,
                    context.strict_equivalent,
                    context.candidates,
                    pair,
                    tuple(decisions),
                )
                files.update(terminal_files)
                updates.update(terminal_updates)
        else:
            raise EvaluationIntegrityError("READINESS_SAFETY_LANE_INVENTORY")

    if next_request is not None:
        next_call = _pending_call(next_request)
        files[next_call.request_artifact_path] = _request_bytes(next_request)
        updates["pending_call"] = next_call
    successor = context.manifest.model_copy(update=updates)
    commit_readiness_transition_v1(
        run_dir,
        expected_manifest_fingerprint=context.manifest.manifest_fingerprint,
        files=files,
        successor=successor,
        expected_root_identity=context.root_identity,
    )
    return resume_readiness_v1(run_dir)


def _guarded_submit(
    run_dir: Path, response: object, *, attempt: Literal[1, 2]
) -> GuardedReadinessSubmissionResultV1:
    with _submission_guard(run_dir):
        context = load_verified_readiness_context_v1(run_dir)
        preflight = artifact_preflight_readiness_response_v1(run_dir, response)
        if not preflight.valid:
            return GuardedReadinessSubmissionResultV1(False, preflight)
        try:
            raw = (
                response.model_dump(mode="json", warnings="error")
                if isinstance(response, ReadinessEvaluatorResponseV1)
                else response
            )
            checked = validate_readiness_evaluator_response_v1(raw)
            state = _advance_response_v1(run_dir, context, checked, attempt=attempt)
        except EvaluationIntegrityError:
            raise
        except (RecursionError, TypeError, ValidationError, ValueError):
            return GuardedReadinessSubmissionResultV1(
                False,
                ReadinessResponsePreflightV1(
                    valid=False, diagnostics=(READINESS_EXTERNAL_RESPONSE_INVALID,)
                ),
            )
        return GuardedReadinessSubmissionResultV1(True, preflight, state)


def guarded_submit_readiness_response_v1(
    run_dir: Path, response: object
) -> GuardedReadinessSubmissionResultV1:
    return _guarded_submit(run_dir, response, attempt=1)


def submit_readiness_response_v1(run_dir: Path, response: object) -> ReadinessRunStateV1:
    result = guarded_submit_readiness_response_v1(run_dir, response)
    if not result.accepted or result.state is None:
        raise ValueError(READINESS_EXTERNAL_RESPONSE_INVALID)
    return result.state


def readiness_exit_code_v1(result: DeliveryReadinessResultV1 | None, *, paused: bool) -> int:
    if paused:
        return 6
    if result is None:
        return 3
    if result.delivery_readiness is DeliveryReadinessTierV1.NOT_DELIVERABLE:
        return 4
    return 0


def _fragment_class(
    request: ReadinessEvaluatorRequestV1,
) -> Literal["ordinary_batch", "contested_requirement", "safety_lane", "safety_dispute"]:
    if request.operation is ReadinessOperationV1.BASELINE_LOCKED_GRADE:
        return "ordinary_batch"
    if request.operation is ReadinessOperationV1.BASELINE_LOCKED_CONTESTED_GRADE:
        return "contested_requirement"
    if request.operation is ReadinessOperationV1.SAFETY_REVIEW:
        return "safety_lane"
    return "safety_dispute"


def _emit(sink: ReadinessTelemetrySinkV1, event: ReadinessTelemetryEventV1) -> None:
    with contextlib.suppress(Exception):
        sink.emit(event)


def _event(
    context: VerifiedReadinessContextV1,
    request: ReadinessEvaluatorRequestV1,
    *,
    attempt: Literal[1, 2],
    normalization_codes: tuple[str, ...] = (),
    clarification_codes: tuple[str, ...] = (),
    paused: bool = False,
) -> ReadinessTelemetryEventV1:
    lane = request.payload.get("lane")
    return ReadinessTelemetryEventV1(
        protocol_version="delivery-readiness-v1",
        compiler_contract_fingerprint=readiness_compiler_contract_fingerprint_v1(),
        scoring_contract_fingerprint=(
            context.inputs.readiness_input.strict_equivalent_scoring_contract_fingerprint
        ),
        operation=request.operation.value,
        fragment_class=_fragment_class(request),
        lane=lane if lane in (1, 2) else None,
        attempt_number=attempt,
        normalization_codes=normalization_codes,
        clarification_codes=clarification_codes,
        pause_count=1 if paused else 0,
        resume_count=1,
    )


def _provenance(
    evaluator: ReadinessDraftEvaluatorV1,
    prompt: ReadinessEvaluatorDraftPromptV1,
    seen_tokens: set[str],
) -> ReadinessEvaluatorProvenanceV1:
    factory = getattr(evaluator, "provenance", None)
    supplied = factory(prompt) if callable(factory) else None
    if supplied is None:
        supplied = ReadinessEvaluatorProvenanceV1(
            provider_name="internal-evaluator",
            model_name=type(evaluator).__qualname__,
            judge_isolation="scripted_fixture",
        )
    if type(supplied) is not ReadinessEvaluatorProvenanceV1:
        raise ValueError(READINESS_CONTEXT_ISOLATION_INVALID)
    checked = supplied
    token_factory = getattr(evaluator, "context_token", None)
    if checked.judge_isolation == "fresh_context" and not callable(token_factory):
        raise ValueError(READINESS_CONTEXT_ISOLATION_INVALID)
    if callable(token_factory):
        token = token_factory(prompt)
        if (
            type(token) is not str
            or not token
            or token != token.strip()
            or len(token.encode("utf-8")) > 256
            or token in seen_tokens
        ):
            raise ValueError(READINESS_CONTEXT_ISOLATION_INVALID)
        seen_tokens.add(token)
    return checked


def _pause(
    run_dir: Path, request: ReadinessEvaluatorRequestV1, *codes: str
) -> ReadinessDriverOutcomeV1:
    context = load_verified_readiness_context_v1(run_dir)
    return ReadinessDriverOutcomeV1(
        state=_state(context),
        result=None,
        engine_paused=True,
        pause_reason_codes=codes,
        pending_request=request,
        exit_code=6,
    )


def _completed(context: VerifiedReadinessContextV1) -> ReadinessDriverOutcomeV1:
    if context.result is None or context.manifest.terminal_status is None:
        raise EvaluationIntegrityError("READINESS_RESULT_REQUIRED")
    return ReadinessDriverOutcomeV1(
        state=_state(context),
        result=context.result,
        engine_paused=False,
        exit_code=readiness_exit_code_v1(context.result, paused=False),
    )


async def continue_readiness_v1(
    run_dir: Path,
    evaluator: ReadinessDraftEvaluatorV1,
    *,
    telemetry_sink: ReadinessTelemetrySinkV1 | None = None,
) -> ReadinessDriverOutcomeV1:
    if not isinstance(evaluator, ReadinessDraftEvaluatorV1):
        raise TypeError("evaluator must implement ReadinessDraftEvaluatorV1")
    sink = _NOOP_TELEMETRY if telemetry_sink is None else telemetry_sink
    seen_tokens: set[str] = set()
    while True:
        context = load_verified_readiness_context_v1(run_dir)
        if context.manifest.terminal_status is not None:
            return _completed(context)
        request = context.pending_request
        if request is None:
            raise EvaluationIntegrityError("READINESS_PENDING_REQUEST_REQUIRED")
        clarification_codes: tuple[ReadinessDraftReasonCodeV1, ...] = ()
        for attempt in cast(tuple[Literal[1, 2], ...], (1, 2)):
            prompt = ReadinessEvaluatorDraftPromptV1(
                request=request,
                attempt=attempt,
                clarification_codes=clarification_codes,
            )
            try:
                provenance = _provenance(evaluator, prompt, seen_tokens)
            except (TypeError, ValueError):
                _emit(
                    sink,
                    _event(
                        context,
                        request,
                        attempt=attempt,
                        clarification_codes=(READINESS_CONTEXT_ISOLATION_INVALID,),
                        paused=True,
                    ),
                )
                return _pause(run_dir, request, READINESS_CONTEXT_ISOLATION_INVALID)
            try:
                draft = await evaluator.evaluate_draft(prompt)
            except Exception:
                _emit(
                    sink,
                    _event(
                        context,
                        request,
                        attempt=attempt,
                        clarification_codes=(READINESS_PROVIDER_FAILURE,),
                        paused=True,
                    ),
                )
                return _pause(run_dir, request, READINESS_PROVIDER_FAILURE)
            compiled = compile_readiness_draft_v1(request, draft, provenance)
            if isinstance(compiled, NeedsReadinessClarificationV1):
                clarification_codes = compiled.reason_codes
                values = tuple(item.value for item in clarification_codes)
                _emit(
                    sink,
                    _event(
                        context,
                        request,
                        attempt=attempt,
                        clarification_codes=values,
                        paused=attempt == 2,
                    ),
                )
                if attempt == 1:
                    continue
                return _pause(run_dir, request, *values)
            if isinstance(compiled, ReadinessEngineDefectV1):
                return _pause(run_dir, request, compiled.reason_code)
            if not isinstance(compiled, CompiledReadinessDraftV1):
                return _pause(run_dir, request, "READINESS_COMPILER_INVARIANT")
            submitted = _guarded_submit(run_dir, compiled.response, attempt=attempt)
            if not submitted.accepted or submitted.state is None:
                current = next_readiness_request_v1(run_dir)
                if current is None or current.request_fingerprint != request.request_fingerprint:
                    updated = load_verified_readiness_context_v1(run_dir)
                    if updated.result is not None:
                        return _completed(updated)
                    return ReadinessDriverOutcomeV1(
                        state=_state(updated),
                        result=updated.result,
                        engine_paused=False,
                        pending_request=current,
                    )
                return _pause(run_dir, request, READINESS_COMPILER_PREFLIGHT_DISAGREEMENT)
            _emit(
                sink,
                _event(
                    context,
                    request,
                    attempt=attempt,
                    normalization_codes=compiled.normalization_codes,
                    clarification_codes=tuple(item.value for item in clarification_codes),
                ),
            )
            break
        else:
            raise AssertionError("unreachable readiness attempt state")


__all__ = [
    "READINESS_CONTEXT_ISOLATION_INVALID",
    "GuardedReadinessSubmissionResultV1",
    "ReadinessDraftEvaluatorV1",
    "ReadinessDriverOutcomeV1",
    "ReadinessTelemetryEventV1",
    "ReadinessTelemetrySinkV1",
    "continue_readiness_v1",
    "guarded_submit_readiness_response_v1",
    "initialize_readiness_v1",
    "next_readiness_request_v1",
    "preflight_readiness_response_v1",
    "readiness_exit_code_v1",
    "resume_readiness_v1",
    "submit_readiness_response_v1",
]
