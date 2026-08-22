"""Bounded full-runtime controller for simplified evaluator protocol 2.0."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol, TypeVar, runtime_checkable

from pydantic import BaseModel

from regulatory_harvest.storage import canonical_json_bytes, sha256_digest

from .attorney_admission import freeze_case
from .attorney_artifacts import (
    EvaluationIntegrityError,
    open_evaluation_storage,
    read_evaluation_artifact,
)
from .attorney_models import AttorneyEvaluationCase, CaseEnvelope
from .attorney_v2_artifacts import (
    V2ResponsePreflight,
    commit_v2_transition,
    initialize_v2_run_storage,
    load_verified_v2_run,
    preflight_v2_response,
)
from .attorney_v2_compiler import compile_baseline, index_review, material_disputes
from .attorney_v2_models import (
    CanonicalBaselineV2,
    CompletedEvaluationV2,
    EvaluationCallRecordV2,
    EvaluationManifestV2,
    EvaluationPhaseV2,
    EvaluationResultV2,
    EvaluationRunStateV2,
    EvaluationTerminalStatusV2,
    EvaluatorOperationV2,
    EvaluatorRequestV2,
    EvaluatorResponseV2,
    GradeResponseV2,
    ReportResultV2,
    SourceAuditV2,
    SourceRefereeResponseV2,
    SourceReviewV2,
    evaluator_request_fingerprint,
    validate_evaluator_response_v2,
)
from .attorney_v2_requests import (
    build_grade_request,
    build_source_audit_request,
    build_source_referee_request,
    build_source_review_request,
    mechanical_retry_request,
)
from .attorney_v2_rubric import RUBRIC_V2, reconcile_grades, score_report, validate_grade_response
from .attorney_workflow import _verify_generation_capsules_for_initialization

_CASE_PATH = "inputs/case.json"
_BUILD_PATH = "inputs/build.json"
_RUBRIC_PATH = "rubric.json"
_BASELINE_PATH = "baseline.json"
_RESULT_PATH = "result.json"
_Model = TypeVar("_Model", bound=BaseModel)


@runtime_checkable
class AttorneyEvaluatorV2(Protocol):
    """A role provider which supplies one independently created response per request."""

    async def evaluate(self, request: EvaluatorRequestV2) -> EvaluatorResponseV2: ...


@dataclass(frozen=True)
class GuardedSubmissionResultV2:
    """The public-safe result of a write-free preflight and optional transition."""

    accepted: bool
    preflight: V2ResponsePreflight
    state: EvaluationRunStateV2 | None = None


def _model_bytes(value: object) -> bytes:
    if not hasattr(value, "model_dump"):
        raise TypeError("workflow artifacts must be Pydantic models")
    return canonical_json_bytes(value.model_dump(mode="json", warnings="error"))


def _state(manifest: EvaluationManifestV2) -> EvaluationRunStateV2:
    pending = [call for call in manifest.calls if call.state == "pending"]
    return EvaluationRunStateV2(
        case_fingerprint=manifest.case_fingerprint,
        phase=manifest.phase,
        current_call_id=pending[0].call_id if pending else None,
        terminal_status=manifest.terminal_status,
        manifest_fingerprint=manifest.manifest_fingerprint,
    )


def _request_path(call_id: str) -> str:
    return f"requests/{call_id}.json"


def _response_path(call_id: str) -> str:
    return f"responses/{call_id}.json"


def _pending_call(
    call_id: str,
    request: EvaluatorRequestV2,
    label: Literal["A", "B"] | None = None,
) -> EvaluationCallRecordV2:
    return EvaluationCallRecordV2(
        call_id=call_id,
        operation=request.operation,
        anonymous_label=label,
        state="pending",
        request_artifact_path=_request_path(call_id),
        request_fingerprint=request.request_fingerprint,
    )


def _accepted_call(
    call: EvaluationCallRecordV2, response: EvaluatorResponseV2
) -> EvaluationCallRecordV2:
    data = call.model_dump(mode="json")
    data.update(
        {
            "state": "accepted",
            "response_artifact_path": _response_path(call.call_id),
            "response_fingerprint": sha256_digest(_model_bytes(response)),
            "provider_name": response.provider_name,
            "model_name": response.model_name,
            "judge_isolation": response.judge_isolation,
        }
    )
    return EvaluationCallRecordV2.model_validate(data)


def _manifest(
    prior: EvaluationManifestV2,
    *,
    calls: list[EvaluationCallRecordV2],
    phase: EvaluationPhaseV2,
    baseline_fingerprint: str | None = None,
    result_hash: str | None = None,
    terminal_status: EvaluationTerminalStatusV2 | None = None,
) -> EvaluationManifestV2:
    data = prior.model_dump(mode="json")
    data.update(
        {
            "calls": calls,
            "phase": phase,
            "baseline_fingerprint": baseline_fingerprint,
            "result_hash": result_hash,
            "terminal_status": terminal_status,
            "artifacts": [],
            "manifest_fingerprint": "0" * 64,
        }
    )
    return EvaluationManifestV2.model_validate(data)


def _read_model(run_dir: Path, path: str, model_type: type[_Model]) -> _Model:
    data = read_evaluation_artifact(run_dir, path)
    payload = json.loads(data.decode("utf-8"))
    validator = model_type.model_validate
    return validator(payload)


def _envelope(run_dir: Path) -> CaseEnvelope:
    return _read_model(run_dir, _CASE_PATH, CaseEnvelope)


def _pending(manifest: EvaluationManifestV2) -> EvaluationCallRecordV2:
    pending = [call for call in manifest.calls if call.state == "pending"]
    if len(pending) != 1:
        raise EvaluationIntegrityError("EVALUATOR_V2_PENDING_CALL")
    return pending[0]


def _accepted_response(
    run_dir: Path, manifest: EvaluationManifestV2, operation: EvaluatorOperationV2
) -> EvaluatorResponseV2:
    calls = [
        call
        for call in manifest.calls
        if call.operation is operation and call.state == "accepted"
    ]
    if len(calls) != 1 or calls[0].response_artifact_path is None:
        raise EvaluationIntegrityError("EVALUATOR_V2_ACCEPTED_RESPONSE")
    return _read_model(run_dir, calls[0].response_artifact_path, EvaluatorResponseV2)


def _review(run_dir: Path, manifest: EvaluationManifestV2) -> SourceReviewV2:
    response = _accepted_response(run_dir, manifest, EvaluatorOperationV2.SOURCE_REVIEW)
    return SourceReviewV2.model_validate(response.payload)


def _audit(
    run_dir: Path, manifest: EvaluationManifestV2, review: SourceReviewV2
) -> SourceAuditV2:
    response = _accepted_response(run_dir, manifest, EvaluatorOperationV2.SOURCE_AUDIT)
    return SourceAuditV2.validate_for_indexed_proposals(response.payload, index_review(review))


def _baseline(run_dir: Path) -> CanonicalBaselineV2:
    return _read_model(run_dir, _BASELINE_PATH, CanonicalBaselineV2)


def _report_text(envelope: CaseEnvelope, label: Literal["A", "B"]) -> str:
    candidate_id = next(
        (
            assignment.candidate_id
            for assignment in envelope.assignments
            if assignment.anonymous_label == label
        ),
        None,
    )
    candidate = next(
        (item for item in envelope.case.candidates if item.candidate_id == candidate_id), None
    )
    if candidate is None:
        raise EvaluationIntegrityError("EVALUATOR_V2_REPORT_LABEL")
    return candidate.report_text


def _semantic_response(
    run_dir: Path,
    manifest: EvaluationManifestV2,
    response: object,
) -> EvaluatorResponseV2:
    validated = validate_evaluator_response_v2(response)
    pending = _pending(manifest)
    if (
        validated.operation is not pending.operation
        or validated.request_fingerprint != pending.request_fingerprint
    ):
        raise ValueError("mechanical response is not bound to the pending request")
    if pending.operation is EvaluatorOperationV2.SOURCE_REVIEW:
        SourceReviewV2.model_validate(validated.payload)
    elif pending.operation is EvaluatorOperationV2.SOURCE_AUDIT:
        review = _review(run_dir, manifest)
        SourceAuditV2.validate_for_indexed_proposals(validated.payload, index_review(review))
    elif pending.operation is EvaluatorOperationV2.SOURCE_REFEREE:
        review = _review(run_dir, manifest)
        audit = _audit(run_dir, manifest, review)
        SourceRefereeResponseV2.validate_for_disputes(
            validated.payload, material_disputes(review, audit)
        )
    else:
        if pending.anonymous_label is None:
            raise ValueError("grade request lacks an anonymous label")
        baseline = _baseline(run_dir)
        grade = GradeResponseV2.validate_for_baseline(validated.payload, baseline)
        if grade.anonymous_label != pending.anonymous_label:
            raise ValueError("grade response label does not match the pending request")
        validate_grade_response(
            baseline, grade, _report_text(_envelope(run_dir), pending.anonymous_label)
        )
    return validated


def _preflight(run_dir: Path, response: object) -> V2ResponsePreflight:
    try:
        manifest, _ = load_verified_v2_run(run_dir)
        pending = _pending(manifest)
        generic = preflight_v2_response(run_dir, pending.call_id, response)
        if not generic.valid:
            return generic
        _semantic_response(run_dir, manifest, response)
    except (EvaluationIntegrityError, TypeError, ValueError, KeyError, json.JSONDecodeError):
        return V2ResponsePreflight(False, ("MECHANICAL_RESPONSE_INVALID",))
    return V2ResponsePreflight(True)


def _result(baseline: CanonicalBaselineV2, reports: list[ReportResultV2]) -> EvaluationResultV2:
    comparison = None
    if len(reports) == 2:
        from .attorney_v2_rubric import compare_report_results

        comparison = compare_report_results(reports[0], reports[1])
    provisional = EvaluationResultV2(
        rubric=RUBRIC_V2,
        baseline=baseline,
        reports=reports,
        comparison=comparison,
        result_fingerprint="0" * 64,
    )
    fingerprint = sha256_digest(
        canonical_json_bytes(provisional.model_dump(mode="json", exclude={"result_fingerprint"}))
    )
    return EvaluationResultV2.model_validate(
        {**provisional.model_dump(mode="json"), "result_fingerprint": fingerprint},
        context={
            "requirement_ids": {item.requirement_id for item in baseline.requirements},
            "baseline_fingerprint": baseline.baseline_fingerprint,
        },
    )


def _grade_response_for(
    run_dir: Path,
    manifest: EvaluationManifestV2,
    label: Literal["A", "B"],
    incoming: EvaluatorResponseV2 | None = None,
) -> list[GradeResponseV2]:
    responses: list[GradeResponseV2] = []
    baseline = _baseline(run_dir)
    report_text = _report_text(_envelope(run_dir), label)
    for call in manifest.calls:
        if call.operation is not EvaluatorOperationV2.GRADE_REPORT or call.anonymous_label != label:
            continue
        if call.state == "accepted":
            if call.response_artifact_path is None:
                raise EvaluationIntegrityError("EVALUATOR_V2_GRADE_RESPONSE")
            response = _read_model(run_dir, call.response_artifact_path, EvaluatorResponseV2)
        elif incoming is not None and call.call_id == _pending(manifest).call_id:
            response = incoming
        else:
            continue
        responses.append(
            validate_grade_response(
                baseline,
                GradeResponseV2.validate_for_baseline(response.payload, baseline),
                report_text,
            )
        )
    return responses


def _advance(
    run_dir: Path, manifest: EvaluationManifestV2, response: EvaluatorResponseV2
) -> EvaluationRunStateV2:
    pending = _pending(manifest)
    accepted = _accepted_call(pending, response)
    calls = [*([call for call in manifest.calls if call.state == "accepted"]), accepted]
    files: dict[str, bytes] = {_response_path(pending.call_id): _model_bytes(response)}
    envelope = _envelope(run_dir)

    if pending.operation is EvaluatorOperationV2.SOURCE_REVIEW:
        review = SourceReviewV2.model_validate(response.payload)
        request = build_source_audit_request(envelope, index_review(review))
        next_call = _pending_call("source-audit", request)
        calls.append(next_call)
        files[next_call.request_artifact_path] = _model_bytes(request)
        successor = _manifest(manifest, calls=calls, phase=EvaluationPhaseV2.SOURCE_AUDIT)
    elif pending.operation is EvaluatorOperationV2.SOURCE_AUDIT:
        review = _review(run_dir, manifest)
        audit = SourceAuditV2.validate_for_indexed_proposals(response.payload, index_review(review))
        disputes = material_disputes(review, audit)
        if disputes:
            request = build_source_referee_request(envelope, disputes)
            next_call = _pending_call("source-referee", request)
            calls.append(next_call)
            files[next_call.request_artifact_path] = _model_bytes(request)
            successor = _manifest(manifest, calls=calls, phase=EvaluationPhaseV2.SOURCE_REFEREE)
        else:
            baseline = compile_baseline(envelope, review, audit, None)
            request = build_grade_request(envelope, baseline, "A", RUBRIC_V2)
            next_call = _pending_call("grade-A-1", request, "A")
            calls.append(next_call)
            files.update(
                {
                    _BASELINE_PATH: _model_bytes(baseline),
                    next_call.request_artifact_path: _model_bytes(request),
                }
            )
            successor = _manifest(
                manifest,
                calls=calls,
                phase=EvaluationPhaseV2.GRADE_REPORT,
                baseline_fingerprint=baseline.baseline_fingerprint,
            )
    elif pending.operation is EvaluatorOperationV2.SOURCE_REFEREE:
        review = _review(run_dir, manifest)
        audit = _audit(run_dir, manifest, review)
        referee = SourceRefereeResponseV2.validate_for_disputes(
            response.payload, material_disputes(review, audit)
        )
        baseline = compile_baseline(envelope, review, audit, referee)
        request = build_grade_request(envelope, baseline, "A", RUBRIC_V2)
        next_call = _pending_call("grade-A-1", request, "A")
        calls.append(next_call)
        files.update(
            {
                _BASELINE_PATH: _model_bytes(baseline),
                next_call.request_artifact_path: _model_bytes(request),
            }
        )
        successor = _manifest(
            manifest,
            calls=calls,
            phase=EvaluationPhaseV2.GRADE_REPORT,
            baseline_fingerprint=baseline.baseline_fingerprint,
        )
    else:
        assert pending.anonymous_label is not None
        label = pending.anonymous_label
        grades = _grade_response_for(run_dir, manifest, label, response)
        if len(grades) == 1:
            request = build_grade_request(envelope, _baseline(run_dir), label, RUBRIC_V2)
            next_call = _pending_call(f"grade-{label}-2", request, label)
            calls.append(next_call)
            files[next_call.request_artifact_path] = _model_bytes(request)
            successor = _manifest(
                manifest,
                calls=calls,
                phase=EvaluationPhaseV2.GRADE_REPORT,
                baseline_fingerprint=_baseline(run_dir).baseline_fingerprint,
            )
        else:
            report_result = score_report(
                _baseline(run_dir),
                reconcile_grades(
                    _baseline(run_dir), grades[0], grades[1], _report_text(envelope, label)
                ),
            )
            files[f"report-results/{label}.json"] = _model_bytes(report_result)
            labels = [assignment.anonymous_label for assignment in envelope.assignments]
            if label == "A" and labels == ["A", "B"]:
                request = build_grade_request(envelope, _baseline(run_dir), "B", RUBRIC_V2)
                next_call = _pending_call("grade-B-1", request, "B")
                calls.append(next_call)
                files[next_call.request_artifact_path] = _model_bytes(request)
                successor = _manifest(
                    manifest,
                    calls=calls,
                    phase=EvaluationPhaseV2.GRADE_REPORT,
                    baseline_fingerprint=_baseline(run_dir).baseline_fingerprint,
                )
            else:
                reports = [report_result]
                if label == "B":
                    report_payload = json.loads(
                        read_evaluation_artifact(run_dir, "report-results/A.json").decode("utf-8")
                    )
                    reports.insert(
                        0,
                        ReportResultV2.model_validate(
                            report_payload,
                            context={
                                "requirement_ids": {
                                    item.requirement_id for item in _baseline(run_dir).requirements
                                },
                                "baseline_fingerprint": _baseline(run_dir).baseline_fingerprint,
                            },
                        ),
                    )
                result = _result(_baseline(run_dir), reports)
                files[_RESULT_PATH] = _model_bytes(result)
                successor = _manifest(
                    manifest,
                    calls=calls,
                    phase=EvaluationPhaseV2.COMPLETED,
                    baseline_fingerprint=_baseline(run_dir).baseline_fingerprint,
                    result_hash=result.result_fingerprint,
                    terminal_status=EvaluationTerminalStatusV2.COMPLETED,
                )

    with open_evaluation_storage(run_dir) as storage:
        committed = commit_v2_transition(storage, successor, files)
    return _state(committed)


def initialize_evaluation_v2(
    case: AttorneyEvaluationCase,
    output_dir: Path,
    *,
    seed_hex: str,
    generation_capsule_paths: Mapping[str, Path] | None = None,
) -> EvaluationRunStateV2:
    """Freeze a schema-1.1 case and persist exactly one source-review request."""
    strict_case = AttorneyEvaluationCase.model_validate(case.model_dump(mode="json"))
    if strict_case.schema_version != "1.1":
        raise ValueError("case schema 1.1 is required for new evaluation runs")
    _verify_generation_capsules_for_initialization(strict_case, generation_capsule_paths)
    envelope = freeze_case(strict_case, seed_hex=seed_hex)
    request = build_source_review_request(envelope)
    call = _pending_call("source-review", request)
    case_bytes = _model_bytes(envelope)
    build_bytes = canonical_json_bytes(
        {"protocol_version": "2.0", "compiler_version": "semantic-compiler-v2"}
    )
    rubric_bytes = _model_bytes(RUBRIC_V2)
    manifest = EvaluationManifestV2(
        case_fingerprint=envelope.case_fingerprint,
        case_envelope_hash=sha256_digest(case_bytes),
        build_fingerprint=sha256_digest(build_bytes),
        rubric_fingerprint=sha256_digest(rubric_bytes),
        compiler_version="semantic-compiler-v2",
        phase=EvaluationPhaseV2.SOURCE_REVIEW,
        calls=[call],
        artifacts=[],
        manifest_fingerprint="0" * 64,
    )
    committed = initialize_v2_run_storage(
        output_dir,
        manifest,
        {
            _CASE_PATH: case_bytes,
            _BUILD_PATH: build_bytes,
            _RUBRIC_PATH: rubric_bytes,
            call.request_artifact_path: _model_bytes(request),
        },
    )
    return _state(committed)


def resume_evaluation_v2(run_dir: Path) -> EvaluationRunStateV2:
    """Return a state only after the complete v2 tree has been reverified."""
    manifest, _ = load_verified_v2_run(run_dir)
    return _state(manifest)


def next_evaluator_request_v2(run_dir: Path) -> EvaluatorRequestV2 | None:
    """Return the one verified pending evaluator packet, if the run is nonterminal."""
    manifest, _ = load_verified_v2_run(run_dir)
    if manifest.terminal_status is not None:
        return None
    call = _pending(manifest)
    request = _read_model(run_dir, call.request_artifact_path, EvaluatorRequestV2)
    if evaluator_request_fingerprint(request) != call.request_fingerprint:
        raise EvaluationIntegrityError("EVALUATOR_V2_REQUEST_BINDING")
    return request


def preflight_evaluator_response_v2(run_dir: Path, response: object) -> V2ResponsePreflight:
    """Mechanically validate an evaluator response without writing any bytes."""
    return _preflight(run_dir, response)


def guarded_submit_evaluator_response_v2(
    run_dir: Path, response: object
) -> GuardedSubmissionResultV2:
    """Commit one semantically valid response; rejected bytes and details are never stored."""
    preflight = _preflight(run_dir, response)
    if not preflight.valid:
        return GuardedSubmissionResultV2(False, preflight)
    manifest, _ = load_verified_v2_run(run_dir)
    try:
        validated = _semantic_response(run_dir, manifest, response)
        state = _advance(run_dir, manifest, validated)
    except (EvaluationIntegrityError, TypeError, ValueError, KeyError, json.JSONDecodeError):
        return GuardedSubmissionResultV2(
            False, V2ResponsePreflight(False, ("MECHANICAL_RESPONSE_INVALID",))
        )
    return GuardedSubmissionResultV2(True, V2ResponsePreflight(True), state)


def submit_evaluator_response_v2(run_dir: Path, response: object) -> EvaluationRunStateV2:
    """Submit one response or raise after the same write-free mechanical preflight."""
    result = guarded_submit_evaluator_response_v2(run_dir, response)
    if not result.accepted or result.state is None:
        raise ValueError("MECHANICAL_RESPONSE_INVALID")
    return result.state


def stop_evaluation_v2_inconclusive(
    run_dir: Path, reason: Literal["MECHANICAL_RESPONSE_INVALID"]
) -> EvaluationRunStateV2:
    """Persist the sole public-safe terminal reason after a second mechanical refusal."""
    if reason != "MECHANICAL_RESPONSE_INVALID":
        raise ValueError("unsupported inconclusive reason")
    manifest, _ = load_verified_v2_run(run_dir)
    accepted = [call for call in manifest.calls if call.state == "accepted"]
    successor = _manifest(
        manifest,
        calls=accepted,
        phase=EvaluationPhaseV2.INCONCLUSIVE,
        baseline_fingerprint=manifest.baseline_fingerprint,
        terminal_status=EvaluationTerminalStatusV2.INCONCLUSIVE,
    )
    with open_evaluation_storage(run_dir) as storage:
        committed = commit_v2_transition(
            storage,
            successor,
            {"terminal-reason.json": canonical_json_bytes({"reason": reason})},
        )
    return _state(committed)


async def run_evaluation_v2(
    case: AttorneyEvaluationCase,
    evaluator: AttorneyEvaluatorV2,
    output_dir: Path,
    *,
    seed_hex: str,
    generation_capsule_paths: Mapping[str, Path] | None = None,
) -> CompletedEvaluationV2:
    """Run one initial response plus one identical fresh-context repair per call."""
    if not isinstance(evaluator, AttorneyEvaluatorV2):
        raise TypeError("evaluator must implement AttorneyEvaluatorV2")
    state = initialize_evaluation_v2(
        case,
        output_dir,
        seed_hex=seed_hex,
        generation_capsule_paths=generation_capsule_paths,
    )
    repaired_call_ids: set[str] = set()
    while state.terminal_status is None:
        request = next_evaluator_request_v2(output_dir)
        if request is None or state.current_call_id is None:
            raise EvaluationIntegrityError("EVALUATOR_V2_PENDING_CALL")
        response = await evaluator.evaluate(request)
        guarded = guarded_submit_evaluator_response_v2(output_dir, response)
        if guarded.accepted:
            assert guarded.state is not None
            state = guarded.state
            continue
        if state.current_call_id in repaired_call_ids:
            state = stop_evaluation_v2_inconclusive(output_dir, "MECHANICAL_RESPONSE_INVALID")
            break
        current_call_id = state.current_call_id
        if current_call_id is None:  # guarded with the request above; preserves type narrowing
            raise EvaluationIntegrityError("EVALUATOR_V2_PENDING_CALL")
        repaired_call_ids.add(current_call_id)
        retry_request = mechanical_retry_request(
            request, expected_request_fingerprint=request.request_fingerprint
        )
        response = await evaluator.evaluate(retry_request)
        guarded = guarded_submit_evaluator_response_v2(output_dir, response)
        if guarded.accepted:
            assert guarded.state is not None
            state = guarded.state
        else:
            state = stop_evaluation_v2_inconclusive(output_dir, "MECHANICAL_RESPONSE_INVALID")
    manifest, result = load_verified_v2_run(output_dir)
    if result is None:
        raise EvaluationIntegrityError("EVALUATOR_V2_INCONCLUSIVE")
    return CompletedEvaluationV2(manifest=manifest, result=result, state=_state(manifest))
