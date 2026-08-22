"""Recoverable controller for evaluator Protocol 2.2."""

from __future__ import annotations

import contextlib
import json
import os
import stat
import threading
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol, cast, runtime_checkable

from pydantic import ValidationError

from regulatory_harvest.storage import canonical_json_bytes, sha256_digest

from .attorney_admission import freeze_case
from .attorney_artifacts import EvaluationIntegrityError, read_evaluation_artifact
from .attorney_models import AttorneyEvaluationCase
from .attorney_v2_models import (
    AbsoluteDispositionV2,
)
from .attorney_v22_artifacts import (
    V22_BASELINE_PATH,
    V22_BUILD_PATH,
    V22_CASE_PATH,
    V22_REFEREE_AGGREGATE_PATH,
    V22_RESULT_PATH,
    V22_RUBRIC_PATH,
    V22ResponsePreflight,
    VerifiedV22Context,
    commit_v22_transition,
    initialize_v22_run_storage,
    load_verified_v22_context,
)
from .attorney_v22_compiler import (
    RUBRIC_V22,
    _SourceFragmentSemanticResponseErrorV22,
    _validate_source_fragment_semantics_v22,
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
from .attorney_v22_drafts import (
    CompiledDraftV22,
    DraftReasonCodeV22,
    EngineDefectV22,
    EvaluatorDraftPromptV22,
    EvaluatorProvenanceV22,
    NeedsClarificationV22,
    compile_evaluator_draft_v22,
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
    EvaluationRunStateV22,
    EvaluationTerminalStatusV22,
    EvaluatorOperationV22,
    EvaluatorRequestV22,
    EvaluatorResponseV22,
    GraderAggregateV22,
    OrdinaryGradeBatchV22,
    OrdinaryGradeFragmentV22,
    ReconciledGradeV22,
    RefereeAggregateV22,
    RefereeDecisionV22,
    RefereeDisputeV22,
    ReportResultV22,
    SensitivityRecordV22,
    SourceAuditAggregateV22,
    SourceAuditFragmentV22,
    SourceReviewAggregateV22,
    SourceReviewFragmentV22,
    _EvaluatorResponseValidationErrorV22,
    build_comparison_result_v22,
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
from .attorney_workflow import _verify_generation_capsules_for_initialization


@runtime_checkable
class AttorneyDraftEvaluatorV22(Protocol):
    """An internal adapter that authors one bounded semantic draft per prompt."""

    async def evaluate_draft(self, prompt: EvaluatorDraftPromptV22) -> object: ...


@dataclass(frozen=True)
class EvaluationTelemetryEventV22:
    """Public-safe operational metadata emitted outside the authoritative run."""

    protocol_version: Literal["2.2"]
    compiler_contract_fingerprint: str
    operation: str
    fragment_identity: str
    attempt_number: Literal[1, 2]
    normalization_codes: tuple[str, ...] = ()
    clarification_codes: tuple[str, ...] = ()
    pause_count: int = 0
    resume_count: int = 0


@runtime_checkable
class EvaluationTelemetrySinkV22(Protocol):
    """A best-effort sink whose failure never affects evaluation state."""

    def emit(self, event: EvaluationTelemetryEventV22) -> None: ...


@dataclass(frozen=True)
class EvaluationDriverOutcomeV22:
    state: EvaluationRunStateV22
    result: EvaluationResultV22 | None
    engine_paused: bool
    pause_reason_codes: tuple[str, ...] = ()
    pending_request: EvaluatorRequestV22 | None = None
    exit_code: int = 0


@dataclass(frozen=True)
class GuardedSubmissionResultV22:
    accepted: bool
    preflight: V22ResponsePreflight
    state: EvaluationRunStateV22 | None = None


@dataclass(frozen=True)
class _GradeStepV22:
    operation: EvaluatorOperationV22
    anonymous_label: Literal["A", "B"]
    grader_lane: Literal[1, 2]
    batch: OrdinaryGradeBatchV22 | None = None
    contested: ContestedRequirementV22 | None = None


class _NoopTelemetrySinkV22:
    def emit(self, event: EvaluationTelemetryEventV22) -> None:
        del event


_NOOP_TELEMETRY = _NoopTelemetrySinkV22()
_SUBMISSION_LOCKS = tuple(threading.RLock() for _ in range(64))
_SubmissionRootIdentity = tuple[int, int]


def _submission_root_identity(run_dir: Path) -> _SubmissionRootIdentity:
    try:
        metadata = os.stat(run_dir, follow_symlinks=False)
    except (NotImplementedError, OSError, TypeError, ValueError) as error:
        raise EvaluationIntegrityError("EVALUATOR_V22_RUN_ROOT_IDENTITY") from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise EvaluationIntegrityError("EVALUATOR_V22_RUN_ROOT_IDENTITY")
    return metadata.st_dev, metadata.st_ino


def _submission_lock(
    run_dir: Path,
    *,
    root_identity: _SubmissionRootIdentity | None = None,
) -> threading.RLock:
    identity = (
        _submission_root_identity(run_dir) if root_identity is None else root_identity
    )
    lock_index = int(sha256_digest(f"{identity[0]}:{identity[1]}".encode())[:8], 16) % len(
        _SUBMISSION_LOCKS
    )
    return _SUBMISSION_LOCKS[lock_index]


@contextlib.contextmanager
def _submission_guard(run_dir: Path) -> Iterator[None]:
    root_identity = _submission_root_identity(run_dir)
    with _submission_lock(run_dir, root_identity=root_identity):
        if _submission_root_identity(run_dir) != root_identity:
            raise EvaluationIntegrityError("EVALUATOR_V22_RUN_ROOT_IDENTITY")
        yield
        if _submission_root_identity(run_dir) != root_identity:
            raise EvaluationIntegrityError("EVALUATOR_V22_RUN_ROOT_IDENTITY")


def _model_bytes(value: object) -> bytes:
    if not hasattr(value, "model_dump"):
        raise TypeError("expected a model value")
    return canonical_json_bytes(value.model_dump(mode="json", warnings="error"))


def _state(manifest: EvaluationManifestV22) -> EvaluationRunStateV22:
    pending = tuple(call for call in manifest.calls if call.state == "pending")
    if len(pending) > 1:
        raise EvaluationIntegrityError("EVALUATOR_V22_PENDING_CALL")
    return EvaluationRunStateV22(
        case_fingerprint=manifest.case_fingerprint,
        phase=manifest.phase,
        current_call_id=pending[0].call_id if pending else None,
        terminal_status=manifest.terminal_status,
        manifest_fingerprint=manifest.manifest_fingerprint,
    )


def _labels(context: VerifiedV22Context) -> tuple[Literal["A", "B"], ...]:
    labels = tuple(
        assignment.anonymous_label for assignment in context.load_case_envelope().assignments
    )
    if labels not in (("A",), ("A", "B")):
        raise EvaluationIntegrityError("EVALUATOR_V22_CASE_BUILD_BINDING")
    return cast(tuple[Literal["A", "B"], ...], labels)


def _report_text(context: VerifiedV22Context, label: Literal["A", "B"]) -> str:
    envelope = context.load_case_envelope()
    assignments = [item for item in envelope.assignments if item.anonymous_label == label]
    if len(assignments) != 1:
        raise EvaluationIntegrityError("EVALUATOR_V22_CASE_BUILD_BINDING")
    reports = [
        item
        for item in envelope.case.candidates
        if item.candidate_id == assignments[0].candidate_id
    ]
    if len(reports) != 1:
        raise EvaluationIntegrityError("EVALUATOR_V22_CASE_BUILD_BINDING")
    return reports[0].report_text


def _pending_call(
    call_id: str,
    request: EvaluatorRequestV22,
    *,
    fragment_ordinal: int | None = None,
    dispute_id: str | None = None,
    anonymous_label: Literal["A", "B"] | None = None,
    grader_lane: Literal[1, 2] | None = None,
    batch_ref: str | None = None,
    contested_requirement_id: str | None = None,
) -> EvaluationCallRecordV22:
    return EvaluationCallRecordV22(
        call_id=call_id,
        operation=request.operation,
        state="pending",
        attempt=1,
        request_artifact_path=f"requests/{call_id}.json",
        request_fingerprint=request.request_fingerprint,
        fragment_ordinal=fragment_ordinal,
        dispute_id=dispute_id,
        anonymous_label=anonymous_label,
        grader_lane=grader_lane,
        batch_ref=batch_ref,
        contested_requirement_id=contested_requirement_id,
    )


def _accepted_call(
    call: EvaluationCallRecordV22, response: EvaluatorResponseV22
) -> EvaluationCallRecordV22:
    response_bytes = _model_bytes(response)
    return call.model_copy(
        update={
            "state": "accepted",
            "response_artifact_path": f"responses/{call.call_id}.json",
            "response_fingerprint": sha256_digest(response_bytes),
            "provider_name": response.provider_name,
            "model_name": response.model_name,
            "judge_isolation": response.judge_isolation,
        }
    )


def _manifest(
    prior: EvaluationManifestV22,
    *,
    calls: tuple[EvaluationCallRecordV22, ...],
    phase: EvaluationPhaseV22,
    baseline: CanonicalBaselineV22 | None = None,
    source_review_fingerprint: str | None = None,
    source_audit_fingerprint: str | None = None,
    referee_fingerprint: str | None = None,
    aggregate_fingerprints: tuple[str, ...] = (),
    sensitivity_fingerprints: tuple[str, ...] = (),
    result_hash: str | None = None,
    terminal_status: EvaluationTerminalStatusV22 | None = None,
    disputes: tuple[RefereeDisputeV22, ...] | None = None,
    batches: tuple[OrdinaryGradeBatchV22, ...] | None = None,
) -> EvaluationManifestV22:
    data = prior.model_dump(mode="json")
    data.update(
        {
            "calls": calls,
            "phase": phase,
            "source_review_aggregate_fingerprint": (
                prior.source_review_aggregate_fingerprint
                if source_review_fingerprint is None
                else source_review_fingerprint
            ),
            "source_audit_aggregate_fingerprint": (
                prior.source_audit_aggregate_fingerprint
                if source_audit_fingerprint is None
                else source_audit_fingerprint
            ),
            "referee_aggregate_fingerprint": (
                prior.referee_aggregate_fingerprint
                if referee_fingerprint is None
                else referee_fingerprint
            ),
            "baseline_fingerprint": (
                prior.baseline_fingerprint if baseline is None else baseline.baseline_fingerprint
            ),
            "grader_aggregate_fingerprints": aggregate_fingerprints,
            "sensitivity_fingerprints": sensitivity_fingerprints,
            "result_hash": result_hash,
            "terminal_status": terminal_status,
            "referee_disputes": prior.referee_disputes if disputes is None else disputes,
            "ordinary_grade_batches": (
                prior.ordinary_grade_batches if batches is None else batches
            ),
            "artifacts": (),
            "manifest_fingerprint": "0" * 64,
        }
    )
    active_batches = tuple(
        OrdinaryGradeBatchV22.model_validate(item) for item in data["ordinary_grade_batches"]
    )
    contested = () if baseline is None else baseline.contested_requirements
    return EvaluationManifestV22.model_validate(
        data,
        context={
            "ordinary_grade_batches": active_batches,
            "contested_requirements": contested,
        },
    )


def _response(run_dir: Path, call: EvaluationCallRecordV22) -> EvaluatorResponseV22:
    if call.response_artifact_path is None:
        raise EvaluationIntegrityError("EVALUATOR_V22_ACCEPTED_RESPONSE")
    return validate_evaluator_response_v22(
        json.loads(read_evaluation_artifact(run_dir, call.response_artifact_path))
    )


def _review_fragments(
    run_dir: Path, manifest: EvaluationManifestV22
) -> tuple[AcceptedSourceReviewFragmentV22, ...]:
    fragments = []
    for call in manifest.calls:
        if (
            call.state == "accepted"
            and call.operation is EvaluatorOperationV22.SOURCE_REVIEW_FRAGMENT
        ):
            response = _response(run_dir, call)
            fragments.append(
                AcceptedSourceReviewFragmentV22(
                    fragment_ordinal=cast(int, call.fragment_ordinal),
                    request_fingerprint=call.request_fingerprint,
                    response_fingerprint=cast(str, call.response_fingerprint),
                    payload=SourceReviewFragmentV22.model_validate(response.payload),
                )
            )
    return tuple(fragments)


def _audit_fragments(
    run_dir: Path,
    manifest: EvaluationManifestV22,
    review: SourceReviewAggregateV22,
) -> tuple[AcceptedSourceAuditFragmentV22, ...]:
    fragments = []
    for call in manifest.calls:
        if (
            call.state == "accepted"
            and call.operation is EvaluatorOperationV22.SOURCE_AUDIT_FRAGMENT
        ):
            response = _response(run_dir, call)
            fragments.append(
                AcceptedSourceAuditFragmentV22(
                    fragment_ordinal=cast(int, call.fragment_ordinal),
                    request_fingerprint=call.request_fingerprint,
                    response_fingerprint=cast(str, call.response_fingerprint),
                    payload=SourceAuditFragmentV22.validate_for_indexed_proposals(
                        response.payload, review.proposals
                    ),
                )
            )
    return tuple(fragments)


def _referee_fragments(
    run_dir: Path, manifest: EvaluationManifestV22
) -> tuple[AcceptedRefereeFragmentV22, ...]:
    fragments = []
    for call in manifest.calls:
        if (
            call.state == "accepted"
            and call.operation is EvaluatorOperationV22.SOURCE_REFEREE_FRAGMENT
        ):
            dispute = next(
                item for item in manifest.referee_disputes if item.dispute_id == call.dispute_id
            )
            fragments.append(
                validate_referee_fragment_v22(
                    dispute,
                    _response(run_dir, call).payload,
                    response_fingerprint=cast(str, call.response_fingerprint),
                )
            )
    return tuple(fragments)


def _grade_steps(
    baseline: CanonicalBaselineV22,
    batches: tuple[OrdinaryGradeBatchV22, ...],
    labels: tuple[Literal["A", "B"], ...],
) -> tuple[_GradeStepV22, ...]:
    return tuple(
        step
        for label in labels
        for lane in cast(tuple[Literal[1, 2], ...], (1, 2))
        for step in (
            *(
                _GradeStepV22(
                    EvaluatorOperationV22.ORDINARY_GRADE_FRAGMENT,
                    label,
                    lane,
                    batch=batch,
                )
                for batch in batches
                if batch.batch_ref.startswith(f"GB-{label}-{lane}-")
            ),
            *(
                _GradeStepV22(
                    EvaluatorOperationV22.CONTESTED_GRADE_FRAGMENT,
                    label,
                    lane,
                    contested=item,
                )
                for item in baseline.contested_requirements
            ),
        )
    )


def _next_grade_call(
    context: VerifiedV22Context,
    step: _GradeStepV22,
) -> tuple[EvaluationCallRecordV22, EvaluatorRequestV22]:
    baseline = context.baseline
    if baseline is None:
        raise EvaluationIntegrityError("EVALUATOR_V22_BASELINE_MISSING")
    report_text = _report_text(context, step.anonymous_label)
    source_context = dict(context.source_context)
    if step.operation is EvaluatorOperationV22.ORDINARY_GRADE_FRAGMENT:
        if step.batch is None:
            raise EvaluationIntegrityError("EVALUATOR_V22_GRADE_STEP")
        request = build_ordinary_grade_request_v22(
            baseline,
            step.batch,
            step.anonymous_label,
            step.grader_lane,
            report_text,
            source_context,
            context.rubric,
        )
        call_id = f"grade-{step.batch.batch_ref}"
        return (
            _pending_call(
                call_id,
                request,
                anonymous_label=step.anonymous_label,
                grader_lane=step.grader_lane,
                batch_ref=step.batch.batch_ref,
            ),
            request,
        )
    if step.contested is None:
        raise EvaluationIntegrityError("EVALUATOR_V22_GRADE_STEP")
    request = build_contested_grade_request_v22(
        baseline,
        step.contested,
        step.anonymous_label,
        step.grader_lane,
        report_text,
        source_context,
        context.rubric,
    )
    call_id = (
        f"grade-contested-{step.anonymous_label}-{step.grader_lane}-"
        f"{step.contested.contested_requirement_id}"
    )
    return (
        _pending_call(
            call_id,
            request,
            anonymous_label=step.anonymous_label,
            grader_lane=step.grader_lane,
            contested_requirement_id=step.contested.contested_requirement_id,
        ),
        request,
    )


def _comparison(
    context: VerifiedV22Context,
    sensitivities: tuple[SensitivityRecordV22, ...],
) -> ComparisonResultV22 | None:
    if len(sensitivities) == 1:
        return None
    envelope = context.load_case_envelope()
    roles = {candidate.candidate_id: candidate.role.value for candidate in envelope.case.candidates}
    labels = {
        roles[assignment.candidate_id]: assignment.anonymous_label
        for assignment in envelope.assignments
    }
    if set(labels) != {"candidate", "comparator"}:
        raise EvaluationIntegrityError("EVALUATOR_V22_COMPARISON_ROLES")
    return build_comparison_result_v22(
        candidate_label=labels["candidate"],
        comparator_label=labels["comparator"],
        dispositions={
            item.anonymous_label: item.absolute_disposition
            for item in sensitivities
        },
    )


def _result(
    context: VerifiedV22Context,
    baseline: CanonicalBaselineV22,
    sensitivities: tuple[SensitivityRecordV22, ...],
    reconciliations: tuple[ReconciledGradeV22, ...],
) -> EvaluationResultV22:
    reports = []
    for sensitivity, reconciliation in zip(sensitivities, reconciliations, strict=True):
        report_payload = {
            "anonymous_label": sensitivity.anonymous_label,
            "reconciliation": reconciliation.model_dump(mode="json"),
            "sensitivity": sensitivity.model_dump(mode="json"),
        }
        reports.append(
            ReportResultV22(
                anonymous_label=sensitivity.anonymous_label,
                reconciliation=reconciliation,
                sensitivity=sensitivity,
                result_fingerprint=sha256_digest(canonical_json_bytes(report_payload)),
            )
        )
    terminal = (
        EvaluationTerminalStatusV22.INCONCLUSIVE
        if any(
            item.absolute_disposition is AbsoluteDispositionV2.INCONCLUSIVE
            for item in sensitivities
        )
        else EvaluationTerminalStatusV22.COMPLETED
    )
    comparison = _comparison(context, sensitivities)
    payload: dict[str, object] = {
        "schema_version": "2.2",
        "rubric": RUBRIC_V22.model_dump(mode="json"),
        "baseline": baseline.model_dump(mode="json"),
        "reports": [item.model_dump(mode="json") for item in reports],
        "comparison": None if comparison is None else comparison.model_dump(mode="json"),
        "terminal_status": terminal.value,
    }
    return EvaluationResultV22(
        schema_version="2.2",
        rubric=RUBRIC_V22,
        baseline=baseline,
        reports=tuple(reports),
        comparison=comparison,
        terminal_status=terminal,
        result_fingerprint=sha256_digest(canonical_json_bytes(payload)),
    )


def _empty_lane_aggregate(
    baseline: CanonicalBaselineV22,
    context: VerifiedV22Context,
    label: Literal["A", "B"],
    lane: Literal[1, 2],
) -> GraderAggregateV22:
    payload: dict[str, object] = {
        "anonymous_label": label,
        "grader_lane": lane,
        "baseline_fingerprint": baseline.baseline_fingerprint,
        "report_fingerprint": sha256_digest(_report_text(context, label).encode()),
        "ordinary_fragments": [],
        "contested_fragments": [],
    }
    return GraderAggregateV22.validate_for_inventories(
        {
            **payload,
            "aggregate_fingerprint": sha256_digest(canonical_json_bytes(payload)),
        },
        (),
        (),
    )


def _empty_sensitivity(
    baseline: CanonicalBaselineV22,
    first: GraderAggregateV22,
    second: GraderAggregateV22,
) -> tuple[ReconciledGradeV22, SensitivityRecordV22]:
    reconciliation = reconcile_grader_lanes_v22(baseline, first, second, RUBRIC_V22)
    payload = {
        "anonymous_label": first.anonymous_label,
        "baseline_fingerprint": baseline.baseline_fingerprint,
        "reconciliation_fingerprint": reconciliation.reconciliation_fingerprint,
        "absolute_disposition": "INCONCLUSIVE",
        "reason_codes": ["BASELINE_EVIDENCE_INSUFFICIENT"],
        "outcome_determinative_contested_ids": [],
    }
    sensitivity = SensitivityRecordV22.model_validate(
        {
            **payload,
            "sensitivity_fingerprint": sha256_digest(canonical_json_bytes(payload)),
        }
    )
    return reconciliation, sensitivity


def _seal_baseline_transition(
    run_dir: Path,
    context: VerifiedV22Context,
    calls: tuple[EvaluationCallRecordV22, ...],
    review: SourceReviewAggregateV22,
    audit: SourceAuditAggregateV22,
    disputes: tuple[RefereeDisputeV22, ...],
    referee: RefereeAggregateV22,
    files: dict[str, bytes],
) -> EvaluationRunStateV22:
    baseline = compile_baseline_v22(context.load_case_envelope(), review, audit, referee)
    files[V22_REFEREE_AGGREGATE_PATH] = _model_bytes(referee)
    files[V22_BASELINE_PATH] = _model_bytes(baseline)
    labels = _labels(context)
    batches = tuple(
        batch
        for label in labels
        for lane in cast(tuple[Literal[1, 2], ...], (1, 2))
        for batch in ordinary_grade_batches_v22(baseline, label, lane)
    )
    if not baseline.requirements and not baseline.contested_requirements:
        aggregates: list[GraderAggregateV22] = []
        reconciliations: list[ReconciledGradeV22] = []
        sensitivities: list[SensitivityRecordV22] = []
        for label in labels:
            first = _empty_lane_aggregate(baseline, context, label, 1)
            second = _empty_lane_aggregate(baseline, context, label, 2)
            files[f"aggregates/grade-{label}-1.json"] = _model_bytes(first)
            files[f"aggregates/grade-{label}-2.json"] = _model_bytes(second)
            aggregates.extend((first, second))
            reconciliation, sensitivity = _empty_sensitivity(baseline, first, second)
            reconciliations.append(reconciliation)
            sensitivities.append(sensitivity)
            files[f"sensitivities/{label}.json"] = _model_bytes(sensitivity)
        result = _result(
            context,
            baseline,
            tuple(sensitivities),
            tuple(reconciliations),
        )
        files[V22_RESULT_PATH] = _model_bytes(result)
        successor = _manifest(
            context.manifest,
            calls=calls,
            phase=EvaluationPhaseV22.INCONCLUSIVE,
            baseline=baseline,
            source_audit_fingerprint=audit.aggregate_fingerprint,
            referee_fingerprint=referee.aggregate_fingerprint,
            aggregate_fingerprints=tuple(item.aggregate_fingerprint for item in aggregates),
            sensitivity_fingerprints=tuple(item.sensitivity_fingerprint for item in sensitivities),
            result_hash=result.result_fingerprint,
            terminal_status=EvaluationTerminalStatusV22.INCONCLUSIVE,
            disputes=disputes,
            batches=batches,
        )
    else:
        provisional = VerifiedV22Context(
            manifest=context.manifest,
            result=None,
            case_envelope_bytes=context.case_envelope_bytes,
            rubric=context.rubric,
            baseline=baseline,
            source_context=context.source_context,
        )
        steps = _grade_steps(baseline, batches, labels)
        if not steps:
            raise EvaluationIntegrityError("EVALUATOR_V22_GRADE_FRAGMENT_COVERAGE")
        call, request = _next_grade_call(provisional, steps[0])
        calls = (*calls, call)
        files[call.request_artifact_path] = _model_bytes(request)
        successor = _manifest(
            context.manifest,
            calls=calls,
            phase=(
                EvaluationPhaseV22.ORDINARY_GRADING
                if call.operation is EvaluatorOperationV22.ORDINARY_GRADE_FRAGMENT
                else EvaluationPhaseV22.CONTESTED_GRADING
            ),
            baseline=baseline,
            source_audit_fingerprint=audit.aggregate_fingerprint,
            referee_fingerprint=referee.aggregate_fingerprint,
            disputes=disputes,
            batches=batches,
        )
    commit_v22_transition(
        run_dir,
        context.manifest.manifest_fingerprint,
        files,
        successor,
    )
    return resume_evaluation_v22(run_dir)


def _accepted_grade_fragments(
    run_dir: Path,
    context: VerifiedV22Context,
    calls: tuple[EvaluationCallRecordV22, ...],
    current_response: EvaluatorResponseV22,
) -> dict[
    tuple[Literal["A", "B"], Literal[1, 2]],
    tuple[list[OrdinaryGradeFragmentV22], list[ContestedGradeFragmentV22]],
]:
    if context.baseline is None:
        raise EvaluationIntegrityError("EVALUATOR_V22_BASELINE_MISSING")
    values: dict[
        tuple[Literal["A", "B"], Literal[1, 2]],
        tuple[list[OrdinaryGradeFragmentV22], list[ContestedGradeFragmentV22]],
    ] = {}
    for call in calls:
        if call.state != "accepted" or call.operation not in {
            EvaluatorOperationV22.ORDINARY_GRADE_FRAGMENT,
            EvaluatorOperationV22.CONTESTED_GRADE_FRAGMENT,
        }:
            continue
        label = cast(Literal["A", "B"], call.anonymous_label)
        lane = cast(Literal[1, 2], call.grader_lane)
        ordinary, contested = values.setdefault((label, lane), ([], []))
        fragment = validate_grade_fragment_v22(
            context.baseline,
            (
                current_response.payload
                if call.call_id == calls[-1].call_id
                else _response(run_dir, call).payload
            ),
            _report_text(context, label),
        )
        if isinstance(fragment, OrdinaryGradeFragmentV22):
            ordinary.append(fragment)
        else:
            contested.append(fragment)
    return values


def _load_grade_aggregate(
    run_dir: Path,
    baseline: CanonicalBaselineV22,
    label: Literal["A", "B"],
    lane: Literal[1, 2],
) -> GraderAggregateV22:
    data = read_evaluation_artifact(run_dir, f"aggregates/grade-{label}-{lane}.json")
    return _grade_aggregate_from_bytes(baseline, label, lane, data)


def _grade_aggregate_from_bytes(
    baseline: CanonicalBaselineV22,
    label: Literal["A", "B"],
    lane: Literal[1, 2],
    data: bytes,
) -> GraderAggregateV22:
    raw = json.loads(data)
    return GraderAggregateV22.validate_for_inventories(
        raw,
        ordinary_grade_batches_v22(baseline, label, lane),
        baseline.contested_requirements,
    )


def _advance_grade(
    run_dir: Path,
    context: VerifiedV22Context,
    calls: tuple[EvaluationCallRecordV22, ...],
    files: dict[str, bytes],
    response: EvaluatorResponseV22,
) -> EvaluationRunStateV22:
    baseline = context.baseline
    if baseline is None:
        raise EvaluationIntegrityError("EVALUATOR_V22_BASELINE_MISSING")
    labels = _labels(context)
    steps = _grade_steps(baseline, context.manifest.ordinary_grade_batches, labels)
    accepted_grade_calls = tuple(
        call
        for call in calls
        if call.state == "accepted"
        and call.operation
        in {
            EvaluatorOperationV22.ORDINARY_GRADE_FRAGMENT,
            EvaluatorOperationV22.CONTESTED_GRADE_FRAGMENT,
        }
    )
    fragments = _accepted_grade_fragments(run_dir, context, calls, response)
    aggregate_fingerprints = list(context.manifest.grader_aggregate_fingerprints)
    sensitivity_fingerprints = list(context.manifest.sensitivity_fingerprints)
    current = accepted_grade_calls[-1]
    current_label = cast(Literal["A", "B"], current.anonymous_label)
    current_lane = cast(Literal[1, 2], current.grader_lane)
    lane_steps = [
        item
        for item in steps
        if item.anonymous_label == current_label and item.grader_lane == current_lane
    ]
    lane_call_count = sum(
        call.anonymous_label == current_label and call.grader_lane == current_lane
        for call in accepted_grade_calls
    )
    if lane_call_count == len(lane_steps):
        ordinary, contested = fragments[(current_label, current_lane)]
        aggregate = aggregate_grader_lane_v22(
            baseline,
            current_label,
            current_lane,
            tuple(ordinary),
            tuple(contested),
        )
        files[f"aggregates/grade-{current_label}-{current_lane}.json"] = _model_bytes(aggregate)
        aggregate_fingerprints.append(aggregate.aggregate_fingerprint)
        if current_lane == 2:
            first = _load_grade_aggregate(run_dir, baseline, current_label, 1)
            reconciliation = reconcile_grader_lanes_v22(baseline, first, aggregate, context.rubric)
            sensitivity = evaluate_outcome_sensitivity_v22(baseline, reconciliation, context.rubric)
            files[f"sensitivities/{current_label}.json"] = _model_bytes(sensitivity)
            sensitivity_fingerprints.append(sensitivity.sensitivity_fingerprint)
    if len(accepted_grade_calls) < len(steps):
        next_step = steps[len(accepted_grade_calls)]
        call, request = _next_grade_call(context, next_step)
        calls = (*calls, call)
        files[call.request_artifact_path] = _model_bytes(request)
        successor = _manifest(
            context.manifest,
            calls=calls,
            phase=(
                EvaluationPhaseV22.ORDINARY_GRADING
                if call.operation is EvaluatorOperationV22.ORDINARY_GRADE_FRAGMENT
                else EvaluationPhaseV22.CONTESTED_GRADING
            ),
            baseline=baseline,
            aggregate_fingerprints=tuple(aggregate_fingerprints),
            sensitivity_fingerprints=tuple(sensitivity_fingerprints),
        )
    else:
        sensitivity_values = []
        for label in labels:
            path = f"sensitivities/{label}.json"
            data = files[path] if path in files else read_evaluation_artifact(run_dir, path)
            sensitivity_values.append(SensitivityRecordV22.model_validate_json(data))
        sensitivities = tuple(sensitivity_values)
        reconciliations = tuple(
            reconcile_grader_lanes_v22(
                baseline,
                _load_grade_aggregate(run_dir, baseline, label, 1),
                (
                    _grade_aggregate_from_bytes(
                        baseline,
                        label,
                        2,
                        files[f"aggregates/grade-{label}-2.json"],
                    )
                    if f"aggregates/grade-{label}-2.json" in files
                    else _load_grade_aggregate(run_dir, baseline, label, 2)
                ),
                context.rubric,
            )
            for label in labels
        )
        result = _result(context, baseline, sensitivities, reconciliations)
        files[V22_RESULT_PATH] = _model_bytes(result)
        successor = _manifest(
            context.manifest,
            calls=calls,
            phase=(
                EvaluationPhaseV22.INCONCLUSIVE
                if result.terminal_status is EvaluationTerminalStatusV22.INCONCLUSIVE
                else EvaluationPhaseV22.COMPLETED
            ),
            baseline=baseline,
            aggregate_fingerprints=tuple(aggregate_fingerprints),
            sensitivity_fingerprints=tuple(sensitivity_fingerprints),
            result_hash=result.result_fingerprint,
            terminal_status=result.terminal_status,
        )
    commit_v22_transition(
        run_dir,
        context.manifest.manifest_fingerprint,
        files,
        successor,
    )
    return resume_evaluation_v22(run_dir)


def initialize_evaluation_v22(
    case: AttorneyEvaluationCase,
    output_dir: Path,
    *,
    seed_hex: str,
    generation_capsule_paths: Mapping[str, Path] | None = None,
) -> EvaluationRunStateV22:
    """Freeze a new case and issue its first source-review fragment."""
    strict_case = AttorneyEvaluationCase.model_validate(case.model_dump(mode="json"))
    if strict_case.schema_version != "1.1":
        raise ValueError("case schema 1.1 is required for new evaluation runs")
    _verify_generation_capsules_for_initialization(strict_case, generation_capsule_paths)
    envelope = freeze_case(strict_case, seed_hex=seed_hex)
    request = build_source_review_fragment_request_v22(envelope, (), fragment_ordinal=1)
    request_path = "requests/source-review-0001.json"
    call = EvaluationCallRecordV22(
        call_id="source-review-0001",
        operation=request.operation,
        state="pending",
        attempt=1,
        request_artifact_path=request_path,
        request_fingerprint=request.request_fingerprint,
        fragment_ordinal=1,
    )
    case_bytes = _model_bytes(envelope)
    build_bytes = canonical_json_bytes(
        {
            "compiler_contract_fingerprint": COMPILER_CONTRACT_FINGERPRINT_V22,
            "compiler_version": "semantic-compiler-v2.2",
            "protocol_version": "2.2",
        }
    )
    rubric_bytes = _model_bytes(RUBRIC_V22)
    manifest = EvaluationManifestV22(
        case_fingerprint=envelope.case_fingerprint,
        case_envelope_hash=sha256_digest(case_bytes),
        build_fingerprint=sha256_digest(build_bytes),
        rubric_fingerprint=sha256_digest(rubric_bytes),
        compiler_contract_fingerprint=COMPILER_CONTRACT_FINGERPRINT_V22,
        compiler_version="semantic-compiler-v2.2",
        phase=EvaluationPhaseV22.SOURCE_REVIEW,
        calls=(call,),
        artifacts=(),
        referee_disputes=(),
        ordinary_grade_batches=(),
        manifest_fingerprint="0" * 64,
    )
    committed = initialize_v22_run_storage(
        output_dir,
        manifest,
        {
            V22_CASE_PATH: case_bytes,
            V22_BUILD_PATH: build_bytes,
            V22_RUBRIC_PATH: rubric_bytes,
            request_path: _model_bytes(request),
        },
    )
    return _state(committed)


def next_evaluator_request_v22(run_dir: Path) -> EvaluatorRequestV22 | None:
    """Return the exact pending request retained by a verified run."""
    context = load_verified_v22_context(run_dir)
    if context.manifest.terminal_status is not None:
        return None
    pending = tuple(call for call in context.manifest.calls if call.state == "pending")
    if len(pending) != 1:
        raise EvaluationIntegrityError("EVALUATOR_V22_PENDING_CALL")
    return EvaluatorRequestV22.model_validate_json(
        read_evaluation_artifact(run_dir, pending[0].request_artifact_path)
    )


def resume_evaluation_v22(run_dir: Path) -> EvaluationRunStateV22:
    """Verify and expose the current resumable Protocol 2.2 state."""
    context = load_verified_v22_context(run_dir)
    if context.manifest.compiler_contract_fingerprint != COMPILER_CONTRACT_FINGERPRINT_V22:
        raise EvaluationIntegrityError("EVALUATOR_V22_COMPILER_CONTRACT")
    return _state(context.manifest)


def preflight_evaluator_response_v22(run_dir: Path, response: object) -> V22ResponsePreflight:
    """Strictly validate an external envelope without changing the run."""
    context = load_verified_v22_context(run_dir)
    pending = tuple(call for call in context.manifest.calls if call.state == "pending")
    if context.manifest.terminal_status is not None or len(pending) != 1:
        return V22ResponsePreflight(False, ("EXTERNAL_RESPONSE_INVALID",))
    call = pending[0]
    request = EvaluatorRequestV22.model_validate_json(
        read_evaluation_artifact(run_dir, call.request_artifact_path)
    )
    if (
        request.operation is not call.operation
        or request.request_fingerprint != call.request_fingerprint
    ):
        raise EvaluationIntegrityError("EVALUATOR_V22_PENDING_CALL")
    try:
        validated = validate_evaluator_response_v22(response)
    except _EvaluatorResponseValidationErrorV22:
        return V22ResponsePreflight(False, ("EXTERNAL_RESPONSE_INVALID",))
    if (
        validated.operation is not call.operation
        or validated.request_fingerprint != call.request_fingerprint
    ):
        return V22ResponsePreflight(False, ("EXTERNAL_RESPONSE_INVALID",))

    if call.operation is EvaluatorOperationV22.SOURCE_REVIEW_FRAGMENT:
        try:
            review_payload = SourceReviewFragmentV22.model_validate(validated.payload)
        except ValidationError:
            return V22ResponsePreflight(False, ("EXTERNAL_RESPONSE_INVALID",))
        review_history = _review_fragments(run_dir, context.manifest)
        try:
            _validate_source_fragment_semantics_v22(
                tuple(
                    proposal
                    for fragment in review_history
                    for proposal in fragment.payload.proposals
                )
                + review_payload.proposals,
                kind="source-review proposal",
            )
        except _SourceFragmentSemanticResponseErrorV22:
            return V22ResponsePreflight(False, ("EXTERNAL_RESPONSE_INVALID",))
    elif call.operation is EvaluatorOperationV22.SOURCE_AUDIT_FRAGMENT:
        review = aggregate_source_review_fragments_v22(
            _review_fragments(run_dir, context.manifest)
        )
        try:
            audit_payload = SourceAuditFragmentV22.model_validate(validated.payload)
        except ValidationError:
            return V22ResponsePreflight(False, ("EXTERNAL_RESPONSE_INVALID",))
        known_proposals = {item.proposal_ref for item in review.proposals}
        if any(
            concern.target_proposal_ref is not None
            and concern.target_proposal_ref not in known_proposals
            for concern in audit_payload.concerns
        ):
            return V22ResponsePreflight(False, ("EXTERNAL_RESPONSE_INVALID",))
        audit_history = _audit_fragments(run_dir, context.manifest, review)
        try:
            _validate_source_fragment_semantics_v22(
                tuple(
                    concern
                    for fragment in audit_history
                    for concern in fragment.payload.concerns
                )
                + audit_payload.concerns,
                kind="source-audit concern",
            )
        except _SourceFragmentSemanticResponseErrorV22:
            return V22ResponsePreflight(False, ("EXTERNAL_RESPONSE_INVALID",))
    elif call.operation is EvaluatorOperationV22.SOURCE_REFEREE_FRAGMENT:
        disputes = tuple(
            dispute
            for dispute in context.manifest.referee_disputes
            if dispute.dispute_id == call.dispute_id
        )
        if len(disputes) != 1:
            raise EvaluationIntegrityError("EVALUATOR_V22_PENDING_CALL")
        try:
            RefereeDecisionV22.model_validate(
                validated.payload,
                context={
                    "evidence_refs": tuple(
                        item.evidence_ref for item in disputes[0].evidence
                    )
                },
            )
        except ValidationError:
            return V22ResponsePreflight(False, ("EXTERNAL_RESPONSE_INVALID",))
    else:
        baseline = context.baseline
        if baseline is None or call.anonymous_label is None or call.grader_lane is None:
            raise EvaluationIntegrityError("EVALUATOR_V22_PENDING_CALL")
        report_text = _report_text(context, call.anonymous_label)
        try:
            if call.operation is EvaluatorOperationV22.ORDINARY_GRADE_FRAGMENT:
                ordinary_payload = OrdinaryGradeFragmentV22.model_validate(
                    validated.payload,
                    context={
                        "ordinary_grade_batches": context.manifest.ordinary_grade_batches
                    },
                )
                call_binding = (
                    ordinary_payload.batch_ref == call.batch_ref
                    and ordinary_payload.anonymous_label == call.anonymous_label
                    and ordinary_payload.grader_lane == call.grader_lane
                )
                payload_baseline = ordinary_payload.baseline_fingerprint
                payload_report = ordinary_payload.report_fingerprint
                report_passages = tuple(
                    passage
                    for grade in ordinary_payload.requirement_grades
                    for passage in grade.report_passages
                )
            elif call.operation is EvaluatorOperationV22.CONTESTED_GRADE_FRAGMENT:
                contested_payload = ContestedGradeFragmentV22.model_validate(
                    validated.payload,
                    context={"contested_requirements": baseline.contested_requirements},
                )
                call_binding = (
                    contested_payload.contested_requirement_id
                    == call.contested_requirement_id
                    and contested_payload.anonymous_label == call.anonymous_label
                    and contested_payload.grader_lane == call.grader_lane
                )
                payload_baseline = contested_payload.baseline_fingerprint
                payload_report = contested_payload.report_fingerprint
                report_passages = tuple(
                    passage
                    for alternative in (
                        contested_payload.reviewer_alternative_grade,
                        contested_payload.auditor_alternative_grade,
                    )
                    for passage in alternative.report_passages
                )
            else:
                raise EvaluationIntegrityError("EVALUATOR_V22_PENDING_CALL")
        except ValidationError:
            return V22ResponsePreflight(False, ("EXTERNAL_RESPONSE_INVALID",))
        if (
            not call_binding
            or payload_baseline != baseline.baseline_fingerprint
            or payload_report != sha256_digest(report_text.encode("utf-8"))
            or any(report_text.count(passage) != 1 for passage in report_passages)
        ):
            return V22ResponsePreflight(False, ("EXTERNAL_RESPONSE_INVALID",))
    return V22ResponsePreflight(True)


def _advance(
    run_dir: Path,
    context: VerifiedV22Context,
    response: EvaluatorResponseV22,
) -> EvaluationRunStateV22:
    manifest = context.manifest
    pending_calls = tuple(call for call in manifest.calls if call.state == "pending")
    if len(pending_calls) != 1:
        raise EvaluationIntegrityError("EVALUATOR_V22_PENDING_CALL")
    pending = pending_calls[0]
    accepted = _accepted_call(pending, response)
    calls = (*tuple(call for call in manifest.calls if call.state == "accepted"), accepted)
    files: dict[str, bytes] = {cast(str, accepted.response_artifact_path): _model_bytes(response)}
    envelope = context.load_case_envelope()

    if pending.operation is EvaluatorOperationV22.SOURCE_REVIEW_FRAGMENT:
        review_history = list(_review_fragments(run_dir, manifest))
        review_payload = SourceReviewFragmentV22.model_validate(response.payload)
        review_history.append(
            AcceptedSourceReviewFragmentV22(
                fragment_ordinal=cast(int, pending.fragment_ordinal),
                request_fingerprint=pending.request_fingerprint,
                response_fingerprint=cast(str, accepted.response_fingerprint),
                payload=review_payload,
            )
        )
        if not review_payload.review_complete:
            if (
                len(review_history) >= 128
                or sum(len(item.payload.proposals) for item in review_history) >= 640
            ):
                raise ValueError("DRAFT_LIMIT_EXCEEDED")
            request = build_source_review_fragment_request_v22(
                envelope,
                tuple(review_history),
                fragment_ordinal=len(review_history) + 1,
            )
            call = _pending_call(
                f"source-review-{len(review_history) + 1:04d}",
                request,
                fragment_ordinal=len(review_history) + 1,
            )
            calls = (*calls, call)
            files[call.request_artifact_path] = _model_bytes(request)
            successor = _manifest(manifest, calls=calls, phase=EvaluationPhaseV22.SOURCE_REVIEW)
            commit_v22_transition(run_dir, manifest.manifest_fingerprint, files, successor)
            return resume_evaluation_v22(run_dir)
        review = aggregate_source_review_fragments_v22(tuple(review_history))
        files["aggregates/source-review.json"] = _model_bytes(review)
        request = build_source_audit_fragment_request_v22(envelope, review, (), fragment_ordinal=1)
        call = _pending_call("source-audit-0001", request, fragment_ordinal=1)
        calls = (*calls, call)
        files[call.request_artifact_path] = _model_bytes(request)
        successor = _manifest(
            manifest,
            calls=calls,
            phase=EvaluationPhaseV22.SOURCE_AUDIT,
            source_review_fingerprint=review.aggregate_fingerprint,
        )
        commit_v22_transition(run_dir, manifest.manifest_fingerprint, files, successor)
        return resume_evaluation_v22(run_dir)

    review = aggregate_source_review_fragments_v22(_review_fragments(run_dir, manifest))
    if pending.operation is EvaluatorOperationV22.SOURCE_AUDIT_FRAGMENT:
        audit_history = list(_audit_fragments(run_dir, manifest, review))
        audit_payload = SourceAuditFragmentV22.validate_for_indexed_proposals(
            response.payload, review.proposals
        )
        audit_history.append(
            AcceptedSourceAuditFragmentV22(
                fragment_ordinal=cast(int, pending.fragment_ordinal),
                request_fingerprint=pending.request_fingerprint,
                response_fingerprint=cast(str, accepted.response_fingerprint),
                payload=audit_payload,
            )
        )
        if not audit_payload.audit_complete:
            if (
                len(audit_history) >= 128
                or sum(len(item.payload.concerns) for item in audit_history) >= 640
            ):
                raise ValueError("DRAFT_LIMIT_EXCEEDED")
            request = build_source_audit_fragment_request_v22(
                envelope,
                review,
                tuple(audit_history),
                fragment_ordinal=len(audit_history) + 1,
            )
            call = _pending_call(
                f"source-audit-{len(audit_history) + 1:04d}",
                request,
                fragment_ordinal=len(audit_history) + 1,
            )
            calls = (*calls, call)
            files[call.request_artifact_path] = _model_bytes(request)
            successor = _manifest(manifest, calls=calls, phase=EvaluationPhaseV22.SOURCE_AUDIT)
            commit_v22_transition(run_dir, manifest.manifest_fingerprint, files, successor)
            return resume_evaluation_v22(run_dir)
        audit = aggregate_source_audit_fragments_v22(review, tuple(audit_history))
        files["aggregates/source-audit.json"] = _model_bytes(audit)
        disputes = build_referee_disputes_v22(envelope, review, audit)
        if disputes:
            request = build_source_referee_fragment_request_v22(
                envelope, disputes[0], controller_disputes=disputes
            )
            call = _pending_call(
                f"referee-{disputes[0].dispute_id}",
                request,
                dispute_id=disputes[0].dispute_id,
            )
            calls = (*calls, call)
            files[call.request_artifact_path] = _model_bytes(request)
            successor = _manifest(
                manifest,
                calls=calls,
                phase=EvaluationPhaseV22.SOURCE_REFEREE,
                source_audit_fingerprint=audit.aggregate_fingerprint,
                disputes=disputes,
            )
            commit_v22_transition(run_dir, manifest.manifest_fingerprint, files, successor)
            return resume_evaluation_v22(run_dir)
        referee = aggregate_referee_decisions_v22((), ())
        return _seal_baseline_transition(
            run_dir,
            context,
            calls,
            review,
            audit,
            disputes,
            referee,
            files,
        )

    audit = aggregate_source_audit_fragments_v22(
        review, _audit_fragments(run_dir, manifest, review)
    )
    if pending.operation is EvaluatorOperationV22.SOURCE_REFEREE_FRAGMENT:
        fragments = list(_referee_fragments(run_dir, manifest))
        dispute = next(
            item for item in manifest.referee_disputes if item.dispute_id == pending.dispute_id
        )
        fragments.append(
            validate_referee_fragment_v22(
                dispute,
                response.payload,
                response_fingerprint=cast(str, accepted.response_fingerprint),
            )
        )
        if len(fragments) < len(manifest.referee_disputes):
            next_dispute = manifest.referee_disputes[len(fragments)]
            request = build_source_referee_fragment_request_v22(
                envelope,
                next_dispute,
                controller_disputes=manifest.referee_disputes,
            )
            call = _pending_call(
                f"referee-{next_dispute.dispute_id}",
                request,
                dispute_id=next_dispute.dispute_id,
            )
            calls = (*calls, call)
            files[call.request_artifact_path] = _model_bytes(request)
            successor = _manifest(
                manifest,
                calls=calls,
                phase=EvaluationPhaseV22.SOURCE_REFEREE,
            )
            commit_v22_transition(run_dir, manifest.manifest_fingerprint, files, successor)
            return resume_evaluation_v22(run_dir)
        referee = aggregate_referee_decisions_v22(manifest.referee_disputes, tuple(fragments))
        return _seal_baseline_transition(
            run_dir,
            context,
            calls,
            review,
            audit,
            manifest.referee_disputes,
            referee,
            files,
        )

    return _advance_grade(run_dir, context, calls, files, response)


def guarded_submit_evaluator_response_v22(
    run_dir: Path, response: object
) -> GuardedSubmissionResultV22:
    """Preflight and atomically accept one complete external strict envelope."""
    with _submission_guard(run_dir):
        preflight = preflight_evaluator_response_v22(run_dir, response)
        if not preflight.valid:
            return GuardedSubmissionResultV22(False, preflight)
        validated = validate_evaluator_response_v22(response)
        context = load_verified_v22_context(run_dir)
        return GuardedSubmissionResultV22(
            True, preflight, _advance(run_dir, context, validated)
        )


def submit_evaluator_response_v22(run_dir: Path, response: object) -> EvaluationRunStateV22:
    result = guarded_submit_evaluator_response_v22(run_dir, response)
    if not result.accepted or result.state is None:
        raise ValueError("EXTERNAL_RESPONSE_INVALID")
    return result.state


def _emit_telemetry(
    sink: EvaluationTelemetrySinkV22,
    event: EvaluationTelemetryEventV22,
) -> None:
    with contextlib.suppress(Exception):
        sink.emit(event)


def _provenance(
    evaluator: AttorneyDraftEvaluatorV22, prompt: EvaluatorDraftPromptV22
) -> EvaluatorProvenanceV22:
    supplied = getattr(evaluator, "provenance", None)
    if callable(supplied):
        supplied = supplied(prompt)
    if isinstance(supplied, EvaluatorProvenanceV22):
        return supplied
    return EvaluatorProvenanceV22(
        provider_name="internal-evaluator",
        model_name=type(evaluator).__qualname__,
        judge_isolation="scripted_fixture",
    )


def _fragment_identity(request: EvaluatorRequestV22) -> str:
    return sha256_digest(
        canonical_json_bytes(
            {
                "operation": request.operation.value,
                "request_fingerprint": request.request_fingerprint,
            }
        )
    )[:24]


def _pause_outcome(
    run_dir: Path,
    request: EvaluatorRequestV22,
    *reason_codes: str,
) -> EvaluationDriverOutcomeV22:
    return EvaluationDriverOutcomeV22(
        state=resume_evaluation_v22(run_dir),
        result=None,
        engine_paused=True,
        pause_reason_codes=("EVALUATION_ENGINE_PAUSED", *reason_codes),
        pending_request=request,
        exit_code=6,
    )


def _outcome_after_stale_request(
    run_dir: Path, request: EvaluatorRequestV22
) -> EvaluationDriverOutcomeV22 | None:
    """Reload a run when another cooperating caller accepted this request."""
    with _submission_guard(run_dir):
        context = load_verified_v22_context(run_dir)
        if context.manifest.terminal_status is not None:
            return _completed_driver_outcome_v22(context)
        pending = next_evaluator_request_v22(run_dir)
        if pending is None:
            return _completed_driver_outcome_v22(context)
        if pending.request_fingerprint == request.request_fingerprint:
            return None
        return EvaluationDriverOutcomeV22(
            state=_state(context.manifest),
            result=context.result,
            engine_paused=False,
            pending_request=pending,
        )


async def _drive_pending_fragment_v22(
    run_dir: Path,
    evaluator: AttorneyDraftEvaluatorV22,
    *,
    telemetry_sink: EvaluationTelemetrySinkV22,
    resume_count: int,
) -> EvaluationDriverOutcomeV22:
    request = next_evaluator_request_v22(run_dir)
    if request is None:
        return _completed_driver_outcome_v22(load_verified_v22_context(run_dir))
    clarification_codes: tuple[DraftReasonCodeV22, ...] = ()
    for attempt in cast(tuple[Literal[1, 2], ...], (1, 2)):
        prompt = EvaluatorDraftPromptV22(
            request=request,
            attempt=attempt,
            clarification_codes=clarification_codes,
        )
        draft = await evaluator.evaluate_draft(prompt)
        compiled = compile_evaluator_draft_v22(request, draft, _provenance(evaluator, prompt))
        if isinstance(compiled, NeedsClarificationV22):
            clarification_codes = compiled.reason_codes
            _emit_telemetry(
                telemetry_sink,
                EvaluationTelemetryEventV22(
                    protocol_version="2.2",
                    compiler_contract_fingerprint=COMPILER_CONTRACT_FINGERPRINT_V22,
                    operation=request.operation.value,
                    fragment_identity=_fragment_identity(request),
                    attempt_number=attempt,
                    clarification_codes=tuple(item.value for item in compiled.reason_codes),
                    pause_count=1 if attempt == 2 else 0,
                    resume_count=resume_count,
                ),
            )
            if attempt == 1:
                continue
            return _pause_outcome(run_dir, request, *(item.value for item in compiled.reason_codes))
        if isinstance(compiled, EngineDefectV22):
            _emit_telemetry(
                telemetry_sink,
                EvaluationTelemetryEventV22(
                    protocol_version="2.2",
                    compiler_contract_fingerprint=COMPILER_CONTRACT_FINGERPRINT_V22,
                    operation=request.operation.value,
                    fragment_identity=_fragment_identity(request),
                    attempt_number=attempt,
                    clarification_codes=(compiled.reason_code,),
                    pause_count=1,
                    resume_count=resume_count,
                ),
            )
            return _pause_outcome(run_dir, request, compiled.reason_code)
        if not isinstance(compiled, CompiledDraftV22):
            return _pause_outcome(run_dir, request, "COMPILER_INVARIANT")
        try:
            submitted = guarded_submit_evaluator_response_v22(run_dir, compiled.response)
        except ValueError as error:
            if str(error) == "DRAFT_LIMIT_EXCEEDED":
                return _pause_outcome(run_dir, request, "DRAFT_LIMIT_EXCEEDED")
            raise
        if not submitted.accepted or submitted.state is None:
            stale_outcome = _outcome_after_stale_request(run_dir, request)
            if stale_outcome is not None:
                return stale_outcome
            defect = EngineDefectV22("COMPILER_PREFLIGHT_DISAGREEMENT")
            _emit_telemetry(
                telemetry_sink,
                EvaluationTelemetryEventV22(
                    protocol_version="2.2",
                    compiler_contract_fingerprint=COMPILER_CONTRACT_FINGERPRINT_V22,
                    operation=request.operation.value,
                    fragment_identity=_fragment_identity(request),
                    attempt_number=attempt,
                    normalization_codes=compiled.normalization_codes,
                    clarification_codes=(defect.reason_code,),
                    pause_count=1,
                    resume_count=resume_count,
                ),
            )
            return _pause_outcome(run_dir, request, defect.reason_code)
        state = submitted.state
        _emit_telemetry(
            telemetry_sink,
            EvaluationTelemetryEventV22(
                protocol_version="2.2",
                compiler_contract_fingerprint=COMPILER_CONTRACT_FINGERPRINT_V22,
                operation=request.operation.value,
                fragment_identity=_fragment_identity(request),
                attempt_number=attempt,
                normalization_codes=compiled.normalization_codes,
                clarification_codes=tuple(item.value for item in clarification_codes),
                resume_count=resume_count,
            ),
        )
        context = load_verified_v22_context(run_dir)
        return EvaluationDriverOutcomeV22(
            state=state,
            result=context.result,
            engine_paused=False,
            pending_request=next_evaluator_request_v22(run_dir),
        )
    raise AssertionError("unreachable evaluator attempt state")


def _completed_driver_outcome_v22(
    context: VerifiedV22Context,
) -> EvaluationDriverOutcomeV22:
    if context.manifest.terminal_status is None or context.result is None:
        raise EvaluationIntegrityError("EVALUATOR_V22_RESULT_REQUIRED")
    exit_code = 0
    if context.result.terminal_status is EvaluationTerminalStatusV22.INCONCLUSIVE:
        exit_code = 3
    elif any(
        item.sensitivity.absolute_disposition is AbsoluteDispositionV2.FAIL
        for item in context.result.reports
    ):
        exit_code = 4
    return EvaluationDriverOutcomeV22(
        state=_state(context.manifest),
        result=context.result,
        engine_paused=False,
        exit_code=exit_code,
    )


async def _continue_evaluation_v22(
    run_dir: Path,
    evaluator: AttorneyDraftEvaluatorV22,
    *,
    telemetry_sink: EvaluationTelemetrySinkV22,
    resume_count: int,
) -> EvaluationDriverOutcomeV22:
    if not isinstance(evaluator, AttorneyDraftEvaluatorV22):
        raise TypeError("evaluator must implement AttorneyDraftEvaluatorV22")
    context = load_verified_v22_context(run_dir)
    if context.manifest.compiler_contract_fingerprint != COMPILER_CONTRACT_FINGERPRINT_V22:
        raise EvaluationIntegrityError("EVALUATOR_V22_COMPILER_CONTRACT")
    while context.manifest.terminal_status is None:
        step = await _drive_pending_fragment_v22(
            run_dir,
            evaluator,
            telemetry_sink=telemetry_sink,
            resume_count=resume_count,
        )
        if step.engine_paused:
            return step
        context = load_verified_v22_context(run_dir)
    return _completed_driver_outcome_v22(context)


async def continue_evaluation_v22(
    run_dir: Path,
    evaluator: AttorneyDraftEvaluatorV22,
    *,
    telemetry_sink: EvaluationTelemetrySinkV22 | None = None,
) -> EvaluationDriverOutcomeV22:
    """Resume one verified pending run without repeating accepted fragments."""
    return await _continue_evaluation_v22(
        run_dir,
        evaluator,
        telemetry_sink=_NOOP_TELEMETRY if telemetry_sink is None else telemetry_sink,
        resume_count=1,
    )


async def run_evaluation_v22(
    case: AttorneyEvaluationCase,
    evaluator: AttorneyDraftEvaluatorV22,
    output_dir: Path,
    *,
    seed_hex: str,
    generation_capsule_paths: Mapping[str, Path] | None = None,
    telemetry_sink: EvaluationTelemetrySinkV22 | None = None,
) -> EvaluationDriverOutcomeV22:
    """Initialize and drive a fresh Protocol 2.2 run to substance or pause."""
    initialize_evaluation_v22(
        case,
        output_dir,
        seed_hex=seed_hex,
        generation_capsule_paths=generation_capsule_paths,
    )
    return await _continue_evaluation_v22(
        output_dir,
        evaluator,
        telemetry_sink=_NOOP_TELEMETRY if telemetry_sink is None else telemetry_sink,
        resume_count=0,
    )
