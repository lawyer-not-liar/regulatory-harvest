"""Bounded controller for fragmented evaluator protocol 2.1."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Protocol, cast, runtime_checkable

from pydantic import BaseModel

from regulatory_harvest.storage import canonical_json_bytes, sha256_digest

from .attorney_admission import freeze_case
from .attorney_artifacts import EvaluationIntegrityError, read_evaluation_artifact
from .attorney_models import AttorneyEvaluationCase, CaseEnvelope
from .attorney_v2_models import AbsoluteDispositionV2, ComparisonDispositionV2, ComparisonResultV2
from .attorney_v21_artifacts import (
    V21_BASELINE_PATH,
    V21_BUILD_PATH,
    V21_CASE_PATH,
    V21_REFEREE_AGGREGATE_PATH,
    V21_RESULT_PATH,
    V21_RUBRIC_PATH,
    V21ResponsePreflight,
    VerifiedV21Context,
    commit_v21_transition,
    initialize_v21_run_storage,
    load_verified_v21_context,
    preflight_v21_response,
)
from .attorney_v21_compiler import (
    aggregate_referee_decisions,
    build_referee_disputes,
    compile_baseline_v21,
    validate_referee_fragment,
)
from .attorney_v21_models import (
    CanonicalBaselineV21,
    ContestedGradeFragmentV21,
    ContestedRequirementV21,
    EvaluationCallRecordV21,
    EvaluationManifestV21,
    EvaluationPhaseV21,
    EvaluationResultV21,
    EvaluationRunStateV21,
    EvaluationTerminalStatusV21,
    EvaluatorOperationV21,
    EvaluatorRequestV21,
    EvaluatorResponseV21,
    GraderAggregateV21,
    OrdinaryGradeBatchV21,
    OrdinaryGradeFragmentV21,
    RefereeDisputeV21,
    ReportResultV21,
    SourceAuditV21,
    SourceReviewV21,
    validate_evaluator_response_v21,
)
from .attorney_v21_requests import (
    build_contested_grade_request_v21,
    build_ordinary_grade_request_v21,
    build_source_audit_request_v21,
    build_source_referee_fragment_request,
    build_source_review_request_v21,
    mechanical_retry_request_v21,
)
from .attorney_v21_rubric import (
    RUBRIC_V21,
    aggregate_grader_lane,
    evaluate_outcome_sensitivity,
    ordinary_grade_batches,
    reconcile_grader_lanes,
)
from .attorney_workflow import _verify_generation_capsules_for_initialization

_CASE_PATH = V21_CASE_PATH
_BUILD_PATH = V21_BUILD_PATH
_RUBRIC_PATH = V21_RUBRIC_PATH
_BASELINE_PATH = V21_BASELINE_PATH
_REFEREE_AGGREGATE_PATH = V21_REFEREE_AGGREGATE_PATH
_RESULT_PATH = V21_RESULT_PATH


@runtime_checkable
class AttorneyEvaluatorV21(Protocol):
    """A provider that supplies one independently-created answer per request."""

    async def evaluate(self, request: EvaluatorRequestV21) -> EvaluatorResponseV21: ...


@dataclass(frozen=True)
class GuardedSubmissionResultV21:
    """Public-safe write-free preflight result and optional committed state."""

    accepted: bool
    preflight: V21ResponsePreflight
    state: EvaluationRunStateV21 | None = None


@dataclass(frozen=True)
class _GradeStep:
    operation: EvaluatorOperationV21
    label: Literal["A", "B"]
    lane: Literal[1, 2]
    batch: OrdinaryGradeBatchV21 | None = None
    contested_id: str | None = None


def _model_bytes(value: BaseModel) -> bytes:
    return canonical_json_bytes(value.model_dump(mode="json", warnings="error"))


def _request_path(call_id: str) -> str:
    return f"requests/{call_id}.json"


def _response_path(call_id: str) -> str:
    return f"responses/{call_id}.json"


def _labels(envelope: CaseEnvelope) -> tuple[Literal["A", "B"], ...]:
    labels = tuple(item.anonymous_label for item in envelope.assignments)
    if labels not in (("A",), ("A", "B")):
        raise EvaluationIntegrityError("EVALUATOR_V21_CASE_BUILD_BINDING")
    return cast(tuple[Literal["A", "B"], ...], labels)


def _state(manifest: EvaluationManifestV21) -> EvaluationRunStateV21:
    pending = tuple(call for call in manifest.calls if call.state == "pending")
    if len(pending) > 1:
        raise EvaluationIntegrityError("EVALUATOR_V21_PENDING_CALL")
    return EvaluationRunStateV21(
        case_fingerprint=manifest.case_fingerprint,
        phase=manifest.phase,
        current_call_id=pending[0].call_id if pending else None,
        terminal_status=manifest.terminal_status,
        manifest_fingerprint=manifest.manifest_fingerprint,
    )


def _call_id(step: _GradeStep) -> str:
    if step.operation is EvaluatorOperationV21.ORDINARY_GRADE_FRAGMENT:
        assert step.batch is not None
        return f"grade-{step.label}-lane{step.lane}-batch{step.batch.batch_ref[-4:]}"
    assert step.contested_id is not None
    return f"grade-{step.label}-lane{step.lane}-contested-{step.contested_id}"


def _pending_call(
    call_id: str,
    request: EvaluatorRequestV21,
    *,
    label: Literal["A", "B"] | None = None,
    lane: Literal[1, 2] | None = None,
    dispute_id: str | None = None,
    batch: OrdinaryGradeBatchV21 | None = None,
    contested_id: str | None = None,
    inventory: tuple[OrdinaryGradeBatchV21, ...] = (),
    contested: tuple[ContestedRequirementV21, ...] = (),
) -> EvaluationCallRecordV21:
    payload: dict[str, object] = {
        "call_id": call_id,
        "operation": request.operation,
        "state": "pending",
        "attempt": 1,
        "request_artifact_path": _request_path(call_id),
        "request_fingerprint": request.request_fingerprint,
        "anonymous_label": label,
        "grader_lane": lane,
        "dispute_id": dispute_id,
        "batch_ref": None if batch is None else batch.batch_ref,
        "contested_requirement_id": contested_id,
    }
    return EvaluationCallRecordV21.validate_for_inventories(payload, inventory, contested)


def _accepted_call(
    call: EvaluationCallRecordV21,
    response: EvaluatorResponseV21,
    inventory: tuple[OrdinaryGradeBatchV21, ...] = (),
    contested: tuple[ContestedRequirementV21, ...] = (),
) -> EvaluationCallRecordV21:
    return EvaluationCallRecordV21.validate_for_inventories(
        {
            **call.model_dump(mode="json"),
            "state": "accepted",
            "response_artifact_path": _response_path(call.call_id),
            "response_fingerprint": sha256_digest(_model_bytes(response)),
            "provider_name": response.provider_name,
            "model_name": response.model_name,
            "judge_isolation": response.judge_isolation,
        },
        inventory,
        contested,
    )


def _manifest(
    prior: EvaluationManifestV21,
    *,
    calls: tuple[EvaluationCallRecordV21, ...],
    phase: EvaluationPhaseV21,
    baseline: CanonicalBaselineV21 | None = None,
    referee_fingerprint: str | None = None,
    aggregate_fingerprints: tuple[str, ...] = (),
    sensitivity_fingerprints: tuple[str, ...] = (),
    result_hash: str | None = None,
    terminal_status: EvaluationTerminalStatusV21 | None = None,
    disputes: tuple[RefereeDisputeV21, ...] | None = None,
    batches: tuple[OrdinaryGradeBatchV21, ...] | None = None,
) -> EvaluationManifestV21:
    data = prior.model_dump(mode="json")
    data.update(
        {
            "calls": calls,
            "phase": phase,
            "baseline_fingerprint": None if baseline is None else baseline.baseline_fingerprint,
            "referee_aggregate_fingerprint": referee_fingerprint,
            "grader_aggregate_fingerprints": aggregate_fingerprints,
            "sensitivity_fingerprints": sensitivity_fingerprints,
            "result_hash": result_hash,
            "terminal_status": terminal_status,
            "referee_disputes": prior.referee_disputes if disputes is None else disputes,
            "ordinary_grade_batches": prior.ordinary_grade_batches if batches is None else batches,
            "artifacts": (),
            "manifest_fingerprint": "0" * 64,
        }
    )
    return EvaluationManifestV21.model_validate(
        data,
        context={
            "ordinary_grade_batches": data["ordinary_grade_batches"],
            "contested_requirements": () if baseline is None else baseline.contested_requirements,
        },
    )


def _response(run_dir: Path, call: EvaluationCallRecordV21) -> EvaluatorResponseV21:
    if call.response_artifact_path is None:
        raise EvaluationIntegrityError("EVALUATOR_V21_ACCEPTED_RESPONSE")
    return EvaluatorResponseV21.model_validate_json(
        read_evaluation_artifact(run_dir, call.response_artifact_path)
    )


def _accepted_response(
    run_dir: Path, manifest: EvaluationManifestV21, operation: EvaluatorOperationV21
) -> EvaluatorResponseV21:
    matches = tuple(
        call for call in manifest.calls if call.operation is operation and call.state == "accepted"
    )
    if len(matches) != 1:
        raise EvaluationIntegrityError("EVALUATOR_V21_ACCEPTED_RESPONSE")
    return _response(run_dir, matches[0])


def _review(run_dir: Path, manifest: EvaluationManifestV21) -> SourceReviewV21:
    return SourceReviewV21.model_validate(
        _accepted_response(run_dir, manifest, EvaluatorOperationV21.SOURCE_REVIEW).payload
    )


def _audit(
    run_dir: Path, manifest: EvaluationManifestV21, review: SourceReviewV21
) -> SourceAuditV21:
    response = _accepted_response(run_dir, manifest, EvaluatorOperationV21.SOURCE_AUDIT)
    request = next(
        call for call in manifest.calls if call.operation is EvaluatorOperationV21.SOURCE_AUDIT
    )
    source_request = EvaluatorRequestV21.model_validate_json(
        read_evaluation_artifact(run_dir, request.request_artifact_path)
    )
    indexed = source_request.payload.get("indexed_proposals")
    if not isinstance(indexed, list):
        raise EvaluationIntegrityError("EVALUATOR_V21_ACCEPTED_RESPONSE")
    from .attorney_v2_models import IndexedProposalV2

    return SourceAuditV21.validate_for_indexed_proposals(
        response.payload, tuple(IndexedProposalV2.model_validate(item) for item in indexed)
    )


def _grade_steps(
    baseline: CanonicalBaselineV21, labels: tuple[Literal["A", "B"], ...]
) -> tuple[_GradeStep, ...]:
    return tuple(
        step
        for label in labels
        for lane in cast(tuple[Literal[1, 2], ...], (1, 2))
        for step in (
            *(
                _GradeStep(
                    EvaluatorOperationV21.ORDINARY_GRADE_FRAGMENT,
                    label,
                    lane,
                    batch=batch,
                )
                for batch in ordinary_grade_batches(baseline, label, lane)
            ),
            *(
                _GradeStep(
                    EvaluatorOperationV21.CONTESTED_GRADE_FRAGMENT,
                    label,
                    lane,
                    contested_id=item.contested_requirement_id,
                )
                for item in baseline.contested_requirements
            ),
        )
    )


def _batch_inventory(
    baseline: CanonicalBaselineV21, labels: tuple[Literal["A", "B"], ...]
) -> tuple[OrdinaryGradeBatchV21, ...]:
    return tuple(
        batch
        for label in labels
        for lane in cast(tuple[Literal[1, 2], ...], (1, 2))
        for batch in ordinary_grade_batches(baseline, label, lane)
    )


def _grade_request(context: VerifiedV21Context, step: _GradeStep) -> EvaluatorRequestV21:
    baseline = context.baseline
    if baseline is None:
        raise EvaluationIntegrityError("EVALUATOR_V21_BASELINE_MISSING")
    envelope = context.load_case_envelope()
    report_text = next(
        candidate.report_text
        for candidate in envelope.case.candidates
        if candidate.candidate_id
        == next(
            assignment.candidate_id
            for assignment in envelope.assignments
            if assignment.anonymous_label == step.label
        )
    )
    source_context: dict[str, object] = dict(context.source_context)
    if step.operation is EvaluatorOperationV21.ORDINARY_GRADE_FRAGMENT:
        assert step.batch is not None
        return build_ordinary_grade_request_v21(
            baseline, step.batch, step.label, step.lane, report_text, source_context, context.rubric
        )
    contested = next(
        item
        for item in baseline.contested_requirements
        if item.contested_requirement_id == step.contested_id
    )
    return build_contested_grade_request_v21(
        baseline, contested, step.label, step.lane, report_text, source_context, context.rubric
    )


def _next_grade_call(
    context: VerifiedV21Context, step: _GradeStep, inventory: tuple[OrdinaryGradeBatchV21, ...]
) -> tuple[EvaluationCallRecordV21, EvaluatorRequestV21]:
    request = _grade_request(context, step)
    return (
        _pending_call(
            _call_id(step),
            request,
            label=step.label,
            lane=step.lane,
            batch=step.batch,
            contested_id=step.contested_id,
            inventory=inventory,
            contested=() if context.baseline is None else context.baseline.contested_requirements,
        ),
        request,
    )


def _accepted_grade_fragments(
    run_dir: Path,
    manifest: EvaluationManifestV21,
    response: EvaluatorResponseV21 | None = None,
    pending: EvaluationCallRecordV21 | None = None,
) -> dict[str, OrdinaryGradeFragmentV21 | ContestedGradeFragmentV21]:
    from .attorney_v21_rubric import validate_grade_fragment_v21

    context = load_verified_v21_context(run_dir)
    if context.baseline is None:
        raise EvaluationIntegrityError("EVALUATOR_V21_BASELINE_MISSING")
    envelope = context.load_case_envelope()
    fragments: dict[str, OrdinaryGradeFragmentV21 | ContestedGradeFragmentV21] = {}
    for call in manifest.calls:
        if call.state != "accepted" or call.operation not in {
            EvaluatorOperationV21.ORDINARY_GRADE_FRAGMENT,
            EvaluatorOperationV21.CONTESTED_GRADE_FRAGMENT,
        }:
            continue
        report = next(
            candidate.report_text
            for candidate in envelope.case.candidates
            if candidate.candidate_id
            == next(
                a.candidate_id
                for a in envelope.assignments
                if a.anonymous_label == call.anonymous_label
            )
        )
        fragments[call.call_id] = validate_grade_fragment_v21(
            context.baseline, _response(run_dir, call).payload, report
        )
    if response is not None and pending is not None:
        report = next(
            candidate.report_text
            for candidate in envelope.case.candidates
            if candidate.candidate_id
            == next(
                a.candidate_id
                for a in envelope.assignments
                if a.anonymous_label == pending.anonymous_label
            )
        )
        fragments[pending.call_id] = validate_grade_fragment_v21(
            context.baseline, response.payload, report
        )
    return fragments


def _artifacts_for_grades(
    run_dir: Path,
    manifest: EvaluationManifestV21,
    response: EvaluatorResponseV21,
    pending: EvaluationCallRecordV21,
    baseline: CanonicalBaselineV21,
    labels: tuple[Literal["A", "B"], ...],
    rubric: BaseModel,
) -> tuple[dict[str, bytes], tuple[str, ...], tuple[str, ...], tuple[ReportResultV21, ...]]:
    fragments = _accepted_grade_fragments(run_dir, manifest, response, pending)
    files: dict[str, bytes] = {}
    aggregate_fingerprints: list[str] = []
    sensitivity_fingerprints: list[str] = []
    reports: list[ReportResultV21] = []
    for label in labels:
        aggregates: list[GraderAggregateV21] = []
        for lane in cast(tuple[Literal[1, 2], ...], (1, 2)):
            ordinary_calls = [
                call
                for call in manifest.calls
                if call.operation is EvaluatorOperationV21.ORDINARY_GRADE_FRAGMENT
                and call.anonymous_label == label
                and call.grader_lane == lane
            ]
            contested_calls = [
                call
                for call in manifest.calls
                if call.operation is EvaluatorOperationV21.CONTESTED_GRADE_FRAGMENT
                and call.anonymous_label == label
                and call.grader_lane == lane
            ]
            expected_ordinary = ordinary_grade_batches(baseline, label, lane)
            expected_contested = tuple(
                item.contested_requirement_id for item in baseline.contested_requirements
            )
            ordinary_ids = tuple(call.batch_ref for call in ordinary_calls)
            contested_ids = tuple(call.contested_requirement_id for call in contested_calls)
            complete = (
                ordinary_ids == tuple(item.batch_ref for item in expected_ordinary)
                and contested_ids == expected_contested
                and all(call.call_id in fragments for call in (*ordinary_calls, *contested_calls))
            )
            if complete:
                aggregate = aggregate_grader_lane(
                    baseline,
                    label,
                    lane,
                    tuple(
                        cast(OrdinaryGradeFragmentV21, fragments[call.call_id])
                        for call in ordinary_calls
                    ),
                    tuple(
                        cast(ContestedGradeFragmentV21, fragments[call.call_id])
                        for call in contested_calls
                    ),
                )
                files[f"aggregates/grade-{label}-{lane}.json"] = _model_bytes(aggregate)
                aggregate_fingerprints.append(aggregate.aggregate_fingerprint)
                aggregates.append(aggregate)
        if len(aggregates) == 2:
            reconciliation = reconcile_grader_lanes(
                baseline, aggregates[0], aggregates[1], cast(Any, rubric)
            )
            sensitivity = evaluate_outcome_sensitivity(baseline, reconciliation, cast(Any, rubric))
            files[f"sensitivities/{label}.json"] = _model_bytes(sensitivity)
            sensitivity_fingerprints.append(sensitivity.sensitivity_fingerprint)
            payload = {
                "anonymous_label": label,
                "reconciliation": reconciliation.model_dump(mode="json"),
                "sensitivity": sensitivity.model_dump(mode="json"),
            }
            reports.append(
                ReportResultV21(
                    anonymous_label=label,
                    reconciliation=reconciliation,
                    sensitivity=sensitivity,
                    result_fingerprint=sha256_digest(canonical_json_bytes(payload)),
                )
            )
    return files, tuple(aggregate_fingerprints), tuple(sensitivity_fingerprints), tuple(reports)


def _comparison(reports: tuple[ReportResultV21, ...]) -> ComparisonResultV2 | None:
    if len(reports) == 1:
        return None
    first, second = reports
    if any(
        report.sensitivity.absolute_disposition is AbsoluteDispositionV2.INCONCLUSIVE
        for report in reports
    ):
        return ComparisonResultV2(
            disposition=ComparisonDispositionV2.INCONCLUSIVE,
            rationale="At least one report is inconclusive.",
        )
    if (
        first.sensitivity.absolute_disposition is AbsoluteDispositionV2.PASS
        and second.sensitivity.absolute_disposition is AbsoluteDispositionV2.FAIL
    ):
        return ComparisonResultV2(
            disposition=ComparisonDispositionV2.CANDIDATE_WIN,
            winner_label="A",
            rationale="Only the candidate report passed the rubric.",
        )
    if (
        first.sensitivity.absolute_disposition is AbsoluteDispositionV2.FAIL
        and second.sensitivity.absolute_disposition is AbsoluteDispositionV2.PASS
    ):
        return ComparisonResultV2(
            disposition=ComparisonDispositionV2.COMPARATOR_WIN,
            winner_label="B",
            rationale="Only the comparator report passed the rubric.",
        )
    if first.sensitivity.absolute_disposition is AbsoluteDispositionV2.FAIL:
        return ComparisonResultV2(
            disposition=ComparisonDispositionV2.NEITHER,
            rationale="Neither report passed the rubric.",
        )
    return ComparisonResultV2(
        disposition=ComparisonDispositionV2.TIE, rationale="Both reports passed the rubric."
    )


def _result(
    baseline: CanonicalBaselineV21, rubric: BaseModel, reports: tuple[ReportResultV21, ...]
) -> EvaluationResultV21:
    terminal = (
        EvaluationTerminalStatusV21.INCONCLUSIVE
        if any(
            item.sensitivity.absolute_disposition is AbsoluteDispositionV2.INCONCLUSIVE
            for item in reports
        )
        else EvaluationTerminalStatusV21.COMPLETED
    )
    comparison = _comparison(reports)
    payload = {
        "schema_version": "2.1",
        "rubric": rubric.model_dump(mode="json"),
        "baseline": baseline.model_dump(mode="json"),
        "reports": [item.model_dump(mode="json") for item in reports],
        "comparison": None if comparison is None else comparison.model_dump(mode="json"),
        "terminal_status": terminal.value,
    }
    return EvaluationResultV21(
        schema_version="2.1",
        rubric=cast(Any, rubric),
        baseline=baseline,
        reports=reports,
        comparison=comparison,
        terminal_status=terminal,
        result_fingerprint=sha256_digest(canonical_json_bytes(payload)),
    )


def initialize_evaluation_v21(
    case: AttorneyEvaluationCase,
    output_dir: Path,
    *,
    seed_hex: str,
    generation_capsule_paths: Mapping[str, Path] | None = None,
) -> EvaluationRunStateV21:
    """Freeze a new case and issue exactly its source-review packet."""
    strict_case = AttorneyEvaluationCase.model_validate(case.model_dump(mode="json"))
    if strict_case.schema_version != "1.1":
        raise ValueError("case schema 1.1 is required for new evaluation runs")
    _verify_generation_capsules_for_initialization(strict_case, generation_capsule_paths)
    envelope = freeze_case(strict_case, seed_hex=seed_hex)
    request = build_source_review_request_v21(envelope)
    call = _pending_call("source-review", request)
    case_bytes = _model_bytes(envelope)
    build_bytes = canonical_json_bytes(
        {"protocol_version": "2.1", "compiler_version": "semantic-compiler-v2.1"}
    )
    rubric_bytes = _model_bytes(RUBRIC_V21)
    manifest = EvaluationManifestV21(
        case_fingerprint=envelope.case_fingerprint,
        case_envelope_hash=sha256_digest(case_bytes),
        build_fingerprint=sha256_digest(build_bytes),
        rubric_fingerprint=sha256_digest(rubric_bytes),
        compiler_version="semantic-compiler-v2.1",
        phase=EvaluationPhaseV21.SOURCE_REVIEW,
        calls=(call,),
        artifacts=(),
        referee_disputes=(),
        ordinary_grade_batches=(),
        manifest_fingerprint="0" * 64,
    )
    committed = initialize_v21_run_storage(
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


def resume_evaluation_v21(run_dir: Path) -> EvaluationRunStateV21:
    return _state(load_verified_v21_context(run_dir).manifest)


def next_evaluator_request_v21(run_dir: Path) -> EvaluatorRequestV21 | None:
    context = load_verified_v21_context(run_dir)
    pending = tuple(call for call in context.manifest.calls if call.state == "pending")
    if context.manifest.terminal_status is not None:
        return None
    if len(pending) != 1:
        raise EvaluationIntegrityError("EVALUATOR_V21_PENDING_CALL")
    return EvaluatorRequestV21.model_validate_json(
        read_evaluation_artifact(run_dir, pending[0].request_artifact_path)
    )


def preflight_evaluator_response_v21(run_dir: Path, response: object) -> V21ResponsePreflight:
    context = load_verified_v21_context(run_dir)
    pending = tuple(call for call in context.manifest.calls if call.state == "pending")
    if len(pending) != 1 or context.manifest.terminal_status is not None:
        return V21ResponsePreflight(False, ("MECHANICAL_RESPONSE_INVALID",))
    return preflight_v21_response(run_dir, pending[0].call_id, response)


def _advance(
    run_dir: Path, context: VerifiedV21Context, response: EvaluatorResponseV21
) -> EvaluationRunStateV21:
    manifest = context.manifest
    pending_calls = tuple(call for call in manifest.calls if call.state == "pending")
    if len(pending_calls) != 1:
        raise EvaluationIntegrityError("EVALUATOR_V21_PENDING_CALL")
    pending = pending_calls[0]
    accepted = _accepted_call(
        pending,
        response,
        manifest.ordinary_grade_batches,
        () if context.baseline is None else context.baseline.contested_requirements,
    )
    calls = (*tuple(call for call in manifest.calls if call.state == "accepted"), accepted)
    files: dict[str, bytes] = {_response_path(pending.call_id): _model_bytes(response)}
    envelope = context.load_case_envelope()

    if pending.operation is EvaluatorOperationV21.SOURCE_REVIEW:
        review = SourceReviewV21.model_validate(response.payload)
        request = build_source_audit_request_v21(envelope, review)
        call = _pending_call("source-audit", request)
        calls += (call,)
        files[call.request_artifact_path] = _model_bytes(request)
        successor = _manifest(manifest, calls=calls, phase=EvaluationPhaseV21.SOURCE_AUDIT)
    elif pending.operation is EvaluatorOperationV21.SOURCE_AUDIT:
        review = _review(run_dir, manifest)
        source_request = EvaluatorRequestV21.model_validate_json(
            read_evaluation_artifact(run_dir, pending.request_artifact_path)
        )
        raw_indexed = source_request.payload.get("indexed_proposals")
        if not isinstance(raw_indexed, list):
            raise EvaluationIntegrityError("EVALUATOR_V21_ACCEPTED_RESPONSE")
        from .attorney_v2_models import IndexedProposalV2

        audit = SourceAuditV21.validate_for_indexed_proposals(
            response.payload,
            tuple(IndexedProposalV2.model_validate(item) for item in raw_indexed),
        )
        disputes = build_referee_disputes(envelope, review, audit)
        if disputes:
            request = build_source_referee_fragment_request(
                envelope, disputes[0], controller_disputes=disputes
            )
            call = _pending_call(
                "source-referee-" + disputes[0].dispute_id,
                request,
                dispute_id=disputes[0].dispute_id,
            )
            calls += (call,)
            files[call.request_artifact_path] = _model_bytes(request)
            successor = _manifest(
                manifest, calls=calls, phase=EvaluationPhaseV21.SOURCE_REFEREE, disputes=disputes
            )
        else:
            aggregate = aggregate_referee_decisions((), ())
            baseline = compile_baseline_v21(envelope, review, audit, aggregate)
            labels = _labels(envelope)
            inventory = _batch_inventory(baseline, labels)
            steps = _grade_steps(baseline, labels)
            if not steps:
                raise EvaluationIntegrityError("EVALUATOR_V21_GRADE_FRAGMENT_COVERAGE")
            sealed_context = VerifiedV21Context(
                manifest,
                None,
                context.case_envelope_bytes,
                context.rubric,
                baseline,
                context.source_context,
            )
            call, request = _next_grade_call(sealed_context, steps[0], inventory)
            calls += (call,)
            files.update(
                {
                    _REFEREE_AGGREGATE_PATH: _model_bytes(aggregate),
                    _BASELINE_PATH: _model_bytes(baseline),
                    call.request_artifact_path: _model_bytes(request),
                }
            )
            phase = (
                EvaluationPhaseV21.ORDINARY_GRADING
                if steps[0].operation is EvaluatorOperationV21.ORDINARY_GRADE_FRAGMENT
                else EvaluationPhaseV21.CONTESTED_GRADING
            )
            successor = _manifest(
                manifest,
                calls=calls,
                phase=phase,
                baseline=baseline,
                referee_fingerprint=aggregate.aggregate_fingerprint,
                batches=inventory,
            )
    elif pending.operation is EvaluatorOperationV21.SOURCE_REFEREE_FRAGMENT:
        review = _review(run_dir, manifest)
        audit = _audit(run_dir, manifest, review)
        fragments = []
        for call in manifest.calls:
            if (
                call.operation is EvaluatorOperationV21.SOURCE_REFEREE_FRAGMENT
                and call.state == "accepted"
            ):
                dispute = next(
                    item for item in manifest.referee_disputes if item.dispute_id == call.dispute_id
                )
                prior_response = _response(run_dir, call)
                fragments.append(
                    validate_referee_fragment(
                        dispute,
                        prior_response.payload,
                        response_fingerprint=sha256_digest(_model_bytes(prior_response)),
                    )
                )
        dispute = next(
            item for item in manifest.referee_disputes if item.dispute_id == pending.dispute_id
        )
        fragments.append(
            validate_referee_fragment(
                dispute,
                response.payload,
                response_fingerprint=sha256_digest(_model_bytes(response)),
            )
        )
        if len(fragments) < len(manifest.referee_disputes):
            next_dispute = manifest.referee_disputes[len(fragments)]
            request = build_source_referee_fragment_request(
                envelope, next_dispute, controller_disputes=manifest.referee_disputes
            )
            call = _pending_call(
                "source-referee-" + next_dispute.dispute_id,
                request,
                dispute_id=next_dispute.dispute_id,
            )
            calls += (call,)
            files[call.request_artifact_path] = _model_bytes(request)
            successor = _manifest(
                manifest,
                calls=calls,
                phase=EvaluationPhaseV21.SOURCE_REFEREE,
                disputes=manifest.referee_disputes,
            )
        else:
            aggregate = aggregate_referee_decisions(manifest.referee_disputes, tuple(fragments))
            baseline = compile_baseline_v21(envelope, review, audit, aggregate)
            labels = _labels(envelope)
            inventory = _batch_inventory(baseline, labels)
            steps = _grade_steps(baseline, labels)
            if not steps:
                raise EvaluationIntegrityError("EVALUATOR_V21_GRADE_FRAGMENT_COVERAGE")
            sealed_context = VerifiedV21Context(
                manifest,
                None,
                context.case_envelope_bytes,
                context.rubric,
                baseline,
                context.source_context,
            )
            call, request = _next_grade_call(sealed_context, steps[0], inventory)
            calls += (call,)
            files.update(
                {
                    _REFEREE_AGGREGATE_PATH: _model_bytes(aggregate),
                    _BASELINE_PATH: _model_bytes(baseline),
                    call.request_artifact_path: _model_bytes(request),
                }
            )
            phase = (
                EvaluationPhaseV21.ORDINARY_GRADING
                if steps[0].operation is EvaluatorOperationV21.ORDINARY_GRADE_FRAGMENT
                else EvaluationPhaseV21.CONTESTED_GRADING
            )
            successor = _manifest(
                manifest,
                calls=calls,
                phase=phase,
                baseline=baseline,
                referee_fingerprint=aggregate.aggregate_fingerprint,
                batches=inventory,
            )
    else:
        active_baseline = context.baseline
        if active_baseline is None:
            raise EvaluationIntegrityError("EVALUATOR_V21_BASELINE_MISSING")
        labels = _labels(envelope)
        grade_files, aggregate_fingerprints, sensitivity_fingerprints, reports = (
            _artifacts_for_grades(
                run_dir, manifest, response, pending, active_baseline, labels, context.rubric
            )
        )
        files.update(grade_files)
        all_steps = _grade_steps(active_baseline, labels)
        accepted_grade_count = (
            sum(
                call.operation
                in {
                    EvaluatorOperationV21.ORDINARY_GRADE_FRAGMENT,
                    EvaluatorOperationV21.CONTESTED_GRADE_FRAGMENT,
                }
                and call.state == "accepted"
                for call in manifest.calls
            )
            + 1
        )
        if accepted_grade_count < len(all_steps):
            next_step = all_steps[accepted_grade_count]
            call, request = _next_grade_call(context, next_step, manifest.ordinary_grade_batches)
            calls += (call,)
            files[call.request_artifact_path] = _model_bytes(request)
            phase = (
                EvaluationPhaseV21.ORDINARY_GRADING
                if next_step.operation is EvaluatorOperationV21.ORDINARY_GRADE_FRAGMENT
                else EvaluationPhaseV21.CONTESTED_GRADING
            )
            successor = _manifest(
                manifest,
                calls=calls,
                phase=phase,
                baseline=active_baseline,
                referee_fingerprint=manifest.referee_aggregate_fingerprint,
                aggregate_fingerprints=aggregate_fingerprints,
                sensitivity_fingerprints=sensitivity_fingerprints,
            )
        else:
            result = _result(active_baseline, context.rubric, reports)
            files[_RESULT_PATH] = _model_bytes(result)
            phase = (
                EvaluationPhaseV21.INCONCLUSIVE
                if result.terminal_status is EvaluationTerminalStatusV21.INCONCLUSIVE
                else EvaluationPhaseV21.COMPLETED
            )
            successor = _manifest(
                manifest,
                calls=calls,
                phase=phase,
                baseline=active_baseline,
                referee_fingerprint=manifest.referee_aggregate_fingerprint,
                aggregate_fingerprints=aggregate_fingerprints,
                sensitivity_fingerprints=sensitivity_fingerprints,
                result_hash=result.result_fingerprint,
                terminal_status=result.terminal_status,
            )
    commit_v21_transition(run_dir, manifest.manifest_fingerprint, files, successor)
    return resume_evaluation_v21(run_dir)


def guarded_submit_evaluator_response_v21(
    run_dir: Path, response: object
) -> GuardedSubmissionResultV21:
    preflight = preflight_evaluator_response_v21(run_dir, response)
    if not preflight.valid:
        return GuardedSubmissionResultV21(False, preflight)
    try:
        context = load_verified_v21_context(run_dir)
        return GuardedSubmissionResultV21(
            True, preflight, _advance(run_dir, context, validate_evaluator_response_v21(response))
        )
    except (EvaluationIntegrityError, TypeError, ValueError, json.JSONDecodeError):
        return GuardedSubmissionResultV21(
            False, V21ResponsePreflight(False, ("MECHANICAL_RESPONSE_INVALID",))
        )


def submit_evaluator_response_v21(run_dir: Path, response: object) -> EvaluationRunStateV21:
    result = guarded_submit_evaluator_response_v21(run_dir, response)
    if not result.accepted or result.state is None:
        raise ValueError("MECHANICAL_RESPONSE_INVALID")
    return result.state


def stop_evaluation_v21_inconclusive(
    run_dir: Path, reason: Literal["MECHANICAL_RESPONSE_INVALID"]
) -> EvaluationRunStateV21:
    if reason != "MECHANICAL_RESPONSE_INVALID":
        raise ValueError("unsupported inconclusive reason")
    context = load_verified_v21_context(run_dir)
    manifest = context.manifest
    pending = tuple(call for call in manifest.calls if call.state == "pending")
    if len(pending) != 1:
        raise EvaluationIntegrityError("EVALUATOR_V21_PENDING_CALL")
    accepted = tuple(call for call in manifest.calls if call.state == "accepted")
    request = next_evaluator_request_v21(run_dir)
    if request is None:
        raise EvaluationIntegrityError("EVALUATOR_V21_PENDING_CALL")
    successor = _manifest(
        manifest,
        calls=accepted,
        phase=EvaluationPhaseV21.INCONCLUSIVE_MECHANICAL,
        baseline=context.baseline,
        referee_fingerprint=manifest.referee_aggregate_fingerprint,
        aggregate_fingerprints=manifest.grader_aggregate_fingerprints,
        sensitivity_fingerprints=manifest.sensitivity_fingerprints,
        disputes=manifest.referee_disputes,
        batches=manifest.ordinary_grade_batches,
        terminal_status=EvaluationTerminalStatusV21.INCONCLUSIVE_MECHANICAL,
    )
    commit_v21_transition(
        run_dir,
        manifest.manifest_fingerprint,
        {"terminal-reason.json": canonical_json_bytes({"reason": reason})},
        successor,
    )
    return resume_evaluation_v21(run_dir)


async def run_evaluation_v21(
    case: AttorneyEvaluationCase,
    evaluator: AttorneyEvaluatorV21,
    output_dir: Path,
    *,
    seed_hex: str,
    generation_capsule_paths: Mapping[str, Path] | None = None,
) -> EvaluationResultV21:
    if not isinstance(evaluator, AttorneyEvaluatorV21):
        raise TypeError("evaluator must implement AttorneyEvaluatorV21")
    state = initialize_evaluation_v21(
        case, output_dir, seed_hex=seed_hex, generation_capsule_paths=generation_capsule_paths
    )
    while state.terminal_status is None:
        request = next_evaluator_request_v21(output_dir)
        if request is None:
            raise EvaluationIntegrityError("EVALUATOR_V21_PENDING_CALL")
        first = await evaluator.evaluate(request)
        guarded = guarded_submit_evaluator_response_v21(output_dir, first)
        if not guarded.accepted:
            retry = (
                mechanical_retry_request_v21(
                    request, expected_request_fingerprint=request.request_fingerprint
                )
                if request.operation
                in {
                    EvaluatorOperationV21.SOURCE_REVIEW,
                    EvaluatorOperationV21.SOURCE_AUDIT,
                    EvaluatorOperationV21.SOURCE_REFEREE_FRAGMENT,
                }
                else request
            )
            second = await evaluator.evaluate(retry)
            guarded = guarded_submit_evaluator_response_v21(output_dir, second)
            if not guarded.accepted:
                state = stop_evaluation_v21_inconclusive(output_dir, "MECHANICAL_RESPONSE_INVALID")
                break
        assert guarded.state is not None
        state = guarded.state
    completed = load_verified_v21_context(output_dir)
    if completed.result is None:
        raise EvaluationIntegrityError("EVALUATOR_V21_INCONCLUSIVE")
    return completed.result
