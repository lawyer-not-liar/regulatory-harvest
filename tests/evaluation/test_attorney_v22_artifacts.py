"""Protocol 2.2 artifact storage and replay contracts."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, replace
from datetime import date
from pathlib import Path
from typing import Literal, cast

import pytest

from regulatory_harvest.evaluation import attorney_artifacts as shared_artifacts
from regulatory_harvest.evaluation import attorney_v22_artifacts as v22_artifacts
from regulatory_harvest.evaluation.attorney_admission import freeze_case
from regulatory_harvest.evaluation.attorney_artifacts import EvaluationIntegrityError
from regulatory_harvest.evaluation.attorney_models import (
    AttorneyEvaluationCase,
    BlindAssignment,
    CandidateReport,
    CandidateRole,
    CaseEnvelope,
    EvaluationMode,
    EvaluationSource,
    RequestedAuthority,
    model_fingerprint,
)
from regulatory_harvest.evaluation.attorney_protocol import detect_evaluation_protocol
from regulatory_harvest.evaluation.attorney_v2_models import (
    AbsoluteDispositionV2,
    ComparisonDispositionV2,
)
from regulatory_harvest.evaluation.attorney_v22_artifacts import (
    commit_v22_transition,
    initialize_v22_run_storage,
    load_verified_v22_run,
    verify_v22_run,
)
from regulatory_harvest.evaluation.attorney_v22_compiler import (
    RUBRIC_V22,
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
from regulatory_harvest.evaluation.attorney_v22_models import (
    AcceptedSourceAuditFragmentV22,
    AcceptedSourceReviewFragmentV22,
    ComparisonResultV22,
    EvaluationCallRecordV22,
    EvaluationManifestV22,
    EvaluationPhaseV22,
    EvaluationResultV22,
    EvaluationTerminalStatusV22,
    EvaluatorOperationV22,
    EvaluatorRequestV22,
    EvaluatorResponseV22,
    GraderAggregateV22,
    ReportResultV22,
    SensitivityRecordV22,
    SourceAuditFragmentV22,
    SourceReviewFragmentV22,
)
from regulatory_harvest.evaluation.attorney_v22_requests import (
    COMPILER_CONTRACT_FINGERPRINT_V22,
    build_contested_grade_request_v22,
    build_ordinary_grade_request_v22,
    build_source_audit_fragment_request_v22,
    build_source_referee_fragment_request_v22,
    build_source_review_fragment_request_v22,
)
from regulatory_harvest.models import SourceQuality, SourceRole
from regulatory_harvest.storage import canonical_json_bytes, sha256_digest


@dataclass(frozen=True)
class _Lifecycle:
    manifest: EvaluationManifestV22
    files: dict[str, bytes]
    result: EvaluationResultV22
    review_end: int
    audit_end: int
    referee_end: int


def _proposal(statement: str, quote: str, *, kind: str = "obligation") -> dict[str, object]:
    return {
        "statement": statement,
        "kind": kind,
        "importance": "critical",
        "passages": [{"source_id": "rule-1", "quote": quote}],
        "dependency": None,
        "confidence": "clear",
        "rationale": "The source states the proposition.",
    }


def _lifecycle_envelope(
    *, comparator: bool = False, seed_hex: str = "f" * 64
) -> CaseEnvelope:
    source_text = (
        "Rule 1: operators must file. "
        "Rule 2: operators must retain records. "
        "Rule 3: small operators are excluded."
    )
    report_text = "Operators must file. Operators must retain records."
    source = EvaluationSource(
        source_id="rule-1",
        title="Example Rule",
        normalized_text=source_text,
        content_hash=sha256_digest(source_text.encode()),
        jurisdiction="Example State",
        authority_type="regulation",
        source_role=SourceRole.OFFICIAL_PRIMARY,
        source_quality=SourceQuality.PRIMARY,
        completeness="complete",
        language="en",
    )
    candidate = CandidateReport(
        candidate_id="candidate",
        role=CandidateRole.CANDIDATE,
        report_text=report_text,
        report_hash=sha256_digest(report_text.encode()),
    )
    comparator_report = CandidateReport(
        candidate_id="comparator",
        role=CandidateRole.COMPARATOR,
        report_text=report_text,
        report_hash=sha256_digest(report_text.encode()),
    )
    case = AttorneyEvaluationCase(
        case_id="v22-lifecycle-case",
        mode=EvaluationMode.CLOSED_UNIVERSE,
        question="What must operators do?",
        jurisdiction="Example State",
        as_of=date(2026, 8, 20),
        requested_authorities=[
            RequestedAuthority(
                authority_id="example-rule",
                title="Example Rule",
                jurisdiction="Example State",
                authority_type="regulation",
                source_ids=[source.source_id],
            )
        ],
        sources=[source],
        candidates=[candidate, comparator_report] if comparator else [candidate],
    )
    return freeze_case(case, seed_hex=seed_hex)


def _response(request: EvaluatorRequestV22, payload: object) -> tuple[EvaluatorResponseV22, bytes]:
    wire_payload = (
        cast(object, payload).model_dump(mode="json") if hasattr(payload, "model_dump") else payload
    )
    response = EvaluatorResponseV22.model_validate(
        {
            "schema_version": "2.2",
            "operation": request.operation,
            "request_fingerprint": request.request_fingerprint,
            "provider_name": "fixture",
            "model_name": "fixture-model",
            "judge_isolation": "scripted_fixture",
            "payload": wire_payload,
        }
    )
    return response, canonical_json_bytes(response.model_dump(mode="json"))


def _accepted_call(
    request: EvaluatorRequestV22,
    request_path: str,
    response_path: str,
    response_bytes: bytes,
    *,
    fragment_ordinal: int | None = None,
    dispute_id: str | None = None,
    anonymous_label: Literal["A", "B"] | None = None,
    grader_lane: Literal[1, 2] | None = None,
    batch_ref: str | None = None,
    contested_requirement_id: str | None = None,
) -> EvaluationCallRecordV22:
    return EvaluationCallRecordV22(
        call_id=Path(request_path).stem,
        operation=request.operation,
        state="accepted",
        attempt=1,
        request_artifact_path=request_path,
        request_fingerprint=request.request_fingerprint,
        response_artifact_path=response_path,
        response_fingerprint=sha256_digest(response_bytes),
        provider_name="fixture",
        model_name="fixture-model",
        judge_isolation="scripted_fixture",
        fragment_ordinal=fragment_ordinal,
        dispute_id=dispute_id,
        anonymous_label=anonymous_label,
        grader_lane=grader_lane,
        batch_ref=batch_ref,
        contested_requirement_id=contested_requirement_id,
    )


def _pending_call(
    call: EvaluationCallRecordV22, *, attempt: Literal[1, 2] = 1
) -> EvaluationCallRecordV22:
    return call.model_copy(
        update={
            "state": "pending",
            "attempt": attempt,
            "response_artifact_path": None,
            "response_fingerprint": None,
            "provider_name": None,
            "model_name": None,
            "judge_isolation": None,
        }
    )


def _put_call(
    files: dict[str, bytes],
    calls: list[EvaluationCallRecordV22],
    request: EvaluatorRequestV22,
    payload: object,
    request_path: str,
    response_path: str,
    **coordinates: object,
) -> tuple[EvaluatorResponseV22, bytes]:
    response, response_bytes = _response(request, payload)
    files[request_path] = canonical_json_bytes(request.model_dump(mode="json"))
    files[response_path] = response_bytes
    calls.append(
        _accepted_call(
            request,
            request_path,
            response_path,
            response_bytes,
            **coordinates,
        )
    )
    return response, response_bytes


def _completed_lifecycle(
    *,
    ordinary_disposition: Literal["met", "not_met"] = "met",
    unresolved: bool = False,
    comparator: bool = False,
    empty_sources: bool = False,
    seed_hex: str = "f" * 64,
    label_dispositions: dict[str, Literal["met", "not_met"]] | None = None,
) -> _Lifecycle:
    envelope = _lifecycle_envelope(comparator=comparator, seed_hex=seed_hex)
    case_bytes = canonical_json_bytes(envelope.model_dump(mode="json"))
    build_bytes = canonical_json_bytes(
        {
            "build": "public-fixture-v2.2",
            "compiler_contract_fingerprint": COMPILER_CONTRACT_FINGERPRINT_V22,
        }
    )
    rubric_bytes = canonical_json_bytes(RUBRIC_V22.model_dump(mode="json"))
    files = {
        "inputs/case.json": case_bytes,
        "inputs/build.json": build_bytes,
        "rubric.json": rubric_bytes,
    }
    calls: list[EvaluationCallRecordV22] = []

    review_history: list[AcceptedSourceReviewFragmentV22] = []
    review_payloads = (
        (SourceReviewFragmentV22(proposals=(), review_complete=True),)
        if empty_sources
        else (
            SourceReviewFragmentV22(
                proposals=[_proposal("Operators must file.", "operators must file")],
                review_complete=False,
            ),
            SourceReviewFragmentV22(
                proposals=[
                    _proposal(
                        "Operators must retain records.",
                        "operators must retain records",
                    ),
                    _proposal(
                        "Small operators are excluded.",
                        "small operators are excluded",
                        kind="exception",
                    ),
                ],
                review_complete=True,
            ),
        )
    )
    for ordinal, payload in enumerate(review_payloads, 1):
        request = build_source_review_fragment_request_v22(
            envelope, tuple(review_history), fragment_ordinal=ordinal
        )
        request_path = f"requests/source-review-{ordinal:04d}.json"
        response_path = f"responses/source-review-{ordinal:04d}.json"
        _, response_bytes = _put_call(
            files,
            calls,
            request,
            payload,
            request_path,
            response_path,
            fragment_ordinal=ordinal,
        )
        review_history.append(
            AcceptedSourceReviewFragmentV22(
                fragment_ordinal=ordinal,
                request_fingerprint=request.request_fingerprint,
                response_fingerprint=sha256_digest(response_bytes),
                payload=payload,
            )
        )
    review = aggregate_source_review_fragments_v22(tuple(review_history))
    files["aggregates/source-review.json"] = canonical_json_bytes(review.model_dump(mode="json"))
    review_end = len(calls)

    audit_history: list[AcceptedSourceAuditFragmentV22] = []
    audit_payloads = (
        (SourceAuditFragmentV22(concerns=(), audit_complete=True),)
        if empty_sources
        else (
            SourceAuditFragmentV22(
                concerns=[
                    {
                        "target_proposal_ref": "P0001",
                        "concern_type": "incorrect_statement",
                        "passages": [
                            {
                                "source_id": "rule-1",
                                "quote": "small operators are excluded",
                            }
                        ],
                        "explanation": "The filing obligation may have an exception.",
                        "correction": _proposal(
                            "Operators other than small operators must file.",
                            "small operators are excluded",
                        ),
                    }
                ],
                audit_complete=False,
            ),
            SourceAuditFragmentV22(
                concerns=[
                    {
                        "target_proposal_ref": "P0003",
                        "concern_type": "ambiguity",
                        "passages": [
                            {
                                "source_id": "rule-1",
                                "quote": "small operators are excluded",
                            }
                        ],
                        "explanation": "The scope of the exclusion requires adjudication.",
                        "correction": None,
                    }
                ],
                audit_complete=True,
            ),
        )
    )
    for ordinal, payload in enumerate(audit_payloads, 1):
        request = build_source_audit_fragment_request_v22(
            envelope, review, tuple(audit_history), fragment_ordinal=ordinal
        )
        request_path = f"requests/source-audit-{ordinal:04d}.json"
        response_path = f"responses/source-audit-{ordinal:04d}.json"
        _, response_bytes = _put_call(
            files,
            calls,
            request,
            payload,
            request_path,
            response_path,
            fragment_ordinal=ordinal,
        )
        audit_history.append(
            AcceptedSourceAuditFragmentV22(
                fragment_ordinal=ordinal,
                request_fingerprint=request.request_fingerprint,
                response_fingerprint=sha256_digest(response_bytes),
                payload=payload,
            )
        )
    audit = aggregate_source_audit_fragments_v22(review, tuple(audit_history))
    files["aggregates/source-audit.json"] = canonical_json_bytes(audit.model_dump(mode="json"))
    audit_end = len(calls)

    disputes = build_referee_disputes_v22(envelope, review, audit)
    assert len(disputes) == (0 if empty_sources else 2)
    referee_fragments = []
    for dispute in disputes:
        request = build_source_referee_fragment_request_v22(
            envelope, dispute, controller_disputes=disputes
        )
        decision = {
            "schema_version": "2.2",
            "decision": "unresolved" if unresolved else "accept_reviewer",
            "unresolved_reason": "SOURCE_AMBIGUITY" if unresolved else None,
            "evidence_refs": [dispute.evidence[0].evidence_ref],
            "rationale": (
                "The close source question remains unresolved."
                if unresolved
                else "The reviewer reading is better supported."
            ),
        }
        request_path = f"requests/referee-{dispute.dispute_id}.json"
        response_path = f"responses/referee-{dispute.dispute_id}.json"
        _, response_bytes = _put_call(
            files,
            calls,
            request,
            decision,
            request_path,
            response_path,
            dispute_id=dispute.dispute_id,
        )
        referee_fragments.append(
            validate_referee_fragment_v22(
                dispute,
                decision,
                response_fingerprint=sha256_digest(response_bytes),
            )
        )
    referee = aggregate_referee_decisions_v22(disputes, tuple(referee_fragments))
    baseline = compile_baseline_v22(envelope, review, audit, referee)
    files["aggregates/referee.json"] = canonical_json_bytes(referee.model_dump(mode="json"))
    files["baseline.json"] = canonical_json_bytes(baseline.model_dump(mode="json"))
    referee_end = len(calls)

    source_context = {source.source_id: source.normalized_text for source in envelope.case.sources}
    labels = cast(
        tuple[Literal["A", "B"], ...],
        tuple(item.anonymous_label for item in envelope.assignments),
    )
    batches = tuple(
        batch
        for label in labels
        for lane in cast(tuple[Literal[1, 2], ...], (1, 2))
        for batch in ordinary_grade_batches_v22(baseline, label, lane)
    )
    lane_aggregates = []
    sensitivities = []
    reports = []
    for label in labels:
        label_disposition = (
            ordinary_disposition
            if label_dispositions is None
            else label_dispositions[label]
        )
        assignment = next(
            item for item in envelope.assignments if item.anonymous_label == label
        )
        report_text = next(
            item.report_text
            for item in envelope.case.candidates
            if item.candidate_id == assignment.candidate_id
        )
        report_hash = sha256_digest(report_text.encode())
        ordinary_by_lane: dict[int, list[object]] = {1: [], 2: []}
        contested_by_lane: dict[int, list[object]] = {1: [], 2: []}
        label_aggregates = []
        for lane in cast(tuple[Literal[1, 2], ...], (1, 2)):
            for batch in ordinary_grade_batches_v22(baseline, label, lane):
                request = build_ordinary_grade_request_v22(
                    baseline,
                    batch,
                    label,
                    lane,
                    report_text,
                    source_context,
                    RUBRIC_V22,
                )
                raw = {
                    "schema_version": "2.2",
                    "anonymous_label": label,
                    "grader_lane": lane,
                    "batch_ref": batch.batch_ref,
                    "baseline_fingerprint": baseline.baseline_fingerprint,
                    "report_fingerprint": report_hash,
                    "requirement_grades": [
                        {
                            "requirement_id": requirement_id,
                            "disposition": label_disposition,
                            "report_passages": ["Operators must retain records."],
                            "rationale": "The report was graded against this requirement.",
                        }
                        for requirement_id in batch.requirement_ids
                    ],
                    "rationale": "Every ordinary requirement in the batch was graded.",
                }
                fragment = validate_grade_fragment_v22(baseline, raw, report_text)
                path_id = batch.batch_ref
                _put_call(
                    files,
                    calls,
                    request,
                    fragment,
                    f"requests/grade-{path_id}.json",
                    f"responses/grade-{path_id}.json",
                    anonymous_label=label,
                    grader_lane=lane,
                    batch_ref=batch.batch_ref,
                )
                ordinary_by_lane[lane].append(fragment)
            for requirement in baseline.contested_requirements:
                request = build_contested_grade_request_v22(
                    baseline,
                    requirement,
                    label,
                    lane,
                    report_text,
                    source_context,
                    RUBRIC_V22,
                )
                disposition = "uncertain" if unresolved else label_disposition
                passages = [] if unresolved else ["Operators must file."]
                raw = {
                    "schema_version": "2.2",
                    "anonymous_label": label,
                    "grader_lane": lane,
                    "contested_requirement_id": requirement.contested_requirement_id,
                    "baseline_fingerprint": baseline.baseline_fingerprint,
                    "report_fingerprint": report_hash,
                    "reviewer_alternative_grade": {
                        "disposition": disposition,
                        "report_passages": passages,
                        "rationale": "The reviewer alternative was graded.",
                    },
                    "auditor_alternative_grade": {
                        "disposition": disposition,
                        "report_passages": passages,
                        "rationale": "The auditor alternative was graded.",
                    },
                    "ambiguity_disposition": (
                        "uncertain" if unresolved else "acknowledged"
                    ),
                    "rationale": "Both alternatives were graded independently.",
                }
                fragment = validate_grade_fragment_v22(baseline, raw, report_text)
                fragment_id = requirement.contested_requirement_id
                _put_call(
                    files,
                    calls,
                    request,
                    fragment,
                    f"requests/grade-contested-{label}-{lane}-{fragment_id}.json",
                    f"responses/grade-contested-{label}-{lane}-{fragment_id}.json",
                    anonymous_label=label,
                    grader_lane=lane,
                    contested_requirement_id=fragment_id,
                )
                contested_by_lane[lane].append(fragment)
            if empty_sources:
                aggregate_payload = {
                    "anonymous_label": label,
                    "grader_lane": lane,
                    "baseline_fingerprint": baseline.baseline_fingerprint,
                    "report_fingerprint": report_hash,
                    "ordinary_fragments": [],
                    "contested_fragments": [],
                }
                aggregate = GraderAggregateV22.validate_for_inventories(
                    {
                        **aggregate_payload,
                        "aggregate_fingerprint": sha256_digest(
                            canonical_json_bytes(aggregate_payload)
                        ),
                    },
                    (),
                    (),
                )
            else:
                aggregate = aggregate_grader_lane_v22(
                    baseline,
                    label,
                    lane,
                    cast(tuple[object, ...], tuple(ordinary_by_lane[lane])),
                    cast(tuple[object, ...], tuple(contested_by_lane[lane])),
                )
            label_aggregates.append(aggregate)
            lane_aggregates.append(aggregate)
            files[f"aggregates/grade-{label}-{lane}.json"] = canonical_json_bytes(
                aggregate.model_dump(mode="json")
            )
        reconciliation = reconcile_grader_lanes_v22(
            baseline, label_aggregates[0], label_aggregates[1], RUBRIC_V22
        )
        sensitivity = evaluate_outcome_sensitivity_v22(
            baseline, reconciliation, RUBRIC_V22
        )
        if empty_sources:
            sensitivity_payload = {
                "anonymous_label": label,
                "baseline_fingerprint": baseline.baseline_fingerprint,
                "reconciliation_fingerprint": reconciliation.reconciliation_fingerprint,
                "absolute_disposition": "INCONCLUSIVE",
                "reason_codes": ["BASELINE_EVIDENCE_INSUFFICIENT"],
                "outcome_determinative_contested_ids": [],
            }
            sensitivity = SensitivityRecordV22.model_validate(
                {
                    **sensitivity_payload,
                    "sensitivity_fingerprint": sha256_digest(
                        canonical_json_bytes(sensitivity_payload)
                    ),
                }
            )
        sensitivities.append(sensitivity)
        files[f"sensitivities/{label}.json"] = canonical_json_bytes(
            sensitivity.model_dump(mode="json")
        )
        report_payload = {
            "anonymous_label": label,
            "reconciliation": reconciliation.model_dump(mode="json"),
            "sensitivity": sensitivity.model_dump(mode="json"),
        }
        reports.append(
            ReportResultV22(
                anonymous_label=label,
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
    comparison: ComparisonResultV22 | None = None
    if len(sensitivities) == 2:
        role_by_candidate = {
            candidate.candidate_id: candidate.role.value
            for candidate in envelope.case.candidates
        }
        label_by_role = {
            role_by_candidate[assignment.candidate_id]: assignment.anonymous_label
            for assignment in envelope.assignments
        }
        candidate_label = cast(Literal["A", "B"], label_by_role["candidate"])
        comparator_label = cast(Literal["A", "B"], label_by_role["comparator"])
        first, second = sensitivities
        if (
            first.absolute_disposition is AbsoluteDispositionV2.INCONCLUSIVE
            or second.absolute_disposition is AbsoluteDispositionV2.INCONCLUSIVE
        ):
            comparison = ComparisonResultV22(
                disposition=ComparisonDispositionV2.INCONCLUSIVE,
                candidate_label=candidate_label,
                comparator_label=comparator_label,
                rationale="At least one report is inconclusive.",
            )
        elif (
            first.absolute_disposition is AbsoluteDispositionV2.PASS
            and second.absolute_disposition is AbsoluteDispositionV2.PASS
        ):
            comparison = ComparisonResultV22(
                disposition=ComparisonDispositionV2.TIE,
                candidate_label=candidate_label,
                comparator_label=comparator_label,
                rationale="Both reports passed the rubric.",
            )
        elif (
            first.absolute_disposition is AbsoluteDispositionV2.FAIL
            and second.absolute_disposition is AbsoluteDispositionV2.FAIL
        ):
            comparison = ComparisonResultV22(
                disposition=ComparisonDispositionV2.NEITHER,
                candidate_label=candidate_label,
                comparator_label=comparator_label,
                rationale="Neither report passed the rubric.",
            )
        else:
            winner_label: Literal["A", "B"] = (
                "A" if first.absolute_disposition is AbsoluteDispositionV2.PASS else "B"
            )
            candidate_wins = winner_label == candidate_label
            comparison = ComparisonResultV22(
                disposition=(
                    ComparisonDispositionV2.CANDIDATE_WIN
                    if candidate_wins
                    else ComparisonDispositionV2.COMPARATOR_WIN
                ),
                winner_label=winner_label,
                candidate_label=candidate_label,
                comparator_label=comparator_label,
                rationale=(
                    "Only the candidate report passed the rubric."
                    if candidate_wins
                    else "Only the comparator report passed the rubric."
                ),
            )
    result_payload = {
        "schema_version": "2.2",
        "rubric": RUBRIC_V22.model_dump(mode="json"),
        "baseline": baseline.model_dump(mode="json"),
        "reports": [report.model_dump(mode="json") for report in reports],
        "comparison": (
            None if comparison is None else comparison.model_dump(mode="json")
        ),
        "terminal_status": terminal.value,
    }
    result = EvaluationResultV22(
        schema_version="2.2",
        rubric=RUBRIC_V22,
        baseline=baseline,
        reports=tuple(reports),
        comparison=comparison,
        terminal_status=terminal,
        result_fingerprint=sha256_digest(canonical_json_bytes(result_payload)),
    )
    files["result.json"] = canonical_json_bytes(result.model_dump(mode="json"))
    manifest = EvaluationManifestV22.model_validate(
        {
            "protocol_version": "2.2",
            "case_fingerprint": envelope.case_fingerprint,
            "case_envelope_hash": sha256_digest(case_bytes),
            "build_fingerprint": sha256_digest(build_bytes),
            "rubric_fingerprint": sha256_digest(rubric_bytes),
            "compiler_contract_fingerprint": COMPILER_CONTRACT_FINGERPRINT_V22,
            "compiler_version": "semantic-compiler-v2.2",
            "source_review_aggregate_fingerprint": review.aggregate_fingerprint,
            "source_audit_aggregate_fingerprint": audit.aggregate_fingerprint,
            "referee_aggregate_fingerprint": referee.aggregate_fingerprint,
            "baseline_fingerprint": baseline.baseline_fingerprint,
            "grader_aggregate_fingerprints": [
                item.aggregate_fingerprint for item in lane_aggregates
            ],
            "sensitivity_fingerprints": [
                item.sensitivity_fingerprint for item in sensitivities
            ],
            "result_hash": result.result_fingerprint,
            "phase": "inconclusive"
            if terminal is EvaluationTerminalStatusV22.INCONCLUSIVE
            else "completed",
            "terminal_status": terminal,
            "calls": calls,
            "artifacts": [],
            "referee_disputes": disputes,
            "ordinary_grade_batches": batches,
            "manifest_fingerprint": "0" * 64,
        },
        context={
            "ordinary_grade_batches": batches,
            "contested_requirements": baseline.contested_requirements,
        },
    )
    return _Lifecycle(manifest, files, result, review_end, audit_end, referee_end)


def _files_for_calls(
    source: dict[str, bytes], calls: tuple[EvaluationCallRecordV22, ...]
) -> dict[str, bytes]:
    keep = {"inputs/case.json", "inputs/build.json", "rubric.json"}
    keep.update(call.request_artifact_path for call in calls)
    keep.update(
        cast(str, call.response_artifact_path)
        for call in calls
        if call.response_artifact_path is not None
    )
    return {path: data for path, data in source.items() if path in keep}


def _pending_state(
    lifecycle: _Lifecycle, accepted_count: int, *, attempt: Literal[1, 2] = 1
) -> tuple[EvaluationManifestV22, dict[str, bytes]]:
    target = lifecycle.manifest.calls[accepted_count]
    calls = (*lifecycle.manifest.calls[:accepted_count], _pending_call(target, attempt=attempt))
    files = _files_for_calls(lifecycle.files, calls)
    update: dict[str, object] = {
        "phase": {
            EvaluatorOperationV22.SOURCE_REVIEW_FRAGMENT: EvaluationPhaseV22.SOURCE_REVIEW,
            EvaluatorOperationV22.SOURCE_AUDIT_FRAGMENT: EvaluationPhaseV22.SOURCE_AUDIT,
            EvaluatorOperationV22.SOURCE_REFEREE_FRAGMENT: EvaluationPhaseV22.SOURCE_REFEREE,
            EvaluatorOperationV22.ORDINARY_GRADE_FRAGMENT: EvaluationPhaseV22.ORDINARY_GRADING,
            EvaluatorOperationV22.CONTESTED_GRADE_FRAGMENT: EvaluationPhaseV22.CONTESTED_GRADING,
        }[target.operation],
        "terminal_status": None,
        "calls": calls,
        "source_review_aggregate_fingerprint": None,
        "source_audit_aggregate_fingerprint": None,
        "referee_aggregate_fingerprint": None,
        "baseline_fingerprint": None,
        "grader_aggregate_fingerprints": (),
        "sensitivity_fingerprints": (),
        "result_hash": None,
        "artifacts": (),
        "manifest_fingerprint": "0" * 64,
    }
    if accepted_count >= lifecycle.review_end:
        files["aggregates/source-review.json"] = lifecycle.files["aggregates/source-review.json"]
        update["source_review_aggregate_fingerprint"] = (
            lifecycle.manifest.source_review_aggregate_fingerprint
        )
    if accepted_count >= lifecycle.audit_end:
        files["aggregates/source-audit.json"] = lifecycle.files["aggregates/source-audit.json"]
        update["source_audit_aggregate_fingerprint"] = (
            lifecycle.manifest.source_audit_aggregate_fingerprint
        )
        update["referee_disputes"] = lifecycle.manifest.referee_disputes
    else:
        update["referee_disputes"] = ()
    if accepted_count >= lifecycle.referee_end:
        files["aggregates/referee.json"] = lifecycle.files["aggregates/referee.json"]
        files["baseline.json"] = lifecycle.files["baseline.json"]
        update["referee_aggregate_fingerprint"] = lifecycle.manifest.referee_aggregate_fingerprint
        update["baseline_fingerprint"] = lifecycle.manifest.baseline_fingerprint
        update["ordinary_grade_batches"] = lifecycle.manifest.ordinary_grade_batches
        aggregate_fingerprints: list[str] = []
        sensitivity_fingerprints: list[str] = []
        for label in cast(
            tuple[Literal["A", "B"], ...],
            tuple(item.anonymous_label for item in lifecycle.result.reports),
        ):
            completed_lanes = 0
            for lane in (1, 2):
                lane_calls = [
                    call
                    for call in lifecycle.manifest.calls[:accepted_count]
                    if call.anonymous_label == label and call.grader_lane == lane
                ]
                all_lane_calls = [
                    call
                    for call in lifecycle.manifest.calls
                    if call.anonymous_label == label and call.grader_lane == lane
                ]
                if len(lane_calls) == len(all_lane_calls):
                    path = f"aggregates/grade-{label}-{lane}.json"
                    files[path] = lifecycle.files[path]
                    aggregate_fingerprints.append(
                        lifecycle.manifest.grader_aggregate_fingerprints[
                            len(aggregate_fingerprints)
                        ]
                    )
                    completed_lanes += 1
            if completed_lanes == 2:
                path = f"sensitivities/{label}.json"
                files[path] = lifecycle.files[path]
                sensitivity_fingerprints.append(
                    lifecycle.manifest.sensitivity_fingerprints[
                        len(sensitivity_fingerprints)
                    ]
                )
        update["grader_aggregate_fingerprints"] = tuple(aggregate_fingerprints)
        update["sensitivity_fingerprints"] = tuple(sensitivity_fingerprints)
    else:
        update["ordinary_grade_batches"] = ()
    return lifecycle.manifest.model_copy(update=update), files


def _snapshot(run_dir: Path) -> dict[str, bytes]:
    return {
        path.relative_to(run_dir).as_posix(): path.read_bytes()
        for path in sorted(run_dir.rglob("*"))
        if path.is_file() and not path.is_symlink()
    }


def _review_to_audit_transition(
    tmp_path: Path,
) -> tuple[Path, EvaluationManifestV22, EvaluationManifestV22, dict[str, bytes]]:
    lifecycle = _completed_lifecycle(unresolved=True)
    initial, initial_files = _pending_state(lifecycle, 1)
    successor, successor_files = _pending_state(lifecycle, 2)
    run_dir = tmp_path / "review-to-audit"
    current = initialize_v22_run_storage(run_dir, initial, initial_files)
    additions = {path: data for path, data in successor_files.items() if path not in initial_files}
    return run_dir, current, successor, additions


def test_protocol_detector_recognizes_v22_manifest(tmp_path: Path) -> None:
    """Protocol 2.2 has an explicit detector branch, not a fallback."""
    run_dir = tmp_path / "v22"
    run_dir.mkdir()
    (run_dir / "run-manifest.json").write_bytes(
        canonical_json_bytes(
            {
                "protocol_version": "2.2",
                "compiler_contract_fingerprint": COMPILER_CONTRACT_FINGERPRINT_V22,
            }
        )
    )

    assert detect_evaluation_protocol(run_dir) == "2.2"


@pytest.mark.parametrize(
    "payload",
    [
        {"protocol_version": "2.2"},
        {
            "protocol_version": "2.2",
            "compiler_contract_fingerprint": "0" * 64,
        },
        {
            "protocol_version": "2.2",
            "schema_version": "1.3",
            "compiler_contract_fingerprint": COMPILER_CONTRACT_FINGERPRINT_V22,
        },
        {
            "protocol_version": "2.1",
            "compiler_contract_fingerprint": COMPILER_CONTRACT_FINGERPRINT_V22,
        },
        {"protocol_version": "9.9"},
    ],
)
def test_protocol_detector_rejects_unknown_mixed_and_downgraded_v22_markers(
    tmp_path: Path, payload: dict[str, object]
) -> None:
    run_dir = tmp_path / sha256_digest(canonical_json_bytes(payload))[:12]
    run_dir.mkdir()
    (run_dir / "run-manifest.json").write_bytes(canonical_json_bytes(payload))

    with pytest.raises(EvaluationIntegrityError, match="EVALUATION_PROTOCOL_UNSUPPORTED"):
        detect_evaluation_protocol(run_dir)


def _envelope() -> CaseEnvelope:
    source_text = "Rule: operators must retain records."
    report_text = "Operators must retain records."
    source = EvaluationSource(
        source_id="rule-1",
        title="Example Rule",
        normalized_text=source_text,
        content_hash=sha256_digest(source_text.encode()),
        jurisdiction="Example State",
        authority_type="regulation",
        source_role=SourceRole.OFFICIAL_PRIMARY,
        source_quality=SourceQuality.PRIMARY,
        completeness="complete",
        language="en",
    )
    candidate = CandidateReport(
        candidate_id="candidate",
        role=CandidateRole.CANDIDATE,
        report_text=report_text,
        report_hash=sha256_digest(report_text.encode()),
    )
    case = AttorneyEvaluationCase(
        case_id="v22-artifact-case",
        mode=EvaluationMode.CLOSED_UNIVERSE,
        question="What must operators do?",
        jurisdiction="Example State",
        as_of="2026-08-20",
        requested_authorities=[
            RequestedAuthority(
                authority_id="example-rule",
                title="Example Rule",
                jurisdiction="Example State",
                authority_type="regulation",
                source_ids=[source.source_id],
            )
        ],
        sources=[source],
        candidates=[candidate],
    )
    return CaseEnvelope(
        case=case,
        assignments=[BlindAssignment(anonymous_label="A", candidate_id="candidate")],
        case_fingerprint=model_fingerprint(case),
        seed_fingerprint="f" * 64,
    )


def test_pending_v22_run_is_valid_and_resumable(tmp_path: Path) -> None:
    envelope = _envelope()
    request = build_source_review_fragment_request_v22(envelope, (), fragment_ordinal=1)
    request_path = "requests/source-review-0001.json"
    case_bytes = canonical_json_bytes(envelope.model_dump(mode="json"))
    build_bytes = canonical_json_bytes({"build": "v2.2-test"})
    rubric_bytes = canonical_json_bytes(RUBRIC_V22.model_dump(mode="json"))
    call = EvaluationCallRecordV22(
        call_id="source-review-0001",
        operation="source_review_fragment",
        state="pending",
        attempt=1,
        request_artifact_path=request_path,
        request_fingerprint=request.request_fingerprint,
        fragment_ordinal=1,
    )
    manifest = EvaluationManifestV22(
        protocol_version="2.2",
        case_fingerprint=envelope.case_fingerprint,
        case_envelope_hash=sha256_digest(case_bytes),
        build_fingerprint=sha256_digest(build_bytes),
        rubric_fingerprint=sha256_digest(rubric_bytes),
        compiler_contract_fingerprint=COMPILER_CONTRACT_FINGERPRINT_V22,
        compiler_version="semantic-compiler-v2.2",
        phase="source_review",
        calls=(call,),
        artifacts=(),
        referee_disputes=(),
        ordinary_grade_batches=(),
        manifest_fingerprint="0" * 64,
    )
    run_dir = tmp_path / "pending"
    initialize_v22_run_storage(
        run_dir,
        manifest,
        {
            "inputs/case.json": case_bytes,
            "inputs/build.json": build_bytes,
            "rubric.json": rubric_bytes,
            request_path: canonical_json_bytes(request.model_dump(mode="json")),
        },
    )

    verification = verify_v22_run(run_dir)
    reloaded, result = load_verified_v22_run(run_dir)

    assert verification.valid is True
    assert result is None
    assert reloaded.terminal_status is None
    assert [call.state for call in reloaded.calls].count("pending") == 1


def test_source_review_transition_replays_fragment_and_successor_request(
    tmp_path: Path,
) -> None:
    envelope = _envelope()
    review_request = build_source_review_fragment_request_v22(envelope, (), fragment_ordinal=1)
    request_path = "requests/source-review-0001.json"
    case_bytes = canonical_json_bytes(envelope.model_dump(mode="json"))
    build_bytes = canonical_json_bytes({"build": "v2.2-test"})
    rubric_bytes = canonical_json_bytes(RUBRIC_V22.model_dump(mode="json"))
    pending = EvaluationCallRecordV22(
        call_id="source-review-0001",
        operation="source_review_fragment",
        state="pending",
        attempt=1,
        request_artifact_path=request_path,
        request_fingerprint=review_request.request_fingerprint,
        fragment_ordinal=1,
    )
    initial = EvaluationManifestV22(
        protocol_version="2.2",
        case_fingerprint=envelope.case_fingerprint,
        case_envelope_hash=sha256_digest(case_bytes),
        build_fingerprint=sha256_digest(build_bytes),
        rubric_fingerprint=sha256_digest(rubric_bytes),
        compiler_contract_fingerprint=COMPILER_CONTRACT_FINGERPRINT_V22,
        compiler_version="semantic-compiler-v2.2",
        phase="source_review",
        calls=(pending,),
        artifacts=(),
        referee_disputes=(),
        ordinary_grade_batches=(),
        manifest_fingerprint="0" * 64,
    )
    run_dir = tmp_path / "review-transition"
    committed = initialize_v22_run_storage(
        run_dir,
        initial,
        {
            "inputs/case.json": case_bytes,
            "inputs/build.json": build_bytes,
            "rubric.json": rubric_bytes,
            request_path: canonical_json_bytes(review_request.model_dump(mode="json")),
        },
    )
    response = EvaluatorResponseV22(
        operation="source_review_fragment",
        request_fingerprint=review_request.request_fingerprint,
        provider_name="fixture",
        model_name="fixture-model",
        judge_isolation="scripted_fixture",
        payload={
            "schema_version": "2.2",
            "proposals": [
                {
                    "statement": "Operators must retain records.",
                    "kind": "obligation",
                    "importance": "critical",
                    "passages": [{"source_id": "rule-1", "quote": "operators must retain records"}],
                    "dependency": None,
                    "confidence": "clear",
                    "rationale": "The source states the obligation.",
                }
            ],
            "review_complete": True,
        },
    )
    response_bytes = canonical_json_bytes(response.model_dump(mode="json"))
    accepted = pending.model_copy(
        update={
            "state": "accepted",
            "response_artifact_path": "responses/source-review-0001.json",
            "response_fingerprint": sha256_digest(response_bytes),
            "provider_name": "fixture",
            "model_name": "fixture-model",
            "judge_isolation": "scripted_fixture",
        }
    )
    aggregate = aggregate_source_review_fragments_v22(
        (
            AcceptedSourceReviewFragmentV22(
                fragment_ordinal=1,
                request_fingerprint=review_request.request_fingerprint,
                response_fingerprint=sha256_digest(response_bytes),
                payload=response.payload,
            ),
        )
    )
    audit_request = build_source_audit_fragment_request_v22(
        envelope, aggregate, (), fragment_ordinal=1
    )
    successor = EvaluationManifestV22.model_validate(
        {
            **initial.model_dump(mode="json"),
            "phase": "source_audit",
            "source_review_aggregate_fingerprint": aggregate.aggregate_fingerprint,
            "calls": (
                accepted,
                EvaluationCallRecordV22(
                    call_id="source-audit-0001",
                    operation="source_audit_fragment",
                    state="pending",
                    attempt=1,
                    request_artifact_path="requests/source-audit-0001.json",
                    request_fingerprint=audit_request.request_fingerprint,
                    fragment_ordinal=1,
                ),
            ),
            "artifacts": (),
            "manifest_fingerprint": "0" * 64,
        }
    )

    commit_v22_transition(
        run_dir,
        committed.manifest_fingerprint,
        {
            "responses/source-review-0001.json": response_bytes,
            "aggregates/source-review.json": canonical_json_bytes(
                aggregate.model_dump(mode="json")
            ),
            "requests/source-audit-0001.json": canonical_json_bytes(
                audit_request.model_dump(mode="json")
            ),
        },
        successor,
    )

    verified, result = load_verified_v22_run(run_dir)
    assert result is None
    assert verified.calls[-1].request_fingerprint == audit_request.request_fingerprint


@pytest.mark.parametrize(
    "accepted_count",
    [
        1,  # partial source review
        3,  # partial source audit
        5,  # first of two referee disputes
        6,  # first ordinary grade fragment
        7,  # contested grade fragment
        9,  # first complete lane aggregate, second lane pending
    ],
)
def test_every_partial_lifecycle_state_replays_with_one_exact_pending_call(
    tmp_path: Path, accepted_count: int
) -> None:
    lifecycle = _completed_lifecycle(unresolved=True)
    manifest, files = _pending_state(lifecycle, accepted_count)
    run_dir = tmp_path / f"pending-{accepted_count}"

    committed = initialize_v22_run_storage(run_dir, manifest, files)
    verification = verify_v22_run(run_dir)
    reloaded, result = load_verified_v22_run(run_dir)

    assert verification.valid
    assert result is None
    assert reloaded == committed
    assert [call.state for call in reloaded.calls].count("pending") == 1
    assert reloaded.calls[-1].request_fingerprint == manifest.calls[-1].request_fingerprint


def test_second_semantic_draft_failure_remains_pending_and_nonterminal(tmp_path: Path) -> None:
    lifecycle = _completed_lifecycle(unresolved=True)
    manifest, files = _pending_state(lifecycle, 7, attempt=2)
    run_dir = tmp_path / "second-draft-pending"

    initialize_v22_run_storage(run_dir, manifest, files)
    reloaded, result = load_verified_v22_run(run_dir)

    assert result is None
    assert reloaded.calls[-1].attempt == 2
    assert reloaded.calls[-1].state == "pending"
    assert reloaded.terminal_status is None
    assert reloaded.phase is EvaluationPhaseV22.CONTESTED_GRADING


def test_baseline_sealed_and_aggregate_states_replay_without_inventing_a_pending_call(
    tmp_path: Path,
) -> None:
    lifecycle = _completed_lifecycle(unresolved=True)
    pending_grade, grade_files = _pending_state(lifecycle, lifecycle.referee_end)
    first_grade = pending_grade.calls[-1]
    grade_files.pop(first_grade.request_artifact_path)
    baseline_sealed = pending_grade.model_copy(
        update={
            "phase": EvaluationPhaseV22.BASELINE_SEALED,
            "calls": pending_grade.calls[:-1],
            "artifacts": (),
            "manifest_fingerprint": "0" * 64,
        }
    )
    baseline_dir = tmp_path / "baseline-sealed"
    initialize_v22_run_storage(baseline_dir, baseline_sealed, grade_files)
    verified_baseline, baseline_result = load_verified_v22_run(baseline_dir)
    assert baseline_result is None
    assert verified_baseline.phase is EvaluationPhaseV22.BASELINE_SEALED
    assert all(call.state == "accepted" for call in verified_baseline.calls)

    aggregate_files = dict(lifecycle.files)
    aggregate_files.pop("result.json")
    aggregate = lifecycle.manifest.model_copy(
        update={
            "phase": EvaluationPhaseV22.AGGREGATE,
            "terminal_status": None,
            "result_hash": None,
            "artifacts": (),
            "manifest_fingerprint": "0" * 64,
        }
    )
    aggregate_dir = tmp_path / "aggregate"
    initialize_v22_run_storage(aggregate_dir, aggregate, aggregate_files)
    verified_aggregate, aggregate_result = load_verified_v22_run(aggregate_dir)
    assert aggregate_result is None
    assert verified_aggregate.phase is EvaluationPhaseV22.AGGREGATE
    assert all(call.state == "accepted" for call in verified_aggregate.calls)


@pytest.mark.parametrize(
    ("ordinary_disposition", "unresolved", "terminal", "absolute"),
    [
        ("met", False, EvaluationTerminalStatusV22.COMPLETED, "PASS"),
        ("not_met", False, EvaluationTerminalStatusV22.COMPLETED, "FAIL"),
        ("met", True, EvaluationTerminalStatusV22.INCONCLUSIVE, "INCONCLUSIVE"),
    ],
)
def test_terminal_pass_fail_and_substantive_inconclusive_replay_from_wire_history(
    tmp_path: Path,
    ordinary_disposition: Literal["met", "not_met"],
    unresolved: bool,
    terminal: EvaluationTerminalStatusV22,
    absolute: str,
) -> None:
    lifecycle = _completed_lifecycle(
        ordinary_disposition=ordinary_disposition, unresolved=unresolved
    )
    run_dir = tmp_path / f"terminal-{terminal.value.lower()}-{absolute.lower()}"

    initialize_v22_run_storage(run_dir, lifecycle.manifest, lifecycle.files)
    verification = verify_v22_run(run_dir)
    manifest, result = load_verified_v22_run(run_dir)

    assert verification.valid
    assert manifest.terminal_status is terminal
    assert result == lifecycle.result
    assert result is not None
    assert result.reports[0].sensitivity.absolute_disposition.value == absolute


def test_two_report_comparison_replays_report_major_grading_and_terminal_binding(
    tmp_path: Path,
) -> None:
    lifecycle = _completed_lifecycle(comparator=True)
    run_dir = tmp_path / "two-report-completed"

    initialize_v22_run_storage(run_dir, lifecycle.manifest, lifecycle.files)
    manifest, result = load_verified_v22_run(run_dir)
    grade_labels = [
        call.anonymous_label
        for call in manifest.calls
        if call.operation
        in {
            EvaluatorOperationV22.ORDINARY_GRADE_FRAGMENT,
            EvaluatorOperationV22.CONTESTED_GRADE_FRAGMENT,
        }
    ]

    assert result == lifecycle.result
    assert result is not None
    assert [report.anonymous_label for report in result.reports] == ["A", "B"]
    assert result.comparison is not None
    assert result.comparison.disposition is ComparisonDispositionV2.TIE
    assert manifest.terminal_status is EvaluationTerminalStatusV22.COMPLETED
    assert len(manifest.grader_aggregate_fingerprints) == 4
    assert len(manifest.sensitivity_fingerprints) == 2
    assert grade_labels == sorted(grade_labels)
    assert set(lifecycle.files) >= {
        "aggregates/grade-A-1.json",
        "aggregates/grade-A-2.json",
        "aggregates/grade-B-1.json",
        "aggregates/grade-B-2.json",
        "sensitivities/A.json",
        "sensitivities/B.json",
        "result.json",
    }


@pytest.mark.parametrize(
    ("seed_digit", "candidate_label", "comparator_label"),
    [("f", "A", "B"), ("0", "B", "A")],
)
def test_replay_derives_comparison_roles_from_both_blind_seed_orientations(
    tmp_path: Path,
    seed_digit: str,
    candidate_label: Literal["A", "B"],
    comparator_label: Literal["A", "B"],
) -> None:
    lifecycle = _completed_lifecycle(
        comparator=True,
        seed_hex=seed_digit * 64,
        label_dispositions={"A": "met", "B": "not_met"},
    )
    run_dir = tmp_path / f"role-replay-{seed_digit}"

    initialize_v22_run_storage(run_dir, lifecycle.manifest, lifecycle.files)
    _, result = load_verified_v22_run(run_dir)

    assert result is not None and result.comparison is not None
    assert result.comparison.candidate_label == candidate_label
    assert result.comparison.comparator_label == comparator_label
    assert result.comparison.winner_label == "A"
    assert result.comparison.disposition is (
        ComparisonDispositionV2.CANDIDATE_WIN
        if candidate_label == "A"
        else ComparisonDispositionV2.COMPARATOR_WIN
    )


def test_one_report_replay_omits_comparison_role_binding(tmp_path: Path) -> None:
    lifecycle = _completed_lifecycle()
    run_dir = tmp_path / "one-report-no-comparison"

    initialize_v22_run_storage(run_dir, lifecycle.manifest, lifecycle.files)
    _, result = load_verified_v22_run(run_dir)

    assert result is not None
    assert result.comparison is None


@pytest.mark.parametrize(
    "comparison",
    [
        {
            "disposition": "candidate_win",
            "winner_label": "A",
            "candidate_label": "A",
            "comparator_label": "B",
            "rationale": "Only the candidate report passed the rubric.",
        },
        {
            "disposition": "neither",
            "winner_label": None,
            "candidate_label": "B",
            "comparator_label": "A",
            "rationale": "Neither report passed the rubric.",
        },
        {
            "disposition": "comparator_win",
            "winner_label": "B",
            "candidate_label": "B",
            "comparator_label": "A",
            "rationale": "Only the comparator report passed the rubric.",
        },
    ],
)
def test_replay_rejects_resealed_role_winner_and_disposition_tampering(
    tmp_path: Path, comparison: dict[str, object]
) -> None:
    lifecycle = _completed_lifecycle(
        comparator=True,
        seed_hex="0" * 64,
        label_dispositions={"A": "met", "B": "not_met"},
    )
    files = dict(lifecycle.files)
    raw = cast(dict[str, object], json.loads(files["result.json"]))
    raw["comparison"] = comparison
    payload = {key: value for key, value in raw.items() if key != "result_fingerprint"}
    resealed = sha256_digest(canonical_json_bytes(payload))
    raw["result_fingerprint"] = resealed
    files["result.json"] = canonical_json_bytes(raw)
    manifest = lifecycle.manifest.model_copy(
        update={
            "result_hash": resealed,
            "artifacts": (),
            "manifest_fingerprint": "0" * 64,
        }
    )

    with pytest.raises(EvaluationIntegrityError, match=r"(?:MODEL_INVALID|RESULT_BINDING)"):
        initialize_v22_run_storage(tmp_path / "comparison-role-tamper", manifest, files)


def test_two_report_run_resumes_exactly_between_report_labels(tmp_path: Path) -> None:
    lifecycle = _completed_lifecycle(comparator=True)
    first_b = next(
        index
        for index, call in enumerate(lifecycle.manifest.calls)
        if call.anonymous_label == "B"
    )
    manifest, files = _pending_state(lifecycle, first_b)
    run_dir = tmp_path / "two-report-between-labels"

    initialize_v22_run_storage(run_dir, manifest, files)
    reloaded, result = load_verified_v22_run(run_dir)

    assert result is None
    assert reloaded.calls[-1].state == "pending"
    assert reloaded.calls[-1].anonymous_label == "B"
    assert len(reloaded.grader_aggregate_fingerprints) == 2
    assert len(reloaded.sensitivity_fingerprints) == 1
    assert (run_dir / "sensitivities/A.json").is_file()
    assert not (run_dir / "sensitivities/B.json").exists()


def test_two_report_label_swap_is_rejected_even_when_result_is_resealed(
    tmp_path: Path,
) -> None:
    lifecycle = _completed_lifecycle(comparator=True)
    files = dict(lifecycle.files)
    raw = cast(dict[str, object], json.loads(files["result.json"]))
    reports = cast(list[dict[str, object]], raw["reports"])
    raw["reports"] = list(reversed(reports))
    payload = {key: value for key, value in raw.items() if key != "result_fingerprint"}
    resealed = sha256_digest(canonical_json_bytes(payload))
    raw["result_fingerprint"] = resealed
    files["result.json"] = canonical_json_bytes(raw)
    manifest = lifecycle.manifest.model_copy(
        update={
            "result_hash": resealed,
            "artifacts": (),
            "manifest_fingerprint": "0" * 64,
        }
    )

    with pytest.raises(
        EvaluationIntegrityError, match=r"(?:MODEL_INVALID|RESULT_BINDING)"
    ):
        initialize_v22_run_storage(tmp_path / "two-report-label-swap", manifest, files)


@pytest.mark.parametrize("comparator", [False, True])
def test_empty_review_and_audit_end_in_substantive_inconclusive_result(
    tmp_path: Path, comparator: bool
) -> None:
    lifecycle = _completed_lifecycle(empty_sources=True, comparator=comparator)
    run_dir = tmp_path / f"empty-terminal-{comparator}"

    initialize_v22_run_storage(run_dir, lifecycle.manifest, lifecycle.files)
    manifest, result = load_verified_v22_run(run_dir)

    assert manifest.phase is EvaluationPhaseV22.INCONCLUSIVE
    assert manifest.terminal_status is EvaluationTerminalStatusV22.INCONCLUSIVE
    assert result == lifecycle.result
    assert result is not None
    assert len(result.reports) == (2 if comparator else 1)
    assert all(
        report.sensitivity.absolute_disposition is AbsoluteDispositionV2.INCONCLUSIVE
        and report.sensitivity.reason_codes == ("BASELINE_EVIDENCE_INSUFFICIENT",)
        for report in result.reports
    )
    assert result.comparison is None or (
        result.comparison.disposition is ComparisonDispositionV2.INCONCLUSIVE
    )


def test_empty_source_history_cannot_be_stranded_in_aggregate_phase(
    tmp_path: Path,
) -> None:
    lifecycle = _completed_lifecycle(empty_sources=True)
    files = {
        path: data
        for path, data in lifecycle.files.items()
        if not path.startswith("aggregates/grade-")
        and not path.startswith("sensitivities/")
        and path != "result.json"
    }
    manifest = lifecycle.manifest.model_copy(
        update={
            "phase": EvaluationPhaseV22.AGGREGATE,
            "terminal_status": None,
            "grader_aggregate_fingerprints": (),
            "sensitivity_fingerprints": (),
            "result_hash": None,
            "artifacts": (),
            "manifest_fingerprint": "0" * 64,
        }
    )

    with pytest.raises(EvaluationIntegrityError, match="CALL_HISTORY"):
        initialize_v22_run_storage(tmp_path / "empty-stranded", manifest, files)


def test_empty_review_cannot_accept_a_nonempty_audit_concern(tmp_path: Path) -> None:
    lifecycle = _completed_lifecycle(empty_sources=True)
    manifest, files = _pending_state(lifecycle, 1)
    run_dir = tmp_path / "empty-review-audit-impossibility"
    initialize_v22_run_storage(run_dir, manifest, files)

    payload = {
        "schema_version": "2.2",
        "concerns": [
            {
                "target_proposal_ref": "P0001",
                "concern_type": "ambiguity",
                "passages": [
                    {"source_id": "rule-1", "quote": "small operators are excluded"}
                ],
                "explanation": "There is no proposal to audit.",
                "correction": None,
            }
        ],
        "audit_complete": True,
    }

    assert not v22_artifacts.preflight_v22_response(
        run_dir, manifest.calls[-1].call_id, payload
    ).valid


def test_mechanical_terminal_artifact_is_not_part_of_v22_grammar(tmp_path: Path) -> None:
    lifecycle = _completed_lifecycle(unresolved=True)
    manifest, files = _pending_state(lifecycle, 7, attempt=2)
    files["terminal-reason.json"] = canonical_json_bytes({"reason": "MECHANICAL_RESPONSE_INVALID"})

    with pytest.raises(EvaluationIntegrityError, match="UNBOUND_ARTIFACT"):
        initialize_v22_run_storage(tmp_path / "mechanical-terminal", manifest, files)


def test_replay_rejects_skipped_referee_and_grade_calls(tmp_path: Path) -> None:
    lifecycle = _completed_lifecycle(unresolved=True)
    for name, accepted_count in (
        ("referee", lifecycle.audit_end),
        ("grade", lifecycle.referee_end),
    ):
        manifest, files = _pending_state(lifecycle, accepted_count)
        skipped = _pending_call(lifecycle.manifest.calls[accepted_count + 1])
        files.pop(manifest.calls[-1].request_artifact_path)
        files[skipped.request_artifact_path] = lifecycle.files[skipped.request_artifact_path]
        manifest = manifest.model_copy(
            update={
                "phase": (
                    EvaluationPhaseV22.SOURCE_REFEREE
                    if name == "referee"
                    else (
                        EvaluationPhaseV22.ORDINARY_GRADING
                        if skipped.operation is EvaluatorOperationV22.ORDINARY_GRADE_FRAGMENT
                        else EvaluationPhaseV22.CONTESTED_GRADING
                    )
                ),
                "calls": (*manifest.calls[:-1], skipped),
                "artifacts": (),
                "manifest_fingerprint": "0" * 64,
            }
        )
        with pytest.raises(
            EvaluationIntegrityError, match=r"CALL_(?:HISTORY|REQUEST_BINDING)"
        ):
            initialize_v22_run_storage(tmp_path / f"skipped-{name}", manifest, files)


def test_replay_rejects_wrong_compiler_contract_even_when_manifest_is_resealed(
    tmp_path: Path,
) -> None:
    lifecycle = _completed_lifecycle()
    pending, files = _pending_state(lifecycle, 1)
    forged = pending.model_copy(
        update={
            "compiler_contract_fingerprint": "a" * 64,
            "artifacts": (),
            "manifest_fingerprint": "0" * 64,
        }
    )

    with pytest.raises(EvaluationIntegrityError, match="COMPILER_CONTRACT"):
        initialize_v22_run_storage(tmp_path / "contract-swap", forged, files)


@pytest.mark.parametrize(
    ("artifact_path", "mutate", "expected"),
    [
        (
            "aggregates/source-review.json",
            lambda raw: {
                **raw,
                "aggregate_fingerprint": "a" * 64,
            },
            "SOURCE_REVIEW_AGGREGATE",
        ),
        (
            "aggregates/referee.json",
            lambda raw: {
                **raw,
                "aggregate_fingerprint": "b" * 64,
            },
            "REFEREE_AGGREGATE",
        ),
        (
            "aggregates/grade-A-1.json",
            lambda raw: {
                **raw,
                "aggregate_fingerprint": "c" * 64,
            },
            "GRADER_AGGREGATE",
        ),
        (
            "sensitivities/A.json",
            lambda raw: {
                **raw,
                "reason_codes": ["RESEALED_TAMPER"],
                "sensitivity_fingerprint": "d" * 64,
            },
            "SENSITIVITY",
        ),
        (
            "result.json",
            lambda raw: {
                **raw,
                "result_fingerprint": "e" * 64,
            },
            "RESULT_BINDING",
        ),
    ],
)
def test_resealed_derived_artifacts_are_comparison_targets_not_replay_authority(
    tmp_path: Path,
    artifact_path: str,
    mutate: object,
    expected: str,
) -> None:
    lifecycle = _completed_lifecycle(unresolved=True)
    files = dict(lifecycle.files)
    raw = cast(dict[str, object], json.loads(files[artifact_path]))
    files[artifact_path] = canonical_json_bytes(cast(object, mutate)(raw))  # type: ignore[operator]
    manifest = lifecycle.manifest.model_copy(
        update={"artifacts": (), "manifest_fingerprint": "0" * 64}
    )

    with pytest.raises(EvaluationIntegrityError, match=expected):
        initialize_v22_run_storage(tmp_path / Path(artifact_path).stem, manifest, files)


def test_resealed_reconciliation_inside_result_cannot_override_compiler_replay(
    tmp_path: Path,
) -> None:
    lifecycle = _completed_lifecycle(unresolved=True)
    files = dict(lifecycle.files)
    raw = cast(dict[str, object], json.loads(files["result.json"]))
    reports = cast(list[dict[str, object]], raw["reports"])
    reconciliation = cast(dict[str, object], reports[0]["reconciliation"])
    reconciliation["reason_codes"] = ["RESEALED_TAMPER"]
    reconciliation["reconciliation_fingerprint"] = "a" * 64
    reports[0]["result_fingerprint"] = "b" * 64
    raw["result_fingerprint"] = "c" * 64
    files["result.json"] = canonical_json_bytes(raw)
    manifest = lifecycle.manifest.model_copy(
        update={
            "result_hash": "c" * 64,
            "artifacts": (),
            "manifest_fingerprint": "0" * 64,
        }
    )

    with pytest.raises(
        EvaluationIntegrityError, match=r"(?:MODEL_INVALID|RESULT_BINDING)"
    ):
        initialize_v22_run_storage(tmp_path / "reconciliation", manifest, files)


def test_response_fragment_and_frozen_source_swaps_fail_closed(tmp_path: Path) -> None:
    lifecycle = _completed_lifecycle(unresolved=True)
    manifest, files = _pending_state(lifecycle, 3)

    swapped = dict(files)
    first = lifecycle.manifest.calls[0]
    second = lifecycle.manifest.calls[1]
    assert first.response_artifact_path and second.response_artifact_path
    swapped[first.response_artifact_path], swapped[second.response_artifact_path] = (
        swapped[second.response_artifact_path],
        swapped[first.response_artifact_path],
    )
    with pytest.raises(EvaluationIntegrityError):
        initialize_v22_run_storage(tmp_path / "fragment-swap", manifest, swapped)

    source_swapped = dict(files)
    case = cast(dict[str, object], json.loads(source_swapped["inputs/case.json"]))
    case_payload = cast(dict[str, object], case["case"])
    sources = cast(list[dict[str, object]], case_payload["sources"])
    sources[0]["normalized_text"] = "Different frozen source."
    source_swapped["inputs/case.json"] = canonical_json_bytes(case)
    source_manifest = manifest.model_copy(
        update={
            "case_envelope_hash": sha256_digest(source_swapped["inputs/case.json"]),
            "artifacts": (),
            "manifest_fingerprint": "0" * 64,
        }
    )
    with pytest.raises(EvaluationIntegrityError, match="CASE_BUILD_BINDING"):
        initialize_v22_run_storage(tmp_path / "source-swap", source_manifest, source_swapped)


@pytest.mark.parametrize(
    ("accepted_count", "call_index", "field"),
    [
        (1, 0, "attempt"),
        (6, -1, "grader_lane"),
    ],
)
def test_stored_manifest_rejects_boolean_for_integer_wire_fields_before_normalization(
    tmp_path: Path, accepted_count: int, call_index: int, field: str
) -> None:
    lifecycle = _completed_lifecycle(unresolved=True)
    manifest, files = _pending_state(lifecycle, accepted_count)
    run_dir = tmp_path / f"raw-bool-{field}"
    initialize_v22_run_storage(run_dir, manifest, files)
    raw = cast(dict[str, object], json.loads((run_dir / "run-manifest.json").read_bytes()))
    calls = cast(list[dict[str, object]], raw["calls"])
    calls[call_index][field] = True
    # Keep the original fingerprint: the vulnerable parser normalizes True back
    # to integer 1 and therefore recreates the originally sealed typed manifest.
    (run_dir / "run-manifest.json").write_bytes(canonical_json_bytes(raw))

    assert not verify_v22_run(run_dir).valid
    with pytest.raises(EvaluationIntegrityError, match="MODEL_INVALID"):
        load_verified_v22_run(run_dir)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("call_id", "arbitrary-controller-call"),
        ("request_artifact_path", "renamed.json"),
        ("request_artifact_path", "requests/source-review-9999.json"),
        ("response_artifact_path", "responses/cross-step-response.json"),
    ],
)
def test_controller_call_identity_and_paths_are_reconstructed_not_trusted(
    tmp_path: Path, field: str, replacement: str
) -> None:
    lifecycle = _completed_lifecycle(unresolved=True)
    manifest, files = _pending_state(lifecycle, 1)
    call = manifest.calls[0]
    update: dict[str, object] = {field: replacement}
    moved = dict(files)
    if field == "request_artifact_path":
        moved[replacement] = moved.pop(call.request_artifact_path)
    elif field == "response_artifact_path":
        original = cast(str, call.response_artifact_path)
        moved[replacement] = moved.pop(original)
    forged_call = call.model_copy(update=update)
    forged = manifest.model_copy(
        update={
            "calls": (forged_call, *manifest.calls[1:]),
            "artifacts": (),
            "manifest_fingerprint": "0" * 64,
        }
    )

    with pytest.raises(EvaluationIntegrityError, match="CALL_HISTORY"):
        initialize_v22_run_storage(
            tmp_path / f"forged-{field}-{Path(replacement).stem}", forged, moved
        )


def test_duplicate_fragment_call_is_rejected_before_replay(tmp_path: Path) -> None:
    lifecycle = _completed_lifecycle(unresolved=True)
    manifest, files = _pending_state(lifecycle, 1)
    duplicate = manifest.model_construct(
        **{
            **manifest.__dict__,
            "calls": (manifest.calls[0], manifest.calls[0], manifest.calls[1]),
            "artifacts": (),
            "manifest_fingerprint": "0" * 64,
        }
    )

    with pytest.raises(EvaluationIntegrityError, match=r"(?:MODEL_INVALID|CALL_HISTORY)"):
        initialize_v22_run_storage(tmp_path / "duplicate-fragment", duplicate, files)


def test_inventory_missing_extra_symlink_duplicate_key_and_oversize_fail_closed(
    tmp_path: Path,
) -> None:
    lifecycle = _completed_lifecycle(unresolved=True)
    manifest, files = _pending_state(lifecycle, 3)

    missing_dir = tmp_path / "missing"
    initialize_v22_run_storage(missing_dir, manifest, files)
    (missing_dir / manifest.calls[-1].request_artifact_path).unlink()
    assert not verify_v22_run(missing_dir).valid

    extra_dir = tmp_path / "extra"
    initialize_v22_run_storage(extra_dir, manifest, files)
    (extra_dir / "unexpected.json").write_bytes(b"{}")
    assert not verify_v22_run(extra_dir).valid

    duplicate_dir = tmp_path / "duplicate-key"
    initialize_v22_run_storage(duplicate_dir, manifest, files)
    (duplicate_dir / "inputs/build.json").write_bytes(b'{"build":"x","build":"y"}')
    assert not verify_v22_run(duplicate_dir).valid

    oversized_dir = tmp_path / "oversized"
    initialize_v22_run_storage(oversized_dir, manifest, files)
    with (oversized_dir / "inputs/build.json").open("r+b") as handle:
        handle.truncate(16 * 1024 * 1024 + 1)
    assert not verify_v22_run(oversized_dir).valid

    if os.name == "posix":
        symlink_dir = tmp_path / "symlink"
        initialize_v22_run_storage(symlink_dir, manifest, files)
        outside = tmp_path / "outside.json"
        outside.write_bytes(b"{}")
        (symlink_dir / "linked.json").symlink_to(outside)
        assert not verify_v22_run(symlink_dir).valid


def test_preflight_contains_cyclic_payload_and_is_write_free(tmp_path: Path) -> None:
    lifecycle = _completed_lifecycle(unresolved=True)
    manifest, files = _pending_state(lifecycle, 1)
    run_dir = tmp_path / "preflight"
    initialize_v22_run_storage(run_dir, manifest, files)
    before = _snapshot(run_dir)
    call = manifest.calls[-1]
    valid = json.loads(
        lifecycle.files[cast(str, lifecycle.manifest.calls[1].response_artifact_path)]
    )
    cyclic: dict[str, object] = {}
    cyclic["self"] = cyclic

    assert v22_artifacts.preflight_v22_response(run_dir, call.call_id, valid).valid
    assert not v22_artifacts.preflight_v22_response(run_dir, call.call_id, cyclic).valid
    assert not v22_artifacts.preflight_v22_response(run_dir, call.call_id, {"bad": True}).valid
    assert _snapshot(run_dir) == before


@pytest.mark.parametrize("accepted_count", [1, 2, 4, 6, 7])
def test_preflight_accepts_the_exact_next_response_for_every_operation(
    tmp_path: Path, accepted_count: int
) -> None:
    lifecycle = _completed_lifecycle(unresolved=True)
    manifest, files = _pending_state(lifecycle, accepted_count)
    run_dir = tmp_path / f"preflight-operation-{accepted_count}"
    initialize_v22_run_storage(run_dir, manifest, files)
    pending = manifest.calls[-1]
    response_path = cast(
        str, lifecycle.manifest.calls[accepted_count].response_artifact_path
    )
    response = json.loads(lifecycle.files[response_path])

    assert v22_artifacts.preflight_v22_response(
        run_dir, pending.call_id, response
    ).valid


def test_transition_rolls_back_before_manifest_replace(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    run_dir, current, successor, additions = _review_to_audit_transition(tmp_path)
    before = _snapshot(run_dir)
    original = shared_artifacts._PosixRunStorage.atomic_write
    writes = 0

    def fail_second(storage: object, path: str, data: bytes, *, mutable: bool) -> bool:
        nonlocal writes
        writes += 1
        if writes == 2:
            raise OSError("injected artifact failure")
        return original(storage, path, data, mutable=mutable)  # type: ignore[arg-type]

    monkeypatch.setattr(shared_artifacts._PosixRunStorage, "atomic_write", fail_second)
    with pytest.raises(EvaluationIntegrityError):
        commit_v22_transition(run_dir, current.manifest_fingerprint, additions, successor)

    assert _snapshot(run_dir) == before
    assert verify_v22_run(run_dir).valid


def test_transition_restores_prior_manifest_after_post_replace_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    run_dir, current, successor, additions = _review_to_audit_transition(tmp_path)
    before = _snapshot(run_dir)
    original = shared_artifacts._PosixRunStorage.atomic_write
    failed = False

    def fail_after_manifest(storage: object, path: str, data: bytes, *, mutable: bool) -> bool:
        nonlocal failed
        created = original(storage, path, data, mutable=mutable)  # type: ignore[arg-type]
        if path == "run-manifest.json" and mutable and not failed:
            failed = True
            raise OSError("injected post-replace failure")
        return created

    monkeypatch.setattr(shared_artifacts._PosixRunStorage, "atomic_write", fail_after_manifest)
    with pytest.raises(EvaluationIntegrityError):
        commit_v22_transition(run_dir, current.manifest_fingerprint, additions, successor)

    assert failed
    assert _snapshot(run_dir) == before
    assert verify_v22_run(run_dir).valid


def test_transition_rolls_back_after_post_commit_verification_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    run_dir, current, successor, additions = _review_to_audit_transition(tmp_path)
    before = _snapshot(run_dir)
    original = v22_artifacts._verify_or_raise
    calls = 0

    def fail_third(storage: object) -> object:
        nonlocal calls
        calls += 1
        if calls == 3:
            raise EvaluationIntegrityError("injected post-commit verification failure")
        return original(storage)  # type: ignore[arg-type]

    monkeypatch.setattr(v22_artifacts, "_verify_or_raise", fail_third)
    with pytest.raises(EvaluationIntegrityError, match="post-commit verification"):
        commit_v22_transition(run_dir, current.manifest_fingerprint, additions, successor)

    assert calls == 3
    assert _snapshot(run_dir) == before
    assert verify_v22_run(run_dir).valid


def test_transition_preserves_same_byte_competitor_on_later_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    run_dir, current, successor, additions = _review_to_audit_transition(tmp_path)
    before = _snapshot(run_dir)
    target = next(path for path in additions if path.startswith("responses/"))
    original = shared_artifacts._PosixRunStorage.atomic_write
    collided = False

    def collide_then_fail(storage: object, path: str, data: bytes, *, mutable: bool) -> bool:
        nonlocal collided
        if path == target and not collided:
            assert original(storage, path, data, mutable=False)  # type: ignore[arg-type]
            collided = True
        if path == "run-manifest.json":
            raise OSError("injected manifest failure")
        return original(storage, path, data, mutable=mutable)  # type: ignore[arg-type]

    monkeypatch.setattr(shared_artifacts._PosixRunStorage, "atomic_write", collide_then_fail)
    with pytest.raises(EvaluationIntegrityError):
        commit_v22_transition(run_dir, current.manifest_fingerprint, additions, successor)

    expected = {**before, target: additions[target]}
    assert collided
    assert _snapshot(run_dir) == expected


@pytest.mark.parametrize("same_bytes", [True, False])
def test_rollback_preserves_replacement_competitor_inode(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, same_bytes: bool
) -> None:
    run_dir, current, successor, additions = _review_to_audit_transition(tmp_path)
    target = next(path for path in additions if path.startswith("responses/"))
    target_path = run_dir / target
    competitor = additions[target] if same_bytes else b'{"competitor":"different"}'
    original = shared_artifacts._PosixRunStorage.atomic_write
    replaced = False

    def replace_owned_then_fail(
        storage: object, path: str, data: bytes, *, mutable: bool
    ) -> bool:
        nonlocal replaced
        created = original(storage, path, data, mutable=mutable)  # type: ignore[arg-type]
        if path == target and created and not replaced:
            target_path.unlink()
            target_path.write_bytes(competitor)
            replaced = True
        if path == "run-manifest.json":
            raise OSError("injected manifest failure after competitor replacement")
        return created

    monkeypatch.setattr(
        shared_artifacts._PosixRunStorage, "atomic_write", replace_owned_then_fail
    )
    with pytest.raises(EvaluationIntegrityError):
        commit_v22_transition(run_dir, current.manifest_fingerprint, additions, successor)

    assert replaced
    assert target_path.read_bytes() == competitor


def test_rollback_preserves_same_byte_competitor_when_inode_numbers_alias(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Model immediate POSIX inode reuse without depending on one filesystem."""
    run_dir, current, successor, additions = _review_to_audit_transition(tmp_path)
    target = next(path for path in additions if path.startswith("responses/"))
    target_path = run_dir / target
    competitor = additions[target]
    original_write = shared_artifacts._PosixRunStorage.atomic_write
    original_read = shared_artifacts._PosixRunStorage._read_leaf_with_identity
    expected_identity: shared_artifacts._NodeIdentity | None = None
    competitor_identity: shared_artifacts._NodeIdentity | None = None

    def replace_owned_then_fail(
        storage: object, path: str, data: bytes, *, mutable: bool
    ) -> bool:
        nonlocal competitor_identity, expected_identity
        created = original_write(storage, path, data, mutable=mutable)  # type: ignore[arg-type]
        if path == target and created and competitor_identity is None:
            receipt = storage.atomic_write_receipt(path)  # type: ignore[attr-defined]
            assert receipt is not None and receipt.identity is not None
            expected_identity = receipt.identity
            target_path.unlink()
            target_path.write_bytes(competitor)
            observed = shared_artifacts._node_identity(target_path.stat())
            competitor_identity = replace(
                observed,
                device=expected_identity.device,
                inode=expected_identity.inode,
                changed_ns=max(observed.changed_ns, expected_identity.changed_ns) + 1,
            )
        if path == "run-manifest.json":
            raise OSError("injected manifest failure after competitor replacement")
        return created

    def read_with_reused_inode_number(
        storage: object,
        parent: int,
        name: str,
        artifact_path: str,
        *,
        max_bytes: int | None = None,
    ) -> tuple[bytes, shared_artifacts._NodeIdentity]:
        result = original_read(  # type: ignore[misc]
            storage,
            parent,
            name,
            artifact_path,
            max_bytes=max_bytes,
        )
        if competitor_identity is not None and artifact_path == target:
            assert result[0] == competitor
            return result[0], competitor_identity
        return result

    monkeypatch.setattr(
        shared_artifacts._PosixRunStorage, "atomic_write", replace_owned_then_fail
    )
    monkeypatch.setattr(
        shared_artifacts._PosixRunStorage,
        "_read_leaf_with_identity",
        read_with_reused_inode_number,
    )
    with pytest.raises(EvaluationIntegrityError):
        commit_v22_transition(run_dir, current.manifest_fingerprint, additions, successor)

    assert expected_identity is not None and competitor_identity is not None
    assert (competitor_identity.device, competitor_identity.inode) == (
        expected_identity.device,
        expected_identity.inode,
    )
    assert competitor_identity.changed_ns != expected_identity.changed_ns
    assert competitor_identity != expected_identity
    assert target_path.read_bytes() == competitor


@pytest.mark.skipif(os.name != "posix", reason="root inode replacement is POSIX-specific")
def test_transition_detects_root_inode_swap_without_mutating_replacement_tree(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    run_dir, current, successor, additions = _review_to_audit_transition(tmp_path)
    replacement = tmp_path / "replacement-root"
    replacement.mkdir()
    sentinel = replacement / "outside.txt"
    sentinel.write_bytes(b"outside\n")
    parked = tmp_path / "parked-root"
    original_link = shared_artifacts.os.link
    target_name = Path(next(path for path in additions if path.startswith("responses/"))).name
    swapped = False

    def racing_link(
        source: object,
        destination: object,
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> None:
        nonlocal swapped
        if not swapped and destination == target_name:
            run_dir.rename(parked)
            replacement.rename(run_dir)
            swapped = True
        original_link(
            source,
            destination,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
            follow_symlinks=follow_symlinks,
        )

    monkeypatch.setattr(shared_artifacts.os, "link", racing_link)
    with pytest.raises(EvaluationIntegrityError, match=r"(?:identity|changed|ROLLBACK_FAILED)"):
        commit_v22_transition(
            run_dir, current.manifest_fingerprint, additions, successor
        )

    assert swapped
    assert (run_dir / "outside.txt").read_bytes() == b"outside\n"
    assert all(not (run_dir / path).exists() for path in additions)


def test_transition_rechecks_root_and_inherited_files_at_commit_boundary(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    run_dir, current, successor, additions = _review_to_audit_transition(tmp_path)
    before = _snapshot(run_dir)
    original_verify = v22_artifacts._verify_or_raise
    calls = 0

    def stale_root(storage: object) -> object:
        nonlocal calls
        calls += 1
        replay = original_verify(storage)  # type: ignore[arg-type]
        if calls == 2:
            return replace(
                replay,
                manifest=replay.manifest.model_copy(update={"manifest_fingerprint": "a" * 64}),
            )
        return replay

    monkeypatch.setattr(v22_artifacts, "_verify_or_raise", stale_root)
    with pytest.raises(EvaluationIntegrityError, match="STALE_TRANSITION"):
        commit_v22_transition(run_dir, current.manifest_fingerprint, additions, successor)
    assert _snapshot(run_dir) == before


def test_transition_cannot_rewrite_an_already_accepted_call_record(tmp_path: Path) -> None:
    run_dir, current, successor, additions = _review_to_audit_transition(tmp_path)
    rewritten = successor.calls[0].model_copy(update={"attempt": 2})
    forged = successor.model_copy(
        update={
            "calls": (rewritten, *successor.calls[1:]),
            "artifacts": (),
            "manifest_fingerprint": "0" * 64,
        }
    )

    with pytest.raises(EvaluationIntegrityError, match="STALE_TRANSITION"):
        commit_v22_transition(
            run_dir, current.manifest_fingerprint, additions, forged
        )
