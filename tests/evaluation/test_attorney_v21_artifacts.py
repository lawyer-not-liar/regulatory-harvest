"""Protocol-2.1 artifact storage and replay boundaries."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import replace
from datetime import date
from pathlib import Path
from typing import cast

import pytest

from regulatory_harvest.evaluation import attorney_artifacts as legacy_artifacts
from regulatory_harvest.evaluation import attorney_v21_artifacts as v21_artifacts
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
from regulatory_harvest.evaluation.attorney_v21_artifacts import (
    V21_MANIFEST_PATH,
    commit_v21_transition,
    initialize_v21_run_storage,
    load_verified_v21_run,
    preflight_v21_response,
    verify_v21_run,
)
from regulatory_harvest.evaluation.attorney_v21_compiler import (
    aggregate_referee_decisions,
    build_referee_disputes,
    compile_baseline_v21,
    validate_referee_fragment,
)
from regulatory_harvest.evaluation.attorney_v21_models import (
    CanonicalBaselineV21,
    EvaluationCallRecordV21,
    EvaluationManifestV21,
    EvaluationPhaseV21,
    EvaluationResultV21,
    EvaluationTerminalStatusV21,
    EvaluatorOperationV21,
    EvaluatorRequestV21,
    EvaluatorResponseV21,
    RefereeDecisionV21,
    ReportResultV21,
    SourceAuditV21,
    SourceReviewV21,
)
from regulatory_harvest.evaluation.attorney_v21_requests import (
    build_contested_grade_request_v21,
    build_ordinary_grade_request_v21,
    build_source_audit_request_v21,
    build_source_referee_fragment_request,
    build_source_review_request_v21,
)
from regulatory_harvest.evaluation.attorney_v21_rubric import (
    RUBRIC_V21,
    aggregate_grader_lane,
    evaluate_outcome_sensitivity,
    ordinary_grade_batches,
    reconcile_grader_lanes,
    validate_grade_fragment_v21,
)
from regulatory_harvest.models import SourceQuality, SourceRole
from regulatory_harvest.storage import canonical_json_bytes, sha256_digest


def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _envelope(*, multi_batch: bool = False) -> CaseEnvelope:
    source_text = (
        "Rule 1: operators must file. "
        "Rule 2: operators must retain records. "
        "Rule 3: small operators are excluded."
        + (
            " Rule 4: operators must register."
            " Rule 5: operators must report annually."
            " Rule 6: operators must preserve receipts."
            " Rule 7: operators must disclose owners."
            if multi_batch
            else ""
        )
    )
    report_text = (
        "Operators must file. Operators must retain records."
        + (
            " Operators must register. Operators must report annually."
            " Operators must preserve receipts. Operators must disclose owners."
            if multi_batch
            else ""
        )
    )
    source = EvaluationSource(
        source_id="rule-1",
        title="Example Rule",
        normalized_text=source_text,
        content_hash=_hash_text(source_text),
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
        report_hash=_hash_text(report_text),
    )
    case = AttorneyEvaluationCase(
        case_id="v21-artifact-case",
        mode=EvaluationMode.CLOSED_UNIVERSE,
        question="What must operators do?",
        jurisdiction="Example State",
        as_of=date(2026, 8, 18),
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


def _proposal(statement: str, quote: str) -> dict[str, object]:
    return {
        "statement": statement,
        "kind": "obligation",
        "importance": "critical",
        "passages": [{"source_id": "rule-1", "quote": quote}],
        "dependency": None,
        "confidence": "clear",
        "rationale": "The source expressly states the obligation.",
    }


def _review(*, multi_batch: bool = False) -> SourceReviewV21:
    proposals = [
        _proposal("Operators must file.", "operators must file"),
        _proposal("Operators must retain records.", "operators must retain records"),
    ]
    if multi_batch:
        proposals.extend(
            (
                _proposal("Operators must register.", "operators must register"),
                _proposal("Operators must report annually.", "operators must report annually"),
                _proposal("Operators must preserve receipts.", "operators must preserve receipts"),
                _proposal("Operators must disclose owners.", "operators must disclose owners"),
            )
        )
    return SourceReviewV21.model_validate(
        {
            "schema_version": "2.1",
            "proposals": proposals,
        }
    )


def _audit() -> SourceAuditV21:
    return SourceAuditV21.model_validate(
        {
            "schema_version": "2.1",
            "concerns": [
                {
                    "target_proposal_ref": "P0001",
                    "concern_type": "incorrect_statement",
                    "passages": [
                        {"source_id": "rule-1", "quote": "small operators are excluded"}
                    ],
                    "explanation": "The filing obligation may have an exception.",
                    "correction": _proposal(
                        "Operators other than small operators must file.",
                        "small operators are excluded",
                    ),
                },
                {
                    "target_proposal_ref": "P0002",
                    "concern_type": "incorrect_statement",
                    "passages": [
                        {"source_id": "rule-1", "quote": "operators must retain records"}
                    ],
                    "explanation": "The retention wording requires referee confirmation.",
                    "correction": _proposal(
                        "Covered operators must retain records.",
                        "operators must retain records",
                    ),
                },
            ],
        },
        context={"proposal_refs": {"P0001", "P0002"}},
    )


def _response(
    request: EvaluatorRequestV21, payload: object
) -> tuple[EvaluatorResponseV21, bytes]:
    response = EvaluatorResponseV21.model_validate(
        {
            "schema_version": "2.1",
            "operation": request.operation,
            "request_fingerprint": request.request_fingerprint,
            "provider_name": "fixture",
            "model_name": "fixture-model",
            "judge_isolation": "scripted_fixture",
            "payload": cast(object, payload).model_dump(mode="json")
            if hasattr(payload, "model_dump")
            else payload,
        }
    )
    return response, canonical_json_bytes(response.model_dump(mode="json"))


def _call(
    call_id: str,
    request_path: str,
    request: EvaluatorRequestV21,
    response_path: str,
    response_bytes: bytes,
    *,
    dispute_id: str | None = None,
    batch_ref: str | None = None,
    contested_requirement_id: str | None = None,
    anonymous_label: str | None = None,
    grader_lane: int | None = None,
    batches: tuple[object, ...] = (),
    contested: tuple[object, ...] = (),
) -> EvaluationCallRecordV21:
    return EvaluationCallRecordV21.model_validate(
        {
            "call_id": call_id,
            "operation": request.operation,
            "state": "accepted",
            "attempt": 1,
            "request_artifact_path": request_path,
            "request_fingerprint": request.request_fingerprint,
            "response_artifact_path": response_path,
            "response_fingerprint": sha256_digest(response_bytes),
            "provider_name": "fixture",
            "model_name": "fixture-model",
            "judge_isolation": "scripted_fixture",
            "anonymous_label": anonymous_label,
            "grader_lane": grader_lane,
            "dispute_id": dispute_id,
            "batch_ref": batch_ref,
            "contested_requirement_id": contested_requirement_id,
        },
        context={
            "ordinary_grade_batches": batches,
            "contested_requirements": contested,
        },
    )


def _pending(
    call: EvaluationCallRecordV21,
    *,
    attempt: int = 1,
    batches: tuple[object, ...] = (),
    contested: tuple[object, ...] = (),
) -> EvaluationCallRecordV21:
    return EvaluationCallRecordV21.model_validate(
        {
            **call.model_dump(mode="json"),
            "state": "pending",
            "attempt": attempt,
            "response_artifact_path": None,
            "response_fingerprint": None,
            "provider_name": None,
            "model_name": None,
            "judge_isolation": None,
        },
        context={
            "ordinary_grade_batches": batches,
            "contested_requirements": contested,
        },
    )


def _completed_data(
    *, contested: bool = False, multi_batch: bool = False
) -> tuple[EvaluationManifestV21, dict[str, bytes], EvaluationResultV21]:
    envelope = _envelope(multi_batch=multi_batch)
    review = _review(multi_batch=multi_batch)
    audit = _audit()
    files: dict[str, bytes] = {
        "inputs/case.json": canonical_json_bytes(envelope.model_dump(mode="json")),
        "inputs/build.json": canonical_json_bytes({"build": "public-fixture-v2.1"}),
        "rubric.json": canonical_json_bytes(RUBRIC_V21.model_dump(mode="json")),
    }
    calls: list[EvaluationCallRecordV21] = []

    review_request = build_source_review_request_v21(envelope)
    _, review_response = _response(review_request, review)
    files["requests/source-review.json"] = canonical_json_bytes(
        review_request.model_dump(mode="json")
    )
    files["responses/source-review.json"] = review_response
    calls.append(
        _call(
            "source-review",
            "requests/source-review.json",
            review_request,
            "responses/source-review.json",
            review_response,
        )
    )

    audit_request = build_source_audit_request_v21(envelope, review)
    _, audit_response = _response(audit_request, audit)
    files["requests/source-audit.json"] = canonical_json_bytes(
        audit_request.model_dump(mode="json")
    )
    files["responses/source-audit.json"] = audit_response
    calls.append(
        _call(
            "source-audit",
            "requests/source-audit.json",
            audit_request,
            "responses/source-audit.json",
            audit_response,
        )
    )

    disputes = build_referee_disputes(envelope, review, audit)
    fragments = []
    for dispute in disputes:
        request = build_source_referee_fragment_request(
            envelope, dispute, controller_disputes=disputes
        )
        unresolved = contested
        decision = RefereeDecisionV21.model_validate(
            {
                "schema_version": "2.1",
                "decision": "unresolved" if unresolved else "accept_reviewer",
                "unresolved_reason": "SOURCE_AMBIGUITY" if unresolved else None,
                "evidence_refs": [dispute.evidence[0].evidence_ref],
                "rationale": "The source ambiguity remains material."
                if unresolved
                else "The reviewer statement is the better supported reading.",
            },
            context={"evidence_refs": {item.evidence_ref for item in dispute.evidence}},
        )
        _, response_bytes = _response(request, decision)
        request_path = f"requests/referee-{dispute.dispute_id}.json"
        response_path = f"responses/referee-{dispute.dispute_id}.json"
        files[request_path] = canonical_json_bytes(request.model_dump(mode="json"))
        files[response_path] = response_bytes
        fragments.append(
            validate_referee_fragment(
                dispute,
                decision,
                response_fingerprint=sha256_digest(response_bytes),
            )
        )
        calls.append(
            _call(
                f"referee-{dispute.dispute_id}",
                request_path,
                request,
                response_path,
                response_bytes,
                dispute_id=dispute.dispute_id,
            )
        )

    referee_aggregate = aggregate_referee_decisions(disputes, tuple(fragments))
    baseline = compile_baseline_v21(envelope, review, audit, referee_aggregate)
    files["aggregates/referee.json"] = canonical_json_bytes(
        referee_aggregate.model_dump(mode="json")
    )
    files["baseline.json"] = canonical_json_bytes(baseline.model_dump(mode="json"))

    report_text = envelope.case.candidates[0].report_text
    source_context = {
        source.source_id: source.normalized_text for source in envelope.case.sources
    }
    manifest_batches = tuple(
        batch
        for lane in (1, 2)
        for batch in ordinary_grade_batches(baseline, "A", lane)
    )
    ordinary_fragments_by_lane: dict[
        int, list[object]
    ] = {1: [], 2: []}
    contested_fragments_by_lane: dict[
        int, list[object]
    ] = {1: [], 2: []}
    for lane in (1, 2):
        lane_batches = ordinary_grade_batches(baseline, "A", lane)
        for batch in lane_batches:
            request = build_ordinary_grade_request_v21(
                baseline,
                batch,
                "A",
                lane,
                report_text,
                source_context,
                RUBRIC_V21,
            )
            raw_fragment = {
                "schema_version": "2.1",
                "anonymous_label": "A",
                "grader_lane": lane,
                "batch_ref": batch.batch_ref,
                "baseline_fingerprint": baseline.baseline_fingerprint,
                "report_fingerprint": _hash_text(report_text),
                "requirement_grades": [
                    {
                        "requirement_id": requirement_id,
                        "disposition": "met",
                        "report_passages": ["Operators must file."],
                        "rationale": "The report states the required obligation.",
                    }
                    for requirement_id in batch.requirement_ids
                ],
                "rationale": "Every requirement in this batch was graded.",
            }
            fragment = validate_grade_fragment_v21(baseline, raw_fragment, report_text)
            _, response_bytes = _response(request, fragment)
            request_path = f"requests/grade-{batch.batch_ref}.json"
            response_path = f"responses/grade-{batch.batch_ref}.json"
            files[request_path] = canonical_json_bytes(request.model_dump(mode="json"))
            files[response_path] = response_bytes
            ordinary_fragments_by_lane[lane].append(fragment)
            calls.append(
                _call(
                    f"grade-{batch.batch_ref}",
                    request_path,
                    request,
                    response_path,
                    response_bytes,
                    batch_ref=batch.batch_ref,
                    anonymous_label="A",
                    grader_lane=lane,
                    batches=manifest_batches,
                    contested=baseline.contested_requirements,
                )
            )
    for lane in (1, 2):
        for contested_requirement in baseline.contested_requirements:
            request = build_contested_grade_request_v21(
                baseline,
                contested_requirement,
                "A",
                lane,
                report_text,
                source_context,
                RUBRIC_V21,
            )
            raw_fragment = {
                "schema_version": "2.1",
                "anonymous_label": "A",
                "grader_lane": lane,
                "contested_requirement_id": (
                    contested_requirement.contested_requirement_id
                ),
                "baseline_fingerprint": baseline.baseline_fingerprint,
                "report_fingerprint": _hash_text(report_text),
                "reviewer_alternative_grade": {
                    "disposition": "met",
                    "report_passages": ["Operators must file."],
                    "rationale": "The report addresses the reviewer alternative.",
                },
                "auditor_alternative_grade": {
                    "disposition": "met",
                    "report_passages": ["Operators must file."],
                    "rationale": "The report addresses the auditor alternative.",
                },
                "ambiguity_disposition": "acknowledged",
                "rationale": "The report acknowledges the source ambiguity.",
            }
            fragment = validate_grade_fragment_v21(
                baseline, raw_fragment, report_text
            )
            _, response_bytes = _response(request, fragment)
            fragment_id = contested_requirement.contested_requirement_id
            request_path = f"requests/grade-contested-A-{lane}-{fragment_id}.json"
            response_path = f"responses/grade-contested-A-{lane}-{fragment_id}.json"
            files[request_path] = canonical_json_bytes(request.model_dump(mode="json"))
            files[response_path] = response_bytes
            contested_fragments_by_lane[lane].append(fragment)
            calls.append(
                _call(
                    f"grade-contested-A-{lane}-{fragment_id}",
                    request_path,
                    request,
                    response_path,
                    response_bytes,
                    contested_requirement_id=fragment_id,
                    anonymous_label="A",
                    grader_lane=lane,
                    batches=manifest_batches,
                    contested=baseline.contested_requirements,
                )
            )

    lane_aggregates = []
    for lane in (1, 2):
        aggregate = aggregate_grader_lane(
            baseline,
            "A",
            lane,
            cast(tuple[object, ...], tuple(ordinary_fragments_by_lane[lane])),
            cast(tuple[object, ...], tuple(contested_fragments_by_lane[lane])),
        )
        lane_aggregates.append(aggregate)
        files[f"aggregates/grade-A-{lane}.json"] = canonical_json_bytes(
            aggregate.model_dump(mode="json")
        )

    reconciliation = reconcile_grader_lanes(
        baseline, lane_aggregates[0], lane_aggregates[1], RUBRIC_V21
    )
    sensitivity = evaluate_outcome_sensitivity(baseline, reconciliation, RUBRIC_V21)
    files["sensitivities/A.json"] = canonical_json_bytes(
        sensitivity.model_dump(mode="json")
    )
    report_payload: dict[str, object] = {
        "anonymous_label": "A",
        "reconciliation": reconciliation.model_dump(mode="json"),
        "sensitivity": sensitivity.model_dump(mode="json"),
    }
    report = ReportResultV21(
        anonymous_label="A",
        reconciliation=reconciliation,
        sensitivity=sensitivity,
        result_fingerprint=sha256_digest(canonical_json_bytes(report_payload)),
    )
    result_payload: dict[str, object] = {
        "schema_version": "2.1",
        "rubric": RUBRIC_V21.model_dump(mode="json"),
        "baseline": baseline.model_dump(mode="json"),
        "reports": [report.model_dump(mode="json")],
        "comparison": None,
        "terminal_status": "COMPLETED",
    }
    result = EvaluationResultV21(
        schema_version="2.1",
        rubric=RUBRIC_V21,
        baseline=baseline,
        reports=(report,),
        comparison=None,
        terminal_status=EvaluationTerminalStatusV21.COMPLETED,
        result_fingerprint=sha256_digest(canonical_json_bytes(result_payload)),
    )
    files["result.json"] = canonical_json_bytes(result.model_dump(mode="json"))
    context = {
        "ordinary_grade_batches": manifest_batches,
        "contested_requirements": baseline.contested_requirements,
    }
    manifest = EvaluationManifestV21.model_validate(
        {
            "protocol_version": "2.1",
            "case_fingerprint": envelope.case_fingerprint,
            "case_envelope_hash": sha256_digest(files["inputs/case.json"]),
            "build_fingerprint": sha256_digest(files["inputs/build.json"]),
            "rubric_fingerprint": sha256_digest(files["rubric.json"]),
            "compiler_version": "semantic-compiler-v2.1",
            "baseline_fingerprint": baseline.baseline_fingerprint,
            "referee_aggregate_fingerprint": referee_aggregate.aggregate_fingerprint,
            "grader_aggregate_fingerprints": [
                item.aggregate_fingerprint for item in lane_aggregates
            ],
            "sensitivity_fingerprints": [sensitivity.sensitivity_fingerprint],
            "result_hash": result.result_fingerprint,
            "phase": "completed",
            "terminal_status": "COMPLETED",
            "calls": [item.model_dump(mode="json") for item in calls],
            "artifacts": [],
            "referee_disputes": [item.model_dump(mode="json") for item in disputes],
            "ordinary_grade_batches": [
                item.model_dump(mode="json") for item in manifest_batches
            ],
            "manifest_fingerprint": "0" * 64,
        },
        context=context,
    )
    return manifest, files, result


def _snapshot(run_dir: Path) -> dict[str, bytes]:
    return {
        path.relative_to(run_dir).as_posix(): path.read_bytes()
        for path in sorted(run_dir.rglob("*"))
        if path.is_file() and not path.is_symlink()
    }


def _files_for_calls(
    source: dict[str, bytes], calls: tuple[EvaluationCallRecordV21, ...]
) -> dict[str, bytes]:
    keep = {"inputs/case.json", "inputs/build.json", "rubric.json"}
    keep.update(call.request_artifact_path for call in calls)
    keep.update(
        cast(str, call.response_artifact_path)
        for call in calls
        if call.response_artifact_path is not None
    )
    return {path: data for path, data in source.items() if path in keep}


def _manifest_only(run_dir: Path, payload: object) -> Path:
    run_dir.mkdir()
    (run_dir / "run-manifest.json").write_bytes(canonical_json_bytes(payload))
    return run_dir


def _mechanical_files(
    source_files: dict[str, bytes],
    calls: tuple[EvaluationCallRecordV21, ...],
    next_request_path: str,
) -> dict[str, bytes]:
    files = _files_for_calls(source_files, calls)
    files[next_request_path] = source_files[next_request_path]
    files["terminal-reason.json"] = canonical_json_bytes(
        {"reason": "MECHANICAL_RESPONSE_INVALID"}
    )
    return files


def _partial_grade_case(
    *, operation: EvaluatorOperationV21, mutation: str
) -> tuple[
    EvaluationManifestV21,
    dict[str, bytes],
    EvaluationManifestV21,
    dict[str, bytes],
    str,
    dict[str, object],
]:
    completed, source_files, _ = _completed_data(
        contested=operation is EvaluatorOperationV21.CONTESTED_GRADE_FRAGMENT,
        multi_batch=operation is EvaluatorOperationV21.ORDINARY_GRADE_FRAGMENT,
    )
    baseline = CanonicalBaselineV21.model_validate(
        json.loads(source_files["baseline.json"])
    )
    matching = [
        (index, call)
        for index, call in enumerate(completed.calls)
        if call.operation is operation
    ]
    target_index, target = matching[0]
    next_call = completed.calls[target_index + 1]
    assert next_call.operation is operation

    raw_response = cast(
        dict[str, object],
        json.loads(source_files[cast(str, target.response_artifact_path)]),
    )
    if mutation == "cross_lane":
        donor = next(
            call
            for _, call in matching
            if call.grader_lane != target.grader_lane
            and (
                call.batch_ref is None
                or call.batch_ref.endswith(cast(str, target.batch_ref)[-4:])
            )
            and (
                call.contested_requirement_id is None
                or call.contested_requirement_id == target.contested_requirement_id
            )
        )
        donor_response = cast(
            dict[str, object],
            json.loads(source_files[cast(str, donor.response_artifact_path)]),
        )
        raw_response["payload"] = donor_response["payload"]
    elif mutation == "cross_label":
        payload = cast(dict[str, object], raw_response["payload"])
        payload["anonymous_label"] = "B"
        if target.batch_ref is not None:
            payload["batch_ref"] = target.batch_ref.replace("GB-A-", "GB-B-")
    elif mutation in {"wrong_batch", "wrong_contested_id"}:
        donor_response = cast(
            dict[str, object],
            json.loads(source_files[cast(str, next_call.response_artifact_path)]),
        )
        raw_response["payload"] = donor_response["payload"]
    else:
        raise AssertionError(f"unknown mutation: {mutation}")

    pending_calls = (
        *completed.calls[:target_index],
        _pending(
            target,
            batches=completed.ordinary_grade_batches,
            contested=baseline.contested_requirements,
        ),
    )
    phase = (
        EvaluationPhaseV21.ORDINARY_GRADING
        if operation is EvaluatorOperationV21.ORDINARY_GRADE_FRAGMENT
        else EvaluationPhaseV21.CONTESTED_GRADING
    )
    pending_manifest = completed.model_copy(
        update={
            "phase": phase,
            "terminal_status": None,
            "calls": pending_calls,
            "grader_aggregate_fingerprints": (),
            "sensitivity_fingerprints": (),
            "result_hash": None,
            "artifacts": (),
            "manifest_fingerprint": "0" * 64,
        }
    )
    pending_files = _files_for_calls(source_files, pending_calls)
    pending_files.update(
        {
            "aggregates/referee.json": source_files["aggregates/referee.json"],
            "baseline.json": source_files["baseline.json"],
        }
    )

    response_bytes = canonical_json_bytes(raw_response)
    accepted_target = target.model_copy(
        update={"response_fingerprint": sha256_digest(response_bytes)}
    )
    accepted_calls = (
        *completed.calls[:target_index],
        accepted_target,
        _pending(
            next_call,
            batches=completed.ordinary_grade_batches,
            contested=baseline.contested_requirements,
        ),
    )
    accepted_manifest = pending_manifest.model_copy(update={"calls": accepted_calls})
    accepted_files = _files_for_calls(source_files, accepted_calls)
    accepted_files[cast(str, target.response_artifact_path)] = response_bytes
    accepted_files.update(
        {
            "aggregates/referee.json": source_files["aggregates/referee.json"],
            "baseline.json": source_files["baseline.json"],
        }
    )
    return (
        pending_manifest,
        pending_files,
        accepted_manifest,
        accepted_files,
        target.call_id,
        raw_response,
    )


def test_protocol_detector_preserves_all_recognized_generations(tmp_path: Path) -> None:
    legacy = _manifest_only(tmp_path / "v13", {"schema_version": "1.3"})
    v20 = _manifest_only(tmp_path / "v20", {"protocol_version": "2.0"})
    v21 = _manifest_only(tmp_path / "v21", {"protocol_version": "2.1"})

    assert detect_evaluation_protocol(legacy) == "1.3"
    assert detect_evaluation_protocol(v20) == "2.0"
    assert detect_evaluation_protocol(v21) == "2.1"


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"schema_version": "2.1"},
        {"protocol_version": "2.2"},
        {"schema_version": "1.3", "protocol_version": "2.1"},
    ],
)
def test_protocol_detector_fails_closed_for_unknown_or_ambiguous_manifests(
    tmp_path: Path, payload: object
) -> None:
    run_dir = _manifest_only(tmp_path / "unknown", payload)

    with pytest.raises(EvaluationIntegrityError, match="EVALUATION_PROTOCOL_UNSUPPORTED"):
        detect_evaluation_protocol(run_dir)


def test_initialization_replays_a_completed_v21_run(tmp_path: Path) -> None:
    manifest, files, expected = _completed_data()
    run_dir = tmp_path / "completed"

    committed = initialize_v21_run_storage(run_dir, manifest, files)
    reloaded, result = load_verified_v21_run(run_dir)

    assert committed.manifest_fingerprint != "0" * 64
    assert reloaded == committed
    assert result == expected
    assert verify_v21_run(run_dir).valid
    assert detect_evaluation_protocol(run_dir) == "2.1"


def test_verified_context_is_one_immutable_run_bound_snapshot(tmp_path: Path) -> None:
    manifest, files, _ = _completed_data()
    first_dir = tmp_path / "context-first"
    second_dir = tmp_path / "context-second"
    initialize_v21_run_storage(first_dir, manifest, files)
    initialize_v21_run_storage(second_dir, manifest, files)

    first = v21_artifacts.load_verified_v21_context(first_dir)
    second = v21_artifacts.load_verified_v21_context(second_dir)
    first_envelope = first.load_case_envelope()

    assert first.case_envelope_bytes == files["inputs/case.json"]
    assert first_envelope.case_fingerprint == first.manifest.case_fingerprint
    assert first.source_context == {
        source.source_id: source.normalized_text for source in first_envelope.case.sources
    }
    assert first.source_context is not second.source_context
    with pytest.raises(TypeError):
        cast(dict[str, str], first.source_context)["rule-1"] = "tampered"
    first_envelope.assignments.clear()
    assert first.load_case_envelope().assignments

    (first_dir / "inputs/case.json").write_bytes(files["inputs/build.json"])
    with pytest.raises(EvaluationIntegrityError):
        v21_artifacts.load_verified_v21_context(first_dir)
    assert v21_artifacts.load_verified_v21_context(second_dir) == second


def test_verifier_accepts_partial_referee_and_grade_histories(tmp_path: Path) -> None:
    completed, source_files, _ = _completed_data()
    calls = completed.calls
    referee_calls = (*calls[:3], _pending(calls[3], attempt=2))
    referee_manifest = completed.model_copy(
        update={
            "phase": EvaluationPhaseV21.SOURCE_REFEREE,
            "terminal_status": None,
            "calls": referee_calls,
            "baseline_fingerprint": None,
            "referee_aggregate_fingerprint": None,
            "ordinary_grade_batches": (),
            "grader_aggregate_fingerprints": (),
            "sensitivity_fingerprints": (),
            "result_hash": None,
            "artifacts": (),
            "manifest_fingerprint": "0" * 64,
        }
    )
    referee_files = _files_for_calls(source_files, referee_calls)
    initialize_v21_run_storage(tmp_path / "partial-referee", referee_manifest, referee_files)
    assert verify_v21_run(tmp_path / "partial-referee").valid

    grade_calls = (
        *calls[:5],
        _pending(
            calls[5],
            batches=completed.ordinary_grade_batches,
        ),
    )
    grade_manifest = completed.model_copy(
        update={
            "phase": EvaluationPhaseV21.ORDINARY_GRADING,
            "terminal_status": None,
            "calls": grade_calls,
            "grader_aggregate_fingerprints": (
                completed.grader_aggregate_fingerprints[0],
            ),
            "sensitivity_fingerprints": (),
            "result_hash": None,
            "artifacts": (),
            "manifest_fingerprint": "0" * 64,
        }
    )
    grade_files = _files_for_calls(source_files, grade_calls)
    for path in ("aggregates/referee.json", "baseline.json", "aggregates/grade-A-1.json"):
        grade_files[path] = source_files[path]
    initialize_v21_run_storage(tmp_path / "partial-grade", grade_manifest, grade_files)
    assert verify_v21_run(tmp_path / "partial-grade").valid


def test_replay_grade_steps_are_report_major_with_mixed_grading_lane() -> None:
    """Replay must emit the same partial-grade sequence as the live controller."""
    envelope = _envelope(multi_batch=True)
    review = _review(multi_batch=True)
    audit = SourceAuditV21.model_validate(
        {
            "schema_version": "2.1",
            "concerns": [
                {
                    "target_proposal_ref": "P0002",
                    "concern_type": "ambiguity",
                    "passages": [
                        {"source_id": "rule-1", "quote": "operators must retain records"}
                    ],
                    "explanation": "The retention duty has two plausible readings.",
                    "correction": None,
                }
            ],
        },
        context={"proposal_refs": {f"P{number:04d}" for number in range(1, 7)}},
    )
    disputes = build_referee_disputes(envelope, review, audit)
    assert len(disputes) == 1
    decision = RefereeDecisionV21.model_validate(
        {
            "schema_version": "2.1",
            "decision": "unresolved",
            "unresolved_reason": "SOURCE_AMBIGUITY",
            "evidence_refs": [disputes[0].evidence[0].evidence_ref],
            "rationale": "The sealed record leaves this duty unresolved.",
        },
        context={"evidence_refs": {item.evidence_ref for item in disputes[0].evidence}},
    )
    fragment = validate_referee_fragment(disputes[0], decision, response_fingerprint="0" * 64)
    baseline = compile_baseline_v21(
        envelope,
        review,
        audit,
        aggregate_referee_decisions(disputes, (fragment,)),
    )
    batches = tuple(
        batch
        for lane in (1, 2)
        for batch in ordinary_grade_batches(baseline, "A", lane)
    )

    steps = v21_artifacts._grade_steps(batches, baseline.contested_requirements, ("A",))

    assert [
        (step.operation.value, step.grader_lane, step.batch_ref, step.contested_requirement_id)
        for step in steps
    ] == [
        ("ordinary_grade_fragment", 1, "GB-A-1-0001", None),
        ("contested_grade_fragment", 1, None, "CONT-0001"),
        ("ordinary_grade_fragment", 2, "GB-A-2-0001", None),
        ("contested_grade_fragment", 2, None, "CONT-0001"),
    ]


def test_verifier_replays_partial_and_completed_contested_grading(tmp_path: Path) -> None:
    completed, source_files, expected = _completed_data(contested=True)
    baseline = CanonicalBaselineV21.model_validate(
        json.loads(source_files["baseline.json"])
    )
    calls = completed.calls
    partial_calls = (
        *calls[:-1],
        _pending(
            calls[-1],
            batches=completed.ordinary_grade_batches,
            contested=baseline.contested_requirements,
        ),
    )
    partial = completed.model_copy(
        update={
            "phase": EvaluationPhaseV21.CONTESTED_GRADING,
            "terminal_status": None,
            "calls": partial_calls,
            "grader_aggregate_fingerprints": (
                completed.grader_aggregate_fingerprints[0],
            ),
            "sensitivity_fingerprints": (),
            "result_hash": None,
            "artifacts": (),
            "manifest_fingerprint": "0" * 64,
        }
    )
    partial_files = _files_for_calls(source_files, partial_calls)
    for path in (
        "aggregates/referee.json",
        "baseline.json",
        "aggregates/grade-A-1.json",
    ):
        partial_files[path] = source_files[path]

    initialize_v21_run_storage(tmp_path / "partial-contested", partial, partial_files)
    initialize_v21_run_storage(tmp_path / "completed-contested", completed, source_files)

    assert verify_v21_run(tmp_path / "partial-contested").valid
    _, result = load_verified_v21_run(tmp_path / "completed-contested")
    assert result == expected


@pytest.mark.parametrize(
    ("operation", "mutation", "shape"),
    [
        (EvaluatorOperationV21.ORDINARY_GRADE_FRAGMENT, "cross_lane", "raw"),
        (EvaluatorOperationV21.ORDINARY_GRADE_FRAGMENT, "cross_label", "typed"),
        (EvaluatorOperationV21.ORDINARY_GRADE_FRAGMENT, "wrong_batch", "constructed"),
        (EvaluatorOperationV21.CONTESTED_GRADE_FRAGMENT, "cross_lane", "raw"),
        (EvaluatorOperationV21.CONTESTED_GRADE_FRAGMENT, "cross_label", "typed"),
        (
            EvaluatorOperationV21.CONTESTED_GRADE_FRAGMENT,
            "wrong_contested_id",
            "constructed",
        ),
    ],
)
def test_preflight_binds_grade_fragment_identity_to_pending_step(
    tmp_path: Path,
    operation: EvaluatorOperationV21,
    mutation: str,
    shape: str,
) -> None:
    pending, files, _, _, call_id, raw_response = _partial_grade_case(
        operation=operation, mutation=mutation
    )
    run_dir = tmp_path / f"preflight-{operation.value}-{mutation}"
    initialize_v21_run_storage(run_dir, pending, files)
    response: object
    if shape == "raw":
        response = raw_response
    elif shape == "typed":
        response = EvaluatorResponseV21.model_validate(raw_response)
    else:
        response = EvaluatorResponseV21.model_construct(**raw_response)

    assert not preflight_v21_response(run_dir, call_id, response).valid


@pytest.mark.parametrize(
    ("operation", "mutation"),
    [
        (EvaluatorOperationV21.ORDINARY_GRADE_FRAGMENT, "cross_lane"),
        (EvaluatorOperationV21.ORDINARY_GRADE_FRAGMENT, "cross_label"),
        (EvaluatorOperationV21.ORDINARY_GRADE_FRAGMENT, "wrong_batch"),
        (EvaluatorOperationV21.CONTESTED_GRADE_FRAGMENT, "cross_lane"),
        (EvaluatorOperationV21.CONTESTED_GRADE_FRAGMENT, "cross_label"),
        (EvaluatorOperationV21.CONTESTED_GRADE_FRAGMENT, "wrong_contested_id"),
    ],
)
def test_replay_binds_partial_grade_fragment_identity_to_accepted_step(
    tmp_path: Path,
    operation: EvaluatorOperationV21,
    mutation: str,
) -> None:
    _, _, accepted, files, _, _ = _partial_grade_case(
        operation=operation, mutation=mutation
    )

    with pytest.raises(EvaluationIntegrityError, match="CALL_RESPONSE_BINDING"):
        initialize_v21_run_storage(
            tmp_path / f"replay-{operation.value}-{mutation}", accepted, files
        )


def test_verifier_rejects_swapped_referee_fragment(tmp_path: Path) -> None:
    manifest, files, _ = _completed_data()
    first_path = "responses/referee-D0001.json"
    second_path = "responses/referee-D0002.json"
    files[first_path], files[second_path] = files[second_path], files[first_path]
    calls = list(manifest.calls)
    first_index, second_index = 2, 3
    calls[first_index] = calls[first_index].model_copy(
        update={"response_fingerprint": sha256_digest(files[first_path])}
    )
    calls[second_index] = calls[second_index].model_copy(
        update={"response_fingerprint": sha256_digest(files[second_path])}
    )
    malformed = manifest.model_copy(
        update={"calls": tuple(calls), "manifest_fingerprint": "0" * 64}
    )

    with pytest.raises(EvaluationIntegrityError, match="CALL_RESPONSE_BINDING"):
        initialize_v21_run_storage(tmp_path / "swapped-referee", malformed, files)


def test_verifier_wraps_invalid_reconstructed_dispute_inventory(tmp_path: Path) -> None:
    manifest, files, _ = _completed_data()
    path = "responses/source-audit.json"
    payload = cast(dict[str, object], json.loads(files[path]))
    response_payload = cast(dict[str, object], payload["payload"])
    concerns = cast(list[dict[str, object]], response_payload["concerns"])
    passages = cast(list[dict[str, object]], concerns[0]["passages"])
    passages[0]["quote"] = "not present in the frozen source"
    files[path] = canonical_json_bytes(payload)
    calls = list(manifest.calls)
    calls[1] = calls[1].model_copy(
        update={"response_fingerprint": sha256_digest(files[path])}
    )
    malformed = manifest.model_copy(
        update={"calls": tuple(calls), "manifest_fingerprint": "0" * 64}
    )

    with pytest.raises(EvaluationIntegrityError, match="REFEREE_INVENTORY"):
        initialize_v21_run_storage(tmp_path / "invalid-disputes", malformed, files)


@pytest.mark.parametrize("shape", ["duplicate", "skipped"])
def test_verifier_rejects_duplicate_or_skipped_fragment_history(
    tmp_path: Path, shape: str
) -> None:
    completed, source_files, _ = _completed_data()
    calls = list(completed.calls[:4])
    if shape == "duplicate":
        duplicate = _pending(calls[2]).model_copy(update={"call_id": "referee-duplicate"})
        calls = [*calls[:3], duplicate]
    else:
        calls = [*calls[:2], _pending(calls[3])]
    files = _files_for_calls(source_files, tuple(calls))
    malformed = completed.model_copy(
        update={
            "phase": EvaluationPhaseV21.SOURCE_REFEREE,
            "terminal_status": None,
            "calls": tuple(calls),
            "baseline_fingerprint": None,
            "referee_aggregate_fingerprint": None,
            "ordinary_grade_batches": (),
            "grader_aggregate_fingerprints": (),
            "sensitivity_fingerprints": (),
            "result_hash": None,
            "artifacts": (),
            "manifest_fingerprint": "0" * 64,
        }
    )

    with pytest.raises(EvaluationIntegrityError, match="CALL_HISTORY"):
        initialize_v21_run_storage(tmp_path / shape, malformed, files)


def test_verifier_recomputes_lane_aggregate_sensitivity_and_result_bindings(
    tmp_path: Path,
) -> None:
    manifest, source_files, _ = _completed_data()
    cases = [
        (
            "aggregate",
            "aggregates/grade-A-1.json",
            "aggregate_fingerprint",
            "grader_aggregate_fingerprints",
        ),
        (
            "sensitivity",
            "sensitivities/A.json",
            "sensitivity_fingerprint",
            "sensitivity_fingerprints",
        ),
        ("result", "result.json", "result_fingerprint", "result_hash"),
    ]
    for name, path, field, manifest_field in cases:
        files = dict(source_files)
        payload = cast(dict[str, object], json.loads(files[path]))
        payload[field] = "0" * 64
        files[path] = canonical_json_bytes(payload)
        value: object = (
            "0" * 64
            if manifest_field == "result_hash"
            else tuple(
                "0" * 64 if index == 0 else item
                for index, item in enumerate(getattr(manifest, manifest_field))
            )
        )
        malformed = manifest.model_copy(
            update={
                manifest_field: value,
                "manifest_fingerprint": "0" * 64,
            }
        )
        with pytest.raises(EvaluationIntegrityError):
            initialize_v21_run_storage(tmp_path / name, malformed, files)


def test_verifier_rejects_partial_aggregate_and_result_shaped_junk(tmp_path: Path) -> None:
    manifest, source_files, _ = _completed_data()
    missing = dict(source_files)
    del missing["aggregates/grade-A-2.json"]
    with pytest.raises(EvaluationIntegrityError, match="GRADER_AGGREGATE"):
        initialize_v21_run_storage(tmp_path / "missing-aggregate", manifest, missing)

    junk = dict(source_files)
    junk["results/extra.json"] = canonical_json_bytes(
        {"schema_version": "2.1", "result_fingerprint": "f" * 64}
    )
    with pytest.raises(EvaluationIntegrityError, match="RESULT"):
        initialize_v21_run_storage(tmp_path / "result-junk", manifest, junk)


def test_terminal_mechanical_state_retains_only_the_exact_next_request(
    tmp_path: Path,
) -> None:
    completed, source_files, _ = _completed_data()
    calls = (completed.calls[0],)
    files = _mechanical_files(
        source_files, calls, completed.calls[1].request_artifact_path
    )
    stopped = completed.model_copy(
        update={
            "phase": EvaluationPhaseV21.INCONCLUSIVE_MECHANICAL,
            "terminal_status": EvaluationTerminalStatusV21.INCONCLUSIVE_MECHANICAL,
            "calls": calls,
            "referee_disputes": (),
            "baseline_fingerprint": None,
            "referee_aggregate_fingerprint": None,
            "ordinary_grade_batches": (),
            "grader_aggregate_fingerprints": (),
            "sensitivity_fingerprints": (),
            "result_hash": None,
            "artifacts": (),
            "manifest_fingerprint": "0" * 64,
        }
    )
    initialize_v21_run_storage(tmp_path / "mechanical", stopped, files)
    assert verify_v21_run(tmp_path / "mechanical").valid

    files["responses/rejected.json"] = canonical_json_bytes(
        {"schema_version": "2.1", "rejected": True}
    )
    with pytest.raises(EvaluationIntegrityError, match="UNBOUND_RESPONSE"):
        initialize_v21_run_storage(tmp_path / "mechanical-response", stopped, files)


def test_terminal_mechanical_during_grading_retains_prior_seals(tmp_path: Path) -> None:
    completed, source_files, _ = _completed_data()
    accepted = completed.calls[:5]
    next_request = completed.calls[5].request_artifact_path
    files = _mechanical_files(source_files, accepted, next_request)
    for path in (
        "aggregates/referee.json",
        "baseline.json",
        "aggregates/grade-A-1.json",
    ):
        files[path] = source_files[path]
    stopped = completed.model_copy(
        update={
            "phase": EvaluationPhaseV21.INCONCLUSIVE_MECHANICAL,
            "terminal_status": EvaluationTerminalStatusV21.INCONCLUSIVE_MECHANICAL,
            "calls": accepted,
            "grader_aggregate_fingerprints": (
                completed.grader_aggregate_fingerprints[0],
            ),
            "sensitivity_fingerprints": (),
            "result_hash": None,
            "artifacts": (),
            "manifest_fingerprint": "0" * 64,
        }
    )

    initialize_v21_run_storage(tmp_path / "mechanical-grade", stopped, files)

    assert verify_v21_run(tmp_path / "mechanical-grade").valid


@pytest.mark.parametrize("missing", ["request", "reason"])
def test_terminal_mechanical_requires_reason_and_exact_orphan_request(
    tmp_path: Path, missing: str
) -> None:
    completed, source_files, _ = _completed_data()
    calls = (completed.calls[0],)
    next_request = completed.calls[1].request_artifact_path
    files = _mechanical_files(source_files, calls, next_request)
    del files[next_request if missing == "request" else "terminal-reason.json"]
    stopped = completed.model_copy(
        update={
            "phase": EvaluationPhaseV21.INCONCLUSIVE_MECHANICAL,
            "terminal_status": EvaluationTerminalStatusV21.INCONCLUSIVE_MECHANICAL,
            "calls": calls,
            "referee_disputes": (),
            "baseline_fingerprint": None,
            "referee_aggregate_fingerprint": None,
            "ordinary_grade_batches": (),
            "grader_aggregate_fingerprints": (),
            "sensitivity_fingerprints": (),
            "result_hash": None,
            "artifacts": (),
            "manifest_fingerprint": "0" * 64,
        }
    )

    with pytest.raises(EvaluationIntegrityError, match=r"TERMINAL|UNBOUND_REQUEST"):
        initialize_v21_run_storage(tmp_path / f"missing-{missing}", stopped, files)


@pytest.mark.parametrize("shape", ["incorrect", "extra"])
def test_terminal_mechanical_rejects_incorrect_or_extra_orphan_request(
    tmp_path: Path, shape: str
) -> None:
    completed, source_files, _ = _completed_data()
    calls = (completed.calls[0],)
    next_request = completed.calls[1].request_artifact_path
    files = _mechanical_files(source_files, calls, next_request)
    if shape == "incorrect":
        files[next_request] = source_files[completed.calls[0].request_artifact_path]
    else:
        files["requests/extra.json"] = source_files[
            completed.calls[0].request_artifact_path
        ]
    stopped = completed.model_copy(
        update={
            "phase": EvaluationPhaseV21.INCONCLUSIVE_MECHANICAL,
            "terminal_status": EvaluationTerminalStatusV21.INCONCLUSIVE_MECHANICAL,
            "calls": calls,
            "referee_disputes": (),
            "baseline_fingerprint": None,
            "referee_aggregate_fingerprint": None,
            "ordinary_grade_batches": (),
            "grader_aggregate_fingerprints": (),
            "sensitivity_fingerprints": (),
            "result_hash": None,
            "artifacts": (),
            "manifest_fingerprint": "0" * 64,
        }
    )

    with pytest.raises(EvaluationIntegrityError, match="UNBOUND_REQUEST"):
        initialize_v21_run_storage(tmp_path / shape, stopped, files)


def test_terminal_mechanical_rejects_complete_substantive_history(tmp_path: Path) -> None:
    completed, source_files, _ = _completed_data()
    files = dict(source_files)
    del files["result.json"]
    files["terminal-reason.json"] = canonical_json_bytes(
        {"reason": "MECHANICAL_RESPONSE_INVALID"}
    )
    stopped = completed.model_copy(
        update={
            "phase": EvaluationPhaseV21.INCONCLUSIVE_MECHANICAL,
            "terminal_status": EvaluationTerminalStatusV21.INCONCLUSIVE_MECHANICAL,
            "result_hash": None,
            "artifacts": (),
            "manifest_fingerprint": "0" * 64,
        }
    )

    with pytest.raises(EvaluationIntegrityError, match="CALL_HISTORY"):
        initialize_v21_run_storage(tmp_path / "mechanical-complete", stopped, files)


def _review_to_audit_transition(
    tmp_path: Path,
) -> tuple[
    Path,
    EvaluationManifestV21,
    EvaluationManifestV21,
    dict[str, bytes],
]:
    completed, source_files, _ = _completed_data()
    pending_review = _pending(completed.calls[0])
    initial = completed.model_copy(
        update={
            "phase": EvaluationPhaseV21.SOURCE_REVIEW,
            "terminal_status": None,
            "calls": (pending_review,),
            "referee_disputes": (),
            "baseline_fingerprint": None,
            "referee_aggregate_fingerprint": None,
            "ordinary_grade_batches": (),
            "grader_aggregate_fingerprints": (),
            "sensitivity_fingerprints": (),
            "result_hash": None,
            "artifacts": (),
            "manifest_fingerprint": "0" * 64,
        }
    )
    initial_files = _files_for_calls(source_files, (pending_review,))
    run_dir = tmp_path / "transition"
    committed_initial = initialize_v21_run_storage(run_dir, initial, initial_files)
    accepted_then_pending = (
        completed.calls[0],
        _pending(completed.calls[1]),
    )
    successor = initial.model_copy(
        update={
            "phase": EvaluationPhaseV21.SOURCE_AUDIT,
            "calls": accepted_then_pending,
            "artifacts": (),
            "manifest_fingerprint": "0" * 64,
        }
    )
    additions = {
        completed.calls[0].response_artifact_path: source_files[
            cast(str, completed.calls[0].response_artifact_path)
        ],
        completed.calls[1].request_artifact_path: source_files[
            completed.calls[1].request_artifact_path
        ],
    }
    return run_dir, committed_initial, successor, cast(dict[str, bytes], additions)


def _ordinary_grade_transition(
    tmp_path: Path,
) -> tuple[Path, EvaluationManifestV21, EvaluationManifestV21, dict[str, bytes]]:
    completed, source_files, _ = _completed_data(multi_batch=True)
    baseline = CanonicalBaselineV21.model_validate(json.loads(source_files["baseline.json"]))
    target_index, target = next(
        (index, call)
        for index, call in enumerate(completed.calls)
        if call.operation is EvaluatorOperationV21.ORDINARY_GRADE_FRAGMENT
    )
    next_call = completed.calls[target_index + 1]
    assert next_call.operation is EvaluatorOperationV21.ORDINARY_GRADE_FRAGMENT
    pending_target = _pending(
        target,
        batches=completed.ordinary_grade_batches,
        contested=baseline.contested_requirements,
    )
    initial_calls = (*completed.calls[:target_index], pending_target)
    initial = completed.model_copy(
        update={
            "phase": EvaluationPhaseV21.ORDINARY_GRADING,
            "terminal_status": None,
            "calls": initial_calls,
            "grader_aggregate_fingerprints": (),
            "sensitivity_fingerprints": (),
            "result_hash": None,
            "artifacts": (),
            "manifest_fingerprint": "0" * 64,
        }
    )
    initial_files = _files_for_calls(source_files, initial_calls)
    initial_files.update(
        {
            "aggregates/referee.json": source_files["aggregates/referee.json"],
            "baseline.json": source_files["baseline.json"],
        }
    )
    run_dir = tmp_path / "ordinary-transition"
    committed_initial = initialize_v21_run_storage(run_dir, initial, initial_files)
    accepted_then_pending = (
        *completed.calls[: target_index + 1],
        _pending(
            next_call,
            batches=completed.ordinary_grade_batches,
            contested=baseline.contested_requirements,
        ),
    )
    successor = initial.model_copy(
        update={
            "calls": accepted_then_pending,
            "artifacts": (),
            "manifest_fingerprint": "0" * 64,
        }
    )
    additions = {
        cast(str, target.response_artifact_path): source_files[
            cast(str, target.response_artifact_path)
        ],
        next_call.request_artifact_path: source_files[next_call.request_artifact_path],
    }
    return run_dir, committed_initial, successor, additions


def test_transition_rolls_back_response_and_request_on_artifact_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    run_dir, current, successor, additions = _review_to_audit_transition(tmp_path)
    before = _snapshot(run_dir)
    original = legacy_artifacts._PosixRunStorage.atomic_write
    writes = 0

    def fail_second(
        storage: object, path: str, data: bytes, *, mutable: bool
    ) -> bool:
        nonlocal writes
        writes += 1
        if writes == 2:
            raise OSError("injected artifact failure")
        return original(storage, path, data, mutable=mutable)  # type: ignore[arg-type]

    monkeypatch.setattr(legacy_artifacts._PosixRunStorage, "atomic_write", fail_second)
    with pytest.raises(EvaluationIntegrityError, match="evaluation storage"):
        commit_v21_transition(
            run_dir, current.manifest_fingerprint, additions, successor
        )

    assert _snapshot(run_dir) == before
    assert verify_v21_run(run_dir).valid


def test_transition_rolls_back_immutable_after_post_install_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    run_dir, current, successor, additions = _review_to_audit_transition(tmp_path)
    before = _snapshot(run_dir)
    original = legacy_artifacts._PosixRunStorage.atomic_write
    failed = False

    def fail_after_immutable_install(
        storage: object, path: str, data: bytes, *, mutable: bool
    ) -> bool:
        nonlocal failed
        created = original(storage, path, data, mutable=mutable)  # type: ignore[arg-type]
        if path != V21_MANIFEST_PATH and not failed:
            failed = True
            assert created
            failure = OSError("injected post-install directory fsync failure")
            raise legacy_artifacts._AtomicWriteOwnershipError(path, failure) from failure
        return created

    monkeypatch.setattr(
        legacy_artifacts._PosixRunStorage,
        "atomic_write",
        fail_after_immutable_install,
    )
    with pytest.raises(EvaluationIntegrityError, match="evaluation storage"):
        commit_v21_transition(
            run_dir, current.manifest_fingerprint, additions, successor
        )

    assert failed
    assert _snapshot(run_dir) == before
    assert verify_v21_run(run_dir).valid


@pytest.mark.skipif(os.name != "posix", reason="link ownership is POSIX-specific")
def test_posix_immutable_write_never_leaves_unreported_path_after_link_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    run_dir = tmp_path / "post-link-failure"
    storage = legacy_artifacts._PosixRunStorage.open(run_dir, initialize=True)
    original_fsync = legacy_artifacts.os.fsync
    original_link = legacy_artifacts.os.link
    linked = False

    def record_link(*args: object, **kwargs: object) -> None:
        nonlocal linked
        original_link(*args, **kwargs)  # type: ignore[arg-type]
        linked = True

    def fail_post_link_directory_fsync(descriptor: int) -> None:
        if linked and stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise OSError("injected post-link directory fsync failure")
        original_fsync(descriptor)

    monkeypatch.setattr(legacy_artifacts.os, "link", record_link)
    monkeypatch.setattr(legacy_artifacts.os, "fsync", fail_post_link_directory_fsync)
    try:
        with pytest.raises(
            legacy_artifacts._AtomicWriteOwnershipError
        ) as raised:
            storage.atomic_write("owned.json", b"{}", mutable=False)
    finally:
        storage.close()

    assert linked
    assert raised.value.created is True
    assert (run_dir / "owned.json").read_bytes() == b"{}"


def test_transition_rolls_back_new_files_when_manifest_write_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    run_dir, current, successor, additions = _review_to_audit_transition(tmp_path)
    before = _snapshot(run_dir)
    original = legacy_artifacts._PosixRunStorage.atomic_write

    def fail_manifest(
        storage: object, path: str, data: bytes, *, mutable: bool
    ) -> bool:
        if path == V21_MANIFEST_PATH:
            raise OSError("injected manifest failure")
        return original(storage, path, data, mutable=mutable)  # type: ignore[arg-type]

    monkeypatch.setattr(legacy_artifacts._PosixRunStorage, "atomic_write", fail_manifest)
    with pytest.raises(EvaluationIntegrityError, match="evaluation storage"):
        commit_v21_transition(
            run_dir, current.manifest_fingerprint, additions, successor
        )

    assert _snapshot(run_dir) == before
    assert verify_v21_run(run_dir).valid


def test_transition_tolerates_same_byte_create_race_and_rejects_stale_writer(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    run_dir, current, successor, additions = _review_to_audit_transition(tmp_path)
    original = legacy_artifacts._PosixRunStorage.atomic_write
    raced = False

    def same_byte_race(
        storage: object, path: str, data: bytes, *, mutable: bool
    ) -> bool:
        nonlocal raced
        if not raced and path != V21_MANIFEST_PATH:
            raced = True
            original(storage, path, data, mutable=False)  # type: ignore[arg-type]
        return original(storage, path, data, mutable=mutable)  # type: ignore[arg-type]

    monkeypatch.setattr(legacy_artifacts._PosixRunStorage, "atomic_write", same_byte_race)
    commit_v21_transition(run_dir, current.manifest_fingerprint, additions, successor)
    assert verify_v21_run(run_dir).valid

    with pytest.raises(EvaluationIntegrityError, match="EVALUATOR_V21_STALE_TRANSITION"):
        commit_v21_transition(run_dir, current.manifest_fingerprint, additions, successor)


@pytest.mark.parametrize("stage", ("source_review", "ordinary_grade"))
def test_transition_never_removes_same_byte_competitor_after_later_failure(
    stage: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    transition = (
        _review_to_audit_transition(tmp_path)
        if stage == "source_review"
        else _ordinary_grade_transition(tmp_path)
    )
    run_dir, current, successor, additions = transition
    before = _snapshot(run_dir)
    target_path = next(path for path in additions if path.startswith("responses/"))
    original = legacy_artifacts._PosixRunStorage.atomic_write
    collided = False

    def same_byte_competitor_then_manifest_failure(
        storage: object, path: str, data: bytes, *, mutable: bool
    ) -> bool:
        nonlocal collided
        if path == target_path and not collided:
            assert original(storage, path, data, mutable=False)  # type: ignore[arg-type]
            collided = True
        if path == V21_MANIFEST_PATH:
            raise OSError("injected manifest failure after same-byte collision")
        return original(storage, path, data, mutable=mutable)  # type: ignore[arg-type]

    monkeypatch.setattr(
        legacy_artifacts._PosixRunStorage,
        "atomic_write",
        same_byte_competitor_then_manifest_failure,
    )
    with pytest.raises(EvaluationIntegrityError, match="evaluation storage"):
        commit_v21_transition(
            run_dir, current.manifest_fingerprint, additions, successor
        )

    expected = {**before, target_path: additions[target_path]}
    assert collided
    assert _snapshot(run_dir) == expected
    assert (run_dir / target_path).read_bytes() == additions[target_path]
    assert (run_dir / V21_MANIFEST_PATH).read_bytes() == before[V21_MANIFEST_PATH]


@pytest.mark.skipif(os.name != "posix", reason="descriptor-relative link is POSIX-specific")
def test_transition_never_clobbers_different_byte_competing_immutable_create(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    run_dir, current, successor, additions = _review_to_audit_transition(tmp_path)
    before = _snapshot(run_dir)
    target_path = sorted(additions)[0]
    target_name = Path(target_path).name
    competing_bytes = b"competing immutable bytes\n"
    original_link = os.link
    raced = False

    def competing_create(
        source: str,
        destination: str,
        *args: object,
        **kwargs: object,
    ) -> None:
        nonlocal raced
        destination_fd = cast(int, kwargs["dst_dir_fd"])
        if not raced and destination == target_name:
            raced = True
            descriptor = os.open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=destination_fd,
            )
            try:
                os.write(descriptor, competing_bytes)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        original_link(source, destination, *args, **kwargs)

    monkeypatch.setattr(os, "link", competing_create)
    with pytest.raises(EvaluationIntegrityError, match="immutable artifact differs"):
        commit_v21_transition(
            run_dir, current.manifest_fingerprint, additions, successor
        )

    after = _snapshot(run_dir)
    assert raced
    assert after[V21_MANIFEST_PATH] == before[V21_MANIFEST_PATH]
    assert after[target_path] == competing_bytes
    assert all(path == target_path or path not in after for path in additions)


def test_transition_restores_prior_manifest_after_post_replace_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    run_dir, current, successor, additions = _review_to_audit_transition(tmp_path)
    before = _snapshot(run_dir)
    original = legacy_artifacts._PosixRunStorage.atomic_write
    failed = False

    def fail_after_manifest_replace(
        storage: object, path: str, data: bytes, *, mutable: bool
    ) -> bool:
        nonlocal failed
        created = original(storage, path, data, mutable=mutable)  # type: ignore[arg-type]
        if path == V21_MANIFEST_PATH and mutable and not failed:
            failed = True
            raise OSError("injected post-replacement fsync failure")
        return created

    monkeypatch.setattr(
        legacy_artifacts._PosixRunStorage,
        "atomic_write",
        fail_after_manifest_replace,
    )
    with pytest.raises(EvaluationIntegrityError, match="evaluation storage"):
        commit_v21_transition(
            run_dir, current.manifest_fingerprint, additions, successor
        )

    assert failed
    assert _snapshot(run_dir) == before
    assert verify_v21_run(run_dir).valid


def test_transition_rechecks_expected_root_at_commit_boundary(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    run_dir, current, successor, additions = _review_to_audit_transition(tmp_path)
    before = _snapshot(run_dir)
    original = v21_artifacts._verify_or_raise
    calls = 0

    def race(storage: object) -> object:
        nonlocal calls
        calls += 1
        replay = original(storage)  # type: ignore[arg-type]
        if calls == 2:
            return replace(
                replay,
                manifest=replay.manifest.model_copy(
                    update={"manifest_fingerprint": "a" * 64}
                ),
            )
        return replay

    monkeypatch.setattr(v21_artifacts, "_verify_or_raise", race)

    with pytest.raises(EvaluationIntegrityError, match="EVALUATOR_V21_STALE_TRANSITION"):
        commit_v21_transition(
            run_dir, current.manifest_fingerprint, additions, successor
        )

    assert _snapshot(run_dir) == before


def test_transition_detects_inherited_artifact_race_before_manifest_replace(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    run_dir, current, successor, additions = _review_to_audit_transition(tmp_path)
    original = legacy_artifacts._PosixRunStorage.atomic_write
    raced = False

    def artifact_race(
        storage: object, path: str, data: bytes, *, mutable: bool
    ) -> bool:
        nonlocal raced
        created = original(storage, path, data, mutable=mutable)  # type: ignore[arg-type]
        if not raced and path != V21_MANIFEST_PATH:
            raced = True
            original(
                storage,
                "inputs/build.json",
                canonical_json_bytes({"build": "concurrent-writer"}),
                mutable=True,
            )  # type: ignore[arg-type]
        return created

    monkeypatch.setattr(legacy_artifacts._PosixRunStorage, "atomic_write", artifact_race)

    with pytest.raises(EvaluationIntegrityError, match="EVALUATOR_V21_STALE_TRANSITION"):
        commit_v21_transition(
            run_dir, current.manifest_fingerprint, additions, successor
        )

    assert not any(path in _snapshot(run_dir) for path in additions)


def test_preflight_is_write_free_for_malformed_and_cyclic_responses(tmp_path: Path) -> None:
    run_dir, _, _, additions = _review_to_audit_transition(tmp_path)
    before = _snapshot(run_dir)
    cyclic: dict[str, object] = {}
    cyclic["self"] = cyclic

    accepted = json.loads(additions["responses/source-review.json"])
    assert preflight_v21_response(run_dir, "source-review", accepted).valid
    assert not preflight_v21_response(run_dir, "source-review", {"bad": True}).valid
    assert not preflight_v21_response(run_dir, "source-review", cyclic).valid
    assert _snapshot(run_dir) == before


def test_verifier_rejects_empty_special_and_unbound_inventory_entries(
    tmp_path: Path,
) -> None:
    manifest, files, _ = _completed_data()
    run_dir = tmp_path / "inventory"
    initialize_v21_run_storage(run_dir, manifest, files)
    (run_dir / "empty").mkdir()
    assert not verify_v21_run(run_dir).valid

    run_dir = tmp_path / "fifo"
    initialize_v21_run_storage(run_dir, manifest, files)
    if hasattr(os, "mkfifo"):
        os.mkfifo(run_dir / "pipe")
        assert not verify_v21_run(run_dir).valid

    extra = dict(files)
    extra["unexpected.txt"] = b"unexpected"
    with pytest.raises(EvaluationIntegrityError, match="UNBOUND_ARTIFACT"):
        initialize_v21_run_storage(tmp_path / "extra", manifest, extra)


@pytest.mark.skipif(os.name != "posix", reason="symlink containment is POSIX-specific")
def test_verifier_rejects_symlink_and_root_alias(tmp_path: Path) -> None:
    manifest, files, _ = _completed_data()
    run_dir = tmp_path / "symlink"
    initialize_v21_run_storage(run_dir, manifest, files)
    outside = tmp_path / "outside.json"
    outside.write_bytes(b"{}")
    (run_dir / "linked.json").symlink_to(outside)
    assert not verify_v21_run(run_dir).valid

    alias = tmp_path / "alias"
    alias.symlink_to(run_dir, target_is_directory=True)
    assert not verify_v21_run(alias).valid


def test_deep_and_malformed_manifest_state_fail_before_writes(tmp_path: Path) -> None:
    deep: object = None
    for _ in range(70):
        deep = [deep]
    deep_run = _manifest_only(tmp_path / "deep", {"protocol_version": "2.1", "x": deep})
    with pytest.raises(EvaluationIntegrityError, match="EVALUATION_PROTOCOL_UNSUPPORTED"):
        detect_evaluation_protocol(deep_run)

    manifest, files, _ = _completed_data()
    malformed = manifest.model_construct(
        **{
            **manifest.__dict__,
            "phase": EvaluationPhaseV21.COMPLETED,
            "terminal_status": None,
        }
    )
    with pytest.raises(EvaluationIntegrityError, match="MODEL_INVALID"):
        initialize_v21_run_storage(tmp_path / "malformed", malformed, files)
    assert not (tmp_path / "malformed").exists() or _snapshot(tmp_path / "malformed") == {}


@pytest.mark.parametrize(
    ("path", "sparse"),
    [
        (V21_MANIFEST_PATH, False),
        ("baseline.json", True),
        ("inputs/build.json", False),
    ],
)
def test_verification_refuses_oversized_files_before_json_allocation(
    tmp_path: Path, path: str, sparse: bool
) -> None:
    manifest, files, _ = _completed_data()
    run_dir = tmp_path / f"oversized-{Path(path).stem}"
    initialize_v21_run_storage(run_dir, manifest, files)
    target = run_dir / path
    if sparse:
        with target.open("r+b") as handle:
            handle.truncate(16 * 1024 * 1024 + 1)
    else:
        target.write_bytes(b"x" * (16 * 1024 * 1024 + 1))

    assert not verify_v21_run(run_dir).valid
    if path == V21_MANIFEST_PATH:
        with pytest.raises(EvaluationIntegrityError, match="UNSUPPORTED"):
            detect_evaluation_protocol(run_dir)


def test_initialization_refuses_oversized_artifact_without_writing(tmp_path: Path) -> None:
    manifest, files, _ = _completed_data()
    files["oversized.bin"] = b"x" * (16 * 1024 * 1024 + 1)
    run_dir = tmp_path / "oversized-no-write"

    with pytest.raises(EvaluationIntegrityError, match="JSON_SIZE"):
        initialize_v21_run_storage(run_dir, manifest, files)

    assert not run_dir.exists() or _snapshot(run_dir) == {}
