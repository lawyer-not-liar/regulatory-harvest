"""Protocol-2.0 artifact storage and replay boundaries."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import date
from pathlib import Path
from typing import cast

import pytest
from test_attorney_artifacts import _FakeWin32API

from regulatory_harvest.evaluation import attorney_artifacts as legacy_artifacts
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
from regulatory_harvest.evaluation.attorney_v2_artifacts import (
    V2_MANIFEST_PATH,
    _require_phase_consistency,
    commit_v2_transition,
    detect_evaluation_protocol,
    initialize_v2_run_storage,
    load_verified_v2_run,
    preflight_v2_response,
    verify_v2_run,
)
from regulatory_harvest.evaluation.attorney_v2_models import (
    CanonicalBaselineV2,
    ComparisonResultV2,
    EvaluationCallRecordV2,
    EvaluationManifestV2,
    EvaluationPhaseV2,
    EvaluationResultV2,
    EvaluationTerminalStatusV2,
    EvaluatorOperationV2,
    EvaluatorRequestV2,
    EvaluatorResponseV2,
    GradeResponseV2,
    ReconciledGradeV2,
    ReportResultV2,
    RubricV2,
    evaluator_request_fingerprint,
)
from regulatory_harvest.models import SourceQuality, SourceRole
from regulatory_harvest.storage import canonical_json_bytes, sha256_digest


def _hash(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _rubric_bytes() -> bytes:
    return canonical_json_bytes(
        RubricV2(
            version="attorney-eval-v2",
            importance_weights={"critical": 3, "material": 2, "supporting": 1},
            critical_recall_floor=1.0,
            weighted_coverage_floor=0.9,
            material_unsupported_assertions_allowed=0,
        ).model_dump(mode="json")
    )


def _request() -> EvaluatorRequestV2:
    request = EvaluatorRequestV2(
        operation=EvaluatorOperationV2.SOURCE_REVIEW,
        request_fingerprint="0" * 64,
        system_instructions="Review frozen sources.",
        json_schema={"type": "object"},
        payload={"case": "frozen"},
    )
    return request.model_copy(
        update={"request_fingerprint": evaluator_request_fingerprint(request)}
    )


def _audit_request() -> EvaluatorRequestV2:
    request = EvaluatorRequestV2(
        operation=EvaluatorOperationV2.SOURCE_AUDIT,
        request_fingerprint="0" * 64,
        system_instructions="Audit the source review.",
        json_schema={"type": "object"},
        payload={"case": "frozen"},
    )
    return request.model_copy(
        update={"request_fingerprint": evaluator_request_fingerprint(request)}
    )


def _envelope(*, labels: int = 1) -> CaseEnvelope:
    source_text = "A covered operator must file a notice."
    report_text = "The operator files a notice."
    source = EvaluationSource(
        source_id="rule-1",
        title="Example Rule",
        normalized_text=source_text,
        content_hash=_hash(source_text.encode("utf-8")),
        jurisdiction="Example State",
        authority_type="regulation",
        source_role=SourceRole.OFFICIAL_PRIMARY,
        source_quality=SourceQuality.PRIMARY,
        completeness="complete",
        language="en",
    )
    case = AttorneyEvaluationCase(
        case_id="example-case",
        mode=EvaluationMode.CLOSED_UNIVERSE,
        question="What does the example rule require?",
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
        candidates=[
            CandidateReport(
                candidate_id="candidate",
                role=CandidateRole.CANDIDATE,
                report_text=report_text,
                report_hash=_hash(report_text.encode("utf-8")),
            )
        ],
    )
    candidates = [
        CandidateReport(
            candidate_id="candidate",
            role=CandidateRole.CANDIDATE,
            report_text=report_text,
            report_hash=_hash(report_text.encode("utf-8")),
        )
    ]
    assignments = [BlindAssignment(anonymous_label="A", candidate_id="candidate")]
    if labels == 2:
        candidates.append(
            CandidateReport(
                candidate_id="comparator",
                role=CandidateRole.COMPARATOR,
                report_text=report_text,
                report_hash=_hash(report_text.encode("utf-8")),
            )
        )
        assignments.append(BlindAssignment(anonymous_label="B", candidate_id="comparator"))
    case = case.model_copy(update={"candidates": candidates})
    return CaseEnvelope(
        case=case,
        assignments=assignments,
        case_fingerprint=model_fingerprint(case),
        seed_fingerprint="f" * 64,
    )


def _files(*, response: bool = False) -> dict[str, bytes]:
    envelope = _envelope()
    build_bytes = canonical_json_bytes({"build": "public-fixture-v2"})
    files = {
        "inputs/case.json": canonical_json_bytes(envelope.model_dump(mode="json")),
        "inputs/build.json": build_bytes,
        "rubric.json": _rubric_bytes(),
        "requests/call-1.json": canonical_json_bytes(_request().model_dump(mode="json")),
    }
    if response:
        files["requests/call-2.json"] = canonical_json_bytes(
            _audit_request().model_dump(mode="json")
        )
        files["responses/call-1.json"] = canonical_json_bytes(
            {
                "schema_version": "2.0",
                "operation": "source_review",
                "request_fingerprint": _request().request_fingerprint,
                "provider_name": "fixture",
                "model_name": "fixture-model",
                "judge_isolation": "scripted_fixture",
                "payload": {"schema_version": "2.0", "proposals": []},
            }
        )
    return files


def _manifest(*, accepted: bool = False) -> EvaluationManifestV2:
    files = _files(response=accepted)
    call = EvaluationCallRecordV2(
        call_id="call-1",
        operation=EvaluatorOperationV2.SOURCE_REVIEW,
        state="accepted" if accepted else "pending",
        request_artifact_path="requests/call-1.json",
        request_fingerprint=_request().request_fingerprint,
        response_artifact_path="responses/call-1.json" if accepted else None,
        response_fingerprint=_hash(files["responses/call-1.json"]) if accepted else None,
        provider_name="fixture" if accepted else None,
        model_name="fixture-model" if accepted else None,
        judge_isolation="scripted_fixture" if accepted else None,
    )
    calls = [call]
    if accepted:
        calls.append(
            EvaluationCallRecordV2(
                call_id="call-2",
                operation=EvaluatorOperationV2.SOURCE_AUDIT,
                state="pending",
                request_artifact_path="requests/call-2.json",
                request_fingerprint=_audit_request().request_fingerprint,
            )
        )
    return EvaluationManifestV2(
        case_fingerprint=_envelope().case_fingerprint,
        case_envelope_hash=_hash(files["inputs/case.json"]),
        build_fingerprint=_hash(files["inputs/build.json"]),
        rubric_fingerprint=_hash(files["rubric.json"]),
        compiler_version="semantic-compiler-v2",
        phase=(EvaluationPhaseV2.SOURCE_AUDIT if accepted else EvaluationPhaseV2.SOURCE_REVIEW),
        calls=calls,
        artifacts=[],
        manifest_fingerprint="0" * 64,
    )


def _request_for(
    operation: EvaluatorOperationV2, *, label: str | None = None
) -> EvaluatorRequestV2:
    request = EvaluatorRequestV2(
        operation=operation,
        request_fingerprint="0" * 64,
        system_instructions=f"Fixture {operation.value} request.",
        json_schema={"type": "object"},
        payload={"fixture": operation.value},
        safe_metadata={} if label is None else {"anonymous_label": label},
    )
    return request.model_copy(
        update={"request_fingerprint": evaluator_request_fingerprint(request)}
    )


def _sealed_baseline(envelope: CaseEnvelope) -> CanonicalBaselineV2:
    payload = {
        "schema_version": "2.0",
        "case_fingerprint": envelope.case_fingerprint,
        "requirements": [],
        "relationships": [],
        "unresolved_dispute_ids": [],
    }
    return CanonicalBaselineV2(
        **payload,
        baseline_fingerprint=sha256_digest(canonical_json_bytes(payload)),
    )


def _report_result(baseline: CanonicalBaselineV2, label: str) -> ReportResultV2:
    grade = GradeResponseV2.validate_for_baseline(
        {
            "schema_version": "2.0",
            "anonymous_label": label,
            "baseline_fingerprint": baseline.baseline_fingerprint,
            "requirement_grades": [],
            "unsupported_assertions": [],
        },
        baseline,
    )
    reconciliation = ReconciledGradeV2.validate_for_baseline(
        {
            "anonymous_label": label,
            "disposition": "PASS",
            "reason_codes": [],
            "grader_responses": [grade, grade],
        },
        baseline,
    )
    payload = {
        "anonymous_label": label,
        "absolute_disposition": "PASS",
        "reconciliation": reconciliation,
        "critical_recall": 1.0,
        "weighted_coverage": 1.0,
        "reason_codes": (),
    }
    return ReportResultV2(
        **payload,
        result_fingerprint=sha256_digest(canonical_json_bytes(payload)),
    )


def _completed_run_data(
    *, labels: int
) -> tuple[EvaluationManifestV2, dict[str, bytes], EvaluationResultV2]:
    envelope = _envelope(labels=labels)
    baseline = _sealed_baseline(envelope)
    reports = [_report_result(baseline, "A")]
    if labels == 2:
        reports.append(_report_result(baseline, "B"))
    comparison = (
        None
        if labels == 1
        else ComparisonResultV2(disposition="tie", rationale="Fixture reports tie.")
    )
    provisional = EvaluationResultV2(
        rubric=RubricV2.model_validate(json.loads(_rubric_bytes())),
        baseline=baseline,
        reports=reports,
        comparison=comparison,
        result_fingerprint="0" * 64,
    )
    result = provisional.model_copy(
        update={
            "result_fingerprint": sha256_digest(
                canonical_json_bytes(
                    provisional.model_dump(mode="json", exclude={"result_fingerprint"})
                )
            )
        }
    )
    operations: list[tuple[str, EvaluatorOperationV2, str | None]] = [
        ("source-review", EvaluatorOperationV2.SOURCE_REVIEW, None),
        ("source-audit", EvaluatorOperationV2.SOURCE_AUDIT, None),
        ("grade-A-1", EvaluatorOperationV2.GRADE_REPORT, "A"),
        ("grade-A-2", EvaluatorOperationV2.GRADE_REPORT, "A"),
    ]
    if labels == 2:
        operations.extend(
            [
                ("grade-B-1", EvaluatorOperationV2.GRADE_REPORT, "B"),
                ("grade-B-2", EvaluatorOperationV2.GRADE_REPORT, "B"),
            ]
        )
    files = {
        "inputs/case.json": canonical_json_bytes(envelope.model_dump(mode="json")),
        "inputs/build.json": canonical_json_bytes({"build": "completed-fixture-v2"}),
        "rubric.json": _rubric_bytes(),
        "baseline.json": canonical_json_bytes(baseline.model_dump(mode="json")),
        "result.json": canonical_json_bytes(result.model_dump(mode="json")),
    }
    calls: list[EvaluationCallRecordV2] = []
    for call_id, operation, label in operations:
        request = _request_for(operation, label=label)
        response = EvaluatorResponseV2(
            operation=operation,
            request_fingerprint=request.request_fingerprint,
            provider_name="fixture",
            model_name="fixture-model",
            judge_isolation="scripted_fixture",
            payload={},
        )
        request_path = f"requests/{call_id}.json"
        response_path = f"responses/{call_id}.json"
        request_bytes = canonical_json_bytes(request.model_dump(mode="json"))
        response_bytes = canonical_json_bytes(response.model_dump(mode="json"))
        files[request_path] = request_bytes
        files[response_path] = response_bytes
        calls.append(
            EvaluationCallRecordV2(
                call_id=call_id,
                operation=operation,
                anonymous_label=label,
                state="accepted",
                request_artifact_path=request_path,
                request_fingerprint=request.request_fingerprint,
                response_artifact_path=response_path,
                response_fingerprint=sha256_digest(response_bytes),
                provider_name=response.provider_name,
                model_name=response.model_name,
                judge_isolation=response.judge_isolation,
            )
        )
    manifest = EvaluationManifestV2(
        case_fingerprint=envelope.case_fingerprint,
        case_envelope_hash=sha256_digest(files["inputs/case.json"]),
        build_fingerprint=sha256_digest(files["inputs/build.json"]),
        rubric_fingerprint=sha256_digest(files["rubric.json"]),
        compiler_version="semantic-compiler-v2",
        baseline_fingerprint=baseline.baseline_fingerprint,
        result_hash=result.result_fingerprint,
        phase=EvaluationPhaseV2.COMPLETED,
        terminal_status=EvaluationTerminalStatusV2.COMPLETED,
        calls=calls,
        artifacts=[],
        manifest_fingerprint="0" * 64,
    )
    return manifest, files, result


def _snapshot(run_dir: Path) -> dict[str, bytes]:
    return {
        path.relative_to(run_dir).as_posix(): path.read_bytes()
        for path in sorted(run_dir.rglob("*"))
        if path.is_file() and not path.is_symlink()
    }


def _initialized(tmp_path: Path) -> Path:
    run_dir = tmp_path / "v2-run"
    initialize_v2_run_storage(run_dir, _manifest(), _files())
    return run_dir


def test_initialization_writes_canonical_manifest_and_verifies(tmp_path: Path) -> None:
    run_dir = _initialized(tmp_path)

    manifest, result = load_verified_v2_run(run_dir)

    assert result is None
    assert manifest.protocol_version == "2.0"
    assert manifest.artifacts == sorted(manifest.artifacts, key=lambda item: item.artifact_path)
    assert legacy_artifacts.read_evaluation_artifact(
        run_dir, V2_MANIFEST_PATH
    ) == canonical_json_bytes(manifest.model_dump(mode="json"))


def test_initialization_rejects_case_fingerprint_not_bound_to_stored_envelope(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "wrong-case"
    manifest = _manifest().model_copy(update={"case_fingerprint": "0" * 64})

    with pytest.raises(EvaluationIntegrityError, match="CASE_BUILD_BINDING"):
        initialize_v2_run_storage(run_dir, manifest, _files())

    assert not run_dir.exists() or _snapshot(run_dir) == {}


def test_accepted_transition_commits_bound_response_and_manifest_together(tmp_path: Path) -> None:
    run_dir = _initialized(tmp_path)
    accepted = _manifest(accepted=True)
    files = _files(response=True)

    with legacy_artifacts.open_evaluation_storage(run_dir) as storage:
        committed = commit_v2_transition(storage, accepted, files)

    assert committed.calls[0].state == "accepted"
    assert verify_v2_run(run_dir).valid
    assert sha256_digest(
        legacy_artifacts.read_evaluation_artifact(run_dir, "responses/call-1.json")
    ) == (committed.calls[0].response_fingerprint)


def test_accepted_transition_inherits_verified_immutable_artifacts(tmp_path: Path) -> None:
    run_dir = _initialized(tmp_path)
    response = _files(response=True)["responses/call-1.json"]

    with legacy_artifacts.open_evaluation_storage(run_dir) as storage:
        committed = commit_v2_transition(
            storage,
            _manifest(accepted=True),
            {
                "requests/call-2.json": _files(response=True)["requests/call-2.json"],
                "responses/call-1.json": response,
            },
        )

    assert verify_v2_run(run_dir).valid
    assert {artifact.artifact_path for artifact in committed.artifacts} == {
        "inputs/build.json",
        "inputs/case.json",
        "rubric.json",
        "requests/call-1.json",
        "requests/call-2.json",
        "responses/call-1.json",
    }


@pytest.mark.parametrize("labels", [1, 2])
def test_verifier_replays_canonical_completed_results_with_sealed_baseline_context(
    tmp_path: Path, labels: int
) -> None:
    manifest, files, expected = _completed_run_data(labels=labels)

    initialize_v2_run_storage(tmp_path / f"completed-{labels}", manifest, files)

    reloaded, result = load_verified_v2_run(tmp_path / f"completed-{labels}")
    assert result == expected
    assert reloaded.result_hash == expected.result_fingerprint


def test_verifier_rejects_constructed_result_with_tampered_grade_baseline(
    tmp_path: Path,
) -> None:
    manifest, files, result = _completed_run_data(labels=1)
    constructed = EvaluationResultV2.model_construct(**result.model_dump(mode="python"))
    payload = constructed.model_dump(mode="json", warnings=False)
    payload["reports"][0]["reconciliation"]["grader_responses"][0][
        "baseline_fingerprint"
    ] = "0" * 64
    files["result.json"] = canonical_json_bytes(payload)

    with pytest.raises(EvaluationIntegrityError, match=r"MODEL_INVALID:result\.json"):
        initialize_v2_run_storage(tmp_path / "tampered-result", manifest, files)


def test_verifier_rejects_tampered_report_fingerprint_after_result_rebinding(
    tmp_path: Path,
) -> None:
    manifest, files, result = _completed_run_data(labels=1)
    payload = result.model_dump(mode="json")
    payload["reports"][0]["result_fingerprint"] = "0" * 64
    payload["result_fingerprint"] = sha256_digest(
        canonical_json_bytes(
            {key: value for key, value in payload.items() if key != "result_fingerprint"}
        )
    )
    files["result.json"] = canonical_json_bytes(payload)
    manifest = manifest.model_copy(update={"result_hash": payload["result_fingerprint"]})

    with pytest.raises(EvaluationIntegrityError, match="REPORT_FINGERPRINT"):
        initialize_v2_run_storage(tmp_path / "tampered-report", manifest, files)


def test_inconclusive_terminal_retains_only_the_final_pending_request(tmp_path: Path) -> None:
    run_dir = _initialized(tmp_path)
    stopped = _manifest().model_copy(
        update={
            "phase": EvaluationPhaseV2.INCONCLUSIVE,
            "terminal_status": EvaluationTerminalStatusV2.INCONCLUSIVE,
            "calls": [],
            "result_hash": None,
        }
    )

    with legacy_artifacts.open_evaluation_storage(run_dir) as storage:
        commit_v2_transition(
            storage,
            stopped,
            {
                "terminal-reason.json": canonical_json_bytes(
                    {"reason": "MECHANICAL_RESPONSE_INVALID"}
                )
            },
        )

    assert verify_v2_run(run_dir).valid


def test_terminal_orphan_request_rejects_forged_packet_fingerprint(tmp_path: Path) -> None:
    stopped = _manifest().model_copy(
        update={
            "phase": EvaluationPhaseV2.INCONCLUSIVE,
            "terminal_status": EvaluationTerminalStatusV2.INCONCLUSIVE,
            "calls": [],
            "result_hash": None,
        }
    )
    files = _files()
    forged = _request().model_copy(update={"request_fingerprint": "0" * 64})
    files["requests/call-1.json"] = canonical_json_bytes(forged.model_dump(mode="json"))

    with pytest.raises(EvaluationIntegrityError, match="CALL_REQUEST_BINDING"):
        initialize_v2_run_storage(tmp_path / "forged-orphan", stopped, files)


@pytest.mark.parametrize("terminal", ["completed", "inconclusive"])
def test_verifier_rejects_result_shaped_artifact_with_different_fingerprint(
    tmp_path: Path, terminal: str
) -> None:
    completed, source_files, result = _completed_run_data(labels=1)
    if terminal == "completed":
        manifest = completed
        files = dict(source_files)
    else:
        calls = completed.calls[:2]
        keep = {
            "inputs/case.json",
            "inputs/build.json",
            "rubric.json",
            "baseline.json",
            *(call.request_artifact_path for call in calls),
            *(cast(str, call.response_artifact_path) for call in calls),
        }
        manifest = completed.model_copy(
            update={
                "phase": EvaluationPhaseV2.INCONCLUSIVE,
                "terminal_status": EvaluationTerminalStatusV2.INCONCLUSIVE,
                "calls": calls,
                "result_hash": None,
                "artifacts": [],
                "manifest_fingerprint": "0" * 64,
            }
        )
        files = {path: data for path, data in source_files.items() if path in keep}
    malformed = result.model_dump(mode="json")
    malformed["reports"][0]["reconciliation"]["grader_responses"][0][
        "baseline_fingerprint"
    ] = "0" * 64
    malformed["result_fingerprint"] = "f" * 64
    files["result-extra.json"] = canonical_json_bytes(malformed)

    with pytest.raises(EvaluationIntegrityError, match=r"MODEL_INVALID:result-extra\.json"):
        initialize_v2_run_storage(tmp_path / terminal, manifest, files)


@pytest.mark.parametrize("terminal", ["completed", "inconclusive"])
def test_verifier_rejects_partial_result_namespace_artifact(
    tmp_path: Path, terminal: str
) -> None:
    completed, source_files, _ = _completed_run_data(labels=1)
    if terminal == "completed":
        manifest = completed
        files = dict(source_files)
    else:
        calls = completed.calls[:2]
        keep = {
            "inputs/case.json",
            "inputs/build.json",
            "rubric.json",
            "baseline.json",
            *(call.request_artifact_path for call in calls),
            *(cast(str, call.response_artifact_path) for call in calls),
        }
        manifest = completed.model_copy(
            update={
                "phase": EvaluationPhaseV2.INCONCLUSIVE,
                "terminal_status": EvaluationTerminalStatusV2.INCONCLUSIVE,
                "calls": calls,
                "result_hash": None,
                "artifacts": [],
                "manifest_fingerprint": "0" * 64,
            }
        )
        files = {path: data for path, data in source_files.items() if path in keep}
    files["results/extra.json"] = canonical_json_bytes({"result_fingerprint": "f" * 64})

    with pytest.raises(EvaluationIntegrityError, match=r"MODEL_INVALID:results/extra\.json"):
        initialize_v2_run_storage(tmp_path / f"partial-{terminal}", manifest, files)


def test_completed_verifier_rejects_a_second_valid_unbound_result(tmp_path: Path) -> None:
    manifest, files, result = _completed_run_data(labels=1)
    report = result.reports[0].model_copy(
        update={"critical_recall": 0.5, "result_fingerprint": "0" * 64}
    )
    report = report.model_copy(
        update={
            "result_fingerprint": sha256_digest(
                canonical_json_bytes(report.model_dump(mode="json", exclude={"result_fingerprint"}))
            )
        }
    )
    extra = result.model_copy(update={"reports": [report], "result_fingerprint": "0" * 64})
    extra = extra.model_copy(
        update={
            "result_fingerprint": sha256_digest(
                canonical_json_bytes(extra.model_dump(mode="json", exclude={"result_fingerprint"}))
            )
        }
    )
    files["results/extra.json"] = canonical_json_bytes(extra.model_dump(mode="json"))

    with pytest.raises(EvaluationIntegrityError, match="RESULT_REQUIRED"):
        initialize_v2_run_storage(tmp_path / "extra-valid-result", manifest, files)


def test_terminal_orphan_request_rejects_wrong_next_operation(tmp_path: Path) -> None:
    manifest = _manifest().model_copy(
        update={
            "phase": EvaluationPhaseV2.INCONCLUSIVE,
            "terminal_status": EvaluationTerminalStatusV2.INCONCLUSIVE,
            "calls": [],
            "result_hash": None,
        }
    )
    files = _files()
    files["requests/call-1.json"] = canonical_json_bytes(
        _audit_request().model_dump(mode="json")
    )

    with pytest.raises(EvaluationIntegrityError, match="UNBOUND_REQUEST"):
        initialize_v2_run_storage(tmp_path / "wrong-terminal-orphan", manifest, files)


def test_terminal_orphan_request_allows_zero_and_rejects_multiple_or_nonterminal(
    tmp_path: Path,
) -> None:
    stopped = _manifest().model_copy(
        update={
            "phase": EvaluationPhaseV2.INCONCLUSIVE,
            "terminal_status": EvaluationTerminalStatusV2.INCONCLUSIVE,
            "calls": [],
            "result_hash": None,
        }
    )
    no_orphan_files = _files()
    del no_orphan_files["requests/call-1.json"]
    initialize_v2_run_storage(tmp_path / "no-orphan", stopped, no_orphan_files)
    assert verify_v2_run(tmp_path / "no-orphan").valid

    two_orphan_files = _files()
    two_orphan_files["requests/second.json"] = canonical_json_bytes(
        _request().model_dump(mode="json")
    )
    with pytest.raises(EvaluationIntegrityError, match="UNBOUND_REQUEST"):
        initialize_v2_run_storage(tmp_path / "two-orphans", stopped, two_orphan_files)

    nonterminal_files = _files()
    nonterminal_files["requests/second.json"] = canonical_json_bytes(
        _request().model_dump(mode="json")
    )
    with pytest.raises(EvaluationIntegrityError, match="UNBOUND_REQUEST"):
        initialize_v2_run_storage(tmp_path / "nonterminal-orphan", _manifest(), nonterminal_files)


def test_terminal_orphan_request_rejects_wrong_grade_label_and_response(tmp_path: Path) -> None:
    completed, source_files, _ = _completed_run_data(labels=1)
    calls = completed.calls[:2]
    keep = {
        "inputs/case.json",
        "inputs/build.json",
        "rubric.json",
        "baseline.json",
        *(call.request_artifact_path for call in calls),
        *(cast(str, call.response_artifact_path) for call in calls),
    }
    files = {path: data for path, data in source_files.items() if path in keep}
    files["requests/grade-B-1.json"] = canonical_json_bytes(
        _request_for(EvaluatorOperationV2.GRADE_REPORT, label="B").model_dump(mode="json")
    )
    stopped = completed.model_copy(
        update={
            "phase": EvaluationPhaseV2.INCONCLUSIVE,
            "terminal_status": EvaluationTerminalStatusV2.INCONCLUSIVE,
            "calls": calls,
            "result_hash": None,
            "artifacts": [],
            "manifest_fingerprint": "0" * 64,
        }
    )
    with pytest.raises(EvaluationIntegrityError, match="UNBOUND_REQUEST"):
        initialize_v2_run_storage(tmp_path / "wrong-grade", stopped, files)

    response_files = _files()
    response_files["responses/refused.json"] = canonical_json_bytes(
        EvaluatorResponseV2(
            operation=EvaluatorOperationV2.SOURCE_REVIEW,
            request_fingerprint=_request().request_fingerprint,
            provider_name="fixture",
            model_name="fixture-model",
            judge_isolation="scripted_fixture",
            payload={},
        ).model_dump(mode="json")
    )
    empty_stop = _manifest().model_copy(
        update={
            "phase": EvaluationPhaseV2.INCONCLUSIVE,
            "terminal_status": EvaluationTerminalStatusV2.INCONCLUSIVE,
            "calls": [],
            "result_hash": None,
        }
    )
    with pytest.raises(EvaluationIntegrityError, match="UNBOUND_RESPONSE"):
        initialize_v2_run_storage(tmp_path / "orphan-response", empty_stop, response_files)


def test_refused_v2_response_leaves_run_tree_unchanged(tmp_path: Path) -> None:
    run_dir = _initialized(tmp_path)
    before = _snapshot(run_dir)

    preflight = preflight_v2_response(run_dir, "call-1", {"not": "a response"})

    assert not preflight.valid
    assert _snapshot(run_dir) == before


def test_rejects_model_construct_baseline_fingerprint_spoof_before_writing(tmp_path: Path) -> None:
    run_dir = _initialized(tmp_path)
    before = _snapshot(run_dir)
    baseline = CanonicalBaselineV2.model_construct(
        schema_version="2.0",
        case_fingerprint="2" * 64,
        requirements=[],
        relationships=(),
        unresolved_dispute_ids=[],
        baseline_fingerprint="4" * 64,
    )
    files = _files(response=True)
    files["baseline.json"] = canonical_json_bytes(baseline.model_dump(mode="json"))
    manifest = _manifest(accepted=True).model_copy(
        update={"baseline_fingerprint": baseline.baseline_fingerprint}
    )

    with (
        pytest.raises(EvaluationIntegrityError, match="BASELINE_FINGERPRINT"),
        legacy_artifacts.open_evaluation_storage(run_dir) as storage,
    ):
        commit_v2_transition(storage, manifest, files)

    assert _snapshot(run_dir) == before


def test_rejects_unbound_baseline_artifact_before_writing(tmp_path: Path) -> None:
    run_dir = _initialized(tmp_path)
    before = _snapshot(run_dir)
    baseline_payload = {
        "schema_version": "2.0",
        "case_fingerprint": _envelope().case_fingerprint,
        "requirements": [],
        "relationships": [],
        "unresolved_dispute_ids": [],
    }
    baseline = CanonicalBaselineV2(
        **baseline_payload,
        baseline_fingerprint=sha256_digest(canonical_json_bytes(baseline_payload)),
    )
    files = _files(response=True)
    files["baseline.json"] = canonical_json_bytes(baseline.model_dump(mode="json"))

    with (
        pytest.raises(EvaluationIntegrityError, match="BASELINE_UNEXPECTED"),
        legacy_artifacts.open_evaluation_storage(run_dir) as storage,
    ):
        commit_v2_transition(storage, _manifest(accepted=True), files)

    assert _snapshot(run_dir) == before


def test_verifier_rejects_hash_mismatch_and_added_file(tmp_path: Path) -> None:
    run_dir = _initialized(tmp_path)
    (run_dir / "rubric.json").write_bytes(b"{}")
    assert not verify_v2_run(run_dir).valid

    run_dir = _initialized(tmp_path / "second")
    (run_dir / "unexpected.txt").write_text("unexpected", encoding="utf-8")
    assert not verify_v2_run(run_dir).valid


def test_verifier_rejects_empty_and_special_inventory_entries(tmp_path: Path) -> None:
    run_dir = _initialized(tmp_path)
    (run_dir / "empty").mkdir()
    verification = verify_v2_run(run_dir)
    assert not verification.valid
    assert verification.issues == ("EVALUATOR_V2_INVENTORY",)

    run_dir = _initialized(tmp_path / "fifo")
    if hasattr(os, "mkfifo"):
        os.mkfifo(run_dir / "pipe")
        assert not verify_v2_run(run_dir).valid


def test_verifier_rejects_out_of_order_accepted_history(tmp_path: Path) -> None:
    files = _files(response=True)
    manifest = _manifest(accepted=True)
    malformed = manifest.model_copy(update={"calls": list(reversed(manifest.calls))})

    with pytest.raises(EvaluationIntegrityError, match="CALL_HISTORY"):
        initialize_v2_run_storage(tmp_path / "out-of-order", malformed, files)


def test_phase_history_rejects_duplicate_source_review_after_acceptance() -> None:
    accepted = _manifest(accepted=True).calls[0]
    pending = accepted.model_copy(
        update={
            "state": "pending",
            "response_artifact_path": None,
            "response_fingerprint": None,
            "provider_name": None,
            "model_name": None,
            "judge_isolation": None,
        }
    )
    malformed = _manifest(accepted=True).model_copy(
        update={"phase": EvaluationPhaseV2.SOURCE_REVIEW, "calls": [accepted, pending]}
    )

    with pytest.raises(EvaluationIntegrityError, match="CALL_HISTORY"):
        _require_phase_consistency(malformed)


def test_inconclusive_terminal_accepts_each_legal_early_stop_prefix() -> None:
    review = _manifest(accepted=True).calls[0]
    audit = (
        _manifest(accepted=True)
        .calls[1]
        .model_copy(
            update={
                "state": "accepted",
                "response_artifact_path": "responses/audit.json",
                "response_fingerprint": "b" * 64,
                "provider_name": "fixture",
                "model_name": "fixture",
                "judge_isolation": "scripted_fixture",
            }
        )
    )

    def accepted_grade(index: int, label: str) -> EvaluationCallRecordV2:
        return review.model_copy(
            update={
                "call_id": f"grade-{index}",
                "operation": EvaluatorOperationV2.GRADE_REPORT,
                "anonymous_label": label,
                "request_artifact_path": f"requests/grade-{index}.json",
                "response_artifact_path": f"responses/grade-{index}.json",
            }
        )

    referee = review.model_copy(
        update={
            "call_id": "referee",
            "operation": EvaluatorOperationV2.SOURCE_REFEREE,
            "anonymous_label": None,
            "request_artifact_path": "requests/referee.json",
            "response_artifact_path": "responses/referee.json",
        }
    )
    grade_prefixes = [
        [],
        [accepted_grade(1, "A")],
        [accepted_grade(1, "A"), accepted_grade(2, "A")],
        [
            accepted_grade(1, "A"),
            accepted_grade(2, "A"),
            accepted_grade(3, "B"),
        ],
        [
            accepted_grade(1, "A"),
            accepted_grade(2, "A"),
            accepted_grade(3, "B"),
            accepted_grade(4, "B"),
        ],
    ]
    prefixes = [[], [review], [review, audit], [review, audit, referee]]
    prefixes.extend([review, audit, *grades] for grades in grade_prefixes[1:])
    prefixes.extend([review, audit, referee, *grades] for grades in grade_prefixes[1:])
    for calls in prefixes:
        stopped = _manifest().model_copy(
            update={
                "phase": EvaluationPhaseV2.INCONCLUSIVE,
                "terminal_status": "inconclusive",
                "calls": calls,
                "result_hash": None,
            }
        )
        _require_phase_consistency(stopped)
        assert stopped.result_hash is None


def test_inconclusive_terminal_rejects_impossible_early_stop_histories() -> None:
    review = _manifest(accepted=True).calls[0]
    audit = _manifest(accepted=True).calls[1].model_copy(
        update={"state": "accepted", "anonymous_label": None}
    )
    referee = review.model_copy(
        update={
            "call_id": "referee",
            "operation": EvaluatorOperationV2.SOURCE_REFEREE,
            "anonymous_label": None,
        }
    )

    def grade(index: int, label: str) -> EvaluationCallRecordV2:
        return review.model_copy(
            update={
                "call_id": f"grade-{index}",
                "operation": EvaluatorOperationV2.GRADE_REPORT,
                "anonymous_label": label,
            }
        )

    invalid_histories = [
        [audit],
        [review, referee],
        [review, audit, review],
        [review, audit, grade(1, "B")],
        [review, audit, grade(1, "A"), grade(2, "B")],
        [review, audit, grade(1, "A"), grade(2, "A"), grade(3, "B"), grade(4, "A")],
        [
            review,
            audit,
            referee,
            grade(1, "A"),
            grade(2, "A"),
            grade(3, "B"),
            grade(4, "B"),
            grade(5, "B"),
        ],
        [_manifest().calls[0]],
    ]
    for calls in invalid_histories:
        stopped = _manifest().model_copy(
            update={
                "phase": EvaluationPhaseV2.INCONCLUSIVE,
                "terminal_status": "inconclusive",
                "calls": calls,
                "result_hash": None,
            }
        )
        with pytest.raises(EvaluationIntegrityError, match="CALL_HISTORY"):
            _require_phase_consistency(stopped)


def test_inconclusive_terminal_rejects_a_result_hash() -> None:
    stopped = _manifest().model_copy(
        update={
            "phase": EvaluationPhaseV2.INCONCLUSIVE,
            "terminal_status": "inconclusive",
            "calls": [],
            "result_hash": "a" * 64,
        }
    )

    with pytest.raises(EvaluationIntegrityError, match="RESULT_TERMINAL"):
        _require_phase_consistency(stopped)


def test_rollback_preserves_same_byte_race_collision(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    run_dir = _initialized(tmp_path)
    additions = {
        "requests/call-2.json": _files(response=True)["requests/call-2.json"],
        "responses/call-1.json": _files(response=True)["responses/call-1.json"],
    }
    with legacy_artifacts.open_evaluation_storage(run_dir) as storage:
        original = storage.atomic_write

        def race_then_fail(path: str, data: bytes, *, mutable: bool) -> bool:
            if path == "requests/call-2.json":
                original(path, data, mutable=mutable)
                return original(path, data, mutable=mutable)
            if path == V2_MANIFEST_PATH:
                raise OSError("injected manifest failure")
            return original(path, data, mutable=mutable)

        monkeypatch.setattr(storage, "atomic_write", race_then_fail)
        with pytest.raises(OSError, match="injected manifest failure"):
            commit_v2_transition(storage, _manifest(accepted=True), additions)

    assert (run_dir / "requests" / "call-2.json").read_bytes() == additions["requests/call-2.json"]
    assert not (run_dir / "responses" / "call-1.json").exists()


def test_transition_rolls_back_new_artifacts_after_injected_write_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    run_dir = _initialized(tmp_path)
    before = _snapshot(run_dir)
    additions = {
        "requests/call-2.json": _files(response=True)["requests/call-2.json"],
        "responses/call-1.json": _files(response=True)["responses/call-1.json"],
    }
    with legacy_artifacts.open_evaluation_storage(run_dir) as storage:
        original = storage.atomic_write
        writes = 0

        def fail_after_first(path: str, data: bytes, *, mutable: bool) -> None:
            nonlocal writes
            writes += 1
            if writes == 2:
                raise OSError("injected write failure")
            return original(path, data, mutable=mutable)

        monkeypatch.setattr(storage, "atomic_write", fail_after_first)
        with pytest.raises(OSError, match="injected write failure"):
            commit_v2_transition(storage, _manifest(accepted=True), additions)

    assert _snapshot(run_dir) == before
    assert verify_v2_run(run_dir).valid


def test_transition_rolls_back_owned_artifact_reported_by_storage_exception(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    run_dir = _initialized(tmp_path)
    before = _snapshot(run_dir)
    additions = {
        "requests/call-2.json": _files(response=True)["requests/call-2.json"],
        "responses/call-1.json": _files(response=True)["responses/call-1.json"],
    }
    with legacy_artifacts.open_evaluation_storage(run_dir) as storage:
        original = storage.atomic_write
        failed = False

        def fail_after_owned_write(path: str, data: bytes, *, mutable: bool) -> bool:
            nonlocal failed
            created = original(path, data, mutable=mutable)
            if created and path != V2_MANIFEST_PATH and not failed:
                failed = True
                cause = OSError("injected post-link failure")
                raise legacy_artifacts._AtomicWriteOwnershipError(path, cause) from cause
            return created

        monkeypatch.setattr(storage, "atomic_write", fail_after_owned_write)
        with pytest.raises(EvaluationIntegrityError, match="evaluation storage"):
            commit_v2_transition(storage, _manifest(accepted=True), additions)

    assert failed
    assert _snapshot(run_dir) == before
    assert verify_v2_run(run_dir).valid


def test_initialization_rolls_back_owned_manifest_reported_by_storage_exception(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    run_dir = tmp_path / "v2-owned-manifest-init"
    original = legacy_artifacts._PosixRunStorage.atomic_write
    failed = False

    def fail_after_owned_manifest(
        storage: object, path: str, data: bytes, *, mutable: bool
    ) -> bool:
        nonlocal failed
        created = original(storage, path, data, mutable=mutable)  # type: ignore[arg-type]
        if path == V2_MANIFEST_PATH and created and not failed:
            failed = True
            cause = OSError("injected post-link manifest failure")
            raise legacy_artifacts._AtomicWriteOwnershipError(path, cause) from cause
        return created

    monkeypatch.setattr(
        legacy_artifacts._PosixRunStorage, "atomic_write", fail_after_owned_manifest
    )
    with pytest.raises(EvaluationIntegrityError, match="evaluation storage"):
        initialize_v2_run_storage(run_dir, _manifest(), _files())

    assert failed
    assert _snapshot(run_dir) == {}


def _fake_windows_v2_storage(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[_FakeWin32API, Path]:
    api = _FakeWin32API()
    api.add_directory("C:\\")
    api.add_directory("C:\\safe")
    run_dir = Path("C:\\safe\\evaluation-run")
    monkeypatch.setattr(legacy_artifacts, "_storage_platform", lambda: "nt")
    monkeypatch.setattr(legacy_artifacts, "_new_win32_api", lambda: api)
    return api, run_dir


def _fail_first_renamed_close(api: _FakeWin32API, target_name: str) -> list[str]:
    failures: list[str] = []

    def fail_once(handle: int) -> None:
        node = api.handles[handle]
        if node.name == target_name and handle in api.temporary_handles and not failures:
            failures.append(node.name)
            raise OSError("injected renamed handle close failure")

    api.before_close_handle = fail_once
    return failures


def test_win32_transition_rolls_back_owned_post_rename_addition(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api, run_dir = _fake_windows_v2_storage(monkeypatch)
    initialize_v2_run_storage(run_dir, _manifest(), _files())
    additions = {
        "requests/call-2.json": _files(response=True)["requests/call-2.json"],
        "responses/call-1.json": _files(response=True)["responses/call-1.json"],
    }
    failures = _fail_first_renamed_close(api, "call-2.json")

    with (
        pytest.raises(
            EvaluationIntegrityError, match="Windows artifact write"
        ) as raised,
        legacy_artifacts.open_evaluation_storage(run_dir) as storage,
    ):
        commit_v2_transition(storage, _manifest(accepted=True), additions)

    assert "ROLLBACK_FAILED" not in str(raised.value)
    assert failures == ["call-2.json"]
    with legacy_artifacts.open_evaluation_storage(run_dir) as storage:
        assert storage.scan_files() == set(_files()) | {V2_MANIFEST_PATH}
    assert verify_v2_run(run_dir).valid


def test_win32_initialization_removes_manifest_and_all_owned_files_after_post_rename(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api, run_dir = _fake_windows_v2_storage(monkeypatch)
    failures = _fail_first_renamed_close(api, V2_MANIFEST_PATH)

    with pytest.raises(EvaluationIntegrityError, match="Windows artifact write") as raised:
        initialize_v2_run_storage(run_dir, _manifest(), _files())

    assert "ROLLBACK_FAILED" not in str(raised.value)
    assert failures == [V2_MANIFEST_PATH]
    root = api._resolve_absolute(str(run_dir), follow_final_reparse=False)
    assert root.children == {}
    assert api.path_child_calls == 0
    assert api.handles == {}


def test_win32_owned_rollback_cleanup_failure_is_controlled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api, run_dir = _fake_windows_v2_storage(monkeypatch)
    initialize_v2_run_storage(run_dir, _manifest(), _files())
    additions = {
        "requests/call-2.json": _files(response=True)["requests/call-2.json"],
        "responses/call-1.json": _files(response=True)["responses/call-1.json"],
    }
    failures = _fail_first_renamed_close(api, "call-2.json")
    api.delete_errors_by_name["call-2.json"] = OSError(
        "injected owned artifact cleanup failure"
    )

    with (
        pytest.raises(EvaluationIntegrityError, match="ROLLBACK_FAILED") as raised,
        legacy_artifacts.open_evaluation_storage(run_dir) as storage,
    ):
        commit_v2_transition(storage, _manifest(accepted=True), additions)

    assert failures == ["call-2.json"]
    assert isinstance(raised.value.__cause__, OSError)
    request = api._resolve_absolute(
        "C:\\safe\\evaluation-run\\requests\\call-2.json",
        follow_final_reparse=False,
    )
    assert request.content == additions["requests/call-2.json"]


def test_win32_rollback_preserves_same_byte_competing_addition(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api, run_dir = _fake_windows_v2_storage(monkeypatch)
    initialize_v2_run_storage(run_dir, _manifest(), _files())
    additions = {
        "requests/call-2.json": _files(response=True)["requests/call-2.json"],
        "responses/call-1.json": _files(response=True)["responses/call-1.json"],
    }
    competitor_path = "C:\\safe\\evaluation-run\\requests\\call-2.json"
    collided = False

    with legacy_artifacts.open_evaluation_storage(run_dir) as storage:
        original = storage.atomic_write

        def compete_then_fail(path: str, data: bytes, *, mutable: bool) -> bool:
            nonlocal collided
            if path == "requests/call-2.json" and not collided:
                api.add_file(competitor_path, data)
                collided = True
            if path == V2_MANIFEST_PATH:
                raise OSError("injected manifest failure")
            return original(path, data, mutable=mutable)

        monkeypatch.setattr(storage, "atomic_write", compete_then_fail)
        with pytest.raises(OSError, match="injected manifest failure"):
            commit_v2_transition(storage, _manifest(accepted=True), additions)

    assert collided
    assert api._resolve_absolute(
        competitor_path, follow_final_reparse=False
    ).content == additions["requests/call-2.json"]
    with pytest.raises(FileNotFoundError):
        api._resolve_absolute(
            "C:\\safe\\evaluation-run\\responses\\call-1.json",
            follow_final_reparse=False,
        )


def test_transition_rolls_back_response_when_manifest_write_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    run_dir = _initialized(tmp_path)
    before = _snapshot(run_dir)
    additions = {
        "requests/call-2.json": _files(response=True)["requests/call-2.json"],
        "responses/call-1.json": _files(response=True)["responses/call-1.json"],
    }
    with legacy_artifacts.open_evaluation_storage(run_dir) as storage:
        original = storage.atomic_write

        def fail_manifest(path: str, data: bytes, *, mutable: bool) -> None:
            if path == V2_MANIFEST_PATH:
                raise OSError("injected manifest failure")
            return original(path, data, mutable=mutable)

        monkeypatch.setattr(storage, "atomic_write", fail_manifest)
        with pytest.raises(OSError, match="injected manifest failure"):
            commit_v2_transition(storage, _manifest(accepted=True), additions)

    assert _snapshot(run_dir) == before
    assert verify_v2_run(run_dir).valid


@pytest.mark.skipif(os.name != "posix", reason="symlink containment is POSIX-specific")
def test_verifier_rejects_symlink_and_root_alias(tmp_path: Path) -> None:
    run_dir = _initialized(tmp_path)
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    (run_dir / "linked.json").symlink_to(outside)
    assert not verify_v2_run(run_dir).valid

    alias = tmp_path / "alias"
    alias.symlink_to(run_dir, target_is_directory=True)
    assert not verify_v2_run(alias).valid


def test_protocol_detection_keeps_legacy_replay_separate(tmp_path: Path) -> None:
    from regulatory_harvest.evaluation.attorney_protocol import (
        detect_evaluation_protocol as extracted_detector,
    )

    run_dir = _initialized(tmp_path / "v2")
    legacy = tmp_path / "legacy"
    legacy.mkdir()
    (legacy / "run-manifest.json").write_bytes(canonical_json_bytes({"schema_version": "1.3"}))

    assert detect_evaluation_protocol(run_dir) == "2.0"
    assert detect_evaluation_protocol(legacy) == "1.3"
    assert detect_evaluation_protocol is extracted_detector


def test_promoted_legacy_storage_aliases_preserve_read_write_behavior(tmp_path: Path) -> None:
    from regulatory_harvest.evaluation.attorney_artifacts import (
        atomic_write_evaluation_artifact,
        open_evaluation_storage,
        read_evaluation_artifact,
    )

    run_dir = tmp_path / "legacy-alias"
    with open_evaluation_storage(run_dir, initialize=True) as storage:
        atomic_write_evaluation_artifact(storage, "sample.json", b"{}")

    assert read_evaluation_artifact(run_dir, "sample.json") == b"{}"
