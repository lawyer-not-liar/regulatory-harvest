"""Provider-neutral, resumable attorney-evaluation orchestration."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol, TypeVar, cast, runtime_checkable

from pydantic import ValidationError

from regulatory_harvest.models.base import StrictModel
from regulatory_harvest.storage import canonical_json_bytes, sha256_digest

from . import attorney_generation as generation
from .attorney_admission import (
    adjudicate_admission,
    build_admission_packet,
    freeze_case,
)
from .attorney_artifacts import (
    EvaluationIntegrityError,
    _artifact_record,
    _atomic_write,
    _audit_action_contract,
    _derive_deterministic_checks,
    _derive_requirement_matrix,
    _derive_source_spans,
    _dict_value,
    _ensure_ordinary_json,
    _ledger_referee_payload,
    _load_model_bytes,
    _model_bytes,
    _model_from_payload,
    _open_run_storage,
    _ordinary_json_bytes,
    _parse_json_bytes,
    _prompt_fingerprint,
    _read_artifact,
    _report_referee_instructions,
    _report_referee_payload,
    _require_artifact_schema,
    _result_fingerprint,
    _RunStorage,
    _score_inputs_payload,
    _serialize_resolved_grade,
    _strict_model_payload,
    _validate_grade_evidence,
    _validate_report_referee_decision,
    _verify_evaluation_run_or_raise,
    _write_manifest,
    render_evaluation_report,
)
from .attorney_contract import preflight_issue_message, safe_preflight_issue
from .attorney_grading import (
    GradeInconclusiveError,
    ResolvedGrade,
    _finding_code_contract,
    material_disputes,
    resolve_grades,
    validate_grade,
)
from .attorney_ledger import (
    LedgerInconclusiveError,
    ledger_disputes,
    ledger_findings,
    ledger_invariant_contract,
    seal_ledger,
    validate_ledger,
)
from .attorney_models import (
    EVALUATION_ARTIFACT_SCHEMA_VERSION,
    ArtifactRecord,
    AttorneyEvaluationCase,
    AttorneyEvaluationResult,
    CandidateGrade,
    CandidateReport,
    CandidateRole,
    CaseAdmissionJudgment,
    CaseEnvelope,
    CaseReadiness,
    ComparativeDisposition,
    ComparisonEvaluation,
    DeterministicChecks,
    EvaluationManifest,
    EvaluationPreflightIssue,
    EvaluationPreflightResult,
    EvaluationRubric,
    EvaluationRunPhase,
    EvaluationRunState,
    EvaluationTerminalStatus,
    GradeDispute,
    GuardedSubmissionResult,
    JudgeCallRecord,
    JudgeIsolation,
    JudgeOperation,
    JudgeRequest,
    JudgeResponse,
    LedgerAudit,
    LedgerDispute,
    LegalLedger,
    Materiality,
    ReadinessStatus,
    RefereeDecision,
    ReportEvaluation,
    RequirementMatrix,
    SealedLedger,
    model_fingerprint,
)
from .attorney_scoring import RUBRIC_V1, ReportScoreInputs, compare_reports, score_report

_CASE_ENVELOPE_PATH = "case-envelope.json"
_READINESS_PATH = "case-readiness.json"
_RUBRIC_PATH = "evaluation-rubric.json"
_PROPOSED_LEDGER_PATH = "legal-ledger.proposed.json"
_LEDGER_AUDIT_PATH = "legal-ledger-audit.json"
_REPAIRED_LEDGER_PATH = "legal-ledger.repaired.json"
_REMAINING_AUDIT_PATH = "legal-ledger.remaining-audit.json"
_LEDGER_REFEREE_PATH = "ledger-referee.json"
_SEALED_LEDGER_PATH = "legal-ledger.json"
_REPORT_DISPUTES_PATH = "report-disputes.json"
_RESULT_PATH = "evaluation-result.json"
_REPORT_PATH = "evaluation-report.md"
_TERMINAL_READINESS_PATH = "terminal-readiness.json"


@runtime_checkable
class AttorneyEvaluationJudge(Protocol):
    async def evaluate(self, request: JudgeRequest) -> JudgeResponse:
        """Return one strict response for one blinded evaluation operation."""
        raise NotImplementedError


@dataclass(frozen=True)
class CompletedEvaluation:
    result: AttorneyEvaluationResult
    manifest: EvaluationManifest
    run_dir: Path


class EvaluationSourceParityUnprovenError(ValueError):
    """A two-report case lacks two verified, matching generation capsules."""


def _verify_generation_capsules_for_initialization(
    case: AttorneyEvaluationCase,
    generation_capsule_paths: Mapping[str, Path] | None,
) -> None:
    """Re-open capsule roots at the mutation boundary before trusting provenance."""
    capsule_candidates = [
        candidate
        for candidate in case.candidates
        if candidate.generation_provenance is not None
        and candidate.generation_provenance.get("kind") == "capsule"
    ]
    if len(case.candidates) == 2 and len(capsule_candidates) != 2:
        raise EvaluationSourceParityUnprovenError(
            "Formal comparison requires two verified generation capsules."
        )
    supplied = {} if generation_capsule_paths is None else dict(generation_capsule_paths)
    if any(
        type(candidate_id) is not str or not isinstance(path, Path)
        for candidate_id, path in supplied.items()
    ):
        raise TypeError("generation capsule paths must map candidate IDs to Path values")
    expected_ids = {candidate.candidate_id for candidate in capsule_candidates}
    if set(supplied) != expected_ids:
        if len(case.candidates) == 2:
            raise EvaluationSourceParityUnprovenError(
                "Formal comparison requires two verified generation capsule paths."
            )
        raise ValueError("each capsule-backed report requires its generation capsule path")

    expected_sources = {source.source_id: source.content_hash for source in case.sources}
    expected_facts_hash = (
        None
        if case.client_facts is None
        else sha256_digest(case.client_facts.encode("utf-8"))
    )
    common_generation_instructions: str | None = None
    for candidate in capsule_candidates:
        provenance, report_bytes, request = generation.load_completed_generation_capsule_context(
            supplied[candidate.candidate_id]
        )
        record = cast(dict[str, object], provenance["generation_record"])
        if record["candidate_id"] != candidate.candidate_id:
            raise ValueError("generation capsule candidate_id does not match candidate report")
        if report_bytes != candidate.report_text.encode("utf-8"):
            raise ValueError("generation capsule report bytes do not match candidate report")
        if record["report_hash"] != candidate.report_hash:
            raise ValueError("generation capsule report hash does not match candidate report")
        if record["source_hashes"] != expected_sources:
            raise EvaluationSourceParityUnprovenError(
                "Generation capsule sources do not match the common case evidence."
            )
        if record["client_facts_hash"] != expected_facts_hash:
            raise EvaluationSourceParityUnprovenError(
                "Generation capsule client facts do not match the common case evidence."
            )
        if request["question"] != case.question:
            raise EvaluationSourceParityUnprovenError(
                "Generation capsule question does not match the evaluation question."
            )
        generation_instructions = cast(str, request["generation_instructions"])
        if common_generation_instructions is None:
            common_generation_instructions = generation_instructions
        elif generation_instructions != common_generation_instructions:
            raise EvaluationSourceParityUnprovenError(
                "Generation capsule instructions do not match across compared reports."
            )
        if candidate.generation_provenance != provenance:
            raise ValueError("candidate capsule provenance does not match the verified capsule")


class _LedgerRepairResponse(StrictModel):
    repaired_ledger: LegalLedger
    remaining_audit: LedgerAudit


@dataclass(frozen=True)
class _AcceptedTransition:
    files: dict[str, bytes]
    next_request: JudgeRequest | None
    next_call_id: str | None
    next_label: Literal["A", "B"] | None
    state: EvaluationRunPhase
    terminal_status: EvaluationTerminalStatus | None = None
    legal_ledger_hash: str | None = None
    result_hash: str | None = None


@dataclass(frozen=True)
class _PreflightSubmissionContext:
    """One verified pending call and its optional already-validated transition."""

    manifest: EvaluationManifest
    envelope: CaseEnvelope
    pending: JudgeCallRecord
    request: JudgeRequest
    transition: _AcceptedTransition | None = None
    validation_error: Exception | None = None


_ResponseModelT = TypeVar("_ResponseModelT", bound=StrictModel)


def _model_from_response_payload(
    payload: object,
    model_type: type[_ResponseModelT],
    *,
    location: str,
) -> _ResponseModelT:
    """Keep malformed judge payloads distinct from immutable-run integrity faults."""
    try:
        return _model_from_payload(payload, model_type, location=location)
    except EvaluationIntegrityError as error:
        raise ValueError(str(error)) from error


def _strict_case(case: AttorneyEvaluationCase) -> AttorneyEvaluationCase:
    return _strict_model_payload(case, AttorneyEvaluationCase)[0]


def _new_request(
    operation: JudgeOperation,
    *,
    system_instructions: str,
    json_schema: dict[str, object],
    payload: dict[str, object],
    safe_metadata: dict[str, str],
) -> JudgeRequest:
    provisional_payload: dict[str, object] = {
        "schema_version": "1.0",
        "operation": operation.value,
        "request_fingerprint": "0" * 64,
        "system_instructions": system_instructions,
        "json_schema": json_schema,
        "payload": payload,
        "safe_metadata": safe_metadata,
    }
    _ensure_ordinary_json(provisional_payload, location="JudgeRequest")
    try:
        provisional = JudgeRequest.model_validate(provisional_payload)
    except (ValidationError, TypeError, ValueError) as error:
        raise EvaluationIntegrityError("cannot construct strict judge request") from error
    _, ordinary = _strict_model_payload(provisional, JudgeRequest)
    fingerprint_payload = {
        key: value for key, value in ordinary.items() if key != "request_fingerprint"
    }
    ordinary["request_fingerprint"] = sha256_digest(canonical_json_bytes(fingerprint_payload))
    try:
        request = JudgeRequest.model_validate(ordinary)
    except (ValidationError, TypeError, ValueError) as error:
        raise EvaluationIntegrityError("cannot bind judge request fingerprint") from error
    return _strict_model_payload(request, JudgeRequest)[0]


def _request_path(call_id: str, attempt: int) -> str:
    return f"judge-requests/{call_id}-attempt-{attempt}.json"


def _response_path(call_id: str, attempt: int) -> str:
    return f"judge-responses/{call_id}-attempt-{attempt}.json"


def _diagnostics_path(call_id: str, attempt: int) -> str:
    return f"judge-diagnostics/{call_id}-attempt-{attempt}.json"


def _pending_call(
    call_id: str,
    request: JudgeRequest,
    *,
    attempt: int = 1,
    retry_count: int = 0,
    anonymous_label: Literal["A", "B"] | None = None,
) -> JudgeCallRecord:
    payload = {
        "call_id": call_id,
        "operation": request.operation.value,
        "anonymous_label": anonymous_label,
        "attempt": attempt,
        "prompt_fingerprint": _prompt_fingerprint(request),
        "request_fingerprint": request.request_fingerprint,
        "response_fingerprint": None,
        "provider_name": None,
        "model_name": None,
        "judge_isolation": None,
        "request_artifact_path": _request_path(call_id, attempt),
        "response_artifact_path": None,
        "diagnostics_artifact_path": None,
        "state": "pending",
        "retry_count": retry_count,
        "terminal_status": "pending",
    }
    try:
        call = JudgeCallRecord.model_validate(payload)
    except (ValidationError, TypeError, ValueError) as error:
        raise EvaluationIntegrityError("cannot construct pending judge-call record") from error
    return _strict_model_payload(call, JudgeCallRecord)[0]


def _completed_call(
    pending: JudgeCallRecord,
    response: JudgeResponse,
    response_fingerprint: str,
) -> JudgeCallRecord:
    payload = pending.model_dump(mode="json")
    payload.update(
        {
            "response_fingerprint": response_fingerprint,
            "provider_name": response.provider_name,
            "model_name": response.model_name,
            "judge_isolation": response.judge_isolation.value,
            "response_artifact_path": _response_path(pending.call_id, pending.attempt),
            "state": "completed",
            "terminal_status": "completed",
        }
    )
    return _strict_model_payload(JudgeCallRecord.model_validate(payload), JudgeCallRecord)[0]


def _failed_call(
    pending: JudgeCallRecord,
    response: JudgeResponse,
    response_fingerprint: str,
    *,
    terminal: bool,
) -> JudgeCallRecord:
    payload = pending.model_dump(mode="json")
    payload.update(
        {
            "response_fingerprint": response_fingerprint,
            "provider_name": response.provider_name,
            "model_name": response.model_name,
            "judge_isolation": response.judge_isolation.value,
            "response_artifact_path": _response_path(pending.call_id, pending.attempt),
            "diagnostics_artifact_path": _diagnostics_path(pending.call_id, pending.attempt),
            "state": "failed",
            "terminal_status": "inconclusive" if terminal else "failed",
        }
    )
    return _strict_model_payload(JudgeCallRecord.model_validate(payload), JudgeCallRecord)[0]


def _replace_call(
    calls: list[JudgeCallRecord],
    replacement: JudgeCallRecord,
) -> list[JudgeCallRecord]:
    result: list[JudgeCallRecord] = []
    replaced = False
    for call in calls:
        if call.call_id == replacement.call_id and call.attempt == replacement.attempt:
            result.append(replacement)
            replaced = True
        else:
            result.append(call)
    if not replaced:
        raise EvaluationIntegrityError("current judge call is absent from manifest")
    return result


def _manifest(
    *,
    case_fingerprint: str,
    case_envelope_hash: str,
    rubric_fingerprint: str,
    legal_ledger_hash: str | None,
    result_hash: str | None,
    judge_calls: list[JudgeCallRecord],
    artifacts: list[ArtifactRecord],
    state: EvaluationRunPhase,
    retry_count: int,
    terminal_status: EvaluationTerminalStatus | None,
) -> EvaluationManifest:
    calls = [_strict_model_payload(call, JudgeCallRecord)[1] for call in judge_calls]
    artifact_snapshots = sorted(
        (_strict_model_payload(artifact, ArtifactRecord)[1] for artifact in artifacts),
        key=lambda item: cast(str, item["artifact_path"]),
    )
    inventory_fingerprint = sha256_digest(canonical_json_bytes(artifact_snapshots))
    payload: dict[str, object] = {
        "schema_version": EVALUATION_ARTIFACT_SCHEMA_VERSION,
        "case_fingerprint": case_fingerprint,
        "case_envelope_hash": case_envelope_hash,
        "rubric_fingerprint": rubric_fingerprint,
        "legal_ledger_hash": legal_ledger_hash,
        "result_hash": result_hash,
        "judge_calls": calls,
        "artifacts": artifact_snapshots,
        "artifact_inventory_fingerprint": inventory_fingerprint,
        "state": state.value,
        "retry_count": retry_count,
        "terminal_status": None if terminal_status is None else terminal_status.value,
        "manifest_fingerprint": "0" * 64,
    }
    _ensure_ordinary_json(payload, location="EvaluationManifest")
    fingerprint_payload = {
        key: value for key, value in payload.items() if key != "manifest_fingerprint"
    }
    payload["manifest_fingerprint"] = sha256_digest(canonical_json_bytes(fingerprint_payload))
    try:
        manifest = EvaluationManifest.model_validate(payload)
    except (ValidationError, TypeError, ValueError) as error:
        raise EvaluationIntegrityError("cannot construct valid evaluation manifest") from error
    return _strict_model_payload(manifest, EvaluationManifest)[0]


def _state_from_manifest(manifest: EvaluationManifest) -> EvaluationRunState:
    pending = [call for call in manifest.judge_calls if call.state == "pending"]
    current = pending[0] if pending else None
    payload = {
        "schema_version": EVALUATION_ARTIFACT_SCHEMA_VERSION,
        "case_fingerprint": manifest.case_fingerprint,
        "case_envelope_hash": manifest.case_envelope_hash,
        "judge_calls": [call.model_dump(mode="json") for call in manifest.judge_calls],
        "current_operation": None if current is None else current.operation.value,
        "current_call_id": None if current is None else current.call_id,
        "attempt": 0 if current is None else current.attempt,
        "state": manifest.state.value,
        "retry_count": manifest.retry_count,
        "terminal_status": (
            None if manifest.terminal_status is None else manifest.terminal_status.value
        ),
        "manifest_fingerprint": manifest.manifest_fingerprint,
    }
    try:
        state = EvaluationRunState.model_validate(payload)
    except (ValidationError, TypeError, ValueError) as error:
        raise EvaluationIntegrityError("manifest cannot produce a valid run state") from error
    return _strict_model_payload(state, EvaluationRunState)[0]


def _commit(
    run_dir: _RunStorage,
    previous: EvaluationManifest,
    *,
    files: dict[str, bytes],
    judge_calls: list[JudgeCallRecord],
    state: EvaluationRunPhase,
    retry_count: int,
    terminal_status: EvaluationTerminalStatus | None = None,
    legal_ledger_hash: str | None = None,
    result_hash: str | None = None,
) -> EvaluationRunState:
    records = {artifact.artifact_path: artifact for artifact in previous.artifacts}
    for artifact_path, data in files.items():
        record = _artifact_record(artifact_path, data)
        existing = records.get(artifact_path)
        if existing is not None and existing != record:
            raise EvaluationIntegrityError(f"immutable artifact record differs: {artifact_path}")
        records[artifact_path] = record
    manifest = _manifest(
        case_fingerprint=previous.case_fingerprint,
        case_envelope_hash=previous.case_envelope_hash,
        rubric_fingerprint=previous.rubric_fingerprint,
        legal_ledger_hash=(
            previous.legal_ledger_hash if legal_ledger_hash is None else legal_ledger_hash
        ),
        result_hash=previous.result_hash if result_hash is None else result_hash,
        judge_calls=judge_calls,
        artifacts=list(records.values()),
        state=state,
        retry_count=retry_count,
        terminal_status=terminal_status,
    )
    for artifact_path, data in sorted(files.items()):
        _atomic_write(run_dir, artifact_path, data)
    _write_manifest(run_dir, manifest)
    return _state_from_manifest(manifest)


def _source_record(envelope: CaseEnvelope) -> dict[str, object]:
    request = build_admission_packet(envelope)
    return request.payload


def _build_ledger_request(envelope: CaseEnvelope) -> JudgeRequest:
    admission = build_admission_packet(envelope)
    return _new_request(
        JudgeOperation.BUILD_LEDGER,
        system_instructions=(
            "Build an atomic legal-requirement ledger from only the supplied source "
            "record. Check and satisfy every supplied ledger_invariant_contract invariant. "
            "Copy payload.source_record.source_record_fingerprint exactly into "
            "case_fingerprint. Use unique ledger and gap IDs and unique contiguous "
            "zero-based walk_order values. Use only known, non-self relationship IDs and "
            "known source IDs. Citations must be exact, nonduplicate half-open slices whose "
            "quote equals the cited source text. Give each operative category exact "
            "non-commentary support; each requirement, prohibition, or right an actor and "
            "object; each deadline timing; each exception a condition or exception; each "
            "enforcement entry an enforcing authority, route, and link to a requirement or "
            "prohibition; and each penalty or remedy a consequence. Enforcement and penalty "
            "entries must identify their triggering requirement or prohibition. Give every "
            "materiality decision a concrete legal or practical rationale. Do not infer "
            "from, request, or discuss candidate reports. Return only the complete LegalLedger."
        ),
        json_schema=LegalLedger.model_json_schema(),
        payload={
            "source_record": admission.payload,
            "ledger_invariant_contract": ledger_invariant_contract(),
        },
        safe_metadata={
            "record_scope": "source-only",
            "source_record_fingerprint": admission.safe_metadata["source_record_fingerprint"],
        },
    )


def _audit_ledger_request(
    envelope: CaseEnvelope,
    ledger: LegalLedger,
) -> JudgeRequest:
    ledger_payload = _strict_model_payload(ledger, LegalLedger)[1]
    source_record = _source_record(envelope)
    return _new_request(
        JudgeOperation.AUDIT_LEDGER,
        system_instructions=(
            "Adversarially audit the proposed ledger against only the supplied source "
            "record. Check every supplied ledger_invariant_contract invariant. Copy this "
            "request's request_fingerprint into the audit. Test every ledger invariant "
            "expressed by the response schema and the proposed entries: "
            "identity and walk order, relationships, exact citation slices, operative-source "
            "support, actor and object, timing, exception conditions, enforcement route and "
            "trigger links, consequences, and concrete materiality. Set complete=true only "
            "after the whole source record and ledger have been checked. Return every "
            "structured finding and no report-based reasoning. Initial findings must use "
            "the supplied audit_action_contract, be concrete enough for repair, and need "
            "not be transaction-ready. A proposal-free add must name an exact source_id "
            "and satisfy the source-grounding rule in that contract. Every supplied "
            "proposed entry must pass the disclosed exact-source validation."
        ),
        json_schema=LedgerAudit.model_json_schema(),
        payload={
            "source_record": source_record,
            "proposed_ledger": ledger_payload,
            "audit_action_contract": _audit_action_contract(),
            "ledger_invariant_contract": ledger_invariant_contract(),
        },
        safe_metadata={
            "record_scope": "source-only",
            "source_record_fingerprint": cast(str, source_record["source_record_fingerprint"]),
        },
    )


def _repair_ledger_request(
    envelope: CaseEnvelope,
    ledger: LegalLedger,
    audit: LedgerAudit,
) -> JudgeRequest:
    source_record = _source_record(envelope)
    return _new_request(
        JudgeOperation.REPAIR_LEDGER,
        system_instructions=(
            "Repair the proposed source-only ledger once. Return the complete repaired "
            "ledger, preserving payload.source_record.source_record_fingerprint as its "
            "case_fingerprint and checking every supplied ledger_invariant_contract "
            "invariant. Perform global walk-order renumbering, new-ID allocation for new "
            "entries, relationship remapping, exact-citation rechecking, and full closure "
            "validation before returning. In remaining_audit, "
            "copy this request's request_fingerprint, set complete=true only after checking "
            "the complete repair, resolve every initial finding, and include only disputes "
            "that genuinely remain. Every remaining dispute must be transaction-ready under "
            "the supplied audit_action_contract."
        ),
        json_schema=_LedgerRepairResponse.model_json_schema(),
        payload={
            "source_record": source_record,
            "proposed_ledger": _strict_model_payload(ledger, LegalLedger)[1],
            "audit": _strict_model_payload(audit, LedgerAudit)[1],
            "audit_action_contract": _audit_action_contract(),
            "ledger_invariant_contract": ledger_invariant_contract(),
        },
        safe_metadata={
            "record_scope": "source-only",
            "source_record_fingerprint": cast(str, source_record["source_record_fingerprint"]),
        },
    )


def _ledger_referee_request(
    envelope: CaseEnvelope,
    repaired_ledger: LegalLedger,
    dispute: LedgerDispute,
) -> JudgeRequest:
    return _new_request(
        JudgeOperation.REFEREE,
        system_instructions=(
            "Resolve only the supplied source-ledger dispute from its allowed alternatives. "
            "Copy the exact dispute_id. Select exactly one allowed ledger resolution. Use "
            "accept_a keeps the repaired ledger unchanged for this dispute; accept_b applies "
            "the supplied audit dispute to the repaired ledger. Use replace only with "
            "complete replacement_entries that satisfy the ledger-entry schema and source "
            "record. Give a concrete rationale and only known source_ids. Do not consider "
            "candidate reports or system identity."
        ),
        json_schema=RefereeDecision.model_json_schema(),
        payload=_ledger_referee_payload(envelope, repaired_ledger, dispute),
        safe_metadata={
            "record_scope": "source-only-dispute",
            "referee_scope": "ledger",
        },
    )


def _candidate_for_label(
    envelope: CaseEnvelope,
    label: Literal["A", "B"],
) -> CandidateReport:
    candidate_id = next(
        assignment.candidate_id
        for assignment in envelope.assignments
        if assignment.anonymous_label == label
    )
    return next(
        candidate
        for candidate in envelope.case.candidates
        if candidate.candidate_id == candidate_id
    )


def _grade_request(
    envelope: CaseEnvelope,
    sealed_ledger: SealedLedger,
    checks: DeterministicChecks,
    label: Literal["A", "B"],
    *,
    legal_ledger_hash: str,
) -> JudgeRequest:
    candidate = _candidate_for_label(envelope, label)
    payload: dict[str, object] = {
        "anonymous_report": {
            "anonymous_label": label,
            "report_hash": candidate.report_hash,
            "report_text": candidate.report_text,
        },
        "sealed_ledger": _strict_model_payload(sealed_ledger, SealedLedger)[1],
        "source_record": _source_record(envelope),
        "source_spans": _derive_source_spans(envelope, sealed_ledger),
        "deterministic_checks": _strict_model_payload(checks, DeterministicChecks)[1],
        "rubric": _strict_model_payload(RUBRIC_V1, EvaluationRubric)[1],
        "finding_code_contract": _finding_code_contract(),
    }
    return _new_request(
        JudgeOperation.GRADE_REPORT,
        system_instructions=(
            "Grade exactly one anonymous report against the sealed source-derived ledger. "
            "Copy this request's request_fingerprint, payload anonymous_label, and sealed "
            "ledger_fingerprint exactly; use schema_version 1.3. Return one entry_grade for "
            "every sealed ledger entry and each of the eight narrative dimensions exactly "
            "once: executive_summary, regulatory_walk, key_requirements, "
            "penalties_enforcement, qualification_placement, "
            "requirements_workplan_boundary, limitations, and scanability. A MISSING entry "
            "must omit report_location; every other content disposition must identify a "
            "specific report location. Bind each present entry and narrative finding to an "
            "exact report_passage. Do not use NOT_APPLICABLE. A present out-of-ledger claim "
            "cannot be MISSING or NOT_APPLICABLE; its claim_text must be an exact report "
            "passage and it must bind the common source_record_fingerprint plus exact source "
            "evidence_spans or an explicit closed_universe_absence. Use only finding-code "
            "enum values allowed by the schema and only when their supplied "
            "finding_code_contract context is satisfied. A bounded closed-record "
            "limitation such as 'the supplied record does "
            "not establish X' is not an affirmative out-of-ledger claim unless the report "
            "also asserts that X is absent from governing law. Do not infer identity, "
            "compare another report, or use an answer key."
        ),
        json_schema=CandidateGrade.model_json_schema(),
        payload=payload,
        safe_metadata={
            "record_scope": "one-anonymous-report",
            "anonymous_label": label,
            "legal_ledger_hash": legal_ledger_hash,
            "legal_ledger_fingerprint": sealed_ledger.ledger_fingerprint,
        },
    )


def _report_referee_request(
    envelope: CaseEnvelope,
    sealed_ledger: SealedLedger,
    dispute: GradeDispute,
    *,
    legal_ledger_hash: str,
) -> JudgeRequest:
    payload = _report_referee_payload(envelope, sealed_ledger, dispute)
    return _new_request(
        JudgeOperation.REFEREE,
        system_instructions=_report_referee_instructions(dispute),
        json_schema=RefereeDecision.model_json_schema(),
        payload=payload,
        safe_metadata={
            "record_scope": "one-material-dispute",
            "referee_scope": "report",
            "grade_dispute_fingerprint": model_fingerprint(dispute),
            "legal_ledger_hash": legal_ledger_hash,
        },
    )


def _retry_request(
    request: JudgeRequest,
    diagnostics_hash: str,
) -> JudgeRequest:
    if len(diagnostics_hash) != 64:
        raise EvaluationIntegrityError("retry diagnostics hash is malformed")
    # Retry the exact role packet.  Response models bind the original packet
    # fingerprint, while the failed call and diagnostics artifacts separately
    # prove why the second attempt was permitted.
    return _strict_model_payload(request, JudgeRequest)[0]


def _labels(envelope: CaseEnvelope) -> list[Literal["A", "B"]]:
    return [assignment.anonymous_label for assignment in envelope.assignments]


def _load_model(
    run_dir: _RunStorage,
    path: str,
    model_type: type[StrictModel],
) -> StrictModel:
    return _load_model_bytes(_read_artifact(run_dir, path), model_type, location=path)


def _result(
    readiness: CaseReadiness,
    reports: list[ReportEvaluation],
    requirement_matrix: RequirementMatrix,
    comparison: ComparisonEvaluation | None,
    judge_isolation: Literal["fresh_context", "sequential_same_context"],
) -> AttorneyEvaluationResult:
    readiness_snapshot = _strict_model_payload(readiness, CaseReadiness)[1]
    report_payloads = [_strict_model_payload(report, ReportEvaluation)[1] for report in reports]
    comparison_payload = (
        None if comparison is None else _strict_model_payload(comparison, ComparisonEvaluation)[1]
    )
    payload: dict[str, object] = {
        "schema_version": EVALUATION_ARTIFACT_SCHEMA_VERSION,
        "rubric": _strict_model_payload(RUBRIC_V1, EvaluationRubric)[1],
        "readiness": readiness_snapshot,
        "reports": report_payloads,
        "requirement_matrix": _strict_model_payload(
            requirement_matrix, RequirementMatrix
        )[1],
        "comparison": comparison_payload,
        "judge_isolation": judge_isolation,
        "result_fingerprint": "0" * 64,
    }
    _ensure_ordinary_json(payload, location="AttorneyEvaluationResult")
    provisional = AttorneyEvaluationResult.model_validate(payload)
    payload["result_fingerprint"] = _result_fingerprint(provisional)
    result = AttorneyEvaluationResult.model_validate(payload)
    return _strict_model_payload(result, AttorneyEvaluationResult)[0]


def _terminal_result(
    envelope: CaseEnvelope,
    readiness: CaseReadiness,
    disposition: ComparativeDisposition,
    judge_isolation: Literal["fresh_context", "sequential_same_context"],
) -> AttorneyEvaluationResult:
    comparison = (
        ComparisonEvaluation(disposition=disposition)
        if len(envelope.case.candidates) == 2
        else None
    )
    unavailable_reason: Literal["CASE_INVALID", "INCONCLUSIVE"] = (
        "CASE_INVALID"
        if disposition is ComparativeDisposition.CASE_INVALID
        else "INCONCLUSIVE"
    )
    matrix = RequirementMatrix(
        available=False,
        unavailable_reason=unavailable_reason,
        rows=[],
    )
    return _result(readiness, [], matrix, comparison, judge_isolation)


def _aggregate_judge_isolation(
    calls: list[JudgeCallRecord],
    current: JudgeIsolation | None = None,
) -> Literal["fresh_context", "sequential_same_context"]:
    values = [
        call.judge_isolation
        for call in calls
        if call.state != "pending" and call.judge_isolation is not None
    ]
    if current is not None:
        values.append(current)
    if JudgeIsolation.SEQUENTIAL_SAME_CONTEXT in values:
        return "sequential_same_context"
    return "fresh_context"


def _inconclusive_readiness(
    envelope: CaseEnvelope,
    *,
    fingerprint: str,
    issue_code: str,
    rationale: str,
    existing: CaseReadiness | None = None,
) -> CaseReadiness:
    issue_codes = [] if existing is None else list(existing.issue_codes)
    if issue_code not in issue_codes:
        issue_codes.append(issue_code)
    return CaseReadiness(
        status=ReadinessStatus.INCONCLUSIVE,
        case_fingerprint=envelope.case_fingerprint,
        judgment_fingerprint=(fingerprint if existing is None else existing.judgment_fingerprint),
        issue_codes=issue_codes,
        rationale=rationale,
    )


def initialize_evaluation(
    case: AttorneyEvaluationCase,
    output_dir: Path,
    *,
    seed_hex: str,
    generation_capsule_paths: Mapping[str, Path] | None = None,
) -> EvaluationRunState:
    """Freeze one case and create its first immutable admission request."""
    case = _strict_case(case)
    if case.schema_version != "1.1":
        raise ValueError("case schema 1.1 is required for new evaluation runs")
    _verify_generation_capsules_for_initialization(case, generation_capsule_paths)
    envelope = freeze_case(case, seed_hex=seed_hex)
    envelope, envelope_bytes = _model_bytes(envelope, CaseEnvelope)
    rubric, rubric_bytes = _model_bytes(RUBRIC_V1, EvaluationRubric)
    request = _strict_model_payload(build_admission_packet(envelope), JudgeRequest)[0]
    request, request_bytes = _model_bytes(request, JudgeRequest)
    call = _pending_call("admission", request)
    files = {
        _CASE_ENVELOPE_PATH: envelope_bytes,
        _RUBRIC_PATH: rubric_bytes,
        call.request_artifact_path: request_bytes,
    }
    artifacts = [_artifact_record(path, data) for path, data in files.items()]
    manifest = _manifest(
        case_fingerprint=envelope.case_fingerprint,
        case_envelope_hash=sha256_digest(envelope_bytes),
        rubric_fingerprint=model_fingerprint(rubric),
        legal_ledger_hash=None,
        result_hash=None,
        judge_calls=[call],
        artifacts=artifacts,
        state=EvaluationRunPhase.ADMISSION,
        retry_count=0,
        terminal_status=None,
    )
    with _open_run_storage(output_dir, initialize=True) as storage:
        for artifact_path, data in sorted(files.items()):
            _atomic_write(storage, artifact_path, data)
        _write_manifest(storage, manifest)
        storage.assert_root_identity()
    return _state_from_manifest(manifest)


def resume_evaluation(run_dir: Path) -> EvaluationRunState:
    """Verify an entire run before exposing resumable state."""
    with _open_run_storage(run_dir) as storage:
        manifest, _, _ = _verify_evaluation_run_or_raise(storage)
        storage.assert_root_identity()
        return _state_from_manifest(manifest)


def next_judge_request(run_dir: Path) -> JudgeRequest | None:
    """Return the exact pending request only after full run verification."""
    with _open_run_storage(run_dir) as storage:
        manifest, _, _ = _verify_evaluation_run_or_raise(storage)
        state = _state_from_manifest(manifest)
        if state.terminal_status is not None:
            return None
        pending = [call for call in state.judge_calls if call.state == "pending"]
        if len(pending) != 1:
            raise EvaluationIntegrityError("run does not contain exactly one pending request")
        call = pending[0]
        request = _load_model_bytes(
            _read_artifact(storage, call.request_artifact_path),
            JudgeRequest,
            location=call.request_artifact_path,
        )
        if request.request_fingerprint != call.request_fingerprint:
            raise EvaluationIntegrityError("pending request fingerprint mismatch")
        storage.assert_root_identity()
        return request


def _load_readiness(run_dir: _RunStorage) -> CaseReadiness | None:
    try:
        return cast(
            CaseReadiness,
            _load_model(run_dir, _READINESS_PATH, CaseReadiness),
        )
    except EvaluationIntegrityError as error:
        if "missing" in str(error):
            return None
        raise


def _sealed_files_and_grade_start(
    envelope: CaseEnvelope,
    sealed: SealedLedger,
) -> _AcceptedTransition:
    sealed, sealed_bytes = _model_bytes(sealed, SealedLedger)
    legal_hash = sha256_digest(sealed_bytes)
    files: dict[str, bytes] = {_SEALED_LEDGER_PATH: sealed_bytes}
    labels = _labels(envelope)
    for label in labels:
        checks = _derive_deterministic_checks(_candidate_for_label(envelope, label), label)
        _, checks_bytes = _model_bytes(checks, DeterministicChecks)
        files[f"deterministic-checks-{label}.json"] = checks_bytes
    first_label = labels[0]
    first_checks = _load_model_bytes(
        files[f"deterministic-checks-{first_label}.json"],
        DeterministicChecks,
        location=f"deterministic-checks-{first_label}.json",
    )
    request = _grade_request(
        envelope,
        sealed,
        first_checks,
        first_label,
        legal_ledger_hash=legal_hash,
    )
    return _AcceptedTransition(
        files,
        request,
        f"grade-{first_label}-1",
        first_label,
        EvaluationRunPhase.GRADE_A,
        legal_ledger_hash=legal_hash,
    )


def _grade_artifact_path(call: JudgeCallRecord) -> str:
    parts = call.call_id.split("-")
    if len(parts) != 3 or parts[0] != "grade" or parts[1] not in {"A", "B"}:
        raise EvaluationIntegrityError("grade call ID is malformed")
    return f"grader-{parts[2]}-report-{parts[1]}.json"


def _grade_number(call: JudgeCallRecord) -> int:
    try:
        return int(call.call_id.rsplit("-", maxsplit=1)[1])
    except (IndexError, ValueError) as error:
        raise EvaluationIntegrityError("grade call ID lacks grader number") from error


def _load_grades(
    run_dir: _RunStorage,
    label: Literal["A", "B"],
    extra_files: dict[str, bytes] | None = None,
) -> tuple[CandidateGrade, CandidateGrade]:
    values: list[CandidateGrade] = []
    for number in (1, 2):
        path = f"grader-{number}-report-{label}.json"
        data = (
            extra_files[path]
            if extra_files is not None and path in extra_files
            else _read_artifact(run_dir, path)
        )
        values.append(_load_model_bytes(data, CandidateGrade, location=path))
    return values[0], values[1]


def _all_disputes(
    run_dir: _RunStorage,
    envelope: CaseEnvelope,
    sealed: SealedLedger,
    extra_files: dict[str, bytes] | None = None,
) -> list[GradeDispute]:
    result: list[GradeDispute] = []
    for label in _labels(envelope):
        first, second = _load_grades(run_dir, label, extra_files)
        result.extend(material_disputes(sealed, first, second))
    return result


def _disputes_payload(disputes: list[GradeDispute]) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": EVALUATION_ARTIFACT_SCHEMA_VERSION,
        "disputes": [_strict_model_payload(dispute, GradeDispute)[1] for dispute in disputes],
    }
    _ensure_ordinary_json(payload, location="report disputes")
    return payload


def _load_disputes(run_dir: _RunStorage) -> list[GradeDispute]:
    payload = _dict_value(
        _parse_json_bytes(
            _read_artifact(run_dir, _REPORT_DISPUTES_PATH),
            location=_REPORT_DISPUTES_PATH,
        ),
        location="report disputes",
    )
    _require_artifact_schema(payload, location=_REPORT_DISPUTES_PATH)
    if set(payload) != {"schema_version", "disputes"}:
        raise EvaluationIntegrityError("report disputes artifact has unexpected shape")
    raw_disputes = payload["disputes"]
    if not isinstance(raw_disputes, list):
        raise EvaluationIntegrityError("report disputes must be an array")
    return [
        _model_from_payload(item, GradeDispute, location="report dispute") for item in raw_disputes
    ]


def _referee_artifact_path(index: int, dispute: GradeDispute) -> str:
    token = model_fingerprint(dispute)[:12]
    return f"referee-report-{dispute.anonymous_label}-{index + 1}-{token}.json"


def _load_referee_decisions(
    run_dir: _RunStorage,
    disputes: list[GradeDispute],
    label: Literal["A", "B"],
    extra_files: dict[str, bytes] | None = None,
) -> list[RefereeDecision]:
    decisions: list[RefereeDecision] = []
    for index, dispute in enumerate(disputes):
        if dispute.anonymous_label != label:
            continue
        path = _referee_artifact_path(index, dispute)
        if extra_files is not None and path in extra_files:
            data = extra_files[path]
        else:
            try:
                data = _read_artifact(run_dir, path)
            except EvaluationIntegrityError:
                continue
        decisions.append(_load_model_bytes(data, RefereeDecision, location=path))
    return decisions


def _aggregate(
    run_dir: _RunStorage,
    envelope: CaseEnvelope,
    sealed: SealedLedger,
    readiness: CaseReadiness,
    *,
    judge_isolation: Literal["fresh_context", "sequential_same_context"],
    extra_files: dict[str, bytes] | None = None,
) -> _AcceptedTransition:
    files: dict[str, bytes] = {}
    disputes = _all_disputes(run_dir, envelope, sealed, extra_files)
    reports: list[ReportEvaluation] = []
    inputs_by_label: dict[str, ReportScoreInputs] = {}
    resolved_by_label: dict[Literal["A", "B"], ResolvedGrade] = {}
    source_record = build_admission_packet(envelope).payload
    source_record_bytes = canonical_json_bytes(source_record)
    for label in _labels(envelope):
        first, second = _load_grades(run_dir, label, extra_files)
        decisions = _load_referee_decisions(run_dir, disputes, label, extra_files)
        resolved = resolve_grades(sealed, first, second, decisions)
        resolved_payload = _serialize_resolved_grade(sealed, resolved)
        files[f"resolved-grade-{label}.json"] = _ordinary_json_bytes(resolved_payload)
        checks_path = f"deterministic-checks-{label}.json"
        checks_data = (
            extra_files[checks_path]
            if extra_files is not None and checks_path in extra_files
            else _read_artifact(run_dir, checks_path)
        )
        checks = _load_model_bytes(
            checks_data,
            DeterministicChecks,
            location=checks_path,
        )
        score_inputs_payload = _score_inputs_payload(
            sealed,
            resolved,
            checks,
            RUBRIC_V1,
            source_record,
        )
        files[f"report-score-inputs-{label}.json"] = _ordinary_json_bytes(score_inputs_payload)
        inputs = ReportScoreInputs(sealed, resolved, checks, source_record_bytes)
        report = score_report(
            sealed,
            resolved,
            checks,
            RUBRIC_V1,
            source_record=source_record,
        )
        _, report_bytes = _model_bytes(report, ReportEvaluation)
        files[f"report-evaluation-{label}.json"] = report_bytes
        reports.append(report)
        inputs_by_label[label] = inputs
        resolved_by_label[label] = resolved

    comparison: ComparisonEvaluation | None = None
    if len(envelope.case.candidates) == 2:
        assignments = {
            assignment.candidate_id: assignment.anonymous_label
            for assignment in envelope.assignments
        }
        candidate_id = next(
            item.candidate_id
            for item in envelope.case.candidates
            if item.role is CandidateRole.CANDIDATE
        )
        comparator_id = next(
            item.candidate_id
            for item in envelope.case.candidates
            if item.role is CandidateRole.COMPARATOR
        )
        candidate_label = assignments[candidate_id]
        comparator_label = assignments[comparator_id]
        reports_by_label = {report.anonymous_label: report for report in reports}
        comparison = compare_reports(
            reports_by_label[candidate_label],
            reports_by_label[comparator_label],
            RUBRIC_V1,
            candidate_inputs=inputs_by_label[candidate_label],
            comparator_inputs=inputs_by_label[comparator_label],
        )
    requirement_matrix = _derive_requirement_matrix(
        sealed,
        resolved_by_label,
    )
    result = _result(
        readiness,
        reports,
        requirement_matrix,
        comparison,
        judge_isolation,
    )
    result, result_bytes = _model_bytes(result, AttorneyEvaluationResult)
    report_text = render_evaluation_report(result)
    report_bytes = report_text.encode("utf-8")
    files[_RESULT_PATH] = result_bytes
    files[_REPORT_PATH] = report_bytes
    return _AcceptedTransition(
        files,
        None,
        None,
        None,
        EvaluationRunPhase.COMPLETED,
        terminal_status=EvaluationTerminalStatus.COMPLETED,
        result_hash=sha256_digest(result_bytes),
    )


def _after_all_grades(
    run_dir: _RunStorage,
    envelope: CaseEnvelope,
    sealed: SealedLedger,
    readiness: CaseReadiness,
    *,
    grade_files: dict[str, bytes],
    legal_ledger_hash: str,
    judge_isolation: Literal["fresh_context", "sequential_same_context"],
) -> _AcceptedTransition:
    disputes = _all_disputes(run_dir, envelope, sealed, grade_files)
    disputes_bytes = _ordinary_json_bytes(_disputes_payload(disputes))
    grade_files[_REPORT_DISPUTES_PATH] = disputes_bytes
    if not disputes:
        aggregated = _aggregate(
            run_dir,
            envelope,
            sealed,
            readiness,
            judge_isolation=judge_isolation,
            extra_files=grade_files,
        )
        return _AcceptedTransition(
            {**grade_files, **aggregated.files},
            None,
            None,
            None,
            aggregated.state,
            aggregated.terminal_status,
            legal_ledger_hash,
            aggregated.result_hash,
        )
    first = disputes[0]
    request = _report_referee_request(
        envelope,
        sealed,
        first,
        legal_ledger_hash=legal_ledger_hash,
    )
    return _AcceptedTransition(
        grade_files,
        request,
        "report-referee-1",
        first.anonymous_label,
        EvaluationRunPhase.REPORT_REFEREE,
        legal_ledger_hash=legal_ledger_hash,
    )


def _accepted_transition(
    run_dir: _RunStorage,
    manifest: EvaluationManifest,
    envelope: CaseEnvelope,
    pending: JudgeCallRecord,
    request: JudgeRequest,
    response: JudgeResponse,
) -> _AcceptedTransition:
    if response.operation is not request.operation:
        raise ValueError("response operation does not match request operation")
    if response.request_fingerprint != request.request_fingerprint:
        raise ValueError("response does not bind the exact request")
    aggregate_isolation = _aggregate_judge_isolation(
        manifest.judge_calls,
        response.judge_isolation,
    )

    if request.operation is JudgeOperation.ADMIT_CASE:
        judgment = _model_from_response_payload(
            response.payload,
            CaseAdmissionJudgment,
            location="admission response payload",
        )
        readiness = adjudicate_admission(envelope, judgment)
        readiness, readiness_bytes = _model_bytes(readiness, CaseReadiness)
        files = {_READINESS_PATH: readiness_bytes}
        if readiness.status is ReadinessStatus.CASE_INVALID:
            result = _terminal_result(
                envelope,
                readiness,
                ComparativeDisposition.CASE_INVALID,
                aggregate_isolation,
            )
            result, result_bytes = _model_bytes(result, AttorneyEvaluationResult)
            files[_RESULT_PATH] = result_bytes
            files[_REPORT_PATH] = render_evaluation_report(result).encode("utf-8")
            return _AcceptedTransition(
                files,
                None,
                None,
                None,
                EvaluationRunPhase.CASE_INVALID,
                EvaluationTerminalStatus.CASE_INVALID,
                result_hash=sha256_digest(result_bytes),
            )
        next_request = _build_ledger_request(envelope)
        return _AcceptedTransition(
            files,
            next_request,
            "ledger-build",
            None,
            EvaluationRunPhase.LEDGER_BUILD,
        )

    current_readiness = _load_readiness(run_dir)
    if current_readiness is None or current_readiness.status is not ReadinessStatus.ADMITTED:
        raise EvaluationIntegrityError("post-admission operation lacks admitted readiness")

    if request.operation is JudgeOperation.BUILD_LEDGER:
        ledger = _model_from_response_payload(
            response.payload, LegalLedger, location="ledger builder response payload"
        )
        issues = validate_ledger(envelope, ledger)
        if issues:
            raise ValueError(
                "invalid proposed ledger: " + ", ".join(issue.code for issue in issues)
            )
        ledger, ledger_bytes = _model_bytes(ledger, LegalLedger)
        next_request = _audit_ledger_request(envelope, ledger)
        return _AcceptedTransition(
            {_PROPOSED_LEDGER_PATH: ledger_bytes},
            next_request,
            "ledger-audit",
            None,
            EvaluationRunPhase.LEDGER_AUDIT,
        )

    proposed = cast(
        LegalLedger,
        _load_model(run_dir, _PROPOSED_LEDGER_PATH, LegalLedger),
    )
    if request.operation is JudgeOperation.AUDIT_LEDGER:
        audit = _model_from_response_payload(
            response.payload, LedgerAudit, location="ledger audit response payload"
        )
        if audit.request_fingerprint != request.request_fingerprint:
            raise ValueError("ledger audit does not bind the exact audit request")
        disputes = ledger_findings(envelope, proposed, audit)
        audit, audit_bytes = _model_bytes(audit, LedgerAudit)
        files = {_LEDGER_AUDIT_PATH: audit_bytes}
        if disputes:
            repair_request = _repair_ledger_request(envelope, proposed, audit)
            return _AcceptedTransition(
                files,
                repair_request,
                "ledger-repair",
                None,
                EvaluationRunPhase.LEDGER_REPAIR,
            )
        sealed = seal_ledger(envelope, proposed, audit, None)
        grade_start = _sealed_files_and_grade_start(envelope, sealed)
        return _AcceptedTransition(
            {**files, **grade_start.files},
            grade_start.next_request,
            grade_start.next_call_id,
            grade_start.next_label,
            grade_start.state,
            legal_ledger_hash=grade_start.legal_ledger_hash,
        )

    if request.operation is JudgeOperation.REPAIR_LEDGER:
        repaired_response = _model_from_response_payload(
            response.payload,
            _LedgerRepairResponse,
            location="ledger repair response payload",
        )
        repaired = repaired_response.repaired_ledger
        remaining = repaired_response.remaining_audit
        if remaining.request_fingerprint != request.request_fingerprint:
            raise ValueError("remaining ledger audit does not bind repair request")
        issues = validate_ledger(envelope, repaired)
        if issues:
            raise ValueError(
                "invalid repaired ledger: " + ", ".join(issue.code for issue in issues)
            )
        disputes = ledger_disputes(remaining)
        repaired, repaired_bytes = _model_bytes(repaired, LegalLedger)
        remaining, remaining_bytes = _model_bytes(remaining, LedgerAudit)
        files = {
            _REPAIRED_LEDGER_PATH: repaired_bytes,
            _REMAINING_AUDIT_PATH: remaining_bytes,
        }
        material = [
            dispute
            for dispute in disputes
            if dispute.materiality in {Materiality.MATERIAL, Materiality.CRITICAL}
        ]
        if len(material) > 1:
            inconclusive = _inconclusive_readiness(
                envelope,
                fingerprint=model_fingerprint(remaining),
                issue_code="MULTIPLE_LEDGER_DISPUTES_UNRESOLVED",
                rationale="More than one material ledger dispute remained after repair.",
                existing=current_readiness,
            )
            result = _terminal_result(
                envelope,
                inconclusive,
                ComparativeDisposition.INCONCLUSIVE,
                aggregate_isolation,
            )
            _, result_bytes = _model_bytes(result, AttorneyEvaluationResult)
            terminal_readiness_bytes = _model_bytes(inconclusive, CaseReadiness)[1]
            files[_TERMINAL_READINESS_PATH] = terminal_readiness_bytes
            files[_RESULT_PATH] = result_bytes
            files[_REPORT_PATH] = render_evaluation_report(result).encode("utf-8")
            return _AcceptedTransition(
                files,
                None,
                None,
                None,
                EvaluationRunPhase.INCONCLUSIVE,
                EvaluationTerminalStatus.INCONCLUSIVE,
                result_hash=sha256_digest(result_bytes),
            )
        if material:
            referee_request = _ledger_referee_request(envelope, repaired, material[0])
            return _AcceptedTransition(
                files,
                referee_request,
                "ledger-referee",
                None,
                EvaluationRunPhase.LEDGER_REFEREE,
            )
        sealed = seal_ledger(envelope, repaired, remaining, None)
        grade_start = _sealed_files_and_grade_start(envelope, sealed)
        return _AcceptedTransition(
            {**files, **grade_start.files},
            grade_start.next_request,
            grade_start.next_call_id,
            grade_start.next_label,
            grade_start.state,
            legal_ledger_hash=grade_start.legal_ledger_hash,
        )

    if (
        request.operation is JudgeOperation.REFEREE
        and request.safe_metadata.get("referee_scope") == "ledger"
    ):
        repaired = cast(
            LegalLedger,
            _load_model(run_dir, _REPAIRED_LEDGER_PATH, LegalLedger),
        )
        remaining = cast(
            LedgerAudit,
            _load_model(run_dir, _REMAINING_AUDIT_PATH, LedgerAudit),
        )
        decision = _model_from_response_payload(
            response.payload, RefereeDecision, location="ledger referee response payload"
        )
        decision, decision_bytes = _model_bytes(decision, RefereeDecision)
        sealed = seal_ledger(envelope, repaired, remaining, decision)
        grade_start = _sealed_files_and_grade_start(envelope, sealed)
        return _AcceptedTransition(
            {_LEDGER_REFEREE_PATH: decision_bytes, **grade_start.files},
            grade_start.next_request,
            grade_start.next_call_id,
            grade_start.next_label,
            grade_start.state,
            legal_ledger_hash=grade_start.legal_ledger_hash,
        )

    sealed = cast(
        SealedLedger,
        _load_model(run_dir, _SEALED_LEDGER_PATH, SealedLedger),
    )
    legal_hash = manifest.legal_ledger_hash
    if legal_hash is None:
        raise EvaluationIntegrityError("grading operation lacks sealed-ledger hash")

    if request.operation is JudgeOperation.GRADE_REPORT:
        if (
            not isinstance(response.payload, dict)
            or response.payload.get("schema_version") != EVALUATION_ARTIFACT_SCHEMA_VERSION
        ):
            raise ValueError("grade response schema version is unsupported")
        grade = _model_from_response_payload(
            response.payload, CandidateGrade, location="grade response payload"
        )
        if grade.request_fingerprint != request.request_fingerprint:
            raise ValueError("grade does not bind the exact grade request")
        if pending.anonymous_label != grade.anonymous_label:
            raise ValueError("grade anonymous label mismatch")
        issues = validate_grade(sealed, grade)
        if issues:
            raise ValueError(
                "invalid candidate grade: "
                + ", ".join(f"{issue.code}: {issue.message}" for issue in issues)
            )
        try:
            _validate_grade_evidence(envelope, grade)
        except EvaluationIntegrityError as error:
            # Response evidence defects remain retryable submit validation failures;
            # storage and transition integrity faults still propagate unchanged.
            raise ValueError(str(error)) from error
        grade, grade_bytes = _model_bytes(grade, CandidateGrade)
        grade_files = {_grade_artifact_path(pending): grade_bytes}
        if pending.anonymous_label not in {"A", "B"}:
            raise EvaluationIntegrityError("grade call lacks an anonymous label")
        label = pending.anonymous_label
        number = _grade_number(pending)
        if number == 1:
            checks = cast(
                DeterministicChecks,
                _load_model(
                    run_dir,
                    f"deterministic-checks-{label}.json",
                    DeterministicChecks,
                ),
            )
            next_request = _grade_request(
                envelope,
                sealed,
                checks,
                label,
                legal_ledger_hash=legal_hash,
            )
            return _AcceptedTransition(
                grade_files,
                next_request,
                f"grade-{label}-2",
                label,
                EvaluationRunPhase.GRADE_A if label == "A" else EvaluationRunPhase.GRADE_B,
                legal_ledger_hash=legal_hash,
            )
        labels = _labels(envelope)
        current_index = labels.index(label)
        if current_index + 1 < len(labels):
            next_label = labels[current_index + 1]
            checks = cast(
                DeterministicChecks,
                _load_model(
                    run_dir,
                    f"deterministic-checks-{next_label}.json",
                    DeterministicChecks,
                ),
            )
            next_request = _grade_request(
                envelope,
                sealed,
                checks,
                next_label,
                legal_ledger_hash=legal_hash,
            )
            return _AcceptedTransition(
                grade_files,
                next_request,
                f"grade-{next_label}-1",
                next_label,
                EvaluationRunPhase.GRADE_B,
                legal_ledger_hash=legal_hash,
            )
        return _after_all_grades(
            run_dir,
            envelope,
            sealed,
            current_readiness,
            grade_files=grade_files,
            legal_ledger_hash=legal_hash,
            judge_isolation=aggregate_isolation,
        )

    if (
        request.operation is JudgeOperation.REFEREE
        and request.safe_metadata.get("referee_scope") == "report"
    ):
        decision = _model_from_response_payload(
            response.payload, RefereeDecision, location="report referee response payload"
        )
        report_disputes = _load_disputes(run_dir)
        completed_referees = [
            call
            for call in manifest.judge_calls
            if call.operation is JudgeOperation.REFEREE
            and call.state == "completed"
            and call.anonymous_label is not None
        ]
        index = len(completed_referees)
        if index >= len(report_disputes):
            raise EvaluationIntegrityError("report referee cursor exceeds dispute list")
        dispute = report_disputes[index]
        if decision.dispute_id != dispute.dispute_id:
            raise ValueError("referee decision does not identify the pending dispute")
        _validate_report_referee_decision(run_dir, envelope, dispute, decision)
        decision, decision_bytes = _model_bytes(decision, RefereeDecision)
        decision_path = _referee_artifact_path(index, dispute)
        files = {decision_path: decision_bytes}
        if index + 1 < len(report_disputes):
            next_dispute = report_disputes[index + 1]
            next_request = _report_referee_request(
                envelope,
                sealed,
                next_dispute,
                legal_ledger_hash=legal_hash,
            )
            return _AcceptedTransition(
                files,
                next_request,
                f"report-referee-{index + 2}",
                next_dispute.anonymous_label,
                EvaluationRunPhase.REPORT_REFEREE,
                legal_ledger_hash=legal_hash,
            )
        aggregated = _aggregate(
            run_dir,
            envelope,
            sealed,
            current_readiness,
            judge_isolation=aggregate_isolation,
            extra_files=files,
        )
        return _AcceptedTransition(
            {**files, **aggregated.files},
            None,
            None,
            None,
            aggregated.state,
            aggregated.terminal_status,
            legal_hash,
            aggregated.result_hash,
        )

    raise ValueError("unsupported judge operation for current workflow state")


def _inconclusive_transition(
    run_dir: _RunStorage,
    envelope: CaseEnvelope,
    response_fingerprint: str,
    diagnostics: bytes,
    judge_isolation: Literal["fresh_context", "sequential_same_context"],
) -> _AcceptedTransition:
    existing = _load_readiness(run_dir)
    readiness = _inconclusive_readiness(
        envelope,
        fingerprint=response_fingerprint,
        issue_code="JUDGE_RESPONSE_INVALID",
        rationale="The judge returned invalid structured output twice.",
        existing=existing,
    )
    result = _terminal_result(
        envelope,
        readiness,
        ComparativeDisposition.INCONCLUSIVE,
        judge_isolation,
    )
    result, result_bytes = _model_bytes(result, AttorneyEvaluationResult)
    files = {
        (_READINESS_PATH if existing is None else _TERMINAL_READINESS_PATH): _model_bytes(
            readiness, CaseReadiness
        )[1],
        _RESULT_PATH: result_bytes,
        _REPORT_PATH: render_evaluation_report(result).encode("utf-8"),
    }
    # Keep diagnostics live in the transition calculation to ensure it was validated first.
    if not diagnostics:
        raise EvaluationIntegrityError("invalid response diagnostics are empty")
    return _AcceptedTransition(
        files,
        None,
        None,
        None,
        EvaluationRunPhase.INCONCLUSIVE,
        EvaluationTerminalStatus.INCONCLUSIVE,
        result_hash=sha256_digest(result_bytes),
    )


def _commit_validated_response(
    run_dir: _RunStorage,
    context: _PreflightSubmissionContext,
    response: JudgeResponse,
    response_bytes: bytes,
) -> EvaluationRunState:
    """Commit the exact transition that preflight already calculated."""
    if context.transition is None:
        raise EvaluationIntegrityError("validated response lacks an accepted transition")
    response_fingerprint = sha256_digest(response_bytes)
    response_path = _response_path(context.pending.call_id, context.pending.attempt)
    files: dict[str, bytes] = {response_path: response_bytes}
    calls = _replace_call(
        list(context.manifest.judge_calls),
        _completed_call(context.pending, response, response_fingerprint),
    )
    files.update(context.transition.files)
    if context.transition.next_request is not None:
        if context.transition.next_call_id is None:
            raise EvaluationIntegrityError("next request lacks a logical call ID")
        next_call = _pending_call(
            context.transition.next_call_id,
            context.transition.next_request,
            anonymous_label=context.transition.next_label,
        )
        _, next_bytes = _model_bytes(context.transition.next_request, JudgeRequest)
        files[next_call.request_artifact_path] = next_bytes
        calls.append(next_call)
    return _commit(
        run_dir,
        context.manifest,
        files=files,
        judge_calls=calls,
        state=context.transition.state,
        retry_count=context.manifest.retry_count,
        terminal_status=context.transition.terminal_status,
        legal_ledger_hash=context.transition.legal_ledger_hash,
        result_hash=context.transition.result_hash,
    )


def _commit_invalid_response(
    run_dir: _RunStorage,
    context: _PreflightSubmissionContext,
    response: JudgeResponse,
    response_bytes: bytes,
) -> EvaluationRunState:
    """Preserve explicit-submit retry semantics for a rejected response."""
    error = context.validation_error
    if error is None:
        raise EvaluationIntegrityError("rejected response lacks a validation error")
    response_fingerprint = sha256_digest(response_bytes)
    response_path = _response_path(context.pending.call_id, context.pending.attempt)
    files: dict[str, bytes] = {response_path: response_bytes}
    calls = list(context.manifest.judge_calls)
    diagnostic_payload = {
            "schema_version": "1.0",
            "call_id": context.pending.call_id,
            "attempt": context.pending.attempt,
            "operation": context.pending.operation.value,
            "response_fingerprint": response_fingerprint,
            "issues": [
                {
                    "code": "JUDGE_RESPONSE_INVALID",
                    "message": str(error) or type(error).__name__,
                }
            ],
        }
    diagnostics = _ordinary_json_bytes(diagnostic_payload)
    diagnostics_path = _diagnostics_path(context.pending.call_id, context.pending.attempt)
    files[diagnostics_path] = diagnostics
    terminal = context.pending.attempt >= 2
    failed = _failed_call(context.pending, response, response_fingerprint, terminal=terminal)
    calls = _replace_call(calls, failed)
    if terminal:
        inconclusive = _inconclusive_transition(
            run_dir,
            context.envelope,
            response_fingerprint,
            diagnostics,
            _aggregate_judge_isolation(calls),
        )
        files.update(inconclusive.files)
        return _commit(
            run_dir,
            context.manifest,
            files=files,
            judge_calls=calls,
            state=inconclusive.state,
            retry_count=context.manifest.retry_count,
            terminal_status=inconclusive.terminal_status,
            legal_ledger_hash=context.manifest.legal_ledger_hash,
            result_hash=inconclusive.result_hash,
        )
    retry_request = _retry_request(context.request, sha256_digest(diagnostics))
    retry_call = _pending_call(
        context.pending.call_id,
        retry_request,
        attempt=2,
        retry_count=1,
        anonymous_label=context.pending.anonymous_label,
    )
    _, retry_bytes = _model_bytes(retry_request, JudgeRequest)
    files[retry_call.request_artifact_path] = retry_bytes
    calls.append(retry_call)
    return _commit(
        run_dir,
        context.manifest,
        files=files,
        judge_calls=calls,
        state=context.manifest.state,
        retry_count=context.manifest.retry_count + 1,
        legal_ledger_hash=context.manifest.legal_ledger_hash,
    )


def _submit_judge_response_in_storage(
    run_dir: _RunStorage,
    response: JudgeResponse,
    response_bytes: bytes,
) -> EvaluationRunState:
    preflight, context = _preflight_in_storage(
        run_dir,
        response,
        pending_error="response submission requires one pending call",
    )
    if preflight.ok:
        if context is None:
            raise EvaluationIntegrityError("successful preflight lacks a submission context")
        return _commit_validated_response(run_dir, context, response, response_bytes)
    if context is None:
        raise EvaluationIntegrityError("response submission requires one pending call")
    return _commit_invalid_response(run_dir, context, response, response_bytes)


def _preflight_result(
    request: JudgeRequest | None,
    *,
    issue: EvaluationPreflightIssue | None = None,
) -> EvaluationPreflightResult:
    issues = [] if issue is None else [issue]
    diagnostic_fingerprint = (
        None
        if issue is None or request is None
        else sha256_digest(
            canonical_json_bytes(
                {
                    "issues": [item.model_dump(mode="json") for item in issues],
                    "operation": request.operation.value,
                    "request_fingerprint": request.request_fingerprint,
                }
            )
        )
    )
    return EvaluationPreflightResult(
        ok=issue is None,
        operation=None if request is None else request.operation,
        request_fingerprint=None if request is None else request.request_fingerprint,
        issues=issues,
        diagnostic_fingerprint=diagnostic_fingerprint,
    )


def _preflight_in_storage(
    run_dir: _RunStorage,
    response: JudgeResponse,
    *,
    pending_error: str = "preflight requires exactly one pending call",
) -> tuple[EvaluationPreflightResult, _PreflightSubmissionContext | None]:
    """Validate a response once and retain the exact accepted transition for commit."""
    manifest, envelope, _ = _verify_evaluation_run_or_raise(run_dir)
    pending_calls = [call for call in manifest.judge_calls if call.state == "pending"]
    if not pending_calls and manifest.terminal_status is not None:
        return (
            _preflight_result(
                None,
                issue=EvaluationPreflightIssue(
                    code="EVALUATION_NO_PENDING_REQUEST",
                    message=preflight_issue_message("EVALUATION_NO_PENDING_REQUEST"),
                ),
            ),
            None,
        )
    if len(pending_calls) != 1:
        raise EvaluationIntegrityError(pending_error)
    pending = pending_calls[0]
    request = _load_model_bytes(
        _read_artifact(run_dir, pending.request_artifact_path),
        JudgeRequest,
        location=pending.request_artifact_path,
    )
    if response.operation is not request.operation:
        error = ValueError("response operation does not match request operation")
        return (
            _preflight_result(
                request,
                issue=EvaluationPreflightIssue(
                    code="EVALUATION_RESPONSE_REQUEST_MISMATCH",
                    message=preflight_issue_message("EVALUATION_RESPONSE_REQUEST_MISMATCH"),
                ),
            ),
            _PreflightSubmissionContext(
                manifest,
                envelope,
                pending,
                request,
                validation_error=error,
            ),
        )
    if response.request_fingerprint != request.request_fingerprint:
        error = ValueError("response does not bind the exact request")
        return (
            _preflight_result(
                request,
                issue=EvaluationPreflightIssue(
                    code="EVALUATION_RESPONSE_REQUEST_MISMATCH",
                    message=preflight_issue_message("EVALUATION_RESPONSE_REQUEST_MISMATCH"),
                ),
            ),
            _PreflightSubmissionContext(
                manifest,
                envelope,
                pending,
                request,
                validation_error=error,
            ),
        )
    try:
        transition = _accepted_transition(run_dir, manifest, envelope, pending, request, response)
    except EvaluationIntegrityError:
        raise
    except (
        GradeInconclusiveError,
        LedgerInconclusiveError,
        ValidationError,
        ValueError,
        TypeError,
        KeyError,
    ) as error:
        return (
            _preflight_result(request, issue=safe_preflight_issue(error)),
            _PreflightSubmissionContext(
                manifest,
                envelope,
                pending,
                request,
                validation_error=error,
            ),
        )
    return _preflight_result(request), _PreflightSubmissionContext(
        manifest,
        envelope,
        pending,
        request,
        transition=transition,
    )


def preflight_judge_response(
    run_dir: Path,
    response: JudgeResponse,
) -> EvaluationPreflightResult:
    """Validate one pending response with the submit transition without writing run bytes."""
    response, _ = _model_bytes(response, JudgeResponse)
    with _open_run_storage(run_dir) as storage:
        result, _ = _preflight_in_storage(storage, response)
        storage.assert_root_identity()
        return result


def guarded_submit_judge_response(
    run_dir: Path,
    response: JudgeResponse,
) -> GuardedSubmissionResult:
    """Commit a response only when one verified preflight accepts its fixed transition."""
    response, response_bytes = _model_bytes(response, JudgeResponse)
    with _open_run_storage(run_dir) as storage:
        preflight, context = _preflight_in_storage(storage, response)
        if not preflight.ok:
            storage.assert_root_identity()
            return GuardedSubmissionResult(accepted=False, preflight=preflight)
        if context is None:
            raise EvaluationIntegrityError("successful preflight lacks a submission context")
        state = _commit_validated_response(storage, context, response, response_bytes)
        storage.assert_root_identity()
        return GuardedSubmissionResult(accepted=True, preflight=preflight, state=state)


def submit_judge_response(
    run_dir: Path,
    response: JudgeResponse,
) -> EvaluationRunState:
    """Persist one response, validate it, and advance exactly one transition."""
    response, response_bytes = _model_bytes(response, JudgeResponse)
    with _open_run_storage(run_dir) as storage:
        state = _submit_judge_response_in_storage(storage, response, response_bytes)
        storage.assert_root_identity()
        return state


async def run_evaluation(
    case: AttorneyEvaluationCase,
    judge: AttorneyEvaluationJudge,
    output_dir: Path,
    *,
    seed_hex: str,
    generation_capsule_paths: Mapping[str, Path] | None = None,
) -> CompletedEvaluation:
    """Run the bounded judge protocol to a completed, invalid, or inconclusive result."""
    if not isinstance(judge, AttorneyEvaluationJudge):
        raise TypeError("judge must implement AttorneyEvaluationJudge")
    state = initialize_evaluation(
        case,
        output_dir,
        seed_hex=seed_hex,
        generation_capsule_paths=generation_capsule_paths,
    )
    while state.terminal_status is None:
        request = next_judge_request(output_dir)
        if request is None:
            raise EvaluationIntegrityError("nonterminal evaluation has no judge request")
        response = await judge.evaluate(request)
        state = submit_judge_response(output_dir, response)
    with _open_run_storage(output_dir) as storage:
        manifest, _, result = _verify_evaluation_run_or_raise(storage)
        if result is None:
            raise EvaluationIntegrityError("terminal evaluation lacks a result artifact")
        storage.assert_root_identity()
        return CompletedEvaluation(result, manifest, output_dir)
