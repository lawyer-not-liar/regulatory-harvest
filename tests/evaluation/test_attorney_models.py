from __future__ import annotations

import hashlib
import json
from datetime import date

import pytest
from pydantic import ValidationError

from regulatory_harvest.evaluation.attorney_models import (
    EVALUATION_ARTIFACT_SCHEMA_VERSION,
    AbsoluteDisposition,
    ArtifactRecord,
    AttorneyEvaluationCase,
    AttorneyEvaluationResult,
    BlindAssignment,
    CandidateReport,
    CandidateRole,
    CaseEnvelope,
    CaseReadiness,
    CoverageDisposition,
    EntryGrade,
    EvaluationManifest,
    EvaluationMode,
    EvaluationRubric,
    EvaluationRunPhase,
    EvaluationRunState,
    EvaluationSource,
    EvaluationTerminalStatus,
    GradeAlternative,
    GradeDispute,
    JudgeCallRecord,
    JudgeIsolation,
    JudgeOperation,
    LedgerCategory,
    Materiality,
    NarrativeScore,
    OutOfLedgerClaim,
    RefereeDecision,
    ReportEvaluation,
    RequestedAuthority,
    RequirementCitationPin,
    RequirementMatrix,
    RequirementMatrixRow,
    RequirementReportFinding,
    model_fingerprint,
)
from regulatory_harvest.models import SourceQuality, SourceRole
from regulatory_harvest.storage import canonical_json_bytes


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def synthetic_case() -> AttorneyEvaluationCase:
    source_text = "Section 1. A controller shall document its processing activities."
    candidate_text = "The controller must document its processing activities."
    comparator_text = "Documentation is required for processing activities."
    return AttorneyEvaluationCase(
        case_id="synthetic-case",
        mode=EvaluationMode.CLOSED_UNIVERSE,
        question="What documentation is required?",
        jurisdiction="Example State",
        as_of=date(2026, 8, 11),
        requested_authorities=[
            RequestedAuthority(
                authority_id="example-statute",
                title="Example Privacy Act",
                jurisdiction="Example State",
                authority_type="statute",
                source_ids=["example-statute-1"],
            )
        ],
        sources=[
            EvaluationSource(
                source_id="example-statute-1",
                title="Example Privacy Act",
                normalized_text=source_text,
                content_hash=_sha256(source_text),
                jurisdiction="Example State",
                authority_type="statute",
                source_role=SourceRole.OFFICIAL_PRIMARY,
                source_quality=SourceQuality.PRIMARY,
                completeness="complete",
                language="en",
            )
        ],
        candidates=[
            CandidateReport(
                candidate_id="harvest",
                role=CandidateRole.CANDIDATE,
                report_text=candidate_text,
                report_hash=_sha256(candidate_text),
            ),
            CandidateReport(
                candidate_id="comparison",
                role=CandidateRole.COMPARATOR,
                report_text=comparator_text,
                report_hash=_sha256(comparator_text),
            ),
        ],
    )


def synthetic_envelope(*, case_fingerprint: str) -> CaseEnvelope:
    return CaseEnvelope(
        case=synthetic_case(),
        assignments=[
            BlindAssignment(anonymous_label="A", candidate_id="harvest"),
            BlindAssignment(anonymous_label="B", candidate_id="comparison"),
        ],
        case_fingerprint=case_fingerprint,
        seed_fingerprint="1" * 64,
    )


def entry_alternative(
    *, ledger_id: str = "ledger-1", disposition: CoverageDisposition = CoverageDisposition.COMPLETE
) -> GradeAlternative:
    return GradeAlternative(
        request_fingerprint="a" * 64,
        entry_grade=EntryGrade(
            ledger_id=ledger_id,
            disposition=disposition,
            rationale="The report covers the proposition.",
            report_location=(
                None if disposition is CoverageDisposition.MISSING else "p. 1"
            ),
            report_passage=(
                None
                if disposition is CoverageDisposition.MISSING
                else "The report covers the proposition."
            ),
        ),
    )


def claim_alternative(
    *, claim_id: str = "claim-1", materiality: Materiality = Materiality.MATERIAL
) -> GradeAlternative:
    return GradeAlternative(
        request_fingerprint="b" * 64,
        out_of_ledger_claim=OutOfLedgerClaim(
            claim_id=claim_id,
            claim_text="The report states an additional penalty.",
            report_location="p. 2",
            disposition=CoverageDisposition.UNSUPPORTED,
            category=LedgerCategory.PENALTY,
            materiality=materiality,
            source_record_fingerprint="1" * 64,
            evidence_basis="closed_universe_absence",
            evidence_spans=[],
            rationale="The assertion lacks support in the sealed ledger.",
        ),
    )


def narrative_alternative(
    *, dimension: str = "executive_summary", score: int = 3
) -> GradeAlternative:
    return GradeAlternative(
        request_fingerprint="c" * 64,
        narrative_score=NarrativeScore(
            dimension=dimension,  # type: ignore[arg-type]
            score=score,
            rationale="The section is clear but could be more concise.",
            report_passage="The section is clear.",
        ),
    )


def absent_claim_alternative() -> GradeAlternative:
    return GradeAlternative(request_fingerprint="d" * 64, absent_claim=True)


def test_evaluation_13_requires_report_and_out_of_ledger_evidence_bindings() -> None:
    with pytest.raises(ValidationError):
        EntryGrade.model_validate(
            {
                "ledger_id": "ledger-1",
                "disposition": "COMPLETE",
                "rationale": "The report covers the proposition.",
                "report_location": "p. 1",
            }
        )
    with pytest.raises(ValidationError):
        NarrativeScore.model_validate(
            {
                "dimension": "executive_summary",
                "score": 4,
                "rationale": "The report is clear.",
            }
        )
    with pytest.raises(ValidationError):
        OutOfLedgerClaim.model_validate(
            {
                "claim_id": "claim-1",
                "claim_text": "An unsupported penalty applies.",
                "report_location": "p. 2",
                "disposition": "UNSUPPORTED",
                "category": "penalty",
                "materiality": "material",
                "rationale": "The closed universe does not support the claim.",
            }
        )


@pytest.mark.parametrize(
    "disposition",
    [value.value for value in CoverageDisposition if value is not CoverageDisposition.UNSUPPORTED],
)
def test_only_unsupported_out_of_ledger_claim_may_use_absence_basis(
    disposition: str,
) -> None:
    """Every non-UNSUPPORTED enum must fail even if positive-credit checks remain."""
    with pytest.raises(ValidationError, match="valid only for the UNSUPPORTED"):
        OutOfLedgerClaim.model_validate(
            {
                "claim_id": "claim-1",
                "claim_text": "The report states an additional penalty.",
                "report_location": "p. 2",
                "disposition": disposition,
                "category": "penalty",
                "materiality": "material",
                "related_ledger_ids": [],
                "source_record_fingerprint": "1" * 64,
                "evidence_basis": "closed_universe_absence",
                "evidence_spans": [],
                "rationale": "The complete source record lacks support.",
            }
        )


def test_unsupported_out_of_ledger_claim_retains_absence_basis() -> None:
    claim = OutOfLedgerClaim.model_validate(
        {
            "claim_id": "claim-1",
            "claim_text": "The report states an unsupported penalty.",
            "report_location": "p. 2",
            "disposition": "UNSUPPORTED",
            "category": "penalty",
            "materiality": "material",
            "related_ledger_ids": [],
            "source_record_fingerprint": "1" * 64,
            "evidence_basis": "closed_universe_absence",
            "evidence_spans": [],
            "rationale": "The complete source record lacks support.",
        }
    )

    assert claim.disposition is CoverageDisposition.UNSUPPORTED
    assert claim.evidence_basis == "closed_universe_absence"
    assert claim.evidence_spans == []


def report_score_fingerprint(payload: dict[str, object]) -> str:
    score_payload = {key: value for key, value in payload.items() if key != "score_fingerprint"}
    return hashlib.sha256(canonical_json_bytes(score_payload)).hexdigest()


def report_evaluation_payload(**updates: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": EVALUATION_ARTIFACT_SCHEMA_VERSION,
        "anonymous_label": "A",
        "absolute_disposition": AbsoluteDisposition.PASS,
        "critical_recall": 1.0,
        "weighted_recall": 1.0,
        "claim_precision": 1.0,
        "walk_average": 4.0,
        "walk_minimum": 4,
        "normalized_score": 100.0,
        "critical_defect": False,
        "issue_codes": [],
        "blocking_codes": [],
        "ledger_fingerprint": "1" * 64,
        "resolved_grade_fingerprint": "2" * 64,
        "deterministic_checks_fingerprint": "3" * 64,
        "rubric_fingerprint": "4" * 64,
    }
    payload.update(updates)
    payload["score_fingerprint"] = report_score_fingerprint(payload)
    return payload


def report_evaluation(**updates: object) -> ReportEvaluation:
    return ReportEvaluation.model_validate(report_evaluation_payload(**updates))


def requirement_matrix_row(**updates: object) -> RequirementMatrixRow:
    payload: dict[str, object] = {
        "ledger_id": "ledger-1",
        "walk_order": 0,
        "category": LedgerCategory.REQUIREMENT,
        "materiality": Materiality.CRITICAL,
        "proposition": "A covered entity must file notice.",
        "citations": [
            RequirementCitationPin(
                source_id="source-1",
                start_char=0,
                end_char=10,
            )
        ],
        "report_a": RequirementReportFinding(
            anonymous_label="A",
            disposition=CoverageDisposition.COMPLETE,
            report_location="paragraph 1",
            rationale="The report covers the requirement.",
        ),
        "report_b": None,
    }
    payload.update(updates)
    return RequirementMatrixRow.model_validate(payload)


def test_requirement_matrix_enforces_availability_and_anonymous_columns() -> None:
    with pytest.raises(ValidationError, match="unavailable matrix must identify"):
        RequirementMatrix(available=False, rows=[])
    with pytest.raises(ValidationError, match="unavailable matrix must not contain rows"):
        RequirementMatrix(
            available=False,
            unavailable_reason="INCONCLUSIVE",
            rows=[requirement_matrix_row()],
        )
    with pytest.raises(ValidationError, match="report_b must use anonymous label B"):
        requirement_matrix_row(
            report_b=RequirementReportFinding(
                anonymous_label="A",
                disposition=CoverageDisposition.MISSING,
                rationale="The requirement is absent.",
            )
        )


def evaluation_result_payload(
    *,
    reports: list[dict[str, object]],
    rows: list[dict[str, object]],
    readiness_status: str = "ADMITTED",
) -> dict[str, object]:
    rubric = EvaluationRubric(
        version="attorney-eval-v1",
        materiality_weights={
            Materiality.CRITICAL: 3,
            Materiality.MATERIAL: 2,
            Materiality.SUPPORTING: 1,
        },
        critical_recall_floor=1.0,
        weighted_recall_floor=0.8,
        claim_precision_floor=0.9,
        walk_average_floor=3.0,
        walk_dimension_floor=2,
        comparison_weights={"recall": 0.5, "precision": 0.25, "walk": 0.25},
        comparison_margin=1.0,
    )
    payload: dict[str, object] = {
        "schema_version": EVALUATION_ARTIFACT_SCHEMA_VERSION,
        "rubric": rubric.model_dump(mode="json"),
        "readiness": CaseReadiness(
            status=readiness_status,
            case_fingerprint="5" * 64,
            judgment_fingerprint="6" * 64,
            rationale="Synthetic readiness.",
        ).model_dump(mode="json"),
        "reports": reports,
        "requirement_matrix": {
            "available": True,
            "unavailable_reason": None,
            "rows": rows,
        },
        "comparison": None,
        "judge_isolation": "fresh_context",
        "result_fingerprint": "0" * 64,
    }
    result_payload = {key: value for key, value in payload.items() if key != "result_fingerprint"}
    payload["result_fingerprint"] = hashlib.sha256(
        canonical_json_bytes(result_payload)
    ).hexdigest()
    return payload


@pytest.mark.parametrize(
    ("reports", "rows", "readiness_status", "message"),
    [
        (
            [report_evaluation_payload()],
            [
                requirement_matrix_row(
                    report_b=RequirementReportFinding(
                        anonymous_label="B",
                        disposition=CoverageDisposition.COMPLETE,
                        rationale="Comparator covers the requirement.",
                    )
                ).model_dump(mode="json")
            ],
            "ADMITTED",
            "report_b presence",
        ),
        (
            [report_evaluation_payload(), report_evaluation_payload()],
            [requirement_matrix_row().model_dump(mode="json")],
            "ADMITTED",
            "unique fixed order",
        ),
        (
            [report_evaluation_payload(anonymous_label="B")],
            [requirement_matrix_row().model_dump(mode="json")],
            "ADMITTED",
            "unique fixed order",
        ),
        (
            [report_evaluation_payload()],
            [requirement_matrix_row().model_dump(mode="json")],
            "INCONCLUSIVE",
            "admitted readiness",
        ),
    ],
)
def test_scored_result_rejects_incoherent_report_and_matrix_shapes(
    reports: list[dict[str, object]],
    rows: list[dict[str, object]],
    readiness_status: str,
    message: str,
) -> None:
    payload = evaluation_result_payload(
        reports=reports,
        rows=rows,
        readiness_status=readiness_status,
    )

    with pytest.raises(ValidationError, match=message):
        AttorneyEvaluationResult.model_validate(payload)


def test_requirement_matrix_rejects_noncontiguous_walk_order() -> None:
    with pytest.raises(ValidationError, match="contiguous zero-based"):
        RequirementMatrix(
            available=True,
            rows=[requirement_matrix_row(walk_order=1)],
        )


def judge_call_payload(
    *,
    call_id: str = "grade-a-judge-1",
    operation: JudgeOperation = JudgeOperation.GRADE_REPORT,
    anonymous_label: object = "A",
    attempt: object = 1,
    retry_count: object = 0,
    state: str = "completed",
    response_fingerprint: str = "3" * 64,
    **updates: object,
) -> dict[str, object]:
    artifact_prefix = f"calls/{call_id}/attempt-{attempt}"
    payload: dict[str, object] = {
        "call_id": call_id,
        "operation": operation,
        "anonymous_label": anonymous_label,
        "attempt": attempt,
        "prompt_fingerprint": "1" * 64,
        "request_fingerprint": "2" * 64,
        "response_fingerprint": response_fingerprint,
        "provider_name": "provider",
        "model_name": "judge-model",
        "judge_isolation": JudgeIsolation.FRESH_CONTEXT,
        "request_artifact_path": f"{artifact_prefix}/request.json",
        "response_artifact_path": f"{artifact_prefix}/response.json",
        "diagnostics_artifact_path": None,
        "state": state,
        "retry_count": retry_count,
        "terminal_status": "completed",
    }
    if state == "pending":
        payload.update(
            response_fingerprint=None,
            provider_name=None,
            model_name=None,
            judge_isolation=None,
            response_artifact_path=None,
            diagnostics_artifact_path=None,
            terminal_status="pending",
        )
    elif state == "failed":
        payload.update(
            diagnostics_artifact_path=f"{artifact_prefix}/diagnostics.json",
            terminal_status="failed",
        )
    payload.update(updates)
    return payload


def judge_call(**updates: object) -> JudgeCallRecord:
    return JudgeCallRecord.model_validate(judge_call_payload(**updates))


def artifact_payloads_for_calls(
    judge_calls: list[JudgeCallRecord],
) -> list[dict[str, object]]:
    paths = {
        path
        for call in judge_calls
        for path in (
            call.request_artifact_path,
            call.response_artifact_path,
            call.diagnostics_artifact_path,
        )
        if path is not None
    }
    return [
        {"artifact_path": path, "artifact_hash": _sha256(f"artifact:{path}")}
        for path in sorted(paths)
    ]


def artifact_inventory_fingerprint(artifacts: list[dict[str, object]]) -> str:
    return hashlib.sha256(canonical_json_bytes(artifacts)).hexdigest()


def manifest_self_fingerprint(payload: dict[str, object]) -> str:
    manifest_payload = {
        key: value for key, value in payload.items() if key != "manifest_fingerprint"
    }
    return hashlib.sha256(canonical_json_bytes(manifest_payload)).hexdigest()


def manifest_payload(
    *,
    judge_calls: list[JudgeCallRecord] | None = None,
    artifacts: list[dict[str, object]] | None = None,
    state: EvaluationRunPhase = EvaluationRunPhase.CREATED,
    terminal_status: EvaluationTerminalStatus | None = None,
    legal_ledger_hash: str | None = None,
    result_hash: str | None = None,
    **updates: object,
) -> dict[str, object]:
    calls = judge_calls or []
    artifact_payloads = artifacts if artifacts is not None else artifact_payloads_for_calls(calls)
    payload: dict[str, object] = {
        "schema_version": EVALUATION_ARTIFACT_SCHEMA_VERSION,
        "case_fingerprint": "4" * 64,
        "case_envelope_hash": "5" * 64,
        "rubric_fingerprint": "6" * 64,
        "legal_ledger_hash": legal_ledger_hash,
        "result_hash": result_hash,
        "judge_calls": [call.model_dump(mode="json") for call in calls],
        "artifacts": artifact_payloads,
        "artifact_inventory_fingerprint": artifact_inventory_fingerprint(artifact_payloads),
        "state": state,
        "retry_count": 0,
        "terminal_status": terminal_status,
    }
    payload.update(updates)
    payload["manifest_fingerprint"] = manifest_self_fingerprint(payload)
    return payload


def evaluation_manifest(**updates: object) -> EvaluationManifest:
    return EvaluationManifest.model_validate(manifest_payload(**updates))


def run_state_payload(**updates: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": EVALUATION_ARTIFACT_SCHEMA_VERSION,
        "case_fingerprint": "4" * 64,
        "case_envelope_hash": "5" * 64,
        "judge_calls": [],
        "current_operation": None,
        "current_call_id": None,
        "attempt": 0,
        "state": EvaluationRunPhase.CREATED,
        "retry_count": 0,
        "terminal_status": None,
        "manifest_fingerprint": None,
    }
    payload.update(updates)
    return payload


_WINDOWS_RESERVED_COMPONENTS = [
    "CON",
    "prn",
    "Aux",
    "nul",
    "COM1",
    "com2",
    "COM3",
    "com4",
    "COM5",
    "com6",
    "COM7",
    "com8",
    "COM9",
    "LPT1",
    "lpt2",
    "LPT3",
    "lpt4",
    "LPT5",
    "lpt6",
    "LPT7",
    "lpt8",
    "LPT9",
]
_WINDOWS_SUPERSCRIPT_RESERVED_COMPONENTS = [
    ("COM¹", "com-1-upper"),
    ("com¹", "com-1-lower"),
    ("COM²", "com-2-upper"),
    ("com²", "com-2-lower"),
    ("COM³", "com-3-upper"),
    ("com³", "com-3-lower"),
    ("LPT¹", "lpt-1-upper"),
    ("lpt¹", "lpt-1-lower"),
    ("LPT²", "lpt-2-upper"),
    ("lpt²", "lpt-2-lower"),
    ("LPT³", "lpt-3-upper"),
    ("lpt³", "lpt-3-lower"),
]
_UNSAFE_PORTABLE_ARTIFACT_PATH_CASES = [
    pytest.param("", id="empty"),
    pytest.param("/absolute/artifact.json", id="posix-absolute"),
    pytest.param("C:/absolute/artifact.json", id="windows-drive-absolute"),
    pytest.param("C:drive-relative-artifact.json", id="windows-drive-relative"),
    pytest.param("artifacts//record.json", id="empty-component"),
    pytest.param("artifacts/./record.json", id="dot-component"),
    pytest.param("artifacts/../record.json", id="dotdot-component"),
    pytest.param("artifacts\\record.json", id="backslash"),
    pytest.param("artifacts/file<name.json", id="less-than"),
    pytest.param("artifacts/file>name.json", id="greater-than"),
    pytest.param('artifacts/file"name.json', id="double-quote"),
    pytest.param("artifacts/file:name.json", id="colon"),
    pytest.param("artifacts/file|name.json", id="pipe"),
    pytest.param("artifacts/file?name.json", id="question-mark"),
    pytest.param("artifacts/file*name.json", id="asterisk"),
    pytest.param("artifacts./record.json", id="directory-trailing-dot"),
    pytest.param("artifacts /record.json", id="directory-trailing-space"),
    pytest.param("artifacts/record.json.", id="filename-trailing-dot"),
    pytest.param("artifacts/record.json ", id="filename-trailing-space"),
    *[
        pytest.param(
            f"artifacts/control-{chr(codepoint)}.json",
            id=f"ascii-control-{codepoint:02x}",
        )
        for codepoint in [*range(0x20), 0x7F]
    ],
    *[
        pytest.param(
            f"artifacts/{component}.json",
            id=f"reserved-extension-{component.lower()}",
        )
        for component in _WINDOWS_RESERVED_COMPONENTS
    ],
    *[
        pytest.param(
            f"artifacts/{component}/record.json",
            id=f"reserved-directory-{component.lower()}",
        )
        for component in _WINDOWS_RESERVED_COMPONENTS
    ],
    *[
        pytest.param(
            f"artifacts/{component}.json",
            id=f"superscript-reserved-extension-{case_id}",
        )
        for component, case_id in _WINDOWS_SUPERSCRIPT_RESERVED_COMPONENTS
    ],
    *[
        pytest.param(
            f"artifacts/{component}/record.json",
            id=f"superscript-reserved-directory-{case_id}",
        )
        for component, case_id in _WINDOWS_SUPERSCRIPT_RESERVED_COMPONENTS
    ],
]
_JUDGE_CALL_PROVENANCE_STRING_FIELDS = [
    ("call_id", "7", "completed"),
    ("prompt_fingerprint", "7" * 64, "completed"),
    ("request_fingerprint", "7" * 64, "completed"),
    ("response_fingerprint", "7" * 64, "completed"),
    ("provider_name", "7", "completed"),
    ("model_name", "7", "completed"),
    ("request_artifact_path", "7", "completed"),
    ("response_artifact_path", "7", "completed"),
    ("diagnostics_artifact_path", "7", "failed"),
]
_MANIFEST_PROVENANCE_STRING_FIELDS = [
    "case_fingerprint",
    "case_envelope_hash",
    "rubric_fingerprint",
    "legal_ledger_hash",
    "result_hash",
    "artifact_inventory_fingerprint",
    "manifest_fingerprint",
]
_RUN_STATE_PROVENANCE_STRING_FIELDS = [
    "case_fingerprint",
    "case_envelope_hash",
    "current_call_id",
    "manifest_fingerprint",
]


def non_string_scalar(value: str, raw_kind: str) -> object:
    if raw_kind == "bytes":
        return value.encode("utf-8")
    if raw_kind == "int":
        return int(value) if value.isdecimal() else 7
    if raw_kind == "bool":
        return True
    raise AssertionError(f"unknown raw scalar kind: {raw_kind}")


def assert_string_type_error(
    error: ValidationError,
    location: tuple[str | int, ...],
) -> None:
    assert any(
        detail["loc"] == location and detail["type"] == "string_type" for detail in error.errors()
    )


def test_case_envelope_rejects_unknown_fields_and_has_stable_fingerprint() -> None:
    """Unknown envelope fields and nondeterministic serialization break the contract."""
    case = synthetic_case()

    assert model_fingerprint(case) == model_fingerprint(case)

    envelope = synthetic_envelope(case_fingerprint=model_fingerprint(case))
    with pytest.raises(ValidationError, match="extra_forbidden"):
        CaseEnvelope.model_validate({**envelope.model_dump(mode="json"), "surprise": True})


def test_case_envelope_rejects_a_fingerprint_for_a_different_case() -> None:
    """A valid digest must not be accepted when it describes different case data."""
    with pytest.raises(ValidationError, match="case_fingerprint must match case"):
        synthetic_envelope(case_fingerprint="0" * 64)


def test_comparator_is_never_marked_as_ground_truth() -> None:
    """A comparator cannot replace the candidate role or become an answer key."""
    case = synthetic_case()

    assert {candidate.role for candidate in case.candidates} == {
        CandidateRole.CANDIDATE,
        CandidateRole.COMPARATOR,
    }
    assert not hasattr(case, "answer_report_id")


def test_case_rejects_duplicate_source_ids_and_report_text_hash_mismatches() -> None:
    """Duplicate evidence identities and detached report hashes corrupt blind review."""
    payload = synthetic_case().model_dump(mode="json")
    payload["sources"].append(payload["sources"][0])
    with pytest.raises(ValidationError, match="source_id values must be unique"):
        AttorneyEvaluationCase.model_validate(payload)

    candidate = payload["candidates"][0]
    candidate["report_hash"] = "0" * 64
    payload["sources"] = payload["sources"][:1]
    with pytest.raises(ValidationError, match="report_hash must match report_text"):
        AttorneyEvaluationCase.model_validate(payload)


def test_source_rejects_a_hash_for_different_normalized_text() -> None:
    """A source digest must bind the exact retained text, not merely be well formed."""
    payload = synthetic_case().sources[0].model_dump(mode="json")
    payload["normalized_text"] = f"{payload['normalized_text']} Additional text."

    with pytest.raises(ValidationError, match="content_hash must match normalized_text"):
        EvaluationSource.model_validate(payload)


@pytest.mark.parametrize(
    "exact_text",
    [
        "  Exact retained text  ",
        "Exact retained text\n",
        "Exact retained text\r\n",
        "\ufeffExact retained text",
    ],
)
def test_content_models_preserve_exact_nonblank_utf8_text(exact_text: str) -> None:
    """Trimming a source, report, or fact string would detach its exact byte hash."""
    source_payload = synthetic_case().sources[0].model_dump(mode="json")
    source_payload.update(
        normalized_text=exact_text,
        content_hash=_sha256(exact_text),
    )
    candidate_payload = synthetic_case().candidates[0].model_dump(mode="json")
    candidate_payload.update(
        report_text=exact_text,
        report_hash=_sha256(exact_text),
    )
    case_payload = synthetic_case().model_dump(mode="json")
    case_payload["sources"] = [source_payload]
    case_payload["requested_authorities"][0]["source_ids"] = [source_payload["source_id"]]
    case_payload["candidates"] = [candidate_payload]
    case_payload["client_facts"] = exact_text

    source = EvaluationSource.model_validate(source_payload)
    candidate = CandidateReport.model_validate(candidate_payload)
    case = AttorneyEvaluationCase.model_validate(case_payload)

    assert source.normalized_text == exact_text
    assert candidate.report_text == exact_text
    assert case.client_facts == exact_text


@pytest.mark.parametrize("blank_text", ["", " \t\r\n", "\ufeff", "\ufeff \r\n"])
def test_content_models_reject_semantically_blank_exact_text(blank_text: str) -> None:
    """Preserving bytes must not turn whitespace or a bare BOM into usable content."""
    source_payload = synthetic_case().sources[0].model_dump(mode="json")
    source_payload.update(normalized_text=blank_text, content_hash=_sha256(blank_text))
    candidate_payload = synthetic_case().candidates[0].model_dump(mode="json")
    candidate_payload.update(report_text=blank_text, report_hash=_sha256(blank_text))
    case_payload = synthetic_case().model_dump(mode="json")
    case_payload["client_facts"] = blank_text

    with pytest.raises(ValidationError, match="must not be blank"):
        EvaluationSource.model_validate(source_payload)
    with pytest.raises(ValidationError, match="must not be blank"):
        CandidateReport.model_validate(candidate_payload)
    with pytest.raises(ValidationError, match="must not be blank"):
        AttorneyEvaluationCase.model_validate(case_payload)


def test_case_fingerprint_distinguishes_exact_line_endings_and_final_newline() -> None:
    """Byte-distinct legal inputs must never collapse to one frozen case identity."""
    fingerprints: set[str] = set()
    for exact_text in ("Rule", "Rule\n", "Rule\r\n"):
        payload = synthetic_case().model_dump(mode="json")
        payload["sources"][0].update(
            normalized_text=exact_text,
            content_hash=_sha256(exact_text),
        )
        case = AttorneyEvaluationCase.model_validate(payload)
        fingerprints.add(model_fingerprint(case))

    assert len(fingerprints) == 3


def test_model_fingerprint_is_canonical_and_excludes_named_self_hashes() -> None:
    """Equivalent mapping order must not change the digest or defeat self-hash removal."""
    report_text = "A synthetic report."
    first = CandidateReport(
        candidate_id="candidate-a",
        role=CandidateRole.CANDIDATE,
        report_text=report_text,
        report_hash=_sha256(report_text),
        bundle_json={"z": 1, "a": 2},
    )
    reordered = CandidateReport(
        candidate_id="candidate-a",
        role=CandidateRole.CANDIDATE,
        report_text=report_text,
        report_hash=_sha256(report_text),
        bundle_json={"a": 2, "z": 1},
    )
    expected_payload = first.model_dump(mode="json")
    expected_payload.pop("report_hash")

    assert model_fingerprint(first) == model_fingerprint(reordered)
    assert (
        model_fingerprint(first, exclude={"report_hash"})
        == hashlib.sha256(canonical_json_bytes(expected_payload)).hexdigest()
    )


def test_case_requires_one_candidate_and_at_most_one_comparator() -> None:
    """Two submissions of either role would make blind assignment ambiguous."""
    payload = synthetic_case().model_dump(mode="json")
    payload["candidates"][1]["role"] = CandidateRole.CANDIDATE

    with pytest.raises(ValidationError, match="exactly one candidate"):
        AttorneyEvaluationCase.model_validate(payload)


def test_run_state_uses_the_approved_evaluation_phase_vocabulary() -> None:
    """Generic running states cannot represent the deterministic Task 5 workflow."""
    assert [phase.value for phase in EvaluationRunPhase] == [
        "created",
        "admission",
        "ledger-build",
        "ledger-audit",
        "ledger-repair",
        "ledger-referee",
        "ledger-sealed",
        "grade-a",
        "grade-b",
        "report-referee",
        "aggregate",
        "completed",
        "inconclusive",
        "case-invalid",
    ]
    state = EvaluationRunState.model_validate(
        run_state_payload(
            attempt=2,
            state=EvaluationRunPhase.LEDGER_REFEREE,
            retry_count=1,
        )
    )

    assert state.model_dump(mode="json")["state"] == "ledger-referee"
    with pytest.raises(ValidationError):
        EvaluationRunState.model_validate(
            run_state_payload(
                state="running",
            )
        )
    assert EvaluationTerminalStatus.CASE_INVALID.value == "case-invalid"


def test_judge_call_records_bind_each_conditional_provenance_state() -> None:
    """Pending, completed, and failed calls retain exactly their permitted evidence."""
    pending = judge_call(state="pending")
    completed = judge_call()
    failed = judge_call(state="failed")
    inconclusive = judge_call(state="failed", terminal_status="inconclusive")

    assert pending.response_fingerprint is None
    assert pending.provider_name is None
    assert pending.response_artifact_path is None
    assert completed.response_fingerprint == "3" * 64
    assert completed.diagnostics_artifact_path is None
    assert failed.diagnostics_artifact_path is not None
    assert inconclusive.terminal_status == "inconclusive"


@pytest.mark.parametrize(
    ("state", "updates"),
    [
        ("pending", {"response_fingerprint": "3" * 64}),
        ("pending", {"provider_name": "provider"}),
        ("pending", {"model_name": "judge-model"}),
        ("pending", {"judge_isolation": JudgeIsolation.FRESH_CONTEXT}),
        ("pending", {"response_artifact_path": "calls/response.json"}),
        ("pending", {"diagnostics_artifact_path": "calls/diagnostics.json"}),
        ("pending", {"terminal_status": "completed"}),
        ("completed", {"response_fingerprint": None}),
        ("completed", {"provider_name": None}),
        ("completed", {"model_name": None}),
        ("completed", {"judge_isolation": None}),
        ("completed", {"response_artifact_path": None}),
        ("completed", {"diagnostics_artifact_path": "calls/diagnostics.json"}),
        ("completed", {"terminal_status": "failed"}),
        ("failed", {"response_fingerprint": None}),
        ("failed", {"provider_name": None}),
        ("failed", {"model_name": None}),
        ("failed", {"judge_isolation": None}),
        ("failed", {"response_artifact_path": None}),
        ("failed", {"diagnostics_artifact_path": None}),
        ("failed", {"terminal_status": "completed"}),
        ("failed", {"terminal_status": "case_invalid"}),
    ],
)
def test_judge_call_records_reject_incomplete_or_cross_state_evidence(
    state: str,
    updates: dict[str, object],
) -> None:
    """No call state may borrow or omit evidence required by another state."""
    payload = judge_call_payload(state=state)
    payload.update(updates)

    with pytest.raises(ValidationError):
        JudgeCallRecord.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "raw_value"),
    [
        ("attempt", 1.0),
        ("attempt", "1"),
        ("attempt", "1.0"),
        ("attempt", True),
        ("retry_count", 0.0),
        ("retry_count", "0"),
        ("retry_count", False),
    ],
)
def test_judge_call_records_reject_coercible_integer_representations(
    field: str,
    raw_value: object,
) -> None:
    """Attempt evidence must arrive as actual integers rather than coerced values."""
    payload = judge_call_payload()
    payload[field] = raw_value

    with pytest.raises(ValidationError):
        JudgeCallRecord.model_validate(payload)


def test_judge_call_records_enforce_blind_label_boundaries() -> None:
    """Only grade and referee calls may carry anonymous A/B report context."""
    blind_referee = judge_call(
        call_id="report-referee-1",
        operation=JudgeOperation.REFEREE,
        anonymous_label="B",
    )
    ledger_referee = judge_call(
        call_id="ledger-referee-1",
        operation=JudgeOperation.REFEREE,
        anonymous_label=None,
    )

    assert blind_referee.anonymous_label == "B"
    assert ledger_referee.anonymous_label is None
    with pytest.raises(ValidationError):
        JudgeCallRecord.model_validate(judge_call_payload(anonymous_label=None))
    with pytest.raises(ValidationError):
        JudgeCallRecord.model_validate(judge_call_payload(anonymous_label="harvest"))
    with pytest.raises(ValidationError):
        JudgeCallRecord.model_validate(
            judge_call_payload(
                call_id="ledger-build-1",
                operation=JudgeOperation.BUILD_LEDGER,
                anonymous_label="A",
            )
        )


@pytest.mark.parametrize("field", ["provider_name", "model_name"])
@pytest.mark.parametrize("invalid_value", ["", "   "])
def test_completed_judge_calls_reject_blank_provider_provenance(
    field: str,
    invalid_value: str,
) -> None:
    """Completed provenance must name both the provider and the model."""
    with pytest.raises(ValidationError):
        JudgeCallRecord.model_validate(judge_call_payload(**{field: invalid_value}))


@pytest.mark.parametrize(
    ("state", "field"),
    [
        ("completed", "request_artifact_path"),
        ("completed", "response_artifact_path"),
        ("failed", "diagnostics_artifact_path"),
    ],
)
@pytest.mark.parametrize(
    "invalid_path",
    _UNSAFE_PORTABLE_ARTIFACT_PATH_CASES,
)
def test_judge_call_records_reject_unsafe_artifact_paths(
    state: str,
    field: str,
    invalid_path: str,
) -> None:
    """Every call artifact link must be a normalized, safe relative path."""
    with pytest.raises(ValidationError):
        JudgeCallRecord.model_validate(judge_call_payload(state=state, **{field: invalid_path}))


@pytest.mark.parametrize(
    "invalid_path",
    _UNSAFE_PORTABLE_ARTIFACT_PATH_CASES,
)
def test_artifact_records_reject_unsafe_paths(invalid_path: str) -> None:
    """Artifact inventory entries cannot escape or ambiguously address the run root."""
    with pytest.raises(ValidationError):
        ArtifactRecord(artifact_path=invalid_path, artifact_hash="a" * 64)


def test_portable_artifact_paths_preserve_unicode_and_forward_slash_subdirectories() -> None:
    """Portable validation retains reasonable Unicode names and nested POSIX separators."""
    artifact_path = "證拠/évaluation-Δ.json"
    artifact = ArtifactRecord(artifact_path=artifact_path, artifact_hash="a" * 64)
    call = judge_call(
        state="failed",
        request_artifact_path="呼び出し/要求.json",
        response_artifact_path="呼び出し/応答.json",
        diagnostics_artifact_path="呼び出し/診断.json",
    )

    assert artifact.artifact_path == artifact_path
    assert call.request_artifact_path == "呼び出し/要求.json"
    assert call.response_artifact_path == "呼び出し/応答.json"
    assert call.diagnostics_artifact_path == "呼び出し/診断.json"


@pytest.mark.parametrize(
    ("field", "valid_value", "state"),
    _JUDGE_CALL_PROVENANCE_STRING_FIELDS,
)
@pytest.mark.parametrize("raw_kind", ["bytes", "int", "bool"])
def test_judge_call_provenance_requires_raw_python_strings(
    field: str,
    valid_value: str,
    state: str,
    raw_kind: str,
) -> None:
    """Provider-bound provenance must reject coercible non-string Python scalars."""
    payload = judge_call_payload(state=state, **{field: valid_value})
    assert getattr(JudgeCallRecord.model_validate(payload), field) == valid_value
    payload[field] = non_string_scalar(valid_value, raw_kind)

    with pytest.raises(ValidationError) as exc_info:
        JudgeCallRecord.model_validate(payload)

    assert_string_type_error(exc_info.value, (field,))


@pytest.mark.parametrize(
    ("field", "valid_value"),
    [("artifact_path", "7"), ("artifact_hash", "7" * 64)],
)
@pytest.mark.parametrize("raw_kind", ["bytes", "int", "bool"])
def test_artifact_provenance_requires_raw_python_strings(
    field: str,
    valid_value: str,
    raw_kind: str,
) -> None:
    """Artifact identity and digest fields must not decode or stringify raw scalars."""
    payload: dict[str, object] = {
        "artifact_path": "7",
        "artifact_hash": "7" * 64,
    }
    assert getattr(ArtifactRecord.model_validate(payload), field) == valid_value
    payload[field] = non_string_scalar(valid_value, raw_kind)

    with pytest.raises(ValidationError) as exc_info:
        ArtifactRecord.model_validate(payload)

    assert_string_type_error(exc_info.value, (field,))


@pytest.mark.parametrize("field", _MANIFEST_PROVENANCE_STRING_FIELDS)
@pytest.mark.parametrize("raw_kind", ["bytes", "int", "bool"])
def test_manifest_provenance_hashes_require_raw_python_strings(
    field: str,
    raw_kind: str,
) -> None:
    """Every persisted manifest digest must retain its exact Python scalar type."""
    payload = manifest_payload(
        state=EvaluationRunPhase.COMPLETED,
        terminal_status=EvaluationTerminalStatus.COMPLETED,
        legal_ledger_hash="7" * 64,
        result_hash="8" * 64,
    )
    original = payload[field]
    assert isinstance(original, str)
    assert getattr(EvaluationManifest.model_validate(payload), field) == original
    payload[field] = non_string_scalar(original, raw_kind)

    with pytest.raises(ValidationError) as exc_info:
        EvaluationManifest.model_validate(payload)

    assert_string_type_error(exc_info.value, (field,))


@pytest.mark.parametrize(
    ("field", "valid_value", "state"),
    _JUDGE_CALL_PROVENANCE_STRING_FIELDS,
)
def test_manifest_rejects_raw_bytes_in_nested_judge_call_provenance(
    field: str,
    valid_value: str,
    state: str,
) -> None:
    """Nested raw call dictionaries cannot decode bytes behind valid enclosing hashes."""
    call = judge_call(state=state, **{field: valid_value})
    payload = manifest_payload(
        judge_calls=[call],
        state=EvaluationRunPhase.GRADE_A,
        legal_ledger_hash="7" * 64,
    )
    raw_calls = payload["judge_calls"]
    assert isinstance(raw_calls, list)
    raw_call = raw_calls[0]
    assert isinstance(raw_call, dict)
    raw_call[field] = valid_value.encode("utf-8")
    # The existing hashes describe the same post-decode snapshot accepted by lax fields.

    with pytest.raises(ValidationError) as exc_info:
        EvaluationManifest.model_validate(payload)

    assert_string_type_error(exc_info.value, ("judge_calls", 0, field))


@pytest.mark.parametrize(
    ("field", "valid_value"),
    [("artifact_path", "7"), ("artifact_hash", "7" * 64)],
)
def test_manifest_rejects_raw_bytes_in_nested_artifact_provenance(
    field: str,
    valid_value: str,
) -> None:
    """Nested inventory bytes cannot hide behind matching inventory and manifest hashes."""
    artifacts: list[dict[str, object]] = [{"artifact_path": "7", "artifact_hash": "7" * 64}]
    payload = manifest_payload(artifacts=artifacts)
    raw_artifacts = payload["artifacts"]
    assert isinstance(raw_artifacts, list)
    raw_artifact = raw_artifacts[0]
    assert isinstance(raw_artifact, dict)
    raw_artifact[field] = valid_value.encode("utf-8")
    # Both existing hashes match the normalized strings the old lax fields produced.

    with pytest.raises(ValidationError) as exc_info:
        EvaluationManifest.model_validate(payload)

    assert_string_type_error(exc_info.value, ("artifacts", 0, field))


def test_manifest_accepts_independent_grades_with_equal_request_fingerprints() -> None:
    """Byte-identical blind packets remain valid when independent responses are distinct."""
    first = judge_call(call_id="grade-a-judge-1", response_fingerprint="a" * 64)
    second = judge_call(call_id="grade-a-judge-2", response_fingerprint="b" * 64)
    manifest = evaluation_manifest(
        judge_calls=[first, second],
        state=EvaluationRunPhase.GRADE_A,
        legal_ledger_hash="7" * 64,
    )

    assert first.request_fingerprint == second.request_fingerprint
    assert first.response_fingerprint != second.response_fingerprint
    assert manifest.artifact_inventory_fingerprint == artifact_inventory_fingerprint(
        [artifact.model_dump(mode="json") for artifact in manifest.artifacts]
    )
    assert manifest.manifest_fingerprint == manifest_self_fingerprint(
        manifest.model_dump(mode="json")
    )
    assert (
        EvaluationManifest.model_validate(
            json.loads(canonical_json_bytes(manifest).decode("utf-8"))
        )
        == manifest
    )


@pytest.mark.parametrize("duplicate_field", ["response_fingerprint", "call_id"])
def test_manifest_rejects_reused_completed_grade_evidence(
    duplicate_field: str,
) -> None:
    """Two completed grades for one label need distinct logical calls and responses."""
    first = judge_call(call_id="grade-a-judge-1", response_fingerprint="a" * 64)
    second_payload = judge_call_payload(
        call_id="grade-a-judge-2",
        attempt=2 if duplicate_field == "call_id" else 1,
        response_fingerprint="b" * 64,
    )
    second_payload[duplicate_field] = getattr(first, duplicate_field)
    second = JudgeCallRecord.model_validate(second_payload)
    payload = manifest_payload(
        judge_calls=[first, second],
        state=EvaluationRunPhase.GRADE_A,
        legal_ledger_hash="7" * 64,
    )

    with pytest.raises(ValidationError):
        EvaluationManifest.model_validate(payload)


def test_manifest_allows_retry_attempts_to_share_one_logical_call_id() -> None:
    """A failed attempt and its pending repair retain one stable logical identity."""
    failed = judge_call(
        call_id="grade-a-judge-1",
        state="failed",
        attempt=1,
        retry_count=0,
    )
    repair = judge_call(
        call_id="grade-a-judge-1",
        state="pending",
        attempt=2,
        retry_count=1,
    )

    manifest = evaluation_manifest(
        judge_calls=[failed, repair],
        state=EvaluationRunPhase.GRADE_A,
        legal_ledger_hash="7" * 64,
        retry_count=1,
    )

    assert [(call.call_id, call.attempt) for call in manifest.judge_calls] == [
        ("grade-a-judge-1", 1),
        ("grade-a-judge-1", 2),
    ]


def test_manifest_rejects_duplicate_attempt_identity_or_changed_logical_context() -> None:
    """One logical call cannot reuse an attempt or change operation between attempts."""
    first = judge_call(
        call_id="referee-1",
        operation=JudgeOperation.REFEREE,
        anonymous_label=None,
    )
    duplicate_attempt = judge_call(
        call_id="referee-1",
        operation=JudgeOperation.REFEREE,
        anonymous_label=None,
        request_artifact_path="calls/referee-1/duplicate/request.json",
        response_artifact_path="calls/referee-1/duplicate/response.json",
        response_fingerprint="a" * 64,
    )
    changed_operation = judge_call(
        call_id="referee-1",
        operation=JudgeOperation.GRADE_REPORT,
        anonymous_label="A",
        attempt=2,
        response_fingerprint="b" * 64,
    )

    for second in (duplicate_attempt, changed_operation):
        payload = manifest_payload(judge_calls=[first, second])
        with pytest.raises(ValidationError):
            EvaluationManifest.model_validate(payload)


@pytest.mark.parametrize(
    "path_field",
    [
        "request_artifact_path",
        "response_artifact_path",
        "diagnostics_artifact_path",
    ],
)
def test_manifest_rejects_missing_judge_call_artifact_links(path_field: str) -> None:
    """Every request, response, and diagnostic path must resolve exactly once."""
    failed = judge_call(state="failed")
    artifacts = artifact_payloads_for_calls([failed])
    missing_path = getattr(failed, path_field)
    artifacts = [record for record in artifacts if record["artifact_path"] != missing_path]
    payload = manifest_payload(judge_calls=[failed], artifacts=artifacts)

    with pytest.raises(ValidationError):
        EvaluationManifest.model_validate(payload)


@pytest.mark.parametrize("defect", ["unsorted", "duplicate", "self-record"])
def test_manifest_rejects_noncanonical_artifact_inventory(defect: str) -> None:
    """The exact inventory must be sorted, unique, and exclude the manifest itself."""
    call = judge_call()
    artifacts = artifact_payloads_for_calls([call])
    if defect == "unsorted":
        artifacts.reverse()
    elif defect == "duplicate":
        artifacts.append(dict(artifacts[0]))
        artifacts.sort(key=lambda artifact: str(artifact["artifact_path"]))
    else:
        artifacts.append({"artifact_path": "run-manifest.json", "artifact_hash": "f" * 64})
        artifacts.sort(key=lambda artifact: str(artifact["artifact_path"]))
    payload = manifest_payload(judge_calls=[call], artifacts=artifacts)

    with pytest.raises(ValidationError):
        EvaluationManifest.model_validate(payload)


def test_manifest_rejects_stale_inventory_and_self_fingerprints() -> None:
    """Inventory bytes and the complete manifest snapshot each have an exact binding."""
    manifest = evaluation_manifest()
    stale_inventory = manifest.model_dump(mode="json")
    stale_inventory["artifacts"] = [{"artifact_path": "rubric.json", "artifact_hash": "f" * 64}]
    stale_inventory["manifest_fingerprint"] = manifest_self_fingerprint(stale_inventory)
    with pytest.raises(ValidationError):
        EvaluationManifest.model_validate(stale_inventory)

    stale_manifest = manifest.model_dump(mode="json")
    stale_manifest["retry_count"] = 1
    with pytest.raises(ValidationError, match="manifest_fingerprint"):
        EvaluationManifest.model_validate(stale_manifest)


@pytest.mark.parametrize(
    ("scope", "field", "raw_value"),
    [
        ("call", "attempt", 1.0),
        ("call", "attempt", "1"),
        ("call", "attempt", True),
        ("call", "retry_count", 0.0),
        ("call", "retry_count", False),
        ("manifest", "retry_count", 0.0),
        ("manifest", "retry_count", "0"),
        ("manifest", "retry_count", False),
    ],
)
def test_manifest_rejects_raw_integer_coercion_with_recomputed_self_hash(
    scope: str,
    field: str,
    raw_value: object,
) -> None:
    """A newly calculated manifest hash cannot legitimize coerced integer evidence."""
    call = judge_call()
    payload = manifest_payload(
        judge_calls=[call],
        state=EvaluationRunPhase.GRADE_A,
        legal_ledger_hash="7" * 64,
    )
    if scope == "call":
        payload["judge_calls"][0][field] = raw_value  # type: ignore[index]
    else:
        payload[field] = raw_value
    payload["manifest_fingerprint"] = manifest_self_fingerprint(payload)

    with pytest.raises(ValidationError):
        EvaluationManifest.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "mutated_value"),
    [("attempt", True), ("provider_name", "")],
)
def test_manifest_revalidates_mutated_judge_call_instances(
    field: str,
    mutated_value: object,
) -> None:
    """Embedding a previously validated call cannot bypass its strict field contract."""
    call = judge_call()
    payload = manifest_payload(
        judge_calls=[call],
        state=EvaluationRunPhase.GRADE_A,
        legal_ledger_hash="7" * 64,
    )
    setattr(call, field, mutated_value)
    payload["judge_calls"] = [call]
    payload["manifest_fingerprint"] = manifest_self_fingerprint(payload)

    with pytest.raises(ValidationError):
        EvaluationManifest.model_validate(payload)


def test_manifest_revalidates_mutated_artifact_record_instances() -> None:
    """An inventory self-hash cannot legitimize a mutated malformed artifact record."""
    artifact = ArtifactRecord(
        artifact_path="rubric.json",
        artifact_hash="a" * 64,
    )
    artifact.artifact_hash = "not-a-hash"
    payload = manifest_payload()
    payload["artifacts"] = [artifact]
    payload["artifact_inventory_fingerprint"] = hashlib.sha256(
        canonical_json_bytes([artifact])
    ).hexdigest()
    payload["manifest_fingerprint"] = manifest_self_fingerprint(payload)

    with pytest.raises(ValidationError):
        EvaluationManifest.model_validate(payload)


@pytest.mark.parametrize("container", ["manifest", "run-state"])
@pytest.mark.parametrize("unsafe_source", ["model-construct", "mutation"])
def test_task5_must_revalidate_json_compatible_payload_before_persistence(
    container: str,
    unsafe_source: str,
) -> None:
    """Ordinary validation, not unchecked construction, is the persistence boundary."""
    valid_call = judge_call()
    if unsafe_source == "model-construct":
        unsafe_payload = valid_call.model_dump(mode="python")
        unsafe_payload["attempt"] = True
        unsafe_call = JudgeCallRecord.model_construct(**unsafe_payload)
    else:
        unsafe_call = valid_call.model_copy()
        unsafe_call.attempt = True
    raw_call = unsafe_call.model_dump(mode="python", warnings=False)
    assert raw_call["attempt"] is True

    if container == "manifest":
        payload = manifest_payload(
            judge_calls=[valid_call],
            state=EvaluationRunPhase.GRADE_A,
            legal_ledger_hash="7" * 64,
        )
        payload["judge_calls"] = [raw_call]
        payload["manifest_fingerprint"] = manifest_self_fingerprint(payload)
        validator = EvaluationManifest.model_validate
    else:
        payload = run_state_payload(
            judge_calls=[raw_call],
            state=EvaluationRunPhase.LEDGER_REFEREE,
            attempt=1,
        )
        validator = EvaluationRunState.model_validate

    # Task 5 must perform this ordinary validation before hashing or writing state.
    with pytest.raises(ValidationError) as exc_info:
        validator(payload)

    assert any(
        detail["loc"] == ("judge_calls", 0, "attempt") and detail["type"] == "int_type"
        for detail in exc_info.value.errors()
    )


@pytest.mark.parametrize(
    ("state", "terminal_status", "legal_ledger_hash", "result_hash"),
    [
        (EvaluationRunPhase.CREATED, None, None, None),
        (EvaluationRunPhase.LEDGER_SEALED, None, "7" * 64, None),
        (
            EvaluationRunPhase.COMPLETED,
            EvaluationTerminalStatus.COMPLETED,
            "7" * 64,
            "8" * 64,
        ),
        (
            EvaluationRunPhase.INCONCLUSIVE,
            EvaluationTerminalStatus.INCONCLUSIVE,
            None,
            None,
        ),
        (
            EvaluationRunPhase.INCONCLUSIVE,
            EvaluationTerminalStatus.INCONCLUSIVE,
            "7" * 64,
            "8" * 64,
        ),
        (
            EvaluationRunPhase.CASE_INVALID,
            EvaluationTerminalStatus.CASE_INVALID,
            None,
            None,
        ),
        (
            EvaluationRunPhase.CASE_INVALID,
            EvaluationTerminalStatus.CASE_INVALID,
            None,
            "8" * 64,
        ),
    ],
)
def test_manifest_accepts_phase_appropriate_terminal_hash_relationships(
    state: EvaluationRunPhase,
    terminal_status: EvaluationTerminalStatus | None,
    legal_ledger_hash: str | None,
    result_hash: str | None,
) -> None:
    """Terminal and sealed-ledger evidence requirements follow the persisted phase."""
    manifest = evaluation_manifest(
        state=state,
        terminal_status=terminal_status,
        legal_ledger_hash=legal_ledger_hash,
        result_hash=result_hash,
    )

    assert manifest.state is state
    assert manifest.terminal_status is terminal_status


@pytest.mark.parametrize(
    ("state", "terminal_status", "legal_ledger_hash", "result_hash"),
    [
        (EvaluationRunPhase.CREATED, EvaluationTerminalStatus.COMPLETED, None, None),
        (EvaluationRunPhase.CREATED, None, "7" * 64, None),
        (EvaluationRunPhase.CREATED, None, None, "8" * 64),
        (EvaluationRunPhase.GRADE_A, None, None, None),
        (EvaluationRunPhase.COMPLETED, None, "7" * 64, "8" * 64),
        (
            EvaluationRunPhase.COMPLETED,
            EvaluationTerminalStatus.INCONCLUSIVE,
            "7" * 64,
            "8" * 64,
        ),
        (EvaluationRunPhase.COMPLETED, EvaluationTerminalStatus.COMPLETED, None, "8" * 64),
        (EvaluationRunPhase.COMPLETED, EvaluationTerminalStatus.COMPLETED, "7" * 64, None),
        (EvaluationRunPhase.INCONCLUSIVE, None, None, None),
        (
            EvaluationRunPhase.CASE_INVALID,
            EvaluationTerminalStatus.CASE_INVALID,
            "7" * 64,
            None,
        ),
        (
            EvaluationRunPhase.CASE_INVALID,
            EvaluationTerminalStatus.INCONCLUSIVE,
            None,
            None,
        ),
    ],
)
def test_manifest_rejects_phase_inconsistent_terminal_hash_relationships(
    state: EvaluationRunPhase,
    terminal_status: EvaluationTerminalStatus | None,
    legal_ledger_hash: str | None,
    result_hash: str | None,
) -> None:
    """A manifest cannot claim terminal or sealed artifacts in an incompatible phase."""
    with pytest.raises(ValidationError):
        EvaluationManifest.model_validate(
            manifest_payload(
                state=state,
                terminal_status=terminal_status,
                legal_ledger_hash=legal_ledger_hash,
                result_hash=result_hash,
            )
        )


def test_terminal_manifest_rejects_unfinished_pending_judge_calls() -> None:
    """A terminal workflow cannot leave an outstanding call in pending state."""
    pending = judge_call(state="pending")

    with pytest.raises(ValidationError):
        EvaluationManifest.model_validate(
            manifest_payload(
                judge_calls=[pending],
                state=EvaluationRunPhase.INCONCLUSIVE,
                terminal_status=EvaluationTerminalStatus.INCONCLUSIVE,
            )
        )


def test_run_state_resolves_the_exact_pending_current_call() -> None:
    """An active cursor resolves by logical ID and attempt to one pending operation."""
    prior = judge_call(call_id="grade-a-judge-1", state="failed", attempt=1)
    current = judge_call(
        call_id="grade-a-judge-1",
        state="pending",
        attempt=2,
        retry_count=1,
    )
    state = EvaluationRunState.model_validate(
        run_state_payload(
            judge_calls=[prior, current],
            current_operation=JudgeOperation.GRADE_REPORT,
            current_call_id="grade-a-judge-1",
            attempt=2,
            state=EvaluationRunPhase.GRADE_A,
            retry_count=1,
            manifest_fingerprint="9" * 64,
        )
    )

    assert state.current_call_id == current.call_id
    assert state.current_operation is current.operation
    assert state.manifest_fingerprint == "9" * 64


@pytest.mark.parametrize("field", _RUN_STATE_PROVENANCE_STRING_FIELDS)
@pytest.mark.parametrize("raw_kind", ["bytes", "int", "bool"])
def test_run_state_provenance_requires_raw_python_strings(
    field: str,
    raw_kind: str,
) -> None:
    """Run-state hashes and the active call identity must reject raw coercion."""
    pending = judge_call(call_id="7", state="pending")
    payload = run_state_payload(
        judge_calls=[pending.model_dump(mode="json")],
        current_operation=JudgeOperation.GRADE_REPORT.value,
        current_call_id=pending.call_id,
        attempt=pending.attempt,
        state=EvaluationRunPhase.GRADE_A.value,
        manifest_fingerprint="9" * 64,
    )
    original = payload[field]
    assert isinstance(original, str)
    assert getattr(EvaluationRunState.model_validate(payload), field) == original
    payload[field] = non_string_scalar(original, raw_kind)

    with pytest.raises(ValidationError) as exc_info:
        EvaluationRunState.model_validate(payload)

    assert_string_type_error(exc_info.value, (field,))


@pytest.mark.parametrize(
    ("field", "valid_value", "state"),
    _JUDGE_CALL_PROVENANCE_STRING_FIELDS,
)
def test_run_state_rejects_raw_bytes_in_nested_judge_call_provenance(
    field: str,
    valid_value: str,
    state: str,
) -> None:
    """A raw nested call dictionary cannot decode provenance bytes in run state."""
    call = judge_call(state=state, **{field: valid_value})
    payload = run_state_payload(
        judge_calls=[call.model_dump(mode="json")],
        state=EvaluationRunPhase.LEDGER_REFEREE.value,
        attempt=1,
        manifest_fingerprint="9" * 64,
    )
    raw_calls = payload["judge_calls"]
    assert isinstance(raw_calls, list)
    raw_call = raw_calls[0]
    assert isinstance(raw_call, dict)
    raw_call[field] = valid_value.encode("utf-8")

    with pytest.raises(ValidationError) as exc_info:
        EvaluationRunState.model_validate(payload)

    assert_string_type_error(exc_info.value, ("judge_calls", 0, field))


def test_provenance_strictness_preserves_none_and_json_enum_strings() -> None:
    """Strict provenance scalars must not make optional values or enum JSON strict."""
    completed = JudgeCallRecord.model_validate(
        judge_call_payload(
            operation=JudgeOperation.GRADE_REPORT.value,
            judge_isolation=JudgeIsolation.FRESH_CONTEXT.value,
        )
    )
    pending = JudgeCallRecord.model_validate(
        judge_call_payload(
            state="pending",
            operation=JudgeOperation.GRADE_REPORT.value,
        )
    )
    manifest = EvaluationManifest.model_validate(
        manifest_payload(
            judge_calls=[completed],
            state=EvaluationRunPhase.GRADE_A.value,  # type: ignore[arg-type]
            legal_ledger_hash="7" * 64,
        )
    )
    run_state = EvaluationRunState.model_validate(
        run_state_payload(
            judge_calls=[pending.model_dump(mode="json")],
            current_operation=JudgeOperation.GRADE_REPORT.value,
            current_call_id=pending.call_id,
            attempt=pending.attempt,
            state=EvaluationRunPhase.GRADE_A.value,
        )
    )

    assert completed.operation is JudgeOperation.GRADE_REPORT
    assert completed.judge_isolation is JudgeIsolation.FRESH_CONTEXT
    assert pending.response_fingerprint is None
    assert pending.provider_name is None
    assert pending.model_name is None
    assert pending.response_artifact_path is None
    assert pending.diagnostics_artifact_path is None
    assert manifest.state is EvaluationRunPhase.GRADE_A
    assert run_state.current_operation is JudgeOperation.GRADE_REPORT
    assert run_state.state is EvaluationRunPhase.GRADE_A
    assert run_state.manifest_fingerprint is None


@pytest.mark.parametrize(
    "updates",
    [
        {"current_operation": JudgeOperation.GRADE_REPORT},
        {"current_call_id": "grade-a-judge-1"},
        {
            "current_operation": JudgeOperation.GRADE_REPORT,
            "current_call_id": "missing-call",
        },
        {
            "current_operation": JudgeOperation.GRADE_REPORT,
            "current_call_id": "grade-a-judge-1",
            "attempt": 2,
        },
        {
            "current_operation": JudgeOperation.REFEREE,
            "current_call_id": "grade-a-judge-1",
            "attempt": 1,
        },
    ],
)
def test_run_state_rejects_unresolved_or_mismatched_current_calls(
    updates: dict[str, object],
) -> None:
    """A cursor cannot omit, invent, or misdescribe its pending call record."""
    pending = judge_call(state="pending")
    payload = run_state_payload(
        judge_calls=[pending],
        state=EvaluationRunPhase.GRADE_A,
        **updates,
    )

    with pytest.raises(ValidationError):
        EvaluationRunState.model_validate(payload)


def test_run_state_rejects_a_current_cursor_to_a_completed_call() -> None:
    """Only a pending call may be exposed as the workflow's current operation."""
    completed = judge_call()

    with pytest.raises(ValidationError):
        EvaluationRunState.model_validate(
            run_state_payload(
                judge_calls=[completed],
                current_operation=JudgeOperation.GRADE_REPORT,
                current_call_id=completed.call_id,
                attempt=completed.attempt,
                state=EvaluationRunPhase.GRADE_A,
            )
        )


@pytest.mark.parametrize(
    "state",
    [EvaluationRunPhase.GRADE_A, EvaluationRunPhase.INCONCLUSIVE],
)
def test_run_state_rejects_pending_calls_without_an_exact_current_cursor(
    state: EvaluationRunPhase,
) -> None:
    """A pending call cannot be orphaned by an active or terminal run snapshot."""
    pending = judge_call(state="pending")
    terminal_status = (
        EvaluationTerminalStatus.INCONCLUSIVE if state is EvaluationRunPhase.INCONCLUSIVE else None
    )

    with pytest.raises(ValidationError):
        EvaluationRunState.model_validate(
            run_state_payload(
                judge_calls=[pending],
                state=state,
                terminal_status=terminal_status,
                attempt=1,
            )
        )


def test_run_state_rejects_a_second_pending_call_outside_the_current_cursor() -> None:
    """Only the one call selected by the cursor may remain pending."""
    current = judge_call(state="pending")
    orphan = judge_call(
        call_id="grade-a-judge-2",
        state="pending",
        response_fingerprint="a" * 64,
    )

    with pytest.raises(ValidationError):
        EvaluationRunState.model_validate(
            run_state_payload(
                judge_calls=[current, orphan],
                current_operation=JudgeOperation.GRADE_REPORT,
                current_call_id=current.call_id,
                attempt=current.attempt,
                state=EvaluationRunPhase.GRADE_A,
            )
        )


@pytest.mark.parametrize(
    ("state", "terminal_status"),
    [
        (EvaluationRunPhase.COMPLETED, EvaluationTerminalStatus.COMPLETED),
        (EvaluationRunPhase.INCONCLUSIVE, EvaluationTerminalStatus.INCONCLUSIVE),
        (EvaluationRunPhase.CASE_INVALID, EvaluationTerminalStatus.CASE_INVALID),
    ],
)
def test_run_state_accepts_terminal_phases_without_a_current_call(
    state: EvaluationRunPhase,
    terminal_status: EvaluationTerminalStatus,
) -> None:
    """Each terminal phase has its matching status and no active operation."""
    run_state = EvaluationRunState.model_validate(
        run_state_payload(state=state, terminal_status=terminal_status)
    )

    assert run_state.current_operation is None
    assert run_state.current_call_id is None


@pytest.mark.parametrize(
    "updates",
    [
        {"state": EvaluationRunPhase.CREATED, "attempt": 1},
        {
            "state": EvaluationRunPhase.CREATED,
            "current_operation": JudgeOperation.GRADE_REPORT,
            "current_call_id": "grade-a-judge-1",
            "attempt": 1,
        },
        {
            "state": EvaluationRunPhase.COMPLETED,
            "terminal_status": EvaluationTerminalStatus.COMPLETED,
            "current_operation": JudgeOperation.GRADE_REPORT,
            "current_call_id": "grade-a-judge-1",
            "attempt": 1,
        },
        {
            "state": EvaluationRunPhase.COMPLETED,
            "terminal_status": EvaluationTerminalStatus.INCONCLUSIVE,
        },
        {
            "state": EvaluationRunPhase.INCONCLUSIVE,
            "terminal_status": None,
        },
        {
            "state": EvaluationRunPhase.GRADE_A,
            "terminal_status": EvaluationTerminalStatus.COMPLETED,
        },
    ],
)
def test_run_state_rejects_created_or_terminal_relationship_mismatches(
    updates: dict[str, object],
) -> None:
    """Created and terminal snapshots have exact cursor, attempt, and status shapes."""
    pending = judge_call(state="pending")
    payload = run_state_payload(judge_calls=[pending], **updates)

    with pytest.raises(ValidationError):
        EvaluationRunState.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "raw_value"),
    [
        ("attempt", 0.0),
        ("attempt", "0"),
        ("attempt", False),
        ("retry_count", 0.0),
        ("retry_count", "0"),
        ("retry_count", False),
    ],
)
def test_run_state_rejects_coercible_integer_representations(
    field: str,
    raw_value: object,
) -> None:
    """Persisted workflow counters must retain their exact integer wire types."""
    payload = run_state_payload()
    payload[field] = raw_value

    with pytest.raises(ValidationError):
        EvaluationRunState.model_validate(payload)


def test_run_state_revalidates_mutated_judge_call_instances() -> None:
    """A mutated nested call cannot bypass strict validation in persisted run state."""
    call = judge_call()
    call.attempt = True

    with pytest.raises(ValidationError):
        EvaluationRunState.model_validate(
            run_state_payload(
                judge_calls=[call],
                state=EvaluationRunPhase.LEDGER_REFEREE,
                attempt=1,
            )
        )


def test_run_state_rejects_duplicate_judge_call_attempt_identity() -> None:
    """A run-state snapshot cannot retain two records for one logical attempt."""
    first = judge_call(
        call_id="referee-1",
        operation=JudgeOperation.REFEREE,
        anonymous_label=None,
    )
    duplicate = judge_call(
        call_id="referee-1",
        operation=JudgeOperation.REFEREE,
        anonymous_label=None,
        request_artifact_path="calls/referee-1/duplicate/request.json",
        response_artifact_path="calls/referee-1/duplicate/response.json",
        response_fingerprint="a" * 64,
    )

    with pytest.raises(ValidationError):
        EvaluationRunState.model_validate(
            run_state_payload(
                judge_calls=[first, duplicate],
                state=EvaluationRunPhase.LEDGER_REFEREE,
                attempt=1,
            )
        )


def test_grade_dispute_accepts_entry_grade_alternatives() -> None:
    """An entry dispute must retain both complete grader alternatives."""
    dispute = GradeDispute(
        dispute_id="grade-entry-ledger-1",
        anonymous_label="A",
        ledger_fingerprint="1" * 64,
        kind="entry_grade",
        subject_id="ledger-1",
        materiality=Materiality.CRITICAL,
        grader_1=entry_alternative(),
        grader_2=entry_alternative(disposition=CoverageDisposition.PARTIAL),
        rationale="The graders disagree on coverage of a critical proposition.",
    )

    assert dispute.grader_1.entry_grade is not None
    assert dispute.grader_2.entry_grade is not None


def test_grade_dispute_accepts_present_and_absent_claim_alternatives() -> None:
    """Claim-presence disagreements must preserve the present claim and explicit absence."""
    dispute = GradeDispute(
        dispute_id="grade-claim-claim-1",
        anonymous_label="B",
        ledger_fingerprint="2" * 64,
        kind="out_of_ledger_claim",
        subject_id="claim-1",
        materiality=Materiality.MATERIAL,
        grader_1=claim_alternative(),
        grader_2=absent_claim_alternative(),
        rationale="Only one grader identified this material extra-report claim.",
    )

    assert dispute.grader_1.out_of_ledger_claim is not None
    assert dispute.grader_2.absent_claim is True


def test_claim_dispute_materiality_equals_maximum_present_claim_materiality() -> None:
    """Claim dispute materiality must be derived from the complete present alternatives."""
    two_present = GradeDispute(
        dispute_id="grade-claim-claim-1",
        anonymous_label="A",
        ledger_fingerprint="2" * 64,
        kind="out_of_ledger_claim",
        subject_id="claim-1",
        materiality=Materiality.CRITICAL,
        grader_1=claim_alternative(materiality=Materiality.SUPPORTING),
        grader_2=claim_alternative(materiality=Materiality.CRITICAL),
        rationale="The critical alternative determines dispute materiality.",
    )
    one_present = GradeDispute(
        dispute_id="grade-claim-claim-1",
        anonymous_label="A",
        ledger_fingerprint="2" * 64,
        kind="out_of_ledger_claim",
        subject_id="claim-1",
        materiality=Materiality.SUPPORTING,
        grader_1=claim_alternative(materiality=Materiality.SUPPORTING),
        grader_2=absent_claim_alternative(),
        rationale="The sole present claim determines dispute materiality.",
    )

    assert two_present.materiality is Materiality.CRITICAL
    assert one_present.materiality is Materiality.SUPPORTING


@pytest.mark.parametrize(
    ("dispute_materiality", "grader_1", "grader_2"),
    [
        (
            Materiality.MATERIAL,
            claim_alternative(materiality=Materiality.CRITICAL),
            claim_alternative(materiality=Materiality.SUPPORTING),
        ),
        (
            Materiality.MATERIAL,
            claim_alternative(materiality=Materiality.SUPPORTING),
            absent_claim_alternative(),
        ),
    ],
)
def test_claim_dispute_rejects_understated_or_overstated_materiality(
    dispute_materiality: Materiality,
    grader_1: GradeAlternative,
    grader_2: GradeAlternative,
) -> None:
    """A claim referee must not receive a dispute with manipulated materiality."""
    with pytest.raises(
        ValidationError, match="materiality must equal maximum present claim materiality"
    ):
        GradeDispute(
            dispute_id="grade-claim-claim-1",
            anonymous_label="A",
            ledger_fingerprint="2" * 64,
            kind="out_of_ledger_claim",
            subject_id="claim-1",
            materiality=dispute_materiality,
            grader_1=grader_1,
            grader_2=grader_2,
            rationale="The supplied dispute materiality does not match its alternatives.",
        )


def test_grade_dispute_accepts_narrative_score_alternatives() -> None:
    """Narrative disputes must carry both full scores without legal materiality."""
    dispute = GradeDispute(
        dispute_id="grade-narrative-executive-summary",
        anonymous_label="A",
        ledger_fingerprint="3" * 64,
        kind="narrative_score",
        subject_id="executive_summary",
        grader_1=narrative_alternative(score=2),
        grader_2=narrative_alternative(score=4),
        rationale="The graders disagree on the executive summary's quality.",
    )

    assert dispute.materiality is None
    assert dispute.grader_2.narrative_score is not None


@pytest.mark.parametrize(
    "payload",
    [
        {"request_fingerprint": "a" * 64},
        {
            "request_fingerprint": "a" * 64,
            "entry_grade": entry_alternative().entry_grade,
            "narrative_score": narrative_alternative().narrative_score,
        },
        {
            "request_fingerprint": "a" * 64,
            "entry_grade": entry_alternative().entry_grade,
            "absent_claim": True,
        },
    ],
)
def test_grade_alternative_rejects_invalid_cardinality(payload: dict[str, object]) -> None:
    """An alternative cannot be empty, multi-valued, or both absent and present."""
    with pytest.raises(ValidationError):
        GradeAlternative.model_validate(payload)


@pytest.mark.parametrize("mutated_bool", [1, "true"])
def test_grade_alternative_strict_boundary_rejects_coerced_absence(
    mutated_bool: object,
) -> None:
    """Strict snapshots must reject integer and string mutations of absent_claim."""
    payload = absent_claim_alternative().model_dump(mode="python")
    payload["absent_claim"] = mutated_bool

    with pytest.raises(ValidationError):
        GradeAlternative.model_validate(payload, strict=True)


@pytest.mark.parametrize(
    ("kind", "subject_id", "materiality", "grader_1", "grader_2"),
    [
        (
            "entry_grade",
            "ledger-1",
            Materiality.MATERIAL,
            entry_alternative(),
            narrative_alternative(),
        ),
        (
            "entry_grade",
            "different-ledger",
            Materiality.MATERIAL,
            entry_alternative(),
            entry_alternative(),
        ),
        ("entry_grade", "ledger-1", None, entry_alternative(), entry_alternative()),
        (
            "out_of_ledger_claim",
            "claim-1",
            Materiality.MATERIAL,
            claim_alternative(),
            entry_alternative(),
        ),
        (
            "out_of_ledger_claim",
            "claim-1",
            Materiality.MATERIAL,
            absent_claim_alternative(),
            absent_claim_alternative(),
        ),
        (
            "out_of_ledger_claim",
            "different-claim",
            Materiality.MATERIAL,
            claim_alternative(),
            absent_claim_alternative(),
        ),
        (
            "out_of_ledger_claim",
            "claim-1",
            None,
            claim_alternative(),
            absent_claim_alternative(),
        ),
        (
            "narrative_score",
            "executive_summary",
            None,
            narrative_alternative(),
            claim_alternative(),
        ),
        (
            "narrative_score",
            "scanability",
            None,
            narrative_alternative(),
            narrative_alternative(),
        ),
        (
            "narrative_score",
            "executive_summary",
            Materiality.SUPPORTING,
            narrative_alternative(),
            narrative_alternative(),
        ),
    ],
)
def test_grade_dispute_rejects_invalid_kind_subject_and_materiality_combinations(
    kind: str,
    subject_id: str,
    materiality: Materiality | None,
    grader_1: GradeAlternative,
    grader_2: GradeAlternative,
) -> None:
    """Each dispute kind must bind the correct payload, subject, and materiality."""
    with pytest.raises(ValidationError):
        GradeDispute(
            dispute_id="grade-dispute-1",
            anonymous_label="A",
            ledger_fingerprint="4" * 64,
            kind=kind,  # type: ignore[arg-type]
            subject_id=subject_id,
            materiality=materiality,
            grader_1=grader_1,
            grader_2=grader_2,
            rationale="The alternatives are deliberately inconsistent.",
        )


def test_grade_dispute_models_reject_unknown_fields_and_fingerprint_stably() -> None:
    """Dispute artifacts must be strict and stable across a JSON round trip."""
    dispute = GradeDispute(
        dispute_id="grade-claim-claim-1",
        anonymous_label="A",
        ledger_fingerprint="5" * 64,
        kind="out_of_ledger_claim",
        subject_id="claim-1",
        materiality=Materiality.MATERIAL,
        grader_1=claim_alternative(),
        grader_2=absent_claim_alternative(),
        rationale="The graders disagree on claim presence.",
    )

    assert model_fingerprint(dispute) == model_fingerprint(
        GradeDispute.model_validate(dispute.model_dump(mode="json"))
    )
    with pytest.raises(ValidationError, match="extra_forbidden"):
        GradeDispute.model_validate({**dispute.model_dump(mode="json"), "surprise": True})
    with pytest.raises(ValidationError, match="extra_forbidden"):
        GradeAlternative.model_validate(
            {**absent_claim_alternative().model_dump(mode="json"), "surprise": True}
        )


def test_grade_dispute_fingerprint_binds_both_grader_alternatives() -> None:
    """Changing either complete grader alternative must change the dispute fingerprint."""
    baseline = GradeDispute(
        dispute_id="grade-entry-ledger-1",
        anonymous_label="A",
        ledger_fingerprint="6" * 64,
        kind="entry_grade",
        subject_id="ledger-1",
        materiality=Materiality.MATERIAL,
        grader_1=entry_alternative(disposition=CoverageDisposition.COMPLETE),
        grader_2=entry_alternative(disposition=CoverageDisposition.PARTIAL),
        rationale="The graders disagree on coverage.",
    )
    changed_grader_1 = baseline.model_copy(
        update={"grader_1": entry_alternative(disposition=CoverageDisposition.MISSING)}
    )
    changed_grader_2 = baseline.model_copy(
        update={"grader_2": entry_alternative(disposition=CoverageDisposition.CONTRADICTED)}
    )

    assert (
        len(
            {
                model_fingerprint(baseline),
                model_fingerprint(changed_grader_1),
                model_fingerprint(changed_grader_2),
            }
        )
        == 3
    )


def test_referee_grade_replacement_requires_exact_resolution_coupling() -> None:
    """Only a replace resolution may carry a replacement grade alternative."""
    replacement = claim_alternative()
    accepted = RefereeDecision(
        dispute_id="grade-claim-claim-1",
        selected_grade_resolution="accept_grader_1",
        grade_dispute_fingerprint="f" * 64,
        rationale="The first grader preserved the supported claim shape.",
    )
    replaced = RefereeDecision(
        dispute_id="grade-claim-claim-1",
        selected_grade_resolution="replace",
        grade_dispute_fingerprint="f" * 64,
        replacement_grade_alternative=replacement,
        rationale="Neither grader captured the supported claim shape.",
    )

    assert accepted.replacement_grade_alternative is None
    assert replaced.replacement_grade_alternative == replacement
    with pytest.raises(ValidationError):
        RefereeDecision(
            dispute_id="grade-claim-claim-1",
            selected_grade_resolution="replace",
            grade_dispute_fingerprint="f" * 64,
            rationale="A replacement was not supplied.",
        )
    with pytest.raises(ValidationError):
        RefereeDecision(
            dispute_id="grade-claim-claim-1",
            selected_grade_resolution="accept_grader_2",
            grade_dispute_fingerprint="f" * 64,
            replacement_grade_alternative=replacement,
            rationale="An accepted alternative cannot also be replaced.",
        )
    with pytest.raises(ValidationError):
        RefereeDecision(
            dispute_id="grade-claim-claim-1",
            replacement_grade_alternative=replacement,
            rationale="A replacement requires an explicit grade resolution.",
        )


def test_referee_grade_resolution_requires_exact_dispute_fingerprint_coupling() -> None:
    """A grade selection and its dispute fingerprint must always travel together."""
    with pytest.raises(ValidationError, match="grade resolution requires dispute fingerprint"):
        RefereeDecision(
            dispute_id="grade-entry-ledger-1",
            selected_grade_resolution="accept_grader_1",
            rationale="This selection is not bound to its alternatives.",
        )
    with pytest.raises(ValidationError, match="dispute fingerprint requires grade resolution"):
        RefereeDecision(
            dispute_id="grade-entry-ledger-1",
            grade_dispute_fingerprint="f" * 64,
            rationale="This fingerprint has no selection.",
        )


def test_fingerprinted_referee_replacement_remains_context_neutral() -> None:
    """The generic model permits any valid alternative; Task 4 checks kind and subject."""
    decision = RefereeDecision(
        dispute_id="grade-claim-claim-1",
        selected_grade_resolution="replace",
        grade_dispute_fingerprint="f" * 64,
        replacement_grade_alternative=entry_alternative(ledger_id="ledger-elsewhere"),
        rationale="Task 4 must reject this entry replacement for a claim dispute.",
    )

    assert decision.replacement_grade_alternative is not None
    assert decision.replacement_grade_alternative.entry_grade is not None
    with pytest.raises(ValidationError, match="grade resolution requires dispute fingerprint"):
        RefereeDecision(
            dispute_id="grade-claim-claim-1",
            selected_grade_resolution="replace",
            replacement_grade_alternative=entry_alternative(ledger_id="ledger-elsewhere"),
            rationale="A structurally valid replacement is still unbound.",
        )


def test_grade_binding_preserves_legacy_referee_decision_domains() -> None:
    """Ledger and disposition decisions remain valid without grade-only binding fields."""
    legacy_disposition = RefereeDecision(
        dispute_id="grade-entry-ledger-1",
        selected_disposition=CoverageDisposition.PARTIAL,
        rationale="Legacy Task 4 validation owns this selector.",
    )
    ledger_decision = RefereeDecision(
        dispute_id="ledger-dispute-1",
        selected_ledger_resolution="accept_a",
        rationale="Task 3 selected the first ledger alternative.",
    )

    assert legacy_disposition.grade_dispute_fingerprint is None
    assert ledger_decision.selected_grade_resolution is None


def test_report_evaluation_accepts_only_its_exact_score_snapshot() -> None:
    """A report score must bind every metric and upstream evidence fingerprint."""
    evaluation = report_evaluation()

    assert evaluation.score_fingerprint == report_score_fingerprint(
        evaluation.model_dump(mode="json")
    )
    with pytest.raises(ValidationError, match="extra_forbidden"):
        ReportEvaluation.model_validate({**evaluation.model_dump(mode="json"), "surprise": True})


@pytest.mark.parametrize(
    ("field", "mutated_value"),
    [
        ("absolute_disposition", AbsoluteDisposition.FAIL),
        ("critical_recall", 0.5),
        ("weighted_recall", 0.75),
        ("claim_precision", 0.8),
        ("walk_average", 3.5),
        ("walk_minimum", 2),
        ("normalized_score", 88.0),
        ("critical_defect", True),
        ("issue_codes", ["CRITICAL_LEDGER_ENTRY_MISSING"]),
        ("blocking_codes", ["WEIGHTED_RECALL_BELOW_FLOOR"]),
        ("ledger_fingerprint", "a" * 64),
        ("resolved_grade_fingerprint", "b" * 64),
        ("deterministic_checks_fingerprint", "c" * 64),
        ("rubric_fingerprint", "d" * 64),
    ],
)
def test_report_evaluation_rejects_stale_score_fingerprint_after_mutation(
    field: str,
    mutated_value: object,
) -> None:
    """Strict revalidation must detect every stale score or evidence mutation."""
    payload = report_evaluation().model_dump(mode="python")
    payload[field] = mutated_value

    with pytest.raises(ValidationError, match="score_fingerprint must match score snapshot"):
        ReportEvaluation.model_validate(payload, strict=True)


def test_report_score_fingerprint_is_stable_across_dict_and_list_serialization() -> None:
    """Canonical mapping order and JSON list round trips must preserve the score binding."""
    evaluation = report_evaluation(blocking_codes=["CODE_A", "CODE_B"])
    serialized = evaluation.model_dump(mode="json")
    score_payload = {key: value for key, value in serialized.items() if key != "score_fingerprint"}
    reordered = dict(reversed(list(score_payload.items())))
    round_trip = json.loads(canonical_json_bytes(serialized).decode("utf-8"))

    assert report_score_fingerprint(score_payload) == report_score_fingerprint(reordered)
    assert ReportEvaluation.model_validate(round_trip) == evaluation
    assert round_trip["blocking_codes"] == ["CODE_A", "CODE_B"]


@pytest.mark.parametrize("walk_minimum", [1, 2, 3, 4])
def test_report_evaluation_accepts_integer_walk_minimum_with_stable_self_hash(
    walk_minimum: int,
) -> None:
    """Each integer in the closed range must retain its exact self-hashed score snapshot."""
    evaluation = report_evaluation(walk_minimum=walk_minimum)

    assert type(evaluation.walk_minimum) is int
    assert evaluation.walk_minimum == walk_minimum
    assert evaluation.score_fingerprint == report_score_fingerprint(
        evaluation.model_dump(mode="json")
    )


@pytest.mark.parametrize(
    "raw_walk_minimum",
    [
        pytest.param(1.0, id="float"),
        pytest.param("1", id="integer-string"),
        pytest.param("1.0", id="float-string"),
        pytest.param(True, id="boolean"),
    ],
)
def test_report_evaluation_rejects_coercible_noninteger_walk_minimum(
    raw_walk_minimum: object,
) -> None:
    """A matching post-coercion hash must not make raw non-integer evidence valid."""
    payload = report_evaluation_payload(walk_minimum=raw_walk_minimum)
    canonical_integer_payload = {**payload, "walk_minimum": 1}
    payload["score_fingerprint"] = report_score_fingerprint(canonical_integer_payload)

    with pytest.raises(ValidationError):
        ReportEvaluation.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    [
        ("critical_recall", -0.01),
        ("critical_recall", 1.01),
        ("walk_minimum", 0),
        ("walk_minimum", 5),
        ("ledger_fingerprint", "not-a-hash"),
        ("resolved_grade_fingerprint", "not-a-hash"),
        ("deterministic_checks_fingerprint", "not-a-hash"),
        ("rubric_fingerprint", "not-a-hash"),
        ("score_fingerprint", "not-a-hash"),
    ],
)
def test_report_evaluation_rejects_malformed_ranges_and_hashes(
    field: str,
    invalid_value: object,
) -> None:
    """Critical recall, walk minimum, and all evidence hashes are bounded strictly."""
    payload = report_evaluation_payload()
    payload[field] = invalid_value
    if field != "score_fingerprint":
        payload["score_fingerprint"] = report_score_fingerprint(payload)

    with pytest.raises(ValidationError):
        ReportEvaluation.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    [
        ("critical_recall", float("nan")),
        ("critical_recall", float("inf")),
        ("critical_recall", float("-inf")),
        ("critical_recall", -0.01),
        ("critical_recall", 1.01),
        ("weighted_recall", float("nan")),
        ("weighted_recall", float("inf")),
        ("weighted_recall", float("-inf")),
        ("weighted_recall", -0.01),
        ("weighted_recall", 1.01),
        ("claim_precision", float("nan")),
        ("claim_precision", float("inf")),
        ("claim_precision", float("-inf")),
        ("claim_precision", -0.01),
        ("claim_precision", 1.01),
        ("walk_average", float("nan")),
        ("walk_average", float("inf")),
        ("walk_average", float("-inf")),
        ("walk_average", 0.99),
        ("walk_average", 4.01),
        ("walk_minimum", float("nan")),
        ("walk_minimum", float("inf")),
        ("walk_minimum", float("-inf")),
        ("walk_minimum", 0),
        ("walk_minimum", 5),
        ("walk_minimum", 1.5),
        ("normalized_score", float("nan")),
        ("normalized_score", float("inf")),
        ("normalized_score", float("-inf")),
        ("normalized_score", -0.01),
        ("normalized_score", 100.01),
    ],
)
def test_report_evaluation_rejects_self_hashed_invalid_numeric_evidence(
    field: str,
    invalid_value: object,
) -> None:
    """A matching self-hash cannot make nonfinite or out-of-domain evidence valid."""
    payload = report_evaluation_payload()
    payload[field] = invalid_value
    payload["score_fingerprint"] = report_score_fingerprint(payload)

    with pytest.raises(ValidationError):
        ReportEvaluation.model_validate(payload)


@pytest.mark.parametrize(
    "upstream_field",
    [
        "ledger_fingerprint",
        "resolved_grade_fingerprint",
        "deterministic_checks_fingerprint",
        "rubric_fingerprint",
    ],
)
def test_each_upstream_fingerprint_changes_required_report_score_fingerprint(
    upstream_field: str,
) -> None:
    """Every upstream evidence identity must contribute to the score fingerprint."""
    baseline = report_evaluation_payload()
    changed = dict(baseline)
    changed[upstream_field] = "f" * 64
    changed["score_fingerprint"] = report_score_fingerprint(changed)

    assert changed["score_fingerprint"] != baseline["score_fingerprint"]
    assert (
        ReportEvaluation.model_validate(changed).score_fingerprint == changed["score_fingerprint"]
    )


def test_evaluation_package_exports_only_the_attorney_contract_api() -> None:
    """Callers need a stable public import surface for the contract layer."""
    from regulatory_harvest import evaluation

    expected_exports = {
        "AbsoluteDisposition",
        "AdmissionCheck",
        "ArtifactRecord",
        "AttorneyEvaluationCase",
        "AttorneyEvaluationResult",
        "BlindAssignment",
        "CandidateGrade",
        "CandidateReport",
        "CandidateRole",
        "CaseAdmissionJudgment",
        "CaseEnvelope",
        "CaseReadiness",
        "ComparativeDisposition",
        "ComparisonEvaluation",
        "CoverageDisposition",
        "DeterministicChecks",
        "EntryGrade",
        "EntryFindingCode",
        "EvaluationIssue",
        "EvaluationManifest",
        "EvaluationMode",
        "EvaluationRubric",
        "EvaluationRunPhase",
        "EvaluationRunState",
        "EvaluationSource",
        "EvaluationTerminalStatus",
        "GradeAlternative",
        "GradeDispute",
        "IssueSeverity",
        "JudgeCallRecord",
        "JudgeIsolation",
        "JudgeOperation",
        "JudgeRequest",
        "JudgeResponse",
        "LedgerAudit",
        "LedgerCategory",
        "LedgerCitation",
        "LedgerDispute",
        "LedgerEntry",
        "LedgerGap",
        "LegalLedger",
        "Materiality",
        "NarrativeScore",
        "NarrativeFindingCode",
        "OutOfLedgerClaim",
        "ReadinessStatus",
        "RefereeDecision",
        "ReportEvaluation",
        "RequestedAuthority",
        "SealedLedger",
        "model_fingerprint",
    }

    assert expected_exports <= set(evaluation.__all__)
    assert all(hasattr(evaluation, name) for name in expected_exports)
