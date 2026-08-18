from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import io
import json
import math
import os
import stat
import subprocess
import sys
import tarfile
from pathlib import Path
from types import ModuleType
from typing import Any, cast

import pytest
from pydantic import ValidationError

from regulatory_harvest.evaluation import attorney_artifacts
from regulatory_harvest.evaluation import attorney_workflow as core_workflow
from regulatory_harvest.evaluation.attorney_admission import (
    adjudicate_admission as adjudicate_core,
)
from regulatory_harvest.evaluation.attorney_admission import build_admission_packet as packet_core
from regulatory_harvest.evaluation.attorney_admission import freeze_case as freeze_core
from regulatory_harvest.evaluation.attorney_cli import _case_from_fixture
from regulatory_harvest.evaluation.attorney_contract import (
    PREFLIGHT_ISSUE_MESSAGES,
    ResponseContractCode,
)
from regulatory_harvest.evaluation.attorney_grading import GradeInconclusiveError
from regulatory_harvest.evaluation.attorney_grading import resolve_grades as resolve_core
from regulatory_harvest.evaluation.attorney_grading import validate_grade as validate_grade_core
from regulatory_harvest.evaluation.attorney_ledger import (
    LedgerInconclusiveError as LedgerInconclusiveErrorCore,
)
from regulatory_harvest.evaluation.attorney_ledger import (
    _ledger_invariant_contract_v1_0,
    ledger_invariant_contract,
)
from regulatory_harvest.evaluation.attorney_ledger import (
    ledger_disputes as ledger_disputes_core,
)
from regulatory_harvest.evaluation.attorney_ledger import ledger_findings as ledger_findings_core
from regulatory_harvest.evaluation.attorney_ledger import seal_ledger as seal_core
from regulatory_harvest.evaluation.attorney_models import (
    AttorneyEvaluationResult,
    CandidateGrade,
    CaseAdmissionJudgment,
    DeterministicChecks,
    EvaluationPreflightIssue,
    GradeDispute,
    JudgeResponse,
    LedgerAudit,
    LedgerDispute,
    LegalLedger,
    QualificationCase,
    SealedLedger,
)
from regulatory_harvest.evaluation.attorney_qualification import (
    _preflight_result as qualification_preflight_result_core,
)
from regulatory_harvest.evaluation.attorney_qualification import (
    guarded_submit_case_qualification as guarded_submit_qualification_core,
)
from regulatory_harvest.evaluation.attorney_qualification import (
    initialize_case_qualification as initialize_qualification_core,
)
from regulatory_harvest.evaluation.attorney_qualification import (
    next_qualification_request as next_qualification_core,
)
from regulatory_harvest.evaluation.attorney_qualification import (
    preflight_case_qualification as preflight_qualification_core,
)
from regulatory_harvest.evaluation.attorney_qualification import (
    resume_case_qualification as resume_qualification_core,
)
from regulatory_harvest.evaluation.attorney_qualification import (
    submit_case_qualification as submit_qualification_core,
)
from regulatory_harvest.evaluation.attorney_qualification import (
    verify_case_qualification as verify_qualification_core,
)
from regulatory_harvest.evaluation.attorney_scoring import (
    ReportScoreInputs,
)
from regulatory_harvest.evaluation.attorney_scoring import (
    compare_reports as compare_core,
)
from regulatory_harvest.evaluation.attorney_scoring import score_report as score_core
from regulatory_harvest.evaluation.attorney_workflow import (
    _audit_ledger_request as audit_ledger_request_core,
)
from regulatory_harvest.evaluation.attorney_workflow import (
    _build_ledger_request as build_ledger_request_core,
)
from regulatory_harvest.evaluation.attorney_workflow import (
    _ledger_referee_request as ledger_referee_request_core,
)
from regulatory_harvest.evaluation.attorney_workflow import (
    _repair_ledger_request as repair_ledger_request_core,
)
from regulatory_harvest.evaluation.attorney_workflow import (
    guarded_submit_judge_response as guarded_submit_core,
)
from regulatory_harvest.evaluation.attorney_workflow import (
    initialize_evaluation as initialize_core,
)
from regulatory_harvest.evaluation.attorney_workflow import (
    next_judge_request as next_core,
)
from regulatory_harvest.evaluation.attorney_workflow import (
    submit_judge_response as submit_core,
)
from regulatory_harvest.storage.serialization import canonical_json_bytes

ROOT = Path(__file__).parents[2]
SCRIPT = ROOT / "scripts" / "attorney_eval_portable.py"
FIXTURE = ROOT / "tests" / "fixtures" / "attorney-eval"
GOLDEN_ARTIFACTS = (
    "case-readiness.json",
    "legal-ledger.json",
    "evaluation-result.json",
    "evaluation-report.md",
)


def _load_portable() -> ModuleType:
    spec = importlib.util.spec_from_file_location("attorney_eval_portable", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _case_payload() -> dict[str, Any]:
    case = _case_from_fixture(FIXTURE / "case.json", root=FIXTURE)
    return case.model_dump(mode="json")


def _scripted_payloads() -> list[dict[str, Any]]:
    value = json.loads(
        (FIXTURE / "responses" / "scripted-responses.json").read_text(encoding="utf-8")
    )
    return cast(list[dict[str, Any]], value["responses"])


def _response(request: dict[str, Any], scripted: dict[str, Any], index: int) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "operation": request["operation"],
        "request_fingerprint": request["request_fingerprint"],
        "provider_name": "local-scripted-fixture",
        "model_name": "no-provider",
        "judge_isolation": "scripted_fixture",
        "payload": scripted["payload"],
        "response_id": f"fixture-response-{index}",
        "usage": {},
    }


def _core_case_from_payload(payload: dict[str, Any]) -> Any:
    case_type = type(_case_from_fixture(FIXTURE / "case.json", root=FIXTURE))
    return case_type.model_validate(payload)


def _case_payload_with_report(report_text: str) -> dict[str, Any]:
    """Return the public fixture with one exact replacement report."""
    payload = _case_payload()
    candidate = payload["candidates"][0]
    candidate["report_text"] = report_text
    candidate["report_hash"] = hashlib.sha256(report_text.encode("utf-8")).hexdigest()
    return payload


def _narrative_dispute(
    sealed: dict[str, Any],
    *,
    dimension: str,
    first_passage: str,
    second_passage: str | None = None,
) -> dict[str, Any]:
    """Build one valid synthetic narrative dispute from literal grader passages."""
    first = {
        "request_fingerprint": "1" * 64,
        "entry_grade": None,
        "out_of_ledger_claim": None,
        "narrative_score": {
            "dimension": dimension,
            "score": 4,
            "rationale": "The first grader found this narrative treatment complete.",
            "report_passage": first_passage,
            "finding_codes": [],
        },
        "absent_claim": False,
    }
    second = copy.deepcopy(first)
    second["request_fingerprint"] = "2" * 64
    second["narrative_score"]["score"] = 2
    second["narrative_score"]["rationale"] = (
        "The second grader found this narrative treatment incomplete."
    )
    second["narrative_score"]["report_passage"] = second_passage or first_passage
    return {
        "dispute_id": f"grade-narrative-{dimension.replace('_', '-')}",
        "anonymous_label": "A",
        "ledger_fingerprint": sealed["ledger_fingerprint"],
        "kind": "narrative_score",
        "subject_id": dimension,
        "materiality": None,
        "grader_1": first,
        "grader_2": second,
        "rationale": "The blind graders assign different narrative scores.",
    }


def _referee_requests_for_report(
    report_text: str,
    *,
    dimension: str,
    first_passage: str,
    second_passage: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build byte-comparable portable and full referee requests."""
    portable = _load_portable()
    case_payload = _case_payload_with_report(report_text)
    portable_envelope = portable.freeze_case(case_payload, seed_hex="0" * 64)
    scripted = _scripted_payloads()
    portable_sealed = portable.seal_ledger(
        portable_envelope,
        scripted[1]["payload"],
        scripted[2]["payload"],
        None,
    )
    dispute_payload = _narrative_dispute(
        portable_sealed,
        dimension=dimension,
        first_passage=first_passage,
        second_passage=second_passage,
    )
    legal_hash = hashlib.sha256(portable.canonical_json_bytes(portable_sealed)).hexdigest()
    portable_request = portable._report_referee_request(
        portable_envelope,
        portable_sealed,
        dispute_payload,
        legal_hash,
    )

    core_envelope = freeze_core(_core_case_from_payload(case_payload), seed_hex="0" * 64)
    core_request = core_workflow._report_referee_request(
        core_envelope,
        SealedLedger.model_validate(portable_sealed),
        GradeDispute.model_validate(dispute_payload),
        legal_ledger_hash=legal_hash,
    ).model_dump(mode="json")
    assert portable.canonical_json_bytes(portable_request) == canonical_json_bytes(core_request)
    return portable_request, core_request


def _run_portable(module: ModuleType, run: Path) -> None:
    module.initialize_evaluation(_case_payload(), run, seed_hex="0" * 64)
    scripted = _scripted_payloads()
    for index, item in enumerate(scripted, start=1):
        request = module.next_judge_request(run)
        assert request is not None
        assert request["operation"] == item["operation"]
        assert request["request_fingerprint"] == item["expect"]["request_fingerprint"]
        module.submit_judge_response(run, _response(request, item, index))
    assert module.next_judge_request(run) is None


def _tree_bytes(run: Path) -> dict[str, bytes]:
    return {
        path.relative_to(run).as_posix(): path.read_bytes()
        for path in sorted(run.rglob("*"))
        if path.is_file()
    }


def _extract_retained_run_fixture(archive_bytes: bytes, destination: Path) -> None:
    """Extract one hash-pinned run fixture after rejecting unsafe members."""
    root = destination.resolve()
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as archive:
        members = archive.getmembers()
        for member in members:
            target = (root / member.name).resolve()
            if (
                not target.is_relative_to(root)
                or member.issym()
                or member.islnk()
                or not (member.isdir() or member.isfile())
            ):
                raise ValueError("unsafe retained run fixture member")
        try:
            archive.extractall(destination, filter="data")
        except TypeError:
            archive.extractall(destination)


def _qualification_payload() -> dict[str, Any]:
    case = _case_payload()
    return {
        "schema_version": "1.0",
        "case_id": case["case_id"],
        "mode": case["mode"],
        "question": case["question"],
        "jurisdiction": case["jurisdiction"],
        "as_of": case["as_of"],
        "requested_authorities": copy.deepcopy(case["requested_authorities"]),
        "sources": copy.deepcopy(case["sources"]),
    }


def _qualification_schema_1_1_payload() -> dict[str, Any]:
    """Return one Unicode, CRLF-preserving schema-1.1 qualification case."""
    payload = _qualification_payload()
    source = payload["sources"][0]
    source_text = (
        "Artículo 1. A covered operator must file notice.\r\n"
        "Estado: vigente al 2026-08-12.\r\n"
    )
    source["normalized_text"] = source_text
    source["content_hash"] = hashlib.sha256(source_text.encode("utf-8")).hexdigest()
    source["language"] = "es"
    payload.update(
        {
            "schema_version": "1.1",
            "build_binding": {
                "commit": "a" * 40,
                "archive_sha256": "b" * 64,
            },
            "language_treatments": [
                {
                    "source_ids": [source["source_id"]],
                    "method": "Revisión bilingüe del texto oficial.",
                    "rationale": "La traducción conserva la obligación jurídica.",
                    "limitations": "La terminología técnica sigue en español.",
                }
            ],
        }
    )
    return payload


def _qualification_judgment_payload(
    request_fingerprint: str,
    *,
    failed_currentness: bool = False,
) -> dict[str, Any]:
    payload = copy.deepcopy(_scripted_payloads()[0]["payload"])
    payload["request_fingerprint"] = request_fingerprint
    if failed_currentness:
        check = next(
            item for item in payload["checks"] if item["code"] == "CURRENTNESS_EVIDENCE"
        )
        check["satisfied"] = False
        check["source_ids"] = []
        check["rationale"] = "No retained status source supports the declared date."
    return cast(dict[str, Any], payload)


def _qualification_response_payload(
    request_fingerprint: str,
    *,
    judge_isolation: str = "fresh_context",
    include_optional_fields: bool = True,
) -> dict[str, Any]:
    response: dict[str, Any] = {
        "schema_version": "1.0",
        "operation": "admit_case",
        "request_fingerprint": request_fingerprint,
        "provider_name": "fictional-provider",
        "model_name": "fictional-model",
        "judge_isolation": judge_isolation,
        "payload": _qualification_judgment_payload(request_fingerprint),
    }
    if include_optional_fields:
        response.update(
            {
                "response_id": "fictional-response-1",
                "usage": {"input_tokens": 101, "output_tokens": 202},
            }
        )
    return response


def _initialize_qualification_pair_from_payload(
    tmp_path: Path,
    payload: dict[str, Any],
) -> tuple[ModuleType, Path, Path, Any, dict[str, Any]]:
    portable = _load_portable()
    core_run = tmp_path / "core-qualification"
    portable_run = tmp_path / "portable-qualification"
    core_state = initialize_qualification_core(
        QualificationCase.model_validate(payload),
        core_run,
        nonce_hex="7" * 64,
    )
    portable_state = portable.initialize_case_qualification(
        payload,
        portable_run,
        nonce_hex="7" * 64,
    )
    assert portable_state == core_state.model_dump(mode="json")
    core_request = next_qualification_core(core_run)
    portable_request = portable.next_qualification_request(portable_run)
    assert core_request is not None and portable_request is not None
    assert portable_request == core_request.model_dump(mode="json")
    assert _tree_bytes(portable_run) == _tree_bytes(core_run)
    return portable, core_run, portable_run, core_request, portable_request


def _initialize_qualification_pair(
    tmp_path: Path,
) -> tuple[ModuleType, Path, Path, Any, dict[str, Any]]:
    portable = _load_portable()
    payload = _qualification_payload()
    core_run = tmp_path / "core-qualification"
    portable_run = tmp_path / "portable-qualification"
    core_state = initialize_qualification_core(
        QualificationCase.model_validate(payload),
        core_run,
        nonce_hex="7" * 64,
    )
    portable_state = portable.initialize_case_qualification(
        payload,
        portable_run,
        nonce_hex="7" * 64,
    )
    assert portable_state == core_state.model_dump(mode="json")
    core_request = next_qualification_core(core_run)
    portable_request = portable.next_qualification_request(portable_run)
    assert core_request is not None and portable_request is not None
    assert portable_request == core_request.model_dump(mode="json")
    assert _tree_bytes(portable_run) == _tree_bytes(core_run)
    return portable, core_run, portable_run, core_request, portable_request


def test_portable_candidate_free_qualification_matches_full_bytes_and_roots(
    tmp_path: Path,
) -> None:
    portable = _load_portable()
    payload = _qualification_payload()
    core_run = tmp_path / "core-qualification"
    portable_run = tmp_path / "portable-qualification"
    core_case = QualificationCase.model_validate(payload)

    core_state = initialize_qualification_core(
        core_case,
        core_run,
        nonce_hex="7" * 64,
    )
    portable_state = portable.initialize_case_qualification(
        payload,
        portable_run,
        nonce_hex="7" * 64,
    )
    assert portable_state == core_state.model_dump(mode="json")
    assert _tree_bytes(portable_run) == _tree_bytes(core_run)

    core_request = next_qualification_core(core_run)
    portable_request = portable.next_qualification_request(portable_run)
    assert core_request is not None and portable_request is not None
    assert portable_request == core_request.model_dump(mode="json")
    assert "candidates" not in portable_request["payload"]
    assert "client_facts" not in portable_request["payload"]

    malformed = {"request_fingerprint": "not-a-hash", "checks": []}
    before = _tree_bytes(core_run)
    core_preflight = preflight_qualification_core(core_run, malformed)
    portable_preflight = portable.preflight_case_qualification(portable_run, malformed)
    assert portable_preflight == core_preflight.model_dump(mode="json")
    core_guarded = guarded_submit_qualification_core(core_run, malformed)
    portable_guarded = portable.guarded_submit_case_qualification(
        portable_run,
        malformed,
    )
    assert portable_guarded == core_guarded.model_dump(mode="json")
    assert _tree_bytes(core_run) == before
    assert _tree_bytes(portable_run) == before

    judgment_payload = copy.deepcopy(_scripted_payloads()[0]["payload"])
    judgment_payload["request_fingerprint"] = core_request.request_fingerprint
    core_receipt = submit_qualification_core(
        core_run,
        CaseAdmissionJudgment.model_validate(judgment_payload),
    )
    portable_receipt = portable.submit_case_qualification(
        portable_run,
        judgment_payload,
    )
    assert portable_receipt == core_receipt.model_dump(mode="json")
    assert _tree_bytes(portable_run) == _tree_bytes(core_run)
    assert portable.resume_case_qualification(portable_run) == (
        resume_qualification_core(core_run).model_dump(mode="json")
    )
    portable_verification = portable.verify_case_qualification(portable_run)
    core_verification = verify_qualification_core(core_run)
    assert portable_verification == core_verification.model_dump(mode="json")


def test_portable_qualification_case_invalid_matches_full_artifacts_and_root(
    tmp_path: Path,
) -> None:
    portable, core_run, portable_run, core_request, portable_request = (
        _initialize_qualification_pair(tmp_path)
    )
    core_payload = _qualification_judgment_payload(
        core_request.request_fingerprint,
        failed_currentness=True,
    )
    portable_payload = _qualification_judgment_payload(
        cast(str, portable_request["request_fingerprint"]),
        failed_currentness=True,
    )

    core_receipt = submit_qualification_core(
        core_run,
        CaseAdmissionJudgment.model_validate(core_payload),
    )
    portable_receipt = portable.submit_case_qualification(
        portable_run,
        portable_payload,
    )

    assert core_receipt.readiness.status.value == "CASE_INVALID"
    assert portable_receipt == core_receipt.model_dump(mode="json")
    assert _tree_bytes(portable_run) == _tree_bytes(core_run)
    assert portable.resume_case_qualification(portable_run) == (
        resume_qualification_core(core_run).model_dump(mode="json")
    )
    assert portable.verify_case_qualification(portable_run) == (
        verify_qualification_core(core_run).model_dump(mode="json")
    )


def test_portable_current_law_qualification_requires_objective_currentness_metadata(
    tmp_path: Path,
) -> None:
    portable = _load_portable()
    payload = _qualification_payload()
    payload["mode"] = "current-law"
    for source in payload["sources"]:
        source["version"] = None
        source["effective_date"] = None
        source["supersession"] = None
    payload["sources"][-1]["source_role"] = "commentary_analysis"
    payload["sources"][-1]["version"] = "2026 commentary edition"
    core_run = tmp_path / "core-currentness-minimum"
    portable_run = tmp_path / "portable-currentness-minimum"
    initialize_qualification_core(
        QualificationCase.model_validate(payload),
        core_run,
        nonce_hex="7" * 64,
    )
    portable.initialize_case_qualification(
        payload,
        portable_run,
        nonce_hex="7" * 64,
    )
    core_request = next_qualification_core(core_run)
    portable_request = portable.next_qualification_request(portable_run)
    assert core_request is not None and portable_request is not None
    core_payload = _qualification_judgment_payload(core_request.request_fingerprint)
    portable_payload = _qualification_judgment_payload(
        cast(str, portable_request["request_fingerprint"])
    )

    core_receipt = submit_qualification_core(
        core_run,
        CaseAdmissionJudgment.model_validate(core_payload),
    )
    portable_receipt = portable.submit_case_qualification(
        portable_run,
        portable_payload,
    )

    assert core_receipt.readiness.status.value == "CASE_INVALID"
    assert core_receipt.readiness.issue_codes == ["CURRENTNESS_EVIDENCE_INSUFFICIENT"]
    assert portable_receipt == core_receipt.model_dump(mode="json")
    assert _tree_bytes(portable_run) == _tree_bytes(core_run)
    assert portable.resume_case_qualification(portable_run) == (
        resume_qualification_core(core_run).model_dump(mode="json")
    )
    assert portable.verify_case_qualification(portable_run) == (
        verify_qualification_core(core_run).model_dump(mode="json")
    )


@pytest.mark.parametrize(
    ("vector", "expected_code"),
    [
        ("request-mismatch", "EVALUATION_RESPONSE_REQUEST_MISMATCH"),
        ("semantic-rejection", "EVALUATION_RESPONSE_SEMANTIC_INVALID"),
    ],
)
def test_portable_qualification_refusal_vectors_match_full_without_mutation(
    tmp_path: Path,
    vector: str,
    expected_code: str,
) -> None:
    portable, core_run, portable_run, core_request, _ = _initialize_qualification_pair(
        tmp_path
    )
    payload = _qualification_judgment_payload(core_request.request_fingerprint)
    if vector == "request-mismatch":
        payload["request_fingerprint"] = "8" * 64
    else:
        payload["checks"] = payload["checks"][:-1]
    before = _tree_bytes(core_run)

    core_preflight = preflight_qualification_core(core_run, payload)
    portable_preflight = portable.preflight_case_qualification(portable_run, payload)
    core_guarded = guarded_submit_qualification_core(core_run, payload)
    portable_guarded = portable.guarded_submit_case_qualification(
        portable_run,
        payload,
    )

    assert [issue.code for issue in core_preflight.issues] == [expected_code]
    assert portable_preflight == core_preflight.model_dump(mode="json")
    assert portable_guarded == core_guarded.model_dump(mode="json")
    assert _tree_bytes(core_run) == before
    assert _tree_bytes(portable_run) == before
    assert portable.resume_case_qualification(portable_run) == (
        resume_qualification_core(core_run).model_dump(mode="json")
    )
    assert portable.verify_case_qualification(portable_run) == (
        verify_qualification_core(core_run).model_dump(mode="json")
    )


def test_portable_qualification_terminal_refusal_matches_full_without_mutation(
    tmp_path: Path,
) -> None:
    portable, core_run, portable_run, core_request, _ = _initialize_qualification_pair(
        tmp_path
    )
    payload = _qualification_judgment_payload(core_request.request_fingerprint)
    submit_qualification_core(
        core_run,
        CaseAdmissionJudgment.model_validate(payload),
    )
    portable.submit_case_qualification(portable_run, payload)
    sealed = _tree_bytes(core_run)

    core_preflight = preflight_qualification_core(core_run, payload)
    portable_preflight = portable.preflight_case_qualification(portable_run, payload)
    core_guarded = guarded_submit_qualification_core(core_run, payload)
    portable_guarded = portable.guarded_submit_case_qualification(portable_run, payload)

    assert [issue.code for issue in core_preflight.issues] == [
        "EVALUATION_NO_PENDING_REQUEST"
    ]
    assert portable_preflight == core_preflight.model_dump(mode="json")
    assert portable_guarded == core_guarded.model_dump(mode="json")
    with pytest.raises(attorney_artifacts.EvaluationIntegrityError):
        submit_qualification_core(
            core_run,
            CaseAdmissionJudgment.model_validate(payload),
        )
    with pytest.raises(portable.EvaluationIntegrityError):
        portable.submit_case_qualification(portable_run, payload)
    assert _tree_bytes(core_run) == sealed
    assert _tree_bytes(portable_run) == sealed
    assert portable.resume_case_qualification(portable_run) == (
        resume_qualification_core(core_run).model_dump(mode="json")
    )
    assert portable.verify_case_qualification(portable_run) == (
        verify_qualification_core(core_run).model_dump(mode="json")
    )


@pytest.mark.parametrize("tamper", ["artifact", "empty-directory", "symlink"])
def test_portable_qualification_tamper_verification_matches_full(
    tmp_path: Path,
    tamper: str,
) -> None:
    portable, core_run, portable_run, _, _ = _initialize_qualification_pair(tmp_path)
    if tamper == "artifact":
        for run in (core_run, portable_run):
            case_path = run / "qualification-case.json"
            case_value = json.loads(case_path.read_text(encoding="utf-8"))
            case_value["question"] = "Tampered question?"
            case_path.write_bytes(canonical_json_bytes(case_value))
    elif tamper == "empty-directory":
        (core_run / "unexpected-empty-directory").mkdir()
        (portable_run / "unexpected-empty-directory").mkdir()
    else:
        core_target = tmp_path / "core-symlink-target"
        portable_target = tmp_path / "portable-symlink-target"
        core_target.mkdir()
        portable_target.mkdir()
        (core_run / "unexpected-link").symlink_to(
            core_target,
            target_is_directory=True,
        )
        (portable_run / "unexpected-link").symlink_to(
            portable_target,
            target_is_directory=True,
        )

    core_verification = verify_qualification_core(core_run)
    portable_verification = portable.verify_case_qualification(portable_run)

    assert core_verification.valid is False
    assert portable_verification == core_verification.model_dump(mode="json")


def test_portable_nonempty_qualification_refusal_preserves_mode_and_stat(
    tmp_path: Path,
) -> None:
    portable = _load_portable()
    payload = _qualification_payload()
    runs = [tmp_path / "core-nonempty", tmp_path / "portable-nonempty"]
    before: dict[Path, tuple[int, int, int, int, int, int]] = {}
    for run in runs:
        run.mkdir(mode=0o755)
        run.chmod(0o755)
        (run / "owned.txt").write_text("owned\n", encoding="utf-8")
        metadata = run.stat()
        before[run] = (
            stat.S_IMODE(metadata.st_mode),
            metadata.st_uid,
            metadata.st_gid,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )

    with pytest.raises(attorney_artifacts.EvaluationIntegrityError, match="must be empty"):
        initialize_qualification_core(
            QualificationCase.model_validate(payload),
            runs[0],
            nonce_hex="9" * 64,
        )
    with pytest.raises(portable.EvaluationIntegrityError, match="must be empty"):
        portable.initialize_case_qualification(
            payload,
            runs[1],
            nonce_hex="9" * 64,
        )

    for run in runs:
        metadata = run.stat()
        assert (
            stat.S_IMODE(metadata.st_mode),
            metadata.st_uid,
            metadata.st_gid,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        ) == before[run]
        assert _tree_bytes(run) == {"owned.txt": b"owned\n"}


def test_portable_qualification_receipt_builder_rejects_inconclusive_readiness() -> None:
    portable = _load_portable()
    readiness = {
        "status": "INCONCLUSIVE",
        "case_fingerprint": "1" * 64,
        "judgment_fingerprint": "2" * 64,
        "issue_codes": ["JUDGE_UNAVAILABLE"],
        "rationale": "No terminal source qualification was reached.",
    }

    with pytest.raises(portable.EvaluationIntegrityError, match="status is invalid"):
        portable._qualification_receipt(
            case_fingerprint="1" * 64,
            source_record_fingerprint="3" * 64,
            request_fingerprint="4" * 64,
            judgment_fingerprint="2" * 64,
            readiness=readiness,
        )


@pytest.mark.parametrize(
    "code",
    [
        "EVALUATION_NO_PENDING_REQUEST",
        "EVALUATION_RESPONSE_REQUEST_MISMATCH",
        "EVALUATION_RESPONSE_SCHEMA_INVALID",
        *(item.value for item in ResponseContractCode),
    ],
)
def test_portable_safe_diagnostic_fixture_covers_every_core_code(
    code: str,
    tmp_path: Path,
) -> None:
    """A wrong code, message, ID normalization, or fingerprint must break byte parity."""
    portable, core_run, _portable_run, core_request, portable_request = (
        _initialize_qualification_pair(tmp_path)
    )
    related_ids = [] if code == "EVALUATION_NO_PENDING_REQUEST" else [
        "z-safe",
        "a-safe",
        "z-safe",
    ]
    issue = EvaluationPreflightIssue(
        code=code,
        message=PREFLIGHT_ISSUE_MESSAGES[code],
        related_ids=related_ids,
    )
    request = None if code == "EVALUATION_NO_PENDING_REQUEST" else core_request
    portable_pending = None if request is None else portable_request

    core_result = qualification_preflight_result_core(request, issue)
    portable_result = portable._preflight_result(
        portable_pending,
        code=code,
        related_ids=tuple(related_ids),
    )

    assert portable.canonical_json_bytes(portable_result) == canonical_json_bytes(
        core_result.model_dump(mode="json")
    )
    assert portable_result["issues"][0]["related_ids"] == (
        [] if request is None else ["a-safe", "z-safe"]
    )
    assert _tree_bytes(core_run)


def test_portable_qualification_safe_diagnostic_rejects_raw_and_validation_bypass(
    tmp_path: Path,
) -> None:
    """Malformed dictionaries and model-construct bypasses must share one safe refusal."""
    portable, core_run, portable_run, core_request, _ = _initialize_qualification_pair(
        tmp_path
    )
    malformed = {
        "request_fingerprint": core_request.request_fingerprint,
        "checks": [{"code": "AUTHORITY_ALIGNMENT", "satisfied": 1, "material": True}],
    }
    bypass = CaseAdmissionJudgment.model_construct(**malformed)
    before = _tree_bytes(core_run)

    core_result = guarded_submit_qualification_core(core_run, bypass)
    portable_result = portable.guarded_submit_case_qualification(portable_run, malformed)

    assert portable_result == core_result.model_dump(mode="json")
    assert portable_result["preflight"]["issues"][0]["code"] == (
        "EVALUATION_RESPONSE_SCHEMA_INVALID"
    )
    assert _tree_bytes(core_run) == before
    assert _tree_bytes(portable_run) == before


@pytest.mark.parametrize(
    ("judge_isolation", "include_optional_fields"),
    [
        ("fresh_context", False),
        ("sequential_same_context", True),
        ("scripted_fixture", True),
    ],
)
def test_portable_qualification_schema_1_1_case_request_and_envelope_parity(
    judge_isolation: str,
    include_optional_fields: bool,
    tmp_path: Path,
) -> None:
    """Any portable projection or envelope-byte drift must fail against the full oracle."""
    payload = _qualification_schema_1_1_payload()
    before_case = copy.deepcopy(payload)
    portable, core_run, portable_run, core_request, portable_request = (
        _initialize_qualification_pair_from_payload(tmp_path, payload)
    )

    assert payload == before_case
    assert portable.validate_qualification_case(payload) == (
        QualificationCase.model_validate(payload).model_dump(mode="json")
    )
    assert "\r\n" in portable_request["payload"]["sources"][0]["normalized_text"]
    assert portable_request["payload"]["language_treatments"] == payload[
        "language_treatments"
    ]
    assert portable_request["payload"]["build_binding"] == payload["build_binding"]
    assert "supplied language treatment and its limitations" in portable_request[
        "system_instructions"
    ]
    assert portable.canonical_json_bytes(portable_request) == canonical_json_bytes(
        core_request.model_dump(mode="json")
    )

    response = _qualification_response_payload(
        core_request.request_fingerprint,
        judge_isolation=judge_isolation,
        include_optional_fields=include_optional_fields,
    )
    before_response = copy.deepcopy(response)
    core_receipt = submit_qualification_core(core_run, response)  # type: ignore[arg-type]
    portable_receipt = portable.submit_case_qualification(portable_run, response)
    expected_response_bytes = canonical_json_bytes(response)

    assert response == before_response
    assert portable_receipt == core_receipt.model_dump(mode="json")
    assert (core_run / "admission-response.json").read_bytes() == expected_response_bytes
    assert (portable_run / "admission-response.json").read_bytes() == expected_response_bytes
    assert portable_receipt["judgment_fingerprint"] == hashlib.sha256(
        canonical_json_bytes(response["payload"])
    ).hexdigest()
    assert _tree_bytes(portable_run) == _tree_bytes(core_run)
    assert portable.resume_case_qualification(portable_run) == (
        resume_qualification_core(core_run).model_dump(mode="json")
    )
    assert portable.verify_case_qualification(portable_run) == (
        verify_qualification_core(core_run).model_dump(mode="json")
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "missing-build-binding",
        "missing-language-treatments",
        "duplicate-treatment",
        "duplicate-after-normalization",
        "unknown-treatment",
        "malformed-commit",
        "malformed-archive",
        "non-string-commit",
        "blank-method",
        "blank-rationale",
        "blank-limitations",
        "legacy-explicit-empty-treatment",
    ],
)
def test_portable_qualification_schema_1_1_invalid_case_vectors_match_full(
    mutation: str,
) -> None:
    """Every schema-directed case refusal must be strict, bounded, and non-mutating."""
    portable = _load_portable()
    payload = _qualification_schema_1_1_payload()
    treatment = payload["language_treatments"][0]
    if mutation == "missing-build-binding":
        payload.pop("build_binding")
    elif mutation == "missing-language-treatments":
        payload.pop("language_treatments")
    elif mutation == "duplicate-treatment":
        payload["language_treatments"].append(copy.deepcopy(treatment))
    elif mutation == "duplicate-after-normalization":
        treatment["source_ids"].append(f"  {treatment['source_ids'][0]}\t")
    elif mutation == "unknown-treatment":
        treatment["source_ids"].append("unknown-source")
    elif mutation == "malformed-commit":
        payload["build_binding"]["commit"] = "A" * 40
    elif mutation == "malformed-archive":
        payload["build_binding"]["archive_sha256"] = "b" * 63
    elif mutation == "non-string-commit":
        payload["build_binding"]["commit"] = True
    elif mutation == "blank-method":
        treatment["method"] = "   "
    elif mutation == "blank-rationale":
        treatment["rationale"] = "\t"
    elif mutation == "blank-limitations":
        treatment["limitations"] = "\n"
    else:
        payload["schema_version"] = "1.0"
        payload.pop("build_binding")
        payload["language_treatments"] = []
    before = copy.deepcopy(payload)

    with pytest.raises((ValidationError, TypeError, ValueError)):
        QualificationCase.model_validate(payload)
    with pytest.raises((portable.PortableEvaluationInputError, TypeError, ValueError)):
        portable.validate_qualification_case(payload)

    assert payload == before


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        ("raw-inner", "EVALUATION_RESPONSE_SCHEMA_INVALID"),
        ("operation", "EVALUATION_RESPONSE_REQUEST_MISMATCH"),
        ("outer-fingerprint", "EVALUATION_RESPONSE_REQUEST_MISMATCH"),
        ("inner-fingerprint", "EVALUATION_RESPONSE_REQUEST_MISMATCH"),
        ("blank-provider", "EVALUATION_RESPONSE_SCHEMA_INVALID"),
        ("blank-model", "EVALUATION_RESPONSE_SCHEMA_INVALID"),
        ("invalid-isolation", "EVALUATION_RESPONSE_SCHEMA_INVALID"),
        ("extra-key", "EVALUATION_RESPONSE_SCHEMA_INVALID"),
        ("usage-string", "EVALUATION_RESPONSE_SCHEMA_INVALID"),
        ("usage-boolean", "EVALUATION_RESPONSE_SCHEMA_INVALID"),
        ("nonfinite-payload", "EVALUATION_RESPONSE_SCHEMA_INVALID"),
        ("response-id-boolean", "EVALUATION_RESPONSE_SCHEMA_INVALID"),
        ("payload-array", "EVALUATION_RESPONSE_SCHEMA_INVALID"),
    ],
)
def test_portable_qualification_schema_1_1_response_refusal_parity_is_write_free(
    mutation: str,
    expected_code: str,
    tmp_path: Path,
) -> None:
    portable, core_run, portable_run, core_request, _ = (
        _initialize_qualification_pair_from_payload(
            tmp_path,
            _qualification_schema_1_1_payload(),
        )
    )
    response: object = _qualification_response_payload(core_request.request_fingerprint)
    assert isinstance(response, dict)
    if mutation == "raw-inner":
        response = response["payload"]
    elif mutation == "operation":
        response["operation"] = "grade_report"
    elif mutation == "outer-fingerprint":
        response["request_fingerprint"] = "0" * 64
    elif mutation == "inner-fingerprint":
        response["payload"]["request_fingerprint"] = "0" * 64
    elif mutation == "blank-provider":
        response["provider_name"] = "   "
    elif mutation == "blank-model":
        response["model_name"] = "\t"
    elif mutation == "invalid-isolation":
        response["judge_isolation"] = "not-isolated"
    elif mutation == "extra-key":
        response["unexpected"] = "forbidden"
    elif mutation == "usage-string":
        response["usage"] = {"input_tokens": "101"}
    elif mutation == "usage-boolean":
        response["usage"] = {"input_tokens": True}
    elif mutation == "nonfinite-payload":
        response["payload"]["checks"][0]["source_ids"] = [float("nan")]
    elif mutation == "response-id-boolean":
        response["response_id"] = False
    else:
        response["payload"] = []
    before_response = copy.deepcopy(response)
    before = _tree_bytes(core_run)

    core_preflight = preflight_qualification_core(core_run, response)
    portable_preflight = portable.preflight_case_qualification(portable_run, response)
    core_guarded = guarded_submit_qualification_core(core_run, response)
    portable_guarded = portable.guarded_submit_case_qualification(portable_run, response)

    assert [issue.code for issue in core_preflight.issues] == [expected_code]
    assert portable_preflight == core_preflight.model_dump(mode="json")
    assert portable_guarded == core_guarded.model_dump(mode="json")
    if mutation == "nonfinite-payload":
        assert math.isnan(response["payload"]["checks"][0]["source_ids"][0])
    else:
        assert response == before_response
    assert _tree_bytes(core_run) == before
    assert _tree_bytes(portable_run) == before


@pytest.mark.parametrize("mutation", ["blank-provider", "unhashable-payload"])
def test_portable_qualification_schema_1_1_model_construct_bypass_matches_raw_mapping(
    mutation: str,
    tmp_path: Path,
) -> None:
    portable, core_run, portable_run, core_request, _ = (
        _initialize_qualification_pair_from_payload(
            tmp_path,
            _qualification_schema_1_1_payload(),
        )
    )
    raw = _qualification_response_payload(core_request.request_fingerprint)
    if mutation == "blank-provider":
        raw["provider_name"] = "   "
    else:
        raw["payload"]["checks"][0]["source_ids"] = [["not-an-identifier"]]
    bypass = JudgeResponse.model_construct(**raw)
    before = _tree_bytes(core_run)

    core_guarded = guarded_submit_qualification_core(core_run, bypass)
    portable_guarded = portable.guarded_submit_case_qualification(portable_run, raw)

    assert portable_guarded == core_guarded.model_dump(mode="json")
    assert portable_guarded["preflight"]["issues"][0]["code"] == (
        "EVALUATION_RESPONSE_SCHEMA_INVALID"
    )
    assert _tree_bytes(core_run) == before
    assert _tree_bytes(portable_run) == before


@pytest.mark.parametrize("shape", ["too-deep", "list-cycle", "dict-cycle"])
def test_portable_qualification_schema_1_1_depth_and_cycle_diagnostics_are_bounded(
    shape: str,
    tmp_path: Path,
) -> None:
    portable, core_run, portable_run, core_request, _ = (
        _initialize_qualification_pair_from_payload(
            tmp_path,
            _qualification_schema_1_1_payload(),
        )
    )
    raw = _qualification_response_payload(core_request.request_fingerprint)
    if shape == "too-deep":
        nested: object = []
        for _ in range(2048):
            nested = [nested]
    elif shape == "list-cycle":
        nested = []
        nested.append(nested)
    else:
        nested = {}
        nested["self"] = nested
    raw["payload"]["checks"][0]["source_ids"] = nested
    bypass = JudgeResponse.model_construct(**raw)
    before = _tree_bytes(core_run)

    core_preflight = preflight_qualification_core(core_run, bypass)
    portable_preflight = portable.preflight_case_qualification(portable_run, raw)

    assert portable_preflight == core_preflight.model_dump(mode="json")
    assert portable_preflight["issues"][0]["code"] == (
        "EVALUATION_RESPONSE_SCHEMA_INVALID"
    )
    assert _tree_bytes(core_run) == before
    assert _tree_bytes(portable_run) == before


@pytest.mark.parametrize(
    ("artifact", "path", "replacement"),
    [
        ("admission-response.json", ("provider_name",), "tampered-provider"),
        ("admission-response.json", ("model_name",), "tampered-model"),
        ("admission-response.json", ("judge_isolation",), "scripted_fixture"),
        ("admission-response.json", ("usage", "input_tokens"), 999),
        ("admission-response.json", ("payload", "request_fingerprint"), "0" * 64),
        ("qualification-case.json", ("build_binding", "commit"), "c" * 40),
        (
            "qualification-case.json",
            ("language_treatments", 0, "limitations"),
            "Tampered limitation.",
        ),
    ],
)
def test_portable_qualification_schema_1_1_tamper_verification_matches_full(
    artifact: str,
    path: tuple[str | int, ...],
    replacement: object,
    tmp_path: Path,
) -> None:
    portable, core_run, portable_run, core_request, _ = (
        _initialize_qualification_pair_from_payload(
            tmp_path,
            _qualification_schema_1_1_payload(),
        )
    )
    response = _qualification_response_payload(core_request.request_fingerprint)
    submit_qualification_core(core_run, response)  # type: ignore[arg-type]
    portable.submit_case_qualification(portable_run, response)
    for run in (core_run, portable_run):
        artifact_path = run / artifact
        value = json.loads(artifact_path.read_bytes())
        target = value
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = replacement
        artifact_path.write_bytes(canonical_json_bytes(value))

    assert portable.verify_case_qualification(portable_run) == (
        verify_qualification_core(core_run).model_dump(mode="json")
    ) == {
        "valid": False,
        "issues": ["QUALIFICATION_INTEGRITY_INVALID"],
        "root_hash": None,
    }


def test_portable_qualification_legacy_1_0_frozen_replay_bytes_are_unchanged(
    tmp_path: Path,
) -> None:
    portable, core_run, portable_run, core_request, _ = _initialize_qualification_pair(
        tmp_path
    )
    judgment = _qualification_judgment_payload(core_request.request_fingerprint)
    core_receipt = submit_qualification_core(
        core_run,
        CaseAdmissionJudgment.model_validate(judgment),
    )
    portable_receipt = portable.submit_case_qualification(portable_run, judgment)

    expected_hashes = {
        "qualification-case.json": (
            "939722d649e99c104e54ac1fd5da339b3fbbfd51c1c142963f61927123e715b4"
        ),
        "admission-request.json": (
            "d27f773b799bfc0197254e375cc7c0ed1c99dc575f00f538d80339114e80a792"
        ),
        "admission-response.json": (
            "e265b2ef3a0a5917aa739f130a11527a87e871bd48a3229ed7f0a030ab7830c7"
        ),
        "qualification-receipt.json": (
            "86036d485f3700b0cc92a15d8e149c5b6986761d42917a9d870c8bbf8c813be0"
        ),
        "manifest.json": "b5f27fbb7513e7297bc60839752aeda99639a14ce48b293c9080b7db8b1e7728",
    }
    assert portable_receipt == core_receipt.model_dump(mode="json")
    assert {
        name: hashlib.sha256((portable_run / name).read_bytes()).hexdigest()
        for name in expected_hashes
    } == expected_hashes
    assert _tree_bytes(portable_run) == _tree_bytes(core_run)
    assert portable.resume_case_qualification(portable_run)["root_hash"] == (
        "3c8d8ec61ac301e8921dd16fe9ea2817f098306b6b79a271662cde8e8ff27ce3"
    )
    assert portable.verify_case_qualification(portable_run) == (
        verify_qualification_core(core_run).model_dump(mode="json")
    )


def _advance_portable_to_first_grade(module: ModuleType, run: Path) -> dict[str, Any]:
    module.initialize_evaluation(_case_payload(), run, seed_hex="0" * 64)
    for index, item in enumerate(_scripted_payloads()[:3], start=1):
        request = module.next_judge_request(run)
        assert request is not None
        module.submit_judge_response(run, _response(request, item, index))
    request = module.next_judge_request(run)
    assert request is not None and request["operation"] == "grade_report"
    return cast(dict[str, Any], request)


def _grade_with_evidence(
    portable: ModuleType,
    envelope: dict[str, Any],
    sealed: dict[str, Any],
    *,
    response_index: int = 3,
) -> dict[str, Any]:
    grade = copy.deepcopy(_scripted_payloads()[response_index]["payload"])
    grade["schema_version"] = "1.3"
    report = portable._candidate_for_label(envelope, grade["anonymous_label"])[
        "report_text"
    ].strip()
    for entry in grade["entry_grades"]:
        entry["report_passage"] = None if entry["disposition"] == "MISSING" else report
    for narrative in grade["narrative_scores"]:
        narrative["report_passage"] = report
    source_record = portable.build_admission_packet(envelope)["payload"]
    source = source_record["sources"][0]
    evidence_quote = "civil penalty of $500"
    start = source["normalized_text"].index(evidence_quote)
    grade["out_of_ledger_claims"] = [
        {
            "claim_id": "civil-penalty-claim",
            "claim_text": "civil penalty of $500",
            "report_location": "paragraph 1",
            "disposition": "COMPLETE",
            "category": "penalty",
            "materiality": "material",
            "related_ledger_ids": ["civil-penalty"],
            "rationale": "The report states the penalty and the source record supports it.",
            "source_record_fingerprint": source_record["source_record_fingerprint"],
            "evidence_basis": "source_spans",
            "evidence_spans": [
                {
                    "source_id": source["source_id"],
                    "start_char": start,
                    "end_char": start + len(evidence_quote),
                    "quote": evidence_quote,
                }
            ],
        }
    ]
    grade["ledger_fingerprint"] = sealed["ledger_fingerprint"]
    return cast(dict[str, Any], grade)


def _portable_comparison_fixture(portable: ModuleType) -> dict[str, Any]:
    """Build two real source-bearing portable scores and their immutable inputs."""
    envelope = portable.freeze_case(_case_payload(), seed_hex="0" * 64)
    responses = _scripted_payloads()
    sealed = portable.seal_ledger(
        envelope,
        responses[1]["payload"],
        responses[2]["payload"],
        None,
    )
    first_a = _grade_with_evidence(portable, envelope, sealed)
    second_a = copy.deepcopy(first_a)
    second_a["request_fingerprint"] = "f" * 64
    first_b = copy.deepcopy(first_a)
    first_b["anonymous_label"] = "B"
    first_b["request_fingerprint"] = "b" * 64
    first_b["narrative_scores"][0]["score"] = 3
    second_b = copy.deepcopy(first_b)
    second_b["request_fingerprint"] = "c" * 64
    resolved_a = portable.resolve_grades(sealed, first_a, second_a)
    resolved_b = portable.resolve_grades(sealed, first_b, second_b)
    checks_a = portable._derive_deterministic_checks(
        portable._candidate_for_label(envelope, "A"), "A"
    )
    checks_b = copy.deepcopy(checks_a)
    checks_b["anonymous_label"] = "B"
    source_record = portable.build_admission_packet(envelope)["payload"]

    def inputs(label: str, resolved: dict[str, Any], checks: dict[str, Any]) -> dict[str, Any]:
        return {
            "schema_version": "1.4",
            "anonymous_label": label,
            "sealed_ledger": copy.deepcopy(sealed),
            "resolved_grade": {"schema_version": "1.3", **copy.deepcopy(resolved)},
            "deterministic_checks": copy.deepcopy(checks),
            "rubric": copy.deepcopy(portable.RUBRIC_V1),
            "source_record": copy.deepcopy(source_record),
        }

    candidate_inputs = inputs("A", resolved_a, checks_a)
    comparator_inputs = inputs("B", resolved_b, checks_b)
    return {
        "envelope": envelope,
        "candidate": portable.score_report(
            sealed,
            resolved_a,
            checks_a,
            source_record=source_record,
        ),
        "comparator": portable.score_report(
            sealed,
            resolved_b,
            checks_b,
            source_record=source_record,
        ),
        "candidate_inputs": candidate_inputs,
        "comparator_inputs": comparator_inputs,
    }


def _rebind_portable_resolution_fingerprint(
    portable: ModuleType,
    score_inputs: dict[str, Any],
) -> None:
    resolved = score_inputs["resolved_grade"]
    payload = {
        key: resolved[key]
        for key in (
            "grade",
            "audit",
            "original_grader_1",
            "original_grader_2",
            "referee_decisions",
        )
    }
    resolved["resolution_fingerprint"] = hashlib.sha256(
        portable.canonical_json_bytes(payload)
    ).hexdigest()


def _run_core(run: Path) -> None:
    case = _case_from_fixture(FIXTURE / "case.json", root=FIXTURE)
    initialize_core(case, run, seed_hex="0" * 64)
    scripted = _scripted_payloads()
    for index, item in enumerate(scripted, start=1):
        request = next_core(run)
        assert request is not None
        response = JudgeResponse.model_validate(
            _response(request.model_dump(mode="json"), item, index)
        )
        submit_core(run, response)


def _differential_payload(
    request: dict[str, Any], grade_counts: dict[str, int], *, hostile: bool = False
) -> dict[str, Any]:
    scripted = _scripted_payloads()
    operation = request["operation"]
    if operation == "admit_case":
        payload = cast(dict[str, Any], copy.deepcopy(scripted[0]["payload"]))
        payload["request_fingerprint"] = request["request_fingerprint"]
        return payload
    if operation == "build_ledger":
        payload = cast(dict[str, Any], copy.deepcopy(scripted[1]["payload"]))
        payload["case_fingerprint"] = request["safe_metadata"]["source_record_fingerprint"]
        if hostile:
            entry = payload["entries"][0]
            source_text = request["payload"]["source_record"]["sources"][0]["normalized_text"]
            entry["proposition"] = (
                "<img src=x onerror=alert(1)> | slash \\ cr\r lf\n tab\t "
                "bell\x07 c1\x85 entity &lt; source <br>"
            )
            entry["citations"] = [
                {
                    "source_id": "synthetic-rule-1-source",
                    "start_char": 0,
                    "end_char": 4,
                    "quote": source_text[0:4],
                },
                {
                    "source_id": "synthetic-rule-1-source",
                    "start_char": 5,
                    "end_char": 7,
                    "quote": source_text[5:7],
                },
            ]
        return payload
    if operation == "audit_ledger":
        payload = cast(dict[str, Any], copy.deepcopy(scripted[2]["payload"]))
        payload["request_fingerprint"] = request["request_fingerprint"]
        return payload
    if operation == "grade_report":
        label = request["safe_metadata"]["anonymous_label"]
        grade_counts[label] = grade_counts.get(label, 0) + 1
        payload = cast(
            dict[str, Any],
            copy.deepcopy(scripted[3 if grade_counts[label] == 1 else 4]["payload"]),
        )
        payload["request_fingerprint"] = request["request_fingerprint"]
        payload["anonymous_label"] = label
        payload["ledger_fingerprint"] = request["safe_metadata"]["legal_ledger_fingerprint"]
        if hostile:
            finding = payload["entry_grades"][0]
            finding.update(
                {
                    "disposition": "MISSING",
                    "report_location": None,
                    "finding_codes": ["CRITICAL_LEDGER_ENTRY_MISSING"],
                    "rationale": "why | because\\yes\r\nthen\tend\x7f &amp; <br>",
                }
            )
        return payload
    raise AssertionError(f"unexpected operation in differential fixture: {operation}")


def _run_differential(
    portable: ModuleType,
    case_payload: dict[str, Any],
    portable_run: Path,
    core_run: Path,
    *,
    hostile: bool = False,
) -> None:
    portable.initialize_evaluation(case_payload, portable_run, seed_hex="0" * 64)
    initialize_core(_core_case_from_payload(case_payload), core_run, seed_hex="0" * 64)
    grade_counts: dict[str, int] = {}
    response_number = 0
    while True:
        portable_request = portable.next_judge_request(portable_run)
        core_request = next_core(core_run)
        if portable_request is None or core_request is None:
            assert portable_request is None and core_request is None
            break
        assert portable.canonical_json_bytes(portable_request) == portable.canonical_json_bytes(
            core_request.model_dump(mode="json")
        )
        payload = _differential_payload(portable_request, grade_counts, hostile=hostile)
        response_number += 1
        response = _response(portable_request, {"payload": payload}, response_number)
        assert response["schema_version"] == "1.0"
        portable.submit_judge_response(portable_run, response)
        submit_core(core_run, JudgeResponse.model_validate(response))


def _rehash_manifest_artifact(portable: ModuleType, run: Path, artifact: str) -> None:
    manifest_path = run / "run-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    record = next(item for item in manifest["artifacts"] if item["artifact_path"] == artifact)
    record["artifact_hash"] = hashlib.sha256((run / artifact).read_bytes()).hexdigest()
    manifest["artifact_inventory_fingerprint"] = hashlib.sha256(
        portable.canonical_json_bytes(manifest["artifacts"])
    ).hexdigest()
    manifest["manifest_fingerprint"] = "0" * 64
    manifest["manifest_fingerprint"] = portable._model_fingerprint(
        manifest, exclude={"manifest_fingerprint"}
    )
    manifest_path.write_bytes(portable.canonical_json_bytes(manifest))


def _rehash_completed_response(portable: ModuleType, run: Path, artifact: str) -> None:
    manifest_path = run / "run-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    digest = hashlib.sha256((run / artifact).read_bytes()).hexdigest()
    call = next(
        item
        for item in manifest["judge_calls"]
        if item["response_artifact_path"] == artifact
    )
    call["response_fingerprint"] = digest
    record = next(item for item in manifest["artifacts"] if item["artifact_path"] == artifact)
    record["artifact_hash"] = digest
    manifest["artifact_inventory_fingerprint"] = hashlib.sha256(
        portable.canonical_json_bytes(manifest["artifacts"])
    ).hexdigest()
    manifest["manifest_fingerprint"] = "0" * 64
    manifest["manifest_fingerprint"] = portable._model_fingerprint(
        manifest, exclude={"manifest_fingerprint"}
    )
    manifest_path.write_bytes(portable.canonical_json_bytes(manifest))


def _rewrite_portable_history_artifacts(
    portable: ModuleType,
    run: Path,
    replacements: dict[str, bytes],
) -> None:
    """Rebind hashes so semantic replay evaluates self-consistent mutations."""
    for artifact_path, artifact_bytes in replacements.items():
        (run / artifact_path).write_bytes(artifact_bytes)
    manifest_path = run / "run-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for record in manifest["artifacts"]:
        artifact_path = record["artifact_path"]
        if artifact_path in replacements:
            record["artifact_hash"] = hashlib.sha256(replacements[artifact_path]).hexdigest()
    for call in manifest["judge_calls"]:
        response_path = call["response_artifact_path"]
        if response_path in replacements:
            call["response_fingerprint"] = hashlib.sha256(
                replacements[response_path]
            ).hexdigest()
        request_path = call["request_artifact_path"]
        if request_path in replacements:
            request = json.loads(replacements[request_path])
            call["request_fingerprint"] = request["request_fingerprint"]
            call["prompt_fingerprint"] = portable._prompt_fingerprint(request)
    manifest["artifact_inventory_fingerprint"] = hashlib.sha256(
        portable.canonical_json_bytes(manifest["artifacts"])
    ).hexdigest()
    manifest["manifest_fingerprint"] = "0" * 64
    manifest["manifest_fingerprint"] = portable._model_fingerprint(
        manifest,
        exclude={"manifest_fingerprint"},
    )
    manifest_path.write_bytes(portable.canonical_json_bytes(manifest))


def _refingerprint_result(portable: ModuleType, result: dict[str, Any]) -> None:
    for report in result["reports"]:
        report["score_fingerprint"] = "0" * 64
        report["score_fingerprint"] = portable._model_fingerprint(
            report, exclude={"score_fingerprint"}
        )
    result["result_fingerprint"] = "0" * 64
    result["result_fingerprint"] = portable._model_fingerprint(
        result, exclude={"result_fingerprint"}
    )


def _render_core_result_payload(payload: dict[str, Any]) -> str:
    result = attorney_artifacts._load_model_bytes(
        canonical_json_bytes(payload),
        AttorneyEvaluationResult,
        location="evaluation-result.json",
    )
    return attorney_artifacts.render_evaluation_report(result)


def test_import_is_standard_library_only_under_isolated_python() -> None:
    code = f"""
import importlib.util
import sys
spec = importlib.util.spec_from_file_location('portable', {str(SCRIPT)!r})
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
assert not (set(sys.modules) & {{'pydantic', 'regulatory_harvest'}})
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", code],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_canonical_json_rejects_nonordinary_and_noncanonical_values() -> None:
    portable = _load_portable()
    assert portable.canonical_json_bytes({"z": 1, "a": "é"}) == b'{"a":"\xc3\xa9","z":1}'
    with pytest.raises(portable.EvaluationIntegrityError, match="non-finite"):
        portable.canonical_json_bytes({"value": float("nan")})
    with pytest.raises(portable.EvaluationIntegrityError, match="non-string key"):
        portable.canonical_json_bytes({1: "not ordinary"})
    with pytest.raises(portable.EvaluationIntegrityError, match="not canonical JSON"):
        portable.parse_canonical_json_bytes(b'{"z":1, "a":2}', location="fixture")


def test_case_validation_is_strict_typed_and_does_not_coerce() -> None:
    portable = _load_portable()
    case = _case_payload()
    assert portable.validate_case(case) == case
    malformed = copy.deepcopy(case)
    malformed["sources"][0]["relationship_ids"] = [1]
    with pytest.raises(portable.PortableEvaluationInputError):
        portable.validate_case(malformed)
    extra = copy.deepcopy(case)
    extra["private_answer_key"] = {"A": "candidate"}
    with pytest.raises(portable.PortableEvaluationInputError):
        portable.validate_case(extra)


@pytest.mark.parametrize(
    "exact_text",
    ["  Exact text  ", "Exact text\n", "Exact text\r\n", "\ufeffExact text"],
)
def test_portable_case_validation_preserves_exact_content_like_core(exact_text: str) -> None:
    """Portable validation must not normalize a byte-equivalent content field."""
    portable = _load_portable()
    case = _case_payload()
    content_hash = hashlib.sha256(exact_text.encode("utf-8")).hexdigest()
    case["sources"][0].update(normalized_text=exact_text, content_hash=content_hash)
    case["candidates"][0].update(report_text=exact_text, report_hash=content_hash)
    case["client_facts"] = exact_text

    portable_case = portable.validate_case(case)
    core_case = _core_case_from_payload(case).model_dump(mode="json")

    assert portable_case == core_case
    assert portable_case["sources"][0]["normalized_text"] == exact_text
    assert portable_case["candidates"][0]["report_text"] == exact_text
    assert portable_case["client_facts"] == exact_text


@pytest.mark.parametrize("blank_text", ["", " \r\n\t", "\ufeff", "\ufeff \r\n"])
def test_portable_case_validation_rejects_semantically_blank_content_like_core(
    blank_text: str,
) -> None:
    """Exact-byte handling must keep the full and portable nonblank boundary identical."""
    portable = _load_portable()
    case = _case_payload()
    content_hash = hashlib.sha256(blank_text.encode("utf-8")).hexdigest()
    case["sources"][0].update(normalized_text=blank_text, content_hash=content_hash)

    with pytest.raises(portable.PortableEvaluationInputError):
        portable.validate_case(case)
    with pytest.raises(ValidationError):
        _core_case_from_payload(case)


def test_role_packets_preserve_source_and_report_noninterference(tmp_path: Path) -> None:
    portable = _load_portable()
    run = tmp_path / "run"
    portable.initialize_evaluation(_case_payload(), run, seed_hex="0" * 64)
    admission = portable.next_judge_request(run)
    assert admission is not None
    serialized = json.dumps(admission, sort_keys=True).casefold()
    assert "report_text" not in serialized
    assert "synthetic-harvest" not in serialized
    assert "assignments" not in serialized

    scripted = _scripted_payloads()
    for index, item in enumerate(scripted[:3], start=1):
        request = portable.next_judge_request(run)
        assert request is not None
        assert request["operation"] == item["operation"]
        source_packet = json.dumps(request, sort_keys=True).casefold()
        assert "report_text" not in source_packet
        assert "synthetic-harvest" not in source_packet
        portable.submit_judge_response(run, _response(request, item, index))

    grade = portable.next_judge_request(run)
    assert grade is not None and grade["operation"] == "grade_report"
    assert grade["payload"]["anonymous_report"]["anonymous_label"] == "A"
    assert "candidate_id" not in json.dumps(grade, sort_keys=True)


def test_grade_packet_exposes_the_complete_source_record_and_evidence_contract(
    tmp_path: Path,
) -> None:
    """Removing closed-universe evidence from a grader packet must break this contract."""
    portable = _load_portable()
    run = tmp_path / "run"
    grade = _advance_portable_to_first_grade(portable, run)
    envelope = json.loads((run / "case-envelope.json").read_text(encoding="utf-8"))

    assert grade["payload"]["source_record"] == portable.build_admission_packet(envelope)[
        "payload"
    ]
    assert grade["payload"]["source_spans"]
    definitions = grade["json_schema"]["$defs"]
    assert "report_passage" in definitions["EntryGrade"]["required"]
    assert "report_passage" in definitions["NarrativeScore"]["required"]
    assert {
        "source_record_fingerprint",
        "evidence_basis",
        "evidence_spans",
    } <= set(definitions["OutOfLedgerClaim"]["required"])
    assert grade["payload"]["finding_code_contract"] == {
        "entry_finding_codes": {
            "CONSEQUENCE_TRIGGER_DETACHED": {
                "allowed_dispositions": ["PARTIAL", "OVERSTATED", "CONTRADICTED"],
                "ledger_categories": ["enforcement", "penalty", "remedy"],
                "ledger_fields": {
                    "consequence": "required",
                    "trigger_or_relationship_ids": "at_least_one_required",
                },
            },
            "CRITICAL_LEDGER_ENTRY_MISSING": {
                "allowed_dispositions": ["MISSING"],
                "ledger_materialities": ["critical"],
            },
            "MATERIAL_EXCEPTION_MISSING": {
                "allowed_dispositions": ["MISSING", "PARTIAL"],
                "ledger_categories": ["exception"],
                "ledger_materialities": ["critical", "material"],
            },
        },
        "narrative_finding_codes": {
            "KEY_REQUIREMENTS_ACTION_PLAN": {
                "allowed_dimensions": [
                    "key_requirements",
                    "requirements_workplan_boundary",
                ],
                "maximum_score": 2,
            }
        },
    }


def test_grade_evidence_requires_exact_report_and_source_slices() -> None:
    """Fabricated passages or evidence offsets must fail before a grade is persisted."""
    portable = _load_portable()
    envelope = portable.freeze_case(_case_payload(), seed_hex="0" * 64)
    responses = _scripted_payloads()
    sealed = portable.seal_ledger(
        envelope,
        responses[1]["payload"],
        responses[2]["payload"],
        None,
    )
    grade = _grade_with_evidence(portable, envelope, sealed)
    validated, issues = portable.validate_grade(sealed, grade)

    assert issues == []
    portable._validate_grade_evidence(envelope, validated, "A")

    fabricated_passage = copy.deepcopy(validated)
    fabricated_passage["narrative_scores"][0]["report_passage"] = "invented passage"
    with pytest.raises(portable.PortableEvaluationInputError, match="report passage"):
        portable._validate_grade_evidence(envelope, fabricated_passage, "A")

    fabricated_source = copy.deepcopy(validated)
    fabricated_source["out_of_ledger_claims"][0]["evidence_spans"][0]["quote"] = (
        "invented source text"
    )
    with pytest.raises(portable.PortableEvaluationInputError, match="evidence span"):
        portable._validate_grade_evidence(envelope, fabricated_source, "A")


@pytest.mark.parametrize(
    "disposition",
    sorted(portable_disposition for portable_disposition in (
        "COMPLETE",
        "PARTIAL",
        "MISSING",
        "OVERSTATED",
        "CONTRADICTED",
        "NOT_APPLICABLE",
    )),
)
def test_portable_only_unsupported_claim_may_use_absence_basis(disposition: str) -> None:
    portable = _load_portable()
    claim = {
        "claim_id": "claim-1",
        "claim_text": "The report states an additional penalty.",
        "report_location": "paragraph 1",
        "disposition": disposition,
        "category": "penalty",
        "materiality": "material",
        "related_ledger_ids": [],
        "source_record_fingerprint": "1" * 64,
        "evidence_basis": "closed_universe_absence",
        "evidence_spans": [],
        "rationale": "The complete source record lacks support.",
    }

    with pytest.raises(
        portable.PortableEvaluationInputError,
        match="valid only for the UNSUPPORTED",
    ):
        portable._validate_claim(claim, location="test claim")


@pytest.mark.parametrize("disposition", ["COMPLETE", "PARTIAL"])
def test_positive_credit_absence_grade_retries_with_full_portable_parity(
    tmp_path: Path,
    disposition: str,
) -> None:
    portable = _load_portable()
    portable_run = tmp_path / "portable"
    core_run = tmp_path / "core"
    request = _advance_portable_to_first_grade(portable, portable_run)
    initialize_core(_core_case_from_payload(_case_payload()), core_run, seed_hex="0" * 64)
    for index, item in enumerate(_scripted_payloads()[:3], start=1):
        core_request = next_core(core_run)
        assert core_request is not None
        submit_core(
            core_run,
            JudgeResponse.model_validate(
                _response(core_request.model_dump(mode="json"), item, index)
            ),
        )
    core_request = next_core(core_run)
    assert core_request is not None
    assert request == core_request.model_dump(mode="json")
    envelope = json.loads((portable_run / "case-envelope.json").read_text(encoding="utf-8"))
    sealed = json.loads((portable_run / "legal-ledger.json").read_text(encoding="utf-8"))
    grade = _grade_with_evidence(portable, envelope, sealed)
    grade["out_of_ledger_claims"][0]["disposition"] = disposition
    grade["out_of_ledger_claims"][0]["evidence_basis"] = "closed_universe_absence"
    grade["out_of_ledger_claims"][0]["evidence_spans"] = []
    response = _response(request, {"payload": grade}, 4)

    portable_state = portable.submit_judge_response(portable_run, response)
    core_state = submit_core(core_run, JudgeResponse.model_validate(response))

    portable_state_without_manifest = {
        key: value for key, value in portable_state.items() if key != "manifest_fingerprint"
    }
    core_state_without_manifest = {
        key: value
        for key, value in core_state.model_dump(mode="json").items()
        if key != "manifest_fingerprint"
    }
    assert portable_state_without_manifest == core_state_without_manifest
    assert portable_state["state"] == "grade-a"
    assert portable_state["attempt"] == 2
    assert portable_state["retry_count"] == 1
    assert not (portable_run / "grader-1-report-A.json").exists()
    assert not (core_run / "grader-1-report-A.json").exists()


@pytest.mark.parametrize(
    ("disposition", "evidence_basis", "expected_precision"),
    [
        ("COMPLETE", "source_spans", 1.0),
        ("UNSUPPORTED", "closed_universe_absence", 0.0),
    ],
)
def test_portable_claim_evidence_binding_retains_expected_precision_credit(
    disposition: str,
    evidence_basis: str,
    expected_precision: float,
) -> None:
    portable = _load_portable()
    envelope = portable.freeze_case(_case_payload(), seed_hex="0" * 64)
    responses = _scripted_payloads()
    sealed = portable.seal_ledger(
        envelope,
        responses[1]["payload"],
        responses[2]["payload"],
        None,
    )
    first = _grade_with_evidence(portable, envelope, sealed)
    claim = first["out_of_ledger_claims"][0]
    claim["disposition"] = disposition
    claim["evidence_basis"] = evidence_basis
    if evidence_basis == "closed_universe_absence":
        claim["evidence_spans"] = []
    first, issues = portable.validate_grade(sealed, first)
    assert issues == []
    portable._validate_grade_evidence(envelope, first, "A")
    second = copy.deepcopy(first)
    second["request_fingerprint"] = "f" * 64
    resolved = portable.resolve_grades(sealed, first, second)
    checks = portable._derive_deterministic_checks(
        portable._candidate_for_label(envelope, "A"), "A"
    )

    scored = portable.score_report(
        sealed,
        resolved,
        checks,
        source_record=portable.build_admission_packet(envelope)["payload"],
    )

    assert scored["claim_precision"] == expected_precision


def test_portable_score_report_requires_the_common_source_record() -> None:
    portable = _load_portable()
    envelope = portable.freeze_case(_case_payload(), seed_hex="0" * 64)
    responses = _scripted_payloads()
    sealed = portable.seal_ledger(
        envelope,
        responses[1]["payload"],
        responses[2]["payload"],
        None,
    )
    first = _grade_with_evidence(portable, envelope, sealed)
    second = copy.deepcopy(first)
    second["request_fingerprint"] = "f" * 64
    resolved = portable.resolve_grades(sealed, first, second)
    checks = portable._derive_deterministic_checks(
        portable._candidate_for_label(envelope, "A"), "A"
    )

    with pytest.raises(TypeError, match="source_record"):
        portable.score_report(sealed, resolved, checks)


@pytest.mark.parametrize(
    "mutation",
    ["fingerprint", "source_id", "bounds", "quote"],
)
def test_portable_score_report_rejects_fabricated_or_unbound_exact_evidence(
    mutation: str,
) -> None:
    portable = _load_portable()
    envelope = portable.freeze_case(_case_payload(), seed_hex="0" * 64)
    responses = _scripted_payloads()
    sealed = portable.seal_ledger(
        envelope,
        responses[1]["payload"],
        responses[2]["payload"],
        None,
    )
    first = _grade_with_evidence(portable, envelope, sealed)
    claim = first["out_of_ledger_claims"][0]
    span = claim["evidence_spans"][0]
    source_record = portable.build_admission_packet(envelope)["payload"]
    if mutation == "fingerprint":
        claim["source_record_fingerprint"] = "f" * 64
    elif mutation == "source_id":
        span["source_id"] = "unknown-source"
    elif mutation == "bounds":
        span["end_char"] = len(source_record["sources"][0]["normalized_text"]) + 1
    else:
        span["quote"] = "fabricated exact quote"
    second = copy.deepcopy(first)
    second["request_fingerprint"] = "f" * 64
    resolved = portable.resolve_grades(sealed, first, second)
    checks = portable._derive_deterministic_checks(
        portable._candidate_for_label(envelope, "A"), "A"
    )

    with pytest.raises(
        portable.EvaluationInconclusiveError,
        match=r"source record|exact source span",
    ):
        portable.score_report(
            sealed,
            resolved,
            checks,
            source_record=source_record,
        )


def test_portable_score_report_rejects_invalid_referee_replacement_source_evidence() -> None:
    portable = _load_portable()
    envelope = portable.freeze_case(_case_payload(), seed_hex="0" * 64)
    responses = _scripted_payloads()
    sealed = portable.seal_ledger(
        envelope,
        responses[1]["payload"],
        responses[2]["payload"],
        None,
    )
    first = _grade_with_evidence(portable, envelope, sealed)
    second = copy.deepcopy(first)
    second["request_fingerprint"] = "f" * 64
    second["out_of_ledger_claims"][0]["disposition"] = "PARTIAL"
    records = portable._comparison_records(sealed, first, second)
    dispute = next(
        record["dispute"]
        for record in records
        if record["kind"] == "out_of_ledger_claim"
    )
    assert dispute is not None
    replacement_claim = copy.deepcopy(first["out_of_ledger_claims"][0])
    replacement_claim["claim_id"] = dispute["subject_id"]
    replacement_claim["evidence_spans"][0]["quote"] = "fabricated exact quote"
    decision = {
        "dispute_id": dispute["dispute_id"],
        "selected_grade_resolution": "replace",
        "grade_dispute_fingerprint": portable._model_fingerprint(dispute),
        "replacement_grade_alternative": {
            "request_fingerprint": "c" * 64,
            "out_of_ledger_claim": replacement_claim,
        },
        "rationale": "The referee supplied a replacement claim.",
    }
    resolved = portable.resolve_grades(sealed, first, second, [decision])
    checks = portable._derive_deterministic_checks(
        portable._candidate_for_label(envelope, "A"), "A"
    )

    with pytest.raises(portable.EvaluationInconclusiveError, match="exact source span"):
        portable.score_report(
            sealed,
            resolved,
            checks,
            source_record=portable.build_admission_packet(envelope)["payload"],
        )


def test_portable_referee_replacement_cannot_introduce_positive_credit_absence() -> None:
    portable = _load_portable()
    envelope = portable.freeze_case(_case_payload(), seed_hex="0" * 64)
    responses = _scripted_payloads()
    sealed = portable.seal_ledger(
        envelope,
        responses[1]["payload"],
        responses[2]["payload"],
        None,
    )
    grade = _grade_with_evidence(portable, envelope, sealed)
    replacement_claim = copy.deepcopy(grade["out_of_ledger_claims"][0])
    replacement_claim["evidence_basis"] = "closed_universe_absence"
    replacement_claim["evidence_spans"] = []
    decision = {
        "dispute_id": "grade-claim-matched-claim-0001",
        "selected_grade_resolution": "replace",
        "grade_dispute_fingerprint": "a" * 64,
        "replacement_grade_alternative": {
            "request_fingerprint": "b" * 64,
            "out_of_ledger_claim": replacement_claim,
        },
        "rationale": "The referee supplied a replacement claim.",
    }

    with pytest.raises(
        portable.PortableEvaluationInputError,
        match="valid only for the UNSUPPORTED",
    ):
        portable.validate_referee_decision(decision)


@pytest.mark.parametrize(
    ("legacy_kind", "message"),
    [
        ("selected_disposition", "legacy resolution domain"),
        ("selected_ledger_resolution", "legacy resolution domain"),
        ("replacement_entries", "legacy resolution domain"),
        ("source_ids", "only the supplied dispute"),
    ],
)
def test_portable_grade_referee_rejects_legacy_domain_and_external_sources(
    legacy_kind: str,
    message: str,
) -> None:
    portable = _load_portable()
    envelope = portable.freeze_case(_case_payload(), seed_hex="0" * 64)
    responses = _scripted_payloads()
    sealed = portable.seal_ledger(
        envelope,
        responses[1]["payload"],
        responses[2]["payload"],
        None,
    )
    first = _grade_with_evidence(portable, envelope, sealed)
    second = copy.deepcopy(first)
    second["request_fingerprint"] = "f" * 64
    second["entry_grades"][0]["disposition"] = "PARTIAL"
    second["entry_grades"][0]["rationale"] = "The report covers only part of the duty."
    dispute = portable.material_disputes(sealed, first, second)[0]
    legacy_fields: dict[str, Any] = {
        "selected_disposition": {"selected_disposition": "PARTIAL"},
        "selected_ledger_resolution": {"selected_ledger_resolution": "accept_a"},
        "replacement_entries": {
            "replacement_entries": [sealed["ledger"]["entries"][0]]
        },
        "source_ids": {"source_ids": ["synthetic-rule-1-source"]},
    }[legacy_kind]
    decision = {
        "dispute_id": dispute["dispute_id"],
        "selected_grade_resolution": "accept_grader_1",
        "grade_dispute_fingerprint": portable._model_fingerprint(dispute),
        "rationale": "The first grade is better supported by the supplied packet.",
        **legacy_fields,
    }

    with pytest.raises(portable.EvaluationInconclusiveError, match=message):
        portable.resolve_grades(sealed, first, second, [decision])


def test_portable_grade_referee_replacement_matches_dispute_invariants() -> None:
    """Portable referees must not rewrite the kind, subject, or weight of a dispute."""
    portable = _load_portable()
    envelope = portable.freeze_case(_case_payload(), seed_hex="0" * 64)
    responses = _scripted_payloads()
    sealed = portable.seal_ledger(
        envelope,
        responses[1]["payload"],
        responses[2]["payload"],
        None,
    )
    first = _grade_with_evidence(portable, envelope, sealed)
    second = copy.deepcopy(first)
    second["request_fingerprint"] = "f" * 64
    second["out_of_ledger_claims"] = []
    claim_dispute = next(
        dispute
        for dispute in portable.material_disputes(sealed, first, second)
        if dispute["kind"] == "out_of_ledger_claim"
    )

    def decision(replacement: dict[str, Any]) -> dict[str, Any]:
        return {
            "dispute_id": claim_dispute["dispute_id"],
            "selected_grade_resolution": "replace",
            "grade_dispute_fingerprint": portable._model_fingerprint(claim_dispute),
            "replacement_grade_alternative": replacement,
            "rationale": "The referee supplied a replacement for the exact dispute.",
        }

    wrong_kind = {
        "request_fingerprint": "c" * 64,
        "entry_grade": copy.deepcopy(first["entry_grades"][0]),
    }
    wrong_identity = copy.deepcopy(claim_dispute["grader_1"])
    wrong_identity["request_fingerprint"] = "c" * 64
    wrong_identity["out_of_ledger_claim"]["claim_text"] = (
        "An unrelated status proposition that would change the scored evidence."
    )
    understated = copy.deepcopy(claim_dispute["grader_1"])
    understated["request_fingerprint"] = "d" * 64
    understated["out_of_ledger_claim"]["materiality"] = "supporting"

    for replacement, message in (
        (wrong_kind, "replacement kind"),
        (wrong_identity, "claim identity"),
        (understated, "understate materiality"),
    ):
        with pytest.raises(portable.EvaluationInconclusiveError, match=message):
            portable.resolve_grades(sealed, first, second, [decision(replacement)])

    absence = {
        "request_fingerprint": "e" * 64,
        "absent_claim": True,
    }
    resolved = portable.resolve_grades(sealed, first, second, [decision(absence)])
    assert resolved["grade"]["out_of_ledger_claims"] == []


def test_portable_grade_referee_replacement_matches_entry_and_narrative_subjects() -> None:
    portable = _load_portable()
    envelope = portable.freeze_case(_case_payload(), seed_hex="0" * 64)
    responses = _scripted_payloads()
    sealed = portable.seal_ledger(
        envelope,
        responses[1]["payload"],
        responses[2]["payload"],
        None,
    )
    first = _grade_with_evidence(portable, envelope, sealed)

    entry_second = copy.deepcopy(first)
    entry_second["request_fingerprint"] = "f" * 64
    entry_second["entry_grades"][0]["disposition"] = "PARTIAL"
    entry_dispute = next(
        dispute
        for dispute in portable.material_disputes(sealed, first, entry_second)
        if dispute["kind"] == "entry_grade"
    )
    wrong_entry = copy.deepcopy(entry_dispute["grader_1"])
    wrong_entry["request_fingerprint"] = "c" * 64
    wrong_entry["entry_grade"]["ledger_id"] = "different-ledger-entry"
    entry_decision = {
        "dispute_id": entry_dispute["dispute_id"],
        "selected_grade_resolution": "replace",
        "grade_dispute_fingerprint": portable._model_fingerprint(entry_dispute),
        "replacement_grade_alternative": wrong_entry,
        "rationale": "The referee supplied an entry replacement.",
    }
    with pytest.raises(portable.EvaluationInconclusiveError, match="entry subject"):
        portable.resolve_grades(sealed, first, entry_second, [entry_decision])

    narrative_second = copy.deepcopy(first)
    narrative_second["request_fingerprint"] = "e" * 64
    narrative_second["narrative_scores"][0]["score"] = 3
    narrative_dispute = next(
        dispute
        for dispute in portable.material_disputes(sealed, first, narrative_second)
        if dispute["kind"] == "narrative_score"
    )
    wrong_narrative = copy.deepcopy(narrative_dispute["grader_1"])
    wrong_narrative["request_fingerprint"] = "d" * 64
    wrong_narrative["narrative_score"]["dimension"] = "scanability"
    narrative_decision = {
        "dispute_id": narrative_dispute["dispute_id"],
        "selected_grade_resolution": "replace",
        "grade_dispute_fingerprint": portable._model_fingerprint(narrative_dispute),
        "replacement_grade_alternative": wrong_narrative,
        "rationale": "The referee supplied a narrative replacement.",
    }
    with pytest.raises(portable.EvaluationInconclusiveError, match="narrative subject"):
        portable.resolve_grades(sealed, first, narrative_second, [narrative_decision])


@pytest.mark.parametrize(
    "disposition",
    ["COMPLETE", "PARTIAL", "MISSING", "OVERSTATED", "CONTRADICTED", "NOT_APPLICABLE"],
)
def test_portable_rebound_resolved_grade_rejects_nonunsupported_absence(
    disposition: str,
) -> None:
    portable = _load_portable()
    envelope = portable.freeze_case(_case_payload(), seed_hex="0" * 64)
    responses = _scripted_payloads()
    sealed = portable.seal_ledger(
        envelope,
        responses[1]["payload"],
        responses[2]["payload"],
        None,
    )
    first = _grade_with_evidence(portable, envelope, sealed)
    second = copy.deepcopy(first)
    second["request_fingerprint"] = "f" * 64
    resolved = portable.resolve_grades(sealed, first, second)

    def rebound(value: object) -> None:
        if isinstance(value, dict):
            if value.get("disposition") == "COMPLETE" and "evidence_basis" in value:
                value["disposition"] = disposition
                value["evidence_basis"] = "closed_universe_absence"
                value["evidence_spans"] = []
            for child in value.values():
                rebound(child)
        elif isinstance(value, list):
            for child in value:
                rebound(child)

    rebound(resolved)
    resolution_payload = {
        key: resolved[key]
        for key in (
            "grade",
            "audit",
            "original_grader_1",
            "original_grader_2",
            "referee_decisions",
        )
    }
    resolved["resolution_fingerprint"] = hashlib.sha256(
        portable.canonical_json_bytes(resolution_payload)
    ).hexdigest()
    checks = portable._derive_deterministic_checks(
        portable._candidate_for_label(envelope, "A"), "A"
    )

    with pytest.raises(
        portable.PortableEvaluationInputError,
        match="valid only for the UNSUPPORTED",
    ):
        portable.score_report(
            sealed,
            resolved,
            checks,
            source_record=portable.build_admission_packet(envelope)["payload"],
        )


def test_report_referee_packet_is_dispute_scoped_label_free_and_self_contained() -> None:
    """A fresh report referee must receive one complete dispute and no report label."""
    portable = _load_portable()
    envelope = portable.freeze_case(_case_payload(), seed_hex="0" * 64)
    responses = _scripted_payloads()
    sealed = portable.seal_ledger(
        envelope,
        responses[1]["payload"],
        responses[2]["payload"],
        None,
    )
    report_passage = "A covered operator must file a registry notice within 10 days"
    first = {
        "request_fingerprint": "1" * 64,
        "entry_grade": {
            "ledger_id": "file-notice",
            "disposition": "COMPLETE",
            "report_location": "paragraph 1",
            "report_passage": report_passage,
            "finding_codes": [],
            "rationale": "The complete filing duty appears in the passage.",
        },
        "out_of_ledger_claim": None,
        "narrative_score": None,
        "absent_claim": False,
    }
    second = copy.deepcopy(first)
    second["request_fingerprint"] = "2" * 64
    second["entry_grade"]["disposition"] = "PARTIAL"
    second["entry_grade"]["rationale"] = "The passage omits part of the filing duty."
    dispute = {
        "dispute_id": "grade-entry-file-notice",
        "anonymous_label": "A",
        "ledger_fingerprint": sealed["ledger_fingerprint"],
        "kind": "entry_grade",
        "subject_id": "file-notice",
        "materiality": "critical",
        "grader_1": first,
        "grader_2": second,
        "rationale": "The blind graders disagree on the entry disposition.",
    }
    legal_hash = hashlib.sha256(portable.canonical_json_bytes(sealed)).hexdigest()

    request = portable._report_referee_request(envelope, sealed, dispute, legal_hash)
    core_envelope = freeze_core(_core_case_from_payload(_case_payload()), seed_hex="0" * 64)
    core_request = core_workflow._report_referee_request(
        core_envelope,
        SealedLedger.model_validate(sealed),
        GradeDispute.model_validate(dispute),
        legal_ledger_hash=legal_hash,
    ).model_dump(mode="json")
    serialized = json.dumps(request, sort_keys=True)

    assert portable.canonical_json_bytes(request) == canonical_json_bytes(core_request)
    assert "anonymous_label" not in serialized
    assert "candidate_id" not in serialized
    assert request["payload"]["anonymous_passages"] == [report_passage]
    assert request["payload"]["relevant_context"]["ledger_entries"][0][
        "ledger_id"
    ] == "file-notice"
    assert request["payload"]["source_spans"]
    assert request["payload"]["dispute"]["grader_1"]["entry_grade"]["rationale"]
    assert request["payload"]["dispute"]["grader_2"]["entry_grade"]["rationale"]
    assert set(request["payload"]["alternative_meanings"]) == {
        "accept_grader_1",
        "accept_grader_2",
        "replace",
    }
    assert "Do not set selected_disposition" in request["system_instructions"]
    assert "source_ids" in request["system_instructions"]
    assert "closed-record limitation" in request["system_instructions"]
    assert "not an affirmative out-of-ledger claim" in request["system_instructions"]
    assert request["safe_metadata"]["grade_dispute_fingerprint"] == portable._model_fingerprint(
        dispute
    )
    assert request["request_fingerprint"] == (
        "96b4f9159549996b1488bb10132da4905a18c0b47b16989fd70993e854b39612"
    )
    assert hashlib.sha256(portable.canonical_json_bytes(request)).hexdigest() == (
        "dcacec8e3117c79ca5db1b66420ceed9518c3de0b694d6f8c9115d7542b2cc61"
    )
    portable._verify_request_noninterference(request, envelope["case"])


@pytest.mark.parametrize(
    "passage",
    [
        "## Key Requirements",
        "| Duty | Timing |\n| --- | --- |",
    ],
)
def test_narrative_referee_expands_heading_and_table_snippets_to_complete_h2_section(
    passage: str,
) -> None:
    """Removing H2 expansion would again leave the referee with a fragment."""
    expected_section = (
        "## Key Requirements\n\n"
        "| Duty | Timing |\n"
        "| --- | --- |\n"
        "| File notice | 10 days |\n\n"
        "The exception applies during an emergency.\n\n"
    )
    report = (
        "# Compliance Brief\n\n"
        "## Executive Summary\n\nSummary.\n\n"
        f"{expected_section}"
        "## Penalties and Enforcement\n\nA violation carries a penalty.\n"
    )

    request, _ = _referee_requests_for_report(
        report,
        dimension="key_requirements",
        first_passage=passage,
    )

    assert request["payload"]["anonymous_passages"] == [expected_section]
    assert request["payload"]["dispute"]["grader_1"]["narrative_score"][
        "report_passage"
    ] == passage


def test_narrative_referee_unions_sections_in_report_order_and_deduplicates_repeats() -> None:
    """Changing union ordering or retaining duplicate sections would bloat the packet."""
    requirements = "## Key Requirements\n\nRepeated duty.\nAnother duty.\n\n"
    penalties = "## Penalties and Enforcement\n\nPenalty consequence.\n\n"
    report = f"# Brief\n\n{requirements}{penalties}## Implementation Workplan\n\nAct.\n"

    request, _ = _referee_requests_for_report(
        report,
        dimension="key_requirements",
        first_passage="Penalty consequence.",
        second_passage="Repeated duty.",
    )
    assert request["payload"]["anonymous_passages"] == [requirements, penalties]

    repeated, _ = _referee_requests_for_report(
        report,
        dimension="key_requirements",
        first_passage="Repeated duty.",
        second_passage="Repeated duty.",
    )
    assert repeated["payload"]["anonymous_passages"] == [requirements]


@pytest.mark.parametrize(
    "dimension",
    [
        "regulatory_walk",
        "qualification_placement",
        "requirements_workplan_boundary",
        "scanability",
    ],
)
def test_workflow_narrative_dimensions_receive_complete_anonymous_report(
    dimension: str,
) -> None:
    """Report-wide rubric dimensions must not be decided from one grader snippet."""
    report = (
        "# Brief\n\n## Scope\n\nCovered operators.\n\n"
        "## Key Requirements\n\nFile notice.\n\n"
        "## Implementation Workplan\n\nAssign an owner.\n"
    )

    request, _ = _referee_requests_for_report(
        report,
        dimension=dimension,
        first_passage="File notice.",
    )

    assert request["payload"]["anonymous_passages"] == [report]
    assert "complete anonymous report" in request["system_instructions"]


def test_narrative_referee_preserves_crlf_section_bytes() -> None:
    """Normalizing CRLF would break the exact report-byte evidence contract."""
    expected_section = "## Key Requirements\r\n\r\nFile notice.\r\n\r\n"
    report = (
        "# Brief\r\n\r\n"
        f"{expected_section}"
        "## Penalties and Enforcement\r\n\r\nPenalty.\r\n"
    )

    request, _ = _referee_requests_for_report(
        report,
        dimension="key_requirements",
        first_passage="File notice.",
    )

    assert request["payload"]["anonymous_passages"] == [expected_section]
    assert request["payload"]["anonymous_passages"][0].encode() == expected_section.encode()


def test_narrative_referee_ignores_h2_like_lines_inside_fenced_code() -> None:
    """Treating a fenced pseudo-heading as H2 would truncate the enclosing section."""
    expected_section = (
        "## Key Requirements\n\n"
        "Before fence.\n\n"
        "```text\n"
        "## Not A Section\n"
        "example only\n"
        "```\n\n"
        "After fence.\n\n"
    )
    report = f"# Brief\n\n{expected_section}## Penalties\n\nPenalty.\n"

    request, _ = _referee_requests_for_report(
        report,
        dimension="key_requirements",
        first_passage="After fence.",
    )

    assert request["payload"]["anonymous_passages"] == [expected_section]


@pytest.mark.parametrize(
    ("report", "passage"),
    [
        (
            "# Brief\n\n## First\n\nRepeated rule.\n\n## Second\n\nRepeated rule.\n",
            "Repeated rule.",
        ),
        (
            "# Brief\n\nUnsectioned summary.\n\n## Requirements\n\nDuty.\n",
            "Unsectioned summary.",
        ),
        (
            "# Brief\n\n## Requirements\n\nDuty.\n\n## Penalties\n\nPenalty.\n",
            "Duty.\n\n## Penalties\n\nPenalty.",
        ),
    ],
)
def test_narrative_referee_falls_back_to_full_report_when_section_is_not_unique(
    report: str,
    passage: str,
) -> None:
    """Guessing at absent, boundary-spanning, or ambiguous sections is unsafe."""
    request, _ = _referee_requests_for_report(
        report,
        dimension="key_requirements",
        first_passage=passage,
    )

    assert request["payload"]["anonymous_passages"] == [report]


def test_portable_admission_packet_exposes_exact_codes_and_rejects_aliases() -> None:
    portable = _load_portable()
    envelope = portable.freeze_case(_case_payload(), seed_hex="0" * 64)
    packet = portable.build_admission_packet(envelope)
    required_codes = {
        "AUTHORITY_ALIGNMENT",
        "OPERATIVE_TEXT",
        "CURRENTNESS_EVIDENCE",
        "LANGUAGE_RESOLUTION",
        "SOURCE_PARITY",
    }

    assert set(
        packet["json_schema"]["$defs"]["AdmissionCheck"]["properties"]["code"][
            "enum"
        ]
    ) == required_codes
    assert all(code in packet["system_instructions"] for code in required_codes)
    judgment = copy.deepcopy(_scripted_payloads()[0]["payload"])
    judgment["checks"][0]["code"] = "REQUESTED_AUTHORITY_COVERAGE"
    with pytest.raises(portable.PortableEvaluationInputError, match="code"):
        portable._validate_admission_judgment(judgment)


@pytest.mark.parametrize("source_ids", [[], ["invented-source"]])
def test_portable_admission_rejects_satisfied_checks_without_known_source_support(
    source_ids: list[str],
) -> None:
    """Portable admission must enforce the same source-support boundary as core."""
    portable = _load_portable()
    envelope = portable.freeze_case(_case_payload(), seed_hex="0" * 64)
    judgment = copy.deepcopy(_scripted_payloads()[0]["payload"])
    judgment["request_fingerprint"] = portable.build_admission_packet(envelope)[
        "request_fingerprint"
    ]
    judgment["checks"][0]["source_ids"] = source_ids

    with pytest.raises(portable.PortableEvaluationInputError, match="supporting source_ids"):
        portable.adjudicate_admission(envelope, judgment)


def test_ledger_referee_helper_rejects_structural_candidate_contamination() -> None:
    portable = _load_portable()
    contaminated = {
        "operation": "referee",
        "safe_metadata": {
            "record_scope": "source-only-dispute",
            "referee_scope": "ledger",
        },
        "payload": {
            "dispute": {"candidate_id": "leaked-candidate"},
            "relevant_entries": [],
        },
    }
    with pytest.raises(portable.EvaluationIntegrityError, match="source-only"):
        portable._verify_request_noninterference(contaminated, _case_payload())


def test_ledger_referee_packet_is_self_contained_and_matches_portable() -> None:
    """Fresh full and portable referees need identical evidence and choice semantics."""
    portable = _load_portable()
    case_payload = _case_payload()
    core_envelope = freeze_core(_core_case_from_payload(case_payload), seed_hex="0" * 64)
    portable_envelope = portable.freeze_case(case_payload, seed_hex="0" * 64)
    ledger_payload = copy.deepcopy(_scripted_payloads()[1]["payload"])
    dispute_payload = {
        "dispute_id": "file-notice-materiality",
        "action": "materiality",
        "target_ledger_ids": ["file-notice"],
        "proposed_entries": [],
        "materiality": "critical",
        "rationale": "Materiality needs an independent source-grounded decision.",
    }

    core_request = ledger_referee_request_core(
        core_envelope,
        LegalLedger.model_validate(ledger_payload),
        LedgerDispute.model_validate(dispute_payload),
    ).model_dump(mode="json")
    portable_request = portable._ledger_referee_request(
        portable_envelope,
        ledger_payload,
        dispute_payload,
    )

    assert core_request == portable_request
    assert core_request["payload"]["resolution_contract"] == {
        "accept_a": "keep the repaired ledger unchanged for this dispute",
        "accept_b": "apply the supplied audit dispute to the repaired ledger",
    }
    assert core_request["payload"]["source_record"]["sources"]
    assert core_request["payload"]["source_spans"]


def test_audit_and_repair_ledger_invariant_contract_packets_match_portable() -> None:
    """Full and portable source-only roles must receive byte-equivalent audit contracts."""
    portable = _load_portable()
    case_payload = _case_payload()
    core_envelope = freeze_core(_core_case_from_payload(case_payload), seed_hex="0" * 64)
    portable_envelope = portable.freeze_case(case_payload, seed_hex="0" * 64)
    ledger_payload = copy.deepcopy(_scripted_payloads()[1]["payload"])
    core_ledger = LegalLedger.model_validate(ledger_payload)
    audit_payload = {
        "request_fingerprint": "a" * 64,
        "complete": True,
        "disputes": [
            {
                "dispute_id": "missing-duty",
                "action": "add",
                "target_ledger_ids": [],
                "proposed_entries": [],
                "materiality": "supporting",
                "rationale": (
                    "synthetic-rule-1-source is missing covered operator registry notice "
                    "requirement."
                ),
            }
        ],
    }
    core_audit = LedgerAudit.model_validate(audit_payload)

    full_audit_request = audit_ledger_request_core(core_envelope, core_ledger).model_dump(
        mode="json"
    )
    portable_audit_request = portable._audit_ledger_request(portable_envelope, ledger_payload)
    full_repair_request = repair_ledger_request_core(
        core_envelope, core_ledger, core_audit
    ).model_dump(mode="json")
    portable_repair_request = portable._repair_ledger_request(
        portable_envelope, ledger_payload, audit_payload
    )

    assert full_audit_request == portable_audit_request
    assert full_repair_request == portable_repair_request
    assert full_audit_request["payload"]["ledger_invariant_contract"] == (
        ledger_invariant_contract()
    )
    assert full_repair_request["payload"]["ledger_invariant_contract"] == (
        ledger_invariant_contract()
    )
    assert (
        full_audit_request["payload"]["audit_action_contract"]
        == full_repair_request["payload"]["audit_action_contract"]
    )
    assert full_audit_request["payload"]["audit_action_contract"][
        "initial_audit_findings"
    ]["action_payloads"]["add"]["ledger_id_rule"] == (
        "new_relative_to_proposed_ledger"
    )
    portable_findings = portable.validate_ledger_audit_findings(
        audit_payload, envelope=portable_envelope, proposed_ledger=ledger_payload
    )
    assert portable_findings["disputes"] == [
        finding.model_dump(mode="json")
        for finding in ledger_findings_core(core_envelope, core_ledger, core_audit)
    ]
    with pytest.raises(portable.PortableEvaluationInputError, match="action payload"):
        portable.validate_ledger_audit(audit_payload)
    with pytest.raises(LedgerInconclusiveErrorCore, match="add"):
        ledger_disputes_core(core_audit)


def test_build_ledger_invariant_contract_packet_matches_portable() -> None:
    """Fresh full and portable ledger builders must receive identical invariants."""
    portable = _load_portable()
    case_payload = _case_payload()
    core_envelope = freeze_core(_core_case_from_payload(case_payload), seed_hex="0" * 64)
    portable_envelope = portable.freeze_case(case_payload, seed_hex="0" * 64)

    full_request = build_ledger_request_core(core_envelope).model_dump(mode="json")
    portable_request = portable._build_ledger_request(portable_envelope)

    assert full_request == portable_request
    assert full_request["payload"]["ledger_invariant_contract"] == (
        ledger_invariant_contract()
    )


def test_portable_ledger_invariant_contract_returns_fresh_json() -> None:
    """Portable callers must not share mutable nested invariant state."""
    portable = _load_portable()

    mutated = portable._ledger_invariant_contract()
    mutated["relationships"]["trigger_link_categories"].append("remedy")

    assert portable._ledger_invariant_contract() == ledger_invariant_contract()


@pytest.mark.parametrize(
    ("action", "targets", "proposed_count", "valid"),
    [
        ("add", [], 0, True),
        ("add", [], 1, True),
        ("add", ["file-notice"], 0, False),
        ("edit", ["file-notice"], 0, True),
        ("edit", ["file-notice"], 1, True),
        ("edit", [], 0, False),
        ("delete", ["file-notice"], 0, True),
        ("delete", ["file-notice"], 1, False),
        ("split", ["file-notice"], 0, True),
        ("split", ["unknown-ledger-id"], 0, False),
        ("split", ["file-notice"], 2, True),
        ("split", ["file-notice"], 1, False),
        ("merge", ["file-notice", "retain-proof"], 0, True),
        ("merge", ["file-notice", "retain-proof"], 1, True),
        ("merge", ["file-notice"], 0, False),
        ("materiality", ["file-notice"], 0, True),
        ("materiality", [], 0, False),
        ("materiality", ["file-notice"], 1, False),
    ],
)
def test_initial_finding_action_validation_matches_core_and_portable(
    action: str,
    targets: list[str],
    proposed_count: int,
    valid: bool,
) -> None:
    portable = _load_portable()
    envelope_payload = portable.freeze_case(_case_payload(), seed_hex="0" * 64)
    ledger_payload = copy.deepcopy(_scripted_payloads()[1]["payload"])
    core_envelope = freeze_core(_core_case_from_payload(_case_payload()), seed_hex="0" * 64)
    core_ledger = LegalLedger.model_validate(ledger_payload)
    proposed = copy.deepcopy(ledger_payload["entries"][:proposed_count])
    if action == "add" and proposed:
        proposed[0]["ledger_id"] = "added-entry"
    if action == "edit" and proposed:
        proposed[0]["ledger_id"] = targets[0]
    payload = {
        "request_fingerprint": "a" * 64,
        "complete": True,
        "disputes": [
            {
                "dispute_id": "finding",
                "action": action,
                "target_ledger_ids": targets,
                "proposed_entries": proposed,
                "materiality": "supporting",
                "rationale": (
                    "synthetic-rule-1-source is missing covered operator registry notice "
                    "requirement."
                ),
            }
        ],
    }
    core_audit = LedgerAudit.model_validate(payload)

    if valid:
        assert portable.validate_ledger_audit_findings(
            payload, envelope=envelope_payload, proposed_ledger=ledger_payload
        )["disputes"] == [
            finding.model_dump(mode="json")
            for finding in ledger_findings_core(core_envelope, core_ledger, core_audit)
        ]
    else:
        with pytest.raises(portable.PortableEvaluationInputError):
            portable.validate_ledger_audit_findings(
                payload, envelope=envelope_payload, proposed_ledger=ledger_payload
            )
        with pytest.raises(LedgerInconclusiveErrorCore):
            ledger_findings_core(core_envelope, core_ledger, core_audit)


def test_initial_add_reused_id_rejection_matches_core_and_portable() -> None:
    portable = _load_portable()
    case_payload = _case_payload()
    portable_envelope = portable.freeze_case(case_payload, seed_hex="0" * 64)
    core_envelope = freeze_core(_core_case_from_payload(case_payload), seed_hex="0" * 64)
    ledger_payload = copy.deepcopy(_scripted_payloads()[1]["payload"])
    payload = {
        "request_fingerprint": "a" * 64,
        "complete": True,
        "disputes": [
            {
                "dispute_id": "reused-add-id",
                "action": "add",
                "target_ledger_ids": [],
                "proposed_entries": [copy.deepcopy(ledger_payload["entries"][0])],
                "materiality": "supporting",
                "rationale": "The source record needs a ledger correction.",
            }
        ],
    }

    with pytest.raises(
        portable.PortableEvaluationInputError,
        match="add initial ledger finding must use new ledger IDs",
    ) as portable_error:
        portable.validate_ledger_audit_findings(
            payload,
            envelope=portable_envelope,
            proposed_ledger=ledger_payload,
        )
    with pytest.raises(
        LedgerInconclusiveErrorCore,
        match="add initial ledger finding must use new ledger IDs",
    ) as core_error:
        ledger_findings_core(
            core_envelope,
            LegalLedger.model_validate(ledger_payload),
            LedgerAudit.model_validate(payload),
        )
    assert str(portable_error.value) == str(core_error.value)


@pytest.mark.parametrize(
    ("rationale", "valid"),
    [
        ("This finding is very important indeed.", False),
        ("The source record needs a ledger correction.", True),
        ("The notice duty combines distinct filing and timing propositions.", True),
    ],
)
def test_initial_finding_rationale_validation_matches_core_and_portable(
    rationale: str, valid: bool
) -> None:
    portable = _load_portable()
    envelope_payload = portable.freeze_case(_case_payload(), seed_hex="0" * 64)
    ledger_payload = copy.deepcopy(_scripted_payloads()[1]["payload"])
    core_envelope = freeze_core(_core_case_from_payload(_case_payload()), seed_hex="0" * 64)
    core_ledger = LegalLedger.model_validate(ledger_payload)
    proposed = copy.deepcopy(ledger_payload["entries"][:1])
    proposed[0]["ledger_id"] = "added-entry"
    payload = {
        "request_fingerprint": "a" * 64,
        "complete": True,
        "disputes": [
            {
                "dispute_id": "generic",
                "action": "add",
                "target_ledger_ids": [],
                "proposed_entries": proposed,
                "materiality": "supporting",
                "rationale": rationale,
            }
        ],
    }

    if valid:
        assert portable.validate_ledger_audit_findings(
            payload, envelope=envelope_payload, proposed_ledger=ledger_payload
        )["disputes"] == [
            finding.model_dump(mode="json")
            for finding in ledger_findings_core(
                core_envelope,
                core_ledger,
                LedgerAudit.model_validate(payload),
            )
        ]
    else:
        with pytest.raises(portable.PortableEvaluationInputError, match="concrete rationale"):
            portable.validate_ledger_audit_findings(
                payload, envelope=envelope_payload, proposed_ledger=ledger_payload
            )
        with pytest.raises(LedgerInconclusiveErrorCore, match="concrete rationale"):
            ledger_findings_core(
                core_envelope,
                core_ledger,
                LedgerAudit.model_validate(payload),
            )


@pytest.mark.parametrize(
    ("rationale", "valid"),
    [
        ("The case metadata needs a ledger correction.", False),
        ("The request fingerprint needs a ledger correction.", False),
        ("The response schema needs a ledger correction.", False),
        ("unknown-source is missing covered operator registry notice requirement.", False),
        (
            "synthetic-rule-1-source is missing covered operator registry notice requirement.",
            True,
        ),
        (
            "synthetic-rule-1-source is missing the requirement at Rule 1.",
            True,
        ),
        (
            "synthetic-rule-1-source is missing the requirement at rUlE 1.",
            True,
        ),
        (
            "synthetic-rule-1-source is missing the requirement at Rule 404.",
            False,
        ),
        (
            "synthetic-rule-1-source is missing covered operator registry notice "
            "requirement at Rule 404.",
            False,
        ),
    ],
)
def test_proposal_free_add_source_grounding_matches_core_and_portable(
    rationale: str, valid: bool
) -> None:
    portable = _load_portable()
    envelope_payload = portable.freeze_case(_case_payload(), seed_hex="0" * 64)
    ledger_payload = copy.deepcopy(_scripted_payloads()[1]["payload"])
    core_envelope = freeze_core(_core_case_from_payload(_case_payload()), seed_hex="0" * 64)
    core_ledger = LegalLedger.model_validate(ledger_payload)
    payload = {
        "request_fingerprint": "a" * 64,
        "complete": True,
        "disputes": [
            {
                "dispute_id": "source-grounding",
                "action": "add",
                "target_ledger_ids": [],
                "proposed_entries": [],
                "materiality": "supporting",
                "rationale": rationale,
            }
        ],
    }
    core_audit = LedgerAudit.model_validate(payload)

    if valid:
        assert portable.validate_ledger_audit_findings(
            payload, envelope=envelope_payload, proposed_ledger=ledger_payload
        )["disputes"] == [
            finding.model_dump(mode="json")
            for finding in ledger_findings_core(core_envelope, core_ledger, core_audit)
        ]
    else:
        with pytest.raises(portable.PortableEvaluationInputError, match="source-grounded"):
            portable.validate_ledger_audit_findings(
                payload, envelope=envelope_payload, proposed_ledger=ledger_payload
            )
        with pytest.raises(LedgerInconclusiveErrorCore, match="source-grounded"):
            ledger_findings_core(core_envelope, core_ledger, core_audit)


@pytest.mark.parametrize(
    ("rationale", "valid"),
    [
        (
            "synthetic-rule-1-source is missing covered operator registry notice "
            "requirement at Rule 1 and Section 2.",
            True,
        ),
        (
            "synthetic-rule-1-source is missing covered operator registry notice "
            "requirement at Rule 1 and Section 999.",
            False,
        ),
    ],
)
def test_multiple_locator_grounding_fails_closed_with_full_portable_parity(
    rationale: str, valid: bool
) -> None:
    portable = _load_portable()
    case_payload = _case_payload()
    case_payload["sources"][0]["title"] = "Synthetic Rule 1 Section 2"
    envelope_payload = portable.freeze_case(case_payload, seed_hex="0" * 64)
    ledger_payload = copy.deepcopy(_scripted_payloads()[1]["payload"])
    ledger_payload["case_fingerprint"] = portable.build_admission_packet(envelope_payload)[
        "safe_metadata"
    ]["source_record_fingerprint"]
    payload = {
        "request_fingerprint": "a" * 64,
        "complete": True,
        "disputes": [
            {
                "dispute_id": "multiple-locators",
                "action": "add",
                "target_ledger_ids": [],
                "proposed_entries": [],
                "materiality": "supporting",
                "rationale": rationale,
            }
        ],
    }
    core_envelope = freeze_core(_core_case_from_payload(case_payload), seed_hex="0" * 64)
    core_ledger = LegalLedger.model_validate(ledger_payload)
    core_audit = LedgerAudit.model_validate(payload)

    if valid:
        assert portable.validate_ledger_audit_findings(
            payload, envelope=envelope_payload, proposed_ledger=ledger_payload
        )["disputes"] == [
            finding.model_dump(mode="json")
            for finding in ledger_findings_core(core_envelope, core_ledger, core_audit)
        ]
    else:
        with pytest.raises(portable.PortableEvaluationInputError, match="source-grounded"):
            portable.validate_ledger_audit_findings(
                payload, envelope=envelope_payload, proposed_ledger=ledger_payload
            )
        with pytest.raises(LedgerInconclusiveErrorCore, match="source-grounded"):
            ledger_findings_core(core_envelope, core_ledger, core_audit)


@pytest.mark.parametrize(
    ("defect", "issue_code"),
    [
        ("unknown-source", "LEDGER_CITATION_SOURCE_UNKNOWN"),
        ("wrong-quote", "LEDGER_QUOTE_MISMATCH"),
        ("out-of-range", "LEDGER_QUOTE_MISMATCH"),
        ("commentary-only", "LEDGER_COMMENTARY_ONLY_SUPPORT"),
    ],
)
def test_initial_proposed_entry_exact_source_validation_matches_core_and_portable(
    defect: str, issue_code: str
) -> None:
    portable = _load_portable()
    case_payload = _case_payload()
    if defect == "commentary-only":
        commentary = copy.deepcopy(case_payload["sources"][0])
        commentary.update(
            {
                "source_id": "commentary-source",
                "source_role": "commentary_analysis",
                "source_quality": "secondary",
            }
        )
        case_payload["sources"].append(commentary)
        case_payload["requested_authorities"][0]["source_ids"].append(
            commentary["source_id"]
        )
    envelope_payload = portable.freeze_case(case_payload, seed_hex="0" * 64)
    ledger_payload = copy.deepcopy(_scripted_payloads()[1]["payload"])
    ledger_payload["case_fingerprint"] = portable.build_admission_packet(envelope_payload)[
        "safe_metadata"
    ]["source_record_fingerprint"]
    proposed = copy.deepcopy(ledger_payload["entries"][0])
    proposed["ledger_id"] = "invalid-proposed"
    citation = proposed["citations"][0]
    if defect == "unknown-source":
        citation["source_id"] = "unknown-source"
    elif defect == "wrong-quote":
        citation["quote"] = "covered operator notice language"
    elif defect == "out-of-range":
        source_text = envelope_payload["case"]["sources"][0]["normalized_text"]
        citation.update(
            {
                "start_char": len(source_text) + 1,
                "end_char": len(source_text) + 2,
                "quote": "x",
            }
        )
    else:
        citation["source_id"] = "commentary-source"
    payload = {
        "request_fingerprint": "a" * 64,
        "complete": True,
        "disputes": [
            {
                "dispute_id": "invalid-proposed-finding",
                "action": "add",
                "target_ledger_ids": [],
                "proposed_entries": [proposed],
                "materiality": "supporting",
                "rationale": "The source record needs a ledger correction.",
            }
        ],
    }
    core_envelope = freeze_core(_core_case_from_payload(case_payload), seed_hex="0" * 64)
    core_ledger = LegalLedger.model_validate(ledger_payload)
    core_audit = LedgerAudit.model_validate(payload)

    with pytest.raises(
        portable.PortableEvaluationInputError,
        match=rf"invalid-proposed-finding.*{issue_code}",
    ) as portable_error:
        portable.validate_ledger_audit_findings(
            payload, envelope=envelope_payload, proposed_ledger=ledger_payload
        )
    with pytest.raises(
        LedgerInconclusiveErrorCore,
        match=rf"invalid-proposed-finding.*{issue_code}",
    ) as core_error:
        ledger_findings_core(core_envelope, core_ledger, core_audit)
    assert str(portable_error.value) == str(core_error.value)


@pytest.mark.parametrize("candidate_id", ["a", "operator"])
def test_candidate_ids_inside_ordinary_source_values_match_core_packets(
    tmp_path: Path, candidate_id: str
) -> None:
    portable = _load_portable()
    case_payload = _case_payload()
    case_payload["candidates"][0]["candidate_id"] = candidate_id
    assert candidate_id.casefold() in case_payload["sources"][0]["normalized_text"].casefold()
    portable_run = tmp_path / "portable"
    core_run = tmp_path / "core"
    portable.initialize_evaluation(case_payload, portable_run, seed_hex="0" * 64)
    initialize_core(_core_case_from_payload(case_payload), core_run, seed_hex="0" * 64)

    for index, scripted in enumerate(_scripted_payloads(), start=1):
        portable_request = portable.next_judge_request(portable_run)
        core_request = next_core(core_run)
        assert portable_request is not None and core_request is not None
        assert portable.canonical_json_bytes(portable_request) == portable.canonical_json_bytes(
            core_request.model_dump(mode="json")
        )
        response = _response(portable_request, scripted, index)
        portable.submit_judge_response(portable_run, response)
        submit_core(core_run, JudgeResponse.model_validate(response))
    assert portable.next_judge_request(portable_run) is None
    assert next_core(core_run) is None
    for artifact in GOLDEN_ARTIFACTS:
        assert (portable_run / artifact).read_bytes() == (core_run / artifact).read_bytes()
    assert portable.verify_evaluation_run(portable_run).valid


def test_cc0_golden_artifacts_are_byte_identical_to_core(tmp_path: Path) -> None:
    portable = _load_portable()
    core_run = tmp_path / "core"
    portable_run = tmp_path / "portable"
    _run_core(core_run)
    _run_portable(portable, portable_run)
    for artifact in GOLDEN_ARTIFACTS:
        assert (portable_run / artifact).read_bytes() == (core_run / artifact).read_bytes()


def test_renderer_rejects_incoherent_report_matrix_shapes(tmp_path: Path) -> None:
    portable = _load_portable()
    one_run = tmp_path / "one"
    _run_portable(portable, one_run)
    one = json.loads((one_run / "evaluation-result.json").read_text(encoding="utf-8"))

    a_with_b = copy.deepcopy(one)
    a_with_b["requirement_matrix"]["rows"][0]["report_b"] = {
        **copy.deepcopy(a_with_b["requirement_matrix"]["rows"][0]["report_a"]),
        "anonymous_label": "B",
    }
    b_only = copy.deepcopy(one)
    b_only["reports"][0]["anonymous_label"] = "B"
    non_admitted = copy.deepcopy(one)
    non_admitted["readiness"]["status"] = "INCONCLUSIVE"
    noncontiguous = copy.deepcopy(one)
    noncontiguous["requirement_matrix"]["rows"][0]["walk_order"] = 1

    for malformed in (a_with_b, b_only, non_admitted, noncontiguous):
        malformed["result_fingerprint"] = "0" * 64
        malformed["result_fingerprint"] = portable._model_fingerprint(
            malformed, exclude={"result_fingerprint"}
        )
        with pytest.raises(portable.EvaluationIntegrityError, match="malformed"):
            portable.render_evaluation_report(malformed)


@pytest.mark.parametrize(
    ("path", "value", "delete"),
    [
        (("rubric", "unexpected"), "value", False),
        (("rubric", "comparison_margin"), None, True),
        (("readiness", "issue_codes"), ["bad code"], False),
        (("reports", 0, "issue_codes"), ["bad code"], False),
        (("reports", 0, "blocking_codes"), ["bad code"], False),
        (("reports", 0, "critical_recall"), 1, False),
        (("reports", 0, "normalized_score"), True, False),
        (("reports", 0, "walk_minimum"), 4.0, False),
        (("rubric", "comparison_margin"), 5, False),
        (("requirement_matrix", "rows", 0, "citations", 0, "start_char"), False, False),
    ],
    ids=[
        "rubric-extra",
        "rubric-missing",
        "readiness-code",
        "report-issue-code",
        "report-blocking-code",
        "report-float-is-int",
        "report-float-is-bool",
        "walk-minimum-is-float",
        "rubric-float-is-int",
        "citation-int-is-bool",
    ],
)
def test_direct_result_validation_rejects_every_value_core_rejects(
    tmp_path: Path,
    path: tuple[str | int, ...],
    value: object,
    delete: bool,
) -> None:
    portable = _load_portable()
    portable_run = tmp_path / "portable"
    _run_differential(portable, _case_payload(), portable_run, tmp_path / "core-fixture")
    malformed = json.loads(
        (portable_run / "evaluation-result.json").read_text(encoding="utf-8")
    )
    target: Any = malformed
    for segment in path[:-1]:
        target = target[segment]
    final = path[-1]
    if delete:
        target.pop(final)
    else:
        target[final] = value
    _refingerprint_result(portable, malformed)

    with pytest.raises(attorney_artifacts.EvaluationIntegrityError):
        _render_core_result_payload(malformed)
    with pytest.raises(portable.EvaluationIntegrityError):
        portable.render_evaluation_report(malformed)


def test_portable_direct_renderer_requires_the_canonical_terminal_rubric(
    tmp_path: Path,
) -> None:
    portable = _load_portable()
    run = tmp_path / "run"
    _run_portable(portable, run)
    malformed = json.loads((run / "evaluation-result.json").read_text(encoding="utf-8"))
    malformed["rubric"]["comparison_margin"] = 6.0
    _refingerprint_result(portable, malformed)

    with pytest.raises(portable.EvaluationIntegrityError, match="malformed"):
        portable.render_evaluation_report(malformed)


def test_core_differential_vectors_cover_admission_ledger_resolution_and_score() -> None:
    portable = _load_portable()
    case_payload = _case_payload()
    core_case = _case_from_fixture(FIXTURE / "case.json", root=FIXTURE)
    portable_envelope = portable.freeze_case(case_payload, seed_hex="0" * 64)
    core_envelope = freeze_core(core_case, seed_hex="0" * 64)
    assert portable_envelope == core_envelope.model_dump(mode="json")
    assert portable.build_admission_packet(portable_envelope) == packet_core(
        core_envelope
    ).model_dump(mode="json")

    responses = _scripted_payloads()
    portable_readiness = portable.adjudicate_admission(portable_envelope, responses[0]["payload"])
    core_readiness = adjudicate_core(
        core_envelope,
        CaseAdmissionJudgment.model_validate(responses[0]["payload"], strict=True),
    )
    assert portable_readiness == core_readiness.model_dump(mode="json")

    portable_sealed = portable.seal_ledger(
        portable_envelope, responses[1]["payload"], responses[2]["payload"], None
    )
    core_sealed = seal_core(
        core_envelope,
        LegalLedger.model_validate(responses[1]["payload"]),
        LedgerAudit.model_validate(responses[2]["payload"]),
        None,
    )
    assert portable_sealed == core_sealed.model_dump(mode="json")

    portable_resolved = portable.resolve_grades(
        portable_sealed, responses[3]["payload"], responses[4]["payload"]
    )
    core_resolved = resolve_core(
        core_sealed,
        CandidateGrade.model_validate(responses[3]["payload"]),
        CandidateGrade.model_validate(responses[4]["payload"]),
        [],
    )
    checks = portable._derive_deterministic_checks(
        portable._candidate_for_label(portable_envelope, "A"), "A"
    )
    source_record = portable.build_admission_packet(portable_envelope)["payload"]
    assert portable.score_report(
        portable_sealed,
        portable_resolved,
        checks,
        source_record=source_record,
    ) == score_core(
        core_sealed,
        core_resolved,
        DeterministicChecks.model_validate(checks),
        source_record=source_record,
    ).model_dump(mode="json")


@pytest.mark.parametrize(
    "issue_code",
    [
        "AUTHORITY_MISMATCH",
        "OPERATIVE_TEXT_MISSING",
        "CURRENTNESS_EVIDENCE_INSUFFICIENT",
        "LANGUAGE_UNRESOLVED",
        "SOURCE_PARITY_UNPROVEN",
    ],
)
def test_material_admission_issue_codes_fail_closed(issue_code: str) -> None:
    portable = _load_portable()
    envelope = portable.freeze_case(_case_payload(), seed_hex="0" * 64)
    judgment = copy.deepcopy(_scripted_payloads()[0]["payload"])
    judgment["issues"] = [
        {
            "code": issue_code,
            "severity": "error",
            "message": "A material admission defect was found.",
            "related_ids": [],
        }
    ]
    readiness = portable.adjudicate_admission(envelope, judgment)
    assert readiness["status"] == "CASE_INVALID"
    assert readiness["issue_codes"] == [issue_code]


def test_portable_resolved_non_english_source_can_be_admitted() -> None:
    """Portable admission must defer language capability to the fresh judge check."""
    portable = _load_portable()
    case_payload = _case_payload()
    case_payload["sources"][0]["language"] = "fr"
    envelope = portable.freeze_case(case_payload, seed_hex="0" * 64)
    judgment = copy.deepcopy(_scripted_payloads()[0]["payload"])
    request = portable.build_admission_packet(envelope)
    judgment["request_fingerprint"] = request["request_fingerprint"]

    readiness = portable.adjudicate_admission(envelope, judgment)

    assert readiness["status"] == "ADMITTED"
    assert "LANGUAGE_UNRESOLVED" not in readiness["issue_codes"]


def test_portable_non_english_source_with_failed_language_resolution_is_invalid() -> None:
    portable = _load_portable()
    case_payload = _case_payload()
    case_payload["sources"][0]["language"] = "fr"
    envelope = portable.freeze_case(case_payload, seed_hex="0" * 64)
    judgment = copy.deepcopy(_scripted_payloads()[0]["payload"])
    request = portable.build_admission_packet(envelope)
    judgment["request_fingerprint"] = request["request_fingerprint"]
    language_check = next(
        check for check in judgment["checks"] if check["code"] == "LANGUAGE_RESOLUTION"
    )
    language_check["satisfied"] = False

    readiness = portable.adjudicate_admission(envelope, judgment)

    assert readiness["status"] == "CASE_INVALID"
    assert readiness["issue_codes"] == ["LANGUAGE_UNRESOLVED"]


@pytest.mark.parametrize(
    "disposition",
    [
        "COMPLETE",
        "PARTIAL",
        "MISSING",
        "OVERSTATED",
        "CONTRADICTED",
        "UNSUPPORTED",
        "NOT_APPLICABLE",
    ],
)
def test_scoring_disposition_vectors_match_core(disposition: str) -> None:
    portable = _load_portable()
    responses = _scripted_payloads()
    envelope = portable.freeze_case(_case_payload(), seed_hex="0" * 64)
    sealed = portable.seal_ledger(envelope, responses[1]["payload"], responses[2]["payload"], None)
    first = copy.deepcopy(responses[3]["payload"])
    second = copy.deepcopy(responses[4]["payload"])
    for grade in (first, second):
        grade["entry_grades"][0]["disposition"] = disposition
        grade["entry_grades"][0]["report_location"] = (
            None if disposition in {"MISSING", "NOT_APPLICABLE"} else "paragraph 1"
        )
        if disposition == "MISSING":
            grade["entry_grades"][0]["report_passage"] = None
    if disposition == "NOT_APPLICABLE":
        with pytest.raises(portable.EvaluationInconclusiveError):
            portable.resolve_grades(sealed, first, second)
        with pytest.raises(GradeInconclusiveError):
            resolve_core(
                SealedLedger.model_validate(sealed),
                CandidateGrade.model_validate(first),
                CandidateGrade.model_validate(second),
                [],
            )
        return
    resolved = portable.resolve_grades(sealed, first, second)
    checks = portable._derive_deterministic_checks(
        portable._candidate_for_label(envelope, "A"), "A"
    )
    source_record = portable.build_admission_packet(envelope)["payload"]
    portable_score = portable.score_report(
        sealed,
        resolved,
        checks,
        source_record=source_record,
    )

    core_sealed = SealedLedger.model_validate(sealed)
    core_resolved = resolve_core(
        core_sealed,
        CandidateGrade.model_validate(first),
        CandidateGrade.model_validate(second),
        [],
    )
    assert portable_score == score_core(
        core_sealed,
        core_resolved,
        DeterministicChecks.model_validate(checks),
        source_record=source_record,
    ).model_dump(mode="json")


def test_multi_code_finding_diagnostics_match_core_and_portable() -> None:
    portable = _load_portable()
    responses = _scripted_payloads()
    envelope = portable.freeze_case(_case_payload(), seed_hex="0" * 64)
    sealed = portable.seal_ledger(
        envelope,
        responses[1]["payload"],
        responses[2]["payload"],
        None,
    )
    grade = copy.deepcopy(responses[3]["payload"])
    finding = next(
        item for item in grade["entry_grades"] if item["ledger_id"] == "file-notice"
    )
    finding["disposition"] = "COMPLETE"
    finding["finding_codes"] = [
        "CRITICAL_LEDGER_ENTRY_MISSING",
        "MATERIAL_EXCEPTION_MISSING",
        "CONSEQUENCE_TRIGGER_DETACHED",
    ]

    portable_grade, portable_issues = portable.validate_grade(sealed, grade)
    portable_diagnostics = portable._grade_issue_diagnostics(
        sealed,
        portable_grade,
        portable_issues,
    )
    core_issues = validate_grade_core(
        SealedLedger.model_validate(sealed),
        CandidateGrade.model_validate(grade),
    )
    core_diagnostics = [f"{issue.code}: {issue.message}" for issue in core_issues]

    assert core_diagnostics == portable_diagnostics
    assert [
        message.split(" finding_code=", maxsplit=1)[1].split(" ", maxsplit=1)[0]
        for message in portable_diagnostics
    ] == finding["finding_codes"]
    assert all("ledger_id=file-notice" in message for message in portable_diagnostics)


def test_portable_invalid_finding_diagnostic_is_specific_and_anonymous_safe(
    tmp_path: Path,
) -> None:
    portable = _load_portable()
    run = tmp_path / "run"
    request = _advance_portable_to_first_grade(portable, run)
    payload = copy.deepcopy(_scripted_payloads()[3]["payload"])
    payload["request_fingerprint"] = request["request_fingerprint"]
    payload["anonymous_label"] = request["safe_metadata"]["anonymous_label"]
    payload["ledger_fingerprint"] = request["safe_metadata"][
        "legal_ledger_fingerprint"
    ]
    finding = next(
        item for item in payload["entry_grades"] if item["ledger_id"] == "file-notice"
    )
    finding["disposition"] = "PARTIAL"
    finding["finding_codes"] = ["MATERIAL_EXCEPTION_MISSING"]

    state = portable.submit_judge_response(
        run,
        _response(request, {"payload": payload}, 4),
    )
    diagnostics = json.loads(
        (run / "judge-diagnostics/grade-A-1-attempt-1.json").read_text(
            encoding="utf-8"
        )
    )
    message = diagnostics["issues"][0]["message"]

    assert state["attempt"] == 2
    assert "ledger_id=file-notice" in message
    assert "finding_code=MATERIAL_EXCEPTION_MISSING" in message
    assert (
        "allowed_context=disposition in [MISSING, PARTIAL]; category=exception; "
        "materiality in [critical, material]" in message
    )
    for forbidden in (
        "synthetic-harvest",
        "candidate_id",
        "mapping",
        payload["entry_grades"][0]["report_passage"],
    ):
        assert forbidden not in message


def test_portable_unknown_ledger_id_is_not_echoed_in_diagnostics(tmp_path: Path) -> None:
    portable = _load_portable()
    run = tmp_path / "run"
    request = _advance_portable_to_first_grade(portable, run)
    payload = copy.deepcopy(_scripted_payloads()[3]["payload"])
    payload["request_fingerprint"] = request["request_fingerprint"]
    payload["anonymous_label"] = request["safe_metadata"]["anonymous_label"]
    payload["ledger_fingerprint"] = request["safe_metadata"][
        "legal_ledger_fingerprint"
    ]
    payload["entry_grades"][0]["ledger_id"] = "synthetic-harvest"
    payload["entry_grades"][0]["finding_codes"] = ["MATERIAL_EXCEPTION_MISSING"]

    portable.submit_judge_response(
        run,
        _response(request, {"payload": payload}, 4),
    )
    diagnostics = json.loads(
        (run / "judge-diagnostics/grade-A-1-attempt-1.json").read_text(
            encoding="utf-8"
        )
    )

    assert "synthetic-harvest" not in diagnostics["issues"][0]["message"]


def test_multi_code_retry_diagnostics_and_hash_match_core_and_portable(
    tmp_path: Path,
) -> None:
    portable = _load_portable()
    case_payload = _case_payload()
    portable_run = tmp_path / "portable"
    core_run = tmp_path / "core"
    portable.initialize_evaluation(case_payload, portable_run, seed_hex="0" * 64)
    initialize_core(_core_case_from_payload(case_payload), core_run, seed_hex="0" * 64)
    for index, item in enumerate(_scripted_payloads()[:3], start=1):
        portable_request = portable.next_judge_request(portable_run)
        core_request = next_core(core_run)
        assert portable_request is not None and core_request is not None
        assert portable_request == core_request.model_dump(mode="json")
        payload = copy.deepcopy(item["payload"])
        if "request_fingerprint" in payload:
            payload["request_fingerprint"] = portable_request["request_fingerprint"]
        response = _response(portable_request, {"payload": payload}, index)
        portable.submit_judge_response(portable_run, response)
        submit_core(core_run, JudgeResponse.model_validate(response))
    portable_request = portable.next_judge_request(portable_run)
    core_request = next_core(core_run)
    assert portable_request is not None and core_request is not None
    assert portable_request == core_request.model_dump(mode="json")
    grade = copy.deepcopy(_scripted_payloads()[3]["payload"])
    grade["request_fingerprint"] = portable_request["request_fingerprint"]
    grade["anonymous_label"] = portable_request["safe_metadata"]["anonymous_label"]
    grade["ledger_fingerprint"] = portable_request["safe_metadata"][
        "legal_ledger_fingerprint"
    ]
    finding = next(
        item for item in grade["entry_grades"] if item["ledger_id"] == "file-notice"
    )
    finding["disposition"] = "COMPLETE"
    finding["finding_codes"] = [
        "CRITICAL_LEDGER_ENTRY_MISSING",
        "MATERIAL_EXCEPTION_MISSING",
        "CONSEQUENCE_TRIGGER_DETACHED",
    ]
    response = _response(portable_request, {"payload": grade}, 4)

    portable_state = portable.submit_judge_response(portable_run, response)
    core_state = submit_core(core_run, JudgeResponse.model_validate(response))
    diagnostic_path = "judge-diagnostics/grade-A-1-attempt-1.json"
    portable_diagnostics = (portable_run / diagnostic_path).read_bytes()
    core_diagnostics = (core_run / diagnostic_path).read_bytes()
    diagnostic_hash = hashlib.sha256(portable_diagnostics).hexdigest()
    portable_manifest = json.loads(
        (portable_run / "run-manifest.json").read_text(encoding="utf-8")
    )
    core_manifest = json.loads(
        (core_run / "run-manifest.json").read_text(encoding="utf-8")
    )

    assert portable_state["attempt"] == core_state.attempt == 2
    assert portable_diagnostics == core_diagnostics
    for manifest in (portable_manifest, core_manifest):
        diagnostic_record = next(
            item for item in manifest["artifacts"] if item["artifact_path"] == diagnostic_path
        )
        assert diagnostic_record["artifact_hash"] == diagnostic_hash
    message = json.loads(portable_diagnostics)["issues"][0]["message"]
    assert [message.count(f"finding_code={code}") for code in finding["finding_codes"]] == [
        1,
        1,
        1,
    ]
    for forbidden in (
        "synthetic-harvest",
        "candidate_id",
        "mapping",
        finding["report_passage"],
    ):
        assert forbidden not in message
    portable_retry = portable.next_judge_request(portable_run)
    core_retry = next_core(core_run)
    assert portable_retry is not None and core_retry is not None
    assert portable_retry == core_retry.model_dump(mode="json")
    assert portable.verify_evaluation_run(portable_run).valid
    assert attorney_artifacts.verify_evaluation_run(core_run).valid


def test_portable_compare_reports_requires_keyword_only_score_inputs() -> None:
    portable = _load_portable()
    fixture = _portable_comparison_fixture(portable)

    with pytest.raises(TypeError, match="candidate_inputs"):
        portable.compare_reports(fixture["candidate"], fixture["comparator"])


def test_portable_comparison_rejects_fabricated_rehashed_report() -> None:
    portable = _load_portable()
    fixture = _portable_comparison_fixture(portable)
    fabricated = copy.deepcopy(fixture["candidate"])
    fabricated["absolute_disposition"] = "FAIL"
    fabricated["blocking_codes"] = ["FABRICATED_BLOCKER"]
    fabricated["score_fingerprint"] = portable._model_fingerprint(
        fabricated,
        exclude={"score_fingerprint"},
    )

    with pytest.raises(
        portable.EvaluationInconclusiveError,
        match="replayed score inputs",
    ):
        portable.compare_reports(
            fabricated,
            fixture["comparator"],
            candidate_inputs=fixture["candidate_inputs"],
            comparator_inputs=fixture["comparator_inputs"],
        )


@pytest.mark.parametrize("side", ["candidate_inputs", "comparator_inputs"])
@pytest.mark.parametrize(
    "mutation",
    ["fingerprint", "source_id", "bounds", "quote"],
)
def test_portable_comparison_rejects_mutated_exact_evidence_in_either_input(
    side: str,
    mutation: str,
) -> None:
    portable = _load_portable()
    fixture = _portable_comparison_fixture(portable)
    score_inputs = copy.deepcopy(fixture[side])

    def mutate_exact_evidence(value: object) -> None:
        if isinstance(value, dict):
            if value.get("evidence_basis") == "source_spans":
                span = value["evidence_spans"][0]
                if mutation == "fingerprint":
                    value["source_record_fingerprint"] = "f" * 64
                elif mutation == "source_id":
                    span["source_id"] = "unknown-source"
                elif mutation == "bounds":
                    span["end_char"] = (
                        len(
                            score_inputs["source_record"]["sources"][0][
                                "normalized_text"
                            ]
                        )
                        + 1
                    )
                else:
                    span["quote"] = "fabricated exact quote"
            for child in value.values():
                mutate_exact_evidence(child)
        elif isinstance(value, list):
            for child in value:
                mutate_exact_evidence(child)

    mutate_exact_evidence(score_inputs["resolved_grade"])
    _rebind_portable_resolution_fingerprint(portable, score_inputs)

    with pytest.raises(
        portable.EvaluationInconclusiveError,
        match=r"source record|exact source span",
    ):
        portable.compare_reports(
            fixture["candidate"],
            fixture["comparator"],
            candidate_inputs=(
                score_inputs if side == "candidate_inputs" else fixture["candidate_inputs"]
            ),
            comparator_inputs=(
                score_inputs if side == "comparator_inputs" else fixture["comparator_inputs"]
            ),
        )


@pytest.mark.parametrize("mutation", ["sealed_ledger", "source_record"])
def test_portable_comparison_requires_same_ledger_and_common_source_record(
    mutation: str,
) -> None:
    portable = _load_portable()
    fixture = _portable_comparison_fixture(portable)
    comparator_inputs = copy.deepcopy(fixture["comparator_inputs"])
    if mutation == "sealed_ledger":
        comparator_inputs["sealed_ledger"]["audit_fingerprint"] = "f" * 64
    else:
        source_record = comparator_inputs["source_record"]
        source_record["question"] = "A different closed-universe question?"
        projection = {
            key: value
            for key, value in source_record.items()
            if key != "source_record_fingerprint"
        }
        source_record["source_record_fingerprint"] = hashlib.sha256(
            portable.canonical_json_bytes(projection)
        ).hexdigest()

    with pytest.raises(
        portable.EvaluationInconclusiveError,
        match=r"same strict sealed ledger|same common source record|bind the scoring source record",
    ):
        portable.compare_reports(
            fixture["candidate"],
            fixture["comparator"],
            candidate_inputs=fixture["candidate_inputs"],
            comparator_inputs=comparator_inputs,
        )


def test_comparison_and_score_threshold_vectors_match_core() -> None:
    portable = _load_portable()
    responses = _scripted_payloads()
    envelope = portable.freeze_case(_case_payload(), seed_hex="0" * 64)
    sealed = portable.seal_ledger(envelope, responses[1]["payload"], responses[2]["payload"], None)
    checks_a = portable._derive_deterministic_checks(
        portable._candidate_for_label(envelope, "A"), "A"
    )
    grade_a_1 = copy.deepcopy(responses[3]["payload"])
    grade_a_2 = copy.deepcopy(responses[4]["payload"])
    grade_b_1 = copy.deepcopy(grade_a_1)
    grade_b_2 = copy.deepcopy(grade_a_2)
    for grade in (grade_b_1, grade_b_2):
        grade["anonymous_label"] = "B"
        grade["request_fingerprint"] = "b" * 64
        grade["narrative_scores"][0]["score"] = 3
    resolved_a = portable.resolve_grades(sealed, grade_a_1, grade_a_2)
    resolved_b = portable.resolve_grades(sealed, grade_b_1, grade_b_2)
    checks_b = copy.deepcopy(checks_a)
    checks_b["anonymous_label"] = "B"
    source_record = portable.build_admission_packet(envelope)["payload"]
    score_a = portable.score_report(
        sealed,
        resolved_a,
        checks_a,
        source_record=source_record,
    )
    score_b = portable.score_report(
        sealed,
        resolved_b,
        checks_b,
        source_record=source_record,
    )
    candidate_input_payload = {
        "schema_version": "1.4",
        "anonymous_label": "A",
        "sealed_ledger": sealed,
        "resolved_grade": {"schema_version": "1.3", **resolved_a},
        "deterministic_checks": checks_a,
        "rubric": copy.deepcopy(portable.RUBRIC_V1),
        "source_record": source_record,
    }
    comparator_input_payload = {
        "schema_version": "1.4",
        "anonymous_label": "B",
        "sealed_ledger": sealed,
        "resolved_grade": {"schema_version": "1.3", **resolved_b},
        "deterministic_checks": checks_b,
        "rubric": copy.deepcopy(portable.RUBRIC_V1),
        "source_record": source_record,
    }
    portable_comparison = portable.compare_reports(
        score_a,
        score_b,
        candidate_inputs=candidate_input_payload,
        comparator_inputs=comparator_input_payload,
    )

    core_sealed = SealedLedger.model_validate(sealed)
    core_resolved_a = resolve_core(
        core_sealed,
        CandidateGrade.model_validate(grade_a_1),
        CandidateGrade.model_validate(grade_a_2),
        [],
    )
    core_resolved_b = resolve_core(
        core_sealed,
        CandidateGrade.model_validate(grade_b_1),
        CandidateGrade.model_validate(grade_b_2),
        [],
    )
    core_checks_a = DeterministicChecks.model_validate(checks_a)
    core_checks_b = DeterministicChecks.model_validate(checks_b)
    core_score_a = score_core(
        core_sealed,
        core_resolved_a,
        core_checks_a,
        source_record=source_record,
    )
    core_score_b = score_core(
        core_sealed,
        core_resolved_b,
        core_checks_b,
        source_record=source_record,
    )
    expected = compare_core(
        core_score_a,
        core_score_b,
        candidate_inputs=ReportScoreInputs(
            sealed_ledger=core_sealed,
            resolved_grade=core_resolved_a,
            deterministic_checks=core_checks_a,
            source_record=portable.canonical_json_bytes(source_record),
        ),
        comparator_inputs=ReportScoreInputs(
            sealed_ledger=core_sealed,
            resolved_grade=core_resolved_b,
            deterministic_checks=core_checks_b,
            source_record=portable.canonical_json_bytes(source_record),
        ),
    )
    assert portable_comparison == expected.model_dump(mode="json")


@pytest.mark.parametrize(
    ("ledger_id", "disposition", "finding_code"),
    [
        ("file-notice", "MISSING", "CRITICAL_LEDGER_ENTRY_MISSING"),
        ("emergency-exception", "MISSING", "MATERIAL_EXCEPTION_MISSING"),
        ("emergency-exception", "PARTIAL", "MATERIAL_EXCEPTION_MISSING"),
        ("bureau-order", "PARTIAL", "CONSEQUENCE_TRIGGER_DETACHED"),
    ],
)
def test_entry_finding_code_vectors_match_core(
    ledger_id: str, disposition: str, finding_code: str
) -> None:
    portable = _load_portable()
    responses = _scripted_payloads()
    envelope = portable.freeze_case(_case_payload(), seed_hex="0" * 64)
    sealed = portable.seal_ledger(envelope, responses[1]["payload"], responses[2]["payload"], None)
    first = copy.deepcopy(responses[3]["payload"])
    second = copy.deepcopy(responses[4]["payload"])
    for grade in (first, second):
        entry = next(item for item in grade["entry_grades"] if item["ledger_id"] == ledger_id)
        entry["disposition"] = disposition
        entry["report_location"] = None if disposition == "MISSING" else "paragraph 1"
        entry["report_passage"] = (
            None if disposition == "MISSING" else entry["report_passage"]
        )
        entry["finding_codes"] = [finding_code]
    resolved = portable.resolve_grades(sealed, first, second)
    checks = portable._derive_deterministic_checks(
        portable._candidate_for_label(envelope, "A"), "A"
    )
    source_record = portable.build_admission_packet(envelope)["payload"]
    portable_score = portable.score_report(
        sealed,
        resolved,
        checks,
        source_record=source_record,
    )
    core_sealed = SealedLedger.model_validate(sealed)
    core_resolved = resolve_core(
        core_sealed,
        CandidateGrade.model_validate(first),
        CandidateGrade.model_validate(second),
        [],
    )
    assert portable_score == score_core(
        core_sealed,
        core_resolved,
        DeterministicChecks.model_validate(checks),
        source_record=source_record,
    ).model_dump(mode="json")


@pytest.mark.parametrize("dimension", ["key_requirements", "requirements_workplan_boundary"])
def test_narrative_finding_code_vectors_match_core(dimension: str) -> None:
    portable = _load_portable()
    responses = _scripted_payloads()
    envelope = portable.freeze_case(_case_payload(), seed_hex="0" * 64)
    sealed = portable.seal_ledger(envelope, responses[1]["payload"], responses[2]["payload"], None)
    first = copy.deepcopy(responses[3]["payload"])
    second = copy.deepcopy(responses[4]["payload"])
    for grade in (first, second):
        narrative = next(
            item for item in grade["narrative_scores"] if item["dimension"] == dimension
        )
        narrative["score"] = 2
        narrative["finding_codes"] = ["KEY_REQUIREMENTS_ACTION_PLAN"]
    resolved = portable.resolve_grades(sealed, first, second)
    checks = portable._derive_deterministic_checks(
        portable._candidate_for_label(envelope, "A"), "A"
    )
    source_record = portable.build_admission_packet(envelope)["payload"]
    portable_score = portable.score_report(
        sealed,
        resolved,
        checks,
        source_record=source_record,
    )
    core_sealed = SealedLedger.model_validate(sealed)
    core_resolved = resolve_core(
        core_sealed,
        CandidateGrade.model_validate(first),
        CandidateGrade.model_validate(second),
        [],
    )
    assert portable_score == score_core(
        core_sealed,
        core_resolved,
        DeterministicChecks.model_validate(checks),
        source_record=source_record,
    ).model_dump(mode="json")


def test_exact_scoring_floor_boundaries_match_core() -> None:
    portable = _load_portable()
    responses = _scripted_payloads()
    envelope = portable.freeze_case(_case_payload(), seed_hex="0" * 64)
    ledger = copy.deepcopy(responses[1]["payload"])
    ledger["entries"] = ledger["entries"][:4]
    ledger["entries"][2]["materiality"] = "supporting"
    ledger["entries"][3]["materiality"] = "supporting"
    for index, entry in enumerate(ledger["entries"]):
        entry["walk_order"] = index
    audit = copy.deepcopy(responses[2]["payload"])
    sealed = portable.seal_ledger(envelope, ledger, audit, None)

    first = copy.deepcopy(responses[3]["payload"])
    second = copy.deepcopy(responses[4]["payload"])
    retained_ids = {entry["ledger_id"] for entry in ledger["entries"]}
    source_record = portable.build_admission_packet(envelope)["payload"]
    source_record_fingerprint = source_record["source_record_fingerprint"]
    source = source_record["sources"][0]
    evidence_quote = source["normalized_text"][0:1]
    narrative_values = (2, 3, 3, 3, 3, 3, 3, 4)
    for grade in (first, second):
        grade["ledger_fingerprint"] = sealed["ledger_fingerprint"]
        grade["entry_grades"] = [
            item for item in grade["entry_grades"] if item["ledger_id"] in retained_ids
        ]
        missing = next(
            item for item in grade["entry_grades"] if item["ledger_id"] == "notice-deadline"
        )
        missing["disposition"] = "MISSING"
        missing["report_location"] = None
        missing["report_passage"] = None
        for narrative, value in zip(grade["narrative_scores"], narrative_values, strict=True):
            narrative["score"] = value
        grade["out_of_ledger_claims"] = [
            {
                "claim_id": f"claim-{index}",
                "claim_text": f"Supported ancillary statement {index}.",
                "report_location": f"paragraph {index + 1}",
                "disposition": "PARTIAL" if index == 9 else "COMPLETE",
                "category": "definition",
                "materiality": "supporting",
                "source_record_fingerprint": source_record_fingerprint,
                "evidence_basis": "source_spans",
                "evidence_spans": [
                    {
                        "source_id": source["source_id"],
                        "start_char": 0,
                        "end_char": 1,
                        "quote": evidence_quote,
                    }
                ],
                "rationale": "The claim is evaluated against the source record.",
                "related_ledger_ids": [],
            }
            for index in range(10)
        ]
    resolved = portable.resolve_grades(sealed, first, second)
    checks = portable._derive_deterministic_checks(
        portable._candidate_for_label(envelope, "A"), "A"
    )
    portable_score = portable.score_report(
        sealed,
        resolved,
        checks,
        source_record=source_record,
    )
    assert portable_score["critical_recall"] == 1.0
    assert portable_score["weighted_recall"] == 0.9
    assert portable_score["claim_precision"] == 0.95
    assert portable_score["walk_average"] == 3.0
    assert portable_score["walk_minimum"] == 2
    assert portable_score["absolute_disposition"] == "PASS"

    core_sealed = SealedLedger.model_validate(sealed)
    core_resolved = resolve_core(
        core_sealed,
        CandidateGrade.model_validate(first),
        CandidateGrade.model_validate(second),
        [],
    )
    assert portable_score == score_core(
        core_sealed,
        core_resolved,
        DeterministicChecks.model_validate(checks),
        source_record=source_record,
    ).model_dump(mode="json")


def test_portable_valid_source_bearing_inputs_reproduce_full_exact_comparison() -> None:
    portable = _load_portable()
    fixture = _portable_comparison_fixture(portable)

    actual = portable.compare_reports(
        fixture["candidate"],
        fixture["comparator"],
        candidate_inputs=fixture["candidate_inputs"],
        comparator_inputs=fixture["comparator_inputs"],
    )

    candidate_inputs = fixture["candidate_inputs"]
    comparator_inputs = fixture["comparator_inputs"]
    core_sealed = SealedLedger.model_validate(candidate_inputs["sealed_ledger"])
    core_candidate_resolved = resolve_core(
        core_sealed,
        CandidateGrade.model_validate(
            candidate_inputs["resolved_grade"]["original_grader_1"]
        ),
        CandidateGrade.model_validate(
            candidate_inputs["resolved_grade"]["original_grader_2"]
        ),
        [],
    )
    core_comparator_resolved = resolve_core(
        core_sealed,
        CandidateGrade.model_validate(
            comparator_inputs["resolved_grade"]["original_grader_1"]
        ),
        CandidateGrade.model_validate(
            comparator_inputs["resolved_grade"]["original_grader_2"]
        ),
        [],
    )
    core_candidate_checks = DeterministicChecks.model_validate(
        candidate_inputs["deterministic_checks"]
    )
    core_comparator_checks = DeterministicChecks.model_validate(
        comparator_inputs["deterministic_checks"]
    )
    source_record_bytes = portable.canonical_json_bytes(
        candidate_inputs["source_record"]
    )
    expected = compare_core(
        score_core(
            core_sealed,
            core_candidate_resolved,
            core_candidate_checks,
            source_record=candidate_inputs["source_record"],
        ),
        score_core(
            core_sealed,
            core_comparator_resolved,
            core_comparator_checks,
            source_record=candidate_inputs["source_record"],
        ),
        candidate_inputs=ReportScoreInputs(
            sealed_ledger=core_sealed,
            resolved_grade=core_candidate_resolved,
            deterministic_checks=core_candidate_checks,
            source_record=source_record_bytes,
        ),
        comparator_inputs=ReportScoreInputs(
            sealed_ledger=core_sealed,
            resolved_grade=core_comparator_resolved,
            deterministic_checks=core_comparator_checks,
            source_record=source_record_bytes,
        ),
    )

    assert actual == expected.model_dump(mode="json")


def test_duplicate_and_out_of_order_responses_do_not_advance(tmp_path: Path) -> None:
    portable = _load_portable()
    run = tmp_path / "run"
    portable.initialize_evaluation(_case_payload(), run, seed_hex="0" * 64)
    request = portable.next_judge_request(run)
    assert request is not None
    item = _scripted_payloads()[0]
    response = _response(request, item, 1)
    portable.submit_judge_response(run, response)
    state_before = portable.resume_evaluation(run)
    with pytest.raises(portable.PortableEvaluationInputError):
        portable.submit_judge_response(run, response)
    assert portable.resume_evaluation(run) == state_before
    wrong = copy.deepcopy(response)
    wrong["operation"] = "grade_report"
    with pytest.raises(portable.PortableEvaluationInputError):
        portable.submit_judge_response(run, wrong)
    assert portable.resume_evaluation(run) == state_before


@pytest.mark.parametrize(
    ("overridden_isolation", "expected"),
    [
        (None, "fresh_context"),
        ("sequential_same_context", "sequential_same_context"),
    ],
)
def test_terminal_result_aggregates_judge_isolation_conservatively(
    tmp_path: Path,
    overridden_isolation: str | None,
    expected: str,
) -> None:
    """One sequential call must downgrade the terminal isolation declaration."""
    portable = _load_portable()
    run = tmp_path / "run"
    portable.initialize_evaluation(_case_payload(), run, seed_hex="0" * 64)
    for index, item in enumerate(_scripted_payloads(), start=1):
        request = portable.next_judge_request(run)
        assert request is not None
        response = _response(request, item, index)
        if overridden_isolation is not None and index == 2:
            response["judge_isolation"] = overridden_isolation
        portable.submit_judge_response(run, response)

    result = json.loads((run / "evaluation-result.json").read_text(encoding="utf-8"))
    report = (run / "evaluation-report.md").read_text(encoding="utf-8")
    assert result["schema_version"] == "1.3"
    assert result["judge_isolation"] == expected
    assert f"- Aggregate judge isolation: {expected}." in report
    assert portable.verify_evaluation_run(run).valid


def test_verifier_recomputes_aggregate_judge_isolation(tmp_path: Path) -> None:
    """Rehashing a stronger isolation claim must not make the run verify."""
    portable = _load_portable()
    run = tmp_path / "run"
    portable.initialize_evaluation(_case_payload(), run, seed_hex="0" * 64)
    for index, item in enumerate(_scripted_payloads(), start=1):
        request = portable.next_judge_request(run)
        assert request is not None
        response = _response(request, item, index)
        if index == 2:
            response["judge_isolation"] = "sequential_same_context"
        portable.submit_judge_response(run, response)

    result_path = run / "evaluation-result.json"
    result = json.loads(result_path.read_text(encoding="utf-8"))
    assert result["judge_isolation"] == "sequential_same_context"
    result["judge_isolation"] = "fresh_context"
    result["result_fingerprint"] = "0" * 64
    result["result_fingerprint"] = portable._model_fingerprint(
        result, exclude={"result_fingerprint"}
    )
    result_path.write_bytes(portable.canonical_json_bytes(result))
    (run / "evaluation-report.md").write_text(
        portable.render_evaluation_report(result), encoding="utf-8"
    )
    manifest_path = run / "run-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["result_hash"] = hashlib.sha256(result_path.read_bytes()).hexdigest()
    manifest_path.write_bytes(portable.canonical_json_bytes(manifest))
    _rehash_manifest_artifact(portable, run, "evaluation-result.json")
    _rehash_manifest_artifact(portable, run, "evaluation-report.md")

    assert portable.verify_evaluation_run(run).issues == ("EVALUATION_INTEGRITY_INVALID",)


def test_invalid_response_retries_once_then_becomes_inconclusive(tmp_path: Path) -> None:
    portable = _load_portable()
    run = tmp_path / "run"
    portable.initialize_evaluation(_case_payload(), run, seed_hex="0" * 64)
    first = portable.next_judge_request(run)
    assert first is not None
    invalid = _response(first, {"payload": {"malformed": True}}, 1)
    retry = portable.submit_judge_response(run, invalid)
    assert retry["attempt"] == 2
    second = portable.next_judge_request(run)
    assert second == first
    terminal = portable.submit_judge_response(
        run, _response(second, {"payload": {"still": "malformed"}}, 2)
    )
    assert terminal["state"] == "inconclusive"
    assert terminal["terminal_status"] == "inconclusive"
    result = json.loads((run / "evaluation-result.json").read_text(encoding="utf-8"))
    assert result["schema_version"] == "1.3"
    assert result["readiness"]["status"] == "INCONCLUSIVE"
    assert "JUDGE_RESPONSE_INVALID" in result["readiness"]["issue_codes"]
    assert result["requirement_matrix"] == {
        "available": False,
        "rows": [],
        "unavailable_reason": "INCONCLUSIVE",
    }


def test_case_invalid_terminal_phase_stops_after_admission(tmp_path: Path) -> None:
    portable = _load_portable()
    portable_run = tmp_path / "portable"
    core_run = tmp_path / "core"
    case_payload = _case_payload()
    portable.initialize_evaluation(case_payload, portable_run, seed_hex="0" * 64)
    initialize_core(_core_case_from_payload(case_payload), core_run, seed_hex="0" * 64)
    request = portable.next_judge_request(portable_run)
    core_request = next_core(core_run)
    assert request is not None and core_request is not None
    assert portable.canonical_json_bytes(request) == portable.canonical_json_bytes(
        core_request.model_dump(mode="json")
    )
    payload = copy.deepcopy(_scripted_payloads()[0]["payload"])
    payload["request_fingerprint"] = request["request_fingerprint"]
    check = next(item for item in payload["checks"] if item["code"] == "OPERATIVE_TEXT")
    check["satisfied"] = False
    response = _response(request, {"payload": payload}, 1)
    terminal = portable.submit_judge_response(portable_run, response)
    core_terminal = submit_core(core_run, JudgeResponse.model_validate(response))
    assert terminal == core_terminal.model_dump(mode="json")
    assert terminal["state"] == "case-invalid"
    assert terminal["terminal_status"] == "case-invalid"
    assert portable.next_judge_request(portable_run) is None
    assert next_core(core_run) is None
    for artifact in ("case-readiness.json", "evaluation-result.json", "evaluation-report.md"):
        assert (portable_run / artifact).read_bytes() == (core_run / artifact).read_bytes()
    result = json.loads((portable_run / "evaluation-result.json").read_text(encoding="utf-8"))
    assert result["requirement_matrix"] == {
        "available": False,
        "rows": [],
        "unavailable_reason": "CASE_INVALID",
    }
    assert portable.verify_evaluation_run(portable_run).valid


@pytest.mark.parametrize(
    "invalid_grade_schema",
    [pytest.param("1.2", id="old-version"), pytest.param(None, id="omitted")],
)
def test_invalid_grade_schema_retries_but_completed_grade_requires_explicit_13(
    tmp_path: Path, invalid_grade_schema: str | None
) -> None:
    portable = _load_portable()
    portable_run = tmp_path / "portable"
    core_run = tmp_path / "core"
    case_payload = _case_payload()
    portable.initialize_evaluation(case_payload, portable_run, seed_hex="0" * 64)
    initialize_core(_core_case_from_payload(case_payload), core_run, seed_hex="0" * 64)
    grade_counts: dict[str, int] = {}
    response_number = 0
    rejected_old_grade = False

    while True:
        request = portable.next_judge_request(portable_run)
        core_request = next_core(core_run)
        if request is None or core_request is None:
            assert request is None and core_request is None
            break
        assert portable.canonical_json_bytes(request) == portable.canonical_json_bytes(
            core_request.model_dump(mode="json")
        )
        payload = _differential_payload(request, grade_counts)
        if request["operation"] == "grade_report" and not rejected_old_grade:
            if invalid_grade_schema is None:
                payload.pop("schema_version")
            else:
                payload["schema_version"] = invalid_grade_schema
            rejected_old_grade = True
            grade_counts[request["safe_metadata"]["anonymous_label"]] -= 1
        response_number += 1
        response = _response(request, {"payload": payload}, response_number)
        portable_state = portable.submit_judge_response(portable_run, response)
        core_state = submit_core(core_run, JudgeResponse.model_validate(response))
        assert portable_state == core_state.model_dump(mode="json")

    assert rejected_old_grade
    assert portable.verify_evaluation_run(portable_run).valid
    failed_response = json.loads(
        (portable_run / "judge-responses" / "grade-A-1-attempt-1.json").read_text(
            encoding="utf-8"
        )
    )
    assert failed_response["schema_version"] == "1.0"
    if invalid_grade_schema is None:
        assert "schema_version" not in failed_response["payload"]
    else:
        assert failed_response["payload"]["schema_version"] == invalid_grade_schema
    completed_response = json.loads(
        (portable_run / "judge-responses" / "grade-A-1-attempt-2.json").read_text(
            encoding="utf-8"
        )
    )
    assert completed_response["schema_version"] == "1.0"
    assert completed_response["payload"]["schema_version"] == "1.3"


def _repair_and_referee_payload(
    request: dict[str, Any],
    scripted: list[dict[str, Any]],
    grade_count: list[int],
    *,
    omit_defaults: bool = False,
) -> dict[str, Any]:
    operation = request["operation"]
    if operation == "admit_case":
        payload = copy.deepcopy(scripted[0]["payload"])
        if omit_defaults:
            payload.pop("issues")
    elif operation == "build_ledger":
        payload = copy.deepcopy(scripted[1]["payload"])
        if omit_defaults:
            payload.pop("gaps")
    elif operation == "audit_ledger":
        dispute = {
            "dispute_id": "file-notice-materiality",
            "action": "materiality",
            "target_ledger_ids": ["file-notice"],
            "proposed_entries": [],
            "materiality": "critical",
            "rationale": "Materiality needs an independent source-grounded decision.",
        }
        if omit_defaults:
            dispute.pop("proposed_entries")
        payload = {
            "request_fingerprint": request["request_fingerprint"],
            "complete": True,
            "disputes": [dispute],
        }
    elif operation == "repair_ledger":
        repaired = copy.deepcopy(request["payload"]["proposed_ledger"])
        dispute = {
            "dispute_id": "file-notice-materiality",
            "action": "materiality",
            "target_ledger_ids": ["file-notice"],
            "proposed_entries": [],
            "materiality": "critical",
            "rationale": "Materiality still needs an independent decision.",
        }
        if omit_defaults:
            repaired.pop("gaps")
            dispute.pop("proposed_entries")
        payload = {
            "repaired_ledger": repaired,
            "remaining_audit": {
                "request_fingerprint": request["request_fingerprint"],
                "complete": True,
                "disputes": [dispute],
            },
        }
    elif operation == "referee" and request["safe_metadata"]["referee_scope"] == "ledger":
        payload = {
            "dispute_id": "file-notice-materiality",
            "selected_ledger_resolution": "accept_a",
            "selected_grade_resolution": None,
            "replacement_entries": [],
            "replacement_grade_alternative": None,
            "selected_disposition": None,
            "grade_dispute_fingerprint": None,
            "rationale": "The original ledger treatment is source supported.",
            "source_ids": ["synthetic-rule-1-source"],
        }
        if omit_defaults:
            for key in (
                "selected_grade_resolution",
                "replacement_entries",
                "replacement_grade_alternative",
                "selected_disposition",
                "grade_dispute_fingerprint",
            ):
                payload.pop(key)
    elif operation == "grade_report":
        grade_count[0] += 1
        payload = copy.deepcopy(scripted[3 if grade_count[0] == 1 else 4]["payload"])
        payload["request_fingerprint"] = request["request_fingerprint"]
        payload["anonymous_label"] = request["safe_metadata"]["anonymous_label"]
        payload["ledger_fingerprint"] = request["safe_metadata"]["legal_ledger_fingerprint"]
        if grade_count[0] == 2:
            payload["entry_grades"][0]["disposition"] = "PARTIAL"
            payload["entry_grades"][0]["rationale"] = "The duty is only partly covered."
        if omit_defaults:
            payload.pop("out_of_ledger_claims")
            for entry_grade in payload["entry_grades"]:
                entry_grade.pop("finding_codes")
            for narrative_score in payload["narrative_scores"]:
                narrative_score.pop("finding_codes")
    else:
        dispute = request["payload"]["dispute"]
        payload = {
            "dispute_id": dispute["dispute_id"],
            "selected_ledger_resolution": None,
            "selected_grade_resolution": "accept_grader_1",
            "replacement_entries": [],
            "replacement_grade_alternative": None,
            "selected_disposition": None,
            "grade_dispute_fingerprint": request["safe_metadata"]["grade_dispute_fingerprint"],
            "rationale": "The first grade is better supported.",
            "source_ids": [],
        }
        if omit_defaults:
            for key in (
                "selected_ledger_resolution",
                "replacement_entries",
                "replacement_grade_alternative",
                "selected_disposition",
                "source_ids",
            ):
                payload.pop(key)
    return cast(dict[str, Any], payload)


@pytest.mark.parametrize(
    ("fixture_name", "archive_hash", "contract_mode"),
    [
        (
            "legacy-ledger-repair-919eb5f.tgz.b64",
            "0a13f0fbeb9c6c5841a198a811efcf1f567c91ebfbeade3f9d4214b87ee7729d",
            "pre-contract",
        ),
        (
            "ledger-invariant-contract-v1-445f4d9.tgz.b64",
            "3446c3904939653460c52ba54334b89739b012107a6e17bc3ee2c041e4d10952",
            "1.0",
        ),
    ],
)
def test_portable_replay_accepts_retained_ledger_contract_generations(
    fixture_name: str,
    archive_hash: str,
    contract_mode: str,
    tmp_path: Path,
) -> None:
    """Genuine pre-contract and schema-1.0 repair runs must replay on both heads."""
    portable = _load_portable()
    fixture = FIXTURE / fixture_name
    archive_bytes = base64.b64decode(fixture.read_bytes())
    assert hashlib.sha256(archive_bytes).hexdigest() == archive_hash
    _extract_retained_run_fixture(archive_bytes, tmp_path)
    run = tmp_path / "completed-repair"
    before = _tree_bytes(run)
    ledger_requests = [
        json.loads(path.read_bytes())
        for path in sorted((run / "judge-requests").glob("ledger-*-attempt-1.json"))
        if path.name
        in {
            "ledger-build-attempt-1.json",
            "ledger-audit-attempt-1.json",
            "ledger-repair-attempt-1.json",
        }
    ]

    assert len(ledger_requests) == 3
    if contract_mode == "pre-contract":
        assert all(
            "ledger_invariant_contract" not in request["payload"]
            and "ledger_invariant_contract" not in request["system_instructions"]
            for request in ledger_requests
        )
    else:
        assert all(
            request["payload"]["ledger_invariant_contract"]
            == _ledger_invariant_contract_v1_0()
            for request in ledger_requests
        )
    full_verification = attorney_artifacts.verify_evaluation_run(run)
    portable_verification = portable.verify_evaluation_run(run)
    assert portable_verification.valid == full_verification.valid is True
    assert portable_verification.issues == tuple(full_verification.issues) == ()
    assert portable_verification.root_hash == full_verification.root_hash
    assert _tree_bytes(run) == before


def test_portable_replay_accepts_current_ledger_contract_generation(
    tmp_path: Path,
) -> None:
    """A current build/audit/repair run remains the schema-1.1 control."""
    portable = _load_portable()
    run = tmp_path / "current-contract"
    portable.initialize_evaluation(_case_payload(), run, seed_hex="0" * 64)
    scripted = _scripted_payloads()
    grade_count = [0]
    for response_number in range(1, 5):
        request = portable.next_judge_request(run)
        assert request is not None
        payload = _repair_and_referee_payload(request, scripted, grade_count)
        portable.submit_judge_response(
            run, _response(request, {"payload": payload}, response_number)
        )
    ledger_requests = [
        json.loads(path.read_bytes())
        for path in sorted((run / "judge-requests").glob("ledger-*-attempt-1.json"))
        if path.name
        in {
            "ledger-build-attempt-1.json",
            "ledger-audit-attempt-1.json",
            "ledger-repair-attempt-1.json",
        }
    ]

    assert all(
        request["payload"]["ledger_invariant_contract"] == ledger_invariant_contract()
        for request in ledger_requests
    )
    full_verification = attorney_artifacts.verify_evaluation_run(run)
    portable_verification = portable.verify_evaluation_run(run)
    assert portable_verification.valid == full_verification.valid is True
    assert portable_verification.issues == tuple(full_verification.issues) == ()
    assert portable_verification.root_hash == full_verification.root_hash


def test_portable_historical_ledger_contract_generation_is_fresh_json() -> None:
    """Historical schema-1.0 replay data must be exact and independently mutable."""
    portable = _load_portable()

    mutated = portable._ledger_invariant_contract_v1_0()
    mutated["relationships"]["trigger_link_categories"].append("remedy")

    assert portable._ledger_invariant_contract_v1_0() == (
        _ledger_invariant_contract_v1_0()
    )


@pytest.mark.parametrize("mutation", ["mixed", "modified", "unknown"])
def test_portable_replay_rejects_mixed_or_modified_ledger_contract_generation(
    mutation: str,
    tmp_path: Path,
) -> None:
    """Self-consistent history cannot mix modes or alter a recognized contract."""
    portable = _load_portable()
    run = tmp_path / mutation
    portable.initialize_evaluation(_case_payload(), run, seed_hex="0" * 64)
    scripted = _scripted_payloads()
    grade_count = [0]
    for response_number in range(1, 3):
        request = portable.next_judge_request(run)
        assert request is not None
        payload = _repair_and_referee_payload(request, scripted, grade_count)
        portable.submit_judge_response(
            run, _response(request, {"payload": payload}, response_number)
        )
    audit_path = "judge-requests/ledger-audit-attempt-1.json"
    request = json.loads((run / audit_path).read_bytes())
    if mutation == "mixed":
        request["payload"]["ledger_invariant_contract"] = (
            _ledger_invariant_contract_v1_0()
        )
    elif mutation == "modified":
        request["payload"]["ledger_invariant_contract"]["binding"][
            "case_fingerprint"
        ] = "modified"
    else:
        request["payload"]["ledger_invariant_contract"]["schema_version"] = "9.9"
    request["request_fingerprint"] = "0" * 64
    request["request_fingerprint"] = portable._model_fingerprint(
        request, exclude={"request_fingerprint"}
    )
    _rewrite_portable_history_artifacts(
        portable,
        run,
        {audit_path: portable.canonical_json_bytes(request)},
    )

    full_verification = attorney_artifacts.verify_evaluation_run(run)
    portable_verification = portable.verify_evaluation_run(run)
    assert portable_verification.valid == full_verification.valid is False
    assert portable_verification.issues == (
        "EVALUATION_INTEGRITY_INVALID",
    )
    assert full_verification.issues
    assert portable_verification.root_hash == full_verification.root_hash is None


def test_repair_and_both_referee_paths_complete_and_replay(tmp_path: Path) -> None:
    portable = _load_portable()
    run = tmp_path / "run"
    portable.initialize_evaluation(_case_payload(), run, seed_hex="0" * 64)
    scripted = _scripted_payloads()
    operations: list[str] = []
    grade_count = [0]
    response_number = 0
    while (request := portable.next_judge_request(run)) is not None:
        before = {
            path.relative_to(run).as_posix(): path.read_bytes()
            for path in run.rglob("*")
            if path.is_file()
        }
        portable.resume_evaluation(run)
        assert portable.next_judge_request(run) == request
        after = {
            path.relative_to(run).as_posix(): path.read_bytes()
            for path in run.rglob("*")
            if path.is_file()
        }
        assert after == before
        response_number += 1
        operation = request["operation"]
        operations.append(operation)
        payload = _repair_and_referee_payload(request, scripted, grade_count)
        portable.submit_judge_response(
            run, _response(request, {"payload": payload}, response_number)
        )
    assert operations == [
        "admit_case",
        "build_ledger",
        "audit_ledger",
        "repair_ledger",
        "referee",
        "grade_report",
        "grade_report",
        "referee",
    ]
    assert portable.verify_evaluation_run(run).valid


@pytest.mark.parametrize("audit_kind", ["initial", "remaining"])
def test_portable_replay_rejects_rebound_inner_audit_request_fingerprint(
    tmp_path: Path,
    audit_kind: str,
) -> None:
    portable = _load_portable()
    run = tmp_path / "run"
    portable.initialize_evaluation(_case_payload(), run, seed_hex="0" * 64)
    scripted = _scripted_payloads()
    grade_count = [0]
    for response_number in range(1, (3 if audit_kind == "initial" else 4) + 1):
        request = portable.next_judge_request(run)
        assert request is not None
        payload = _repair_and_referee_payload(request, scripted, grade_count)
        portable.submit_judge_response(
            run, _response(request, {"payload": payload}, response_number)
        )
    assert portable.verify_evaluation_run(run).valid

    if audit_kind == "initial":
        response_path = "judge-responses/ledger-audit-attempt-1.json"
        response = json.loads((run / response_path).read_text(encoding="utf-8"))
        wrong = "f" * 64 if response["request_fingerprint"] != "f" * 64 else "e" * 64
        response["payload"]["request_fingerprint"] = wrong
        audit = response["payload"]
        envelope = json.loads((run / "case-envelope.json").read_text(encoding="utf-8"))
        proposed = json.loads(
            (run / "legal-ledger.proposed.json").read_text(encoding="utf-8")
        )
        repair_request = portable._repair_ledger_request(envelope, proposed, audit)
        replacements = {
            response_path: portable.canonical_json_bytes(response),
            "legal-ledger-audit.json": portable.canonical_json_bytes(audit),
            "judge-requests/ledger-repair-attempt-1.json": portable.canonical_json_bytes(
                repair_request
            ),
        }
    else:
        response_path = "judge-responses/ledger-repair-attempt-1.json"
        response = json.loads((run / response_path).read_text(encoding="utf-8"))
        wrong = "f" * 64 if response["request_fingerprint"] != "f" * 64 else "e" * 64
        response["payload"]["remaining_audit"]["request_fingerprint"] = wrong
        remaining = response["payload"]["remaining_audit"]
        replacements = {
            response_path: portable.canonical_json_bytes(response),
            "legal-ledger.remaining-audit.json": portable.canonical_json_bytes(remaining),
        }
    _rewrite_portable_history_artifacts(portable, run, replacements)

    assert portable.verify_evaluation_run(run).issues == ("EVALUATION_INTEGRITY_INVALID",)


def test_omitted_defaults_across_repair_and_referees_match_core(tmp_path: Path) -> None:
    portable = _load_portable()
    portable_run = tmp_path / "portable"
    core_run = tmp_path / "core"
    case_payload = _case_payload()
    portable.initialize_evaluation(case_payload, portable_run, seed_hex="1" * 64)
    initialize_core(_core_case_from_payload(case_payload), core_run, seed_hex="1" * 64)
    scripted = _scripted_payloads()
    grade_count = [0]
    response_number = 0

    while True:
        portable_request = portable.next_judge_request(portable_run)
        core_request = next_core(core_run)
        if portable_request is None or core_request is None:
            assert portable_request is None and core_request is None
            break
        assert portable.canonical_json_bytes(portable_request) == portable.canonical_json_bytes(
            core_request.model_dump(mode="json")
        )
        payload = _repair_and_referee_payload(
            portable_request,
            scripted,
            grade_count,
            omit_defaults=True,
        )
        response_number += 1
        response = _response(portable_request, {"payload": payload}, response_number)
        portable_state = portable.submit_judge_response(portable_run, response)
        core_state = submit_core(core_run, JudgeResponse.model_validate(response))

        assert portable_state == core_state.model_dump(mode="json")
        assert portable.verify_evaluation_run(portable_run).valid
        assert attorney_artifacts.verify_evaluation_run(core_run).valid

    assert (portable_run / "evaluation-result.json").read_bytes() == (
        core_run / "evaluation-result.json"
    ).read_bytes()
    assert (portable_run / "evaluation-report.md").read_bytes() == (
        core_run / "evaluation-report.md"
    ).read_bytes()


def test_multiple_remaining_ledger_disputes_terminal_matches_core(tmp_path: Path) -> None:
    portable = _load_portable()
    portable_run = tmp_path / "portable"
    core_run = tmp_path / "core"
    case_payload = _case_payload()
    portable.initialize_evaluation(case_payload, portable_run, seed_hex="0" * 64)
    initialize_core(_core_case_from_payload(case_payload), core_run, seed_hex="0" * 64)
    scripted = _scripted_payloads()
    portable_state: dict[str, Any] | None = None
    core_state: Any = None

    for index in range(4):
        portable_request = portable.next_judge_request(portable_run)
        core_request = next_core(core_run)
        assert portable_request is not None and core_request is not None
        assert portable.canonical_json_bytes(portable_request) == portable.canonical_json_bytes(
            core_request.model_dump(mode="json")
        )
        if index == 0:
            payload = copy.deepcopy(scripted[0]["payload"])
            payload["request_fingerprint"] = portable_request["request_fingerprint"]
        elif index == 1:
            payload = copy.deepcopy(scripted[1]["payload"])
            payload["case_fingerprint"] = portable_request["safe_metadata"][
                "source_record_fingerprint"
            ]
        elif index == 2:
            payload = {
                "request_fingerprint": portable_request["request_fingerprint"],
                "complete": True,
                "disputes": [
                    {
                        "dispute_id": "file-notice-materiality",
                        "action": "materiality",
                        "target_ledger_ids": ["file-notice"],
                        "proposed_entries": [],
                        "materiality": "critical",
                        "rationale": "The duty needs independent materiality review.",
                    }
                ],
            }
        else:
            dispute_template = {
                "action": "materiality",
                "proposed_entries": [],
                "rationale": "The duty still needs independent materiality review.",
            }
            payload = {
                "repaired_ledger": portable_request["payload"]["proposed_ledger"],
                "remaining_audit": {
                    "request_fingerprint": portable_request["request_fingerprint"],
                    "complete": True,
                    "disputes": [
                        {
                            **dispute_template,
                            "dispute_id": "file-notice-materiality",
                            "target_ledger_ids": ["file-notice"],
                            "materiality": "critical",
                        },
                        {
                            **dispute_template,
                            "dispute_id": "retain-proof-materiality",
                            "target_ledger_ids": ["retain-proof"],
                            "materiality": "material",
                        },
                    ],
                },
            }
        response = _response(portable_request, {"payload": payload}, index + 1)
        portable_state = portable.submit_judge_response(portable_run, response)
        core_state = submit_core(core_run, JudgeResponse.model_validate(response))

    assert portable_state is not None
    assert portable_state == core_state.model_dump(mode="json")
    assert portable_state["state"] == "inconclusive"
    assert portable_state["terminal_status"] == "inconclusive"
    assert portable.next_judge_request(portable_run) is None
    assert next_core(core_run) is None
    for artifact in (
        "legal-ledger.repaired.json",
        "legal-ledger.remaining-audit.json",
        "terminal-readiness.json",
        "evaluation-result.json",
        "evaluation-report.md",
    ):
        assert (portable_run / artifact).read_bytes() == (core_run / artifact).read_bytes()
    result = json.loads((portable_run / "evaluation-result.json").read_text(encoding="utf-8"))
    assert result["readiness"]["issue_codes"][-1] == ("MULTIPLE_LEDGER_DISPUTES_UNRESOLVED")
    assert portable.verify_evaluation_run(portable_run).valid


def test_portable_initial_nontransaction_audit_advances_to_repair(tmp_path: Path) -> None:
    portable = _load_portable()
    run = tmp_path / "run"
    portable.initialize_evaluation(_case_payload(), run, seed_hex="9" * 64)
    scripted = _scripted_payloads()
    for index, item in enumerate(scripted[:2], start=1):
        request = portable.next_judge_request(run)
        assert request is not None
        portable.submit_judge_response(run, _response(request, item, index))

    audit_request = portable.next_judge_request(run)
    assert audit_request is not None
    assert audit_request["operation"] == "audit_ledger"
    audit_response = _response(
        audit_request,
        {
            "payload": {
                "request_fingerprint": audit_request["request_fingerprint"],
                "complete": True,
                "disputes": [
                    {
                        "dispute_id": "add-omitted-record",
                        "action": "add",
                        "target_ledger_ids": [],
                        "proposed_entries": [],
                        "materiality": "supporting",
                        "rationale": (
                            "synthetic-rule-1-source is missing covered operator registry "
                            "notice requirement."
                        ),
                    },
                    {
                        "dispute_id": "add-located-record",
                        "action": "add",
                        "target_ledger_ids": [],
                        "proposed_entries": [],
                        "materiality": "supporting",
                        "rationale": (
                            "synthetic-rule-1-source is missing the notice requirement "
                            "at Rule 1."
                        ),
                    },
                    {
                        "dispute_id": "add-proposed-record",
                        "action": "add",
                        "target_ledger_ids": [],
                        "proposed_entries": [
                            {
                                **copy.deepcopy(
                                    audit_request["payload"]["proposed_ledger"]["entries"][0]
                                ),
                                "ledger_id": "proposed-notice",
                            }
                        ],
                        "materiality": "supporting",
                        "rationale": "The source record needs a ledger correction.",
                    },
                    {
                        "dispute_id": "split-notice-duty",
                        "action": "split",
                        "target_ledger_ids": ["file-notice"],
                        "proposed_entries": [],
                        "materiality": "supporting",
                        "rationale": (
                            "The notice duty combines distinct filing and timing propositions."
                        ),
                    },
                ],
            }
        },
        3,
    )

    state = portable.submit_judge_response(run, audit_response)
    repair_request = portable.next_judge_request(run)

    assert state["state"] == "ledger-repair"
    assert repair_request is not None
    assert repair_request["operation"] == "repair_ledger"
    assert portable.verify_evaluation_run(run).valid

    remaining = copy.deepcopy(audit_response["payload"])
    remaining["request_fingerprint"] = repair_request["request_fingerprint"]
    retry_state = portable.submit_judge_response(
        run,
        _response(
            repair_request,
            {
                "payload": {
                    "repaired_ledger": repair_request["payload"]["proposed_ledger"],
                    "remaining_audit": remaining,
                }
            },
            4,
        ),
    )
    retry_request = portable.next_judge_request(run)

    assert retry_state["state"] == "ledger-repair"
    assert retry_state["attempt"] == 2
    assert retry_request is not None
    assert retry_request["operation"] == "repair_ledger"
    assert portable.verify_evaluation_run(run).valid


def test_portable_initial_add_reusing_existing_ledger_id_retries_and_replays(
    tmp_path: Path,
) -> None:
    portable = _load_portable()
    run = tmp_path / "run"
    portable.initialize_evaluation(_case_payload(), run, seed_hex="5" * 64)
    for index, item in enumerate(_scripted_payloads()[:2], start=1):
        request = portable.next_judge_request(run)
        assert request is not None
        payload = copy.deepcopy(item["payload"])
        if "request_fingerprint" in payload:
            payload["request_fingerprint"] = request["request_fingerprint"]
        if request["operation"] == "build_ledger":
            payload["case_fingerprint"] = request["safe_metadata"][
                "source_record_fingerprint"
            ]
        portable.submit_judge_response(
            run,
            _response(request, {"payload": payload}, index),
        )
    audit_request = portable.next_judge_request(run)
    assert audit_request is not None
    existing_entry = copy.deepcopy(
        audit_request["payload"]["proposed_ledger"]["entries"][0]
    )

    state = portable.submit_judge_response(
        run,
        _response(
            audit_request,
            {
                "payload": {
                    "request_fingerprint": audit_request["request_fingerprint"],
                    "complete": True,
                    "disputes": [
                        {
                            "dispute_id": "reused-add-id",
                            "action": "add",
                            "target_ledger_ids": [],
                            "proposed_entries": [existing_entry],
                            "materiality": "supporting",
                            "rationale": "The source record needs a ledger correction.",
                        }
                    ],
                }
            },
            3,
        ),
    )
    retry = portable.next_judge_request(run)

    assert state["state"] == "ledger-audit"
    assert state["attempt"] == 2
    assert retry is not None and retry["operation"] == "audit_ledger"
    diagnostics = json.loads(
        (run / "judge-diagnostics/ledger-audit-attempt-1.json").read_text(
            encoding="utf-8"
        )
    )
    assert "add initial ledger finding must use new ledger IDs" in diagnostics["issues"][0][
        "message"
    ]
    assert portable.verify_evaluation_run(run).valid


def test_portable_replay_rejects_rebound_initial_add_with_existing_ledger_id(
    tmp_path: Path,
) -> None:
    portable = _load_portable()
    run = tmp_path / "run"
    portable.initialize_evaluation(_case_payload(), run, seed_hex="6" * 64)
    for index, item in enumerate(_scripted_payloads()[:2], start=1):
        request = portable.next_judge_request(run)
        assert request is not None
        payload = copy.deepcopy(item["payload"])
        if "request_fingerprint" in payload:
            payload["request_fingerprint"] = request["request_fingerprint"]
        if request["operation"] == "build_ledger":
            payload["case_fingerprint"] = request["safe_metadata"][
                "source_record_fingerprint"
            ]
        portable.submit_judge_response(
            run,
            _response(request, {"payload": payload}, index),
        )
    audit_request = portable.next_judge_request(run)
    assert audit_request is not None
    proposed = copy.deepcopy(
        audit_request["payload"]["proposed_ledger"]["entries"][0]
    )
    proposed["ledger_id"] = "proposed-notice"
    response = _response(
        audit_request,
        {
            "payload": {
                "request_fingerprint": audit_request["request_fingerprint"],
                "complete": True,
                "disputes": [
                    {
                        "dispute_id": "add-proposed-record",
                        "action": "add",
                        "target_ledger_ids": [],
                        "proposed_entries": [proposed],
                        "materiality": "supporting",
                        "rationale": "The source record needs a ledger correction.",
                    }
                ],
            }
        },
        3,
    )
    portable.submit_judge_response(run, response)
    assert portable.verify_evaluation_run(run).valid

    response_path = "judge-responses/ledger-audit-attempt-1.json"
    rebound_response = json.loads((run / response_path).read_text(encoding="utf-8"))
    rebound_response["payload"]["disputes"][0]["proposed_entries"][0][
        "ledger_id"
    ] = "file-notice"
    rebound_audit = rebound_response["payload"]
    envelope = json.loads((run / "case-envelope.json").read_text(encoding="utf-8"))
    proposed_ledger = json.loads(
        (run / "legal-ledger.proposed.json").read_text(encoding="utf-8")
    )
    repair_request = portable._repair_ledger_request(
        envelope,
        proposed_ledger,
        rebound_audit,
    )
    _rewrite_portable_history_artifacts(
        portable,
        run,
        {
            response_path: portable.canonical_json_bytes(rebound_response),
            "legal-ledger-audit.json": portable.canonical_json_bytes(rebound_audit),
            "judge-requests/ledger-repair-attempt-1.json": portable.canonical_json_bytes(
                repair_request
            ),
        },
    )

    assert portable.verify_evaluation_run(run).issues == ("EVALUATION_INTEGRITY_INVALID",)


def test_portable_initial_contradictory_generic_finding_retries_and_replays(
    tmp_path: Path,
) -> None:
    portable = _load_portable()
    run = tmp_path / "run"
    portable.initialize_evaluation(_case_payload(), run, seed_hex="8" * 64)
    scripted = _scripted_payloads()
    for index, item in enumerate(scripted[:2], start=1):
        request = portable.next_judge_request(run)
        assert request is not None
        portable.submit_judge_response(run, _response(request, item, index))
    audit_request = portable.next_judge_request(run)
    assert audit_request is not None

    state = portable.submit_judge_response(
        run,
        _response(
            audit_request,
            {
                "payload": {
                    "request_fingerprint": audit_request["request_fingerprint"],
                    "complete": True,
                    "disputes": [
                        {
                            "dispute_id": "contradictory-add",
                            "action": "add",
                            "target_ledger_ids": ["file-notice"],
                            "proposed_entries": [],
                            "materiality": "supporting",
                            "rationale": "This finding is very important indeed.",
                        }
                    ],
                }
            },
            3,
        ),
    )
    retry = portable.next_judge_request(run)

    assert state["state"] == "ledger-audit"
    assert state["attempt"] == 2
    assert retry is not None
    assert retry["operation"] == "audit_ledger"
    assert portable.verify_evaluation_run(run).valid


@pytest.mark.parametrize(
    ("action", "targets", "rationale"),
    [
        ("add", [], "The source record needs a ledger correction."),
        ("add", [], "The source record requires this concrete ledger correction."),
        ("add", [], "The case metadata needs a ledger correction."),
        ("add", [], "The request fingerprint needs a ledger correction."),
        ("add", [], "The response schema needs a ledger correction."),
        (
            "add",
            [],
            "unknown-source is missing covered operator registry notice requirement.",
        ),
        (
            "split",
            ["unknown-ledger-id"],
            "The notice duty combines distinct filing and timing propositions.",
        ),
        (
            "add",
            [],
            "synthetic-rule-1-source is missing the requirement at Rule 404.",
        ),
        (
            "add",
            [],
            (
                "synthetic-rule-1-source is missing covered operator registry notice "
                "requirement at Rule 404."
            ),
        ),
    ],
)
def test_portable_initial_content_free_finding_retries_and_replays(
    tmp_path: Path, action: str, targets: list[str], rationale: str
) -> None:
    portable = _load_portable()
    run = tmp_path / "run"
    portable.initialize_evaluation(_case_payload(), run, seed_hex="7" * 64)
    scripted = _scripted_payloads()
    for index, item in enumerate(scripted[:2], start=1):
        request = portable.next_judge_request(run)
        assert request is not None
        portable.submit_judge_response(run, _response(request, item, index))
    audit_request = portable.next_judge_request(run)
    assert audit_request is not None

    state = portable.submit_judge_response(
        run,
        _response(
            audit_request,
            {
                "payload": {
                    "request_fingerprint": audit_request["request_fingerprint"],
                    "complete": True,
                    "disputes": [
                        {
                            "dispute_id": "ungrounded-finding",
                            "action": action,
                            "target_ledger_ids": targets,
                            "proposed_entries": [],
                            "materiality": "supporting",
                            "rationale": rationale,
                        }
                    ],
                }
            },
            3,
        ),
    )
    retry = portable.next_judge_request(run)

    assert state["state"] == "ledger-audit"
    assert state["attempt"] == 2
    assert retry is not None
    assert retry["operation"] == "audit_ledger"
    assert portable.verify_evaluation_run(run).valid


@pytest.mark.parametrize(
    ("defect", "issue_code"),
    [
        ("unknown-source", "LEDGER_CITATION_SOURCE_UNKNOWN"),
        ("wrong-quote", "LEDGER_QUOTE_MISMATCH"),
        ("out-of-range", "LEDGER_QUOTE_MISMATCH"),
        ("commentary-only", "LEDGER_COMMENTARY_ONLY_SUPPORT"),
    ],
)
def test_portable_initial_invalid_proposed_entry_retries_and_replays(
    tmp_path: Path, defect: str, issue_code: str
) -> None:
    portable = _load_portable()
    case_payload = _case_payload()
    if defect == "commentary-only":
        commentary = copy.deepcopy(case_payload["sources"][0])
        commentary.update(
            {
                "source_id": "commentary-source",
                "source_role": "commentary_analysis",
                "source_quality": "secondary",
            }
        )
        case_payload["sources"].append(commentary)
        case_payload["requested_authorities"][0]["source_ids"].append(
            commentary["source_id"]
        )
    run = tmp_path / "run"
    portable.initialize_evaluation(case_payload, run, seed_hex="6" * 64)
    scripted = _scripted_payloads()
    for index, item in enumerate(scripted[:2], start=1):
        request = portable.next_judge_request(run)
        assert request is not None
        payload = copy.deepcopy(item["payload"])
        if "request_fingerprint" in payload:
            payload["request_fingerprint"] = request["request_fingerprint"]
        if request["operation"] == "build_ledger":
            payload["case_fingerprint"] = request["safe_metadata"][
                "source_record_fingerprint"
            ]
        portable.submit_judge_response(
            run, _response(request, {"payload": payload}, index)
        )
    audit_request = portable.next_judge_request(run)
    assert audit_request is not None
    proposed = copy.deepcopy(audit_request["payload"]["proposed_ledger"]["entries"][0])
    proposed["ledger_id"] = "invalid-proposed"
    citation = proposed["citations"][0]
    if defect == "unknown-source":
        citation["source_id"] = "unknown-source"
    elif defect == "wrong-quote":
        citation["quote"] = "covered operator notice language"
    elif defect == "out-of-range":
        source_text = audit_request["payload"]["source_record"]["sources"][0][
            "normalized_text"
        ]
        citation.update(
            {
                "start_char": len(source_text) + 1,
                "end_char": len(source_text) + 2,
                "quote": "x",
            }
        )
    else:
        citation["source_id"] = "commentary-source"

    state = portable.submit_judge_response(
        run,
        _response(
            audit_request,
            {
                "payload": {
                    "request_fingerprint": audit_request["request_fingerprint"],
                    "complete": True,
                    "disputes": [
                        {
                            "dispute_id": "invalid-proposed-finding",
                            "action": "add",
                            "target_ledger_ids": [],
                            "proposed_entries": [proposed],
                            "materiality": "supporting",
                            "rationale": "The source record needs a ledger correction.",
                        }
                    ],
                }
            },
            3,
        ),
    )
    retry = portable.next_judge_request(run)

    assert state["state"] == "ledger-audit"
    assert state["attempt"] == 2
    assert retry is not None
    assert retry["operation"] == "audit_ledger"
    attempt = json.loads(
        (run / "judge-diagnostics" / "ledger-audit-attempt-1.json").read_text()
    )
    message = attempt["issues"][0]["message"]
    assert "invalid-proposed-finding" in message
    assert issue_code in message
    assert portable.verify_evaluation_run(run).valid


@pytest.mark.parametrize("phase_count", range(6))
def test_resume_is_read_only_at_each_golden_phase(tmp_path: Path, phase_count: int) -> None:
    portable = _load_portable()
    run = tmp_path / f"run-{phase_count}"
    portable.initialize_evaluation(_case_payload(), run, seed_hex="0" * 64)
    for index, item in enumerate(_scripted_payloads()[:phase_count], start=1):
        request = portable.next_judge_request(run)
        assert request is not None
        portable.submit_judge_response(run, _response(request, item, index))
    before = {
        path.relative_to(run).as_posix(): path.read_bytes()
        for path in run.rglob("*")
        if path.is_file()
    }
    state = portable.resume_evaluation(run)
    request = portable.next_judge_request(run)
    after = {
        path.relative_to(run).as_posix(): path.read_bytes()
        for path in run.rglob("*")
        if path.is_file()
    }
    assert state["terminal_status"] is None or request is None
    assert after == before


def test_verification_rejects_added_tampered_and_mixed_version_artifacts(tmp_path: Path) -> None:
    portable = _load_portable()
    run = tmp_path / "run"
    _run_portable(portable, run)
    before = {
        path.relative_to(run).as_posix(): path.read_bytes()
        for path in run.rglob("*")
        if path.is_file()
    }
    verification = portable.verify_evaluation_run(run)
    assert verification.valid is True
    assert verification.root_hash
    after = {
        path.relative_to(run).as_posix(): path.read_bytes()
        for path in run.rglob("*")
        if path.is_file()
    }
    assert after == before

    (run / "unexpected.json").write_text("{}", encoding="utf-8")
    assert portable.verify_evaluation_run(run).issues == ("EVALUATION_INTEGRITY_INVALID",)
    (run / "unexpected.json").unlink()

    manifest = json.loads((run / "run-manifest.json").read_text(encoding="utf-8"))
    manifest["schema_version"] = "1.0"
    (run / "run-manifest.json").write_bytes(portable.canonical_json_bytes(manifest))
    assert portable.verify_evaluation_run(run).issues == ("EVALUATION_ARTIFACT_SCHEMA_UNSUPPORTED",)


@pytest.mark.parametrize(
    ("artifact", "nested_path"),
    [
        ("evaluation-result.json", ("schema_version",)),
        ("report-evaluation-A.json", ("schema_version",)),
        ("report-disputes.json", ("schema_version",)),
        ("grader-1-report-A.json", ("schema_version",)),
        ("resolved-grade-A.json", ("schema_version",)),
        ("resolved-grade-A.json", ("grade", "schema_version")),
        ("report-score-inputs-A.json", ("resolved_grade", "grade", "schema_version")),
    ],
)
def test_mixed_12_and_13_artifact_families_fail_with_stable_schema_code(
    tmp_path: Path, artifact: str, nested_path: tuple[str, ...]
) -> None:
    portable = _load_portable()
    run = tmp_path / "run"
    _run_portable(portable, run)
    value = json.loads((run / artifact).read_text(encoding="utf-8"))
    target = value
    for key in nested_path[:-1]:
        target = target[key]
    target[nested_path[-1]] = "1.2"
    (run / artifact).write_bytes(portable.canonical_json_bytes(value))
    _rehash_manifest_artifact(portable, run, artifact)

    assert portable.verify_evaluation_run(run).issues == (
        "EVALUATION_ARTIFACT_SCHEMA_UNSUPPORTED",
    )


@pytest.mark.parametrize("legacy_schema", ["1.3", "1.2"])
def test_portable_legacy_score_input_schema_fails_closed(
    tmp_path: Path,
    legacy_schema: str,
) -> None:
    portable = _load_portable()
    run = tmp_path / "run"
    _run_portable(portable, run)
    artifact = "report-score-inputs-A.json"
    path = run / artifact
    value = json.loads(path.read_text(encoding="utf-8"))
    value["schema_version"] = legacy_schema
    path.write_bytes(portable.canonical_json_bytes(value))
    _rehash_manifest_artifact(portable, run, artifact)

    assert portable.verify_evaluation_run(run).issues == (
        "EVALUATION_SCORE_INPUT_SCHEMA_UNSUPPORTED",
    )


def test_portable_score_input_source_record_tamper_fails_exact_replay(
    tmp_path: Path,
) -> None:
    portable = _load_portable()
    run = tmp_path / "run"
    _run_portable(portable, run)
    artifact = "report-score-inputs-A.json"
    path = run / artifact
    value = json.loads(path.read_text(encoding="utf-8"))
    source_record = value["source_record"]
    source = source_record["sources"][0]
    source["normalized_text"] += " Tampered."
    source["content_hash"] = hashlib.sha256(
        source["normalized_text"].encode("utf-8")
    ).hexdigest()
    projection = {
        key: item
        for key, item in source_record.items()
        if key != "source_record_fingerprint"
    }
    source_record["source_record_fingerprint"] = hashlib.sha256(
        portable.canonical_json_bytes(projection)
    ).hexdigest()
    path.write_bytes(portable.canonical_json_bytes(value))
    _rehash_manifest_artifact(portable, run, artifact)

    assert portable.verify_evaluation_run(run).issues == (
        "EVALUATION_SCORE_INPUT_SOURCE_RECORD_MISMATCH",
    )


def test_completed_grade_response_with_pre_matrix_payload_fails_stable_schema_check(
    tmp_path: Path,
) -> None:
    portable = _load_portable()
    run = tmp_path / "run"
    _run_portable(portable, run)
    artifact = "judge-responses/grade-A-1-attempt-1.json"
    response = json.loads((run / artifact).read_text(encoding="utf-8"))
    assert response["schema_version"] == "1.0"
    response["payload"]["schema_version"] = "1.2"
    (run / artifact).write_bytes(portable.canonical_json_bytes(response))
    _rehash_completed_response(portable, run, artifact)

    assert portable.verify_evaluation_run(run).issues == (
        "EVALUATION_ARTIFACT_SCHEMA_UNSUPPORTED",
    )


def test_verification_replays_requirement_matrix_from_immutable_evidence(
    tmp_path: Path,
) -> None:
    portable = _load_portable()
    run = tmp_path / "run"
    _run_portable(portable, run)
    result_path = run / "evaluation-result.json"
    result = json.loads(result_path.read_text(encoding="utf-8"))
    result["requirement_matrix"]["rows"][0]["proposition"] = "Altered proposition."
    result["result_fingerprint"] = "0" * 64
    result["result_fingerprint"] = portable._model_fingerprint(
        result, exclude={"result_fingerprint"}
    )
    result_path.write_bytes(portable.canonical_json_bytes(result))
    (run / "evaluation-report.md").write_text(
        portable.render_evaluation_report(result), encoding="utf-8"
    )
    manifest_path = run / "run-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["result_hash"] = hashlib.sha256(result_path.read_bytes()).hexdigest()
    manifest_path.write_bytes(portable.canonical_json_bytes(manifest))
    _rehash_manifest_artifact(portable, run, "evaluation-result.json")
    _rehash_manifest_artifact(portable, run, "evaluation-report.md")

    assert portable.verify_evaluation_run(run).issues == ("EVALUATION_INTEGRITY_INVALID",)


def test_verification_rejects_self_consistent_semantic_artifact_rewrite(tmp_path: Path) -> None:
    portable = _load_portable()
    run = tmp_path / "run"
    portable.initialize_evaluation(_case_payload(), run, seed_hex="0" * 64)
    request = portable.next_judge_request(run)
    assert request is not None
    portable.submit_judge_response(run, _response(request, _scripted_payloads()[0], 1))

    readiness_path = run / "case-readiness.json"
    readiness = json.loads(readiness_path.read_text(encoding="utf-8"))
    readiness["status"] = "CASE_INVALID"
    readiness_path.write_bytes(portable.canonical_json_bytes(readiness))
    _rehash_manifest_artifact(portable, run, "case-readiness.json")

    assert portable.verify_evaluation_run(run).issues == ("EVALUATION_INTEGRITY_INVALID",)


def test_verification_rejects_self_consistent_request_expansion(tmp_path: Path) -> None:
    portable = _load_portable()
    run = tmp_path / "run"
    portable.initialize_evaluation(_case_payload(), run, seed_hex="0" * 64)
    request_path = run / "judge-requests" / "admission-attempt-1.json"
    request = json.loads(request_path.read_text(encoding="utf-8"))
    request["safe_metadata"]["unexpected_scope"] = "expanded"
    request["request_fingerprint"] = "0" * 64
    request["request_fingerprint"] = portable._model_fingerprint(
        request, exclude={"request_fingerprint"}
    )
    request_path.write_bytes(portable.canonical_json_bytes(request))

    manifest_path = run / "run-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    call = manifest["judge_calls"][0]
    call["request_fingerprint"] = request["request_fingerprint"]
    call["prompt_fingerprint"] = portable._prompt_fingerprint(request)
    manifest_path.write_bytes(portable.canonical_json_bytes(manifest))
    _rehash_manifest_artifact(portable, run, "judge-requests/admission-attempt-1.json")

    assert portable.verify_evaluation_run(run).issues == ("EVALUATION_INTEGRITY_INVALID",)


def test_storage_rejects_symlink_components_and_nonregular_leaves(tmp_path: Path) -> None:
    portable = _load_portable()
    outside = tmp_path / "outside"
    outside.mkdir()
    link = tmp_path / "linked-run"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"symlinks unavailable: {error}")
    with pytest.raises(portable.EvaluationIntegrityError):
        portable.initialize_evaluation(_case_payload(), link, seed_hex="0" * 64)

    run = tmp_path / "run"
    _run_portable(portable, run)
    (run / "evaluation-report.md").unlink()
    os.mkfifo(run / "evaluation-report.md")
    try:
        assert portable.verify_evaluation_run(run).issues == ("EVALUATION_INTEGRITY_INVALID",)
    finally:
        (run / "evaluation-report.md").unlink()


def test_storage_rejects_hardlinked_artifacts(tmp_path: Path) -> None:
    portable = _load_portable()
    run = tmp_path / "run"
    _run_portable(portable, run)
    try:
        os.link(run / "evaluation-report.md", tmp_path / "report-hardlink.md")
    except OSError as error:
        pytest.skip(f"hardlinks unavailable: {error}")
    assert portable.verify_evaluation_run(run).issues == ("EVALUATION_INTEGRITY_INVALID",)


def test_storage_detects_root_replacement_after_descriptor_open(tmp_path: Path) -> None:
    portable = _load_portable()
    run = tmp_path / "run"
    _run_portable(portable, run)
    displaced = tmp_path / "displaced"
    with portable._open_run_storage(run) as storage:
        run.rename(displaced)
        run.mkdir()
        with pytest.raises(portable.EvaluationIntegrityError, match="path identity changed"):
            storage.assert_root_identity()


def test_storage_detects_leaf_replacement_during_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    portable = _load_portable()
    run = tmp_path / "run"
    _run_portable(portable, run)
    report = run / "evaluation-report.md"
    displaced = tmp_path / "displaced-report.md"
    original_read = portable._read_all
    raced = False

    def replace_after_read(descriptor: int) -> bytes:
        nonlocal raced
        data = original_read(descriptor)
        if not raced:
            raced = True
            report.rename(displaced)
            report.write_bytes(data)
        return cast(bytes, data)

    with portable._open_run_storage(run) as storage:
        monkeypatch.setattr(portable, "_read_all", replace_after_read)
        with pytest.raises(portable.EvaluationIntegrityError, match="changed while reading"):
            storage.read_artifact("evaluation-report.md")


def test_storage_detects_late_inventory_addition(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    portable = _load_portable()
    run = tmp_path / "run"
    _run_portable(portable, run)
    original_scan = portable._PosixRunStorage.scan_inventory
    calls = 0

    def racing_scan(storage: Any) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        if calls == 2:
            (run / "late-addition.json").write_text("{}", encoding="utf-8")
        return cast(dict[str, Any], original_scan(storage))

    monkeypatch.setattr(portable._PosixRunStorage, "scan_inventory", racing_scan)
    assert portable.verify_evaluation_run(run).issues == ("EVALUATION_INTEGRITY_INVALID",)


def test_failed_atomic_write_cleans_exclusive_temporary_leaf(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    portable = _load_portable()
    run = tmp_path / "run"

    def fail_replace(*args: Any, **kwargs: Any) -> None:
        raise OSError("race")

    with portable._open_run_storage(run, initialize=True) as storage:
        monkeypatch.setattr(portable.os, "replace", fail_replace)
        with pytest.raises(OSError, match="race"):
            storage.atomic_write("artifact.json", b"{}", mutable=False)
        assert [path.name for path in run.iterdir()] == []


def test_windows_storage_fails_closed_without_a_pathname_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    portable = _load_portable()
    monkeypatch.setattr(portable, "_storage_platform", lambda: "nt")
    with pytest.raises(
        portable.EvaluationIntegrityError,
        match="EVALUATION_STORAGE_PLATFORM_UNSUPPORTED",
    ):
        portable.initialize_evaluation(_case_payload(), tmp_path / "run", seed_hex="0" * 64)
    verification = portable.verify_evaluation_run(tmp_path / "run")
    assert verification.valid is False
    assert verification.issues == ("EVALUATION_STORAGE_PLATFORM_UNSUPPORTED",)
    with pytest.raises(
        portable.EvaluationIntegrityError,
        match="EVALUATION_STORAGE_PLATFORM_UNSUPPORTED",
    ):
        portable.resume_evaluation(tmp_path / "run")
    assert not (tmp_path / "run").exists()


def test_portable_preflight_matches_core_and_never_changes_run_bytes(tmp_path: Path) -> None:
    """Portable preflight must calculate the same transition without committing either run."""
    portable = _load_portable()
    portable_run = tmp_path / "portable"
    core_run = tmp_path / "core"
    case_payload = _case_payload()
    portable.initialize_evaluation(case_payload, portable_run, seed_hex="0" * 64)
    initialize_core(_core_case_from_payload(case_payload), core_run, seed_hex="0" * 64)
    for index, item in enumerate(_scripted_payloads()[:3], start=1):
        portable_request = portable.next_judge_request(portable_run)
        core_request = next_core(core_run)
        assert portable_request is not None and core_request is not None
        assert portable_request == core_request.model_dump(mode="json")
        accepted = _response(portable_request, item, index)
        portable.submit_judge_response(portable_run, accepted)
        submit_core(core_run, JudgeResponse.model_validate(accepted))
    request = portable.next_judge_request(portable_run)
    assert request is not None and request["operation"] == "grade_report"
    response = _response(request, _scripted_payloads()[3], 4)
    invalid = copy.deepcopy(response)
    invalid["payload"] = {"malformed": True}
    portable_before = _tree_bytes(portable_run)
    core_before = _tree_bytes(core_run)

    portable_valid = portable.preflight_judge_response(portable_run, response)
    core_valid = core_workflow.preflight_judge_response(
        core_run, JudgeResponse.model_validate(response)
    )
    portable_invalid = portable.preflight_judge_response(portable_run, invalid)
    core_invalid = core_workflow.preflight_judge_response(
        core_run, JudgeResponse.model_validate(invalid)
    )

    assert portable_valid == core_valid.model_dump(mode="json")
    assert portable_invalid == core_invalid.model_dump(mode="json")
    assert _tree_bytes(portable_run) == portable_before
    assert _tree_bytes(core_run) == core_before

    portable_state = portable.submit_judge_response(portable_run, response)
    core_state = submit_core(core_run, JudgeResponse.model_validate(response))
    assert portable_state == core_state.model_dump(mode="json")


def test_portable_preflight_refuses_terminal_run_without_changing_bytes(
    tmp_path: Path,
) -> None:
    """A terminal run has no transition to validate and must remain byte-identical."""
    portable = _load_portable()
    run = tmp_path / "terminal"
    portable.initialize_evaluation(_case_payload(), run, seed_hex="0" * 64)
    request = portable.next_judge_request(run)
    assert request is not None
    payload = copy.deepcopy(_scripted_payloads()[0]["payload"])
    payload["request_fingerprint"] = request["request_fingerprint"]
    payload["checks"][0]["satisfied"] = False
    response = _response(request, {"payload": payload}, 1)
    portable.submit_judge_response(run, response)
    before = _tree_bytes(run)

    refused = portable.preflight_judge_response(run, response)

    assert refused == {
        "schema_version": "1.0",
        "ok": False,
        "operation": None,
        "request_fingerprint": None,
        "diagnostic_fingerprint": None,
        "issues": [
            {
                "code": "EVALUATION_NO_PENDING_REQUEST",
                "message": "The evaluation run has no pending request.",
                "related_ids": [],
            }
        ],
    }
    assert _tree_bytes(run) == before


def test_portable_preflight_propagates_transition_integrity_failure_without_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Portable integrity faults must remain distinct from semantic rejection."""
    portable = _load_portable()
    run = tmp_path / "run"
    portable.initialize_evaluation(_case_payload(), run, seed_hex="0" * 64)
    request = portable.next_judge_request(run)
    assert request is not None
    response = _response(request, _scripted_payloads()[0], 1)
    before = _tree_bytes(run)

    def fail_integrity(*args: object, **kwargs: object) -> None:
        raise portable.EvaluationIntegrityError("injected transition failure")

    monkeypatch.setattr(portable, "_accepted_transition", fail_integrity)

    with pytest.raises(
        portable.EvaluationIntegrityError,
        match="injected transition failure",
    ):
        portable.preflight_judge_response(run, response)

    assert _tree_bytes(run) == before


def test_portable_guarded_submit_matches_core_for_valid_and_refused_responses(
    tmp_path: Path,
) -> None:
    """Guarded portable submission must share the core result and artifact contracts."""
    portable = _load_portable()
    case_payload = _case_payload()
    portable_run = tmp_path / "portable"
    core_run = tmp_path / "core"
    portable.initialize_evaluation(case_payload, portable_run, seed_hex="d" * 64)
    initialize_core(_core_case_from_payload(case_payload), core_run, seed_hex="d" * 64)
    request = portable.next_judge_request(portable_run)
    core_request = next_core(core_run)
    assert request is not None and core_request is not None
    assert request == core_request.model_dump(mode="json")
    valid = _response(request, _scripted_payloads()[0], 1)
    refused = copy.deepcopy(valid)
    refused["payload"] = {"malformed": True}
    portable_before = _tree_bytes(portable_run)
    core_before = _tree_bytes(core_run)

    portable_refused = portable.guarded_submit_judge_response(portable_run, refused)
    core_refused = guarded_submit_core(core_run, JudgeResponse.model_validate(refused))

    assert portable_refused == core_refused.model_dump(mode="json")
    assert _tree_bytes(portable_run) == portable_before
    assert _tree_bytes(core_run) == core_before

    portable_accepted = portable.guarded_submit_judge_response(portable_run, valid)
    core_accepted = guarded_submit_core(core_run, JudgeResponse.model_validate(valid))

    assert portable_accepted == core_accepted.model_dump(mode="json")
    assert _tree_bytes(portable_run) == _tree_bytes(core_run)


def test_portable_guarded_submit_propagates_transition_integrity_write_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Injected transition integrity faults are exit-class 5, not retryable responses."""
    portable = _load_portable()
    case_payload = _case_payload()
    portable_run = tmp_path / "portable"
    core_run = tmp_path / "core"
    portable.initialize_evaluation(case_payload, portable_run, seed_hex="e" * 64)
    initialize_core(_core_case_from_payload(case_payload), core_run, seed_hex="e" * 64)
    request = portable.next_judge_request(portable_run)
    assert request is not None
    response = _response(request, _scripted_payloads()[0], 1)
    portable_before = _tree_bytes(portable_run)
    core_before = _tree_bytes(core_run)

    def fail_portable(*args: object, **kwargs: object) -> None:
        raise portable.EvaluationIntegrityError("injected transition fault")

    def fail_core(*args: object, **kwargs: object) -> None:
        raise attorney_artifacts.EvaluationIntegrityError("injected transition fault")

    monkeypatch.setattr(portable, "_accepted_transition", fail_portable)
    monkeypatch.setattr(core_workflow, "_accepted_transition", fail_core)

    with pytest.raises(portable.EvaluationIntegrityError, match="injected transition fault"):
        portable.guarded_submit_judge_response(portable_run, response)
    with pytest.raises(
        attorney_artifacts.EvaluationIntegrityError, match="injected transition fault"
    ):
        guarded_submit_core(core_run, JudgeResponse.model_validate(response))
    with pytest.raises(portable.EvaluationIntegrityError, match="injected transition fault"):
        portable.submit_judge_response(portable_run, response)
    with pytest.raises(
        attorney_artifacts.EvaluationIntegrityError, match="injected transition fault"
    ):
        submit_core(core_run, JudgeResponse.model_validate(response))

    assert portable.EVAL_EXIT_INTEGRITY == 5
    assert _tree_bytes(portable_run) == portable_before
    assert _tree_bytes(core_run) == core_before
