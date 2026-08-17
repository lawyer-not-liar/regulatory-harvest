from __future__ import annotations

import base64
import hashlib
import io
import json
import tarfile
from collections import Counter
from datetime import date
from pathlib import Path

import pytest

import regulatory_harvest.evaluation.attorney_artifacts as attorney_artifacts
import regulatory_harvest.evaluation.attorney_workflow as attorney_workflow
from regulatory_harvest.evaluation.attorney_admission import freeze_case
from regulatory_harvest.evaluation.attorney_artifacts import verify_evaluation_run
from regulatory_harvest.evaluation.attorney_ledger import (
    _ledger_invariant_contract_v1_0,
    ledger_invariant_contract,
)
from regulatory_harvest.evaluation.attorney_models import (
    AbsoluteDisposition,
    AdmissionCheck,
    AttorneyEvaluationCase,
    CandidateReport,
    CandidateRole,
    CaseEnvelope,
    CoverageDisposition,
    EntryGrade,
    EvaluationMode,
    EvaluationRunPhase,
    EvaluationSource,
    EvaluationTerminalStatus,
    JudgeIsolation,
    JudgeOperation,
    JudgeRequest,
    JudgeResponse,
    LedgerAudit,
    LedgerCategory,
    LedgerCitation,
    LedgerDispute,
    LedgerEntry,
    LegalLedger,
    Materiality,
    NarrativeScore,
    ReadinessStatus,
    RefereeDecision,
    RequestedAuthority,
)
from regulatory_harvest.evaluation.attorney_workflow import (
    AttorneyEvaluationJudge,
    guarded_submit_judge_response,
    initialize_evaluation,
    next_judge_request,
    resume_evaluation,
    run_evaluation,
    submit_judge_response,
)
from regulatory_harvest.models import SourceQuality, SourceRole

SOURCE_TEXT = "A covered entity must file notice within 30 days."
NARRATIVE_DIMENSIONS = (
    "executive_summary",
    "regulatory_walk",
    "key_requirements",
    "penalties_enforcement",
    "qualification_placement",
    "requirements_workplan_boundary",
    "limitations",
    "scanability",
)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _extract_tar_fixture(archive_bytes: bytes, destination: Path) -> None:
    """Extract a known fixture only after rejecting unsafe archive members."""
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
                raise ValueError("unsafe fixture archive member")
        try:
            archive.extractall(destination, filter="data")
        except TypeError:
            archive.extractall(destination)


def artifact_tree_bytes(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _rewrite_core_history_artifacts(
    run: Path,
    replacements: dict[str, bytes],
) -> None:
    """Rebind hashes so replay, rather than inventory hashing, judges a mutation."""
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
            request = JudgeRequest.model_validate_json(
                replacements[request_path],
                strict=True,
            )
            call["request_fingerprint"] = request.request_fingerprint
            call["prompt_fingerprint"] = attorney_artifacts._prompt_fingerprint(request)
    manifest["artifact_inventory_fingerprint"] = hashlib.sha256(
        attorney_artifacts._ordinary_json_bytes(manifest["artifacts"])
    ).hexdigest()
    manifest["manifest_fingerprint"] = "0" * 64
    manifest["manifest_fingerprint"] = hashlib.sha256(
        attorney_artifacts._ordinary_json_bytes(
            {
                key: value
                for key, value in manifest.items()
                if key != "manifest_fingerprint"
            }
        )
    ).hexdigest()
    manifest_path.write_bytes(attorney_artifacts._ordinary_json_bytes(manifest))


def _capsule_provenance(
    candidate_id: str,
    report_text: str,
    *,
    source_hash: str,
) -> dict[str, object]:
    report_hash = _sha256(report_text)
    return {
        "capsule_root": _sha256(f"capsule:{candidate_id}"),
        "generation_record": {
            "candidate_id": candidate_id,
            "capture_fingerprint": _sha256(f"capture:{candidate_id}"),
            "client_facts_hash": None,
            "generation_isolation": "scripted_fixture",
            "generator_artifact_hashes": {"generator": _sha256("generator")},
            "model_name": "synthetic-model",
            "nonce_fingerprint": _sha256(f"nonce:{candidate_id}"),
            "provider_name": "synthetic-provider",
            "report_hash": report_hash,
            "request_fingerprint": _sha256(f"request:{candidate_id}"),
            "response_fingerprint": _sha256(f"response:{candidate_id}"),
            "response_id": None,
            "schema_version": "1.0",
            "source_hashes": {"source-1": source_hash},
            "usage": {},
        },
        "generation_question": "When must notice be filed?",
        "kind": "capsule",
    }


def synthetic_case(*, comparator: bool = False) -> AttorneyEvaluationCase:
    source_hash = _sha256(SOURCE_TEXT)
    candidate_text = "The report says notice is due within 30 days."
    candidates = [
        CandidateReport(
            candidate_id="harvest-private-id",
            role=CandidateRole.CANDIDATE,
            report_text=candidate_text,
            report_hash=_sha256(candidate_text),
            validation_receipt=(
                _capsule_provenance(
                    "harvest-private-id", candidate_text, source_hash=source_hash
                )
                if comparator
                else {"kind": "external"}
            ),
        )
    ]
    if comparator:
        comparator_text = "Covered entities must file notice within thirty days."
        candidates.append(
            CandidateReport(
                candidate_id="comparator-private-id",
                role=CandidateRole.COMPARATOR,
                report_text=comparator_text,
                report_hash=_sha256(comparator_text),
                validation_receipt=_capsule_provenance(
                    "comparator-private-id", comparator_text, source_hash=source_hash
                ),
            )
        )
    return AttorneyEvaluationCase(
        schema_version="1.1",
        case_id="public-synthetic-case",
        mode=EvaluationMode.CLOSED_UNIVERSE,
        question="When must notice be filed?",
        jurisdiction="Example State",
        as_of=date(2026, 8, 12),
        requested_authorities=[
            RequestedAuthority(
                authority_id="example-rule",
                title="Example Notice Rule",
                jurisdiction="Example State",
                authority_type="regulation",
                source_ids=["source-1"],
            )
        ],
        sources=[
            EvaluationSource(
                source_id="source-1",
                title="Example Notice Rule",
                normalized_text=SOURCE_TEXT,
                content_hash=source_hash,
                jurisdiction="Example State",
                authority_type="regulation",
                source_role=SourceRole.OFFICIAL_PRIMARY,
                source_quality=SourceQuality.PRIMARY,
                completeness="complete",
                language="en",
            )
        ],
        candidates=candidates,
    )


class ScriptedJudge:
    def __init__(
        self,
        *,
        invalid_attempts: dict[JudgeOperation, int] | None = None,
        invalid_admission: bool = False,
    ) -> None:
        self.invalid_attempts = Counter(invalid_attempts or {})
        self.invalid_admission = invalid_admission
        self.requests: list[JudgeRequest] = []
        self._response_number = 0

    async def evaluate(self, request: JudgeRequest) -> JudgeResponse:
        self.requests.append(request)
        self._response_number += 1
        if self.invalid_attempts[request.operation]:
            self.invalid_attempts[request.operation] -= 1
            payload: dict[str, object] = {"malformed": True}
        else:
            payload = self._payload(request)
        return JudgeResponse(
            operation=request.operation,
            request_fingerprint=request.request_fingerprint,
            provider_name="synthetic-provider",
            model_name="synthetic-model",
            judge_isolation=JudgeIsolation.SCRIPTED_FIXTURE,
            response_id=f"response-{self._response_number}",
            payload=payload,
        )

    def _payload(self, request: JudgeRequest) -> dict[str, object]:
        if request.operation is JudgeOperation.ADMIT_CASE:
            checks = [
                AdmissionCheck(
                    code=code,
                    satisfied=not (self.invalid_admission and code == "OPERATIVE_TEXT"),
                    material=True,
                    rationale="The synthetic record supplies the required evidence.",
                    source_ids=["source-1"],
                ).model_dump(mode="json")
                for code in (
                    "AUTHORITY_ALIGNMENT",
                    "OPERATIVE_TEXT",
                    "CURRENTNESS_EVIDENCE",
                    "LANGUAGE_RESOLUTION",
                    "SOURCE_PARITY",
                )
            ]
            return {
                "request_fingerprint": request.request_fingerprint,
                "checks": checks,
                "issues": [],
            }
        if request.operation is JudgeOperation.BUILD_LEDGER:
            return LegalLedger(
                case_fingerprint=request.safe_metadata["source_record_fingerprint"],
                entries=[
                    LedgerEntry(
                        ledger_id="notice-duty",
                        walk_order=0,
                        category=LedgerCategory.REQUIREMENT,
                        materiality=Materiality.CRITICAL,
                        actor="covered entity",
                        modality="must",
                        operative_action="file notice",
                        object="notice",
                        timing="within 30 days",
                        proposition="A covered entity must file notice within 30 days.",
                        materiality_rationale=(
                            "Missing the filing deadline defeats timely legal notice."
                        ),
                        citations=[
                            LedgerCitation(
                                source_id="source-1",
                                start_char=0,
                                end_char=len(SOURCE_TEXT),
                                quote=SOURCE_TEXT,
                            )
                        ],
                    )
                ],
            ).model_dump(mode="json")
        if request.operation is JudgeOperation.AUDIT_LEDGER:
            return LedgerAudit(
                request_fingerprint=request.request_fingerprint,
                disputes=[],
                complete=True,
            ).model_dump(mode="json")
        if request.operation is JudgeOperation.GRADE_REPORT:
            label = request.payload["anonymous_report"]["anonymous_label"]
            ledger_fingerprint = request.safe_metadata["legal_ledger_fingerprint"]
            return {
                "schema_version": "1.3",
                "request_fingerprint": request.request_fingerprint,
                "anonymous_label": label,
                "ledger_fingerprint": ledger_fingerprint,
                "entry_grades": [
                    EntryGrade(
                        ledger_id="notice-duty",
                        disposition=CoverageDisposition.COMPLETE,
                        rationale="The report states the duty and its deadline.",
                        report_location="paragraph 1",
                        report_passage=str(
                            request.payload["anonymous_report"]["report_text"]
                        ),
                    ).model_dump(mode="json")
                ],
                "out_of_ledger_claims": [],
                "narrative_scores": [
                    NarrativeScore(
                        dimension=dimension,
                        score=4,
                        rationale="The report handles this dimension clearly.",
                        report_passage=str(
                            request.payload["anonymous_report"]["report_text"]
                        ),
                    ).model_dump(mode="json")
                    for dimension in NARRATIVE_DIMENSIONS
                ],
            }
        raise AssertionError(f"unexpected operation: {request.operation}")


def test_ledger_invariant_contract_matches_validator_boundary() -> None:
    """Each full-runtime ledger request discloses the validator's closed boundary."""
    expected = {
        "schema_version": "1.1",
        "binding": {
            "case_fingerprint": "source_record.source_record_fingerprint",
        },
        "identity": {
            "ledger_ids": "unique",
            "gap_ids": "unique",
            "entry_gap_ids": "disjoint",
            "walk_order": "unique_contiguous_zero_based",
        },
        "relationships": {
            "targets": "known_ledger_ids",
            "self_reference": "forbidden",
            "trigger_link_categories": ["enforcement", "penalty"],
            "trigger_target_categories": ["requirement", "prohibition"],
        },
        "citations": {
            "source_ids": "known_retained_sources",
            "slices": "unique_exact_half_open",
            "quote": "exact_source_text",
            "operative_categories_require_exact_support": True,
            "operative_categories_forbid_commentary_only_support": True,
        },
        "required_fields": {
            "requirement_prohibition_right": ["actor", "object"],
            "deadline": ["timing"],
            "exception": ["conditions_or_exceptions"],
            "enforcement": [
                "enforcing_authority",
                "enforcement_route",
                "trigger_link",
            ],
            "penalty": ["consequence", "trigger_link"],
            "remedy": ["consequence"],
        },
        "materiality_rationale": {
            "minimum_word_tokens": 5,
            "forbidden_exact_normalized_values": [
                "critical",
                "high priority",
                "important",
                "material",
                "significant",
            ],
        },
        "repair_closure": {
            "resolve_every_initial_finding": "evaluator_attestation",
            "remaining_audit_request_fingerprint": (
                "deterministically_enforced"
            ),
            "complete_true_requires_full_recheck": "evaluator_attestation",
            "remaining_disputes": (
                "deterministically_enforced_transaction_ready_only"
            ),
        },
    }

    assert ledger_invariant_contract.__doc__ == (
        "Return the mixed deterministic/attested ledger-role contract."
    )
    assert ledger_invariant_contract() == expected

    envelope = freeze_case(synthetic_case(comparator=False), seed_hex="0" * 64)
    build_request = attorney_workflow._build_ledger_request(envelope)
    ledger = LegalLedger.model_validate(ScriptedJudge()._payload(build_request))
    audit_request = attorney_workflow._audit_ledger_request(envelope, ledger)
    audit = LedgerAudit(
        request_fingerprint=audit_request.request_fingerprint,
        disputes=[],
        complete=True,
    )
    repair_request = attorney_workflow._repair_ledger_request(envelope, ledger, audit)

    for request in (build_request, audit_request, repair_request):
        assert list(request.payload).count("ledger_invariant_contract") == 1
        assert request.payload["ledger_invariant_contract"] == expected
        assert "ledger_invariant_contract" in request.system_instructions

    for requirement in (
        "global walk-order renumbering",
        "new-ID allocation",
        "relationship remapping",
        "exact-citation rechecking",
        "full closure validation",
    ):
        assert requirement in repair_request.system_instructions
    assert "deterministically_enforced" not in repair_request.system_instructions


def test_ledger_invariant_contract_returns_fresh_nested_values() -> None:
    """Mutating a returned contract cannot alter a later request's contract."""
    expected = ledger_invariant_contract()
    mutated = ledger_invariant_contract()
    relationships = mutated["relationships"]
    assert isinstance(relationships, dict)
    trigger_categories = relationships["trigger_link_categories"]
    assert isinstance(trigger_categories, list)
    trigger_categories.append("remedy")

    assert ledger_invariant_contract() == expected


def _ledger_requests_with_contract_modes(
    build_mode: str,
    audit_mode: str,
    repair_mode: str,
) -> dict[JudgeOperation, JudgeRequest]:
    """Build exact ledger request shapes whose contract modes can be compared."""
    envelope = freeze_case(synthetic_case(comparator=False), seed_hex="0" * 64)
    build_request = attorney_workflow._build_ledger_request(envelope)
    ledger = LegalLedger.model_validate(ScriptedJudge()._payload(build_request))
    audit_request = attorney_workflow._audit_ledger_request(envelope, ledger)
    audit = LedgerAudit(
        request_fingerprint=audit_request.request_fingerprint,
        disputes=[],
        complete=True,
    )
    repair_request = attorney_workflow._repair_ledger_request(envelope, ledger, audit)

    def with_mode(request: JudgeRequest, mode: str) -> JudgeRequest:
        payload = json.loads(json.dumps(request.payload))
        instructions = request.system_instructions
        if mode == "pre-contract":
            payload.pop("ledger_invariant_contract")
            instructions = instructions.replace(
                "ledger_invariant_contract", "ledger invariant contract"
            )
        elif mode == "1.0":
            payload["ledger_invariant_contract"] = _ledger_invariant_contract_v1_0()
        elif mode == "1.1":
            payload["ledger_invariant_contract"] = ledger_invariant_contract()
        else:
            raise AssertionError(f"unexpected ledger contract mode: {mode}")
        return request.model_copy(
            update={"payload": payload, "system_instructions": instructions}
        )

    return {
        JudgeOperation.BUILD_LEDGER: with_mode(build_request, build_mode),
        JudgeOperation.AUDIT_LEDGER: with_mode(audit_request, audit_mode),
        JudgeOperation.REPAIR_LEDGER: with_mode(repair_request, repair_mode),
    }


@pytest.mark.parametrize(
    ("first_mode", "second_mode"),
    [
        ("pre-contract", "1.0"),
        ("1.0", "pre-contract"),
        ("1.0", "1.1"),
        ("1.1", "1.0"),
        ("1.1", "pre-contract"),
        ("pre-contract", "1.1"),
    ],
)
@pytest.mark.parametrize(
    "transition",
    [
        (JudgeOperation.BUILD_LEDGER, JudgeOperation.AUDIT_LEDGER),
        (JudgeOperation.AUDIT_LEDGER, JudgeOperation.REPAIR_LEDGER),
    ],
)
def test_artifact_replay_rejects_mixed_ledger_contract_modes_at_each_transition(
    first_mode: str,
    second_mode: str,
    transition: tuple[JudgeOperation, JudgeOperation],
) -> None:
    """Every ledger request in one replay run must use the same contract mode."""
    modes = {
        JudgeOperation.BUILD_LEDGER: "1.1",
        JudgeOperation.AUDIT_LEDGER: "1.1",
        JudgeOperation.REPAIR_LEDGER: "1.1",
    }
    modes[transition[0]] = first_mode
    modes[transition[1]] = second_mode
    requests = _ledger_requests_with_contract_modes(
        modes[JudgeOperation.BUILD_LEDGER],
        modes[JudgeOperation.AUDIT_LEDGER],
        modes[JudgeOperation.REPAIR_LEDGER],
    )

    with pytest.raises(
        attorney_artifacts.EvaluationIntegrityError,
        match="ledger request invariant-contract modes differ",
    ):
        attorney_artifacts._verify_ledger_contract_mode_consistency(
            [requests[transition[0]], requests[transition[1]]]
        )


@pytest.mark.parametrize("mode", ["pre-contract", "1.0", "1.1"])
def test_artifact_replay_accepts_each_coherent_ledger_contract_mode(mode: str) -> None:
    """Pre-contract, 1.0, and 1.1 each remain valid when coherent per run."""
    requests = _ledger_requests_with_contract_modes(mode, mode, mode)

    attorney_artifacts._verify_ledger_contract_mode_consistency(list(requests.values()))


@pytest.mark.parametrize(
    ("fixture_name", "archive_hash", "contract_version"),
    [
        (
            "legacy-ledger-repair-919eb5f.tgz.b64",
            "0a13f0fbeb9c6c5841a198a811efcf1f567c91ebfbeade3f9d4214b87ee7729d",
            None,
        ),
        (
            "ledger-invariant-contract-v1-445f4d9.tgz.b64",
            "3446c3904939653460c52ba54334b89739b012107a6e17bc3ee2c041e4d10952",
            "1.0",
        ),
    ],
)
def test_replay_accepts_base_version_completed_ledger_repair_fixture(
    tmp_path: Path,
    fixture_name: str,
    archive_hash: str,
    contract_version: str | None,
) -> None:
    """Actual pre-contract and schema-1.0 completed repairs remain replayable."""
    fixture = Path(__file__).parents[1] / "fixtures/attorney-eval" / fixture_name
    archive_bytes = base64.b64decode(fixture.read_bytes())
    assert hashlib.sha256(archive_bytes).hexdigest() == archive_hash
    _extract_tar_fixture(archive_bytes, tmp_path)

    run_dir = tmp_path / "completed-repair"
    ledger_requests = [
        JudgeRequest.model_validate_json(path.read_bytes())
        for path in sorted((run_dir / "judge-requests").glob("ledger-*-attempt-1.json"))
        if path.name
        in {
            "ledger-build-attempt-1.json",
            "ledger-audit-attempt-1.json",
            "ledger-repair-attempt-1.json",
        }
    ]

    assert {request.operation for request in ledger_requests} == {
        JudgeOperation.BUILD_LEDGER,
        JudgeOperation.AUDIT_LEDGER,
        JudgeOperation.REPAIR_LEDGER,
    }
    if contract_version is None:
        assert all(
            "ledger_invariant_contract" not in request.payload for request in ledger_requests
        )
    else:
        contracts = [request.payload["ledger_invariant_contract"] for request in ledger_requests]
        assert all(isinstance(contract, dict) for contract in contracts)
        assert [contract["schema_version"] for contract in contracts] == [
            contract_version,
            contract_version,
            contract_version,
        ]
    assert verify_evaluation_run(run_dir).valid


def test_fixture_extraction_rejects_unsafe_archive_member(tmp_path: Path) -> None:
    """A fixture archive cannot write outside its supplied extraction directory."""
    archive_bytes = io.BytesIO()
    with tarfile.open(fileobj=archive_bytes, mode="w:gz") as archive:
        member = tarfile.TarInfo("../outside.txt")
        payload = b"unsafe"
        member.size = len(payload)
        archive.addfile(member, io.BytesIO(payload))

    with pytest.raises(ValueError, match="unsafe fixture archive member"):
        _extract_tar_fixture(archive_bytes.getvalue(), tmp_path)

    assert not (tmp_path.parent / "outside.txt").exists()


@pytest.mark.parametrize("mutation", ["unknown_version", "modified_contract"])
def test_replay_rejects_unknown_or_modified_ledger_contract(
    tmp_path: Path,
    mutation: str,
) -> None:
    """Replay accepts only the exact recognized invariant-contract versions."""
    initialize_evaluation(synthetic_case(comparator=False), tmp_path, seed_hex="0" * 64)
    judge = ScriptedJudge()
    admission_request = next_judge_request(tmp_path)
    assert admission_request is not None
    submit_judge_response(
        tmp_path,
        JudgeResponse(
            operation=admission_request.operation,
            request_fingerprint=admission_request.request_fingerprint,
            provider_name="synthetic-provider",
            model_name="synthetic-model",
            judge_isolation=JudgeIsolation.SCRIPTED_FIXTURE,
            response_id=f"contract-mutation-{mutation}",
            payload=judge._payload(admission_request),
        ),
    )
    request_path = "judge-requests/ledger-build-attempt-1.json"
    request = JudgeRequest.model_validate_json((tmp_path / request_path).read_bytes())
    payload = json.loads(json.dumps(request.payload))
    contract = payload["ledger_invariant_contract"]
    assert isinstance(contract, dict)
    if mutation == "unknown_version":
        contract["schema_version"] = "9.9"
    else:
        binding = contract["binding"]
        assert isinstance(binding, dict)
        binding["case_fingerprint"] = "modified"
    tampered = request.model_copy(
        update={"payload": payload, "request_fingerprint": "0" * 64}
    )
    tampered = tampered.model_copy(
        update={
            "request_fingerprint": attorney_artifacts._expected_request_fingerprint(tampered)
        }
    )
    _rewrite_core_history_artifacts(
        tmp_path,
        {request_path: attorney_artifacts._model_bytes(tampered, JudgeRequest)[1]},
    )

    with pytest.raises(
        attorney_artifacts.EvaluationIntegrityError,
        match="ledger-build request differs from the exact source-only packet",
    ):
        resume_evaluation(tmp_path)


@pytest.fixture
def initialized_audit_run(tmp_path: Path) -> Path:
    initialize_evaluation(synthetic_case(comparator=False), tmp_path, seed_hex="a" * 64)
    judge = ScriptedJudge()
    for response_number, expected_operation in enumerate(
        (JudgeOperation.ADMIT_CASE, JudgeOperation.BUILD_LEDGER), start=1
    ):
        request = next_judge_request(tmp_path)
        assert request is not None
        assert request.operation is expected_operation
        submit_judge_response(
            tmp_path,
            JudgeResponse(
                operation=request.operation,
                request_fingerprint=request.request_fingerprint,
                provider_name="synthetic-provider",
                model_name="synthetic-model",
                judge_isolation=JudgeIsolation.SCRIPTED_FIXTURE,
                response_id=f"initialized-audit-run-{response_number}",
                payload=judge._payload(request),
            ),
        )
    request = next_judge_request(tmp_path)
    assert request is not None
    assert request.operation is JudgeOperation.AUDIT_LEDGER
    return tmp_path


def synthetic_audit_response(run_dir: Path, audit_mutation: str) -> JudgeResponse:
    request = next_judge_request(run_dir)
    assert request is not None
    assert request.operation is JudgeOperation.AUDIT_LEDGER
    audit = LedgerAudit(
        request_fingerprint=request.request_fingerprint,
        complete=audit_mutation != "incomplete",
        disputes=(
            []
            if audit_mutation == "incomplete"
            else [
                LedgerDispute(
                    dispute_id="audit-1",
                    action="materiality",
                    target_ledger_ids=(
                        ["missing-entry"]
                        if audit_mutation == "unknown_target"
                        else ["notice-duty"]
                    ),
                    proposed_entries=[],
                    materiality=Materiality.SUPPORTING,
                    rationale=(
                        "brief"
                        if audit_mutation == "short_rationale"
                        else "The source record needs a ledger correction."
                    ),
                )
            ]
        ),
    )
    return JudgeResponse(
        operation=request.operation,
        request_fingerprint=request.request_fingerprint,
        provider_name="synthetic-provider",
        model_name="synthetic-model",
        judge_isolation=JudgeIsolation.SCRIPTED_FIXTURE,
        response_id=f"audit-response-{audit_mutation}",
        payload=audit.model_dump(mode="json"),
    )


@pytest.mark.parametrize(
    ("audit_mutation", "expected_code", "related_ids"),
    [
        ("short_rationale", "EVALUATION_AUDIT_RATIONALE_INSUFFICIENT", ["audit-1"]),
        ("incomplete", "EVALUATION_AUDIT_INCOMPLETE", []),
        ("unknown_target", "EVALUATION_AUDIT_TARGET_UNKNOWN", ["missing-entry"]),
    ],
)
def test_preflight_returns_safe_operation_specific_diagnostic(
    initialized_audit_run: Path,
    audit_mutation: str,
    expected_code: str,
    related_ids: list[str],
) -> None:
    """Audit contract defects return public-safe diagnostics without consuming the run."""
    before = artifact_tree_bytes(initialized_audit_run)
    response = synthetic_audit_response(initialized_audit_run, audit_mutation)

    result = attorney_workflow.preflight_judge_response(initialized_audit_run, response)

    assert result.ok is False
    assert [issue.code for issue in result.issues] == [expected_code]
    assert result.issues[0].related_ids == related_ids
    assert result.diagnostic_fingerprint is not None
    assert all(
        forbidden not in result.issues[0].message
        for forbidden in (
            SOURCE_TEXT,
            str(initialized_audit_run),
            "harvest-private-id",
            "A",
        )
    )
    assert artifact_tree_bytes(initialized_audit_run) == before


def test_guarded_submit_rejects_without_mutating_run(initialized_audit_run: Path) -> None:
    """A rejected guarded response must leave the append-only run byte-identical."""
    before = artifact_tree_bytes(initialized_audit_run)

    result = guarded_submit_judge_response(
        initialized_audit_run,
        synthetic_audit_response(initialized_audit_run, "incomplete"),
    )

    assert result.accepted is False
    assert result.state is None
    assert result.preflight.ok is False
    assert artifact_tree_bytes(initialized_audit_run) == before


@pytest.mark.asyncio
async def test_guarded_submit_matches_existing_valid_submit(tmp_path: Path) -> None:
    """Guarded submission commits the validation transition, not a recalculated variant."""
    guarded_run = tmp_path / "guarded"
    explicit_run = tmp_path / "explicit"
    for run in (guarded_run, explicit_run):
        initialize_evaluation(synthetic_case(comparator=False), run, seed_hex="c" * 64)
    request = next_judge_request(guarded_run)
    assert request is not None
    response = await ScriptedJudge().evaluate(request)

    guarded = guarded_submit_judge_response(guarded_run, response)
    explicit = submit_judge_response(explicit_run, response)

    assert guarded.accepted is True
    assert guarded.state == explicit
    assert artifact_tree_bytes(guarded_run) == artifact_tree_bytes(explicit_run)


class RepairAndRefereeJudge(ScriptedJudge):
    def __init__(self) -> None:
        super().__init__()
        self.grade_counts: Counter[str] = Counter()

    def _ledger_dispute(self) -> LedgerDispute:
        return LedgerDispute(
            dispute_id="notice-duty-materiality",
            action="materiality",
            target_ledger_ids=["notice-duty"],
            proposed_entries=[],
            materiality=Materiality.CRITICAL,
            rationale="The duty's materiality requires an independent decision.",
        )

    def _payload(self, request: JudgeRequest) -> dict[str, object]:
        if request.operation is JudgeOperation.AUDIT_LEDGER:
            return LedgerAudit(
                request_fingerprint=request.request_fingerprint,
                disputes=[self._ledger_dispute()],
                complete=True,
            ).model_dump(mode="json")
        if request.operation is JudgeOperation.REPAIR_LEDGER:
            return {
                "repaired_ledger": request.payload["proposed_ledger"],
                "remaining_audit": LedgerAudit(
                    request_fingerprint=request.request_fingerprint,
                    disputes=[self._ledger_dispute()],
                    complete=True,
                ).model_dump(mode="json"),
            }
        if (
            request.operation is JudgeOperation.REFEREE
            and request.safe_metadata["referee_scope"] == "ledger"
        ):
            return RefereeDecision(
                dispute_id="notice-duty-materiality",
                selected_ledger_resolution="accept_a",
                rationale="The source record supports the ledger's existing treatment.",
                source_ids=["source-1"],
            ).model_dump(mode="json")
        if request.operation is JudgeOperation.GRADE_REPORT:
            label = request.safe_metadata["anonymous_label"]
            self.grade_counts[label] += 1
            payload = super()._payload(request)
            if self.grade_counts[label] == 2:
                entry_grades = payload["entry_grades"]
                assert isinstance(entry_grades, list)
                entry_grade = entry_grades[0]
                assert isinstance(entry_grade, dict)
                entry_grade["disposition"] = CoverageDisposition.PARTIAL.value
                entry_grade["rationale"] = "The report only partially states the duty."
            return payload
        if (
            request.operation is JudgeOperation.REFEREE
            and request.safe_metadata["referee_scope"] == "report"
        ):
            dispute = request.payload["dispute"]
            assert isinstance(dispute, dict)
            return RefereeDecision(
                dispute_id=str(dispute["dispute_id"]),
                selected_grade_resolution="accept_grader_1",
                grade_dispute_fingerprint=str(
                    request.safe_metadata["grade_dispute_fingerprint"]
                ),
                rationale="The first grade is better supported by the supplied alternatives.",
            ).model_dump(mode="json")
        return super()._payload(request)


@pytest.mark.asyncio
async def test_initial_audit_nontransaction_add_and_split_findings_advance_to_repair(
    tmp_path: Path,
) -> None:
    """Initial source-only findings must reach repair without duplicating replacement entries."""
    case = synthetic_case(comparator=False)
    case.sources[0].title = "Example Notice Rule 1"
    initialize_evaluation(case, tmp_path, seed_hex="9" * 64)
    judge = ScriptedJudge()
    for _ in range(2):
        request = next_judge_request(tmp_path)
        assert request is not None
        submit_judge_response(tmp_path, await judge.evaluate(request))

    audit_request = next_judge_request(tmp_path)
    assert audit_request is not None
    assert audit_request.operation is JudgeOperation.AUDIT_LEDGER
    audit_response = JudgeResponse(
        operation=JudgeOperation.AUDIT_LEDGER,
        request_fingerprint=audit_request.request_fingerprint,
        provider_name="synthetic-provider",
        model_name="synthetic-model",
        judge_isolation=JudgeIsolation.SCRIPTED_FIXTURE,
        response_id="initial-nontransaction-audit",
        payload=LedgerAudit(
            request_fingerprint=audit_request.request_fingerprint,
            complete=True,
            disputes=[
                LedgerDispute(
                    dispute_id="add-omitted-record",
                    action="add",
                    target_ledger_ids=[],
                    proposed_entries=[],
                    materiality=Materiality.SUPPORTING,
                    rationale=(
                        "source-1 is missing covered entity notice requirement details."
                    ),
                ),
                LedgerDispute(
                    dispute_id="add-located-record",
                    action="add",
                    target_ledger_ids=[],
                    proposed_entries=[],
                    materiality=Materiality.SUPPORTING,
                    rationale="source-1 is missing the notice requirement at Rule 1.",
                ),
                LedgerDispute(
                    dispute_id="add-proposed-record",
                    action="add",
                    target_ledger_ids=[],
                    proposed_entries=[
                        LedgerEntry.model_validate(
                            audit_request.payload["proposed_ledger"]["entries"][0]
                        ).model_copy(update={"ledger_id": "proposed-notice"})
                    ],
                    materiality=Materiality.SUPPORTING,
                    rationale="The source record needs a ledger correction.",
                ),
                LedgerDispute(
                    dispute_id="split-notice-duty",
                    action="split",
                    target_ledger_ids=["notice-duty"],
                    proposed_entries=[],
                    materiality=Materiality.SUPPORTING,
                    rationale="The notice duty combines distinct filing and timing propositions.",
                ),
            ],
        ).model_dump(mode="json"),
    )

    state = submit_judge_response(tmp_path, audit_response)
    repair_request = next_judge_request(tmp_path)

    assert state.state is EvaluationRunPhase.LEDGER_REPAIR
    assert repair_request is not None
    assert repair_request.operation is JudgeOperation.REPAIR_LEDGER
    assert verify_evaluation_run(tmp_path).valid

    remaining = audit_response.payload.copy()
    remaining["request_fingerprint"] = repair_request.request_fingerprint
    retry_state = submit_judge_response(
        tmp_path,
        JudgeResponse(
            operation=JudgeOperation.REPAIR_LEDGER,
            request_fingerprint=repair_request.request_fingerprint,
            provider_name="synthetic-provider",
            model_name="synthetic-model",
            judge_isolation=JudgeIsolation.SCRIPTED_FIXTURE,
            response_id="remaining-nontransaction-audit",
            payload={
                "repaired_ledger": repair_request.payload["proposed_ledger"],
                "remaining_audit": remaining,
            },
        ),
    )
    retry_request = next_judge_request(tmp_path)

    assert retry_state.state is EvaluationRunPhase.LEDGER_REPAIR
    assert retry_state.attempt == 2
    assert retry_request is not None
    assert retry_request.operation is JudgeOperation.REPAIR_LEDGER
    assert verify_evaluation_run(tmp_path).valid


@pytest.mark.asyncio
async def test_initial_add_reusing_existing_ledger_id_retries_and_replays(
    tmp_path: Path,
) -> None:
    """An add-shaped repair subject must not reuse an entry already in the ledger."""
    initialize_evaluation(synthetic_case(comparator=False), tmp_path, seed_hex="5" * 64)
    judge = ScriptedJudge()
    for _ in range(2):
        request = next_judge_request(tmp_path)
        assert request is not None
        submit_judge_response(tmp_path, await judge.evaluate(request))
    audit_request = next_judge_request(tmp_path)
    assert audit_request is not None
    existing_entry = LedgerEntry.model_validate(
        audit_request.payload["proposed_ledger"]["entries"][0]
    )

    state = submit_judge_response(
        tmp_path,
        JudgeResponse(
            operation=JudgeOperation.AUDIT_LEDGER,
            request_fingerprint=audit_request.request_fingerprint,
            provider_name="synthetic-provider",
            model_name="synthetic-model",
            judge_isolation=JudgeIsolation.SCRIPTED_FIXTURE,
            response_id="reused-initial-add-id",
            payload=LedgerAudit(
                request_fingerprint=audit_request.request_fingerprint,
                complete=True,
                disputes=[
                    LedgerDispute(
                        dispute_id="reused-add-id",
                        action="add",
                        target_ledger_ids=[],
                        proposed_entries=[existing_entry],
                        materiality=Materiality.SUPPORTING,
                        rationale="The source record needs a ledger correction.",
                    )
                ],
            ).model_dump(mode="json"),
        ),
    )
    retry = next_judge_request(tmp_path)

    assert state.state is EvaluationRunPhase.LEDGER_AUDIT
    assert state.attempt == 2
    assert retry is not None and retry.operation is JudgeOperation.AUDIT_LEDGER
    diagnostics = json.loads(
        (tmp_path / "judge-diagnostics/ledger-audit-attempt-1.json").read_text(
            encoding="utf-8"
        )
    )
    assert "add initial ledger finding must use new ledger IDs" in diagnostics["issues"][0][
        "message"
    ]
    assert verify_evaluation_run(tmp_path).valid


@pytest.mark.asyncio
async def test_replay_rejects_rebound_initial_add_with_existing_ledger_id(
    tmp_path: Path,
) -> None:
    """A self-consistently rebound completed add finding must retain add semantics."""
    initialize_evaluation(synthetic_case(comparator=False), tmp_path, seed_hex="6" * 64)
    judge = ScriptedJudge()
    for _ in range(2):
        request = next_judge_request(tmp_path)
        assert request is not None
        submit_judge_response(tmp_path, await judge.evaluate(request))
    audit_request = next_judge_request(tmp_path)
    assert audit_request is not None
    proposed = LedgerEntry.model_validate(
        audit_request.payload["proposed_ledger"]["entries"][0]
    ).model_copy(update={"ledger_id": "proposed-notice"})
    response = JudgeResponse(
        operation=JudgeOperation.AUDIT_LEDGER,
        request_fingerprint=audit_request.request_fingerprint,
        provider_name="synthetic-provider",
        model_name="synthetic-model",
        judge_isolation=JudgeIsolation.SCRIPTED_FIXTURE,
        response_id="valid-initial-add-id",
        payload=LedgerAudit(
            request_fingerprint=audit_request.request_fingerprint,
            complete=True,
            disputes=[
                LedgerDispute(
                    dispute_id="add-proposed-record",
                    action="add",
                    target_ledger_ids=[],
                    proposed_entries=[proposed],
                    materiality=Materiality.SUPPORTING,
                    rationale="The source record needs a ledger correction.",
                )
            ],
        ).model_dump(mode="json"),
    )
    submit_judge_response(tmp_path, response)
    assert verify_evaluation_run(tmp_path).valid

    response_path = "judge-responses/ledger-audit-attempt-1.json"
    rebound_response = json.loads((tmp_path / response_path).read_text(encoding="utf-8"))
    rebound_response["payload"]["disputes"][0]["proposed_entries"][0][
        "ledger_id"
    ] = "notice-duty"
    rebound_audit = rebound_response["payload"]
    envelope = CaseEnvelope.model_validate_json(
        (tmp_path / "case-envelope.json").read_bytes(),
        strict=True,
    )
    proposed_ledger = LegalLedger.model_validate_json(
        (tmp_path / "legal-ledger.proposed.json").read_bytes(),
        strict=True,
    )
    rebound_repair_request = attorney_workflow._repair_ledger_request(
        envelope,
        proposed_ledger,
        LedgerAudit.model_validate(rebound_audit),
    )
    repair_request_path = "judge-requests/ledger-repair-attempt-1.json"
    _rewrite_core_history_artifacts(
        tmp_path,
        {
            response_path: attorney_artifacts._ordinary_json_bytes(rebound_response),
            "legal-ledger-audit.json": attorney_artifacts._ordinary_json_bytes(
                rebound_audit
            ),
            repair_request_path: attorney_artifacts._model_bytes(
                rebound_repair_request,
                JudgeRequest,
            )[1],
        },
    )

    assert verify_evaluation_run(tmp_path).issues == (
        "add initial ledger finding must use new ledger IDs",
    )


@pytest.mark.asyncio
async def test_initial_audit_contradictory_generic_finding_retries_and_replays(
    tmp_path: Path,
) -> None:
    """A contradictory generic finding must persist only as a failed, replayable attempt."""
    initialize_evaluation(synthetic_case(comparator=False), tmp_path, seed_hex="8" * 64)
    judge = ScriptedJudge()
    for _ in range(2):
        request = next_judge_request(tmp_path)
        assert request is not None
        submit_judge_response(tmp_path, await judge.evaluate(request))
    audit_request = next_judge_request(tmp_path)
    assert audit_request is not None

    state = submit_judge_response(
        tmp_path,
        JudgeResponse(
            operation=JudgeOperation.AUDIT_LEDGER,
            request_fingerprint=audit_request.request_fingerprint,
            provider_name="synthetic-provider",
            model_name="synthetic-model",
            judge_isolation=JudgeIsolation.SCRIPTED_FIXTURE,
            response_id="contradictory-generic-finding",
            payload=LedgerAudit(
                request_fingerprint=audit_request.request_fingerprint,
                complete=True,
                disputes=[
                    LedgerDispute(
                        dispute_id="contradictory-add",
                        action="add",
                        target_ledger_ids=["notice-duty"],
                        proposed_entries=[],
                        materiality=Materiality.SUPPORTING,
                        rationale="This finding is very important indeed.",
                    )
                ],
            ).model_dump(mode="json"),
        ),
    )
    retry = next_judge_request(tmp_path)

    assert state.state is EvaluationRunPhase.LEDGER_AUDIT
    assert state.attempt == 2
    assert retry is not None
    assert retry.operation is JudgeOperation.AUDIT_LEDGER
    assert verify_evaluation_run(tmp_path).valid


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
            "unknown-source is missing covered entity notice requirement details.",
        ),
        (
            "split",
            ["unknown-ledger-id"],
            "The notice duty combines distinct filing and timing propositions.",
        ),
        (
            "add",
            [],
            "source-1 is missing the notice requirement at Rule 404.",
        ),
        (
            "add",
            [],
            (
                "source-1 is missing covered entity notice requirement details "
                "at Section 999."
            ),
        ),
    ],
)
@pytest.mark.asyncio
async def test_initial_audit_content_free_finding_retries_and_replays(
    tmp_path: Path, action: str, targets: list[str], rationale: str
) -> None:
    """Ungrounded findings must remain replayable failed attempts."""
    initialize_evaluation(synthetic_case(comparator=False), tmp_path, seed_hex="7" * 64)
    judge = ScriptedJudge()
    for _ in range(2):
        request = next_judge_request(tmp_path)
        assert request is not None
        submit_judge_response(tmp_path, await judge.evaluate(request))
    audit_request = next_judge_request(tmp_path)
    assert audit_request is not None

    state = submit_judge_response(
        tmp_path,
        JudgeResponse(
            operation=JudgeOperation.AUDIT_LEDGER,
            request_fingerprint=audit_request.request_fingerprint,
            provider_name="synthetic-provider",
            model_name="synthetic-model",
            judge_isolation=JudgeIsolation.SCRIPTED_FIXTURE,
            response_id="content-free-finding",
            payload=LedgerAudit(
                request_fingerprint=audit_request.request_fingerprint,
                complete=True,
                disputes=[
                    LedgerDispute(
                        dispute_id="ungrounded-finding",
                        action=action,  # type: ignore[arg-type]
                        target_ledger_ids=targets,
                        proposed_entries=[],
                        materiality=Materiality.SUPPORTING,
                        rationale=rationale,
                    )
                ],
            ).model_dump(mode="json"),
        ),
    )
    retry = next_judge_request(tmp_path)

    assert state.state is EvaluationRunPhase.LEDGER_AUDIT
    assert state.attempt == 2
    assert retry is not None
    assert retry.operation is JudgeOperation.AUDIT_LEDGER
    assert verify_evaluation_run(tmp_path).valid


@pytest.mark.parametrize(
    ("defect", "issue_code"),
    [
        ("unknown-source", "LEDGER_CITATION_SOURCE_UNKNOWN"),
        ("wrong-quote", "LEDGER_QUOTE_MISMATCH"),
        ("out-of-range", "LEDGER_QUOTE_MISMATCH"),
        ("commentary-only", "LEDGER_COMMENTARY_ONLY_SUPPORT"),
    ],
)
@pytest.mark.asyncio
async def test_initial_audit_invalid_proposed_entry_retries_and_replays(
    tmp_path: Path, defect: str, issue_code: str
) -> None:
    """Source-invalid proposed entries must persist only as replayable failed attempts."""
    case = synthetic_case(comparator=False)
    if defect == "commentary-only":
        commentary = case.sources[0].model_copy(
            update={
                "source_id": "commentary-source",
                "source_role": SourceRole.COMMENTARY_ANALYSIS,
                "source_quality": SourceQuality.SECONDARY,
            }
        )
        case.sources.append(commentary)
        case.requested_authorities[0].source_ids.append(commentary.source_id)
    initialize_evaluation(case, tmp_path, seed_hex="6" * 64)
    judge = ScriptedJudge()
    for _ in range(2):
        request = next_judge_request(tmp_path)
        assert request is not None
        submit_judge_response(tmp_path, await judge.evaluate(request))
    audit_request = next_judge_request(tmp_path)
    assert audit_request is not None
    proposed = LedgerEntry.model_validate(
        audit_request.payload["proposed_ledger"]["entries"][0]
    ).model_copy(deep=True, update={"ledger_id": "invalid-proposed"})
    citation = proposed.citations[0]
    if defect == "unknown-source":
        citation.source_id = "unknown-source"
    elif defect == "wrong-quote":
        citation.quote = "notice must be filed by another entity"
    elif defect == "out-of-range":
        citation.start_char = len(SOURCE_TEXT) + 1
        citation.end_char = len(SOURCE_TEXT) + 2
        citation.quote = "x"
    else:
        citation.source_id = "commentary-source"

    state = submit_judge_response(
        tmp_path,
        JudgeResponse(
            operation=JudgeOperation.AUDIT_LEDGER,
            request_fingerprint=audit_request.request_fingerprint,
            provider_name="synthetic-provider",
            model_name="synthetic-model",
            judge_isolation=JudgeIsolation.SCRIPTED_FIXTURE,
            response_id="invalid-proposed-entry",
            payload=LedgerAudit(
                request_fingerprint=audit_request.request_fingerprint,
                complete=True,
                disputes=[
                    LedgerDispute(
                        dispute_id="invalid-proposed-finding",
                        action="add",
                        target_ledger_ids=[],
                        proposed_entries=[proposed],
                        materiality=Materiality.SUPPORTING,
                        rationale="The source record needs a ledger correction.",
                    )
                ],
            ).model_dump(mode="json"),
        ),
    )
    retry = next_judge_request(tmp_path)

    assert state.state is EvaluationRunPhase.LEDGER_AUDIT
    assert state.attempt == 2
    assert retry is not None
    assert retry.operation is JudgeOperation.AUDIT_LEDGER
    attempt = json.loads(
        (tmp_path / "judge-diagnostics" / "ledger-audit-attempt-1.json").read_text()
    )
    message = attempt["issues"][0]["message"]
    assert "invalid-proposed-finding" in message
    assert issue_code in message
    assert verify_evaluation_run(tmp_path).valid


class MultiDisputeRefereeJudge(RepairAndRefereeJudge):
    def __init__(self) -> None:
        super().__init__()
        self.invalid_report_referee_responses = 1

    def _payload(self, request: JudgeRequest) -> dict[str, object]:
        if (
            request.operation is JudgeOperation.REFEREE
            and request.safe_metadata["referee_scope"] == "report"
            and self.invalid_report_referee_responses
        ):
            self.invalid_report_referee_responses -= 1
            dispute = request.payload["dispute"]
            assert isinstance(dispute, dict)
            return RefereeDecision(
                dispute_id=str(dispute["dispute_id"]),
                selected_ledger_resolution="accept_a",
                rationale="This uses the wrong referee decision domain.",
            ).model_dump(mode="json")
        payload = super()._payload(request)
        if (
            request.operation is JudgeOperation.GRADE_REPORT
            and self.grade_counts[request.safe_metadata["anonymous_label"]] == 2
        ):
            narrative_scores = payload["narrative_scores"]
            assert isinstance(narrative_scores, list)
            narrative_score = narrative_scores[0]
            assert isinstance(narrative_score, dict)
            narrative_score["score"] = 3
            narrative_score["rationale"] = "This dimension is adequate, not excellent."
        return payload


def _omit_grade_defaults(payload: dict[str, object]) -> dict[str, object]:
    """Model a valid host response that leaves optional empty fields implicit."""
    payload.pop("out_of_ledger_claims")
    entry_grades = payload["entry_grades"]
    assert isinstance(entry_grades, list)
    for entry_grade in entry_grades:
        assert isinstance(entry_grade, dict)
        entry_grade.pop("finding_codes")
    narrative_scores = payload["narrative_scores"]
    assert isinstance(narrative_scores, list)
    for narrative_score in narrative_scores:
        assert isinstance(narrative_score, dict)
        narrative_score.pop("finding_codes")
    return payload


class DefaultOmittingJudge(ScriptedJudge):
    def _payload(self, request: JudgeRequest) -> dict[str, object]:
        payload = super()._payload(request)
        if request.operation is JudgeOperation.ADMIT_CASE:
            payload.pop("issues")
        elif request.operation is JudgeOperation.BUILD_LEDGER:
            payload.pop("gaps")
        elif request.operation is JudgeOperation.AUDIT_LEDGER:
            payload.pop("disputes")
        elif request.operation is JudgeOperation.GRADE_REPORT:
            _omit_grade_defaults(payload)
        return payload


class DefaultOmittingRepairAndRefereeJudge(RepairAndRefereeJudge):
    def _payload(self, request: JudgeRequest) -> dict[str, object]:
        payload = super()._payload(request)
        if request.operation is JudgeOperation.REPAIR_LEDGER:
            repaired = payload["repaired_ledger"]
            assert isinstance(repaired, dict)
            repaired.pop("gaps")
            remaining = payload["remaining_audit"]
            assert isinstance(remaining, dict)
            disputes = remaining["disputes"]
            assert isinstance(disputes, list)
            for dispute in disputes:
                assert isinstance(dispute, dict)
                dispute.pop("proposed_entries")
        elif request.operation is JudgeOperation.GRADE_REPORT:
            _omit_grade_defaults(payload)
        elif request.operation is JudgeOperation.REFEREE:
            for key in (
                "selected_disposition",
                "replacement_entries",
                "replacement_grade_alternative",
                "source_ids",
            ):
                payload.pop(key)
            if request.safe_metadata["referee_scope"] == "ledger":
                payload.pop("selected_grade_resolution")
                payload.pop("grade_dispute_fingerprint")
            else:
                payload.pop("selected_ledger_resolution")
        return payload


class EvidenceBindingJudge(ScriptedJudge):
    def __init__(self, mutation: str | None = None) -> None:
        super().__init__()
        self.mutation = mutation

    def _payload(self, request: JudgeRequest) -> dict[str, object]:
        payload = super()._payload(request)
        if request.operation is not JudgeOperation.GRADE_REPORT:
            return payload
        source_record = request.payload["source_record"]
        report = request.payload["anonymous_report"]
        assert isinstance(source_record, dict) and isinstance(report, dict)
        source = source_record["sources"][0]
        assert isinstance(source, dict)
        span = {
            "source_id": source["source_id"],
            "start_char": 0,
            "end_char": len(source["normalized_text"]),
            "quote": source["normalized_text"],
        }
        claim = {
            "claim_id": "whole-report-claim",
            "claim_text": report["report_text"],
            "report_location": "whole report",
            "disposition": "UNSUPPORTED",
            "category": "penalty",
            "materiality": "material",
            "related_ledger_ids": [],
            "source_record_fingerprint": source_record["source_record_fingerprint"],
            "evidence_basis": "source_spans",
            "evidence_spans": [span],
            "rationale": "The source span controls the claim disposition.",
        }
        if self.mutation == "wrong-fingerprint":
            claim["source_record_fingerprint"] = "f" * 64
        elif self.mutation == "unknown-source":
            span["source_id"] = "unknown-source"
        elif self.mutation == "bad-offsets":
            span["end_char"] = len(source["normalized_text"]) + 1
        elif self.mutation == "wrong-quote":
            span["quote"] = "Fabricated source quote."
        claims = payload["out_of_ledger_claims"]
        assert isinstance(claims, list)
        claims.append(claim)
        return payload


def _json_text(request: JudgeRequest) -> str:
    return json.dumps(request.model_dump(mode="json"), sort_keys=True)


@pytest.mark.asyncio
async def test_workflow_seals_and_verifies_blind_two_grader_evidence(
    tmp_path: Path,
) -> None:
    case = synthetic_case(comparator=False)
    judge = ScriptedJudge()

    completed = await run_evaluation(case, judge, tmp_path, seed_hex="4" * 64)

    assert isinstance(judge, AttorneyEvaluationJudge)
    assert completed.manifest.state is EvaluationRunPhase.COMPLETED
    assert completed.manifest.terminal_status is EvaluationTerminalStatus.COMPLETED
    assert completed.manifest.legal_ledger_hash
    assert completed.result.readiness.status is ReadinessStatus.ADMITTED
    assert all(
        report.absolute_disposition is AbsoluteDisposition.PASS
        for report in completed.result.reports
    )
    assert completed.result.comparison is None
    assert completed.result.judge_isolation == "fresh_context"
    assert "- Aggregate judge isolation: fresh_context." in (
        tmp_path / "evaluation-report.md"
    ).read_text(encoding="utf-8")
    matrix = completed.result.requirement_matrix
    assert matrix.available is True
    assert matrix.unavailable_reason is None
    assert len(matrix.rows) == 1
    row = matrix.rows[0]
    assert row.model_dump(mode="json") == {
        "ledger_id": "notice-duty",
        "walk_order": 0,
        "category": "requirement",
        "materiality": "critical",
        "proposition": "A covered entity must file notice within 30 days.",
        "citations": [
            {
                "source_id": "source-1",
                "start_char": 0,
                "end_char": len(SOURCE_TEXT),
            }
        ],
        "report_a": {
            "anonymous_label": "A",
            "disposition": "COMPLETE",
            "report_location": "paragraph 1",
            "finding_codes": [],
            "rationale": "The report states the duty and its deadline.",
        },
        "report_b": None,
    }

    grade_requests = [
        request for request in judge.requests if request.operation is JudgeOperation.GRADE_REPORT
    ]
    assert len(grade_requests) == 2
    assert all(
        request.safe_metadata["legal_ledger_hash"] == completed.manifest.legal_ledger_hash
        for request in grade_requests
    )
    for request in grade_requests:
        packet = request.payload
        assert set(packet) == {
            "anonymous_report",
            "sealed_ledger",
            "source_record",
            "source_spans",
            "deterministic_checks",
            "rubric",
            "finding_code_contract",
        }
        assert set(packet["anonymous_report"]) == {
            "anonymous_label",
            "report_hash",
            "report_text",
        }
        packet_text = _json_text(request)
        assert "harvest-private-id" not in packet_text
        assert "comparator-private-id" not in packet_text
        assert '"candidate"' not in packet_text
        assert '"comparator"' not in packet_text
        assert packet["source_record"]["sources"][0]["normalized_text"] == SOURCE_TEXT

    source_only_operations = {
        JudgeOperation.ADMIT_CASE,
        JudgeOperation.BUILD_LEDGER,
        JudgeOperation.AUDIT_LEDGER,
        JudgeOperation.REPAIR_LEDGER,
    }
    for request in judge.requests:
        if request.operation in source_only_operations:
            request_text = _json_text(request)
            assert all(
                candidate.report_text not in request_text
                for candidate in case.candidates
            )

    completed_grades = [
        call
        for call in completed.manifest.judge_calls
        if call.operation is JudgeOperation.GRADE_REPORT and call.state == "completed"
    ]
    calls = [call for call in completed_grades if call.anonymous_label == "A"]
    assert len(calls) == 2
    assert len({call.call_id for call in calls}) == 2
    assert len({call.response_fingerprint for call in calls}) == 2
    assert len({call.request_fingerprint for call in calls}) == 1

    paths = {artifact.artifact_path for artifact in completed.manifest.artifacts}
    assert {
        "report-score-inputs-A.json",
        "evaluation-result.json",
        "evaluation-report.md",
    }.issubset(paths)
    verification = verify_evaluation_run(tmp_path)
    assert verification.valid, verification.issues
    assert verification.root_hash == completed.manifest.manifest_fingerprint


@pytest.mark.asyncio
async def test_grader_receives_every_common_source_not_only_ledger_citations(
    tmp_path: Path,
) -> None:
    case = synthetic_case(comparator=False)
    second_text = "A separate definition governs covered entity status."
    case.sources.append(
        EvaluationSource(
            source_id="source-2",
            title="Synthetic Definition",
            normalized_text=second_text,
            content_hash=_sha256(second_text),
            jurisdiction="Example State",
            authority_type="regulation",
            source_role=SourceRole.OFFICIAL_PRIMARY,
            source_quality=SourceQuality.PRIMARY,
            completeness="complete",
            language="en",
        )
    )
    case.requested_authorities[0].source_ids.append("source-2")
    initialize_evaluation(case, tmp_path, seed_hex="0" * 64)
    judge = ScriptedJudge()
    for _ in range(3):
        request = next_judge_request(tmp_path)
        assert request is not None
        submit_judge_response(tmp_path, await judge.evaluate(request))

    grade_request = next_judge_request(tmp_path)

    assert grade_request is not None
    assert grade_request.operation is JudgeOperation.GRADE_REPORT
    assert {
        source["source_id"] for source in grade_request.payload["source_record"]["sources"]
    } == {"source-1", "source-2"}


@pytest.mark.asyncio
async def test_out_of_ledger_evidence_binding_persists_and_replays(
    tmp_path: Path,
) -> None:
    completed = await run_evaluation(
        synthetic_case(comparator=False),
        EvidenceBindingJudge(),
        tmp_path,
        seed_hex="1" * 64,
    )

    persisted = json.loads(
        (tmp_path / "grader-1-report-A.json").read_text(encoding="utf-8")
    )["out_of_ledger_claims"][0]
    assert persisted["source_record_fingerprint"]
    assert persisted["evidence_basis"] == "source_spans"
    assert persisted["evidence_spans"]
    assert completed.manifest.state is EvaluationRunPhase.COMPLETED
    assert verify_evaluation_run(tmp_path).valid


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mutation", "diagnostic"),
    [
        ("wrong-fingerprint", "common source record"),
        ("unknown-source", "unknown source"),
        ("bad-offsets", "exact common-source span"),
        ("wrong-quote", "exact common-source span"),
    ],
)
async def test_out_of_ledger_evidence_binding_fails_closed(
    tmp_path: Path,
    mutation: str,
    diagnostic: str,
) -> None:
    initialize_evaluation(
        synthetic_case(comparator=False),
        tmp_path,
        seed_hex="2" * 64,
    )
    judge = EvidenceBindingJudge(mutation)
    for _ in range(3):
        request = next_judge_request(tmp_path)
        assert request is not None
        submit_judge_response(tmp_path, await judge.evaluate(request))
    grade_request = next_judge_request(tmp_path)
    assert grade_request is not None

    state = submit_judge_response(tmp_path, await judge.evaluate(grade_request))
    diagnostics = json.loads(
        (tmp_path / "judge-diagnostics/grade-A-1-attempt-1.json").read_text(
            encoding="utf-8"
        )
    )

    assert state.attempt == 2
    assert diagnostic in diagnostics["issues"][0]["message"]
    assert verify_evaluation_run(tmp_path).valid


@pytest.mark.asyncio
async def test_source_text_equal_to_report_text_is_not_false_identity_leak(
    tmp_path: Path,
) -> None:
    case = synthetic_case(comparator=False)
    case.candidates[0].report_text = SOURCE_TEXT
    case.candidates[0].report_hash = _sha256(SOURCE_TEXT)

    completed = await run_evaluation(
        case,
        ScriptedJudge(),
        tmp_path,
        seed_hex="1" * 64,
    )

    assert completed.manifest.state is EvaluationRunPhase.COMPLETED
    assert completed.result.schema_version == "1.3"
    assert completed.result.requirement_matrix.available is True
    assert completed.result.requirement_matrix.rows[0].report_a.anonymous_label == "A"
    assert completed.result.requirement_matrix.rows[0].report_b is None
    assert verify_evaluation_run(tmp_path).valid


@pytest.mark.asyncio
async def test_malformed_native_bundle_fails_deterministic_checks(
    tmp_path: Path,
) -> None:
    case = synthetic_case(comparator=False)
    case.candidates[0].bundle_json = {"schema_version": "1.0"}

    completed = await run_evaluation(
        case,
        ScriptedJudge(),
        tmp_path,
        seed_hex="0" * 64,
    )

    checks = json.loads((tmp_path / "deterministic-checks-A.json").read_text(encoding="utf-8"))
    assert checks["valid"] is False
    assert checks["critical_codes"] == ["NATIVE_BUNDLE_MALFORMED"]
    assert completed.result.reports[0].absolute_disposition is AbsoluteDisposition.FAIL
    assert verify_evaluation_run(tmp_path).valid


@pytest.mark.asyncio
async def test_optional_repair_and_referees_remain_replayable(tmp_path: Path) -> None:
    judge = RepairAndRefereeJudge()

    completed = await run_evaluation(
        synthetic_case(comparator=False),
        judge,
        tmp_path,
        seed_hex="3" * 64,
    )

    assert [request.operation for request in judge.requests] == [
        JudgeOperation.ADMIT_CASE,
        JudgeOperation.BUILD_LEDGER,
        JudgeOperation.AUDIT_LEDGER,
        JudgeOperation.REPAIR_LEDGER,
        JudgeOperation.REFEREE,
        JudgeOperation.GRADE_REPORT,
        JudgeOperation.GRADE_REPORT,
        JudgeOperation.REFEREE,
    ]
    assert completed.manifest.state is EvaluationRunPhase.COMPLETED
    assert completed.result.comparison is None
    ledger_referee = next(
        request
        for request in judge.requests
        if request.operation is JudgeOperation.REFEREE
        and request.safe_metadata["referee_scope"] == "ledger"
    )
    assert set(ledger_referee.payload) == {
        "dispute",
        "relevant_entries",
        "resolution_contract",
        "source_record",
        "source_spans",
    }
    assert ledger_referee.payload["resolution_contract"] == {
        "accept_a": "keep the repaired ledger unchanged for this dispute",
        "accept_b": "apply the supplied audit dispute to the repaired ledger",
    }
    assert ledger_referee.payload["source_record"]["sources"]
    assert ledger_referee.payload["source_spans"]
    for span in ledger_referee.payload["source_spans"]:
        source = next(
            item
            for item in ledger_referee.payload["source_record"]["sources"]
            if item["source_id"] == span["source_id"]
        )
        assert span["quote"] == source["normalized_text"][
            span["start_char"] : span["end_char"]
        ]
    assert verify_evaluation_run(tmp_path).valid
    report_referee = next(
        request
        for request in judge.requests
        if request.operation is JudgeOperation.REFEREE
        and request.safe_metadata["referee_scope"] == "report"
    )
    assert set(report_referee.payload) == {
        "dispute",
        "anonymous_passages",
        "relevant_context",
        "source_record",
        "source_spans",
        "alternative_meanings",
    }
    assert "anonymous_label" not in _json_text(report_referee)
    assert report_referee.safe_metadata == {
        "record_scope": "one-material-dispute",
        "referee_scope": "report",
        "grade_dispute_fingerprint": report_referee.safe_metadata[
            "grade_dispute_fingerprint"
        ],
        "legal_ledger_hash": completed.manifest.legal_ledger_hash,
    }
    assert report_referee.payload["anonymous_passages"]
    assert report_referee.payload["relevant_context"]["ledger_entries"]
    assert report_referee.payload["source_spans"]
    assert report_referee.payload["alternative_meanings"] == {
        "accept_grader_1": "select exactly the grader_1 alternative",
        "accept_grader_2": "select exactly the grader_2 alternative",
        "replace": (
            "supply one complete replacement_grade_alternative matching the dispute "
            "kind and subject"
        ),
    }
    assert "Do not set selected_disposition" in report_referee.system_instructions
    assert "source_ids" in report_referee.system_instructions
    assert "closed-record limitation" in report_referee.system_instructions


@pytest.mark.asyncio
@pytest.mark.parametrize("audit_kind", ["initial", "remaining"])
async def test_replay_rejects_rebound_inner_audit_request_fingerprint(
    tmp_path: Path,
    audit_kind: str,
) -> None:
    """Replay must bind both nested audit payloads to their own completed calls."""
    judge = RepairAndRefereeJudge()
    initialize_evaluation(synthetic_case(comparator=False), tmp_path, seed_hex="4" * 64)
    for _ in range(3 if audit_kind == "initial" else 4):
        request = next_judge_request(tmp_path)
        assert request is not None
        submit_judge_response(tmp_path, await judge.evaluate(request))
    assert verify_evaluation_run(tmp_path).valid

    if audit_kind == "initial":
        response_path = "judge-responses/ledger-audit-attempt-1.json"
        response = json.loads((tmp_path / response_path).read_text(encoding="utf-8"))
        wrong = "f" * 64 if response["request_fingerprint"] != "f" * 64 else "e" * 64
        response["payload"]["request_fingerprint"] = wrong
        audit = response["payload"]
        envelope = CaseEnvelope.model_validate_json(
            (tmp_path / "case-envelope.json").read_bytes(), strict=True
        )
        proposed = LegalLedger.model_validate_json(
            (tmp_path / "legal-ledger.proposed.json").read_bytes(), strict=True
        )
        repair_request = attorney_workflow._repair_ledger_request(
            envelope, proposed, LedgerAudit.model_validate(audit)
        )
        replacements = {
            response_path: attorney_artifacts._ordinary_json_bytes(response),
            "legal-ledger-audit.json": attorney_artifacts._ordinary_json_bytes(audit),
            "judge-requests/ledger-repair-attempt-1.json": attorney_artifacts._model_bytes(
                repair_request, JudgeRequest
            )[1],
        }
    else:
        response_path = "judge-responses/ledger-repair-attempt-1.json"
        response = json.loads((tmp_path / response_path).read_text(encoding="utf-8"))
        wrong = "f" * 64 if response["request_fingerprint"] != "f" * 64 else "e" * 64
        response["payload"]["remaining_audit"]["request_fingerprint"] = wrong
        remaining = response["payload"]["remaining_audit"]
        replacements = {
            response_path: attorney_artifacts._ordinary_json_bytes(response),
            "legal-ledger.remaining-audit.json": attorney_artifacts._ordinary_json_bytes(
                remaining
            ),
        }
    _rewrite_core_history_artifacts(tmp_path, replacements)

    expected_issue = (
        "ledger-audit evidence request fingerprint mismatch"
        if audit_kind == "initial"
        else "remaining-audit evidence request fingerprint mismatch"
    )
    assert verify_evaluation_run(tmp_path).issues == (expected_issue,)


@pytest.mark.asyncio
async def test_delivered_result_and_report_disclose_conservative_judge_isolation(
    tmp_path: Path,
) -> None:
    class SequentialLedgerJudge(ScriptedJudge):
        async def evaluate(self, request: JudgeRequest) -> JudgeResponse:
            response = await super().evaluate(request)
            if request.operation is JudgeOperation.BUILD_LEDGER:
                response.judge_isolation = JudgeIsolation.SEQUENTIAL_SAME_CONTEXT
            return response

    completed = await run_evaluation(
        synthetic_case(comparator=False),
        SequentialLedgerJudge(),
        tmp_path,
        seed_hex="f" * 64,
    )

    assert completed.result.judge_isolation == "sequential_same_context"
    assert (
        "- Aggregate judge isolation: sequential_same_context."
        in (tmp_path / "evaluation-report.md").read_text(encoding="utf-8")
    )
    assert verify_evaluation_run(tmp_path).valid


@pytest.mark.asyncio
async def test_failed_sequential_attempt_keeps_inconclusive_aggregate_sequential(
    tmp_path: Path,
) -> None:
    class MixedIsolationInvalidJudge(ScriptedJudge):
        def __init__(self) -> None:
            super().__init__(invalid_attempts={JudgeOperation.ADMIT_CASE: 2})

        async def evaluate(self, request: JudgeRequest) -> JudgeResponse:
            response = await super().evaluate(request)
            response.judge_isolation = (
                JudgeIsolation.SEQUENTIAL_SAME_CONTEXT
                if self._response_number == 1
                else JudgeIsolation.FRESH_CONTEXT
            )
            return response

    completed = await run_evaluation(
        synthetic_case(comparator=False),
        MixedIsolationInvalidJudge(),
        tmp_path,
        seed_hex="e" * 64,
    )

    assert completed.manifest.state is EvaluationRunPhase.INCONCLUSIVE
    assert completed.result.judge_isolation == "sequential_same_context"
    assert verify_evaluation_run(tmp_path).valid


@pytest.mark.asyncio
async def test_every_role_packet_states_its_complete_decision_contract(
    tmp_path: Path,
) -> None:
    """Fresh packet-only judges must not need hidden host or runner instructions."""
    judge = RepairAndRefereeJudge()
    await run_evaluation(
        synthetic_case(comparator=False),
        judge,
        tmp_path,
        seed_hex="4" * 64,
    )

    admission = next(
        request for request in judge.requests if request.operation is JudgeOperation.ADMIT_CASE
    )
    required_codes = {
        "AUTHORITY_ALIGNMENT",
        "OPERATIVE_TEXT",
        "CURRENTNESS_EVIDENCE",
        "LANGUAGE_RESOLUTION",
        "SOURCE_PARITY",
    }
    assert set(
        admission.json_schema["$defs"]["AdmissionCheck"]["properties"]["code"]["enum"]
    ) == required_codes
    assert all(code in admission.system_instructions for code in required_codes)
    assert all(
        marker in admission.system_instructions
        for marker in ("exactly once", "material=true", "request_fingerprint")
    )

    instructions_by_operation = {
        request.operation: request.system_instructions for request in judge.requests
    }
    for marker in (
        "source_record_fingerprint",
        "walk_order",
        "half-open",
        "actor",
        "object",
        "timing",
        "enforcing authority",
        "consequence",
        "materiality",
    ):
        assert marker in instructions_by_operation[JudgeOperation.BUILD_LEDGER]
    for marker in ("request_fingerprint", "complete=true", "citation", "trigger links"):
        assert marker in instructions_by_operation[JudgeOperation.AUDIT_LEDGER]
    for marker in ("request_fingerprint", "complete=true", "case_fingerprint"):
        assert marker in instructions_by_operation[JudgeOperation.REPAIR_LEDGER]
    audit_request = next(
        request for request in judge.requests if request.operation is JudgeOperation.AUDIT_LEDGER
    )
    repair_request = next(
        request for request in judge.requests if request.operation is JudgeOperation.REPAIR_LEDGER
    )
    audit_action_contract = {
        "initial_audit_findings": {
            "action_payloads": {
                "add": {
                    "ledger_id_rule": "new_relative_to_proposed_ledger",
                    "proposed_entries": "zero_or_more",
                    "target_ledger_ids": "none",
                },
                "delete": {"proposed_entries": "none", "target_ledger_ids": "one_or_more"},
                "edit": {
                    "ledger_id_rule": "preserve_target_if_proposed",
                    "proposed_entries": "zero_or_one",
                    "target_ledger_ids": "exactly_one",
                },
                "materiality": {
                    "proposed_entries": "none",
                    "target_ledger_ids": "exactly_one",
                },
                "merge": {
                    "proposed_entries": "zero_or_exactly_one",
                    "target_ledger_ids": "two_or_more",
                },
                "split": {
                    "proposed_entries": "zero_or_two_or_more",
                    "target_ledger_ids": "exactly_one",
                },
            },
            "actions": ["add", "edit", "delete", "split", "merge", "materiality"],
            "rationale": {
                "defect_or_correction_signals": [
                    "add",
                    "combine",
                    "combined",
                    "combines",
                    "conflict",
                    "correction",
                    "delete",
                    "duplicate",
                    "edit",
                    "fails",
                    "incorrect",
                    "incomplete",
                    "lacks",
                    "merge",
                    "missing",
                    "needs",
                    "omitted",
                    "overaggregated",
                    "overstates",
                    "repair",
                    "requires",
                    "separate",
                    "split",
                    "understates",
                    "unsupported",
                    "wrong",
                ],
                "generic_filler_rejected": True,
                "legal_or_record_anchors": [
                    "authority",
                    "citation",
                    "condition",
                    "consequence",
                    "deadline",
                    "duty",
                    "exception",
                    "ledger",
                    "materiality",
                    "penalty",
                    "proposition",
                    "record",
                    "regulation",
                    "requirement",
                    "right",
                    "source",
                    "statute",
                    "text",
                    "timing",
                    "trigger",
                ],
                "minimum_words": 6,
                "specificity": {
                    "alphabetic_character_required": True,
                    "accepted_if": [
                        "legal_locator_with_identifier",
                        "two_specific_subject_terms",
                    ],
                    "discounted_metadata_phrases": ["source record"],
                    "discounted_tokens": [
                        "a",
                        "add",
                        "added",
                        "adds",
                        "adding",
                        "an",
                        "and",
                        "are",
                        "as",
                        "at",
                        "audit",
                        "be",
                        "because",
                        "been",
                        "being",
                        "by",
                        "change",
                        "changed",
                        "changes",
                        "changing",
                        "combine",
                        "combined",
                        "combines",
                        "concrete",
                        "conflict",
                        "contains",
                        "correction",
                        "corrections",
                        "critical",
                        "delete",
                        "distinct",
                        "duplicate",
                        "edit",
                        "entries",
                        "entry",
                        "fails",
                        "finding",
                        "findings",
                        "for",
                        "from",
                        "has",
                        "have",
                        "high",
                        "identified",
                        "immaterial",
                        "importance",
                        "important",
                        "in",
                        "incomplete",
                        "incorrect",
                        "indeed",
                        "into",
                        "is",
                        "it",
                        "its",
                        "lacks",
                        "ledger",
                        "low",
                        "major",
                        "material",
                        "materially",
                        "materiality",
                        "merge",
                        "minor",
                        "missing",
                        "need",
                        "needed",
                        "needing",
                        "needs",
                        "of",
                        "omit",
                        "omission",
                        "omissions",
                        "omits",
                        "omitted",
                        "omitting",
                        "on",
                        "or",
                        "overaggregated",
                        "overstates",
                        "payload",
                        "priority",
                        "proposal",
                        "proposed",
                        "repair",
                        "repaired",
                        "repairing",
                        "repairs",
                        "require",
                        "required",
                        "requires",
                        "requiring",
                        "separate",
                        "significant",
                        "source",
                        "split",
                        "still",
                        "supporting",
                        "target",
                        "targets",
                        "that",
                        "the",
                        "their",
                        "this",
                        "to",
                        "understates",
                        "unsupported",
                        "very",
                        "was",
                        "were",
                        "with",
                        "wrong",
                    ],
                    "legal_locator_terms": [
                        "article",
                        "chapter",
                        "paragraph",
                        "rule",
                        "schedule",
                        "section",
                    ],
                    "locator_identifier_forms": [
                        "contains_digit",
                        "single_letter",
                        "roman_numeral",
                    ],
                    "locator_identifier_required": True,
                    "locator_terms_count_as_specific_terms": False,
                    "minimum_specific_subject_terms": 2,
                    "signal_tokens_count_as_specific_terms": False,
                    "specific_subject_terms_must_be_distinct": True,
                },
            },
            "required_fields": ["dispute_id", "action", "materiality", "rationale"],
            "transaction_payload_required": False,
        },
        "remaining_audit_transactions": {
            "action_payloads": {
                "add": {"proposed_entries": "one_or_more", "target_ledger_ids": "none"},
                "delete": {"proposed_entries": "none", "target_ledger_ids": "one_or_more"},
                "edit": {
                    "ledger_id_rule": "preserve_target",
                    "proposed_entries": "exactly_one",
                    "target_ledger_ids": "exactly_one",
                },
                "materiality": {
                    "proposed_entries": "none",
                    "target_ledger_ids": "exactly_one",
                },
                "merge": {
                    "proposed_entries": "exactly_one",
                    "target_ledger_ids": "two_or_more",
                },
                "split": {
                    "proposed_entries": "two_or_more",
                    "target_ledger_ids": "exactly_one",
                },
            },
            "transaction_payload_required": True,
        },
    }
    expected_initial = audit_action_contract["initial_audit_findings"]
    expected_rationale = expected_initial["rationale"]
    assert isinstance(expected_rationale, dict)
    expected_rationale.pop("specificity")
    actual_contract = audit_request.payload["audit_action_contract"]
    assert isinstance(actual_contract, dict)
    actual_initial = actual_contract["initial_audit_findings"]
    assert isinstance(actual_initial, dict)
    grounding = actual_initial["grounding"]
    assert isinstance(grounding, dict)
    expected_initial["grounding"] = grounding
    assert grounding["candidate_reports_permitted"] is False
    assert grounding["non_add"] == "every_target_id_must_exist_in_proposed_ledger"
    assert (
        grounding["add_with_proposed_entries"]
        == "proposed_entries_are_repair_subject"
    )
    proposal_free_add = grounding["proposal_free_add"]
    assert isinstance(proposal_free_add, dict)
    assert proposal_free_add["exact_known_source_id_required"] is True
    assert proposal_free_add["accepted_if"] == [
        "known_source_id_and_all_asserted_locators_match_source",
        "known_source_id_and_no_locators_and_two_source_terms",
    ]
    proposed_entry_grounding = grounding["proposed_entries"]
    assert isinstance(proposed_entry_grounding, dict)
    assert proposed_entry_grounding == {
        "context": ["proposed_ledger", "finding_proposed_entries"],
        "issue_reporting": "finding_id_and_issue_codes",
        "standalone_contiguous_transaction_required": False,
        "validation": "existing_exact_source_entry_validation",
    }
    locator_match = proposal_free_add["locator_match"]
    assert isinstance(locator_match, dict)
    assert locator_match == {
        "all_asserted_locators_must_match": True,
        "case_sensitive": False,
        "exact_type_and_identifier_required": True,
        "fields": ["title", "normalized_text"],
        "source_term_fallback_when_any_locator_asserted": False,
    }
    source_term_match = proposal_free_add["source_term_match"]
    assert isinstance(source_term_match, dict)
    assert source_term_match["fields"] == ["title", "normalized_text"]
    assert source_term_match["minimum_distinct_terms"] == 2
    assert source_term_match["source_id_tokens_excluded"] is True
    assert source_term_match["defect_or_correction_signals_excluded"] is True
    assert audit_request.payload["audit_action_contract"] == audit_action_contract
    assert repair_request.payload["audit_action_contract"] == audit_action_contract
    assert "need not be transaction-ready" in audit_request.system_instructions
    assert "transaction-ready" in repair_request.system_instructions
    grade_request = next(
        request for request in judge.requests if request.operation is JudgeOperation.GRADE_REPORT
    )
    assert grade_request.payload["finding_code_contract"] == {
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
    for marker in (
        "request_fingerprint",
        "anonymous_label",
        "ledger_fingerprint",
        "schema_version 1.3",
        "eight narrative dimensions",
        "MISSING",
        "report_location",
        "NOT_APPLICABLE",
    ):
        assert marker in instructions_by_operation[JudgeOperation.GRADE_REPORT]
    assert "closed-record limitation" in instructions_by_operation[JudgeOperation.GRADE_REPORT]
    assert "not an affirmative out-of-ledger claim" in instructions_by_operation[
        JudgeOperation.GRADE_REPORT
    ]

    referees = [
        request for request in judge.requests if request.operation is JudgeOperation.REFEREE
    ]
    ledger_referee = next(
        request for request in referees if request.safe_metadata["referee_scope"] == "ledger"
    )
    for marker in (
        "dispute_id",
        "accept_a keeps the repaired ledger unchanged",
        "accept_b applies the supplied audit dispute",
        "replace",
        "replacement_entries",
    ):
        assert marker in ledger_referee.system_instructions
    report_referee = next(
        request for request in referees if request.safe_metadata["referee_scope"] == "report"
    )
    for marker in (
        "dispute_id",
        "grade_dispute_fingerprint",
        "accept_grader_1",
        "accept_grader_2",
        "replacement_grade_alternative",
    ):
        assert marker in report_referee.system_instructions


@pytest.mark.asyncio
async def test_invalid_finding_context_diagnostic_is_specific_and_anonymous_safe(
    tmp_path: Path,
) -> None:
    initialize_evaluation(
        synthetic_case(comparator=False),
        tmp_path,
        seed_hex="8" * 64,
    )
    judge = ScriptedJudge()
    for _ in range(3):
        request = next_judge_request(tmp_path)
        assert request is not None
        submit_judge_response(tmp_path, await judge.evaluate(request))
    grade_request = next_judge_request(tmp_path)
    assert grade_request is not None
    response = await judge.evaluate(grade_request)
    entry_grades = response.payload["entry_grades"]
    assert isinstance(entry_grades, list) and isinstance(entry_grades[0], dict)
    entry_grades[0]["disposition"] = "PARTIAL"
    entry_grades[0]["finding_codes"] = ["MATERIAL_EXCEPTION_MISSING"]

    state = submit_judge_response(tmp_path, response)
    diagnostics = json.loads(
        (tmp_path / "judge-diagnostics/grade-A-1-attempt-1.json").read_text(
            encoding="utf-8"
        )
    )
    message = diagnostics["issues"][0]["message"]

    assert state.attempt == 2
    assert "ledger_id=notice-duty" in message
    assert "finding_code=MATERIAL_EXCEPTION_MISSING" in message
    assert (
        "allowed_context=disposition in [MISSING, PARTIAL]; category=exception; "
        "materiality in [critical, material]" in message
    )
    for forbidden in (
        "harvest-private-id",
        "candidate_id",
        "mapping",
        synthetic_case(comparator=False).candidates[0].report_text,
    ):
        assert forbidden not in message

@pytest.mark.asyncio
async def test_in_progress_grade_with_omitted_valid_defaults_verifies_and_resumes(
    tmp_path: Path,
) -> None:
    initialize_evaluation(
        synthetic_case(comparator=False),
        tmp_path,
        seed_hex="b" * 64,
    )
    judge = DefaultOmittingJudge()

    for _ in range(4):
        request = next_judge_request(tmp_path)
        assert request is not None
        submit_judge_response(tmp_path, await judge.evaluate(request))

    request = next_judge_request(tmp_path)
    assert request is not None
    assert request.operation is JudgeOperation.GRADE_REPORT
    state = resume_evaluation(tmp_path)
    verification = verify_evaluation_run(tmp_path)

    assert state.state is EvaluationRunPhase.GRADE_A
    assert state.attempt == 1
    assert verification.valid, verification.issues


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", ["wrong-type", "unknown-field"])
async def test_omitted_defaults_do_not_launder_an_invalid_grade_response(
    tmp_path: Path,
    mutation: str,
) -> None:
    initialize_evaluation(
        synthetic_case(comparator=False),
        tmp_path,
        seed_hex="c" * 64,
    )
    judge = DefaultOmittingJudge()
    for _ in range(3):
        request = next_judge_request(tmp_path)
        assert request is not None
        submit_judge_response(tmp_path, await judge.evaluate(request))
    request = next_judge_request(tmp_path)
    assert request is not None and request.operation is JudgeOperation.GRADE_REPORT
    response = await judge.evaluate(request)
    if mutation == "wrong-type":
        scores = response.payload["narrative_scores"]
        assert isinstance(scores, list) and isinstance(scores[0], dict)
        scores[0]["score"] = True
    else:
        response.payload["unexpected"] = "not allowed"

    state = submit_judge_response(tmp_path, response)
    verification = verify_evaluation_run(tmp_path)
    resumed = resume_evaluation(tmp_path)

    assert state.state is EvaluationRunPhase.GRADE_A
    assert state.attempt == 2
    assert resumed == state
    assert verification.valid, verification.issues
    failed = json.loads(
        (tmp_path / "judge-responses" / "grade-A-1-attempt-1.json").read_text(
            encoding="utf-8"
        )
    )
    assert failed["payload"].get("schema_version") == "1.3"


@pytest.mark.asyncio
async def test_each_report_referee_is_semantically_validated_before_advancing(
    tmp_path: Path,
) -> None:
    completed = await run_evaluation(
        synthetic_case(comparator=False),
        MultiDisputeRefereeJudge(),
        tmp_path,
        seed_hex="2" * 64,
    )

    first_referee_calls = [
        call for call in completed.manifest.judge_calls if call.call_id == "report-referee-1"
    ]
    assert [(call.attempt, call.state) for call in first_referee_calls] == [
        (1, "failed"),
        (2, "completed"),
    ]
    assert completed.manifest.state is EvaluationRunPhase.COMPLETED
    assert verify_evaluation_run(tmp_path).valid


@pytest.mark.asyncio
async def test_case_invalid_stops_before_ledger_or_grading(tmp_path: Path) -> None:
    judge = ScriptedJudge(invalid_admission=True)

    completed = await run_evaluation(
        synthetic_case(comparator=False), judge, tmp_path, seed_hex="5" * 64
    )

    assert [request.operation for request in judge.requests] == [JudgeOperation.ADMIT_CASE]
    assert completed.manifest.state is EvaluationRunPhase.CASE_INVALID
    assert completed.manifest.legal_ledger_hash is None
    assert completed.result.readiness.status is ReadinessStatus.CASE_INVALID
    assert completed.result.judge_isolation == "fresh_context"
    assert completed.result.reports == []
    assert completed.result.comparison is None
    assert completed.result.requirement_matrix.model_dump(mode="json") == {
        "available": False,
        "unavailable_reason": "CASE_INVALID",
        "rows": [],
    }


@pytest.mark.asyncio
async def test_one_malformed_response_is_retried_with_diagnostics(
    tmp_path: Path,
) -> None:
    judge = ScriptedJudge(invalid_attempts={JudgeOperation.ADMIT_CASE: 1})

    completed = await run_evaluation(
        synthetic_case(comparator=False),
        judge,
        tmp_path,
        seed_hex="6" * 64,
    )

    admission_calls = [
        call
        for call in completed.manifest.judge_calls
        if call.operation is JudgeOperation.ADMIT_CASE
    ]
    assert [(call.attempt, call.state) for call in admission_calls] == [
        (1, "failed"),
        (2, "completed"),
    ]
    assert admission_calls[0].diagnostics_artifact_path is not None
    assert admission_calls[1].diagnostics_artifact_path is None
    assert admission_calls[0].call_id == admission_calls[1].call_id
    assert completed.manifest.retry_count == 1
    assert completed.manifest.state is EvaluationRunPhase.COMPLETED
    assert verify_evaluation_run(tmp_path).valid


@pytest.mark.asyncio
async def test_live_pre_matrix_grade_response_uses_normal_retry_path(
    tmp_path: Path,
) -> None:
    class FirstGradeUsesOldSchema(ScriptedJudge):
        def __init__(self) -> None:
            super().__init__()
            self.old_grade_remaining = 1

        def _payload(self, request):  # type: ignore[no-untyped-def]
            payload = super()._payload(request)
            if request.operation is JudgeOperation.GRADE_REPORT and self.old_grade_remaining:
                self.old_grade_remaining -= 1
                payload["schema_version"] = "1.1"
            return payload

    completed = await run_evaluation(
        synthetic_case(comparator=False),
        FirstGradeUsesOldSchema(),
        tmp_path,
        seed_hex="a" * 64,
    )

    first_grade_calls = [
        call for call in completed.manifest.judge_calls if call.call_id == "grade-A-1"
    ]
    assert [(call.attempt, call.state) for call in first_grade_calls] == [
        (1, "failed"),
        (2, "completed"),
    ]
    assert completed.manifest.state is EvaluationRunPhase.COMPLETED
    assert verify_evaluation_run(tmp_path).valid


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "disposition",
    [CoverageDisposition.COMPLETE, CoverageDisposition.PARTIAL],
)
async def test_positive_credit_absence_grade_response_uses_normal_retry_path(
    tmp_path: Path,
    disposition: CoverageDisposition,
) -> None:
    class FirstGradeUsesAbsenceForPositiveCredit(ScriptedJudge):
        def __init__(self) -> None:
            super().__init__()
            self.invalid_grade_remaining = 1

        def _payload(self, request):  # type: ignore[no-untyped-def]
            payload = super()._payload(request)
            if request.operation is JudgeOperation.GRADE_REPORT and self.invalid_grade_remaining:
                self.invalid_grade_remaining -= 1
                source_record = request.payload["source_record"]
                assert isinstance(source_record, dict)
                payload["out_of_ledger_claims"] = [
                    {
                        "claim_id": "positive-credit-without-support",
                        "claim_text": "within 30 days",
                        "report_location": "paragraph 1",
                        "disposition": disposition.value,
                        "category": "deadline",
                        "materiality": "material",
                        "related_ledger_ids": ["notice-duty"],
                        "source_record_fingerprint": source_record[
                            "source_record_fingerprint"
                        ],
                        "evidence_basis": "closed_universe_absence",
                        "evidence_spans": [],
                        "rationale": "The claimed support is absent from the source record.",
                    }
                ]
            return payload

    initialize_evaluation(
        synthetic_case(comparator=False),
        tmp_path,
        seed_hex="d" * 64,
    )
    judge = FirstGradeUsesAbsenceForPositiveCredit()
    for _ in range(3):
        request = next_judge_request(tmp_path)
        assert request is not None
        submit_judge_response(tmp_path, await judge.evaluate(request))
    request = next_judge_request(tmp_path)
    assert request is not None and request.operation is JudgeOperation.GRADE_REPORT

    state = submit_judge_response(tmp_path, await judge.evaluate(request))

    assert state.state is EvaluationRunPhase.GRADE_A
    assert state.attempt == 2
    assert state.retry_count == 1
    assert not (tmp_path / "grader-1-report-A.json").exists()
    assert verify_evaluation_run(tmp_path).valid


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("disposition", "evidence_basis", "expected_precision"),
    [
        (CoverageDisposition.COMPLETE, "source_spans", 1.0),
        (CoverageDisposition.UNSUPPORTED, "closed_universe_absence", 0.0),
    ],
)
async def test_claim_evidence_binding_retains_expected_precision_credit(
    tmp_path: Path,
    disposition: CoverageDisposition,
    evidence_basis: str,
    expected_precision: float,
) -> None:
    class EvidenceBoundClaimJudge(ScriptedJudge):
        def _payload(self, request):  # type: ignore[no-untyped-def]
            payload = super()._payload(request)
            if request.operation is JudgeOperation.GRADE_REPORT:
                source_record = request.payload["source_record"]
                assert isinstance(source_record, dict)
                start = SOURCE_TEXT.index("within 30 days")
                payload["out_of_ledger_claims"] = [
                    {
                        "claim_id": "deadline-claim",
                        "claim_text": "within 30 days",
                        "report_location": "paragraph 1",
                        "disposition": disposition.value,
                        "category": "deadline",
                        "materiality": "material",
                        "related_ledger_ids": ["notice-duty"],
                        "source_record_fingerprint": source_record[
                            "source_record_fingerprint"
                        ],
                        "evidence_basis": evidence_basis,
                        "evidence_spans": (
                            [
                                {
                                    "source_id": "source-1",
                                    "start_char": start,
                                    "end_char": start + len("within 30 days"),
                                    "quote": "within 30 days",
                                }
                            ]
                            if evidence_basis == "source_spans"
                            else []
                        ),
                        "rationale": "The claim is bound to the complete source record.",
                    }
                ]
            return payload

    completed = await run_evaluation(
        synthetic_case(comparator=False),
        EvidenceBoundClaimJudge(),
        tmp_path,
        seed_hex="e" * 64,
    )

    assert completed.result.reports[0].claim_precision == expected_precision
    assert verify_evaluation_run(tmp_path).valid


@pytest.mark.asyncio
async def test_second_malformed_response_is_explicitly_inconclusive(
    tmp_path: Path,
) -> None:
    judge = ScriptedJudge(invalid_attempts={JudgeOperation.ADMIT_CASE: 2})

    completed = await run_evaluation(
        synthetic_case(comparator=False), judge, tmp_path, seed_hex="7" * 64
    )

    assert completed.manifest.state is EvaluationRunPhase.INCONCLUSIVE
    assert completed.manifest.terminal_status is EvaluationTerminalStatus.INCONCLUSIVE
    assert completed.result.readiness.status is ReadinessStatus.INCONCLUSIVE
    assert completed.result.reports == []
    assert completed.result.comparison is None
    assert completed.result.requirement_matrix.model_dump(mode="json") == {
        "available": False,
        "unavailable_reason": "INCONCLUSIVE",
        "rows": [],
    }
    admission_calls = [
        call
        for call in completed.manifest.judge_calls
        if call.operation is JudgeOperation.ADMIT_CASE
    ]
    assert [(call.attempt, call.state, call.terminal_status) for call in admission_calls] == [
        (1, "failed", "failed"),
        (2, "failed", "inconclusive"),
    ]
    assert all(call.diagnostics_artifact_path for call in admission_calls)
    assert verify_evaluation_run(tmp_path).valid


@pytest.mark.asyncio
async def test_second_post_admission_malformed_response_preserves_readiness(
    tmp_path: Path,
) -> None:
    judge = ScriptedJudge(invalid_attempts={JudgeOperation.BUILD_LEDGER: 2})

    completed = await run_evaluation(
        synthetic_case(comparator=False),
        judge,
        tmp_path,
        seed_hex="1" * 64,
    )

    assert completed.manifest.state is EvaluationRunPhase.INCONCLUSIVE
    admission = json.loads((tmp_path / "case-readiness.json").read_text(encoding="utf-8"))
    terminal = json.loads((tmp_path / "terminal-readiness.json").read_text(encoding="utf-8"))
    assert admission["status"] == "ADMITTED"
    assert terminal["status"] == "INCONCLUSIVE"
    assert completed.result.readiness.status is ReadinessStatus.INCONCLUSIVE
    assert completed.result.comparison is None
    assert verify_evaluation_run(tmp_path).valid


@pytest.mark.asyncio
async def test_incremental_submit_and_resume_advance_exact_state(tmp_path: Path) -> None:
    case = synthetic_case(comparator=False)
    state = initialize_evaluation(case, tmp_path, seed_hex="8" * 64)
    assert state.state is EvaluationRunPhase.ADMISSION
    request = next_judge_request(tmp_path)
    assert request is not None
    assert request.operation is JudgeOperation.ADMIT_CASE

    judge = ScriptedJudge()
    response = await judge.evaluate(request)
    advanced = submit_judge_response(tmp_path, response)

    assert advanced.state is EvaluationRunPhase.LEDGER_BUILD
    resumed = resume_evaluation(tmp_path)
    assert resumed == advanced
    next_request = next_judge_request(tmp_path)
    assert next_request is not None
    assert next_request.operation is JudgeOperation.BUILD_LEDGER


@pytest.mark.asyncio
async def test_run_evaluation_never_verifies_through_a_bare_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_verify = attorney_workflow._verify_evaluation_run_or_raise
    storage_arguments: list[bool] = []

    def tracking_verify(
        storage: Path | attorney_artifacts._RunStorage,
    ) -> tuple[object, object, object]:
        storage_arguments.append(isinstance(storage, attorney_artifacts._RunStorage))
        return original_verify(storage)

    monkeypatch.setattr(
        attorney_workflow,
        "_verify_evaluation_run_or_raise",
        tracking_verify,
    )

    await run_evaluation(
        synthetic_case(comparator=False),
        ScriptedJudge(),
        tmp_path,
        seed_hex="9" * 64,
    )

    assert storage_arguments
    assert all(storage_arguments)


@pytest.mark.asyncio
async def test_preflight_reuses_submit_validation_without_changing_run_bytes(
    tmp_path: Path,
) -> None:
    """A validator that commits its calculated transition would consume immutable state."""
    initialize_evaluation(synthetic_case(comparator=False), tmp_path, seed_hex="6" * 64)
    request = next_judge_request(tmp_path)
    assert request is not None
    response = await ScriptedJudge().evaluate(request)
    before = {
        path.relative_to(tmp_path).as_posix(): path.read_bytes()
        for path in sorted(tmp_path.rglob("*"))
        if path.is_file()
    }

    valid = attorney_workflow.preflight_judge_response(tmp_path, response)
    invalid = attorney_workflow.preflight_judge_response(
        tmp_path,
        response.model_copy(update={"payload": {"malformed": True}}),
    )
    after = {
        path.relative_to(tmp_path).as_posix(): path.read_bytes()
        for path in sorted(tmp_path.rglob("*"))
        if path.is_file()
    }

    assert valid.model_dump(mode="json") == {
        "schema_version": "1.0",
        "ok": True,
        "operation": "admit_case",
        "request_fingerprint": request.request_fingerprint,
        "issues": [],
        "diagnostic_fingerprint": None,
    }
    assert invalid.ok is False
    assert invalid.operation is JudgeOperation.ADMIT_CASE
    assert invalid.request_fingerprint == request.request_fingerprint
    assert invalid.diagnostic_fingerprint is not None
    assert [issue.model_dump(mode="json") for issue in invalid.issues] == [
        {
            "code": "EVALUATION_RESPONSE_SEMANTIC_INVALID",
            "message": "The response does not satisfy the pending operation contract.",
            "related_ids": [],
        }
    ]
    assert after == before

    advanced = submit_judge_response(tmp_path, response)
    assert advanced.state is EvaluationRunPhase.LEDGER_BUILD


@pytest.mark.asyncio
async def test_preflight_propagates_transition_integrity_failure_without_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Transition-time integrity faults must not be downgraded to response errors."""
    initialize_evaluation(synthetic_case(comparator=False), tmp_path, seed_hex="5" * 64)
    request = next_judge_request(tmp_path)
    assert request is not None
    response = await ScriptedJudge().evaluate(request)
    before = {
        path.relative_to(tmp_path).as_posix(): path.read_bytes()
        for path in sorted(tmp_path.rglob("*"))
        if path.is_file()
    }

    def fail_integrity(*args: object, **kwargs: object) -> None:
        raise attorney_artifacts.EvaluationIntegrityError("injected transition failure")

    monkeypatch.setattr(attorney_workflow, "_accepted_transition", fail_integrity)

    with pytest.raises(
        attorney_artifacts.EvaluationIntegrityError,
        match="injected transition failure",
    ):
        attorney_workflow.preflight_judge_response(tmp_path, response)

    after = {
        path.relative_to(tmp_path).as_posix(): path.read_bytes()
        for path in sorted(tmp_path.rglob("*"))
        if path.is_file()
    }
    assert after == before
