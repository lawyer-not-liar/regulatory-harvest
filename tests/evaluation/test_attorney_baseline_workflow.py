"""Recoverable workflow tests for evaluation-baseline-v1."""

from __future__ import annotations

import asyncio
import json
from datetime import date
from pathlib import Path
from typing import cast

import pytest

from regulatory_harvest.evaluation.attorney_baseline_artifacts import (
    BASELINE_MANIFEST_PATH,
    load_verified_baseline_run,
    verify_baseline_run,
)
from regulatory_harvest.evaluation.attorney_baseline_models import (
    BaselineCorrectionRecordV1,
    BaselineEvaluatorResponseV1,
    BaselinePhaseV1,
    BaselineRequirementV1,
)
from regulatory_harvest.evaluation.attorney_baseline_workflow import (
    BASELINE_EXTERNAL_RESPONSE_INVALID,
    BaselineDraftPromptV1,
    baseline_status_payload_v1,
    continue_baseline_v1,
    guarded_submit_baseline_response_v1,
    initialize_baseline_v1,
    next_baseline_request_v1,
    resume_baseline_v1,
)
from regulatory_harvest.evaluation.attorney_models import (
    AdmissionCheck,
    CaseAdmissionJudgment,
    EvaluationMode,
    EvaluationSource,
    JudgeIsolation,
    JudgeOperation,
    JudgeResponse,
    QualificationCase,
    RequestedAuthority,
)
from regulatory_harvest.evaluation.attorney_qualification import (
    initialize_case_qualification,
    next_qualification_request,
    submit_case_qualification,
)
from regulatory_harvest.models import SourceQuality, SourceRole
from regulatory_harvest.storage import canonical_json_bytes, sha256_digest


def _source(source_id: str, text: str, *, authority_type: str) -> EvaluationSource:
    return EvaluationSource(
        source_id=source_id,
        title=f"Fictional {source_id}",
        normalized_text=text,
        content_hash=sha256_digest(text.encode()),
        canonical_url=f"https://public.example/{source_id}",
        publisher="Example Legislative Office",
        jurisdiction="Example State",
        authority_type=authority_type,
        source_role=SourceRole.OFFICIAL_PRIMARY,
        source_quality=SourceQuality.PRIMARY,
        completeness="complete",
        language="en",
        version="2026-08-24",
        effective_date="2026-08-24",
        relationship_ids=["fictional-rule"] if source_id == "fictional-status" else [],
    )


def _qualification_case() -> QualificationCase:
    sources = [
        _source(
            "fictional-rule",
            (
                "Section 4. A covered operator must file an annual notice. "
                "The notice must identify the operator."
            ),
            authority_type="regulation",
        ),
        _source(
            "fictional-status",
            "Status notice. Section 4 is effective and unsuperseded on 2026-08-24.",
            authority_type="official-status",
        ),
    ]
    return QualificationCase.model_validate(
        {
            "schema_version": "1.1",
            "case_id": "fictional-baseline-workflow",
            "mode": EvaluationMode.CURRENT_LAW,
            "question": "What notice must a covered operator file?",
            "jurisdiction": "Example State",
            "as_of": date(2026, 8, 24),
            "requested_authorities": [
                RequestedAuthority(
                    authority_id="fictional-rule",
                    title="Fictional Rule",
                    jurisdiction="Example State",
                    authority_type="regulation",
                    source_ids=["fictional-rule"],
                )
            ],
            "sources": sources,
            "build_binding": {"commit": "a" * 40, "archive_sha256": "b" * 64},
            "language_treatments": [
                {
                    "source_ids": [source.source_id for source in sources],
                    "method": "Original-language review of the English sources.",
                    "rationale": "Both fictional sources are written in English.",
                    "limitations": "No non-English source was present.",
                }
            ],
        }
    )


def _qualification(run: Path) -> None:
    case = _qualification_case()
    initialize_case_qualification(case, run, nonce_hex="1" * 64)
    request = next_qualification_request(run)
    assert request is not None
    source_ids = [source.source_id for source in case.sources]
    judgment = CaseAdmissionJudgment(
        request_fingerprint=request.request_fingerprint,
        checks=[
            AdmissionCheck(
                code=code,
                satisfied=True,
                material=True,
                rationale="The retained fictional sources satisfy this admission check.",
                source_ids=source_ids,
            )
            for code in (
                "AUTHORITY_ALIGNMENT",
                "OPERATIVE_TEXT",
                "CURRENTNESS_EVIDENCE",
                "LANGUAGE_RESOLUTION",
                "SOURCE_PARITY",
            )
        ],
    )
    submit_case_qualification(
        run,
        JudgeResponse(
            operation=JudgeOperation.ADMIT_CASE,
            request_fingerprint=request.request_fingerprint,
            provider_name="fictional-provider",
            model_name="fictional-model",
            judge_isolation=JudgeIsolation.FRESH_CONTEXT,
            response_id="fictional-baseline-workflow-response",
            usage={"input_tokens": 101, "output_tokens": 202},
            payload=judgment.model_dump(mode="json"),
        ),
    )


def _control(root: Path) -> Path:
    _qualification(root / "qualification")
    path = root / "baseline-control.json"
    path.write_bytes(
        canonical_json_bytes(
            {
                "client_facts_path": None,
                "qualification_capsule_path": "qualification",
                "schema_version": "1.0",
            }
        )
    )
    return path


def _review_payload(*, complete: bool = True, two: bool = False) -> dict[str, object]:
    proposals: list[dict[str, object]] = [
        {
            "statement": "A covered operator must file an annual notice.",
            "kind": "obligation",
            "importance": "critical",
            "importance_basis": ["legal_bottom_line"],
            "importance_rationale": "Omission could change the legal bottom line.",
            "passages": [
                {"source_id": "fictional-rule", "quote": "must file an annual notice"}
            ],
            "dependency": None,
            "confidence": "clear",
            "substantive_rationale": "The source uses mandatory language.",
        }
    ]
    if two:
        proposals.append(
            {
                "statement": "The notice must identify the operator.",
                "kind": "obligation",
                "importance": "material",
                "importance_basis": ["attorney_briefing"],
                "importance_rationale": (
                    "The notice detail is necessary for a competent attorney briefing."
                ),
                "passages": [
                    {"source_id": "fictional-rule", "quote": "must identify the operator"}
                ],
                "dependency": None,
                "confidence": "clear",
                "substantive_rationale": "The source expressly identifies required content.",
            }
        )
    return {"proposals": proposals, "review_complete": complete}


def _audit_payload(*, two: bool = False, disputed: bool = False) -> dict[str, object]:
    findings: list[dict[str, object]] = [
        {
            "proposal_ref": "PR-0001",
            "reviewed_importance": "critical",
            "reviewed_importance_basis": ["legal_bottom_line"],
            "importance_rationale": "Omission could change the legal bottom line.",
            "disposition": "agree",
        }
    ]
    if two:
        findings.append(
            {
                "proposal_ref": "PR-0002",
                "reviewed_importance": "material",
                "reviewed_importance_basis": ["attorney_briefing"],
                "importance_rationale": (
                    "The notice detail is necessary for a competent attorney briefing."
                ),
                "disposition": "agree",
            }
        )
    concerns: list[dict[str, object]] = []
    if disputed:
        concerns.append(
            {
                "target_proposal_ref": "PR-0001",
                "concern_type": "ambiguity",
                "passages": [
                    {"source_id": "fictional-rule", "quote": "must file an annual notice"}
                ],
                "explanation": "The retained source could support a narrower filing duty.",
                "correction": None,
            }
        )
    return {"concerns": concerns, "importance_findings": findings, "audit_complete": True}


def _snapshot(run: Path) -> dict[str, bytes]:
    if not run.exists():
        return {}
    return {
        path.relative_to(run).as_posix(): path.read_bytes()
        for path in sorted(run.rglob("*"))
        if path.is_file()
    }


def _submit(run: Path, payload: object):
    return guarded_submit_baseline_response_v1(
        run,
        payload,
        provider_name="fictional-provider",
        model_name="fictional-model",
        judge_isolation="scripted_fixture",
    )


def _complete_ordinary(control: Path, run: Path, *, two: bool = False) -> None:
    initialize_baseline_v1(control, run, nonce_hex="2" * 64)
    assert _submit(run, _review_payload(two=two)).accepted
    assert _submit(run, _audit_payload(two=two)).accepted
    assert resume_baseline_v1(run).phase is BaselinePhaseV1.COMPLETED


def _write_correction(
    path: Path,
    *,
    prior_root: str,
    prior_fingerprint: str,
    action: dict[str, object],
    correction_id: str,
) -> None:
    payload: dict[str, object] = {
        "schema_version": "baseline-correction-v1",
        "prior_baseline_root": prior_root,
        "prior_baseline_fingerprint": prior_fingerprint,
        "correction_id": correction_id,
        "actions": [action],
        "reason": "The retained source supports this attorney-approved baseline correction.",
        "attorney_approval": {
            "approved_by": "Fictional Reviewing Attorney",
            "approved_at": "2026-08-24T20:00:00-07:00",
            "approval_statement": "I approve this report-free source-bound correction.",
        },
        "correction_fingerprint": "0" * 64,
    }
    provisional = BaselineCorrectionRecordV1.model_validate(payload)
    payload["correction_fingerprint"] = sha256_digest(
        canonical_json_bytes(
            provisional.model_dump(mode="json", exclude={"correction_fingerprint"})
        )
    )
    path.write_bytes(canonical_json_bytes(payload))


def test_ordinary_initialization_issues_one_idempotent_report_blind_review(
    tmp_path: Path,
) -> None:
    control = _control(tmp_path)
    run = tmp_path / "baseline"

    state = initialize_baseline_v1(control, run, nonce_hex="2" * 64)
    first = next_baseline_request_v1(run)
    second = next_baseline_request_v1(run)

    assert state.phase is BaselinePhaseV1.SOURCE_REVIEW
    assert first == second
    assert first is not None
    assert first.operation.value == "baseline_source_review"
    wire = canonical_json_bytes(first.model_dump(mode="json"))
    assert str(control).encode() not in wire
    assert b"report_text" not in wire


def test_role_order_is_review_audit_one_referee_per_dispute_then_completed(
    tmp_path: Path,
) -> None:
    run = tmp_path / "baseline"
    initialize_baseline_v1(_control(tmp_path), run, nonce_hex="2" * 64)

    assert _submit(run, _review_payload()).accepted
    assert next_baseline_request_v1(run).operation.value == "baseline_source_audit"  # type: ignore[union-attr]
    assert _submit(run, _audit_payload(disputed=True)).accepted
    referee = next_baseline_request_v1(run)
    assert referee is not None and referee.operation.value == "baseline_source_referee"
    dispute = cast(dict[str, object], referee.payload["dispute"])
    dispute_id = cast(str, dispute["dispute_id"])
    accepted = _submit(
        run,
        {
            "dispute_id": dispute_id,
            "decision": "accept_reviewer",
            "passages": [
                {"source_id": "fictional-rule", "quote": "must file an annual notice"}
            ],
            "importance": "critical",
            "importance_basis": ["legal_bottom_line"],
            "importance_rationale": "Omission could change the legal bottom line.",
            "substantive_rationale": "The reviewer statement best matches the source.",
        },
    )

    assert accepted.accepted
    assert accepted.state is not None
    assert accepted.state.phase is BaselinePhaseV1.COMPLETED
    assert next_baseline_request_v1(run) is None
    context = load_verified_baseline_run(run)
    assert [call.operation.value for call in context.manifest.accepted_calls] == [
        "baseline_source_review",
        "baseline_source_audit",
        "baseline_source_referee",
    ]
    assert len(context.baseline.requirements) == 1


def test_incomplete_audit_and_invalid_payload_are_write_free_with_one_safe_code(
    tmp_path: Path,
) -> None:
    run = tmp_path / "baseline"
    initialize_baseline_v1(_control(tmp_path), run, nonce_hex="2" * 64)
    before_invalid = _snapshot(run)

    invalid = _submit(run, {"malformed": "private source response"})

    assert not invalid.accepted
    assert invalid.issue_codes == (BASELINE_EXTERNAL_RESPONSE_INVALID,)
    assert _snapshot(run) == before_invalid

    assert _submit(run, _review_payload(two=True)).accepted
    before_incomplete = _snapshot(run)
    incomplete = _submit(run, _audit_payload(two=False))

    assert not incomplete.accepted
    assert incomplete.issue_codes == (BASELINE_EXTERNAL_RESPONSE_INVALID,)
    assert _snapshot(run) == before_incomplete


class _DraftEvaluator:
    provider_name = "fictional-provider"
    model_name = "fictional-model"
    judge_isolation = "scripted_fixture"

    def __init__(self, drafts: list[object]) -> None:
        self.drafts = drafts
        self.prompts: list[BaselineDraftPromptV1] = []

    async def evaluate_draft(self, prompt: BaselineDraftPromptV1) -> object:
        self.prompts.append(prompt)
        if not self.drafts:
            raise RuntimeError("provider exhausted")
        value = self.drafts.pop(0)
        if isinstance(value, BaseException):
            raise value
        return value


def test_continue_uses_one_fresh_repair_then_accepts_without_persisting_rejection(
    tmp_path: Path,
) -> None:
    run = tmp_path / "baseline"
    initialize_baseline_v1(_control(tmp_path), run, nonce_hex="2" * 64)
    evaluator = _DraftEvaluator([{"malformed": True}, _review_payload()])

    outcome = asyncio.run(continue_baseline_v1(run, evaluator, max_roles=1))

    assert not outcome.engine_paused
    assert outcome.exit_code == 0
    assert [prompt.attempt for prompt in evaluator.prompts] == [1, 2]
    assert evaluator.prompts[0].request == evaluator.prompts[1].request
    assert evaluator.prompts[0] is not evaluator.prompts[1]
    assert not any("reject" in path for path in _snapshot(run))
    assert resume_baseline_v1(run).phase is BaselinePhaseV1.SOURCE_AUDIT


def test_second_refusal_and_provider_exception_pause_with_exact_request_unchanged(
    tmp_path: Path,
) -> None:
    for name, drafts, expected_code in (
        (
            "refusal",
            [{"malformed": "first"}, {"malformed": "second"}],
            "BASELINE_EXTERNAL_RESPONSE_INVALID",
        ),
        ("provider", [RuntimeError("private provider endpoint")], "BASELINE_PROVIDER_FAILURE"),
    ):
        root = tmp_path / name
        root.mkdir()
        run = root / "baseline"
        initialize_baseline_v1(_control(root), run, nonce_hex="2" * 64)
        pending = next_baseline_request_v1(run)
        before = _snapshot(run)

        outcome = asyncio.run(
            continue_baseline_v1(run, _DraftEvaluator(drafts), max_roles=1)
        )

        assert outcome.exit_code == 6
        assert outcome.engine_paused is True
        assert outcome.pause_reason_codes == (expected_code,)
        assert outcome.pending_request == pending
        assert _snapshot(run) == before


def test_resume_after_role_boundary_does_not_duplicate_accepted_calls(tmp_path: Path) -> None:
    run = tmp_path / "baseline"
    initialize_baseline_v1(_control(tmp_path), run, nonce_hex="2" * 64)
    first = _DraftEvaluator([_review_payload(), RuntimeError("provider restart")])

    paused = asyncio.run(continue_baseline_v1(run, first))
    resumed = asyncio.run(continue_baseline_v1(run, _DraftEvaluator([_audit_payload()])))

    assert paused.engine_paused and paused.exit_code == 6
    assert resumed.exit_code == 0 and not resumed.engine_paused
    context = load_verified_baseline_run(run)
    assert [call.call_id for call in context.manifest.accepted_calls] == [
        "source-review-0001",
        "source-audit-0001",
    ]


def test_correction_initialization_requires_explicit_verified_ancestry(
    tmp_path: Path,
) -> None:
    control = _control(tmp_path)
    p0 = tmp_path / "p0"
    _complete_ordinary(control, p0, two=True)
    first = load_verified_baseline_run(p0)
    correction_1 = tmp_path / "correction-1.json"
    source_text = first.baseline_input.sources[0].normalized_text
    quote = "must identify the operator"
    start = source_text.find(quote)
    added = BaselineRequirementV1(
        requirement_id="REQ-9999",
        canonical_order=999,
        statement="The notice must identify the operator in a separate field.",
        kind="obligation",
        importance="material",
        importance_basis=("attorney_briefing",),
        importance_rationale="The detail is necessary for a competent attorney briefing.",
        passages=(
            {
                "source_id": "fictional-rule",
                "quote": quote,
                "start_char": start,
                "end_char": start + len(quote),
            },
        ),
        confidence="clear",
        substantive_rationale="The source expressly identifies the required content.",
    )
    _write_correction(
        correction_1,
        prior_root=first.manifest.root_hash,
        prior_fingerprint=first.baseline.baseline_fingerprint,
        action={"action": "add_requirement", "requirement": added.model_dump(mode="json")},
        correction_id="CORR-0001",
    )
    p1 = tmp_path / "p1"
    state = initialize_baseline_v1(
        control,
        p1,
        nonce_hex="3" * 64,
        prior_baseline_path=p0,
        correction_path=correction_1,
    )
    assert state.phase is BaselinePhaseV1.COMPLETED
    assert load_verified_baseline_run(p1, prior_run_dir=p0).manifest.pending_call is None

    p1_context = load_verified_baseline_run(p1, prior_run_dir=p0)
    correction_2 = tmp_path / "correction-2.json"
    _write_correction(
        correction_2,
        prior_root=p1_context.manifest.root_hash,
        prior_fingerprint=p1_context.baseline.baseline_fingerprint,
        action={"action": "remove_requirement", "requirement_id": "REQ-0003"},
        correction_id="CORR-0002",
    )
    p2 = tmp_path / "p2"
    with pytest.raises(ValueError, match="BASELINE_CORRECTION_PRIOR"):
        initialize_baseline_v1(
            control,
            p2,
            nonce_hex="4" * 64,
            prior_baseline_path=p1,
            correction_path=correction_2,
        )
    assert not p2.exists()

    state_2 = initialize_baseline_v1(
        control,
        p2,
        nonce_hex="4" * 64,
        prior_baseline_path=p1,
        correction_path=correction_2,
        prior_ancestry=(p0,),
    )
    assert state_2.phase is BaselinePhaseV1.COMPLETED
    assert verify_baseline_run(p2, prior_run_dir=p1, prior_ancestry=(p0,)).valid
    status = baseline_status_payload_v1(
        p2, prior_baseline_path=p1, prior_ancestry=(p0,)
    )
    assert status["phase"] == "completed"
    assert status["baseline_fingerprint"] == load_verified_baseline_run(
        p2, prior_run_dir=p1, prior_ancestry=(p0,)
    ).baseline.baseline_fingerprint


def test_ordinary_initialization_rejects_correction_arguments_write_free(
    tmp_path: Path,
) -> None:
    run = tmp_path / "ordinary"
    with pytest.raises(ValueError, match="BASELINE_CORRECTION_ARGUMENTS"):
        initialize_baseline_v1(
            _control(tmp_path),
            run,
            nonce_hex="2" * 64,
            correction_path=tmp_path / "correction.json",
        )
    assert not run.exists()


def test_response_template_is_exact_canonical_strict_seven_key_envelope() -> None:
    path = Path(__file__).resolve().parents[2] / "assets" / (
        "attorney-evaluation-baseline-response.template.json"
    )
    data = path.read_bytes()
    value = json.loads(data)

    assert data == canonical_json_bytes(value)
    assert not data.endswith(b"\n")
    assert list(value) == sorted(value)
    assert set(value) == {
        "judge_isolation",
        "model_name",
        "operation",
        "payload",
        "provider_name",
        "request_fingerprint",
        "schema_version",
    }
    assert value["judge_isolation"] == "scripted_fixture"
    assert value["request_fingerprint"] == "0" * 64
    BaselineEvaluatorResponseV1.model_validate(value)


def test_manifest_bytes_are_canonical_after_every_workflow_transition(tmp_path: Path) -> None:
    run = tmp_path / "baseline"
    initialize_baseline_v1(_control(tmp_path), run, nonce_hex="2" * 64)
    for payload in (_review_payload(), _audit_payload()):
        data = (run / BASELINE_MANIFEST_PATH).read_bytes()
        assert data == canonical_json_bytes(json.loads(data))
        assert _submit(run, payload).accepted
    data = (run / BASELINE_MANIFEST_PATH).read_bytes()
    assert data == canonical_json_bytes(json.loads(data))
