"""State-machine controls for fragmented evaluator protocol 2.1."""

from __future__ import annotations

import hashlib
from datetime import date
from pathlib import Path
from typing import Any

import pytest

from regulatory_harvest.evaluation.attorney_artifacts import EvaluationIntegrityError
from regulatory_harvest.evaluation.attorney_models import (
    AttorneyEvaluationCase,
    CandidateReport,
    CandidateRole,
    EvaluationMode,
    EvaluationSource,
    RequestedAuthority,
)
from regulatory_harvest.evaluation.attorney_v2_models import AbsoluteDispositionV2
from regulatory_harvest.evaluation.attorney_v21_artifacts import load_verified_v21_context
from regulatory_harvest.evaluation.attorney_v21_models import (
    EvaluationTerminalStatusV21,
    EvaluatorOperationV21,
    EvaluatorResponseV21,
)
from regulatory_harvest.evaluation.attorney_v21_workflow import (
    guarded_submit_evaluator_response_v21,
    initialize_evaluation_v21,
    next_evaluator_request_v21,
    preflight_evaluator_response_v21,
    resume_evaluation_v21,
    run_evaluation_v21,
    stop_evaluation_v21_inconclusive,
)
from regulatory_harvest.models import SourceQuality, SourceRole

SOURCE_TEXT = "A covered operator must file a notice."
REPORT_TEXT = SOURCE_TEXT


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _case(
    *, labels: int = 1, question: str = "What must a covered operator do?"
) -> AttorneyEvaluationCase:
    candidates = [
        CandidateReport(
            candidate_id="candidate-a",
            role=CandidateRole.CANDIDATE,
            report_text=REPORT_TEXT,
            report_hash=_hash(REPORT_TEXT),
            validation_receipt={"kind": "external"},
        )
    ]
    if labels == 2:
        candidates.append(
            CandidateReport(
                candidate_id="candidate-b",
                role=CandidateRole.COMPARATOR,
                report_text=REPORT_TEXT,
                report_hash=_hash(REPORT_TEXT),
                validation_receipt={"kind": "external"},
            )
        )
    return AttorneyEvaluationCase(
        schema_version="1.1",
        case_id="workflow-v21-case",
        mode=EvaluationMode.CLOSED_UNIVERSE,
        question=question,
        jurisdiction="Example State",
        as_of=date(2026, 8, 18),
        requested_authorities=[
            RequestedAuthority(
                authority_id="rule",
                title="Example Rule",
                jurisdiction="Example State",
                authority_type="regulation",
                source_ids=["rule-1"],
            )
        ],
        sources=[
            EvaluationSource(
                source_id="rule-1",
                title="Example Rule",
                normalized_text=SOURCE_TEXT,
                content_hash=_hash(SOURCE_TEXT),
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


def _payload(
    request: Any,
    *,
    disputed: bool = False,
    unresolved: bool = False,
    ordinary_not_met: bool = False,
    contested_changing: bool = False,
    contested_failure: bool = False,
    proposal_count: int = 1,
    mixed_referee: bool = False,
) -> dict[str, object]:
    if request.operation is EvaluatorOperationV21.SOURCE_REVIEW:
        proposals = [
            {
                "statement": f"Duty {index}: file a notice.",
                "kind": "obligation",
                "importance": "critical",
                "passages": [{"source_id": "rule-1", "quote": SOURCE_TEXT}],
                "dependency": None,
                "confidence": "clear",
                "rationale": "The source states a mandatory filing duty.",
            }
            for index in range(1, proposal_count + 1)
        ]
        return {
            "schema_version": "2.1",
            "proposals": proposals,
        }
    if request.operation is EvaluatorOperationV21.SOURCE_AUDIT:
        target = f"P{proposal_count:04d}"
        concerns: list[dict[str, object]] = []
        if disputed:
            concerns = [
                {
                    "target_proposal_ref": target,
                    "concern_type": "ambiguity",
                    "passages": [{"source_id": "rule-1", "quote": SOURCE_TEXT}],
                    "explanation": "The source is ambiguous.",
                    "correction": None,
                }
            ]
        if mixed_referee:
            concerns = [
                {
                    "target_proposal_ref": f"P{index:04d}",
                    "concern_type": "ambiguity",
                    "passages": [{"source_id": "rule-1", "quote": SOURCE_TEXT}],
                    "explanation": f"Dispute {index}.",
                    "correction": (
                        None
                        if index != 2
                        else {
                            "statement": "Corrected duty two.",
                            "kind": "obligation",
                            "importance": "critical",
                            "passages": [{"source_id": "rule-1", "quote": SOURCE_TEXT}],
                            "dependency": None,
                            "confidence": "clear",
                            "rationale": "Correction supported.",
                        }
                    ),
                }
                for index in range(1, 4)
            ]
        return {
            "schema_version": "2.1",
            "concerns": concerns,
        }
    if request.operation is EvaluatorOperationV21.SOURCE_REFEREE_FRAGMENT:
        decisions = {
            "D0001": ("accept_reviewer", None),
            "D0002": ("accept_auditor", None),
            "D0003": ("unresolved", "SOURCE_AMBIGUITY"),
        }
        decision, reason = (
            decisions[request.safe_metadata["dispute_id"]]
            if mixed_referee
            else (
                ("unresolved", "SOURCE_AMBIGUITY")
                if unresolved
                else ("accept_reviewer", None)
            )
        )
        return {
            "schema_version": "2.1",
            "decision": decision,
            "unresolved_reason": reason,
            "evidence_refs": [
                request.payload["material_disputes"][0]["evidence"][0]["evidence_ref"]
            ],
            "rationale": "The closed record does not resolve the ambiguity."
            if unresolved
            else "The reviewer interpretation is supported.",
        }
    if request.operation is EvaluatorOperationV21.ORDINARY_GRADE_FRAGMENT:
        return {
            "schema_version": "2.1",
            "anonymous_label": request.payload["anonymous_label"],
            "grader_lane": request.payload["grader_lane"],
            "batch_ref": request.payload["batch_ref"],
            "baseline_fingerprint": request.payload["baseline_fingerprint"],
            "report_fingerprint": request.payload["report_fingerprint"],
            "requirement_grades": [
                {
                    "requirement_id": item["requirement_id"],
                    "disposition": "not_met" if ordinary_not_met else "met",
                    "report_passages": [REPORT_TEXT],
                    "rationale": "The report states the duty.",
                    "omission": None,
                }
                for item in request.payload["requirements"]
            ],
            "rationale": "The report satisfies this bounded batch.",
        }
    contested = request.payload["contested_requirement"]
    return {
        "schema_version": "2.1",
        "anonymous_label": request.payload["anonymous_label"],
        "grader_lane": request.payload["grader_lane"],
        "contested_requirement_id": contested["contested_requirement_id"],
        "baseline_fingerprint": request.payload["baseline_fingerprint"],
        "report_fingerprint": request.payload["report_fingerprint"],
        "reviewer_alternative_grade": {
            "disposition": "not_met" if contested_failure else "met",
            "report_passages": [REPORT_TEXT],
            "rationale": "Met.",
        },
        "auditor_alternative_grade": {
            "disposition": "not_met" if contested_changing or contested_failure else "met",
            "report_passages": [REPORT_TEXT],
            "rationale": "Met.",
        },
        "ambiguity_disposition": (
            "omitted"
            if contested_changing and request.payload["grader_lane"] == 2
            else "acknowledged"
        ),
        "rationale": "The report satisfies both alternatives.",
    }


def _response(request: Any, **kwargs: Any) -> EvaluatorResponseV21:
    return EvaluatorResponseV21(
        operation=request.operation,
        request_fingerprint=request.request_fingerprint,
        provider_name="fixture-provider",
        model_name="fixture-model",
        judge_isolation="fresh_context",
        payload=_payload(request, **kwargs),
    )


def _snapshot(run_dir: Path) -> dict[str, bytes]:
    return {
        path.relative_to(run_dir).as_posix(): path.read_bytes()
        for path in sorted(run_dir.rglob("*"))
        if path.is_file() and not path.is_symlink()
    }


def _advance(run_dir: Path, **kwargs: Any) -> list[str]:
    seen: list[str] = []
    while (request := next_evaluator_request_v21(run_dir)) is not None:
        seen.append(request.operation.value)
        accepted = guarded_submit_evaluator_response_v21(run_dir, _response(request, **kwargs))
        assert accepted.accepted, (seen, request.operation, accepted.preflight)
    return seen


def test_no_dispute_completes_both_lanes_for_a_before_b(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Changing fragment ordering can let B advance before A is sealed."""
    monkeypatch.setattr(
        "regulatory_harvest.evaluation.attorney_v21_workflow._verify_generation_capsules_for_initialization",
        lambda case, paths: None,
    )
    run_dir = tmp_path / "run"
    initialize_evaluation_v21(_case(labels=2), run_dir, seed_hex="0" * 64)
    operations = _advance(run_dir)
    calls = resume_evaluation_v21(run_dir)
    assert operations == ["source_review", "source_audit"] + ["ordinary_grade_fragment"] * 4
    assert calls.terminal_status is EvaluationTerminalStatusV21.COMPLETED


def test_unresolved_referee_continues_to_contested_grading(tmp_path: Path) -> None:
    """Treating a valid unresolved decision as mechanical would stop before grading."""
    run_dir = tmp_path / "run"
    initialize_evaluation_v21(_case(), run_dir, seed_hex="0" * 64)
    for _ in range(2):
        request = next_evaluator_request_v21(run_dir)
        assert request is not None
        assert guarded_submit_evaluator_response_v21(
            run_dir, _response(request, disputed=True)
        ).accepted
    request = next_evaluator_request_v21(run_dir)
    assert (
        request is not None and request.operation is EvaluatorOperationV21.SOURCE_REFEREE_FRAGMENT
    )
    assert guarded_submit_evaluator_response_v21(
        run_dir, _response(request, disputed=True, unresolved=True)
    ).accepted
    request = next_evaluator_request_v21(run_dir)
    assert request is not None
    assert request.operation is EvaluatorOperationV21.CONTESTED_GRADE_FRAGMENT


def test_audit_concern_for_second_sealed_proposal_advances_to_referee(tmp_path: Path) -> None:
    """Hard-coding P0001 rejects a valid controller-issued P0002 audit concern."""
    run_dir = tmp_path / "run"
    initialize_evaluation_v21(_case(), run_dir, seed_hex="0" * 64)
    review_request = next_evaluator_request_v21(run_dir)
    assert review_request is not None
    review_payload = _payload(review_request)
    proposals = review_payload["proposals"]
    assert isinstance(proposals, list)
    proposals.append({**proposals[0], "statement": "A second notice duty applies."})
    review_response = EvaluatorResponseV21(
        operation=review_request.operation,
        request_fingerprint=review_request.request_fingerprint,
        provider_name="fixture-provider",
        model_name="fixture-model",
        judge_isolation="fresh_context",
        payload=review_payload,
    )
    assert guarded_submit_evaluator_response_v21(run_dir, review_response).accepted
    audit_request = next_evaluator_request_v21(run_dir)
    assert audit_request is not None
    audit_response = _response(audit_request).model_copy(
        update={
            "payload": {
                "schema_version": "2.1",
                "concerns": [
                    {
                        "target_proposal_ref": "P0002",
                        "concern_type": "ambiguity",
                        "passages": [{"source_id": "rule-1", "quote": SOURCE_TEXT}],
                        "explanation": "The second proposal is ambiguous.",
                        "correction": None,
                    }
                ],
            }
        }
    )

    submitted = guarded_submit_evaluator_response_v21(run_dir, audit_response)

    assert submitted.accepted
    next_request = next_evaluator_request_v21(run_dir)
    assert next_request is not None
    assert next_request.operation is EvaluatorOperationV21.SOURCE_REFEREE_FRAGMENT


def test_contested_grading_completes_a_before_b_and_resumes_exact_next(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Interleaving B before A's contested lane would violate report-major ordering."""
    monkeypatch.setattr(
        "regulatory_harvest.evaluation.attorney_v21_workflow._verify_generation_capsules_for_initialization",
        lambda case, paths: None,
    )
    run_dir = tmp_path / "run"
    initialize_evaluation_v21(_case(labels=2), run_dir, seed_hex="0" * 64)
    for _ in range(3):
        request = next_evaluator_request_v21(run_dir)
        assert request is not None
        assert guarded_submit_evaluator_response_v21(
            run_dir, _response(request, disputed=True, unresolved=True)
        ).accepted
    first_contested = next_evaluator_request_v21(run_dir)
    assert first_contested is not None
    assert first_contested.safe_metadata["contested_requirement_id"] == "CONT-0001"
    assert guarded_submit_evaluator_response_v21(
        run_dir, _response(first_contested, disputed=True, unresolved=True)
    ).accepted
    pending = next_evaluator_request_v21(run_dir)
    assert pending is not None
    assert pending.payload["anonymous_label"] == "A"
    assert pending.payload["grader_lane"] == 2
    assert resume_evaluation_v21(run_dir).current_call_id == "grade-A-lane2-contested-CONT-0001"
    assert next_evaluator_request_v21(run_dir) == pending
    assert guarded_submit_evaluator_response_v21(
        run_dir, _response(pending, disputed=True, unresolved=True)
    ).accepted
    next_after_a = next_evaluator_request_v21(run_dir)
    assert next_after_a is not None
    assert next_after_a.payload["anonymous_label"] == "B"
    assert next_after_a.payload["grader_lane"] == 1


def test_valid_fail_and_outcome_changing_inconclusive_are_terminal(tmp_path: Path) -> None:
    """Retrying a substantive terminal would relabel legal judgment as mechanics."""
    failed_run = tmp_path / "failed"
    initialize_evaluation_v21(_case(), failed_run, seed_hex="0" * 64)
    _advance(failed_run, ordinary_not_met=True)
    assert (
        resume_evaluation_v21(failed_run).terminal_status is EvaluationTerminalStatusV21.COMPLETED
    )

    contested_run = tmp_path / "contested"
    initialize_evaluation_v21(_case(), contested_run, seed_hex="1" * 64)
    _advance(contested_run, disputed=True, unresolved=True, contested_changing=True)
    terminal = resume_evaluation_v21(contested_run)
    assert terminal.terminal_status is EvaluationTerminalStatusV21.INCONCLUSIVE
    assert next_evaluator_request_v21(contested_run) is None


@pytest.mark.parametrize("shape", ["raw", "typed", "constructed"])
def test_refusal_is_write_free_and_second_refusal_stops_mechanically(
    tmp_path: Path, shape: str
) -> None:
    """Storing a refused payload or allowing a third attempt leaks invalid data."""
    run_dir = tmp_path / "run"
    initialize_evaluation_v21(_case(), run_dir, seed_hex="0" * 64)
    request = next_evaluator_request_v21(run_dir)
    assert request is not None
    bad: object = {"invalid": "response"}
    if shape == "typed":
        bad = EvaluatorResponseV21.model_construct(payload={"invalid": "response"})
    elif shape == "constructed":
        cycle: dict[str, object] = {}
        cycle["cycle"] = cycle
        bad = EvaluatorResponseV21.model_construct(payload=cycle)
    before = _snapshot(run_dir)
    assert not preflight_evaluator_response_v21(run_dir, bad).valid
    assert not guarded_submit_evaluator_response_v21(run_dir, bad).accepted
    assert _snapshot(run_dir) == before
    state = stop_evaluation_v21_inconclusive(run_dir, "MECHANICAL_RESPONSE_INVALID")
    assert state.terminal_status is EvaluationTerminalStatusV21.INCONCLUSIVE_MECHANICAL
    assert next_evaluator_request_v21(run_dir) is None


def test_resume_reissues_exact_pending_request_without_repeating_accepted_fragment(
    tmp_path: Path,
) -> None:
    """Directory-derived resume could resubmit an accepted source review."""
    run_dir = tmp_path / "run"
    initialize_evaluation_v21(_case(), run_dir, seed_hex="0" * 64)
    first = next_evaluator_request_v21(run_dir)
    assert first is not None
    assert guarded_submit_evaluator_response_v21(run_dir, _response(first)).accepted
    pending = next_evaluator_request_v21(run_dir)
    assert pending is not None
    resumed = resume_evaluation_v21(run_dir)
    assert resumed.current_call_id == "source-audit"
    assert next_evaluator_request_v21(run_dir) == pending


@pytest.mark.parametrize("shape", ["raw", "typed", "constructed"])
def test_cross_step_and_cross_case_responses_are_write_free(tmp_path: Path, shape: str) -> None:
    """Dropping step/case request binding could accept a valid foreign fragment."""
    first, second = tmp_path / "first", tmp_path / "second"
    initialize_evaluation_v21(_case(), first, seed_hex="0" * 64)
    initialize_evaluation_v21(
        _case(question="Different closed question?"), second, seed_hex="2" * 64
    )
    request_a = next_evaluator_request_v21(first)
    assert request_a is not None
    foreign = _response(request_a).model_dump(mode="json")
    response: object = foreign
    if shape == "typed":
        response = EvaluatorResponseV21.model_validate(foreign)
    elif shape == "constructed":
        response = EvaluatorResponseV21.model_construct(**foreign)
    before = _snapshot(second)
    rejected = guarded_submit_evaluator_response_v21(second, response)
    assert not rejected.accepted
    assert rejected.preflight.diagnostics == ("MECHANICAL_RESPONSE_INVALID",)
    assert _snapshot(second) == before


class _ScriptedEvaluator:
    def __init__(self) -> None:
        self.requests: list[Any] = []

    async def evaluate(self, request: Any) -> object:
        self.requests.append(request)
        return _response(request)


@pytest.mark.asyncio
async def test_runner_uses_one_repair_then_completes(tmp_path: Path) -> None:
    """A retry must reuse only the exact approved request, never rejected bytes."""
    evaluator = _ScriptedEvaluator()
    original = evaluator.evaluate
    calls = 0
    attempts: list[Any] = []

    async def flaky(request: Any) -> object:
        nonlocal calls
        calls += 1
        attempts.append(request)
        if calls == 1:
            return {"invalid": "response"}
        return await original(request)

    evaluator.evaluate = flaky  # type: ignore[method-assign]
    completed = await run_evaluation_v21(_case(), evaluator, tmp_path / "run", seed_hex="0" * 64)
    assert completed.terminal_status is EvaluationTerminalStatusV21.COMPLETED
    assert attempts[0] == attempts[1]


@pytest.mark.asyncio
async def test_runner_stops_after_second_mechanical_refusal(tmp_path: Path) -> None:
    """A third provider invocation would violate the single-repair limit."""
    evaluator = _ScriptedEvaluator()

    async def invalid(request: Any) -> object:
        evaluator.requests.append(request)
        return {"invalid": "response"}

    evaluator.evaluate = invalid  # type: ignore[method-assign]
    with pytest.raises(EvaluationIntegrityError, match="EVALUATOR_V21_INCONCLUSIVE"):
        await run_evaluation_v21(_case(), evaluator, tmp_path / "run", seed_hex="0" * 64)
    assert len(evaluator.requests) == 2
    assert (
        resume_evaluation_v21(tmp_path / "run").terminal_status
        is EvaluationTerminalStatusV21.INCONCLUSIVE_MECHANICAL
    )


def test_first_multibatch_fragment_commits_and_resumes_without_aggregation(
    tmp_path: Path,
) -> None:
    """A valid first ordinary fragment must advance to its exact second batch."""
    run_dir = tmp_path / "run"
    initialize_evaluation_v21(_case(), run_dir, seed_hex="0" * 64)
    review = next_evaluator_request_v21(run_dir)
    assert review is not None
    assert guarded_submit_evaluator_response_v21(
        run_dir, _response(review, proposal_count=7)
    ).accepted
    audit = next_evaluator_request_v21(run_dir)
    assert audit is not None
    assert guarded_submit_evaluator_response_v21(
        run_dir, _response(audit, disputed=True, proposal_count=7)
    ).accepted
    referee = next_evaluator_request_v21(run_dir)
    assert referee is not None
    assert guarded_submit_evaluator_response_v21(
        run_dir, _response(referee, unresolved=True, proposal_count=7)
    ).accepted

    first = next_evaluator_request_v21(run_dir)
    assert first is not None
    assert first.payload["anonymous_label"] == "A"
    assert first.payload["grader_lane"] == 1
    assert first.payload["batch_ref"] == "GB-A-1-0001"
    assert guarded_submit_evaluator_response_v21(run_dir, _response(first)).accepted
    second = next_evaluator_request_v21(run_dir)
    assert second is not None
    assert second.payload["anonymous_label"] == "A"
    assert second.payload["grader_lane"] == 1
    assert second.payload["batch_ref"] == "GB-A-1-0002"
    assert second.request_fingerprint != first.request_fingerprint
    assert resume_evaluation_v21(run_dir).current_call_id == "grade-A-lane1-batch0002"
    assert next_evaluator_request_v21(run_dir) == second

    assert guarded_submit_evaluator_response_v21(run_dir, _response(second)).accepted
    contested = next_evaluator_request_v21(run_dir)
    assert contested is not None
    assert contested.payload["anonymous_label"] == "A"
    assert contested.payload["grader_lane"] == 1
    assert contested.payload["contested_requirement"]["contested_requirement_id"] == "CONT-0001"
    assert guarded_submit_evaluator_response_v21(run_dir, _response(contested)).accepted
    pending_after_contested = next_evaluator_request_v21(run_dir)
    assert pending_after_contested is not None
    assert pending_after_contested.payload["anonymous_label"] == "A"
    assert pending_after_contested.payload["grader_lane"] == 2
    assert pending_after_contested.payload["batch_ref"] == "GB-A-2-0001"
    assert resume_evaluation_v21(run_dir).current_call_id == "grade-A-lane2-batch0001"
    context = load_verified_v21_context(run_dir)
    assert [call.call_id for call in context.manifest.calls].count("grade-A-lane1-batch0001") == 1


def test_mixed_common_and_contested_first_ordinary_advances_to_same_report_contested(
    tmp_path: Path,
) -> None:
    """The aggregate gate cannot skip from a partial lane directly to a result."""
    run_dir = tmp_path / "run"
    initialize_evaluation_v21(_case(), run_dir, seed_hex="0" * 64)
    review = next_evaluator_request_v21(run_dir)
    assert review is not None
    assert guarded_submit_evaluator_response_v21(
        run_dir, _response(review, proposal_count=2)
    ).accepted
    audit = next_evaluator_request_v21(run_dir)
    assert audit is not None
    assert guarded_submit_evaluator_response_v21(
        run_dir, _response(audit, disputed=True, proposal_count=2)
    ).accepted
    referee = next_evaluator_request_v21(run_dir)
    assert referee is not None
    assert guarded_submit_evaluator_response_v21(
        run_dir, _response(referee, unresolved=True, proposal_count=2)
    ).accepted

    ordinary = next_evaluator_request_v21(run_dir)
    assert ordinary is not None
    assert ordinary.operation is EvaluatorOperationV21.ORDINARY_GRADE_FRAGMENT
    assert ordinary.payload["anonymous_label"] == "A"
    assert ordinary.payload["grader_lane"] == 1
    assert guarded_submit_evaluator_response_v21(run_dir, _response(ordinary)).accepted
    contested = next_evaluator_request_v21(run_dir)
    assert contested is not None
    assert contested.operation is EvaluatorOperationV21.CONTESTED_GRADE_FRAGMENT
    assert contested.payload["anonymous_label"] == "A"
    assert contested.payload["grader_lane"] == 1
    assert contested.payload["contested_requirement"]["contested_requirement_id"] == "CONT-0001"
    assert resume_evaluation_v21(run_dir).current_call_id == "grade-A-lane1-contested-CONT-0001"
    assert next_evaluator_request_v21(run_dir) == contested


def test_three_mixed_referee_outcomes_drive_controller_to_completion(tmp_path: Path) -> None:
    """Reviewer, auditor, and unresolved decisions must each be accepted once."""
    run_dir = tmp_path / "run"
    initialize_evaluation_v21(_case(), run_dir, seed_hex="0" * 64)

    operations = _advance(
        run_dir,
        disputed=True,
        mixed_referee=True,
        proposal_count=3,
    )

    assert operations[:5] == [
        "source_review",
        "source_audit",
        "source_referee_fragment",
        "source_referee_fragment",
        "source_referee_fragment",
    ]
    context = load_verified_v21_context(run_dir)
    assert context.result is not None
    assert context.result.terminal_status is EvaluationTerminalStatusV21.COMPLETED
    assert [call.call_id for call in context.manifest.calls].count("source-referee-D0001") == 1
    assert [call.call_id for call in context.manifest.calls].count("source-referee-D0002") == 1
    assert [call.call_id for call in context.manifest.calls].count("source-referee-D0003") == 1


def test_unresolved_outcome_stable_pass_and_fail_are_completed(tmp_path: Path) -> None:
    """A substantive unresolved baseline remains terminal when both lanes agree."""
    passed = tmp_path / "passed"
    initialize_evaluation_v21(_case(), passed, seed_hex="0" * 64)
    _advance(passed, disputed=True, unresolved=True)
    passed_result = load_verified_v21_context(passed).result
    assert passed_result is not None
    assert passed_result.terminal_status is EvaluationTerminalStatusV21.COMPLETED
    assert passed_result.reports[0].sensitivity.absolute_disposition is AbsoluteDispositionV2.PASS

    failed = tmp_path / "failed"
    initialize_evaluation_v21(_case(), failed, seed_hex="1" * 64)
    _advance(
        failed,
        disputed=True,
        unresolved=True,
        proposal_count=2,
        ordinary_not_met=True,
        contested_failure=True,
    )
    failed_result = load_verified_v21_context(failed).result
    assert failed_result is not None
    assert failed_result.terminal_status is EvaluationTerminalStatusV21.COMPLETED
    assert failed_result.reports[0].sensitivity.absolute_disposition is AbsoluteDispositionV2.FAIL
