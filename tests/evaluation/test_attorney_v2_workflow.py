"""End-to-end transition tests for evaluator protocol 2.0."""

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
from regulatory_harvest.evaluation.attorney_v2_models import (
    EvaluationPhaseV2,
    EvaluationTerminalStatusV2,
    EvaluatorOperationV2,
    EvaluatorResponseV2,
)
from regulatory_harvest.evaluation.attorney_v2_workflow import (
    guarded_submit_evaluator_response_v2,
    initialize_evaluation_v2,
    next_evaluator_request_v2,
    preflight_evaluator_response_v2,
    resume_evaluation_v2,
    run_evaluation_v2,
)
from regulatory_harvest.models import SourceQuality, SourceRole

SOURCE_TEXT = "A covered operator must file a notice."
REPORT_TEXT = "A covered operator must file a notice."


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _case(*, labels: int) -> AttorneyEvaluationCase:
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
        case_id="workflow-case",
        mode=EvaluationMode.CLOSED_UNIVERSE,
        question="What must a covered operator do?",
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


def _payload(request: Any, *, audit_has_concerns: bool) -> dict[str, object]:
    if request.operation is EvaluatorOperationV2.SOURCE_REVIEW:
        return {
            "schema_version": "2.0",
            "proposals": [
                {
                    "statement": "A covered operator must file a notice.",
                    "kind": "obligation",
                    "importance": "critical",
                    "passages": [{"source_id": "rule-1", "quote": SOURCE_TEXT}],
                    "dependency": None,
                    "confidence": "clear",
                    "rationale": "The source states a mandatory filing duty.",
                }
            ],
        }
    if request.operation is EvaluatorOperationV2.SOURCE_AUDIT:
        concerns: list[dict[str, object]] = []
        if audit_has_concerns:
            concerns = [
                {
                    "target_proposal_ref": "P0001",
                    "concern_type": "ambiguity",
                    "passages": [{"source_id": "rule-1", "quote": SOURCE_TEXT}],
                    "explanation": "The reviewer should resolve the material ambiguity.",
                    "correction": None,
                }
            ]
        return {"schema_version": "2.0", "concerns": concerns}
    if request.operation is EvaluatorOperationV2.SOURCE_REFEREE:
        return {
            "schema_version": "2.0",
            "decisions": [
                {
                    "dispute_id": "D0001",
                    "decision": "unresolved",
                    "passages": [{"source_id": "rule-1", "quote": SOURCE_TEXT}],
                    "rationale": "The supplied record does not resolve the ambiguity.",
                }
            ],
        }
    baseline_fingerprint = request.payload["baseline_fingerprint"]
    label = request.payload["anonymous_report"]["anonymous_label"]
    assert isinstance(baseline_fingerprint, str)
    assert label in {"A", "B"}
    return {
        "schema_version": "2.0",
        "anonymous_label": label,
        "baseline_fingerprint": baseline_fingerprint,
        "requirement_grades": [
            {
                "requirement_id": "REQ-0001",
                "disposition": "met",
                "report_passages": [REPORT_TEXT],
                "rationale": "The report states the required filing duty.",
                "omission": None,
            }
        ],
        "unsupported_assertions": [],
        "baseline_defect": None,
    }


def _response(request: Any, *, audit_has_concerns: bool) -> EvaluatorResponseV2:
    return EvaluatorResponseV2(
        operation=request.operation,
        request_fingerprint=request.request_fingerprint,
        provider_name="fixture-provider",
        model_name="fixture-model",
        judge_isolation="fresh_context",
        payload=_payload(request, audit_has_concerns=audit_has_concerns),
    )


class _ScriptedEvaluator:
    def __init__(self, *, audit_has_concerns: bool, first_invalid: bool = False) -> None:
        self.audit_has_concerns = audit_has_concerns
        self.first_invalid = first_invalid
        self.requests: list[Any] = []

    async def evaluate(self, request: Any) -> object:
        self.requests.append(request)
        if self.first_invalid and len(self.requests) == 1:
            return {"not": "an evaluator response"}
        return _response(request, audit_has_concerns=self.audit_has_concerns)


@pytest.mark.parametrize(
    ("audit_has_concerns", "labels", "operations"),
    [
        (
            False,
            1,
            ["source_review", "source_audit", "grade_report", "grade_report"],
        ),
        (
            True,
            2,
            [
                "source_review",
                "source_audit",
                "source_referee",
                "grade_report",
                "grade_report",
                "grade_report",
                "grade_report",
            ],
        ),
    ],
)
@pytest.mark.asyncio
async def test_v2_operation_sequence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    audit_has_concerns: bool,
    labels: int,
    operations: list[str],
) -> None:
    """A transition regression would change this exact bounded protocol trace."""
    if labels == 2:
        monkeypatch.setattr(
            "regulatory_harvest.evaluation.attorney_v2_workflow._verify_generation_capsules_for_initialization",
            lambda case, paths: None,
        )
    evaluator = _ScriptedEvaluator(audit_has_concerns=audit_has_concerns)

    completed = await run_evaluation_v2(
        _case(labels=labels),
        evaluator,
        tmp_path / "run",
        seed_hex="0" * 64,
    )

    assert [call.operation.value for call in completed.manifest.calls] == operations
    assert [call.judge_isolation for call in completed.manifest.calls] == [
        "fresh_context"
    ] * len(operations)
    assert completed.manifest.phase is EvaluationPhaseV2.COMPLETED


def _snapshot(run_dir: Path) -> dict[str, bytes]:
    return {
        path.relative_to(run_dir).as_posix(): path.read_bytes()
        for path in sorted(run_dir.rglob("*"))
        if path.is_file() and not path.is_symlink()
    }


def _advance_to_grade_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    labels: int,
    target_label: str,
) -> tuple[Path, Any]:
    if labels == 2:
        monkeypatch.setattr(
            "regulatory_harvest.evaluation.attorney_v2_workflow._verify_generation_capsules_for_initialization",
            lambda case, paths: None,
        )
    run_dir = tmp_path / "run"
    initialize_evaluation_v2(_case(labels=labels), run_dir, seed_hex="0" * 64)
    while True:
        request = next_evaluator_request_v2(run_dir)
        assert request is not None
        if (
            request.operation is EvaluatorOperationV2.GRADE_REPORT
            and request.safe_metadata["anonymous_label"] == target_label
        ):
            return run_dir, request
        accepted = guarded_submit_evaluator_response_v2(
            run_dir, _response(request, audit_has_concerns=False)
        )
        assert accepted.accepted


@pytest.mark.parametrize(
    ("labels", "target_label", "wrong_label", "shape"),
    [
        (1, "A", "B", "raw"),
        (1, "A", "B", "typed"),
        (1, "A", "B", "constructed"),
        (2, "B", "A", "raw"),
        (2, "B", "A", "typed"),
        (2, "B", "A", "constructed"),
    ],
)
def test_pending_grade_rejects_a_response_for_the_other_label_without_writing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    labels: int,
    target_label: str,
    wrong_label: str,
    shape: str,
) -> None:
    """Dropping the pending-call label binding accepts a valid grade for the wrong report."""
    run_dir, request = _advance_to_grade_request(
        tmp_path, monkeypatch, labels=labels, target_label=target_label
    )
    payload = _response(request, audit_has_concerns=False).model_dump(mode="json")
    payload["payload"]["anonymous_label"] = wrong_label
    response: object = payload
    if shape == "typed":
        response = EvaluatorResponseV2.model_validate(payload)
    elif shape == "constructed":
        response = EvaluatorResponseV2.model_construct(**payload)
    before = _snapshot(run_dir)

    preflight = preflight_evaluator_response_v2(run_dir, response)
    guarded = guarded_submit_evaluator_response_v2(run_dir, response)
    resumed = resume_evaluation_v2(run_dir)

    assert not preflight.valid
    assert not guarded.accepted
    assert guarded.preflight.diagnostics == ("MECHANICAL_RESPONSE_INVALID",)
    assert _snapshot(run_dir) == before
    assert resumed.current_call_id is not None
    assert next_evaluator_request_v2(run_dir).request_fingerprint == request.request_fingerprint


@pytest.mark.parametrize(("labels", "target_label"), [(1, "A"), (2, "B")])
def test_pending_grade_accepts_its_exact_label(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    labels: int,
    target_label: str,
) -> None:
    """The label check must not reject the canonical grade request it binds."""
    run_dir, request = _advance_to_grade_request(
        tmp_path, monkeypatch, labels=labels, target_label=target_label
    )
    response = _response(request, audit_has_concerns=False)

    submitted = guarded_submit_evaluator_response_v2(run_dir, response)

    assert submitted.accepted


@pytest.mark.parametrize(
    ("fault", "shape"),
    [
        ("missing", "raw"),
        ("missing", "constructed"),
        ("unhashable", "raw"),
        ("unhashable", "constructed"),
    ],
)
def test_pending_grade_refuses_missing_or_unhashable_labels_without_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str, shape: str
) -> None:
    """A malformed label must use the same generic, write-free mechanical boundary."""
    run_dir, request = _advance_to_grade_request(
        tmp_path, monkeypatch, labels=1, target_label="A"
    )
    payload = _response(request, audit_has_concerns=False).model_dump(mode="json")
    if fault == "missing":
        payload["payload"].pop("anonymous_label")
    else:
        payload["payload"]["anonymous_label"] = []
    response: object = payload
    if shape == "constructed":
        response = EvaluatorResponseV2.model_construct(**payload)
    before = _snapshot(run_dir)

    result = guarded_submit_evaluator_response_v2(run_dir, response)

    assert not result.accepted
    assert result.preflight.diagnostics == ("MECHANICAL_RESPONSE_INVALID",)
    assert _snapshot(run_dir) == before
    assert resume_evaluation_v2(run_dir).current_call_id is not None


def test_mechanical_preflight_is_write_free_and_keeps_no_refused_bytes(tmp_path: Path) -> None:
    """A failed preflight must never become a stored response or diagnostic detail."""
    run_dir = tmp_path / "run"
    initialize_evaluation_v2(_case(labels=1), run_dir, seed_hex="0" * 64)
    before = _snapshot(run_dir)

    preflight = preflight_evaluator_response_v2(run_dir, {"bad": "response"})
    guarded = guarded_submit_evaluator_response_v2(run_dir, {"bad": "response"})

    assert not preflight.valid
    assert not guarded.accepted
    assert _snapshot(run_dir) == before
    assert not any("response" in path for path in before)
    assert guarded.preflight.diagnostics == ("MECHANICAL_RESPONSE_INVALID",)


@pytest.mark.parametrize("kind", ["raw", "constructed-cycle", "oversized"])
def test_mechanical_response_shapes_never_mutate_the_run(tmp_path: Path, kind: str) -> None:
    """Removing deep response validation would allow a malformed shape to alter artifacts."""
    run_dir = tmp_path / "run"
    initialize_evaluation_v2(_case(labels=1), run_dir, seed_hex="0" * 64)
    request = next_evaluator_request_v2(run_dir)
    assert request is not None
    if kind == "raw":
        response: object = {"bad": "response"}
    elif kind == "constructed-cycle":
        cycle: dict[str, object] = {}
        cycle["cycle"] = cycle
        response = EvaluatorResponseV2.model_construct(
            schema_version="2.0",
            operation=request.operation,
            request_fingerprint=request.request_fingerprint,
            provider_name="fixture-provider",
            model_name="fixture-model",
            judge_isolation="fresh_context",
            payload=cycle,
        )
    else:
        response = {
            "schema_version": "2.0",
            "operation": request.operation.value,
            "request_fingerprint": request.request_fingerprint,
            "provider_name": "fixture-provider",
            "model_name": "fixture-model",
            "judge_isolation": "fresh_context",
            "payload": {"text": "x" * (16 * 1024 * 1024 + 1)},
        }
    before = _snapshot(run_dir)

    result = preflight_evaluator_response_v2(run_dir, response)

    assert not result.valid
    assert _snapshot(run_dir) == before


@pytest.mark.asyncio
async def test_runner_retries_one_identical_request_then_accepts(tmp_path: Path) -> None:
    """Changing retry packet contents or allowing a third attempt breaks this guard."""
    evaluator = _ScriptedEvaluator(audit_has_concerns=False, first_invalid=True)

    completed = await run_evaluation_v2(
        _case(labels=1), evaluator, tmp_path / "run", seed_hex="0" * 64
    )

    assert evaluator.requests[0].model_dump(mode="json") == evaluator.requests[1].model_dump(
        mode="json"
    )
    assert len(completed.manifest.calls) == 4
    assert all(call.state == "accepted" for call in completed.manifest.calls)


@pytest.mark.asyncio
async def test_runner_stops_after_the_second_mechanical_refusal(tmp_path: Path) -> None:
    """A third evaluator invocation would violate the protocol's bounded repair rule."""
    evaluator = _ScriptedEvaluator(audit_has_concerns=False, first_invalid=True)

    evaluator.evaluate = lambda request: _invalid_response()  # type: ignore[method-assign]
    with pytest.raises(EvaluationIntegrityError, match="EVALUATOR_V2_INCONCLUSIVE"):
        await run_evaluation_v2(_case(labels=1), evaluator, tmp_path / "run", seed_hex="0" * 64)

    state = resume_evaluation_v2(tmp_path / "run")
    assert state.terminal_status is EvaluationTerminalStatusV2.INCONCLUSIVE


async def _invalid_response() -> object:
    return {"not": "an evaluator response"}


def test_resume_exposes_exactly_one_pending_source_review_request(tmp_path: Path) -> None:
    """A changed initializer must still freeze schema 1.1 and make only review pending."""
    run_dir = tmp_path / "run"
    state = initialize_evaluation_v2(_case(labels=1), run_dir, seed_hex="0" * 64)

    resumed = resume_evaluation_v2(run_dir)
    request = next_evaluator_request_v2(run_dir)

    assert state == resumed
    assert request is not None
    assert request.operation is EvaluatorOperationV2.SOURCE_REVIEW
