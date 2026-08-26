"""Resumable controller tests for ``delivery-readiness-v1``."""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, replace
from pathlib import Path
from typing import cast

import pytest
from test_attorney_baseline_projection import _resealed_context
from test_attorney_readiness_drafts import (
    _contested_draft,
    _ordinary_draft,
    _provenance,
    _referee_draft,
    _safety_draft,
)
from test_attorney_readiness_inputs import _historical_context, _make_verified_inputs
from test_attorney_readiness_requests import (
    _contest,
    _requirement,
)
from test_attorney_readiness_requests import (
    inputs as _request_inputs_fixture,
)

from regulatory_harvest.evaluation.attorney_baseline_projection import (
    project_gradeable_baseline_v1,
    verify_gradeable_baseline_projection_v1,
)
from regulatory_harvest.evaluation.attorney_readiness_artifacts import (
    READINESS_RESULT_PATH,
    load_verified_readiness_context_v1,
    verify_readiness_run_v1,
)
from regulatory_harvest.evaluation.attorney_readiness_drafts import (
    CompiledReadinessDraftV1,
    ReadinessEvaluatorDraftPromptV1,
    ReadinessEvaluatorProvenanceV1,
    compile_readiness_draft_v1,
)
from regulatory_harvest.evaluation.attorney_readiness_models import (
    ReadinessEvaluatorRequestV1,
    ReadinessOperationV1,
)
from regulatory_harvest.evaluation.attorney_readiness_workflow import (
    READINESS_CONTEXT_ISOLATION_INVALID,
    GuardedReadinessSubmissionResultV1,
    ReadinessTelemetryEventV1,
    continue_readiness_v1,
    guarded_submit_readiness_response_v1,
    initialize_readiness_v1,
    next_readiness_request_v1,
    preflight_readiness_response_v1,
    readiness_exit_code_v1,
    resume_readiness_v1,
    submit_readiness_response_v1,
)


def test_workflow_api_is_exported_additively() -> None:
    from regulatory_harvest import evaluation

    assert evaluation.initialize_readiness_v1 is initialize_readiness_v1
    assert evaluation.continue_readiness_v1 is continue_readiness_v1
    assert evaluation.guarded_submit_readiness_response_v1 is (guarded_submit_readiness_response_v1)


def _tree_bytes(root: Path) -> dict[str, bytes]:
    if not root.exists():
        return {}
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _draft(
    request: ReadinessEvaluatorRequestV1,
    *,
    grade_mode: str = "partial",
    blocking_safety: bool = False,
    disputes: bool = False,
) -> dict[str, object]:
    if request.operation is ReadinessOperationV1.BASELINE_LOCKED_GRADE:
        result = _ordinary_draft(request)
        grades = cast(list[dict[str, object]], result["requirement_grades"])
        for index, grade in enumerate(grades):
            if (
                grade_mode == "met"
                or (grade_mode == "review" and index != 0)
                or (grade_mode == "inconclusive" and request.payload["lane"] == 1)
            ):
                grade.update(
                    disposition="met",
                    omission=None,
                    rationale="The exact report passage addresses this requirement.",
                )
            elif grade_mode == "inconclusive" and request.payload["lane"] == 2:
                grade.update(
                    disposition="not_met",
                    omission="The report does not address this requirement.",
                    rationale="The exact report does not supply the required treatment.",
                )
        return result
    if request.operation is ReadinessOperationV1.BASELINE_LOCKED_CONTESTED_GRADE:
        result = _contested_draft(request)
        if grade_mode == "met" or (grade_mode == "inconclusive" and request.payload["lane"] == 1):
            result.update(
                reviewer_alternative_disposition="met",
                auditor_alternative_disposition="met",
                reviewer_rationale="The exact passage addresses the reviewer alternative.",
                auditor_rationale="The exact passage addresses the auditor alternative.",
            )
        elif grade_mode == "review":
            result.update(
                reviewer_alternative_disposition="partially_met",
                auditor_alternative_disposition="partially_met",
            )
        elif grade_mode == "inconclusive" and request.payload["lane"] == 2:
            result.update(
                reviewer_alternative_disposition="not_met",
                auditor_alternative_disposition="not_met",
                reviewer_report_passages=[],
                auditor_report_passages=[],
                reviewer_rationale="The report does not address the reviewer alternative.",
                auditor_rationale="The report does not address the auditor alternative.",
            )
        return result
    if request.operation is ReadinessOperationV1.SAFETY_REVIEW:
        result = _safety_draft(request)
        if not blocking_safety:
            result["finding_proposals"] = []
        if disputes and request.payload["lane"] == 2:
            for assessment in cast(list[dict[str, object]], result["candidate_assessments"]):
                assessment["owner_role"] = "outside_counsel"
        return result
    return _referee_draft(request)


class ScriptedEvaluator:
    def __init__(
        self,
        *,
        grade_mode: str = "partial",
        blocking_safety: bool = False,
        disputes: bool = False,
        fail_after: int | None = None,
        refuse: bool = False,
        fresh: bool = False,
        reused_token: bool = False,
    ) -> None:
        self.grade_mode = grade_mode
        self.blocking_safety = blocking_safety
        self.disputes = disputes
        self.fail_after = fail_after
        self.refuse = refuse
        self.fresh = fresh
        self.reused_token = reused_token
        self.prompts: list[ReadinessEvaluatorDraftPromptV1] = []
        self.tokens: list[str] = []

    async def evaluate_draft(self, prompt: ReadinessEvaluatorDraftPromptV1) -> object:
        if self.fail_after is not None and len(self.prompts) >= self.fail_after:
            raise RuntimeError("injected interruption")
        self.prompts.append(prompt)
        if self.refuse:
            return {}
        return _draft(
            prompt.request,
            grade_mode=self.grade_mode,
            blocking_safety=self.blocking_safety,
            disputes=self.disputes,
        )

    def provenance(self, prompt: ReadinessEvaluatorDraftPromptV1) -> ReadinessEvaluatorProvenanceV1:
        del prompt
        if not self.fresh:
            return _provenance()
        return ReadinessEvaluatorProvenanceV1(
            provider_name="public-test-provider",
            model_name="public-test-model",
            judge_isolation="fresh_context",
        )

    def context_token(self, prompt: ReadinessEvaluatorDraftPromptV1) -> str:
        del prompt
        token = "context-constant" if self.reused_token else f"context-{len(self.tokens) + 1}"
        self.tokens.append(token)
        return token


def _initialize_real(tmp_path: Path, *, limitations: str | None = None) -> tuple[Path, object]:
    source = _make_verified_inputs(tmp_path, limitations=limitations)
    run_dir = tmp_path / "readiness-run"
    initialize_readiness_v1(
        run_dir,
        baseline_run_dir=source.baseline_run_dir,
        qualification_run_dir=source.qualification_run_dir,
        generation_run_dir=source.generation_run_dir,
        validation_receipt_path=source.validation_receipt_path,
    )
    return run_dir, source


def _initialize_synthetic(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> tuple[Path, object]:
    import regulatory_harvest.evaluation.attorney_readiness_workflow as workflow

    inputs = _request_inputs_fixture.__wrapped__(tmp_path)
    roots = tuple(
        tmp_path / name for name in ("source-baseline", "source-qualification", "source-generation")
    )
    for root in roots:
        root.mkdir()
    receipt = tmp_path / "validation-receipt.json"
    receipt.write_bytes(b"{}")
    monkeypatch.setattr(workflow, "build_verified_readiness_input_v1", lambda **_: inputs)
    run_dir = tmp_path / "readiness-run"
    initialize_readiness_v1(
        run_dir,
        baseline_run_dir=roots[0],
        qualification_run_dir=roots[1],
        generation_run_dir=roots[2],
        validation_receipt_path=receipt,
    )
    return run_dir, inputs


def _initialize_verified_multi(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> tuple[Path, object]:
    import regulatory_harvest.evaluation.attorney_readiness_workflow as workflow

    source = _make_verified_inputs(tmp_path, limitations=None)
    verified = workflow.build_verified_readiness_input_v1(
        baseline_run_dir=source.baseline_run_dir,
        qualification_run_dir=source.qualification_run_dir,
        generation_run_dir=source.generation_run_dir,
        validation_receipt_path=source.validation_receipt_path,
    )
    requirements = tuple(
        _requirement(
            index,
            kind="gap" if index == 2 else "obligation",
            importance="critical" if index in {2, 5} else "material",
        )
        for index in range(1, 8)
    )
    baseline_context = _resealed_context(
        verified.baseline_context,
        baseline_mutation={
            "requirements": requirements,
            "relationships": (),
            "contested_requirements": (_contest(),),
        },
    )
    projection = verify_gradeable_baseline_projection_v1(
        baseline_context,
        project_gradeable_baseline_v1(baseline_context),
    )
    readiness_input = verified.readiness_input.__class__.model_validate(
        {
            **verified.readiness_input.model_dump(mode="python"),
            "gradeable_baseline": projection,
            "grade_target_fingerprint": projection.binding.grade_target_fingerprint,
        }
    )
    inputs = replace(
        verified,
        readiness_input=readiness_input,
        baseline_context=baseline_context,
        gradeable_baseline=projection,
    )
    monkeypatch.setattr(workflow, "build_verified_readiness_input_v1", lambda **_: inputs)
    run_dir = tmp_path / "readiness-run"
    initialize_readiness_v1(
        run_dir,
        baseline_run_dir=source.baseline_run_dir,
        qualification_run_dir=source.qualification_run_dir,
        generation_run_dir=source.generation_run_dir,
        validation_receipt_path=source.validation_receipt_path,
    )
    return run_dir, inputs


def _advance_to_operation(
    run_dir: Path, operation: ReadinessOperationV1
) -> ReadinessEvaluatorRequestV1:
    while True:
        request = next_readiness_request_v1(run_dir)
        assert request is not None
        if request.operation is operation:
            return request
        compiled = compile_readiness_draft_v1(
            request,
            _draft(request, grade_mode="partial", disputes=True),
            _provenance(),
        )
        assert isinstance(compiled, CompiledReadinessDraftV1)
        submit_readiness_response_v1(run_dir, compiled.response)


def test_initialization_admits_all_inputs_before_output_and_never_writes_source_roots(
    tmp_path: Path,
) -> None:
    source = _make_verified_inputs(tmp_path)
    source_roots = (
        source.baseline_run_dir,
        source.qualification_run_dir,
        source.generation_run_dir,
    )
    before = tuple(_tree_bytes(root) for root in source_roots)
    output = tmp_path / "readiness-run"

    state = initialize_readiness_v1(
        output,
        baseline_run_dir=source.baseline_run_dir,
        qualification_run_dir=source.qualification_run_dir,
        generation_run_dir=source.generation_run_dir,
        validation_receipt_path=source.validation_receipt_path,
    )

    assert state.current_call_id == "grade-lane-1-GB-1-0001"
    assert tuple(_tree_bytes(root) for root in source_roots) == before
    assert verify_readiness_run_v1(output).valid is True


def test_failed_admission_creates_no_output(tmp_path: Path) -> None:
    source = _make_verified_inputs(tmp_path)
    source.validation_receipt_path.write_bytes(b"{}")
    output = tmp_path / "readiness-run"
    with pytest.raises(ValueError):
        initialize_readiness_v1(
            output,
            baseline_run_dir=source.baseline_run_dir,
            qualification_run_dir=source.qualification_run_dir,
            generation_run_dir=source.generation_run_dir,
            validation_receipt_path=source.validation_receipt_path,
        )
    assert not output.exists()


@pytest.mark.parametrize("source_name", ["baseline", "qualification", "generation"])
def test_output_cannot_be_created_inside_any_source_root(tmp_path: Path, source_name: str) -> None:
    source = _make_verified_inputs(tmp_path)
    root = {
        "baseline": source.baseline_run_dir,
        "qualification": source.qualification_run_dir,
        "generation": source.generation_run_dir,
    }[source_name]
    before = _tree_bytes(root)
    output = root / "forbidden-readiness"
    with pytest.raises(ValueError, match="OVERLAPS_INPUT"):
        initialize_readiness_v1(
            output,
            baseline_run_dir=source.baseline_run_dir,
            qualification_run_dir=source.qualification_run_dir,
            generation_run_dir=source.generation_run_dir,
            validation_receipt_path=source.validation_receipt_path,
        )
    assert _tree_bytes(root) == before


def test_output_cannot_be_created_inside_historical_v22_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import regulatory_harvest.evaluation.attorney_readiness_inputs as input_module

    source = _make_verified_inputs(tmp_path)
    historical = _historical_context(source, disposition="PASS")
    monkeypatch.setattr(input_module, "load_verified_v22_context", lambda _: historical)
    historical_dir = tmp_path / "historical-run"
    historical_dir.mkdir()
    before = _tree_bytes(historical_dir)
    with pytest.raises(ValueError, match="OVERLAPS_INPUT"):
        initialize_readiness_v1(
            historical_dir / "forbidden-readiness",
            baseline_run_dir=source.baseline_run_dir,
            qualification_run_dir=source.qualification_run_dir,
            generation_run_dir=source.generation_run_dir,
            validation_receipt_path=source.validation_receipt_path,
            historical_v22_run_dir=historical_dir,
            historical_anonymous_label="A",
        )
    assert _tree_bytes(historical_dir) == before


@pytest.mark.asyncio
async def test_exact_operation_order_fresh_contexts_and_terminal_replay(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    run_dir, inputs = _initialize_verified_multi(monkeypatch, tmp_path)
    evaluator = ScriptedEvaluator(grade_mode="partial", disputes=True, fresh=True)
    outcome = await continue_readiness_v1(run_dir, evaluator)
    operations = tuple(prompt.request.operation.value for prompt in evaluator.prompts)
    first_safety = operations.index("safety_review")
    assert all(value.startswith("baseline_locked") for value in operations[:first_safety])
    assert operations[first_safety : first_safety + 2] == (
        "safety_review",
        "safety_review",
    )
    assert all(value == "safety_referee" for value in operations[first_safety + 2 :])
    assert operations.count("baseline_locked_contested_grade") == (
        2 * len(inputs.gradeable_baseline.contested_requirements)
    )
    assert operations.count("safety_referee") > 1
    for prompt in evaluator.prompts:
        payload = repr(prompt.request.payload).lower()
        assert "provider_name" not in payload
        assert "model_name" not in payload
        if prompt.request.operation is ReadinessOperationV1.SAFETY_REVIEW:
            assert "finding_proposals" not in payload
    assert all(prompt.attempt == 1 for prompt in evaluator.prompts)
    assert len(evaluator.tokens) == len(set(evaluator.tokens)) == len(evaluator.prompts)
    assert outcome.engine_paused is False
    assert outcome.result is not None
    assert verify_readiness_run_v1(run_dir).valid is True
    assert next_readiness_request_v1(run_dir) is None
    assert resume_readiness_v1(run_dir).terminal_status == "COMPLETED"


def test_all_ordinary_and_contested_grade_requests_are_lane_ordered_before_safety(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    run_dir, inputs = _initialize_synthetic(monkeypatch, tmp_path)
    observed: list[tuple[str, int]] = []
    while True:
        request = next_readiness_request_v1(run_dir)
        assert request is not None
        if request.operation is ReadinessOperationV1.SAFETY_REVIEW:
            break
        observed.append((request.operation.value, cast(int, request.payload["lane"])))
        draft = _draft(request, grade_mode="review")
        compiled = compile_readiness_draft_v1(request, draft, _provenance())
        assert isinstance(compiled, CompiledReadinessDraftV1)
        submit_readiness_response_v1(run_dir, compiled.response)

    batches_per_lane = len(inputs.gradeable_baseline.requirements) // 5
    if len(inputs.gradeable_baseline.requirements) % 5:
        batches_per_lane += 1
    contests_per_lane = len(inputs.gradeable_baseline.contested_requirements)
    expected_lane = [1] * (batches_per_lane + contests_per_lane) + [2] * (
        batches_per_lane + contests_per_lane
    )
    assert [lane for _, lane in observed] == expected_lane
    for lane in (1, 2):
        lane_operations = [operation for operation, item_lane in observed if item_lane == lane]
        assert (
            lane_operations
            == ["baseline_locked_grade"] * batches_per_lane
            + ["baseline_locked_contested_grade"] * contests_per_lane
        )


@pytest.mark.asyncio
async def test_second_mechanical_refusal_is_write_free_and_pauses_with_original_request(
    tmp_path: Path,
) -> None:
    run_dir, _ = _initialize_real(tmp_path)
    request = next_readiness_request_v1(run_dir)
    assert request is not None
    before = _tree_bytes(run_dir)
    evaluator = ScriptedEvaluator(refuse=True, fresh=True)
    outcome = await continue_readiness_v1(run_dir, evaluator)
    assert outcome.engine_paused is True
    assert outcome.exit_code == 6
    assert outcome.result is None
    assert outcome.pending_request == request == next_readiness_request_v1(run_dir)
    assert [item.attempt for item in evaluator.prompts] == [1, 2]
    assert len(evaluator.tokens) == len(set(evaluator.tokens)) == 2
    assert _tree_bytes(run_dir) == before
    assert READINESS_RESULT_PATH not in _tree_bytes(run_dir)


@pytest.mark.asyncio
async def test_one_mechanical_refusal_gets_one_fresh_repair_and_records_attempt_two(
    tmp_path: Path,
) -> None:
    class RepairingEvaluator(ScriptedEvaluator):
        async def evaluate_draft(self, prompt: ReadinessEvaluatorDraftPromptV1) -> object:
            if len(self.prompts) >= 2:
                raise RuntimeError("stop after repaired response")
            self.prompts.append(prompt)
            if prompt.attempt == 1:
                return {}
            return _draft(prompt.request, grade_mode="met")

    run_dir, _ = _initialize_real(tmp_path, limitations=None)
    evaluator = RepairingEvaluator(fresh=True, fail_after=2)
    outcome = await continue_readiness_v1(run_dir, evaluator)
    assert outcome.engine_paused is True
    assert [prompt.attempt for prompt in evaluator.prompts] == [1, 2]
    assert len(evaluator.tokens) == len(set(evaluator.tokens)) == 3
    context = load_verified_readiness_context_v1(run_dir)
    assert len(context.manifest.accepted_calls) == 1
    assert context.manifest.accepted_calls[0].attempt == 2


@pytest.mark.asyncio
async def test_fresh_context_token_reuse_pauses_without_accepting_second_role(
    tmp_path: Path,
) -> None:
    run_dir, _ = _initialize_real(tmp_path, limitations=None)
    evaluator = ScriptedEvaluator(grade_mode="met", fresh=True, reused_token=True)
    outcome = await continue_readiness_v1(run_dir, evaluator)
    assert outcome.engine_paused is True
    assert outcome.pause_reason_codes == (READINESS_CONTEXT_ISOLATION_INVALID,)
    context = load_verified_readiness_context_v1(run_dir)
    assert len(context.manifest.accepted_calls) == 1
    assert context.pending_request == outcome.pending_request
    assert len(evaluator.prompts) == 1


@pytest.mark.asyncio
async def test_unfavorable_substantive_safety_result_is_accepted_without_retry(
    tmp_path: Path,
) -> None:
    run_dir, _ = _initialize_real(tmp_path, limitations=None)
    evaluator = ScriptedEvaluator(grade_mode="met", blocking_safety=True, fresh=True)
    outcome = await continue_readiness_v1(run_dir, evaluator)
    assert outcome.result is not None
    assert outcome.result.delivery_readiness.value == "NOT_DELIVERABLE"
    assert outcome.exit_code == 4
    assert all(prompt.attempt == 1 for prompt in evaluator.prompts)


@pytest.mark.asyncio
async def test_high_assurance_path_and_exit_code(tmp_path: Path) -> None:
    run_dir, _ = _initialize_real(tmp_path, limitations=None)
    outcome = await continue_readiness_v1(run_dir, ScriptedEvaluator(grade_mode="met"))
    assert outcome.result is not None
    assert outcome.result.baseline_locked_strict_equivalent_disposition.value == "PASS"
    assert outcome.result.delivery_readiness.value == "HIGH_ASSURANCE"
    assert outcome.exit_code == readiness_exit_code_v1(outcome.result, paused=False) == 0


@pytest.mark.asyncio
async def test_review_ready_with_declared_language_gap_is_deliverable_for_review(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    run_dir, _ = _initialize_verified_multi(monkeypatch, tmp_path)
    outcome = await continue_readiness_v1(run_dir, ScriptedEvaluator(grade_mode="review"))
    assert outcome.result is not None
    assert outcome.result.delivery_readiness.value == "REVIEW_READY_WITH_GAPS"
    assert outcome.exit_code == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("grade_mode", "expected_strict"),
    [("review", "FAIL"), ("inconclusive", "INCONCLUSIVE")],
)
async def test_strict_fail_or_inconclusive_can_reach_a_non_high_assurance_tier(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    grade_mode: str,
    expected_strict: str,
) -> None:
    run_dir, _ = _initialize_verified_multi(monkeypatch, tmp_path)
    evaluator = ScriptedEvaluator(grade_mode=grade_mode)
    outcome = await continue_readiness_v1(run_dir, evaluator)
    assert outcome.result is not None
    assert all(prompt.attempt == 1 for prompt in evaluator.prompts)
    assert outcome.result.baseline_locked_strict_equivalent_disposition.value == expected_strict
    assert outcome.result.delivery_readiness.value in {
        "REVIEW_READY_WITH_GAPS",
        "NOT_DELIVERABLE",
    }


@pytest.mark.asyncio
async def test_resume_after_each_accepted_role_never_reissues_an_accepted_request(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    run_dir, _ = _initialize_verified_multi(monkeypatch, tmp_path)
    accepted: set[str] = set()
    operation_classes: set[ReadinessOperationV1] = set()
    while True:
        request = next_readiness_request_v1(run_dir)
        assert request is not None
        assert request.request_fingerprint not in accepted
        evaluator = ScriptedEvaluator(grade_mode="partial", disputes=True, fail_after=1)
        outcome = await continue_readiness_v1(run_dir, evaluator)
        assert evaluator.prompts == [
            ReadinessEvaluatorDraftPromptV1(request=request, attempt=1, clarification_codes=())
        ]
        accepted.add(request.request_fingerprint)
        operation_classes.add(request.operation)
        if outcome.result is not None:
            break
        assert outcome.engine_paused is True
        assert outcome.pending_request is not None
        assert outcome.pending_request.request_fingerprint not in accepted
        assert next_readiness_request_v1(run_dir) == outcome.pending_request
        assert resume_readiness_v1(run_dir).terminal_status is None
    assert operation_classes == set(ReadinessOperationV1)
    assert verify_readiness_run_v1(run_dir).valid is True


def test_guarded_submit_is_total_write_free_and_rejects_wrong_bindings(tmp_path: Path) -> None:
    run_dir, _ = _initialize_real(tmp_path)
    request = next_readiness_request_v1(run_dir)
    assert request is not None
    compiled = compile_readiness_draft_v1(request, _ordinary_draft(request), _provenance())
    assert isinstance(compiled, CompiledReadinessDraftV1)
    valid = compiled.response.model_dump(mode="json")
    payload = cast(dict[str, object], valid["payload"])
    cyclic: dict[str, object] = {}
    cyclic["self"] = cyclic
    mutations = [
        None,
        True,
        object(),
        cyclic,
        {},
        {**valid, "request_fingerprint": "f" * 64},
        {**valid, "payload": {**payload, "lane": 2}},
        {**valid, "payload": {**payload, "batch_ref": "GB-1-9999"}},
    ]
    before = _tree_bytes(run_dir)
    for mutation in mutations:
        result = guarded_submit_readiness_response_v1(run_dir, mutation)
        assert isinstance(result, GuardedReadinessSubmissionResultV1)
        assert result.accepted is False
        assert result.preflight.valid is False
        assert _tree_bytes(run_dir) == before


@pytest.mark.parametrize(
    ("operation", "identity_field", "wrong_identity"),
    [
        (
            ReadinessOperationV1.BASELINE_LOCKED_CONTESTED_GRADE,
            "contested_requirement_id",
            "CONT-9999",
        ),
        (ReadinessOperationV1.SAFETY_REFEREE, "dispute_id", "SD-9999"),
    ],
)
def test_contested_and_dispute_identity_mutations_are_write_free(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    operation: ReadinessOperationV1,
    identity_field: str,
    wrong_identity: str,
) -> None:
    run_dir, _ = _initialize_verified_multi(monkeypatch, tmp_path)
    request = _advance_to_operation(run_dir, operation)
    compiled = compile_readiness_draft_v1(
        request,
        _draft(request, grade_mode="partial", disputes=True),
        _provenance(),
    )
    assert isinstance(compiled, CompiledReadinessDraftV1)
    raw = compiled.response.model_dump(mode="json")
    payload = cast(dict[str, object], raw["payload"])
    hostile = {**raw, "payload": {**payload, identity_field: wrong_identity}}
    before = _tree_bytes(run_dir)
    result = guarded_submit_readiness_response_v1(run_dir, hostile)
    assert result.accepted is False
    assert result.preflight.valid is False
    assert _tree_bytes(run_dir) == before


def test_submit_rejects_terminal_response_without_writes(tmp_path: Path) -> None:
    run_dir, _ = _initialize_real(tmp_path, limitations=None)
    outcome = asyncio.run(continue_readiness_v1(run_dir, ScriptedEvaluator(grade_mode="met")))
    assert outcome.result is not None
    before = _tree_bytes(run_dir)
    context = load_verified_readiness_context_v1(run_dir)
    response = context.responses[context.manifest.accepted_calls[-1].call_id]
    assert preflight_readiness_response_v1(run_dir, response).valid is False
    with pytest.raises(ValueError):
        submit_readiness_response_v1(run_dir, response)
    assert _tree_bytes(run_dir) == before


def test_concurrent_alias_submission_accepts_exactly_once(tmp_path: Path) -> None:
    run_dir, _ = _initialize_real(tmp_path)
    request = next_readiness_request_v1(run_dir)
    assert request is not None
    compiled = compile_readiness_draft_v1(request, _ordinary_draft(request), _provenance())
    assert isinstance(compiled, CompiledReadinessDraftV1)
    alias = run_dir / "."
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(
            executor.map(
                lambda path: guarded_submit_readiness_response_v1(path, compiled.response),
                (run_dir, alias),
            )
        )
    assert sum(item.accepted for item in results) == 1
    assert verify_readiness_run_v1(run_dir).valid is True


@pytest.mark.asyncio
async def test_telemetry_contains_only_safe_operational_metadata(tmp_path: Path) -> None:
    class Sink:
        def __init__(self) -> None:
            self.events: list[ReadinessTelemetryEventV1] = []

        def emit(self, event: ReadinessTelemetryEventV1) -> None:
            self.events.append(event)

    run_dir, source = _initialize_real(tmp_path, limitations=None)
    sink = Sink()
    outcome = await continue_readiness_v1(
        run_dir, ScriptedEvaluator(grade_mode="met"), telemetry_sink=sink
    )
    assert outcome.result is not None
    assert sink.events
    serialized = repr(tuple(asdict(event) for event in sink.events))
    assert source.report_text not in serialized
    assert str(tmp_path) not in serialized
    assert "historical_v22" not in serialized.lower()
    assert "anonymous_label" not in serialized.lower()


@pytest.mark.parametrize(
    ("historical_kwargs", "expected_status"),
    [
        (None, "NOT_PROVIDED"),
        ({"disposition": "FAIL"}, "DISPOSITION_DIFFERS"),
        ({"disposition": "PASS"}, "MATCH"),
        ({"report_hash": "f" * 64}, "REPORT_NOT_COMPARABLE"),
        ({"baseline_comparable": False}, "BASELINE_NOT_COMPARABLE"),
    ],
)
def test_historical_cross_check_modes_remain_initialization_only_evidence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    historical_kwargs: dict[str, object] | None,
    expected_status: str,
) -> None:
    import regulatory_harvest.evaluation.attorney_readiness_inputs as input_module

    source = _make_verified_inputs(tmp_path)
    run_dir = tmp_path / "readiness-run"
    arguments: dict[str, object] = {}
    if historical_kwargs is not None:
        historical = _historical_context(source, **historical_kwargs)
        monkeypatch.setattr(input_module, "load_verified_v22_context", lambda _: historical)
        historical_dir = tmp_path / "historical-run"
        historical_dir.mkdir()
        arguments = {
            "historical_v22_run_dir": historical_dir,
            "historical_anonymous_label": "A",
        }
    initialize_readiness_v1(
        run_dir,
        baseline_run_dir=source.baseline_run_dir,
        qualification_run_dir=source.qualification_run_dir,
        generation_run_dir=source.generation_run_dir,
        validation_receipt_path=source.validation_receipt_path,
        **arguments,  # type: ignore[arg-type]
    )
    initialized = load_verified_readiness_context_v1(run_dir)
    request = initialized.pending_request
    assert request is not None
    assert "historical" not in repr(request.payload).lower()
    outcome = asyncio.run(continue_readiness_v1(run_dir, ScriptedEvaluator(grade_mode="met")))
    assert outcome.result is not None
    assert outcome.result.historical_v22_cross_check_status.value == expected_status


def test_readiness_exit_code_contract() -> None:
    assert readiness_exit_code_v1(None, paused=True) == 6
    assert readiness_exit_code_v1(None, paused=False) == 3
