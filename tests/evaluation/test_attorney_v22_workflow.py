"""Recoverable Protocol 2.2 evaluator workflow contracts."""

from __future__ import annotations

import asyncio
import contextlib
import itertools
import shutil
import threading
import unicodedata
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from datetime import date
from pathlib import Path
from typing import Any, Literal

import pytest

import regulatory_harvest.evaluation as evaluation
from regulatory_harvest.evaluation import attorney_v2_models as shared_models
from regulatory_harvest.evaluation import attorney_v22_artifacts as artifacts
from regulatory_harvest.evaluation import attorney_v22_compiler as compiler
from regulatory_harvest.evaluation import attorney_v22_models as models
from regulatory_harvest.evaluation import attorney_v22_workflow as workflow
from regulatory_harvest.evaluation.attorney_artifacts import EvaluationIntegrityError
from regulatory_harvest.evaluation.attorney_models import (
    AttorneyEvaluationCase,
    CandidateReport,
    CandidateRole,
    EvaluationMode,
    EvaluationSource,
    RequestedAuthority,
)
from regulatory_harvest.evaluation.attorney_v22_artifacts import verify_v22_run
from regulatory_harvest.evaluation.attorney_v22_drafts import (
    CompiledDraftV22,
    EvaluatorDraftPromptV22,
    EvaluatorProvenanceV22,
    compile_evaluator_draft_v22,
)
from regulatory_harvest.evaluation.attorney_v22_models import (
    EvaluationTerminalStatusV22,
    EvaluatorOperationV22,
    EvaluatorRequestV22,
    EvaluatorResponseV22,
)
from regulatory_harvest.evaluation.attorney_v22_workflow import (
    EvaluationTelemetryEventV22,
    continue_evaluation_v22,
    guarded_submit_evaluator_response_v22,
    initialize_evaluation_v22,
    next_evaluator_request_v22,
    preflight_evaluator_response_v22,
    resume_evaluation_v22,
    run_evaluation_v22,
)
from regulatory_harvest.models import SourceQuality, SourceRole
from regulatory_harvest.storage import sha256_digest


def _case(
    *, comparator: bool = False, report_text: str = "Operators must retain records."
) -> AttorneyEvaluationCase:
    source_text = "Rule: operators must retain records."
    source = EvaluationSource(
        source_id="rule-1",
        title="Example Rule",
        normalized_text=source_text,
        content_hash=sha256_digest(source_text.encode()),
        jurisdiction="Example State",
        authority_type="regulation",
        source_role=SourceRole.OFFICIAL_PRIMARY,
        source_quality=SourceQuality.PRIMARY,
        completeness="complete",
        language="en",
    )
    candidate = CandidateReport(
        candidate_id="private-candidate",
        role=CandidateRole.CANDIDATE,
        report_text=report_text,
        report_hash=sha256_digest(report_text.encode()),
        validation_receipt={"kind": "external"},
    )
    candidates = [candidate]
    if comparator:
        candidates.append(
            CandidateReport(
                candidate_id="private-comparator",
                role=CandidateRole.COMPARATOR,
                report_text=report_text,
                report_hash=sha256_digest(report_text.encode()),
                validation_receipt={"kind": "external"},
            )
        )
    return AttorneyEvaluationCase(
        schema_version="1.1",
        case_id="v22-workflow-case",
        mode=EvaluationMode.CLOSED_UNIVERSE,
        question="What must operators do?",
        jurisdiction="Example State",
        as_of=date(2026, 8, 20),
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
        candidates=candidates,
    )


def _tree_bytes(run_dir: Path) -> dict[str, bytes]:
    return {
        path.relative_to(run_dir).as_posix(): path.read_bytes()
        for path in sorted(run_dir.rglob("*"))
        if path.is_file() and not path.is_symlink()
    }


def _proposal(*, statement: str = "Operators must retain records.") -> dict[str, object]:
    return {
        "statement": statement,
        "kind": "obligation",
        "importance": "critical",
        "passages": [{"source_id": "rule-1", "quote": "operators must retain records"}],
        "dependency": None,
        "confidence": "clear",
        "rationale": "Bare but source-bound.",
    }


class _ScriptedEvaluator:
    def __init__(
        self,
        *,
        bad_attempts: int = 0,
        review_fragments: int = 1,
        audit_fragments: int = 1,
        referee_decision: str = "accept_reviewer",
        ordinary_disposition: str = "met",
        label_dispositions: dict[str, str] | None = None,
        unresolved_grade: bool = False,
        empty_sources: bool = False,
    ) -> None:
        self.bad_attempts = bad_attempts
        self.review_fragments = review_fragments
        self.audit_fragments = audit_fragments
        self.referee_decision = referee_decision
        self.ordinary_disposition = ordinary_disposition
        self.label_dispositions = {} if label_dispositions is None else label_dispositions
        self.unresolved_grade = unresolved_grade
        self.empty_sources = empty_sources
        self.prompts: list[EvaluatorDraftPromptV22] = []
        self.operations: list[tuple[str, str | None, int | None]] = []

    async def evaluate_draft(self, prompt: EvaluatorDraftPromptV22) -> object:
        self.prompts.append(prompt)
        if self.bad_attempts:
            self.bad_attempts -= 1
            return {"malformed": "draft-private-secret"}
        request = prompt.request
        label = request.payload.get("anonymous_label")
        lane = request.payload.get("grader_lane")
        self.operations.append(
            (
                request.operation.value,
                label if isinstance(label, str) else None,
                lane if isinstance(lane, int) else None,
            )
        )
        if request.operation is EvaluatorOperationV22.SOURCE_REVIEW_FRAGMENT:
            ordinal = int(request.payload["fragment_ordinal"])
            complete = ordinal >= self.review_fragments
            proposals = (
                []
                if self.empty_sources
                else [_proposal(statement=f"Duty {ordinal}: operators must retain records.")]
            )
            return {"proposals": proposals, "review_complete": complete}
        if request.operation is EvaluatorOperationV22.SOURCE_AUDIT_FRAGMENT:
            ordinal = int(request.payload["fragment_ordinal"])
            complete = ordinal >= self.audit_fragments
            concerns: list[dict[str, object]] = []
            if not self.empty_sources and ordinal == 1 and self.referee_decision != "none":
                concerns = [
                    {
                        "target_proposal_ordinal": 1,
                        "concern_type": "incorrect_statement",
                        "passages": [
                            {"source_id": "rule-1", "quote": "operators must retain records"}
                        ],
                        "explanation": "The exact formulation is disputed.",
                        "correction": _proposal(statement="Covered operators must retain records."),
                    }
                ]
            return {"concerns": concerns, "audit_complete": complete}
        if request.operation is EvaluatorOperationV22.SOURCE_REFEREE_FRAGMENT:
            unresolved = self.referee_decision == "unresolved"
            return {
                "decision": self.referee_decision,
                "unresolved_reason": "SOURCE_AMBIGUITY" if unresolved else None,
                "evidence_ordinals": [1],
                "rationale": "The source-bound alternatives support this disposition.",
            }
        if request.operation is EvaluatorOperationV22.ORDINARY_GRADE_FRAGMENT:
            disposition = self.label_dispositions.get(str(label), self.ordinary_disposition)
            return {
                "requirement_grades": [
                    {
                        "requirement_ordinal": index,
                        "disposition": disposition,
                        "report_passages": []
                        if disposition in {"not_met", "uncertain"}
                        else [request.payload["report_text"]],
                        "rationale": "The report is graded as written, even if weak.",
                        "omission": "The rule is absent."
                        if disposition == "not_met"
                        else None,
                    }
                    for index, _ in enumerate(request.payload["requirements"], 1)
                ],
                "rationale": "Every issued requirement was graded.",
            }
        disposition = (
            "uncertain"
            if self.unresolved_grade
            else self.label_dispositions.get(str(label), self.ordinary_disposition)
        )
        passages = (
            [] if disposition in {"uncertain", "not_met"} else [request.payload["report_text"]]
        )
        alternative = {
            "disposition": disposition,
            "report_passages": passages,
            "rationale": "The alternative remains substantively uncertain."
            if disposition == "uncertain"
            else "The report was graded.",
        }
        return {
            "reviewer_alternative_grade": alternative,
            "auditor_alternative_grade": alternative,
            "ambiguity_disposition": "uncertain" if disposition == "uncertain" else "acknowledged",
            "rationale": "Both alternatives were evaluated.",
        }


class _CollectingSink:
    def __init__(self, *, fail: bool = False) -> None:
        self.events: list[EvaluationTelemetryEventV22] = []
        self.fail = fail

    def emit(self, event: EvaluationTelemetryEventV22) -> None:
        self.events.append(event)
        if self.fail:
            raise RuntimeError("telemetry unavailable")


def _strict_review_response(
    request: EvaluatorRequestV22,
    *,
    provider_name: str = "external-provider",
    model_name: str = "external-model",
    statement: str = "Operators must retain records.",
    review_complete: bool = True,
) -> EvaluatorResponseV22:
    compiled = compile_evaluator_draft_v22(
        request,
        {
            "proposals": [_proposal(statement=statement)],
            "review_complete": review_complete,
        },
        EvaluatorProvenanceV22(
            provider_name=provider_name,
            model_name=model_name,
            judge_isolation="fresh_context",
        ),
    )
    assert isinstance(compiled, CompiledDraftV22)
    return compiled.response


def _strict_draft_response(
    request: EvaluatorRequestV22, draft: dict[str, object]
) -> EvaluatorResponseV22:
    compiled = compile_evaluator_draft_v22(
        request,
        draft,
        EvaluatorProvenanceV22(
            provider_name="external-provider",
            model_name="external-model",
            judge_isolation="fresh_context",
        ),
    )
    assert isinstance(compiled, CompiledDraftV22)
    return compiled.response


def _old_lexical_lock_index(path: Path) -> int:
    return int(sha256_digest(str(path.absolute()).encode())[:8], 16) % 64


def _assert_alias_submission_race_is_serialized(
    run_dir: Path,
    alias: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = next_evaluator_request_v22(run_dir)
    assert request is not None
    first = _strict_review_response(request, provider_name="physical-root-one")
    second = _strict_review_response(request, provider_name="physical-root-two")
    original_advance = workflow._advance
    collision = threading.Barrier(2)

    def collide(*args: Any, **kwargs: Any) -> Any:
        with contextlib.suppress(threading.BrokenBarrierError):
            collision.wait(timeout=0.25)
        return original_advance(*args, **kwargs)

    monkeypatch.setattr(workflow, "_advance", collide)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(guarded_submit_evaluator_response_v22, path, response)
            for path, response in ((run_dir, first), (alias, second))
        ]
        outcomes = [future.result() for future in futures]

    assert sum(outcome.accepted for outcome in outcomes) == 1
    rejected = next(outcome for outcome in outcomes if not outcome.accepted)
    assert rejected.preflight.diagnostics == ("EXTERNAL_RESPONSE_INVALID",)
    assert verify_v22_run(run_dir).valid
    assert _tree_bytes(alias) == _tree_bytes(run_dir)


def test_initialization_issues_the_first_exact_review_fragment(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"

    state = initialize_evaluation_v22(_case(), run_dir, seed_hex="f" * 64)
    request = next_evaluator_request_v22(run_dir)

    assert state.phase.value == "source_review"
    assert state.current_call_id == "source-review-0001"
    assert request is not None
    assert request.operation.value == "source_review_fragment"
    assert request.payload["fragment_ordinal"] == 1


@pytest.mark.parametrize("shape", ["raw", "constructed"])
def test_external_invalid_response_is_write_free_and_nonterminal(
    tmp_path: Path, shape: str
) -> None:
    run_dir = tmp_path / shape
    initialize_evaluation_v22(_case(), run_dir, seed_hex="a" * 64)
    pending = next_evaluator_request_v22(run_dir)
    before = _tree_bytes(run_dir)
    invalid: object = {"invalid": "secret response"}
    if shape == "constructed":
        invalid = EvaluatorResponseV22.model_construct(payload={"invalid": True})

    preflight = preflight_evaluator_response_v22(run_dir, invalid)
    submitted = guarded_submit_evaluator_response_v22(run_dir, invalid)

    assert preflight.valid is False
    assert preflight.diagnostics == ("EXTERNAL_RESPONSE_INVALID",)
    assert submitted.accepted is False
    assert _tree_bytes(run_dir) == before
    assert next_evaluator_request_v22(run_dir) == pending
    assert resume_evaluation_v22(run_dir).terminal_status is None


@pytest.mark.parametrize("field", ["provider_name", "model_name"])
def test_blank_external_envelope_is_write_free_and_nonterminal(tmp_path: Path, field: str) -> None:
    """Invalid supplied envelope text receives the controlled refusal taxonomy."""
    run_dir = tmp_path / field
    initialize_evaluation_v22(_case(), run_dir, seed_hex="a" * 64)
    pending = next_evaluator_request_v22(run_dir)
    assert pending is not None
    invalid = _strict_review_response(pending).model_dump(mode="json")
    invalid[field] = "   "
    before = _tree_bytes(run_dir)

    preflight = preflight_evaluator_response_v22(run_dir, invalid)
    submitted = guarded_submit_evaluator_response_v22(run_dir, invalid)

    assert not preflight.valid
    assert preflight.diagnostics == ("EXTERNAL_RESPONSE_INVALID",)
    assert not submitted.accepted
    assert submitted.preflight == preflight
    assert _tree_bytes(run_dir) == before
    assert next_evaluator_request_v22(run_dir) == pending


@pytest.mark.parametrize("fault_type", [TypeError, ValueError, RuntimeError])
@pytest.mark.parametrize("boundary", ["canonicalizer", "serializer"])
def test_response_validation_propagates_engine_faults_outside_typed_input_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
    fault_type: type[Exception],
) -> None:
    """Canonicalization and serialization defects are not external-response refusals."""
    run_dir = tmp_path / f"{boundary}-{fault_type.__name__}"
    initialize_evaluation_v22(_case(), run_dir, seed_hex="a" * 64)
    pending = next_evaluator_request_v22(run_dir)
    assert pending is not None
    response = _strict_review_response(pending)
    before = _tree_bytes(run_dir)

    def fail(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise fault_type(f"injected {boundary} fault")

    if boundary == "canonicalizer":
        original_canonicalizer = models.canonical_json_bytes

        def fail_response_only(value: object) -> bytes:
            if isinstance(value, dict) and "provider_name" in value:
                return fail(value)  # type: ignore[return-value]
            return original_canonicalizer(value)

        monkeypatch.setattr(models, "canonical_json_bytes", fail_response_only)
    else:
        monkeypatch.setattr(models.EvaluatorResponseV22, "model_dump", fail)

    with pytest.raises(fault_type, match=f"injected {boundary} fault"):
        preflight_evaluator_response_v22(run_dir, response)

    assert _tree_bytes(run_dir) == before
    assert next_evaluator_request_v22(run_dir) == pending


@pytest.mark.parametrize("fault_type", [TypeError, ValueError, RecursionError])
def test_response_payload_canonicalizer_fault_escapes_shared_model_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault_type: type[Exception],
) -> None:
    """A valid JSON tree's canonicalizer defect is not invalid external input."""
    run_dir = tmp_path / f"shared-canonicalizer-{fault_type.__name__}"
    initialize_evaluation_v22(_case(), run_dir, seed_hex="a" * 64)
    pending = next_evaluator_request_v22(run_dir)
    assert pending is not None
    response = _strict_review_response(pending)
    before = _tree_bytes(run_dir)
    original = shared_models.canonical_json_bytes

    def fail_response_payload(value: object) -> bytes:
        if (
            isinstance(value, dict)
            and value.get("schema_version") == "2.2"
            and "proposals" in value
        ):
            raise fault_type("injected shared canonicalizer fault")
        return original(value)

    monkeypatch.setattr(
        shared_models, "canonical_json_bytes", fail_response_payload
    )

    with pytest.raises(RuntimeError, match="canonical JSON"):
        preflight_evaluator_response_v22(run_dir, response)

    assert _tree_bytes(run_dir) == before
    assert next_evaluator_request_v22(run_dir) == pending


def test_preflight_reuses_one_verified_context_without_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Response admission performs exactly one complete verified-run replay."""
    run_dir = tmp_path / "single-replay"
    initialize_evaluation_v22(_case(), run_dir, seed_hex="a" * 64)
    request = next_evaluator_request_v22(run_dir)
    assert request is not None
    response = _strict_review_response(request)
    before = _tree_bytes(run_dir)
    original = artifacts._verify_or_raise
    calls = 0

    def counted_verify(*args: Any, **kwargs: Any) -> Any:
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(artifacts, "_verify_or_raise", counted_verify)

    preflight = preflight_evaluator_response_v22(run_dir, response)

    assert preflight.valid
    assert calls == 1
    assert _tree_bytes(run_dir) == before


@pytest.mark.parametrize("fault_type", [TypeError, ValueError])
@pytest.mark.parametrize("stage", ["controller", "serializer"])
def test_preflight_propagates_controller_and_serializer_faults_write_free(
    stage: str,
    fault_type: type[Exception],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only supplied-response validation failures receive the public refusal."""
    run_dir = tmp_path / f"{stage}-{fault_type.__name__}"
    initialize_evaluation_v22(_case(), run_dir, seed_hex="b" * 64)
    pending = next_evaluator_request_v22(run_dir)
    assert pending is not None
    response = _strict_review_response(pending)
    before = _tree_bytes(run_dir)
    error = fault_type(f"injected {stage} fault")

    def fail(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise error

    with monkeypatch.context() as patch:
        if stage == "controller":
            patch.setattr(workflow, "_review_fragments", fail)
        else:
            patch.setattr(compiler, "canonical_json_bytes", fail)
        with pytest.raises(fault_type, match=str(error)):
            preflight_evaluator_response_v22(run_dir, response)

    assert _tree_bytes(run_dir) == before
    assert next_evaluator_request_v22(run_dir) == pending


def test_external_complete_strict_response_advances_exactly_one_fragment(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "valid-external"
    initialize_evaluation_v22(_case(), run_dir, seed_hex="7" * 64)
    request = next_evaluator_request_v22(run_dir)
    assert request is not None
    response = _strict_review_response(request)

    submitted = guarded_submit_evaluator_response_v22(run_dir, response)

    assert submitted.accepted is True
    assert submitted.state is not None
    assert submitted.state.current_call_id == "source-audit-0001"
    assert next_evaluator_request_v22(run_dir).operation is (
        EvaluatorOperationV22.SOURCE_AUDIT_FRAGMENT
    )
    assert verify_v22_run(run_dir).valid


@pytest.mark.parametrize("operation", ["review", "audit"])
@pytest.mark.parametrize("conflict", [False, True])
def test_safe_submission_rejects_cross_fragment_semantics_before_mutation(
    tmp_path: Path, operation: str, conflict: bool
) -> None:
    run_dir = tmp_path / f"{operation}-{'conflict' if conflict else 'duplicate'}"
    initialize_evaluation_v22(_case(), run_dir, seed_hex="6" * 64)
    request = next_evaluator_request_v22(run_dir)
    assert request is not None

    if operation == "review":
        initial = _strict_review_response(request, review_complete=False)
        assert guarded_submit_evaluator_response_v22(run_dir, initial).accepted
        pending = next_evaluator_request_v22(run_dir)
        assert pending is not None
        candidate = _proposal()
        if conflict:
            candidate["rationale"] = "Different bytes for the same semantic duty."
        response = _strict_draft_response(
            pending, {"proposals": [candidate], "review_complete": False}
        )
    else:
        complete_review = _strict_review_response(request)
        assert guarded_submit_evaluator_response_v22(run_dir, complete_review).accepted
        audit_request = next_evaluator_request_v22(run_dir)
        assert audit_request is not None
        concern = {
            "target_proposal_ordinal": 1,
            "concern_type": "incorrect_statement",
            "passages": [
                {"source_id": "rule-1", "quote": "operators must retain records"}
            ],
            "explanation": "The exact formulation is disputed.",
            "correction": _proposal(statement="Covered operators must retain records."),
        }
        initial = _strict_draft_response(
            audit_request, {"concerns": [concern], "audit_complete": False}
        )
        assert guarded_submit_evaluator_response_v22(run_dir, initial).accepted
        pending = next_evaluator_request_v22(run_dir)
        assert pending is not None
        candidate = dict(concern)
        if conflict:
            candidate["explanation"] = "Different bytes for the same semantic concern."
        response = _strict_draft_response(
            pending, {"concerns": [candidate], "audit_complete": False}
        )

    before = _tree_bytes(run_dir)
    preflight = preflight_evaluator_response_v22(run_dir, response)
    submitted = guarded_submit_evaluator_response_v22(run_dir, response)

    assert not preflight.valid
    assert preflight.diagnostics == ("EXTERNAL_RESPONSE_INVALID",)
    assert not submitted.accepted
    assert submitted.preflight == preflight
    assert _tree_bytes(run_dir) == before
    assert next_evaluator_request_v22(run_dir) == pending
    assert verify_v22_run(run_dir).valid


@pytest.mark.parametrize("same_provenance", [False, True])
def test_concurrent_guarded_submissions_accept_one_and_reject_the_stale_loser(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    same_provenance: bool,
) -> None:
    run_dir = tmp_path / f"guarded-race-{same_provenance}"
    initialize_evaluation_v22(_case(), run_dir, seed_hex="8" * 64)
    request = next_evaluator_request_v22(run_dir)
    assert request is not None
    first = _strict_review_response(request, provider_name="provider-one")
    second = _strict_review_response(
        request,
        provider_name="provider-one" if same_provenance else "provider-two",
    )
    original_advance = workflow._advance
    collision = threading.Barrier(2)

    def collide(*args: Any, **kwargs: Any) -> Any:
        with contextlib.suppress(threading.BrokenBarrierError):
            collision.wait(timeout=0.25)
        return original_advance(*args, **kwargs)

    monkeypatch.setattr(workflow, "_advance", collide)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(guarded_submit_evaluator_response_v22, run_dir, response)
            for response in (first, second)
        ]
        outcomes = [future.result() for future in futures]

    assert sum(outcome.accepted for outcome in outcomes) == 1
    rejected = next(outcome for outcome in outcomes if not outcome.accepted)
    assert rejected.preflight.diagnostics == ("EXTERNAL_RESPONSE_INVALID",)
    assert next_evaluator_request_v22(run_dir).operation is (
        EvaluatorOperationV22.SOURCE_AUDIT_FRAGMENT
    )
    assert verify_v22_run(run_dir).valid
    after = _tree_bytes(run_dir)
    stale = guarded_submit_evaluator_response_v22(
        run_dir, second if outcomes[0].accepted else first
    )
    assert not stale.accepted
    assert _tree_bytes(run_dir) == after


def test_case_alias_guarded_submissions_share_the_physical_root_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_dir = tmp_path / "CaseAliasEvaluation"
    initialize_evaluation_v22(_case(), run_dir, seed_hex="8" * 64)
    original_index = _old_lexical_lock_index(run_dir)
    variants = (
        "".join(chars)
        for chars in itertools.product(
            *((character.lower(), character.upper()) for character in run_dir.name)
        )
    )
    alias = next(
        (
            tmp_path / variant
            for variant in variants
            if variant != run_dir.name
            and (tmp_path / variant).exists()
            and (tmp_path / variant).samefile(run_dir)
            and _old_lexical_lock_index(tmp_path / variant) != original_index
        ),
        None,
    )
    if alias is None:
        pytest.skip("filesystem does not support a distinct case alias")

    _assert_alias_submission_race_is_serialized(run_dir, alias, monkeypatch)


def test_lexical_alias_guarded_submissions_share_the_physical_root_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_dir = tmp_path / "lexical-alias-evaluation"
    initialize_evaluation_v22(_case(), run_dir, seed_hex="8" * 64)
    alias = run_dir / ".." / run_dir.name
    while _old_lexical_lock_index(alias) == _old_lexical_lock_index(run_dir):
        alias = alias / ".." / run_dir.name
    assert alias.samefile(run_dir)

    _assert_alias_submission_race_is_serialized(run_dir, alias, monkeypatch)


def test_unicode_alias_guarded_submissions_share_the_physical_root_lock_when_supported(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_dir = tmp_path / "Caf\u00e9Evaluation"
    initialize_evaluation_v22(_case(), run_dir, seed_hex="8" * 64)
    alias = tmp_path / unicodedata.normalize("NFD", run_dir.name)
    if (
        not alias.exists()
        or not alias.samefile(run_dir)
        or _old_lexical_lock_index(alias) == _old_lexical_lock_index(run_dir)
    ):
        pytest.skip("filesystem does not support a distinct Unicode normalization alias")

    _assert_alias_submission_race_is_serialized(run_dir, alias, monkeypatch)


def test_submission_root_replacement_while_waiting_for_lock_fails_safe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_dir = tmp_path / "replaced-root"
    displaced = tmp_path / "displaced-root"
    initialize_evaluation_v22(_case(), run_dir, seed_hex="8" * 64)
    request = next_evaluator_request_v22(run_dir)
    assert request is not None
    response = _strict_review_response(request, provider_name="replacement-loser")
    original_lock = workflow._submission_lock
    held_lock = original_lock(run_dir)
    lock_selected = threading.Event()

    def observed_lock(*args: Any, **kwargs: Any) -> threading.RLock:
        selected = original_lock(*args, **kwargs)
        lock_selected.set()
        return selected

    monkeypatch.setattr(workflow, "_submission_lock", observed_lock)
    held_lock.acquire()
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(guarded_submit_evaluator_response_v22, run_dir, response)
            assert lock_selected.wait(timeout=2)
            run_dir.rename(displaced)
            shutil.copytree(displaced, run_dir)
            replacement_before = _tree_bytes(run_dir)
            held_lock.release()
            with pytest.raises(EvaluationIntegrityError, match="RUN_ROOT_IDENTITY"):
                future.result()
    finally:
        with contextlib.suppress(RuntimeError):
            held_lock.release()

    assert _tree_bytes(displaced) == replacement_before
    assert _tree_bytes(run_dir) == replacement_before
    assert verify_v22_run(displaced).valid
    assert verify_v22_run(run_dir).valid


@pytest.mark.parametrize("root_kind", ["missing", "file", "symlink"])
def test_submission_lock_refuses_non_directory_or_aliased_roots_without_creation(
    tmp_path: Path,
    root_kind: str,
) -> None:
    valid = tmp_path / "valid-root"
    initialize_evaluation_v22(_case(), valid, seed_hex="8" * 64)
    run_dir = tmp_path / root_kind
    if root_kind == "file":
        run_dir.write_text("not a directory", encoding="utf-8")
    elif root_kind == "symlink":
        run_dir.symlink_to(valid, target_is_directory=True)

    with pytest.raises(EvaluationIntegrityError):
        guarded_submit_evaluator_response_v22(run_dir, {"invalid": True})

    if root_kind == "missing":
        assert not run_dir.exists()
    assert verify_v22_run(valid).valid


@pytest.mark.asyncio
async def test_guarded_submission_wins_against_continuation_without_stale_pause(
    tmp_path: Path,
) -> None:
    class CoordinatedEvaluator(_ScriptedEvaluator):
        def __init__(self) -> None:
            super().__init__(referee_decision="none")
            self.started = asyncio.Event()
            self.release = asyncio.Event()

        async def evaluate_draft(self, prompt: EvaluatorDraftPromptV22) -> object:
            if not self.prompts:
                self.started.set()
                await self.release.wait()
            return await super().evaluate_draft(prompt)

    run_dir = tmp_path / "guarded-versus-continue"
    initialize_evaluation_v22(_case(), run_dir, seed_hex="9" * 64)
    request = next_evaluator_request_v22(run_dir)
    assert request is not None
    evaluator = CoordinatedEvaluator()
    continuing = asyncio.create_task(continue_evaluation_v22(run_dir, evaluator))
    await evaluator.started.wait()

    external = guarded_submit_evaluator_response_v22(
        run_dir,
        _strict_review_response(request, provider_name="external-winner"),
    )
    evaluator.release.set()
    outcome = await continuing

    assert external.accepted
    assert not outcome.engine_paused
    assert outcome.state.terminal_status is EvaluationTerminalStatusV22.COMPLETED
    context = workflow.load_verified_v22_context(run_dir)
    review_calls = [
        call
        for call in context.manifest.calls
        if call.operation is EvaluatorOperationV22.SOURCE_REVIEW_FRAGMENT
    ]
    assert len(review_calls) == 1
    assert review_calls[0].state == "accepted"
    assert review_calls[0].provider_name == "external-winner"
    assert verify_v22_run(run_dir).valid


@pytest.mark.asyncio
async def test_concurrent_external_win_survives_provider_crash_and_reentry(
    tmp_path: Path,
) -> None:
    class CoordinatedCrash:
        def __init__(self) -> None:
            self.started = asyncio.Event()
            self.release = asyncio.Event()

        async def evaluate_draft(self, prompt: EvaluatorDraftPromptV22) -> object:
            del prompt
            self.started.set()
            await self.release.wait()
            raise RuntimeError("provider crash after concurrent acceptance")

    run_dir = tmp_path / "guarded-versus-crash"
    initialize_evaluation_v22(_case(), run_dir, seed_hex="9" * 64)
    request = next_evaluator_request_v22(run_dir)
    assert request is not None
    evaluator = CoordinatedCrash()
    continuing = asyncio.create_task(continue_evaluation_v22(run_dir, evaluator))
    await evaluator.started.wait()
    external = guarded_submit_evaluator_response_v22(
        run_dir,
        _strict_review_response(request, provider_name="external-before-crash"),
    )
    assert external.accepted
    after_external = _tree_bytes(run_dir)
    evaluator.release.set()

    with pytest.raises(RuntimeError, match="provider crash after concurrent acceptance"):
        await continuing
    assert _tree_bytes(run_dir) == after_external

    completed = await continue_evaluation_v22(
        run_dir, _ScriptedEvaluator(referee_decision="none")
    )
    assert completed.state.terminal_status is EvaluationTerminalStatusV22.COMPLETED
    context = workflow.load_verified_v22_context(run_dir)
    review_calls = [
        call
        for call in context.manifest.calls
        if call.operation is EvaluatorOperationV22.SOURCE_REVIEW_FRAGMENT
    ]
    assert len(review_calls) == 1
    assert review_calls[0].provider_name == "external-before-crash"
    assert verify_v22_run(run_dir).valid


@pytest.mark.asyncio
async def test_concurrent_continuations_reload_after_one_accepts_the_fragment(
    tmp_path: Path,
) -> None:
    class Coordinator:
        def __init__(self) -> None:
            self.arrivals = 0
            self.both_started = asyncio.Event()
            self.release = asyncio.Event()

    class CoordinatedEvaluator(_ScriptedEvaluator):
        def __init__(self, coordinator: Coordinator) -> None:
            super().__init__(referee_decision="none")
            self.coordinator = coordinator

        async def evaluate_draft(self, prompt: EvaluatorDraftPromptV22) -> object:
            if prompt.request.operation is EvaluatorOperationV22.SOURCE_REVIEW_FRAGMENT:
                self.coordinator.arrivals += 1
                if self.coordinator.arrivals == 2:
                    self.coordinator.both_started.set()
                await self.coordinator.release.wait()
            return await super().evaluate_draft(prompt)

    run_dir = tmp_path / "continue-race"
    initialize_evaluation_v22(_case(), run_dir, seed_hex="a" * 64)
    coordinator = Coordinator()
    first = asyncio.create_task(
        continue_evaluation_v22(run_dir, CoordinatedEvaluator(coordinator))
    )
    second = asyncio.create_task(
        continue_evaluation_v22(run_dir, CoordinatedEvaluator(coordinator))
    )
    await coordinator.both_started.wait()
    coordinator.release.set()

    outcomes = await asyncio.gather(first, second)

    assert all(not outcome.engine_paused for outcome in outcomes)
    assert all(
        outcome.state.terminal_status is EvaluationTerminalStatusV22.COMPLETED
        for outcome in outcomes
    )
    context = workflow.load_verified_v22_context(run_dir)
    call_ids = [call.call_id for call in context.manifest.calls]
    assert len(call_ids) == len(set(call_ids))
    assert sum(
        call.operation is EvaluatorOperationV22.SOURCE_REVIEW_FRAGMENT
        for call in context.manifest.calls
    ) == 1
    assert verify_v22_run(run_dir).valid


@pytest.mark.asyncio
async def test_two_bad_internal_drafts_pause_without_changing_run(tmp_path: Path) -> None:
    run_dir = tmp_path / "paused"
    initialize_evaluation_v22(_case(), run_dir, seed_hex="b" * 64)
    before = _tree_bytes(run_dir)
    evaluator = _ScriptedEvaluator(bad_attempts=2)

    outcome = await continue_evaluation_v22(run_dir, evaluator)

    assert outcome.engine_paused is True
    assert outcome.exit_code == 6
    assert outcome.pause_reason_codes == (
        "EVALUATION_ENGINE_PAUSED",
        "SUBSTANCE_MISSING",
    )
    assert _tree_bytes(run_dir) == before
    assert next_evaluator_request_v22(run_dir) == outcome.pending_request
    assert [prompt.attempt for prompt in evaluator.prompts] == [1, 2]
    assert evaluator.prompts[1].request == evaluator.prompts[0].request
    assert evaluator.prompts[1].clarification_codes
    assert "draft-private-secret" not in repr(evaluator.prompts[1])


@pytest.mark.asyncio
@pytest.mark.parametrize("shape", ["raw", "model_construct"])
async def test_adversarial_internal_draft_shapes_pause_nonterminal(
    tmp_path: Path, shape: str
) -> None:
    class InvalidEvaluator:
        async def evaluate_draft(self, prompt: EvaluatorDraftPromptV22) -> object:
            if shape == "raw":
                return {"unexpected": [True]}
            return EvaluatorResponseV22.model_construct(payload={"unexpected": True})

    run_dir = tmp_path / f"internal-{shape}"
    initialize_evaluation_v22(_case(), run_dir, seed_hex="6" * 64)
    before = _tree_bytes(run_dir)

    outcome = await continue_evaluation_v22(run_dir, InvalidEvaluator())

    assert outcome.engine_paused
    assert outcome.state.terminal_status is None
    assert _tree_bytes(run_dir) == before


@pytest.mark.asyncio
async def test_empty_final_review_and_audit_are_substantive_inconclusive(tmp_path: Path) -> None:
    run_dir = tmp_path / "empty"
    evaluator = _ScriptedEvaluator(empty_sources=True, referee_decision="none")

    outcome = await run_evaluation_v22(
        _case(report_text="Substantively empty answer."),
        evaluator,
        run_dir,
        seed_hex="c" * 64,
    )

    assert outcome.engine_paused is False
    assert outcome.state.terminal_status is EvaluationTerminalStatusV22.INCONCLUSIVE
    assert outcome.result is not None
    assert outcome.result.reports[0].sensitivity.reason_codes == ("BASELINE_EVIDENCE_INSUFFICIENT",)
    assert verify_v22_run(run_dir).valid


@pytest.mark.asyncio
async def test_pause_then_resume_reuses_exact_request_without_repeating_accepted_fragments(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "resume"
    initialize_evaluation_v22(_case(), run_dir, seed_hex="d" * 64)
    paused = await continue_evaluation_v22(run_dir, _ScriptedEvaluator(bad_attempts=2))
    pending = paused.pending_request

    resumed_evaluator = _ScriptedEvaluator(referee_decision="none")
    completed = await continue_evaluation_v22(run_dir, resumed_evaluator)

    assert resumed_evaluator.prompts[0].request == pending
    assert completed.engine_paused is False
    assert completed.state.terminal_status is EvaluationTerminalStatusV22.COMPLETED
    call_ids = [call.call_id for call in workflow.load_verified_v22_context(run_dir).manifest.calls]
    assert len(call_ids) == len(set(call_ids))


@pytest.mark.asyncio
async def test_provider_crash_is_write_free_and_later_resume_completes(tmp_path: Path) -> None:
    class CrashingEvaluator:
        async def evaluate_draft(self, prompt: EvaluatorDraftPromptV22) -> object:
            raise RuntimeError("provider crash")

    run_dir = tmp_path / "crash"
    initialize_evaluation_v22(_case(), run_dir, seed_hex="e" * 64)
    before = _tree_bytes(run_dir)
    with pytest.raises(RuntimeError, match="provider crash"):
        await continue_evaluation_v22(run_dir, CrashingEvaluator())
    assert _tree_bytes(run_dir) == before

    completed = await continue_evaluation_v22(run_dir, _ScriptedEvaluator(referee_decision="none"))
    assert completed.state.terminal_status is EvaluationTerminalStatusV22.COMPLETED


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("decision", "ordinary", "uncertain", "terminal", "absolute"),
    [
        ("accept_reviewer", "met", False, "COMPLETED", "PASS"),
        ("accept_auditor", "not_met", False, "COMPLETED", "FAIL"),
        ("unresolved", "met", False, "COMPLETED", "PASS"),
        ("unresolved", "not_met", False, "COMPLETED", "FAIL"),
        ("unresolved", "met", True, "INCONCLUSIVE", "INCONCLUSIVE"),
    ],
)
async def test_all_referee_and_terminal_substantive_outcomes(
    tmp_path: Path,
    decision: str,
    ordinary: str,
    uncertain: bool,
    terminal: str,
    absolute: str,
) -> None:
    evaluator = _ScriptedEvaluator(
        referee_decision=decision,
        ordinary_disposition=ordinary,
        unresolved_grade=uncertain,
    )
    outcome = await run_evaluation_v22(
        _case(), evaluator, tmp_path / f"{decision}-{absolute}", seed_hex="1" * 64
    )

    assert outcome.engine_paused is False
    assert outcome.state.terminal_status is not None
    assert outcome.state.terminal_status.value == terminal
    assert outcome.result is not None
    assert outcome.result.reports[0].sensitivity.absolute_disposition.value == absolute


@pytest.mark.asyncio
async def test_multi_fragment_two_report_sequence_is_report_major(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        workflow,
        "_verify_generation_capsules_for_initialization",
        lambda case, paths: None,
    )
    evaluator = _ScriptedEvaluator(
        review_fragments=2,
        audit_fragments=2,
        referee_decision="unresolved",
    )
    outcome = await run_evaluation_v22(
        _case(comparator=True), evaluator, tmp_path / "two-reports", seed_hex="2" * 64
    )

    assert outcome.state.terminal_status is EvaluationTerminalStatusV22.COMPLETED, (
        outcome.pause_reason_codes
    )
    grade_coordinates = [
        (label, lane)
        for operation, label, lane in evaluator.operations
        if operation.endswith("grade_fragment")
    ]
    first_b = next(index for index, item in enumerate(grade_coordinates) if item[0] == "B")
    assert all(label == "A" for label, _ in grade_coordinates[:first_b])
    assert all(label == "B" for label, _ in grade_coordinates[first_b:])
    assert [
        prompt.request.payload["fragment_ordinal"]
        for prompt in evaluator.prompts
        if prompt.request.operation is EvaluatorOperationV22.SOURCE_REVIEW_FRAGMENT
    ] == [1, 2]
    assert [
        prompt.request.payload["fragment_ordinal"]
        for prompt in evaluator.prompts
        if prompt.request.operation is EvaluatorOperationV22.SOURCE_AUDIT_FRAGMENT
    ] == [1, 2]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    (
        "seed_digit",
        "a_disposition",
        "b_disposition",
        "comparison_disposition",
        "winner_label",
        "candidate_label",
        "comparator_label",
    ),
    [
        ("0", "met", "not_met", "candidate_win", "A", "A", "B"),
        ("0", "not_met", "met", "comparator_win", "B", "A", "B"),
        ("3", "met", "not_met", "comparator_win", "A", "B", "A"),
        ("3", "not_met", "met", "candidate_win", "B", "B", "A"),
        ("0", "met", "met", "tie", None, "A", "B"),
        ("3", "uncertain", "met", "inconclusive", None, "B", "A"),
    ],
)
async def test_comparison_binds_outcomes_to_frozen_candidate_roles(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    seed_digit: str,
    a_disposition: str,
    b_disposition: str,
    comparison_disposition: str,
    winner_label: Literal["A", "B"] | None,
    candidate_label: Literal["A", "B"],
    comparator_label: Literal["A", "B"],
) -> None:
    monkeypatch.setattr(
        workflow,
        "_verify_generation_capsules_for_initialization",
        lambda case, paths: None,
    )
    outcome = await run_evaluation_v22(
        _case(comparator=True),
        _ScriptedEvaluator(
            referee_decision="none",
            label_dispositions={"A": a_disposition, "B": b_disposition},
        ),
        tmp_path / f"roles-{seed_digit}-{a_disposition}-{b_disposition}",
        seed_hex=seed_digit * 64,
    )

    assert outcome.result is not None
    comparison = outcome.result.comparison
    assert comparison is not None
    assert comparison.disposition.value == comparison_disposition
    assert comparison.winner_label == winner_label
    assert comparison.candidate_label == candidate_label
    assert comparison.comparator_label == comparator_label
    assert verify_v22_run(
        tmp_path / f"roles-{seed_digit}-{a_disposition}-{b_disposition}"
    ).valid


@pytest.mark.asyncio
async def test_compiler_preflight_disagreement_pauses_without_retry_or_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_dir = tmp_path / "disagreement"
    initialize_evaluation_v22(_case(), run_dir, seed_hex="3" * 64)
    before = _tree_bytes(run_dir)
    evaluator = _ScriptedEvaluator(referee_decision="none")
    monkeypatch.setattr(
        workflow,
        "preflight_evaluator_response_v22",
        lambda run, response: workflow.V22ResponsePreflight(False, ("EXTERNAL_RESPONSE_INVALID",)),
    )

    outcome = await continue_evaluation_v22(run_dir, evaluator)

    assert outcome.engine_paused is True
    assert outcome.pause_reason_codes == (
        "EVALUATION_ENGINE_PAUSED",
        "COMPILER_PREFLIGHT_DISAGREEMENT",
    )
    assert len(evaluator.prompts) == 1
    assert _tree_bytes(run_dir) == before


@pytest.mark.asyncio
async def test_telemetry_is_private_and_sink_failure_cannot_change_result(tmp_path: Path) -> None:
    sink = _CollectingSink(fail=True)
    run_dir = tmp_path / "telemetry"
    evaluator = _ScriptedEvaluator(bad_attempts=1, referee_decision="none")

    outcome = await run_evaluation_v22(
        _case(),
        evaluator,
        run_dir,
        seed_hex="4" * 64,
        telemetry_sink=sink,
    )

    assert outcome.state.terminal_status is EvaluationTerminalStatusV22.COMPLETED
    assert verify_v22_run(run_dir).valid
    assert sink.events
    assert [prompt.attempt for prompt in evaluator.prompts[:2]] == [1, 2]
    assert evaluator.prompts[0].request == evaluator.prompts[1].request
    assert "draft-private-secret" not in repr(evaluator.prompts[1])
    serialized = repr([asdict(event) for event in sink.events])
    for secret in (
        "operators must retain records",
        "private-candidate",
        str(run_dir),
        "draft-private-secret",
        "fixture-provider-secret",
    ):
        assert secret not in serialized.lower()
    assert set(asdict(sink.events[0])) == {
        "protocol_version",
        "compiler_contract_fingerprint",
        "operation",
        "fragment_identity",
        "attempt_number",
        "normalization_codes",
        "clarification_codes",
        "pause_count",
        "resume_count",
    }


def test_raw_constructed_request_is_reverified_before_return(tmp_path: Path) -> None:
    run_dir = tmp_path / "constructed"
    initialize_evaluation_v22(_case(), run_dir, seed_hex="5" * 64)
    original = workflow.load_verified_v22_context

    def corrupt(path: Path) -> Any:
        context = original(path)
        bad_manifest = context.manifest.model_copy(
            update={"compiler_contract_fingerprint": "0" * 64}
        )
        return context.__class__(
            manifest=bad_manifest,
            result=context.result,
            case_envelope_bytes=context.case_envelope_bytes,
            rubric=context.rubric,
            baseline=context.baseline,
            source_context=context.source_context,
        )

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(workflow, "load_verified_v22_context", corrupt)
        with pytest.raises(EvaluationIntegrityError, match="EVALUATOR_V22_COMPILER_CONTRACT"):
            workflow.resume_evaluation_v22(run_dir)


def test_package_exports_complete_v22_workflow_surface() -> None:
    required = {
        "AttorneyDraftEvaluatorV22",
        "EvaluationTelemetryEventV22",
        "EvaluationTelemetrySinkV22",
        "EvaluationDriverOutcomeV22",
        "initialize_evaluation_v22",
        "resume_evaluation_v22",
        "next_evaluator_request_v22",
        "preflight_evaluator_response_v22",
        "guarded_submit_evaluator_response_v22",
        "submit_evaluator_response_v22",
        "run_evaluation_v22",
        "continue_evaluation_v22",
    }

    assert all(hasattr(evaluation, name) for name in required)
