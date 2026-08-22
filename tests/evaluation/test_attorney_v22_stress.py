"""Deterministic public stress gate for recoverable Protocol 2.2 lifecycles."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Literal

import pytest

from regulatory_harvest.evaluation.attorney_v22_artifacts import load_verified_v22_context
from regulatory_harvest.evaluation.attorney_v22_compiler import (
    aggregate_source_audit_fragments_v22,
    aggregate_source_review_fragments_v22,
)
from regulatory_harvest.evaluation.attorney_v22_drafts import (
    CompiledDraftV22,
    EvaluatorDraftPromptV22,
    EvaluatorProvenanceV22,
    NeedsClarificationV22,
    compile_evaluator_draft_v22,
)
from regulatory_harvest.evaluation.attorney_v22_models import (
    AcceptedSourceAuditFragmentV22,
    AcceptedSourceReviewFragmentV22,
    EvaluatorOperationV22,
    EvaluatorRequestV22,
    SourceAuditFragmentV22,
    SourceReviewFragmentV22,
)
from regulatory_harvest.evaluation.attorney_v22_requests import (
    build_source_audit_fragment_request_v22,
    build_source_review_fragment_request_v22,
)
from regulatory_harvest.evaluation.attorney_v22_workflow import (
    continue_evaluation_v22,
    next_evaluator_request_v22,
    submit_evaluator_response_v22,
)
from regulatory_harvest.storage import canonical_json_bytes, sha256_digest

ROOT = Path(__file__).parents[2]
FULL_RUNNER = ROOT / "scripts" / "harvest_skill.py"
PORTABLE_RUNNER = ROOT / "scripts" / "harvest_portable.py"
PORTABLE_EVALUATOR = ROOT / "scripts" / "attorney_eval_portable.py"
PUBLIC_CASE = ROOT / "tests" / "fixtures" / "attorney-eval-v22" / "stable" / "case.json"
PROVENANCE = EvaluatorProvenanceV22(
    provider_name="local-scripted-fixture",
    model_name="no-provider",
    judge_isolation="scripted_fixture",
)
PROVENANCE_JSON = {
    "provider_name": PROVENANCE.provider_name,
    "model_name": PROVENANCE.model_name,
    "judge_isolation": PROVENANCE.judge_isolation,
}


@dataclass(frozen=True)
class StressCase:
    proposals: int
    concerns: int
    referee: Literal["reviewer", "auditor", "unresolved", "mixed"]
    outcome: Literal["pass", "fail", "inconclusive"]
    recovery: Literal["none", "clarify", "pause", "interrupt"]
    normalized: bool
    weak: bool


@dataclass(frozen=True)
class LifecycleResult:
    transcript: tuple[tuple[int, str, str], ...]
    tree: dict[str, bytes]
    terminal_status: str
    absolute_disposition: str
    strict_submission_diagnostics: str
    proposal_count: int
    concern_count: int


def _portable_module() -> ModuleType:
    name = "attorney_eval_portable_v22_stress"
    existing = sys.modules.get(name)
    if existing is not None:
        return existing
    spec = importlib.util.spec_from_file_location(name, PORTABLE_EVALUATOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _tree(run: Path) -> dict[str, bytes]:
    return {
        path.relative_to(run).as_posix(): path.read_bytes()
        for path in sorted(run.rglob("*"))
        if path.is_file() and not path.is_symlink()
    }


def _command(runner: Path, *args: str, timeout: int = 300) -> subprocess.CompletedProcess[str]:
    command = [sys.executable]
    if runner == PORTABLE_RUNNER:
        command.extend(("-I", "-S"))
    return subprocess.run(
        [*command, str(runner), *args],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _stress_case(seed: int) -> StressCase:
    boundary_proposals = (0, 1, 5, 6, 52, 128, 129)
    boundary_concerns = (1, 5, 6, 21, 129)
    if seed < len(boundary_proposals):
        proposals = boundary_proposals[seed]
        concerns = 0
    elif seed < len(boundary_proposals) + len(boundary_concerns):
        concerns = boundary_concerns[seed - len(boundary_proposals)]
        proposals = concerns
    else:
        proposals = (1, 2, 5, 6)[seed % 4]
        concerns = min(proposals, (0, 1, 2)[(seed // 4) % 3])
    referee = ("reviewer", "auditor", "unresolved", "mixed")[seed % 4]
    outcome = ("pass", "fail", "inconclusive")[seed % 3]
    recovery: Literal["none", "clarify", "pause", "interrupt"] = "none"
    if seed in {13, 41, 73}:
        recovery = "clarify"
    elif seed in {14, 42, 74}:
        recovery = "pause"
    elif seed in {15, 43, 75}:
        recovery = "interrupt"
    return StressCase(
        proposals=proposals,
        concerns=concerns,
        referee=referee,
        outcome=outcome,
        recovery=recovery,
        normalized=seed % 5 == 0,
        weak=seed % 7 == 0,
    )


def _source(request: EvaluatorRequestV22) -> dict[str, object]:
    source_record = request.payload["source_record"]
    assert isinstance(source_record, dict)
    sources = source_record["sources"]
    assert isinstance(sources, list) and sources and isinstance(sources[0], dict)
    return sources[0]


def _proposal(
    request: EvaluatorRequestV22,
    ordinal: int,
    *,
    normalized: bool,
    weak: bool,
) -> dict[str, object]:
    source = _source(request)
    source_id = source["source_id"]
    quote = source["normalized_text"]
    assert isinstance(source_id, str) and isinstance(quote, str)
    anchor = "What fictional duties apply to a covered operator?"
    assert quote.count(anchor) == 1
    quote = anchor
    statement = f"Synthetic duty {ordinal}: covered operators must comply."
    if normalized:
        statement = f"  {statement}  "
        quote = "  ".join(quote.split(" "))
    return {
        "statement": statement,
        "kind": "OBLIGATION" if normalized else "obligation",
        "importance": "CRITICAL" if normalized else "critical",
        "passages": [{"source_id": source_id, "quote": quote}],
        "dependency": None,
        "confidence": "CLEAR" if normalized else "clear",
        "rationale": "Maybe." if weak else "The synthetic source states this duty.",
    }


def _draft(request: EvaluatorRequestV22, case: StressCase) -> dict[str, object]:
    payload = request.payload
    if request.operation is EvaluatorOperationV22.SOURCE_REVIEW_FRAGMENT:
        ordinal = payload.get("fragment_ordinal")
        assert isinstance(ordinal, int)
        start = (ordinal - 1) * 5
        count = min(5, max(0, case.proposals - start))
        return {
            "proposals": [
                _proposal(
                    request,
                    start + index,
                    normalized=case.normalized,
                    weak=case.weak,
                )
                for index in range(1, count + 1)
            ],
            "review_complete": start + count >= case.proposals,
        }
    if request.operation is EvaluatorOperationV22.SOURCE_AUDIT_FRAGMENT:
        ordinal = payload.get("fragment_ordinal")
        assert isinstance(ordinal, int)
        start = (ordinal - 1) * 5
        count = min(5, max(0, case.concerns - start))
        indexed = payload["indexed_proposals"]
        assert isinstance(indexed, list)
        concerns: list[dict[str, object]] = []
        for index in range(1, count + 1):
            target = start + index
            item = indexed[target - 1]
            assert isinstance(item, dict)
            semantic = item["proposal"]
            assert isinstance(semantic, dict)
            correction = json.loads(json.dumps(semantic))
            correction["statement"] = (
                f"Corrected synthetic duty {target}: covered operators must comply."
            )
            concerns.append(
                {
                    "target_proposal_ordinal": target,
                    "concern_type": "incorrect_statement",
                    "passages": semantic["passages"],
                    "explanation": "The synthetic formulation is disputed.",
                    "correction": correction,
                }
            )
        return {
            "concerns": concerns,
            "audit_complete": start + count >= case.concerns,
        }
    if request.operation is EvaluatorOperationV22.SOURCE_REFEREE_FRAGMENT:
        decision = case.referee
        if decision == "mixed":
            dispute_id = request.safe_metadata.get("dispute_id")
            assert isinstance(dispute_id, str)
            ordinal = int(dispute_id.removeprefix("D"))
            decision = ("reviewer", "auditor", "unresolved")[(ordinal - 1) % 3]
        mapped = {
            "reviewer": "accept_reviewer",
            "auditor": "accept_auditor",
            "unresolved": "unresolved",
        }[decision]
        return {
            "decision": mapped,
            "unresolved_reason": "SOURCE_AMBIGUITY" if mapped == "unresolved" else None,
            "evidence_ordinals": [1],
            "rationale": "The synthetic evidence supports this substantive disposition.",
        }
    report_text = payload["report_text"]
    assert isinstance(report_text, str)
    disposition = {
        "pass": "met",
        "fail": "not_met",
        "inconclusive": "uncertain",
    }[case.outcome]
    if request.operation is EvaluatorOperationV22.ORDINARY_GRADE_FRAGMENT:
        requirements = payload["requirements"]
        assert isinstance(requirements, list)
        return {
            "requirement_grades": [
                {
                    "requirement_ordinal": index,
                    "disposition": disposition,
                    "report_passages": [report_text] if disposition == "met" else [],
                    "rationale": "The synthetic report is graded as written.",
                    "omission": "The duty is absent." if disposition == "not_met" else None,
                }
                for index, _ in enumerate(requirements, 1)
            ],
            "rationale": "Every issued synthetic requirement was graded.",
        }
    assert request.operation is EvaluatorOperationV22.CONTESTED_GRADE_FRAGMENT
    reviewer = disposition
    auditor = disposition
    if case.outcome == "inconclusive":
        reviewer, auditor = "met", "not_met"

    def alternative(value: str) -> dict[str, object]:
        return {
            "disposition": value,
            "report_passages": [report_text] if value == "met" else [],
            "rationale": "The issued synthetic alternative was graded.",
        }

    return {
        "reviewer_alternative_grade": alternative(reviewer),
        "auditor_alternative_grade": alternative(auditor),
        "ambiguity_disposition": "acknowledged",
        "rationale": "Both issued synthetic alternatives were evaluated.",
    }


def _compile_exact(
    portable: ModuleType,
    request: EvaluatorRequestV22,
    draft: dict[str, object],
) -> CompiledDraftV22:
    full = compile_evaluator_draft_v22(request, draft, PROVENANCE)
    assert isinstance(full, CompiledDraftV22), full
    mirrored = portable._compile_evaluator_draft_v22_for_test(
        canonical_json_bytes(request.model_dump(mode="json")),
        canonical_json_bytes(draft),
        PROVENANCE_JSON,
    )
    assert mirrored == canonical_json_bytes(full.response.model_dump(mode="json"))
    return full


def _run_large_boundary_contract(probe: Path, case: StressCase) -> tuple[int, int, int]:
    """Exercise large exact fragment histories without tripling storage replay cost."""
    envelope = load_verified_v22_context(probe).load_case_envelope()
    portable = _portable_module()
    review_fragments: list[AcceptedSourceReviewFragmentV22] = []
    proposal_count = normalization_count = 0
    while proposal_count < case.proposals or not review_fragments:
        ordinal = len(review_fragments) + 1
        request = build_source_review_fragment_request_v22(
            envelope,
            tuple(review_fragments),
            fragment_ordinal=ordinal,
        )
        draft = _draft(request, case)
        compiled = _compile_exact(portable, request, draft)
        payload = SourceReviewFragmentV22.model_validate(compiled.response.payload)
        response_bytes = canonical_json_bytes(compiled.response.model_dump(mode="json"))
        review_fragments.append(
            AcceptedSourceReviewFragmentV22(
                fragment_ordinal=ordinal,
                request_fingerprint=request.request_fingerprint,
                response_fingerprint=sha256_digest(response_bytes),
                payload=payload,
            )
        )
        proposal_count += len(payload.proposals)
        normalization_count += bool(compiled.normalization_codes)
        if payload.review_complete:
            break
    review = aggregate_source_review_fragments_v22(tuple(review_fragments))
    assert len(review.proposals) == case.proposals

    audit_fragments: list[AcceptedSourceAuditFragmentV22] = []
    concern_count = 0
    while concern_count < case.concerns or not audit_fragments:
        ordinal = len(audit_fragments) + 1
        request = build_source_audit_fragment_request_v22(
            envelope,
            review,
            tuple(audit_fragments),
            fragment_ordinal=ordinal,
        )
        draft = _draft(request, case)
        compiled = _compile_exact(portable, request, draft)
        payload = SourceAuditFragmentV22.validate_for_indexed_proposals(
            compiled.response.payload, review.proposals
        )
        response_bytes = canonical_json_bytes(compiled.response.model_dump(mode="json"))
        audit_fragments.append(
            AcceptedSourceAuditFragmentV22(
                fragment_ordinal=ordinal,
                request_fingerprint=request.request_fingerprint,
                response_fingerprint=sha256_digest(response_bytes),
                payload=payload,
            )
        )
        concern_count += len(payload.concerns)
        normalization_count += bool(compiled.normalization_codes)
        if payload.audit_complete:
            break
    audit = aggregate_source_audit_fragments_v22(review, tuple(audit_fragments))
    assert len(audit.concerns) == case.concerns
    assert len({item.response_fingerprint for item in review.fragments}) == len(review.fragments)
    assert len({item.response_fingerprint for item in audit.fragments}) == len(audit.fragments)
    return proposal_count, concern_count, normalization_count


def _script_from_probe(
    probe: Path,
    script: Path,
    case: StressCase,
    *,
    clarify_first: bool = False,
) -> tuple[int, int, int]:
    portable = _portable_module()
    entries: list[dict[str, object]] = []
    proposals = concerns = normalized = 0
    first = True
    while (request := next_evaluator_request_v22(probe)) is not None:
        draft = _draft(request, case)
        compiled = _compile_exact(portable, request, draft)
        if request.operation is EvaluatorOperationV22.SOURCE_REVIEW_FRAGMENT:
            proposals += len(draft["proposals"])
        elif request.operation is EvaluatorOperationV22.SOURCE_AUDIT_FRAGMENT:
            concerns += len(draft["concerns"])
        normalized += bool(compiled.normalization_codes)
        if first and clarify_first:
            invalid = {"malformed": "synthetic-invalid-draft"}
            refusal = compile_evaluator_draft_v22(request, invalid, PROVENANCE)
            assert isinstance(refusal, NeedsClarificationV22)
            codes = [code.value for code in refusal.reason_codes]
            entries.append(
                {
                    "draft": invalid,
                    "expect": {
                        "attempt": 1,
                        "clarification_codes": [],
                        "request_fingerprint": request.request_fingerprint,
                    },
                    "operation": request.operation.value,
                }
            )
            attempt = 2
        else:
            codes = []
            attempt = 1
        entries.append(
            {
                "draft": draft,
                "expect": {
                    "attempt": attempt,
                    "clarification_codes": codes,
                    "request_fingerprint": request.request_fingerprint,
                },
                "operation": request.operation.value,
            }
        )
        submit_evaluator_response_v22(probe, compiled.response)
        first = False
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_bytes(
        canonical_json_bytes({"fixture_type": "local-scripted-drafts-v2.2", "responses": entries})
    )
    return proposals, concerns, normalized


def _invalid_script(probe: Path, script: Path) -> None:
    request = next_evaluator_request_v22(probe)
    assert request is not None
    invalid = {"malformed": "synthetic-invalid-draft"}
    refusal = compile_evaluator_draft_v22(request, invalid, PROVENANCE)
    assert isinstance(refusal, NeedsClarificationV22)
    codes = [code.value for code in refusal.reason_codes]
    entries = [
        {
            "draft": invalid,
            "expect": {
                "attempt": attempt,
                "clarification_codes": [] if attempt == 1 else codes,
                "request_fingerprint": request.request_fingerprint,
            },
            "operation": request.operation.value,
        }
        for attempt in (1, 2)
    ]
    script.write_bytes(
        canonical_json_bytes({"fixture_type": "local-scripted-drafts-v2.2", "responses": entries})
    )


def _initialize_probe(seed: int, probe: Path) -> None:
    initialized = _command(
        FULL_RUNNER,
        "eval-init",
        "--protocol",
        "2.2",
        "--case",
        str(PUBLIC_CASE),
        "--run",
        str(probe),
        "--seed-hex",
        f"{seed:064x}",
    )
    assert initialized.returncode == 0, initialized.stderr


def _run_lifecycle(
    runner: Path,
    seed: int,
    run: Path,
    case: StressCase,
    script: Path,
    counts: tuple[int, int],
    *,
    pause_script: Path | None,
    interrupt_response: Path | None,
) -> LifecycleResult:
    transcript: list[tuple[int, str, str]] = []

    def command(*args: str) -> subprocess.CompletedProcess[str]:
        completed = _command(runner, *args)
        transcript.append((completed.returncode, completed.stdout, completed.stderr))
        return completed

    initialized = command(
        "eval-init",
        "--protocol",
        "2.2",
        "--case",
        str(PUBLIC_CASE),
        "--run",
        str(run),
        "--seed-hex",
        f"{seed:064x}",
    )
    assert initialized.returncode == 0, initialized.stderr
    before = _tree(run)
    if interrupt_response is not None:
        pending = command("eval-next", "--run", str(run))
        assert pending.returncode == 0, pending.stderr
        accepted = command(
            "eval-submit-safe",
            "--run",
            str(run),
            "--response",
            str(interrupt_response),
        )
        assert accepted.returncode == 0, accepted.stderr or accepted.stdout
        interrupted_tree = _tree(run)
        assert interrupted_tree != before
        status = command("eval-status", "--run", str(run))
        verified = command("eval-verify", "--run", str(run))
        assert status.returncode == verified.returncode == 0
        assert _tree(run) == interrupted_tree
    if pause_script is not None:
        paused = command(
            "eval-resume", "--run", str(run), "--scripted-responses", str(pause_script)
        )
        assert paused.returncode == 6, paused.stderr or paused.stdout
        assert _tree(run) == before
        pending = command("eval-next", "--run", str(run))
        assert pending.returncode == 0, pending.stderr
        verified = command("eval-verify", "--run", str(run))
        assert verified.returncode == 0, verified.stderr
        assert _tree(run) == before
    resumed = command("eval-resume", "--run", str(run), "--scripted-responses", str(script))
    assert resumed.returncode in {0, 3, 4}, resumed.stderr or resumed.stdout
    terminal_tree = _tree(run)
    status = command("eval-status", "--run", str(run))
    verified = command("eval-verify", "--run", str(run))
    assert status.returncode == verified.returncode == resumed.returncode
    assert verified.returncode in {0, 3, 4}
    assert _tree(run) == terminal_tree
    result = json.loads((run / "result.json").read_bytes())
    reports = result["reports"]
    assert isinstance(reports, list) and reports and isinstance(reports[0], dict)
    sensitivity = reports[0]["sensitivity"]
    assert isinstance(sensitivity, dict)
    rendered = "".join(stdout + stderr for _, stdout, stderr in transcript)
    return LifecycleResult(
        transcript=tuple(transcript),
        tree=terminal_tree,
        terminal_status=result["terminal_status"],
        absolute_disposition=sensitivity["absolute_disposition"],
        strict_submission_diagnostics=rendered,
        proposal_count=counts[0],
        concern_count=counts[1],
    )


@pytest.mark.parametrize("seed", range(100))
def test_protocol_22_internal_drafts_never_end_mechanically(seed: int, tmp_path: Path) -> None:
    """One hundred seeded public lifecycles remain exact, substantive, and resumable."""
    case = _stress_case(seed)
    probe = tmp_path / "probe"
    _initialize_probe(seed, probe)
    if case.proposals >= 52 or case.concerns >= 21:
        proposals, concerns, normalized = _run_large_boundary_contract(probe, case)
        assert (proposals, concerns) == (case.proposals, case.concerns)
        if case.normalized and case.proposals:
            assert normalized > 0
        return
    script = tmp_path / "responses" / "valid.json"
    interrupt_response: Path | None = None
    if case.recovery == "interrupt":
        request = next_evaluator_request_v22(probe)
        assert request is not None
        first_draft = _draft(request, case)
        first_compiled = _compile_exact(_portable_module(), request, first_draft)
        interrupt_response = tmp_path / "responses" / "interrupted-response.json"
        interrupt_response.parent.mkdir(parents=True, exist_ok=True)
        interrupt_response.write_bytes(
            canonical_json_bytes(first_compiled.response.model_dump(mode="json"))
        )
        submit_evaluator_response_v22(probe, first_compiled.response)
        remaining = _script_from_probe(probe, script, case)
        proposals = len(first_draft.get("proposals", [])) + remaining[0]
        concerns = len(first_draft.get("concerns", [])) + remaining[1]
        normalized = bool(first_compiled.normalization_codes) + remaining[2]
    else:
        proposals, concerns, normalized = _script_from_probe(
            probe,
            script,
            case,
            clarify_first=case.recovery == "clarify",
        )
    assert (proposals, concerns) == (case.proposals, case.concerns)
    if case.normalized and case.proposals:
        assert normalized > 0
    pause_script: Path | None = None
    if case.recovery == "pause":
        pause_probe = tmp_path / "pause-probe"
        _initialize_probe(seed, pause_probe)
        pause_script = tmp_path / "responses" / "pause.json"
        _invalid_script(pause_probe, pause_script)

    full = _run_lifecycle(
        FULL_RUNNER,
        seed,
        tmp_path / "full",
        case,
        script,
        (proposals, concerns),
        pause_script=pause_script,
        interrupt_response=interrupt_response,
    )
    portable = _run_lifecycle(
        PORTABLE_RUNNER,
        seed,
        tmp_path / "portable",
        case,
        script,
        (proposals, concerns),
        pause_script=pause_script,
        interrupt_response=interrupt_response,
    )

    assert full.transcript == portable.transcript
    assert full.tree == portable.tree
    assert full.proposal_count == case.proposals
    assert full.concern_count == case.concerns
    assert "MECHANICAL_RESPONSE_INVALID" not in full.strict_submission_diagnostics
    assert full.terminal_status != "INCONCLUSIVE_MECHANICAL"
    if case.recovery != "none":
        control_probe = tmp_path / "control-probe"
        _initialize_probe(seed, control_probe)
        control_script = tmp_path / "responses" / "control.json"
        control_counts = _script_from_probe(control_probe, control_script, case)
        assert control_counts[:2] == (case.proposals, case.concerns)
        control = _run_lifecycle(
            FULL_RUNNER,
            seed,
            tmp_path / "control",
            case,
            control_script,
            control_counts[:2],
            pause_script=None,
            interrupt_response=None,
        )
        assert (full.transcript[-2:], full.tree) == (
            control.transcript[-2:],
            control.tree,
        )
    if case.proposals == 0:
        assert (full.terminal_status, full.absolute_disposition) == (
            "INCONCLUSIVE",
            "INCONCLUSIVE",
        )
    elif case.outcome == "pass":
        assert (full.terminal_status, full.absolute_disposition) == ("COMPLETED", "PASS")
    elif case.outcome == "fail":
        assert (full.terminal_status, full.absolute_disposition) == ("COMPLETED", "FAIL")
    else:
        assert (full.terminal_status, full.absolute_disposition) == (
            "INCONCLUSIVE",
            "INCONCLUSIVE",
        )


def test_protocol_22_injected_crash_resumes_to_uninterrupted_control(
    tmp_path: Path,
) -> None:
    """A provider crash after accepted work preserves it and resumes exactly."""
    case = _stress_case(7)

    class CrashableEvaluator:
        def __init__(self, crash_at: int | None) -> None:
            self.crash_at = crash_at
            self.calls = 0

        async def evaluate_draft(self, prompt: EvaluatorDraftPromptV22) -> object:
            self.calls += 1
            if self.calls == self.crash_at:
                raise RuntimeError("synthetic provider crash")
            return _draft(prompt.request, case)

    run = tmp_path / "crashed"
    _initialize_probe(7, run)
    initial_tree = _tree(run)
    with pytest.raises(RuntimeError, match="synthetic provider crash"):
        asyncio.run(continue_evaluation_v22(run, CrashableEvaluator(crash_at=2)))
    crashed_tree = _tree(run)
    assert crashed_tree != initial_tree
    pending = next_evaluator_request_v22(run)
    assert pending is not None
    assert pending.operation is EvaluatorOperationV22.SOURCE_AUDIT_FRAGMENT

    resumed = asyncio.run(continue_evaluation_v22(run, CrashableEvaluator(crash_at=None)))
    assert not resumed.engine_paused
    assert resumed.result is not None

    control = tmp_path / "control"
    _initialize_probe(7, control)
    uninterrupted = asyncio.run(continue_evaluation_v22(control, CrashableEvaluator(crash_at=None)))
    assert not uninterrupted.engine_paused
    assert _tree(run) == _tree(control)


def test_protocol_22_stress_matrix_covers_every_required_boundary() -> None:
    """The deterministic seed schedule cannot silently lose a required stress class."""
    cases = [_stress_case(seed) for seed in range(100)]
    assert {case.proposals for case in cases}.issuperset({0, 1, 5, 6, 52, 128, 129})
    assert {case.concerns for case in cases}.issuperset({0, 1, 5, 6, 21, 129})
    assert {case.outcome for case in cases} == {"pass", "fail", "inconclusive"}
    assert {case.referee for case in cases} == {"reviewer", "auditor", "unresolved", "mixed"}
    assert {case.recovery for case in cases} == {"none", "clarify", "pause", "interrupt"}
    assert any(case.normalized for case in cases)
    assert any(case.weak for case in cases)
