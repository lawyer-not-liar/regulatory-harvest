"""Seeded public lifecycle and hard-boundary gates for evaluation-baseline-v1."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import random
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import fields, is_dataclass
from enum import Enum
from pathlib import Path
from types import ModuleType
from typing import cast

import pytest
from test_attorney_baseline_artifacts import _baseline_input
from test_attorney_baseline_compiler import (
    _audit,
    _importance,
    _referees,
    _review,
)
from test_attorney_baseline_compiler import (
    _proposal as _compiler_proposal,
)

import regulatory_harvest.evaluation.attorney_baseline_artifacts as baseline_artifacts
from regulatory_harvest.evaluation.attorney_baseline_artifacts import (
    load_verified_baseline_run,
    verify_baseline_run,
)
from regulatory_harvest.evaluation.attorney_baseline_compiler import (
    build_baseline_disputes_v1,
    compile_canonical_baseline_v1,
)
from regulatory_harvest.evaluation.attorney_baseline_models import (
    AcceptedBaselineReviewFragmentV1,
    BaselineCorrectionRecordV1,
    BaselineRefereeDecisionV1,
    BaselineReviewFragmentV1,
)
from regulatory_harvest.evaluation.attorney_baseline_projection import (
    project_gradeable_baseline_v1,
)
from regulatory_harvest.evaluation.attorney_baseline_requests import (
    build_baseline_source_review_request_v1,
)
from regulatory_harvest.evaluation.attorney_baseline_workflow import (
    baseline_status_payload_v1,
    guarded_submit_baseline_response_v1,
    initialize_baseline_v1,
    next_baseline_request_v1,
)
from regulatory_harvest.evaluation.attorney_models import (
    AdmissionCheck,
    CaseAdmissionJudgment,
    JudgeIsolation,
    JudgeOperation,
    JudgeResponse,
    QualificationCase,
)
from regulatory_harvest.evaluation.attorney_qualification import (
    initialize_case_qualification,
    next_qualification_request,
    submit_case_qualification,
)
from regulatory_harvest.storage import canonical_json_bytes, sha256_digest

ROOT = Path(__file__).resolve().parents[2]
PORTABLE_RUNNER = ROOT / "scripts" / "attorney_eval_portable.py"
BASELINE_FIXTURE = ROOT / "tests" / "fixtures" / "attorney-eval-baseline"

_REPORT_BOUND_KEYS = {
    "anonymous_label",
    "candidate",
    "candidate_id",
    "case_fingerprint",
    "generation",
    "generation_metadata",
    "grader",
    "grader_responses",
    "label",
    "report",
    "report_hash",
    "report_text",
    "run_seed",
}
_IMPORTANCE = (
    (
        "critical",
        ["legal_bottom_line"],
        "Omission could change the fictional legal bottom line.",
    ),
    (
        "material",
        ["attorney_briefing"],
        "The rule is necessary for a competent fictional attorney briefing.",
    ),
    (
        "supporting",
        ["implementation_detail"],
        "The rule is useful fictional implementation detail that does not change the answer.",
    ),
)
_PROPOSAL_FACTS = (
    (
        "A covered operator must register each filing by 10 June.",
        "must register each filing by 10 June",
        "obligation",
    ),
    (
        "The registration duty does not apply during a declared exercise.",
        "does not apply during a declared exercise",
        "exception",
    ),
    (
        "The registry bureau may inspect the filing.",
        "may inspect the filing",
        "permission",
    ),
    (
        "A covered operator may publish an explanatory notice.",
        "may publish an explanatory notice",
        "permission",
    ),
    (
        "The filing must contain the operator's legal name.",
        "must contain the operator's legal name",
        "obligation",
    ),
)


def _load_portable() -> ModuleType:
    name = "attorney_eval_portable_task10_stress"
    existing = sys.modules.get(name)
    if existing is not None:
        return cast(ModuleType, existing)
    spec = importlib.util.spec_from_file_location(name, PORTABLE_RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _wire(value: object) -> object:
    if hasattr(value, "model_dump"):
        return _wire(value.model_dump(mode="json", warnings="error"))  # type: ignore[union-attr]
    if is_dataclass(value):
        return {
            field.name: _wire(getattr(value, field.name))
            for field in fields(value)
        }
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _wire(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_wire(item) for item in value]
    return value


def _tree_bytes(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _contains_report_key(value: object) -> bool:
    if isinstance(value, dict):
        if _REPORT_BOUND_KEYS.intersection(map(str, value)):
            return True
        return any(_contains_report_key(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_report_key(item) for item in value)
    return False


def _control_input(tmp_path: Path, fact_mode: int) -> Path:
    control_root = tmp_path / "control"
    control_root.mkdir()
    qualification = control_root / "qualification"
    case = QualificationCase.model_validate_json(
        (BASELINE_FIXTURE / "qualification" / "qualification-case.json").read_bytes()
    )
    initialize_case_qualification(case, qualification, nonce_hex="1" * 64)
    request = next_qualification_request(qualification)
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
        qualification,
        JudgeResponse(
            operation=JudgeOperation.ADMIT_CASE,
            request_fingerprint=request.request_fingerprint,
            provider_name="fictional-provider",
            model_name="fictional-model",
            judge_isolation=JudgeIsolation.FRESH_CONTEXT,
            response_id="fictional-task-10-qualification-response",
            usage={"input_tokens": 101, "output_tokens": 202},
            payload=judgment.model_dump(mode="json"),
        ),
    )
    client_facts_path: str | None
    if fact_mode == 0:
        client_facts_path = None
    else:
        client_facts_path = "client-facts.txt"
        facts = b"" if fact_mode == 1 else b"Fictional operator fact.\r\n"
        (control_root / client_facts_path).write_bytes(facts)
    control = control_root / "baseline-control.json"
    control.write_bytes(
        canonical_json_bytes(
            {
                "client_facts_path": client_facts_path,
                "qualification_capsule_path": "qualification",
                "schema_version": "1.0",
            }
        )
    )
    return control


def _proposal(index: int, importance_index: int) -> dict[str, object]:
    statement, quote, kind = _PROPOSAL_FACTS[index]
    importance, basis, rationale = _IMPORTANCE[importance_index % len(_IMPORTANCE)]
    return {
        "statement": statement,
        "kind": kind,
        "importance": importance,
        "importance_basis": basis,
        "importance_rationale": rationale,
        "passages": [{"source_id": "fictional-registry-rule", "quote": quote}],
        "dependency": None,
        "confidence": "clear",
        "substantive_rationale": "The fictional source states this source-bound rule.",
    }


def _importance_finding(
    proposal_ref: str,
    importance_index: int,
    *,
    disposition: str,
) -> dict[str, object]:
    importance, basis, rationale = _IMPORTANCE[importance_index % len(_IMPORTANCE)]
    return {
        "proposal_ref": proposal_ref,
        "reviewed_importance": importance,
        "reviewed_importance_basis": basis,
        "importance_rationale": rationale,
        "disposition": disposition,
    }


def _semantic_correction(proposal: dict[str, object]) -> dict[str, object]:
    changed = copy.deepcopy(proposal)
    changed["statement"] = f"{proposal['statement']} The auditor preserves the exact scope."
    changed["substantive_rationale"] = (
        "The auditor records a distinct fictional source-bound interpretation."
    )
    return changed


def _referee_payload(request: dict[str, object], decision: str) -> dict[str, object]:
    dispute = cast(dict[str, object], cast(dict[str, object], request["payload"])["dispute"])
    reviewer = cast(dict[str, object] | None, dispute["reviewer_proposal"])
    concern = cast(dict[str, object] | None, dispute["auditor_concern"])
    finding = cast(dict[str, object] | None, dispute["importance_finding"])
    selected = reviewer
    if decision == "accept_auditor" and concern is not None:
        selected = cast(dict[str, object] | None, concern["correction"])
    if selected is None:
        selected = reviewer
    assert selected is not None
    if decision == "accept_auditor" and finding is not None:
        importance = finding["reviewed_importance"]
        basis = finding["reviewed_importance_basis"]
        rationale = finding["importance_rationale"]
    else:
        importance = selected["importance"]
        basis = selected["importance_basis"]
        rationale = selected["importance_rationale"]
    return {
        "dispute_id": dispute["dispute_id"],
        "decision": decision,
        "passages": selected["passages"],
        "importance": importance,
        "importance_basis": basis,
        "importance_rationale": rationale,
        "substantive_rationale": (
            "The fictional source-bound alternatives support this bounded referee decision."
        ),
    }


def _submit_pair(
    portable: ModuleType,
    full_run: Path,
    portable_run: Path,
    payload: dict[str, object],
    transcript: list[object],
) -> None:
    full = guarded_submit_baseline_response_v1(
        full_run,
        payload,
        provider_name="fictional-provider",
        model_name="fictional-model",
        judge_isolation="scripted_fixture",
    )
    mirrored = portable.guarded_submit_baseline_response_v1(
        portable_run,
        payload,
        provider_name="fictional-provider",
        model_name="fictional-model",
        judge_isolation="scripted_fixture",
    )
    mirrored_wire = cast(dict[str, object], _wire(mirrored))
    mirrored_wire = {
        "accepted": mirrored_wire["accepted"],
        "issue_codes": mirrored_wire["diagnostics"],
        "state": mirrored_wire["state"],
    }
    assert _wire(full) == mirrored_wire
    transcript.append(_wire(full))
    assert _tree_bytes(full_run) == _tree_bytes(portable_run)


def _write_correction(path: Path, run: Path, seed: int) -> None:
    context = load_verified_baseline_run(run)
    replacement = context.baseline.requirements[0].model_dump(mode="json")
    replacement["substantive_rationale"] = (
        f"Attorney-approved fictional source clarification for seed {seed}."
    )
    payload: dict[str, object] = {
        "schema_version": "baseline-correction-v1",
        "prior_baseline_root": context.manifest.root_hash,
        "prior_baseline_fingerprint": context.baseline.baseline_fingerprint,
        "correction_id": f"CORR-{seed + 1:04d}",
        "actions": [
            {
                "action": "replace_requirement",
                "requirement_id": replacement["requirement_id"],
                "relationship_id": None,
                "requirement": replacement,
                "relationship": None,
            }
        ],
        "reason": "The retained fictional source supports this exact correction.",
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


@pytest.mark.parametrize(
    ("semantic_decision", "importance_decision"),
    (
        ("unresolved", "accept_reviewer"),
        ("unresolved", "accept_auditor"),
        ("unresolved", "unresolved"),
        ("accept_reviewer", "unresolved"),
        ("accept_auditor", "unresolved"),
    ),
)
def test_combined_dispute_order_and_outcomes_compile_identically(
    semantic_decision: str,
    importance_decision: str,
) -> None:
    """Combined reconciliation must match the typed compiler in either dispute order."""
    portable = _load_portable()
    baseline_input = _baseline_input()
    reviewer = _compiler_proposal(
        "A covered operator must file a notice.", "must file a notice"
    )
    auditor = _compiler_proposal(
        "A covered operator must file an annual notice.", "must file a notice"
    )
    review = _review(baseline_input, (reviewer,))
    audit = _audit(
        baseline_input,
        review,
        concerns=(
            {
                "target_proposal_ref": "PR-0001",
                "concern_type": "incorrect_statement",
                "passages": ({"source_id": "rule-1", "quote": "must file a notice"},),
                "explanation": "The fictional proposal may omit an annual qualification.",
                "correction": auditor,
            },
        ),
        importance_findings=(
            _importance(
                "PR-0001",
                importance="material",
                basis=("attorney_briefing",),
                rationale="The rule is necessary for a competent fictional briefing.",
                disposition="correct",
            ),
        ),
    )
    disputes = build_baseline_disputes_v1(baseline_input, review, audit)
    assert len(disputes) == 2

    def decision_for(dispute: object) -> BaselineRefereeDecisionV1:
        finding = dispute.importance_finding
        decision = importance_decision if finding is not None else semantic_decision
        if finding is not None and decision == "accept_auditor":
            importance = "material"
            basis = ("attorney_briefing",)
        else:
            importance = "critical"
            basis = ("legal_bottom_line",)
        return BaselineRefereeDecisionV1(
            dispute_id=dispute.dispute_id,
            decision=decision,
            passages=({"source_id": "rule-1", "quote": "must file a notice"},),
            importance=importance,
            importance_basis=basis,
            importance_rationale="The fictional consequence fixes the selected importance.",
            substantive_rationale="The fictional evidence supports this bounded outcome.",
        )

    referees = _referees(baseline_input, disputes, decision_for)
    full = compile_canonical_baseline_v1(baseline_input, review, audit, referees)
    mirrored = portable._baseline_compile(
        baseline_input.model_dump(mode="json"),
        review.model_dump(mode="json"),
        audit.model_dump(mode="json"),
        referees.model_dump(mode="json"),
    )
    assert full.model_dump(mode="json") == mirrored


@pytest.mark.parametrize(
    "mutation",
    ("wrong_dispute", "third_importance", "missing_correction"),
)
def test_combined_dispute_malformed_choices_fail_closed(mutation: str) -> None:
    """Portable combined-dispute support must not relax exact binding or alternatives."""
    portable = _load_portable()
    dispute = {
        "reviewer_proposal": _boundary_proposal(0),
        "auditor_concern": {
            "correction": None if mutation == "missing_correction" else _boundary_proposal(1)
        },
        "importance_finding": None
        if mutation == "missing_correction"
        else {
            "reviewed_importance": "material",
            "reviewed_importance_basis": ["attorney_briefing"],
        },
    }
    decision = {
        "decision": "accept_auditor",
        "importance": "supporting" if mutation == "third_importance" else "material",
        "importance_basis": (
            ["implementation_detail"]
            if mutation == "third_importance"
            else ["attorney_briefing"]
        ),
    }
    if mutation == "wrong_dispute":
        decision["decision"] = "accept_reviewer"
        decision["importance"] = "material"
    elif mutation == "third_importance":
        decision["decision"] = "unresolved"
    with pytest.raises(Exception, match="BASELINE_SEMANTIC_REPLAY_INVALID"):
        portable._baseline_validate_referee_choice(dispute, decision)


@pytest.mark.parametrize("seed", range(100))
def test_seeded_public_lifecycle_is_deterministic_report_blind_and_portable(
    seed: int,
    tmp_path: Path,
) -> None:
    """Wrong dispatch, identity, dispute, correction, or mirror code breaks a seeded row."""
    portable = _load_portable()
    rng = random.Random(seed)
    control = _control_input(tmp_path, seed % 3)
    full_run = tmp_path / "full"
    portable_run = tmp_path / "portable"
    nonce = hashlib.sha256(f"public-baseline-seed:{seed}".encode()).hexdigest()
    transcript: list[object] = []

    full_state = initialize_baseline_v1(control, full_run, nonce_hex=nonce)
    portable_state = portable.initialize_baseline_v1(control, portable_run, nonce_hex=nonce)
    assert _wire(full_state) == _wire(portable_state)
    transcript.append(_wire(full_state))
    assert _tree_bytes(full_run) == _tree_bytes(portable_run)

    invalid = {
        "report_text": f"forbidden-report-{seed}",
        "provider_secret": f"sk-public-fixture-{seed:04d}",
    }
    before = _tree_bytes(full_run)
    _submit_pair(portable, full_run, portable_run, invalid, transcript)
    assert _tree_bytes(full_run) == before
    assert transcript[-1] == {
        "accepted": False,
        "issue_codes": ["BASELINE_EXTERNAL_RESPONSE_INVALID"],
        "state": None,
    }

    proposal_count = 1 + seed % len(_PROPOSAL_FACTS)
    reviewer_importance = seed % len(_IMPORTANCE)
    auditor_importance = (seed // len(_IMPORTANCE)) % len(_IMPORTANCE)
    proposals = [
        _proposal(index, (reviewer_importance + index) % len(_IMPORTANCE))
        for index in range(proposal_count)
    ]
    review_payload = {"proposals": proposals, "review_complete": True}
    _submit_pair(portable, full_run, portable_run, review_payload, transcript)

    add_semantic_dispute = seed % 4 == 0
    first_audit = True
    while True:
        full_request = next_baseline_request_v1(full_run)
        portable_request = portable.next_baseline_request_v1(portable_run)
        assert _wire(full_request) == _wire(portable_request)
        if full_request is None:
            request = {}
            break
        request = cast(dict[str, object], _wire(full_request))
        transcript.append(request)
        if request["operation"] != "baseline_source_audit":
            break
        request_payload = cast(dict[str, object], request["payload"])
        targets = cast(list[str], request_payload["required_new_importance_targets"])
        capacity = 4 if first_audit and add_semantic_dispute else 5
        selected_targets = targets[:capacity]
        findings = []
        for proposal_ref in selected_targets:
            index = int(proposal_ref.split("-")[1]) - 1
            tier = (
                auditor_importance
                if index == 0
                else (reviewer_importance + index) % len(_IMPORTANCE)
            )
            original_tier = (reviewer_importance + index) % len(_IMPORTANCE)
            findings.append(
                _importance_finding(
                    proposal_ref,
                    tier,
                    disposition="agree" if tier == original_tier else "correct",
                )
            )
        concerns: list[dict[str, object]] = []
        if first_audit and add_semantic_dispute:
            concerns.append(
                {
                    "target_proposal_ref": "PR-0001",
                    "concern_type": "incorrect_statement",
                    "passages": proposals[0]["passages"],
                    "explanation": (
                        "The fictional source permits a distinct bounded statement of scope."
                    ),
                    "correction": _semantic_correction(proposals[0]),
                }
            )
        remaining = len(targets) - len(selected_targets)
        audit_payload = {
            "concerns": concerns,
            "importance_findings": findings,
            "audit_complete": remaining == 0,
        }
        _submit_pair(portable, full_run, portable_run, audit_payload, transcript)
        first_audit = False

    referee_index = 0
    decisions = ("accept_reviewer", "accept_auditor", "unresolved")
    while request.get("operation") == "baseline_source_referee":
        decision = decisions[(seed + referee_index) % len(decisions)]
        _submit_pair(
            portable,
            full_run,
            portable_run,
            _referee_payload(request, decision),
            transcript,
        )
        referee_index += 1
        full_request = next_baseline_request_v1(full_run)
        portable_request = portable.next_baseline_request_v1(portable_run)
        assert _wire(full_request) == _wire(portable_request)
        if full_request is None:
            break
        request = cast(dict[str, object], _wire(full_request))
        transcript.append(request)

    full_status = baseline_status_payload_v1(full_run)
    portable_status = portable.baseline_status_payload_v1(portable_run)
    assert _wire(full_status) == _wire(portable_status)
    transcript.append(_wire(full_status))
    assert _wire(verify_baseline_run(full_run)) == _wire(
        portable.verify_baseline_run(portable_run)
    )
    assert _tree_bytes(full_run) == _tree_bytes(portable_run)

    full_projection = project_gradeable_baseline_v1(load_verified_baseline_run(full_run))
    portable_projection = portable._baseline_gradeable_projection_bytes_for_test(
        _tree_bytes(portable_run)
    )
    assert canonical_json_bytes(full_projection.model_dump(mode="json")) == portable_projection
    baseline_bytes = canonical_json_bytes(full_projection.model_dump(mode="json"))
    for report_revision in (
        f"# Synthetic report revision A for {seed}".encode(),
        f"# Synthetic report revision B for {rng.randrange(1_000_000)}".encode(),
    ):
        assert report_revision not in baseline_bytes
        assert hashlib.sha256(report_revision).hexdigest().encode() not in baseline_bytes
    assert not _contains_report_key(json.loads(baseline_bytes))
    assert all(
        not _contains_report_key(json.loads(data))
        for name, data in _tree_bytes(full_run).items()
        if name.endswith(".json")
    )

    if seed % 10 == 0 and load_verified_baseline_run(full_run).baseline.requirements:
        correction = tmp_path / "correction.json"
        _write_correction(correction, full_run, seed)
        full_corrected = tmp_path / "full-corrected"
        portable_corrected = tmp_path / "portable-corrected"
        full_corrected_state = initialize_baseline_v1(
            control,
            full_corrected,
            nonce_hex=nonce,
            prior_baseline_path=full_run,
            correction_path=correction,
        )
        portable_corrected_state = portable.initialize_baseline_v1(
            control,
            portable_corrected,
            nonce_hex=nonce,
            prior_baseline_path=portable_run,
            correction_path=correction,
        )
        assert _wire(full_corrected_state) == _wire(portable_corrected_state)
        assert _tree_bytes(full_corrected) == _tree_bytes(portable_corrected)
        assert _tree_bytes(full_run) == _tree_bytes(portable_run)


def _boundary_proposal(index: int) -> dict[str, object]:
    importance, basis, rationale = _IMPORTANCE[index % len(_IMPORTANCE)]
    return {
        "statement": f"The fictional operator must file notice item {index}.",
        "kind": "obligation",
        "importance": importance,
        "importance_basis": basis,
        "importance_rationale": rationale,
        "passages": [{"source_id": "rule-1", "quote": "must file a notice"}],
        "dependency": None,
        "confidence": "clear",
        "substantive_rationale": "The fictional rule states this notice duty.",
    }


def test_fragment_and_compiled_item_boundaries_are_exact_and_mutation_sensitive() -> None:
    """Changing any 5/128/640 controller limit makes one literal boundary assertion fail."""
    baseline_input = _baseline_input()
    histories: dict[int, tuple[AcceptedBaselineReviewFragmentV1, ...]] = {0: ()}
    history: tuple[AcceptedBaselineReviewFragmentV1, ...] = ()
    for ordinal in range(1, 129):
        request = build_baseline_source_review_request_v1(
            baseline_input,
            history,
            fragment_ordinal=ordinal,
        )
        payload = BaselineReviewFragmentV1(
            proposals=tuple(_boundary_proposal(index) for index in range(5)),
            review_complete=False,
        )
        history = (
            *history,
            AcceptedBaselineReviewFragmentV1(
                fragment_ordinal=ordinal,
                request_fingerprint=request.request_fingerprint,
                response_fingerprint=hashlib.sha256(f"fragment:{ordinal}".encode()).hexdigest(),
                payload=payload,
            ),
        )
        if ordinal in {1, 5, 6, 127, 128}:
            histories[ordinal] = history

    for count in (0, 1, 5, 6, 127):
        request = build_baseline_source_review_request_v1(
            baseline_input,
            histories[count],
            fragment_ordinal=count + 1,
        )
        assert request.payload["fragment_ordinal"] == count + 1
        assert request.payload["max_new_items"] == 5

    assert sum(len(item.payload.proposals) for item in histories[128]) == 640
    assert 640 + 1 > 640
    with pytest.raises(ValueError, match="ordinal"):
        build_baseline_source_review_request_v1(
            baseline_input,
            histories[128],
            fragment_ordinal=129,
        )
    with pytest.raises(ValueError):
        BaselineReviewFragmentV1(
            proposals=tuple(_boundary_proposal(index) for index in range(6)),
            review_complete=True,
        )


def test_full_and_portable_submission_crashes_are_write_free_and_resumable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An injected crash at either public commit boundary preserves the pending tree."""
    portable = _load_portable()
    control = _control_input(tmp_path, 0)
    full_run = tmp_path / "full-crash"
    portable_run = tmp_path / "portable-crash"
    initialize_baseline_v1(control, full_run, nonce_hex="9" * 64)
    portable.initialize_baseline_v1(control, portable_run, nonce_hex="9" * 64)
    before = _tree_bytes(full_run)
    payload = {"proposals": [_proposal(0, 0)], "review_complete": True}

    full_commit = baseline_artifacts.commit_baseline_transition_v1
    portable_commit = portable._baseline_commit

    def crash_full(*_args: object, **_kwargs: object) -> None:
        raise OSError("injected full commit crash")

    def crash_portable(*_args: object, **_kwargs: object) -> None:
        raise OSError("injected portable commit crash")

    monkeypatch.setattr(baseline_artifacts, "commit_baseline_transition_v1", crash_full)
    with pytest.raises(OSError, match="injected full commit crash"):
        guarded_submit_baseline_response_v1(
            full_run,
            payload,
            provider_name="fictional-provider",
            model_name="fictional-model",
            judge_isolation="scripted_fixture",
        )
    monkeypatch.setattr(baseline_artifacts, "commit_baseline_transition_v1", full_commit)
    monkeypatch.setattr(portable, "_baseline_commit", crash_portable)
    with pytest.raises(OSError, match="injected portable commit crash"):
        portable.guarded_submit_baseline_response_v1(
            portable_run,
            payload,
            provider_name="fictional-provider",
            model_name="fictional-model",
            judge_isolation="scripted_fixture",
        )
    monkeypatch.setattr(portable, "_baseline_commit", portable_commit)

    assert _tree_bytes(full_run) == _tree_bytes(portable_run) == before
    transcript: list[object] = []
    _submit_pair(portable, full_run, portable_run, payload, transcript)


def test_concurrent_full_and_portable_submissions_have_one_exact_winner(
    tmp_path: Path,
) -> None:
    """Two concurrent submissions serialize identically without duplicate acceptance."""
    portable = _load_portable()
    control = _control_input(tmp_path, 1)
    full_run = tmp_path / "full-concurrent"
    portable_run = tmp_path / "portable-concurrent"
    initialize_baseline_v1(control, full_run, nonce_hex="a" * 64)
    portable.initialize_baseline_v1(control, portable_run, nonce_hex="a" * 64)
    payload = {"proposals": [_proposal(0, 0)], "review_complete": True}

    def submit_full() -> object:
        return _wire(
            guarded_submit_baseline_response_v1(
                full_run,
                payload,
                provider_name="fictional-provider",
                model_name="fictional-model",
                judge_isolation="scripted_fixture",
            )
        )

    def submit_portable() -> object:
        raw = cast(
            dict[str, object],
            portable.guarded_submit_baseline_response_v1(
                portable_run,
                payload,
                provider_name="fictional-provider",
                model_name="fictional-model",
                judge_isolation="scripted_fixture",
            ),
        )
        return {
            "accepted": raw["accepted"],
            "issue_codes": raw["diagnostics"],
            "state": raw["state"],
        }

    with ThreadPoolExecutor(max_workers=4) as pool:
        full_futures = (pool.submit(submit_full), pool.submit(submit_full))
        full_results = [future.result() for future in full_futures]
        portable_results = [
            future.result()
            for future in (pool.submit(submit_portable), pool.submit(submit_portable))
        ]
    key = lambda value: canonical_json_bytes(value)  # noqa: E731
    assert sorted(full_results, key=key) == sorted(portable_results, key=key)
    assert sum(cast(dict[str, object], item)["accepted"] is True for item in full_results) == 1
    assert _tree_bytes(full_run) == _tree_bytes(portable_run)
