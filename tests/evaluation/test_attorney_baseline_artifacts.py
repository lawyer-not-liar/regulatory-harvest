"""Immutable storage and semantic replay for evaluation-baseline-v1."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import fields
from pathlib import Path
from threading import Event
from typing import cast

import pytest

from regulatory_harvest.evaluation import attorney_artifacts as shared_artifacts
from regulatory_harvest.evaluation import attorney_baseline_artifacts as baseline_artifacts
from regulatory_harvest.evaluation.attorney_artifacts import EvaluationIntegrityError
from regulatory_harvest.evaluation.attorney_baseline_artifacts import (
    BASELINE_AUDIT_PATH,
    BASELINE_CORRECTION_PATH,
    BASELINE_INPUT_PATH,
    BASELINE_MANIFEST_PATH,
    BASELINE_REFEREES_PATH,
    BASELINE_REVIEW_PATH,
    BASELINE_SAFE_ISSUE_CODES,
    BASELINE_VERIFICATION_PATH,
    CANONICAL_BASELINE_PATH,
    VerifiedBaselineContextV1,
    commit_baseline_transition_v1,
    initialize_baseline_storage_v1,
    load_verified_baseline_run,
    verify_baseline_run,
)
from regulatory_harvest.evaluation.attorney_baseline_compiler import (
    aggregate_baseline_audit_v1,
    aggregate_baseline_referees_v1,
    aggregate_baseline_review_v1,
    apply_baseline_correction_v1,
    build_baseline_disputes_v1,
    compile_canonical_baseline_v1,
)
from regulatory_harvest.evaluation.attorney_baseline_input import (
    legal_input_fingerprint_v1,
)
from regulatory_harvest.evaluation.attorney_baseline_models import (
    AcceptedBaselineAuditFragmentV1,
    AcceptedBaselineRefereeFragmentV1,
    AcceptedBaselineReviewFragmentV1,
    BaselineAuditFragmentV1,
    BaselineCorrectionRecordV1,
    BaselineEvaluatorRequestV1,
    BaselineEvaluatorResponseV1,
    BaselineInputV1,
    BaselineManifestV1,
    BaselinePhaseV1,
    BaselineRefereeDecisionV1,
    BaselineRequirementV1,
    BaselineReviewFragmentV1,
    BaselineVerificationV1,
)
from regulatory_harvest.evaluation.attorney_baseline_requests import (
    BASELINE_COMPILER_CONTRACT_FINGERPRINT_V1,
    BASELINE_COMPILER_CONTRACT_V1,
    build_baseline_source_audit_request_v1,
    build_baseline_source_referee_request_v1,
    build_baseline_source_review_request_v1,
)
from regulatory_harvest.evaluation.attorney_v22_compiler import RUBRIC_V22
from regulatory_harvest.storage import canonical_json_bytes, sha256_digest

_REVIEW_REQUEST = "requests/source-review-0001.json"
_REVIEW_RESPONSE = "responses/source-review-0001.json"
_AUDIT_REQUEST = "requests/source-audit-0001.json"
_AUDIT_RESPONSE = "responses/source-audit-0001.json"


def _baseline_input() -> BaselineInputV1:
    source_text = (
        "Section 1. A covered operator must file a notice. "
        "Section 2. The notice must identify the operator."
    )
    policy_bytes = (
        b'{"definitions":{"critical":"omission or material misstatement could change the legal '
        b"bottom line, applicability, operative status, core duty or prohibition, enforcement "
        b'exposure, remedy, or a dispositive deadline.","material":"necessary for a competent '
        b"attorney briefing or implementation decision but not independently outcome-determinative "
        b'under the current scoped question.","supporting":"useful explanatory, contextual, or '
        b"implementation detail whose absence does not materially change the legal answer"
        b' or required next action."},"importance_policy_version":"importance-policy-v1"}'
    )
    rubric_bytes = canonical_json_bytes(RUBRIC_V22.model_dump(mode="json"))
    client_facts = "The operator is covered."
    payload: dict[str, object] = {
        "schema_version": "baseline-input-v1",
        "sources": (
            {
                "source_id": "rule-1",
                "title": "Rule 1",
                "normalized_text": source_text,
                "content_hash": hashlib.sha256(source_text.encode()).hexdigest(),
                "jurisdiction": "Example",
                "authority_type": "regulation",
                "source_role": "official_primary",
                "source_quality": "primary",
                "completeness": "complete",
                "language": "en",
            },
        ),
        "source_record_fingerprint": "a" * 64,
        "question": "What must a covered operator do?",
        "jurisdiction": "Example",
        "as_of": "2026-08-24",
        "requested_authorities": (
            {
                "authority_id": "rule-1",
                "title": "Rule 1",
                "jurisdiction": "Example",
                "authority_type": "regulation",
                "source_ids": ["rule-1"],
            },
        ),
        "client_facts": client_facts,
        "client_facts_binding": "sha256:" + sha256_digest(client_facts.encode()),
        "qualification_root": "b" * 64,
        "qualification_receipt_fingerprint": "c" * 64,
        "qualification_readiness": "ADMITTED",
        "compiler_contract": BASELINE_COMPILER_CONTRACT_V1,
        "compiler_contract_fingerprint": BASELINE_COMPILER_CONTRACT_FINGERPRINT_V1,
        "evaluation_rubric_version": "attorney-eval-v2.2",
        "evaluation_rubric_bytes": rubric_bytes,
        "evaluation_rubric_fingerprint": sha256_digest(rubric_bytes),
        "importance_policy_version": "importance-policy-v1",
        "importance_policy_bytes": policy_bytes,
        "importance_policy_fingerprint": sha256_digest(policy_bytes),
        "legal_input_fingerprint": "0" * 64,
    }
    provisional = BaselineInputV1.model_validate(payload)
    payload["legal_input_fingerprint"] = legal_input_fingerprint_v1(provisional)
    return BaselineInputV1.model_validate(payload)


def _response_bytes(request: BaselineEvaluatorRequestV1, payload: object) -> bytes:
    wire = payload.model_dump(mode="json") if hasattr(payload, "model_dump") else payload
    response = BaselineEvaluatorResponseV1(
        operation=request.operation,
        request_fingerprint=request.request_fingerprint,
        provider_name="fixture",
        model_name="fixture-model",
        judge_isolation="scripted_fixture",
        payload=cast(dict[str, object], wire),
    )
    return canonical_json_bytes(response.model_dump(mode="json"))


def _manifest(
    baseline_input: BaselineInputV1,
    phase: BaselinePhaseV1,
    *,
    baseline_fingerprint: str | None = None,
    terminal_status: str | None = None,
) -> BaselineManifestV1:
    return BaselineManifestV1.model_validate(
        {
            "legal_input_fingerprint": baseline_input.legal_input_fingerprint,
            "baseline_fingerprint": baseline_fingerprint,
            "phase": phase,
            "terminal_status": terminal_status,
            "artifacts": (),
            "manifest_fingerprint": "0" * 64,
        }
    )


def _canonical(value: object) -> bytes:
    assert hasattr(value, "model_dump")
    return canonical_json_bytes(value.model_dump(mode="json"))  # type: ignore[union-attr]


def _complete_graph() -> tuple[
    BaselineInputV1,
    dict[str, bytes],
    BaselineManifestV1,
]:
    baseline_input = _baseline_input()
    review_request = build_baseline_source_review_request_v1(
        baseline_input, (), fragment_ordinal=1
    )
    review_payload = BaselineReviewFragmentV1(
        proposals=(
            {
                "statement": "A covered operator must file a notice.",
                "kind": "obligation",
                "importance": "critical",
                "importance_basis": ("legal_bottom_line",),
                "importance_rationale": "Omission could change the legal bottom line.",
                "passages": ({"source_id": "rule-1", "quote": "must file a notice"},),
                "dependency": None,
                "confidence": "clear",
                "substantive_rationale": "The source uses mandatory language.",
            },
        ),
        review_complete=True,
    )
    review_response = _response_bytes(review_request, review_payload)
    review_fragment = AcceptedBaselineReviewFragmentV1(
        fragment_ordinal=1,
        request_fingerprint=review_request.request_fingerprint,
        response_fingerprint=sha256_digest(review_response),
        payload=review_payload,
    )
    review = aggregate_baseline_review_v1(baseline_input, (review_fragment,))

    audit_request = build_baseline_source_audit_request_v1(
        baseline_input, review, (), fragment_ordinal=1
    )
    audit_payload = BaselineAuditFragmentV1(
        concerns=(),
        importance_findings=(
            {
                "proposal_ref": "PR-0001",
                "reviewed_importance": "critical",
                "reviewed_importance_basis": ("legal_bottom_line",),
                "importance_rationale": "Omission could change the legal bottom line.",
                "disposition": "agree",
            },
        ),
        audit_complete=True,
    )
    audit_response = _response_bytes(audit_request, audit_payload)
    audit_fragment = AcceptedBaselineAuditFragmentV1(
        fragment_ordinal=1,
        request_fingerprint=audit_request.request_fingerprint,
        response_fingerprint=sha256_digest(audit_response),
        payload=audit_payload,
    )
    audit = aggregate_baseline_audit_v1(
        baseline_input, review, (audit_fragment,)
    )
    referees = aggregate_baseline_referees_v1(baseline_input, (), ())
    baseline = compile_canonical_baseline_v1(
        baseline_input, review, audit, referees
    )
    verification = BaselineVerificationV1(valid=True)
    files = {
        BASELINE_INPUT_PATH: _canonical(baseline_input),
        _REVIEW_REQUEST: _canonical(review_request),
        _REVIEW_RESPONSE: review_response,
        BASELINE_REVIEW_PATH: _canonical(review),
        _AUDIT_REQUEST: _canonical(audit_request),
        _AUDIT_RESPONSE: audit_response,
        BASELINE_AUDIT_PATH: _canonical(audit),
        BASELINE_REFEREES_PATH: _canonical(referees),
        CANONICAL_BASELINE_PATH: _canonical(baseline),
        BASELINE_VERIFICATION_PATH: _canonical(verification),
    }
    manifest = _manifest(
        baseline_input,
        BaselinePhaseV1.COMPLETED,
        baseline_fingerprint=baseline.baseline_fingerprint,
        terminal_status="COMPLETED",
    )
    return baseline_input, files, manifest


def _snapshot(run_dir: Path) -> dict[str, bytes]:
    return {
        path.relative_to(run_dir).as_posix(): path.read_bytes()
        for path in sorted(run_dir.rglob("*"))
        if path.is_file()
    }


def _referee_graph() -> tuple[BaselineInputV1, dict[str, bytes], BaselineManifestV1]:
    baseline_input = _baseline_input()
    review_request = build_baseline_source_review_request_v1(
        baseline_input, (), fragment_ordinal=1
    )
    review_payload = BaselineReviewFragmentV1(
        proposals=(
            {
                "statement": "A covered operator must file a notice.",
                "kind": "obligation",
                "importance": "critical",
                "importance_basis": ("legal_bottom_line",),
                "importance_rationale": "Omission could change the legal bottom line.",
                "passages": ({"source_id": "rule-1", "quote": "must file a notice"},),
                "dependency": None,
                "confidence": "clear",
                "substantive_rationale": "The source uses mandatory language.",
            },
        ),
        review_complete=True,
    )
    review_response = _response_bytes(review_request, review_payload)
    review_fragment = AcceptedBaselineReviewFragmentV1(
        fragment_ordinal=1,
        request_fingerprint=review_request.request_fingerprint,
        response_fingerprint=sha256_digest(review_response),
        payload=review_payload,
    )
    review = aggregate_baseline_review_v1(baseline_input, (review_fragment,))
    audit_request = build_baseline_source_audit_request_v1(
        baseline_input, review, (), fragment_ordinal=1
    )
    audit_payload = BaselineAuditFragmentV1(
        concerns=(
            {
                "target_proposal_ref": "PR-0001",
                "concern_type": "incorrect_statement",
                "passages": ({"source_id": "rule-1", "quote": "must file a notice"},),
                "explanation": "The source may support a narrower annual obligation.",
                "correction": {
                    "statement": "A covered operator must file an annual notice.",
                    "kind": "obligation",
                    "importance": "critical",
                    "importance_basis": ("legal_bottom_line",),
                    "importance_rationale": (
                        "The frequency could change the legal bottom line."
                    ),
                    "passages": (
                        {"source_id": "rule-1", "quote": "must file a notice"},
                    ),
                    "dependency": None,
                    "confidence": "ambiguous",
                    "substantive_rationale": "The source wording may imply a narrower duty.",
                },
            },
        ),
        importance_findings=(
            {
                "proposal_ref": "PR-0001",
                "reviewed_importance": "critical",
                "reviewed_importance_basis": ("legal_bottom_line",),
                "importance_rationale": "Omission could change the legal bottom line.",
                "disposition": "agree",
            },
        ),
        audit_complete=True,
    )
    audit_response = _response_bytes(audit_request, audit_payload)
    audit_fragment = AcceptedBaselineAuditFragmentV1(
        fragment_ordinal=1,
        request_fingerprint=audit_request.request_fingerprint,
        response_fingerprint=sha256_digest(audit_response),
        payload=audit_payload,
    )
    audit = aggregate_baseline_audit_v1(
        baseline_input, review, (audit_fragment,)
    )
    disputes = build_baseline_disputes_v1(baseline_input, review, audit)
    assert len(disputes) == 1
    dispute = disputes[0]
    referee_request = build_baseline_source_referee_request_v1(
        baseline_input, dispute
    )
    referee_decision = BaselineRefereeDecisionV1(
        dispute_id=dispute.dispute_id,
        decision="accept_reviewer",
        passages=({"source_id": "rule-1", "quote": "must file a notice"},),
        importance="critical",
        importance_basis=("legal_bottom_line",),
        importance_rationale="Omission could change the legal bottom line.",
        substantive_rationale="The reviewer statement best matches the retained source.",
    )
    referee_response = _response_bytes(referee_request, referee_decision)
    fragment = AcceptedBaselineRefereeFragmentV1(
        dispute_id=dispute.dispute_id,
        dispute_fingerprint=dispute.dispute_fingerprint,
        response_fingerprint=sha256_digest(referee_response),
        decision=referee_decision,
    )
    referees = aggregate_baseline_referees_v1(
        baseline_input, disputes, (fragment,)
    )
    baseline = compile_canonical_baseline_v1(
        baseline_input, review, audit, referees
    )
    referee_request_path = f"requests/source-referee-{dispute.dispute_id}.json"
    referee_response_path = f"responses/source-referee-{dispute.dispute_id}.json"
    files = {
        BASELINE_INPUT_PATH: _canonical(baseline_input),
        _REVIEW_REQUEST: _canonical(review_request),
        _REVIEW_RESPONSE: review_response,
        BASELINE_REVIEW_PATH: _canonical(review),
        _AUDIT_REQUEST: _canonical(audit_request),
        _AUDIT_RESPONSE: audit_response,
        BASELINE_AUDIT_PATH: _canonical(audit),
        referee_request_path: _canonical(referee_request),
        referee_response_path: referee_response,
        BASELINE_REFEREES_PATH: _canonical(referees),
        CANONICAL_BASELINE_PATH: _canonical(baseline),
        BASELINE_VERIFICATION_PATH: _canonical(BaselineVerificationV1(valid=True)),
    }
    return (
        baseline_input,
        files,
        _manifest(
            baseline_input,
            BaselinePhaseV1.COMPLETED,
            baseline_fingerprint=baseline.baseline_fingerprint,
            terminal_status="COMPLETED",
        ),
    )


def _artifact_paths(manifest: BaselineManifestV1) -> tuple[str, ...]:
    return tuple(item.artifact_path for item in manifest.artifacts)


def _reseal_manifest(run_dir: Path, mutate: Mapping[str, bytes]) -> None:
    manifest_path = run_dir / BASELINE_MANIFEST_PATH
    raw = json.loads(manifest_path.read_bytes())
    artifacts = {
        item["artifact_path"]: item for item in raw["artifacts"]
    }
    for path, data in mutate.items():
        target = run_dir / path
        target.chmod(0o600)
        target.write_bytes(data)
        artifacts[path]["artifact_hash"] = sha256_digest(data)
    raw["artifacts"] = [artifacts[path] for path in sorted(artifacts)]
    raw["root_hash"] = "0" * 64
    raw["manifest_fingerprint"] = "0" * 64
    provisional = BaselineManifestV1.model_validate(raw)
    raw["manifest_fingerprint"] = sha256_digest(
        canonical_json_bytes(
            provisional.model_dump(
                mode="json", exclude={"manifest_fingerprint", "root_hash"}
            )
        )
    )
    with_fingerprint = BaselineManifestV1.model_validate(raw)
    raw["root_hash"] = sha256_digest(
        canonical_json_bytes(with_fingerprint.model_dump(mode="json", exclude={"root_hash"}))
    )
    manifest_path.chmod(0o600)
    manifest_path.write_bytes(canonical_json_bytes(raw))


def test_terminal_inventory_and_verified_context_are_exact(tmp_path: Path) -> None:
    baseline_input, files_by_path, manifest = _complete_graph()
    run_dir = tmp_path / "baseline"
    committed = initialize_baseline_storage_v1(run_dir, manifest, files_by_path)
    context = load_verified_baseline_run(run_dir)

    assert [item.name for item in fields(VerifiedBaselineContextV1)] == [
        "manifest",
        "baseline_input",
        "baseline",
        "verification",
    ]
    assert context.manifest == committed
    assert context.baseline_input == baseline_input
    assert context.verification == BaselineVerificationV1(valid=True)
    assert set(_artifact_paths(context.manifest)) == set(files_by_path)
    assert set(_snapshot(run_dir)) == {BASELINE_MANIFEST_PATH, *files_by_path}


def test_verified_context_is_recursively_immutable(tmp_path: Path) -> None:
    _, files_by_path, manifest = _complete_graph()
    run_dir = tmp_path / "immutable-context"
    initialize_baseline_storage_v1(run_dir, manifest, files_by_path)
    context = load_verified_baseline_run(run_dir)
    before = _snapshot(run_dir)

    with pytest.raises((AttributeError, TypeError, ValueError)):
        context.manifest.artifacts[0].artifact_hash = "f" * 64
    with pytest.raises((AttributeError, TypeError, ValueError)):
        context.baseline_input.sources[0].title = "mutated"
    with pytest.raises((AttributeError, TypeError, ValueError)):
        context.baseline_input.requested_authorities[0].source_ids.append("other")

    assert _snapshot(run_dir) == before
    assert verify_baseline_run(run_dir).valid


def test_terminal_manifest_binds_calls_aggregates_and_root(tmp_path: Path) -> None:
    _, files_by_path, manifest = _complete_graph()
    run_dir = tmp_path / "manifest-bindings"
    committed = initialize_baseline_storage_v1(run_dir, manifest, files_by_path)
    context = load_verified_baseline_run(run_dir)

    assert committed.pending_call is None
    assert [call.call_id for call in committed.accepted_calls] == [
        "source-review-0001",
        "source-audit-0001",
    ]
    assert committed.source_review_aggregate_fingerprint == (
        context.baseline.provenance.source_review_aggregate_fingerprint
    )
    assert committed.source_audit_aggregate_fingerprint == (
        context.baseline.provenance.source_audit_aggregate_fingerprint
    )
    assert committed.source_referee_aggregate_fingerprint == (
        context.baseline.provenance.source_referee_aggregate_fingerprint
    )
    assert committed.prior_baseline_root is None
    assert committed.prior_baseline_fingerprint is None
    assert committed.correction_record_fingerprint is None
    assert committed.root_hash != "0" * 64


def test_sealed_baseline_without_persisted_verification_cannot_load(
    tmp_path: Path,
) -> None:
    baseline_input, complete, terminal_manifest = _complete_graph()
    files_by_path = {
        path: data
        for path, data in complete.items()
        if path != BASELINE_VERIFICATION_PATH
    }
    run_dir = tmp_path / "sealed-without-receipt"
    initialize_baseline_storage_v1(
        run_dir,
        _manifest(
            baseline_input,
            BaselinePhaseV1.BASELINE_SEALED,
            baseline_fingerprint=terminal_manifest.baseline_fingerprint,
        ),
        files_by_path,
    )

    assert verify_baseline_run(run_dir).valid
    with pytest.raises(EvaluationIntegrityError, match="BASELINE_RESULT_REQUIRED"):
        load_verified_baseline_run(run_dir)


@pytest.mark.parametrize(
    ("phase", "selected"),
    [
        (BaselinePhaseV1.CREATED, {BASELINE_INPUT_PATH}),
        (
            BaselinePhaseV1.SOURCE_REVIEW,
            {BASELINE_INPUT_PATH, _REVIEW_REQUEST},
        ),
        (
            BaselinePhaseV1.SOURCE_AUDIT,
            {
                BASELINE_INPUT_PATH,
                _REVIEW_REQUEST,
                _REVIEW_RESPONSE,
                BASELINE_REVIEW_PATH,
                _AUDIT_REQUEST,
            },
        ),
        (
            BaselinePhaseV1.BASELINE_SEALED,
            {
                BASELINE_INPUT_PATH,
                _REVIEW_REQUEST,
                _REVIEW_RESPONSE,
                BASELINE_REVIEW_PATH,
                _AUDIT_REQUEST,
                _AUDIT_RESPONSE,
                BASELINE_AUDIT_PATH,
                BASELINE_REFEREES_PATH,
                CANONICAL_BASELINE_PATH,
            },
        ),
    ],
)
def test_each_nonterminal_phase_has_one_exact_manifest_inventory(
    tmp_path: Path,
    phase: BaselinePhaseV1,
    selected: set[str],
) -> None:
    baseline_input, complete, terminal_manifest = _complete_graph()
    files_by_path = {path: complete[path] for path in selected}
    baseline_fingerprint = (
        terminal_manifest.baseline_fingerprint
        if CANONICAL_BASELINE_PATH in selected
        else None
    )
    committed = initialize_baseline_storage_v1(
        tmp_path / phase.value,
        _manifest(
            baseline_input,
            phase,
            baseline_fingerprint=baseline_fingerprint,
        ),
        files_by_path,
    )
    assert _artifact_paths(committed) == tuple(sorted(selected))
    assert verify_baseline_run(tmp_path / phase.value).valid


def test_pending_call_is_exactly_bound_by_the_manifest(tmp_path: Path) -> None:
    baseline_input, complete, _ = _complete_graph()
    run_dir = tmp_path / "pending-binding"
    committed = initialize_baseline_storage_v1(
        run_dir,
        _manifest(baseline_input, BaselinePhaseV1.SOURCE_REVIEW),
        {
            BASELINE_INPUT_PATH: complete[BASELINE_INPUT_PATH],
            _REVIEW_REQUEST: complete[_REVIEW_REQUEST],
        },
    )

    assert committed.accepted_calls == ()
    assert committed.pending_call is not None
    assert committed.pending_call.call_id == "source-review-0001"
    assert committed.pending_call.request_artifact_path == _REVIEW_REQUEST
    assert committed.pending_call.response_artifact_path is None
    assert committed.pending_call.response_fingerprint is None


def test_replay_rejects_rehashed_manifest_call_and_root_tamper(tmp_path: Path) -> None:
    _, files_by_path, manifest = _complete_graph()
    call_dir = tmp_path / "call-binding-tamper"
    initialize_baseline_storage_v1(call_dir, manifest, files_by_path)
    manifest_path = call_dir / BASELINE_MANIFEST_PATH
    raw = json.loads(manifest_path.read_bytes())
    raw["accepted_calls"][0]["response_fingerprint"] = "f" * 64
    raw["root_hash"] = "0" * 64
    raw["manifest_fingerprint"] = "0" * 64
    provisional = BaselineManifestV1.model_validate(raw)
    raw["manifest_fingerprint"] = sha256_digest(
        canonical_json_bytes(
            provisional.model_dump(
                mode="json", exclude={"manifest_fingerprint", "root_hash"}
            )
        )
    )
    with_fingerprint = BaselineManifestV1.model_validate(raw)
    raw["root_hash"] = sha256_digest(
        canonical_json_bytes(with_fingerprint.model_dump(mode="json", exclude={"root_hash"}))
    )
    manifest_path.chmod(0o600)
    manifest_path.write_bytes(canonical_json_bytes(raw))
    assert not verify_baseline_run(call_dir).valid

    root_dir = tmp_path / "root-tamper"
    initialize_baseline_storage_v1(root_dir, manifest, files_by_path)
    root_manifest = root_dir / BASELINE_MANIFEST_PATH
    root_raw = json.loads(root_manifest.read_bytes())
    root_raw["root_hash"] = "f" * 64
    root_manifest.chmod(0o600)
    root_manifest.write_bytes(canonical_json_bytes(root_raw))
    assert not verify_baseline_run(root_dir).valid


def test_referee_phase_and_terminal_history_are_reconstructed_from_bytes(
    tmp_path: Path,
) -> None:
    baseline_input, complete, terminal_manifest = _referee_graph()
    request_path = "requests/source-referee-DSP-0001.json"
    response_path = "responses/source-referee-DSP-0001.json"
    pending_files = {
        path: data
        for path, data in complete.items()
        if path
        not in {
            response_path,
            BASELINE_REFEREES_PATH,
            CANONICAL_BASELINE_PATH,
            BASELINE_VERIFICATION_PATH,
        }
    }
    pending_dir = tmp_path / "referee-pending"
    initialize_baseline_storage_v1(
        pending_dir,
        _manifest(baseline_input, BaselinePhaseV1.SOURCE_REFEREE),
        pending_files,
    )
    assert request_path in _snapshot(pending_dir)
    assert verify_baseline_run(pending_dir).valid

    terminal_dir = tmp_path / "referee-complete"
    initialize_baseline_storage_v1(terminal_dir, terminal_manifest, complete)
    loaded = load_verified_baseline_run(terminal_dir)
    assert loaded.baseline.requirements[0].statement == (
        "A covered operator must file a notice."
    )


def test_transition_is_atomic_and_rejects_stale_root(
    tmp_path: Path,
) -> None:
    baseline_input, complete, _ = _complete_graph()
    run_dir = tmp_path / "transition"
    created = initialize_baseline_storage_v1(
        run_dir,
        _manifest(baseline_input, BaselinePhaseV1.CREATED),
        {BASELINE_INPUT_PATH: complete[BASELINE_INPUT_PATH]},
    )
    successor = _manifest(baseline_input, BaselinePhaseV1.SOURCE_REVIEW)
    commit_baseline_transition_v1(
        run_dir,
        created.manifest_fingerprint,
        {_REVIEW_REQUEST: complete[_REVIEW_REQUEST]},
        successor,
    )
    after = _snapshot(run_dir)
    assert verify_baseline_run(run_dir).valid

    with pytest.raises(EvaluationIntegrityError, match="STALE_TRANSITION"):
        commit_baseline_transition_v1(
            run_dir,
            created.manifest_fingerprint,
            {},
            successor,
        )
    assert _snapshot(run_dir) == after


def test_transition_rolls_back_artifacts_and_manifest_after_injected_crashes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    baseline_input, complete, _ = _complete_graph()
    run_dir = tmp_path / "crash"
    current = initialize_baseline_storage_v1(
        run_dir,
        _manifest(baseline_input, BaselinePhaseV1.CREATED),
        {BASELINE_INPUT_PATH: complete[BASELINE_INPUT_PATH]},
    )
    before = _snapshot(run_dir)
    original = shared_artifacts._PosixRunStorage.atomic_write
    failed = False

    def fail_after_manifest(
        storage: object, path: str, data: bytes, *, mutable: bool
    ) -> bool:
        nonlocal failed
        created = original(storage, path, data, mutable=mutable)  # type: ignore[arg-type]
        if path == BASELINE_MANIFEST_PATH and mutable and not failed:
            failed = True
            raise OSError("injected post-manifest crash")
        return created

    monkeypatch.setattr(
        shared_artifacts._PosixRunStorage, "atomic_write", fail_after_manifest
    )
    with pytest.raises(EvaluationIntegrityError):
        commit_baseline_transition_v1(
            run_dir,
            current.manifest_fingerprint,
            {_REVIEW_REQUEST: complete[_REVIEW_REQUEST]},
            _manifest(baseline_input, BaselinePhaseV1.SOURCE_REVIEW),
        )
    assert failed
    assert _snapshot(run_dir) == before
    assert verify_baseline_run(run_dir).valid


@pytest.mark.parametrize(
    "failure_boundary",
    ["before_artifact", "after_artifact", "before_manifest"],
)
def test_transition_rolls_back_each_precommit_durable_boundary(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    failure_boundary: str,
) -> None:
    baseline_input, complete, _ = _complete_graph()
    run_dir = tmp_path / failure_boundary
    current = initialize_baseline_storage_v1(
        run_dir,
        _manifest(baseline_input, BaselinePhaseV1.CREATED),
        {BASELINE_INPUT_PATH: complete[BASELINE_INPUT_PATH]},
    )
    before = _snapshot(run_dir)
    original = shared_artifacts._PosixRunStorage.atomic_write

    def inject(storage: object, path: str, data: bytes, *, mutable: bool) -> bool:
        if failure_boundary == "before_artifact" and path == _REVIEW_REQUEST:
            raise OSError("injected before artifact durability")
        if failure_boundary == "before_manifest" and path == BASELINE_MANIFEST_PATH:
            raise OSError("injected before manifest replace")
        created = original(storage, path, data, mutable=mutable)  # type: ignore[arg-type]
        if failure_boundary == "after_artifact" and path == _REVIEW_REQUEST:
            raise OSError("injected after artifact fsync")
        return created

    monkeypatch.setattr(shared_artifacts._PosixRunStorage, "atomic_write", inject)
    with pytest.raises(EvaluationIntegrityError):
        commit_baseline_transition_v1(
            run_dir,
            current.manifest_fingerprint,
            {_REVIEW_REQUEST: complete[_REVIEW_REQUEST]},
            _manifest(baseline_input, BaselinePhaseV1.SOURCE_REVIEW),
        )
    assert _snapshot(run_dir) == before
    assert verify_baseline_run(run_dir).valid


def test_transition_rolls_back_after_post_commit_replay_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    baseline_input, complete, _ = _complete_graph()
    run_dir = tmp_path / "post-replay"
    current = initialize_baseline_storage_v1(
        run_dir,
        _manifest(baseline_input, BaselinePhaseV1.CREATED),
        {BASELINE_INPUT_PATH: complete[BASELINE_INPUT_PATH]},
    )
    before = _snapshot(run_dir)
    original = baseline_artifacts._verify_or_raise
    calls = 0

    def fail_third(storage: object, **kwargs: object) -> object:
        nonlocal calls
        calls += 1
        if calls == 3:
            raise EvaluationIntegrityError("injected post-commit replay failure")
        return original(storage, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(baseline_artifacts, "_verify_or_raise", fail_third)
    with pytest.raises(EvaluationIntegrityError, match="post-commit replay"):
        commit_baseline_transition_v1(
            run_dir,
            current.manifest_fingerprint,
            {_REVIEW_REQUEST: complete[_REVIEW_REQUEST]},
            _manifest(baseline_input, BaselinePhaseV1.SOURCE_REVIEW),
        )
    assert calls == 3
    assert _snapshot(run_dir) == before


def test_terminal_receipt_transition_is_atomic(tmp_path: Path) -> None:
    baseline_input, complete, terminal_manifest = _complete_graph()
    sealed_files = {
        path: data
        for path, data in complete.items()
        if path != BASELINE_VERIFICATION_PATH
    }
    run_dir = tmp_path / "terminal-receipt"
    sealed = initialize_baseline_storage_v1(
        run_dir,
        _manifest(
            baseline_input,
            BaselinePhaseV1.BASELINE_SEALED,
            baseline_fingerprint=terminal_manifest.baseline_fingerprint,
        ),
        sealed_files,
    )
    commit_baseline_transition_v1(
        run_dir,
        sealed.manifest_fingerprint,
        {BASELINE_VERIFICATION_PATH: complete[BASELINE_VERIFICATION_PATH]},
        terminal_manifest,
    )
    loaded = load_verified_baseline_run(run_dir)
    assert loaded.manifest.phase is BaselinePhaseV1.COMPLETED
    assert loaded.verification == BaselineVerificationV1(valid=True)


def test_verified_inconclusive_baseline_retains_its_sealed_context(
    tmp_path: Path,
) -> None:
    baseline_input, complete, terminal_manifest = _complete_graph()
    run_dir = tmp_path / "inconclusive"
    initialize_baseline_storage_v1(
        run_dir,
        _manifest(
            baseline_input,
            BaselinePhaseV1.INCONCLUSIVE,
            baseline_fingerprint=terminal_manifest.baseline_fingerprint,
            terminal_status="INCONCLUSIVE",
        ),
        complete,
    )
    context = load_verified_baseline_run(run_dir)
    assert context.manifest.terminal_status == "INCONCLUSIVE"
    assert context.verification.valid


def test_concurrent_verify_never_observes_a_mixed_transition(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    baseline_input, complete, _ = _complete_graph()
    run_dir = tmp_path / "concurrent"
    current = initialize_baseline_storage_v1(
        run_dir,
        _manifest(baseline_input, BaselinePhaseV1.CREATED),
        {BASELINE_INPUT_PATH: complete[BASELINE_INPUT_PATH]},
    )
    artifact_visible = Event()
    release_writer = Event()
    verifier_entered_mixed_state = Event()
    original = shared_artifacts._PosixRunStorage.atomic_write
    original_verify = baseline_artifacts._verify_or_raise

    def pause_after_artifact(
        storage: object, path: str, data: bytes, *, mutable: bool
    ) -> bool:
        created = original(storage, path, data, mutable=mutable)  # type: ignore[arg-type]
        if path == _REVIEW_REQUEST:
            artifact_visible.set()
            assert release_writer.wait(timeout=5)
        return created

    monkeypatch.setattr(
        shared_artifacts._PosixRunStorage, "atomic_write", pause_after_artifact
    )

    def observe_verify(storage: object, **kwargs: object) -> object:
        if artifact_visible.is_set() and not release_writer.is_set():
            verifier_entered_mixed_state.set()
        return original_verify(storage, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(baseline_artifacts, "_verify_or_raise", observe_verify)
    with ThreadPoolExecutor(max_workers=2) as executor:
        writer = executor.submit(
            commit_baseline_transition_v1,
            run_dir,
            current.manifest_fingerprint,
            {_REVIEW_REQUEST: complete[_REVIEW_REQUEST]},
            _manifest(baseline_input, BaselinePhaseV1.SOURCE_REVIEW),
        )
        assert artifact_visible.wait(timeout=5)
        verifier = executor.submit(verify_baseline_run, run_dir)
        observed_mixed = verifier_entered_mixed_state.wait(timeout=0.2)
        release_writer.set()
        writer.result(timeout=5)
        verification = verifier.result(timeout=5)

    assert not observed_mixed
    assert verification.valid
    assert verify_baseline_run(run_dir).valid


@pytest.mark.skipif(os.name != "posix", reason="POSIX cross-process lock proof")
def test_cross_process_alias_verify_never_observes_a_mixed_transition(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    baseline_input, complete, _ = _complete_graph()
    run_dir = tmp_path / "cross-process"
    current = initialize_baseline_storage_v1(
        run_dir,
        _manifest(baseline_input, BaselinePhaseV1.CREATED),
        {BASELINE_INPUT_PATH: complete[BASELINE_INPUT_PATH]},
    )
    case_alias = run_dir.with_name(run_dir.name.swapcase())
    alias = (
        case_alias
        if case_alias.exists() and case_alias.samefile(run_dir)
        else run_dir / ".." / run_dir.name
    )
    assert alias.samefile(run_dir)
    artifact_visible = Event()
    release_writer = Event()
    original = shared_artifacts._PosixRunStorage.atomic_write

    def pause_after_artifact(
        storage: object, path: str, data: bytes, *, mutable: bool
    ) -> bool:
        created = original(storage, path, data, mutable=mutable)  # type: ignore[arg-type]
        if path == _REVIEW_REQUEST:
            artifact_visible.set()
            assert release_writer.wait(timeout=5)
        return created

    monkeypatch.setattr(
        shared_artifacts._PosixRunStorage, "atomic_write", pause_after_artifact
    )
    with ThreadPoolExecutor(max_workers=1) as executor:
        writer = executor.submit(
            commit_baseline_transition_v1,
            run_dir,
            current.manifest_fingerprint,
            {_REVIEW_REQUEST: complete[_REVIEW_REQUEST]},
            _manifest(baseline_input, BaselinePhaseV1.SOURCE_REVIEW),
        )
        assert artifact_visible.wait(timeout=5)
        process = subprocess.Popen(
            [
                sys.executable,
                "-c",
                (
                    "from pathlib import Path; import sys; "
                    "from regulatory_harvest.evaluation.attorney_baseline_artifacts "
                    "import verify_baseline_run; "
                    "print(verify_baseline_run(Path(sys.argv[1])).valid, flush=True)"
                ),
                os.fspath(alias),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, "PYTHONPATH": "src"},
        )
        time.sleep(0.25)
        blocked_during_transition = process.poll() is None
        release_writer.set()
        writer.result(timeout=5)
        stdout, stderr = process.communicate(timeout=5)

    assert blocked_during_transition, (stdout, stderr)
    assert process.returncode == 0, stderr
    assert stdout.strip() == "True"


def test_replay_rejects_semantic_tamper_even_after_hash_reseal(tmp_path: Path) -> None:
    _, files_by_path, manifest = _complete_graph()
    run_dir = tmp_path / "resealed"
    initialize_baseline_storage_v1(run_dir, manifest, files_by_path)
    raw = json.loads(files_by_path[CANONICAL_BASELINE_PATH])
    raw["requirements"][0]["substantive_rationale"] = (
        "A different but still syntactically valid rationale."
    )
    raw["baseline_fingerprint"] = "0" * 64
    provisional = raw.copy()
    provisional.pop("baseline_fingerprint")
    raw["baseline_fingerprint"] = sha256_digest(canonical_json_bytes(provisional))
    forged = canonical_json_bytes(raw)
    _reseal_manifest(run_dir, {CANONICAL_BASELINE_PATH: forged})

    result = verify_baseline_run(run_dir)
    assert not result.valid
    assert result.issues
    assert set(result.issues) <= BASELINE_SAFE_ISSUE_CODES
    assert all(str(run_dir) not in issue for issue in result.issues)
    with pytest.raises(EvaluationIntegrityError):
        load_verified_baseline_run(run_dir)


@pytest.mark.parametrize(
    ("left", "right"),
    [
        (_REVIEW_REQUEST, _AUDIT_REQUEST),
        (_REVIEW_RESPONSE, _AUDIT_RESPONSE),
        (BASELINE_REVIEW_PATH, BASELINE_AUDIT_PATH),
    ],
)
def test_replay_rejects_request_response_and_aggregate_swaps_after_reseal(
    tmp_path: Path,
    left: str,
    right: str,
) -> None:
    _, files_by_path, manifest = _complete_graph()
    run_dir = tmp_path / f"swap-{Path(left).stem}-{Path(right).stem}"
    initialize_baseline_storage_v1(run_dir, manifest, files_by_path)
    _reseal_manifest(
        run_dir,
        {
            left: files_by_path[right],
            right: files_by_path[left],
        },
    )
    result = verify_baseline_run(run_dir)
    assert not result.valid
    assert set(result.issues) <= BASELINE_SAFE_ISSUE_CODES


@pytest.mark.skipif(os.name != "posix", reason="POSIX special-file proof")
@pytest.mark.parametrize("attack", ["symlink", "fifo", "hardlink"])
def test_storage_rejects_alias_and_special_file_inventory(
    tmp_path: Path, attack: str
) -> None:
    _, files_by_path, manifest = _complete_graph()
    run_dir = tmp_path / attack
    initialize_baseline_storage_v1(run_dir, manifest, files_by_path)
    target = run_dir / BASELINE_INPUT_PATH
    if attack == "symlink":
        outside = tmp_path / "outside.json"
        outside.write_bytes(files_by_path[BASELINE_INPUT_PATH])
        target.unlink()
        target.symlink_to(outside)
    elif attack == "fifo":
        target.unlink()
        os.mkfifo(target)
    else:
        alias = tmp_path / "alias.json"
        os.link(target, alias)
    result = verify_baseline_run(run_dir)
    assert not result.valid
    assert set(result.issues) <= BASELINE_SAFE_ISSUE_CODES


@pytest.mark.skipif(os.name != "posix", reason="POSIX root replacement proof")
def test_transition_never_mutates_a_replacement_root(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    baseline_input, complete, _ = _complete_graph()
    run_dir = tmp_path / "root-race"
    current = initialize_baseline_storage_v1(
        run_dir,
        _manifest(baseline_input, BaselinePhaseV1.CREATED),
        {BASELINE_INPUT_PATH: complete[BASELINE_INPUT_PATH]},
    )
    replacement = tmp_path / "replacement"
    replacement.mkdir()
    sentinel = replacement / "outside.txt"
    sentinel.write_bytes(b"outside\n")
    parked = tmp_path / "parked"
    original_link = shared_artifacts.os.link
    swapped = False

    def racing_link(
        source: object,
        destination: object,
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> None:
        nonlocal swapped
        if not swapped and destination == Path(_REVIEW_REQUEST).name:
            run_dir.rename(parked)
            replacement.rename(run_dir)
            swapped = True
        original_link(
            source,
            destination,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
            follow_symlinks=follow_symlinks,
        )

    monkeypatch.setattr(shared_artifacts.os, "link", racing_link)
    with pytest.raises(EvaluationIntegrityError):
        commit_baseline_transition_v1(
            run_dir,
            current.manifest_fingerprint,
            {_REVIEW_REQUEST: complete[_REVIEW_REQUEST]},
            _manifest(baseline_input, BaselinePhaseV1.SOURCE_REVIEW),
        )
    assert swapped
    assert (run_dir / "outside.txt").read_bytes() == b"outside\n"
    assert not (run_dir / _REVIEW_REQUEST).exists()


def _correction(
    prior_root: str,
    prior_fingerprint: str,
    requirement: BaselineRequirementV1,
) -> BaselineCorrectionRecordV1:
    payload: dict[str, object] = {
        "schema_version": "baseline-correction-v1",
        "prior_baseline_root": prior_root,
        "prior_baseline_fingerprint": prior_fingerprint,
        "correction_id": "CORR-0001",
        "actions": ({"action": "add_requirement", "requirement": requirement},),
        "reason": "The source review omitted an express notice-content requirement.",
        "attorney_approval": {
            "approved_by": "Fictional Reviewing Attorney",
            "approved_at": "2026-08-24T20:00:00-07:00",
            "approval_statement": "I approve this source-bound baseline correction.",
        },
        "correction_fingerprint": "0" * 64,
    }
    provisional = BaselineCorrectionRecordV1.model_validate(payload)
    payload["correction_fingerprint"] = sha256_digest(
        canonical_json_bytes(
            provisional.model_dump(mode="json", exclude={"correction_fingerprint"})
        )
    )
    return BaselineCorrectionRecordV1.model_validate(payload)


def _removal_correction(
    prior_root: str,
    prior_fingerprint: str,
    requirement_id: str,
) -> BaselineCorrectionRecordV1:
    payload: dict[str, object] = {
        "schema_version": "baseline-correction-v1",
        "prior_baseline_root": prior_root,
        "prior_baseline_fingerprint": prior_fingerprint,
        "correction_id": "CORR-0002",
        "actions": (
            {"action": "remove_requirement", "requirement_id": requirement_id},
        ),
        "reason": "The second requirement needs a separate attorney-approved baseline revision.",
        "attorney_approval": {
            "approved_by": "Fictional Reviewing Attorney",
            "approved_at": "2026-08-24T20:30:00-07:00",
            "approval_statement": "I approve this source-bound baseline correction.",
        },
        "correction_fingerprint": "0" * 64,
    }
    provisional = BaselineCorrectionRecordV1.model_validate(payload)
    payload["correction_fingerprint"] = sha256_digest(
        canonical_json_bytes(
            provisional.model_dump(mode="json", exclude={"correction_fingerprint"})
        )
    )
    return BaselineCorrectionRecordV1.model_validate(payload)


def test_verified_prior_creates_new_sibling_correction_without_mutation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    baseline_input, files_by_path, manifest = _complete_graph()
    prior_dir = tmp_path / "prior"
    initialize_baseline_storage_v1(prior_dir, manifest, files_by_path)
    prior = load_verified_baseline_run(prior_dir)
    before = _snapshot(prior_dir)
    text = baseline_input.sources[0].normalized_text
    quote = "must identify the operator"
    start = text.find(quote)
    added = BaselineRequirementV1(
        requirement_id="REQ-9999",
        canonical_order=999,
        statement="The notice must identify the operator.",
        kind="obligation",
        importance="material",
        importance_basis=("attorney_briefing",),
        importance_rationale="The detail is necessary for a competent attorney briefing.",
        passages=(
            {
                "source_id": "rule-1",
                "quote": quote,
                "start_char": start,
                "end_char": start + len(quote),
            },
        ),
        confidence="clear",
        substantive_rationale="The source expressly identifies the required content.",
    )
    correction = _correction(
        prior.manifest.root_hash,
        prior.baseline.baseline_fingerprint,
        added,
    )
    corrected = apply_baseline_correction_v1(
        prior.baseline_input,
        prior.baseline,
        correction,
        prior_baseline_root=prior.manifest.root_hash,
    )
    sibling_dir = tmp_path / "corrected"
    baseline_artifacts.initialize_corrected_baseline_storage_v1(
        prior_dir,
        sibling_dir,
        correction,
    )

    loaded = load_verified_baseline_run(sibling_dir, prior_run_dir=prior_dir)
    assert loaded.baseline == corrected
    assert loaded.baseline.prior_baseline_fingerprint == prior.baseline.baseline_fingerprint
    assert loaded.baseline.correction_record_fingerprint == correction.correction_fingerprint
    assert set(_snapshot(sibling_dir)) == {
        BASELINE_MANIFEST_PATH,
        BASELINE_INPUT_PATH,
        BASELINE_CORRECTION_PATH,
        CANONICAL_BASELINE_PATH,
        BASELINE_VERIFICATION_PATH,
    }
    assert _snapshot(prior_dir) == before

    original = shared_artifacts._PosixRunStorage.atomic_write

    def crash_after_correction(
        storage: object, path: str, data: bytes, *, mutable: bool
    ) -> bool:
        created = original(storage, path, data, mutable=mutable)  # type: ignore[arg-type]
        if path == BASELINE_CORRECTION_PATH:
            raise OSError("injected correction creation crash")
        return created

    monkeypatch.setattr(
        shared_artifacts._PosixRunStorage,
        "atomic_write",
        crash_after_correction,
    )
    with pytest.raises(EvaluationIntegrityError):
        baseline_artifacts.initialize_corrected_baseline_storage_v1(
            prior_dir,
            tmp_path / "corrected-crash",
            correction,
        )
    assert _snapshot(prior_dir) == before


def test_correction_requires_the_exact_verified_prior_sibling(tmp_path: Path) -> None:
    baseline_input, files_by_path, manifest = _complete_graph()
    prior_dir = tmp_path / "prior"
    initialize_baseline_storage_v1(prior_dir, manifest, files_by_path)
    prior = load_verified_baseline_run(prior_dir)
    source_text = baseline_input.sources[0].normalized_text
    quote = "must identify the operator"
    start = source_text.find(quote)
    requirement = prior.baseline.requirements[0].model_copy(
        update={
            "requirement_id": "REQ-9999",
            "canonical_order": 999,
            "statement": "The notice must identify the operator.",
            "passages": (
                {
                    "source_id": "rule-1",
                    "quote": quote,
                    "start_char": start,
                    "end_char": start + len(quote),
                },
            ),
        }
    )
    correction = _correction(
        prior.manifest.root_hash,
        prior.baseline.baseline_fingerprint,
        requirement,
    )
    sibling_dir = tmp_path / "corrected"
    baseline_artifacts.initialize_corrected_baseline_storage_v1(
        prior_dir,
        sibling_dir,
        correction,
    )

    assert not verify_baseline_run(sibling_dir).valid
    with pytest.raises(EvaluationIntegrityError):
        load_verified_baseline_run(sibling_dir)
    missing = tmp_path / "missing-prior"
    assert not verify_baseline_run(sibling_dir, prior_run_dir=missing).valid
    with pytest.raises(EvaluationIntegrityError):
        load_verified_baseline_run(sibling_dir, prior_run_dir=missing)
    assert verify_baseline_run(sibling_dir, prior_run_dir=prior_dir).valid
    assert (
        load_verified_baseline_run(sibling_dir, prior_run_dir=prior_dir).baseline
        .prior_baseline_fingerprint
        == prior.baseline.baseline_fingerprint
    )


def test_correction_accepts_an_authentic_verified_inconclusive_prior(
    tmp_path: Path,
) -> None:
    baseline_input, files_by_path, terminal_manifest = _complete_graph()
    prior_dir = tmp_path / "inconclusive-prior"
    initialize_baseline_storage_v1(
        prior_dir,
        _manifest(
            baseline_input,
            BaselinePhaseV1.INCONCLUSIVE,
            baseline_fingerprint=terminal_manifest.baseline_fingerprint,
            terminal_status="INCONCLUSIVE",
        ),
        files_by_path,
    )
    prior = load_verified_baseline_run(prior_dir)
    text = baseline_input.sources[0].normalized_text
    quote = "must identify the operator"
    start = text.find(quote)
    added = BaselineRequirementV1(
        requirement_id="REQ-9999",
        canonical_order=999,
        statement="The notice must identify the operator.",
        kind="obligation",
        importance="material",
        importance_basis=("attorney_briefing",),
        importance_rationale="The detail is necessary for a competent attorney briefing.",
        passages=(
            {
                "source_id": "rule-1",
                "quote": quote,
                "start_char": start,
                "end_char": start + len(quote),
            },
        ),
        confidence="clear",
        substantive_rationale="The source expressly identifies the required content.",
    )
    correction = _correction(
        prior.manifest.root_hash,
        prior.baseline.baseline_fingerprint,
        added,
    )
    sibling_dir = tmp_path / "corrected-from-inconclusive"

    baseline_artifacts.initialize_corrected_baseline_storage_v1(
        prior_dir,
        sibling_dir,
        correction,
    )

    assert verify_baseline_run(sibling_dir, prior_run_dir=prior_dir).valid
    assert (
        load_verified_baseline_run(sibling_dir, prior_run_dir=prior_dir)
        .manifest.prior_baseline_root
        == prior.manifest.root_hash
    )


def test_two_hop_correction_chain_requires_explicit_verified_ancestry(
    tmp_path: Path,
) -> None:
    baseline_input, files_by_path, manifest = _complete_graph()
    p0_dir = tmp_path / "p0"
    initialize_baseline_storage_v1(p0_dir, manifest, files_by_path)
    p0 = load_verified_baseline_run(p0_dir)
    p0_before = _snapshot(p0_dir)

    text = baseline_input.sources[0].normalized_text
    quote = "must identify the operator"
    start = text.find(quote)
    added = BaselineRequirementV1(
        requirement_id="REQ-9999",
        canonical_order=999,
        statement="The notice must identify the operator.",
        kind="obligation",
        importance="material",
        importance_basis=("attorney_briefing",),
        importance_rationale="The detail is necessary for a competent attorney briefing.",
        passages=(
            {
                "source_id": "rule-1",
                "quote": quote,
                "start_char": start,
                "end_char": start + len(quote),
            },
        ),
        confidence="clear",
        substantive_rationale="The source expressly identifies the required content.",
    )
    first_correction = _correction(
        p0.manifest.root_hash,
        p0.baseline.baseline_fingerprint,
        added,
    )
    p1_dir = tmp_path / "p1"
    baseline_artifacts.initialize_corrected_baseline_storage_v1(
        p0_dir,
        p1_dir,
        first_correction,
    )
    p1 = load_verified_baseline_run(p1_dir, prior_run_dir=p0_dir)
    p1_before = _snapshot(p1_dir)
    second_correction = _removal_correction(
        p1.manifest.root_hash,
        p1.baseline.baseline_fingerprint,
        "REQ-0002",
    )
    wrong_ancestor_dir = tmp_path / "wrong-ancestor"
    initialize_baseline_storage_v1(
        wrong_ancestor_dir,
        _manifest(
            baseline_input,
            BaselinePhaseV1.INCONCLUSIVE,
            baseline_fingerprint=p0.baseline.baseline_fingerprint,
            terminal_status="INCONCLUSIVE",
        ),
        files_by_path,
    )
    p2_dir = tmp_path / "p2"

    baseline_artifacts.initialize_corrected_baseline_storage_v1(
        p1_dir,
        p2_dir,
        second_correction,
        prior_ancestry=(p0_dir,),
    )

    assert not verify_baseline_run(p2_dir, prior_run_dir=p1_dir).valid
    with pytest.raises(EvaluationIntegrityError):
        load_verified_baseline_run(p2_dir, prior_run_dir=p1_dir)
    assert not verify_baseline_run(
        p2_dir,
        prior_run_dir=p1_dir,
        prior_ancestry=(wrong_ancestor_dir,),
    ).valid
    with pytest.raises(EvaluationIntegrityError):
        load_verified_baseline_run(
            p2_dir,
            prior_run_dir=p1_dir,
            prior_ancestry=(wrong_ancestor_dir,),
        )
    assert verify_baseline_run(
        p2_dir,
        prior_run_dir=p1_dir,
        prior_ancestry=(p0_dir,),
    ).valid
    p2 = load_verified_baseline_run(
        p2_dir,
        prior_run_dir=p1_dir,
        prior_ancestry=(p0_dir,),
    )
    assert len(p2.baseline.requirements) == 1
    assert p2.manifest.prior_baseline_root == p1.manifest.root_hash
    assert _snapshot(p0_dir) == p0_before
    assert _snapshot(p1_dir) == p1_before


def test_unexpected_or_noncanonical_artifact_is_refused(tmp_path: Path) -> None:
    _, files_by_path, manifest = _complete_graph()
    run_dir = tmp_path / "unexpected"
    initialize_baseline_storage_v1(run_dir, manifest, files_by_path)
    (run_dir / "unexpected.json").write_bytes(b"{}")
    assert not verify_baseline_run(run_dir).valid

    duplicate_dir = tmp_path / "duplicate-key"
    initialize_baseline_storage_v1(duplicate_dir, manifest, files_by_path)
    target = duplicate_dir / BASELINE_VERIFICATION_PATH
    target.chmod(0o600)
    target.write_bytes(b'{"issues":[],"issues":[],"valid":true}')
    assert not verify_baseline_run(duplicate_dir).valid
