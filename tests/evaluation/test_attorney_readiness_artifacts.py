"""Immutable storage and exact replay for ``delivery-readiness-v1``."""

from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Literal

import pytest
from test_attorney_readiness_drafts import (
    _contested_draft,
    _ordinary_draft,
    _provenance,
    _referee_draft,
    _safety_draft,
)
from test_attorney_readiness_requests import inputs as _request_inputs_fixture

from regulatory_harvest.evaluation import attorney_artifacts as shared_artifacts
from regulatory_harvest.evaluation import (
    attorney_readiness_artifacts as readiness_artifacts,
)
from regulatory_harvest.evaluation.attorney_readiness_artifacts import (
    ATTORNEY_HANDOFF_PATH,
    GAP_MATRIX_PATH,
    GRADER_LANE_1_PATH,
    GRADER_LANE_2_PATH,
    HISTORICAL_CROSS_CHECK_PATH,
    READINESS_MANIFEST_PATH,
    READINESS_RESULT_PATH,
    REQUIREMENT_MATRIX_PATH,
    SAFETY_REVIEW_PATH,
    STRICT_EQUIVALENT_PATH,
    _manifest_bytes,
    _manifest_from_bytes,
    _pending_call,
    _with_inventory,
    commit_readiness_transition_v1,
    initialize_readiness_run_storage_v1,
    load_verified_readiness_context_v1,
    load_verified_readiness_run_v1,
    preflight_readiness_response_v1,
    verify_readiness_run_v1,
)
from regulatory_harvest.evaluation.attorney_readiness_compiler import (
    aggregate_baseline_locked_grader_lane_v1,
    compile_gap_follow_up_matrix_v1,
    compile_requirement_matrix_v1,
    derive_baseline_locked_strict_equivalent_v1,
    derive_delivery_readiness_v1,
    reconcile_safety_lanes_v1,
)
from regulatory_harvest.evaluation.attorney_readiness_drafts import (
    CompiledReadinessDraftV1,
    ReadinessEvaluatorProvenanceV1,
    compile_readiness_draft_v1,
)
from regulatory_harvest.evaluation.attorney_readiness_handoff import (
    render_attorney_review_handoff_v1,
)
from regulatory_harvest.evaluation.attorney_readiness_models import (
    BaselineLockedContestedGradeV1,
    BaselineLockedGradeFragmentV1,
    ReadinessEvaluatorResponseV1,
    ReadinessManifestV1,
    ReadinessPhaseV1,
    SafetyLaneResponseV1,
    SafetyRefereeDecisionV1,
)
from regulatory_harvest.evaluation.attorney_readiness_requests import (
    build_baseline_locked_contested_grade_request_v1,
    build_baseline_locked_grade_batches_v1,
    build_baseline_locked_grade_request_v1,
    build_gap_candidate_inventory_v1,
    build_safety_disputes_v1,
    build_safety_lane_request_v1,
    build_safety_referee_request_v1,
)


def test_readiness_manifest_uses_the_canonical_relative_path() -> None:
    assert READINESS_MANIFEST_PATH == "readiness-manifest.json"


def _tree_bytes(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _first_transition_parts(
    tmp_path: Path,
    *,
    judge_isolation: Literal["fresh_context", "scripted_fixture"] = "scripted_fixture",
    context_token_fingerprint: str | None = None,
) -> tuple[Path, ReadinessManifestV1, dict[str, bytes], ReadinessManifestV1]:
    from regulatory_harvest.storage import canonical_json_bytes, sha256_digest

    inputs = _request_inputs_fixture.__wrapped__(tmp_path)
    batches = build_baseline_locked_grade_batches_v1(inputs.gradeable_baseline, lane=1)
    first = build_baseline_locked_grade_request_v1(inputs, batches[0])
    run_dir = tmp_path / "readiness-run"
    manifest = initialize_readiness_run_storage_v1(run_dir, inputs, first)
    provenance = (
        _provenance()
        if judge_isolation == "scripted_fixture"
        else ReadinessEvaluatorProvenanceV1(
            provider_name="public-test-provider",
            model_name="public-test-model",
            judge_isolation="fresh_context",
        )
    )
    compiled = compile_readiness_draft_v1(first, _ordinary_draft(first), provenance)
    assert isinstance(compiled, CompiledReadinessDraftV1)
    response = compiled.response
    response_bytes = canonical_json_bytes(response.model_dump(mode="json"))
    pending = manifest.pending_call
    assert pending is not None
    accepted = pending.model_copy(
        update={
            "state": "accepted",
            "response_artifact_path": f"responses/{pending.call_id}.json",
            "response_fingerprint": sha256_digest(response_bytes),
            "provider_name": response.provider_name,
            "model_name": response.model_name,
            "judge_isolation": response.judge_isolation,
            "context_token_fingerprint": context_token_fingerprint,
        }
    )
    second = build_baseline_locked_grade_request_v1(inputs, batches[1])
    next_call = _pending_call(second)
    files = {
        accepted.response_artifact_path: response_bytes,
        next_call.request_artifact_path: canonical_json_bytes(second.model_dump(mode="json")),
    }
    successor = manifest.model_copy(
        update={
            "accepted_calls": (accepted,),
            "pending_call": next_call,
        }
    )
    return run_dir, manifest, files, successor


def _commit_first_transition(
    tmp_path: Path,
    *,
    context_token_fingerprint: str | None = None,
) -> tuple[Path, ReadinessManifestV1]:
    isolation = "fresh_context" if context_token_fingerprint is not None else "scripted_fixture"
    run_dir, manifest, files, successor = _first_transition_parts(
        tmp_path,
        judge_isolation=isolation,
        context_token_fingerprint=context_token_fingerprint,
    )
    committed = commit_readiness_transition_v1(
        run_dir,
        expected_manifest_fingerprint=manifest.manifest_fingerprint,
        files=files,
        successor=successor,
    )
    return run_dir, committed


def _second_transition_parts(
    run_dir: Path,
    manifest: ReadinessManifestV1,
    *,
    context_token_fingerprint: str | None,
) -> tuple[dict[str, bytes], ReadinessManifestV1]:
    from regulatory_harvest.storage import canonical_json_bytes, sha256_digest

    context = load_verified_readiness_context_v1(run_dir)
    request = context.pending_request
    assert request is not None
    provenance = ReadinessEvaluatorProvenanceV1(
        provider_name="public-test-provider",
        model_name="public-test-model",
        judge_isolation=(
            "fresh_context" if context_token_fingerprint is not None else "scripted_fixture"
        ),
    )
    compiled = compile_readiness_draft_v1(request, _ordinary_draft(request), provenance)
    assert isinstance(compiled, CompiledReadinessDraftV1)
    response = compiled.response
    response_bytes = canonical_json_bytes(response.model_dump(mode="json"))
    pending = manifest.pending_call
    assert pending is not None
    accepted = pending.model_copy(
        update={
            "state": "accepted",
            "response_artifact_path": f"responses/{pending.call_id}.json",
            "response_fingerprint": sha256_digest(response_bytes),
            "provider_name": response.provider_name,
            "model_name": response.model_name,
            "judge_isolation": response.judge_isolation,
            "context_token_fingerprint": context_token_fingerprint,
        }
    )
    next_request = readiness_artifacts._grade_requests(context.inputs)[
        len(manifest.accepted_calls) + 1
    ]
    next_call = _pending_call(next_request)
    files = {
        accepted.response_artifact_path: response_bytes,
        next_call.request_artifact_path: canonical_json_bytes(next_request.model_dump(mode="json")),
    }
    successor = manifest.model_copy(
        update={
            "accepted_calls": (*manifest.accepted_calls, accepted),
            "pending_call": next_call,
        }
    )
    return files, successor


def test_initialization_seals_exact_admitted_input_and_first_request(
    tmp_path: Path,
) -> None:
    inputs = _request_inputs_fixture.__wrapped__(tmp_path)
    batch = build_baseline_locked_grade_batches_v1(
        inputs.gradeable_baseline,
        lane=1,
    )[0]
    request = build_baseline_locked_grade_request_v1(inputs, batch)
    before = _tree_bytes(tmp_path)
    run_dir = tmp_path / "readiness-run"

    manifest = initialize_readiness_run_storage_v1(run_dir, inputs, request)

    assert manifest.phase == "baseline_locked_grade"
    assert manifest.pending_call is not None
    assert manifest.pending_call.call_id == "grade-lane-1-GB-1-0001"
    assert set(_tree_bytes(run_dir)) == {
        "readiness-input.json",
        "readiness-manifest.json",
        "readiness-rubric.json",
        "requests/grade-lane-1-GB-1-0001.json",
    }
    verification = verify_readiness_run_v1(run_dir)
    assert verification.valid is True
    loaded_manifest, result = load_verified_readiness_run_v1(run_dir)
    assert loaded_manifest == manifest
    assert result is None
    context = load_verified_readiness_context_v1(run_dir)
    assert context.inputs == inputs
    assert context.pending_request == request
    assert context.result is None
    after = _tree_bytes(tmp_path)
    assert {
        path: data for path, data in after.items() if not path.startswith("readiness-run/")
    } == before


def test_transition_accepts_exact_compiled_response_and_only_next_request(
    tmp_path: Path,
) -> None:
    inputs = _request_inputs_fixture.__wrapped__(tmp_path)
    batches = build_baseline_locked_grade_batches_v1(inputs.gradeable_baseline, lane=1)
    first = build_baseline_locked_grade_request_v1(inputs, batches[0])
    run_dir = tmp_path / "readiness-run"
    manifest = initialize_readiness_run_storage_v1(run_dir, inputs, first)
    compiled = compile_readiness_draft_v1(first, _ordinary_draft(first), _provenance())
    assert isinstance(compiled, CompiledReadinessDraftV1)
    response = compiled.response
    # Artifact code owns canonical serialization; the test deliberately supplies it.
    from regulatory_harvest.storage import canonical_json_bytes, sha256_digest

    response_bytes = canonical_json_bytes(response.model_dump(mode="json"))
    second = build_baseline_locked_grade_request_v1(inputs, batches[1])
    second_bytes = canonical_json_bytes(second.model_dump(mode="json"))
    pending = manifest.pending_call
    assert pending is not None
    accepted = pending.model_copy(
        update={
            "state": "accepted",
            "response_artifact_path": f"responses/{pending.call_id}.json",
            "response_fingerprint": sha256_digest(response_bytes),
            "provider_name": response.provider_name,
            "model_name": response.model_name,
            "judge_isolation": response.judge_isolation,
        }
    )
    successor = manifest.model_copy(
        update={
            "accepted_calls": (accepted,),
            "pending_call": pending.model_copy(
                update={
                    "call_id": "grade-lane-1-GB-1-0002",
                    "request_artifact_path": ("requests/grade-lane-1-GB-1-0002.json"),
                    "request_fingerprint": second.request_fingerprint,
                }
            ),
        }
    )

    committed = commit_readiness_transition_v1(
        run_dir,
        expected_manifest_fingerprint=manifest.manifest_fingerprint,
        files={
            accepted.response_artifact_path: response_bytes,
            successor.pending_call.request_artifact_path: second_bytes,
        },
        successor=successor,
    )

    assert committed.accepted_calls == (accepted,)
    context = load_verified_readiness_context_v1(run_dir)
    assert context.pending_request == second
    assert verify_readiness_run_v1(run_dir).valid is True


def test_fresh_context_token_changes_manifest_root_and_survives_replay(
    tmp_path: Path,
) -> None:
    token_fingerprint = "c" * 64
    run_dir, committed = _commit_first_transition(
        tmp_path,
        context_token_fingerprint=token_fingerprint,
    )
    accepted = committed.accepted_calls[0]
    files = {
        path: data for path, data in _tree_bytes(run_dir).items() if path != READINESS_MANIFEST_PATH
    }
    without_token = _with_inventory(
        committed.model_copy(
            update={
                "accepted_calls": (accepted.model_copy(update={"context_token_fingerprint": None}),)
            }
        ),
        files,
    )

    context = load_verified_readiness_context_v1(run_dir)
    loaded_manifest, loaded_result = load_verified_readiness_run_v1(run_dir)
    raw_manifest = json.loads((run_dir / READINESS_MANIFEST_PATH).read_bytes())

    assert committed.manifest_fingerprint != without_token.manifest_fingerprint
    assert committed.root_hash != without_token.root_hash
    assert context.manifest.accepted_calls[0].context_token_fingerprint == token_fingerprint
    assert loaded_manifest.accepted_calls[0].context_token_fingerprint == token_fingerprint
    assert loaded_result is None
    assert raw_manifest["accepted_calls"][0]["context_token_fingerprint"] == token_fingerprint
    assert verify_readiness_run_v1(run_dir).valid is True


def test_backward_compatible_none_token_is_omitted_from_raw_manifest(tmp_path: Path) -> None:
    run_dir, committed = _commit_first_transition(tmp_path)

    raw_manifest = json.loads((run_dir / READINESS_MANIFEST_PATH).read_bytes())
    context = load_verified_readiness_context_v1(run_dir)

    assert "context_token_fingerprint" not in raw_manifest["accepted_calls"][0]
    assert committed.accepted_calls[0].context_token_fingerprint is None
    assert context.manifest.accepted_calls[0].context_token_fingerprint is None


def test_noncanonical_explicit_null_token_in_raw_manifest_is_rejected(tmp_path: Path) -> None:
    from regulatory_harvest.storage import canonical_json_bytes

    run_dir, _ = _commit_first_transition(tmp_path)
    raw_manifest = json.loads((run_dir / READINESS_MANIFEST_PATH).read_bytes())
    raw_manifest["accepted_calls"][0]["context_token_fingerprint"] = None
    (run_dir / READINESS_MANIFEST_PATH).write_bytes(canonical_json_bytes(raw_manifest))

    verification = verify_readiness_run_v1(run_dir)

    assert verification.valid is False
    assert verification.issues == ("READINESS_ARTIFACT_INVALID",)


def test_raw_context_token_tamper_without_original_root_is_rejected(tmp_path: Path) -> None:
    token_fingerprint = "c" * 64
    run_dir, _ = _commit_first_transition(
        tmp_path,
        context_token_fingerprint=token_fingerprint,
    )
    manifest_path = run_dir / READINESS_MANIFEST_PATH
    original = manifest_path.read_bytes()
    raw_manifest = json.loads(original)
    raw_manifest["accepted_calls"][0]["context_token_fingerprint"] = "d" * 64
    from regulatory_harvest.storage import canonical_json_bytes

    manifest_path.write_bytes(canonical_json_bytes(raw_manifest))

    assert verify_readiness_run_v1(run_dir).valid is False

    manifest_path.write_bytes(original)
    assert verify_readiness_run_v1(run_dir).valid is True


def test_truncated_context_token_is_rejected_after_raw_manifest_reseal(
    tmp_path: Path,
) -> None:
    from regulatory_harvest.storage import canonical_json_bytes, sha256_digest

    run_dir, _ = _commit_first_transition(
        tmp_path,
        context_token_fingerprint="c" * 64,
    )
    raw_manifest = json.loads((run_dir / READINESS_MANIFEST_PATH).read_bytes())
    raw_manifest["accepted_calls"][0]["context_token_fingerprint"] = "c" * 63
    fingerprint_input = {
        key: value
        for key, value in raw_manifest.items()
        if key not in {"manifest_fingerprint", "root_hash"}
    }
    raw_manifest["manifest_fingerprint"] = sha256_digest(canonical_json_bytes(fingerprint_input))
    root_input = {key: value for key, value in raw_manifest.items() if key != "root_hash"}
    raw_manifest["root_hash"] = sha256_digest(canonical_json_bytes(root_input))
    (run_dir / READINESS_MANIFEST_PATH).write_bytes(canonical_json_bytes(raw_manifest))

    verification = verify_readiness_run_v1(run_dir)

    assert verification.valid is False
    assert verification.issues == ("READINESS_ARTIFACT_INVALID",)


@pytest.mark.parametrize("replacement", [None, "e" * 64], ids=("drop", "change"))
def test_resealed_successor_cannot_drop_or_change_an_inherited_context_token(
    tmp_path: Path,
    replacement: str | None,
) -> None:
    run_dir, committed = _commit_first_transition(
        tmp_path,
        context_token_fingerprint="c" * 64,
    )
    files, successor = _second_transition_parts(
        run_dir,
        committed,
        context_token_fingerprint="d" * 64,
    )
    inherited = successor.accepted_calls[0].model_copy(
        update={"context_token_fingerprint": replacement}
    )
    forged = successor.model_copy(
        update={"accepted_calls": (inherited, successor.accepted_calls[-1])}
    )
    before = _tree_bytes(run_dir)

    with pytest.raises(
        shared_artifacts.EvaluationIntegrityError,
        match="READINESS_STALE_TRANSITION",
    ):
        commit_readiness_transition_v1(
            run_dir,
            expected_manifest_fingerprint=committed.manifest_fingerprint,
            files=files,
            successor=forged,
        )

    assert _tree_bytes(run_dir) == before


def test_resealed_fresh_context_call_reorder_is_rejected(tmp_path: Path) -> None:
    run_dir, first = _commit_first_transition(
        tmp_path,
        context_token_fingerprint="c" * 64,
    )
    files, successor = _second_transition_parts(
        run_dir,
        first,
        context_token_fingerprint="d" * 64,
    )
    second = commit_readiness_transition_v1(
        run_dir,
        expected_manifest_fingerprint=first.manifest_fingerprint,
        files=files,
        successor=successor,
    )
    all_files = {
        path: data for path, data in _tree_bytes(run_dir).items() if path != READINESS_MANIFEST_PATH
    }
    reordered = _with_inventory(
        second.model_copy(update={"accepted_calls": tuple(reversed(second.accepted_calls))}),
        all_files,
    )
    (run_dir / READINESS_MANIFEST_PATH).write_bytes(_manifest_bytes(reordered))

    verification = verify_readiness_run_v1(run_dir)

    assert verification.valid is False
    assert verification.issues == ("READINESS_SEMANTIC_REPLAY_INVALID",)


def test_transition_rejects_a_context_token_reused_by_the_just_accepted_call(
    tmp_path: Path,
) -> None:
    run_dir, first = _commit_first_transition(
        tmp_path,
        context_token_fingerprint="c" * 64,
    )
    files, duplicate_successor = _second_transition_parts(
        run_dir,
        first,
        context_token_fingerprint="c" * 64,
    )
    before = _tree_bytes(run_dir)

    with pytest.raises(ValueError, match="readiness manifest is invalid"):
        commit_readiness_transition_v1(
            run_dir,
            expected_manifest_fingerprint=first.manifest_fingerprint,
            files=files,
            successor=duplicate_successor,
        )

    assert _tree_bytes(run_dir) == before


def test_canonically_resealed_duplicate_context_tokens_fail_task7_replay(
    tmp_path: Path,
) -> None:
    from regulatory_harvest.storage import canonical_json_bytes, sha256_digest

    run_dir, first = _commit_first_transition(
        tmp_path,
        context_token_fingerprint="c" * 64,
    )
    files, successor = _second_transition_parts(
        run_dir,
        first,
        context_token_fingerprint="d" * 64,
    )
    commit_readiness_transition_v1(
        run_dir,
        expected_manifest_fingerprint=first.manifest_fingerprint,
        files=files,
        successor=successor,
    )
    raw_manifest = json.loads((run_dir / READINESS_MANIFEST_PATH).read_bytes())
    raw_manifest["accepted_calls"][1]["context_token_fingerprint"] = "c" * 64
    fingerprint_input = {
        key: value
        for key, value in raw_manifest.items()
        if key not in {"manifest_fingerprint", "root_hash"}
    }
    raw_manifest["manifest_fingerprint"] = sha256_digest(canonical_json_bytes(fingerprint_input))
    root_input = {key: value for key, value in raw_manifest.items() if key != "root_hash"}
    raw_manifest["root_hash"] = sha256_digest(canonical_json_bytes(root_input))
    (run_dir / READINESS_MANIFEST_PATH).write_bytes(canonical_json_bytes(raw_manifest))

    verification = verify_readiness_run_v1(run_dir)

    assert verification.valid is False
    assert verification.issues == ("READINESS_ARTIFACT_INVALID",)


def test_repeated_none_context_tokens_remain_replay_compatible(tmp_path: Path) -> None:
    run_dir, first = _commit_first_transition(tmp_path)
    files, successor = _second_transition_parts(
        run_dir,
        first,
        context_token_fingerprint=None,
    )

    second = commit_readiness_transition_v1(
        run_dir,
        expected_manifest_fingerprint=first.manifest_fingerprint,
        files=files,
        successor=successor,
    )
    loaded, result = load_verified_readiness_run_v1(run_dir)
    raw_manifest = json.loads((run_dir / READINESS_MANIFEST_PATH).read_bytes())

    assert tuple(call.context_token_fingerprint for call in second.accepted_calls) == (None, None)
    assert tuple(call.context_token_fingerprint for call in loaded.accepted_calls) == (None, None)
    assert all("context_token_fingerprint" not in call for call in raw_manifest["accepted_calls"])
    assert result is None
    assert verify_readiness_run_v1(run_dir).valid is True


def test_external_context_control_ledger_is_not_task7_replay_authority(
    tmp_path: Path,
) -> None:
    run_dir, committed = _commit_first_transition(
        tmp_path,
        context_token_fingerprint="c" * 64,
    )
    context = load_verified_readiness_context_v1(run_dir)
    ledger = run_dir.parent / (
        f".readiness-context-{context.root_identity[0]:x}-{context.root_identity[1]:x}.tokens"
    )

    assert not ledger.exists()
    assert verify_readiness_run_v1(run_dir).valid is True
    ledger.write_bytes(b"I:")
    assert verify_readiness_run_v1(run_dir).valid is True
    ledger.write_bytes(
        (f"I:{committed.accepted_calls[0].request_fingerprint}:{'e' * 64}\n").encode("ascii")
    )
    assert verify_readiness_run_v1(run_dir).valid is True


@pytest.mark.parametrize(
    "boundary",
    ["before_artifact", "after_artifact", "before_manifest", "after_manifest"],
)
def test_transition_rolls_back_every_durable_boundary(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boundary: str,
) -> None:
    run_dir, manifest, files, successor = _first_transition_parts(tmp_path)
    before = _tree_bytes(run_dir)
    response_path = next(path for path in files if path.startswith("responses/"))
    original = shared_artifacts._PosixRunStorage.atomic_write

    def inject(storage: object, path: str, data: bytes, *, mutable: bool) -> bool:
        if boundary == "before_artifact" and path == response_path:
            raise OSError("injected before artifact durability")
        if boundary == "before_manifest" and path == READINESS_MANIFEST_PATH:
            raise OSError("injected before manifest durability")
        written = original(storage, path, data, mutable=mutable)  # type: ignore[arg-type]
        if boundary == "after_artifact" and path == response_path:
            raise OSError("injected after artifact durability")
        if boundary == "after_manifest" and path == READINESS_MANIFEST_PATH:
            raise OSError("injected after manifest durability")
        return written

    monkeypatch.setattr(shared_artifacts._PosixRunStorage, "atomic_write", inject)
    with pytest.raises(shared_artifacts.EvaluationIntegrityError):
        commit_readiness_transition_v1(
            run_dir,
            expected_manifest_fingerprint=manifest.manifest_fingerprint,
            files=files,
            successor=successor,
        )
    assert _tree_bytes(run_dir) == before
    assert verify_readiness_run_v1(run_dir).valid is True


def test_transition_rolls_back_after_post_commit_replay_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    run_dir, manifest, files, successor = _first_transition_parts(tmp_path)
    before = _tree_bytes(run_dir)
    original = readiness_artifacts._verify_or_raise
    calls = 0

    def fail_second(storage: object) -> object:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected post-commit replay")
        return original(storage)  # type: ignore[arg-type]

    monkeypatch.setattr(readiness_artifacts, "_verify_or_raise", fail_second)
    with pytest.raises(shared_artifacts.EvaluationIntegrityError):
        commit_readiness_transition_v1(
            run_dir,
            expected_manifest_fingerprint=manifest.manifest_fingerprint,
            files=files,
            successor=successor,
        )
    assert calls == 2
    assert _tree_bytes(run_dir) == before


def test_initialization_rolls_back_a_post_fsync_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs = _request_inputs_fixture.__wrapped__(tmp_path)
    batch = build_baseline_locked_grade_batches_v1(inputs.gradeable_baseline, lane=1)[0]
    request = build_baseline_locked_grade_request_v1(inputs, batch)
    run_dir = tmp_path / "readiness-run"
    original = shared_artifacts._PosixRunStorage.atomic_write
    failed = False

    def inject(storage: object, path: str, data: bytes, *, mutable: bool) -> bool:
        nonlocal failed
        written = original(storage, path, data, mutable=mutable)  # type: ignore[arg-type]
        if path == "readiness-input.json" and not failed:
            failed = True
            raise OSError("injected initialization crash")
        return written

    monkeypatch.setattr(shared_artifacts._PosixRunStorage, "atomic_write", inject)
    with pytest.raises(shared_artifacts.EvaluationIntegrityError):
        initialize_readiness_run_storage_v1(run_dir, inputs, request)
    assert failed
    assert _tree_bytes(run_dir) == {}


def test_stale_and_destination_competitor_transitions_are_write_free(
    tmp_path: Path,
) -> None:
    run_dir, manifest, files, successor = _first_transition_parts(tmp_path)
    before = _tree_bytes(run_dir)
    with pytest.raises(shared_artifacts.EvaluationIntegrityError, match="STALE_TRANSITION"):
        commit_readiness_transition_v1(
            run_dir,
            expected_manifest_fingerprint="0" * 64,
            files=files,
            successor=successor,
        )
    assert _tree_bytes(run_dir) == before

    competitor = next(path for path in files if path.startswith("responses/"))
    destination = run_dir / competitor
    destination.parent.mkdir(exist_ok=True)
    destination.write_bytes(b"{}")
    competed = _tree_bytes(run_dir)
    with pytest.raises(shared_artifacts.EvaluationIntegrityError):
        commit_readiness_transition_v1(
            run_dir,
            expected_manifest_fingerprint=manifest.manifest_fingerprint,
            files=files,
            successor=successor,
        )
    assert _tree_bytes(run_dir) == competed


@pytest.mark.skipif(os.name != "posix", reason="POSIX root replacement proof")
def test_transition_never_mutates_a_replacement_root(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    run_dir, manifest, files, successor = _first_transition_parts(tmp_path)
    replacement = tmp_path / "replacement"
    replacement.mkdir()
    sentinel = replacement / "outside.txt"
    sentinel.write_bytes(b"outside\n")
    parked = tmp_path / "parked"
    trigger = Path(next(iter(sorted(files)))).name
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
        if not swapped and destination == trigger:
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
    with pytest.raises(shared_artifacts.EvaluationIntegrityError):
        commit_readiness_transition_v1(
            run_dir,
            expected_manifest_fingerprint=manifest.manifest_fingerprint,
            files=files,
            successor=successor,
        )
    assert swapped
    assert (run_dir / "outside.txt").read_bytes() == b"outside\n"
    assert set(_tree_bytes(run_dir)) == {"outside.txt"}


@pytest.mark.parametrize(
    "hostile",
    [None, True, 1, "response", [], {}, {"payload": object()}],
)
def test_preflight_is_total_and_write_free_for_hostile_values(
    tmp_path: Path,
    hostile: object,
) -> None:
    inputs = _request_inputs_fixture.__wrapped__(tmp_path)
    batch = build_baseline_locked_grade_batches_v1(inputs.gradeable_baseline, lane=1)[0]
    request = build_baseline_locked_grade_request_v1(inputs, batch)
    run_dir = tmp_path / "readiness-run"
    initialize_readiness_run_storage_v1(run_dir, inputs, request)
    before = _tree_bytes(run_dir)

    result = preflight_readiness_response_v1(run_dir, hostile)

    assert result.valid is False
    assert result.diagnostics == ("READINESS_EXTERNAL_RESPONSE_INVALID",)
    assert _tree_bytes(run_dir) == before


def test_preflight_contains_an_ordinary_runtime_failure_and_is_write_free(
    tmp_path: Path,
) -> None:
    class ExplodingResponse(ReadinessEvaluatorResponseV1):
        def model_dump(self, *args: object, **kwargs: object) -> dict[str, object]:
            raise RuntimeError("boom")

    inputs = _request_inputs_fixture.__wrapped__(tmp_path)
    batch = build_baseline_locked_grade_batches_v1(inputs.gradeable_baseline, lane=1)[0]
    request = build_baseline_locked_grade_request_v1(inputs, batch)
    compiled = compile_readiness_draft_v1(request, _ordinary_draft(request), _provenance())
    assert isinstance(compiled, CompiledReadinessDraftV1)
    hostile = ExplodingResponse.model_construct(**compiled.response.model_dump(mode="python"))
    run_dir = tmp_path / "readiness-run"
    initialize_readiness_run_storage_v1(run_dir, inputs, request)
    before = _tree_bytes(run_dir)

    result = preflight_readiness_response_v1(run_dir, hostile)

    assert result.valid is False
    assert result.diagnostics == ("READINESS_EXTERNAL_RESPONSE_INVALID",)
    assert _tree_bytes(run_dir) == before


def test_generation_validation_tamper_fails_even_after_outer_manifest_reseal(
    tmp_path: Path,
) -> None:
    from regulatory_harvest.storage import canonical_json_bytes

    inputs = _request_inputs_fixture.__wrapped__(tmp_path)
    batch = build_baseline_locked_grade_batches_v1(inputs.gradeable_baseline, lane=1)[0]
    request = build_baseline_locked_grade_request_v1(inputs, batch)
    run_dir = tmp_path / "readiness-run"
    initialize_readiness_run_storage_v1(run_dir, inputs, request)
    wire = json.loads((run_dir / "readiness-input.json").read_bytes())
    wire["readiness_input"]["generation_validation"]["receipt_hash"] = "f" * 64
    (run_dir / "readiness-input.json").write_bytes(canonical_json_bytes(wire))
    manifest = _manifest_from_bytes((run_dir / READINESS_MANIFEST_PATH).read_bytes())
    files = {
        path: data for path, data in _tree_bytes(run_dir).items() if path != READINESS_MANIFEST_PATH
    }
    resealed = _with_inventory(manifest, files)
    (run_dir / READINESS_MANIFEST_PATH).write_bytes(_manifest_bytes(resealed))

    verification = verify_readiness_run_v1(run_dir)

    assert verification.valid is False
    assert verification.issues == ("READINESS_SEMANTIC_REPLAY_INVALID",)


def test_resealed_malformed_response_returns_a_bounded_invalid_verification(
    tmp_path: Path,
) -> None:
    from regulatory_harvest.storage import canonical_json_bytes, sha256_digest

    run_dir, manifest, files, successor = _first_transition_parts(tmp_path)
    committed = commit_readiness_transition_v1(
        run_dir,
        expected_manifest_fingerprint=manifest.manifest_fingerprint,
        files=files,
        successor=successor,
    )
    accepted = committed.accepted_calls[0]
    assert accepted.response_artifact_path is not None
    response_path = accepted.response_artifact_path
    response_wire = json.loads((run_dir / response_path).read_bytes())
    response_wire["payload"] = {}
    response_bytes = canonical_json_bytes(response_wire)
    all_files = {
        path: data for path, data in _tree_bytes(run_dir).items() if path != READINESS_MANIFEST_PATH
    }
    all_files[response_path] = response_bytes
    accepted_calls = (
        accepted.model_copy(update={"response_fingerprint": sha256_digest(response_bytes)}),
    )
    resealed = _with_inventory(
        committed.model_copy(update={"accepted_calls": accepted_calls}), all_files
    )
    (run_dir / response_path).write_bytes(response_bytes)
    (run_dir / READINESS_MANIFEST_PATH).write_bytes(_manifest_bytes(resealed))

    verification = verify_readiness_run_v1(run_dir)

    assert verification.valid is False
    assert verification.issues == ("READINESS_SEMANTIC_REPLAY_INVALID",)


def test_unexpected_links_fifo_and_concurrent_verification_are_fail_closed(
    tmp_path: Path,
) -> None:
    inputs = _request_inputs_fixture.__wrapped__(tmp_path)
    batch = build_baseline_locked_grade_batches_v1(inputs.gradeable_baseline, lane=1)[0]
    request = build_baseline_locked_grade_request_v1(inputs, batch)
    run_dir = tmp_path / "readiness-run"
    initialize_readiness_run_storage_v1(run_dir, inputs, request)
    with ThreadPoolExecutor(max_workers=8) as executor:
        results = tuple(executor.map(lambda _: verify_readiness_run_v1(run_dir), range(32)))
    assert all(item.valid for item in results)

    extra = run_dir / "orphan.json"
    extra.symlink_to(run_dir / "readiness-input.json")
    assert verify_readiness_run_v1(run_dir).valid is False
    extra.unlink()
    os.link(run_dir / "readiness-input.json", extra)
    assert verify_readiness_run_v1(run_dir).valid is False
    extra.unlink()
    if hasattr(os, "mkfifo"):
        os.mkfifo(extra)
        assert verify_readiness_run_v1(run_dir).valid is False
        extra.unlink()
    assert verify_readiness_run_v1(run_dir).valid is True


def test_full_lifecycle_replays_every_derived_terminal_byte(tmp_path: Path) -> None:
    from test_attorney_readiness_inputs import _make_verified_inputs

    from regulatory_harvest.evaluation.attorney_readiness_inputs import (
        build_verified_readiness_input_v1,
    )
    from regulatory_harvest.storage import canonical_json_bytes, sha256_digest

    source = _make_verified_inputs(tmp_path)
    source_before = {
        path: _tree_bytes(path)
        for path in (
            source.baseline_run_dir,
            source.qualification_run_dir,
            source.generation_run_dir,
        )
    }
    inputs = build_verified_readiness_input_v1(
        baseline_run_dir=source.baseline_run_dir,
        qualification_run_dir=source.qualification_run_dir,
        generation_run_dir=source.generation_run_dir,
        validation_receipt_path=source.validation_receipt_path,
    )
    grade_requests = []
    contest_ids = tuple(
        item.contested_requirement.contested_requirement_id
        for item in inputs.gradeable_baseline.contested_requirements
    )
    for lane in (1, 2):
        grade_requests.extend(
            build_baseline_locked_grade_request_v1(inputs, batch)
            for batch in build_baseline_locked_grade_batches_v1(
                inputs.gradeable_baseline, lane=lane
            )
        )
        grade_requests.extend(
            build_baseline_locked_contested_grade_request_v1(
                inputs, lane=lane, contested_requirement_id=contest_id
            )
            for contest_id in contest_ids
        )
    run_dir = tmp_path / "readiness-run"
    manifest = initialize_readiness_run_storage_v1(run_dir, inputs, grade_requests[0])
    ordinary = {1: [], 2: []}
    contested = {1: [], 2: []}
    safety_lanes: list[SafetyLaneResponseV1] = []
    decisions: list[SafetyRefereeDecisionV1] = []
    grader_lanes = None
    strict = None
    candidates = None
    disputes = ()

    while manifest.pending_call is not None:
        request = load_verified_readiness_context_v1(run_dir).pending_request
        assert request is not None
        draft = {
            "baseline_locked_grade": _ordinary_draft,
            "baseline_locked_contested_grade": _contested_draft,
            "safety_review": _safety_draft,
            "safety_referee": _referee_draft,
        }[request.operation.value](request)
        if request.operation.value == "safety_review" and request.payload["lane"] == 2:
            draft["candidate_assessments"][0]["owner_role"] = "outside_counsel"  # type: ignore[index]
        compiled = compile_readiness_draft_v1(request, draft, _provenance())
        assert isinstance(compiled, CompiledReadinessDraftV1), (
            manifest.pending_call.call_id,
            compiled,
        )
        response = compiled.response
        before = _tree_bytes(run_dir)
        assert preflight_readiness_response_v1(run_dir, response).valid is True
        assert _tree_bytes(run_dir) == before
        payload = response.payload
        if request.operation.value == "baseline_locked_grade":
            fragment = BaselineLockedGradeFragmentV1.model_validate(payload)
            ordinary[fragment.lane].append(fragment)
        elif request.operation.value == "baseline_locked_contested_grade":
            grade = BaselineLockedContestedGradeV1.model_validate(payload)
            contested[grade.lane].append(grade)
        elif request.operation.value == "safety_review":
            safety_lanes.append(SafetyLaneResponseV1.model_validate(payload))
        else:
            decisions.append(SafetyRefereeDecisionV1.model_validate(payload))

        accepted = manifest.pending_call.model_copy(
            update={
                "state": "accepted",
                "response_artifact_path": f"responses/{manifest.pending_call.call_id}.json",
                "response_fingerprint": sha256_digest(
                    canonical_json_bytes(response.model_dump(mode="json"))
                ),
                "provider_name": response.provider_name,
                "model_name": response.model_name,
                "judge_isolation": response.judge_isolation,
            }
        )
        files = {
            accepted.response_artifact_path: canonical_json_bytes(response.model_dump(mode="json"))
        }
        accepted_calls = (*manifest.accepted_calls, accepted)
        next_request = None
        phase = ReadinessPhaseV1.BASELINE_LOCKED_GRADE
        updates = {}
        if len(accepted_calls) < len(grade_requests):
            next_request = grade_requests[len(accepted_calls)]
        elif len(accepted_calls) == len(grade_requests):
            grader_lanes = (
                aggregate_baseline_locked_grader_lane_v1(
                    inputs,
                    lane=1,
                    ordinary_fragments=tuple(ordinary[1]),
                    contested_grades=tuple(contested[1]),
                ),
                aggregate_baseline_locked_grader_lane_v1(
                    inputs,
                    lane=2,
                    ordinary_fragments=tuple(ordinary[2]),
                    contested_grades=tuple(contested[2]),
                ),
            )
            strict = derive_baseline_locked_strict_equivalent_v1(
                inputs.gradeable_baseline,
                grader_lanes[0],
                grader_lanes[1],
                inputs.readiness_rubric,
            )
            candidates = build_gap_candidate_inventory_v1(inputs, grader_lanes)
            files.update(
                {
                    GRADER_LANE_1_PATH: canonical_json_bytes(
                        grader_lanes[0].model_dump(mode="json")
                    ),
                    GRADER_LANE_2_PATH: canonical_json_bytes(
                        grader_lanes[1].model_dump(mode="json")
                    ),
                    STRICT_EQUIVALENT_PATH: canonical_json_bytes(strict.model_dump(mode="json")),
                }
            )
            if inputs.historical_v22 is not None:
                files[HISTORICAL_CROSS_CHECK_PATH] = canonical_json_bytes(
                    inputs.historical_v22.model_dump(mode="json")
                )
            updates["baseline_locked_strict_equivalent_fingerprint"] = (
                strict.strict_equivalent_fingerprint
            )
            next_request = build_safety_lane_request_v1(inputs, grader_lanes, candidates, lane=1)
            phase = ReadinessPhaseV1.SAFETY_REVIEW
        elif len(safety_lanes) == 1:
            assert grader_lanes is not None and candidates is not None
            next_request = build_safety_lane_request_v1(inputs, grader_lanes, candidates, lane=2)
            phase = ReadinessPhaseV1.SAFETY_REVIEW
        elif len(safety_lanes) == 2 and not disputes:
            disputes = build_safety_disputes_v1(inputs, *safety_lanes)
            if disputes:
                next_request = build_safety_referee_request_v1(inputs, disputes[0])
                phase = ReadinessPhaseV1.SAFETY_REFEREE
        elif len(decisions) < len(disputes):
            next_request = build_safety_referee_request_v1(inputs, disputes[len(decisions)])
            phase = ReadinessPhaseV1.SAFETY_REFEREE

        if next_request is None:
            assert grader_lanes is not None and strict is not None and candidates is not None
            safety = reconcile_safety_lanes_v1(
                inputs,
                candidates,
                safety_lanes[0],
                safety_lanes[1],
                tuple(decisions),
            )
            requirement = compile_requirement_matrix_v1(inputs, grader_lanes)
            gap = compile_gap_follow_up_matrix_v1(inputs, strict, candidates, safety)
            result = derive_delivery_readiness_v1(
                inputs,
                strict,
                requirement,
                gap,
                safety,
                safety_lanes[0],
                safety_lanes[1],
            )
            files.update(
                {
                    SAFETY_REVIEW_PATH: canonical_json_bytes(safety.model_dump(mode="json")),
                    REQUIREMENT_MATRIX_PATH: canonical_json_bytes(
                        requirement.model_dump(mode="json")
                    ),
                    GAP_MATRIX_PATH: canonical_json_bytes(gap.model_dump(mode="json")),
                    READINESS_RESULT_PATH: canonical_json_bytes(result.model_dump(mode="json")),
                    ATTORNEY_HANDOFF_PATH: render_attorney_review_handoff_v1(
                        report_text=inputs.report_text,
                        requirement_matrix=requirement,
                        gap_matrix=gap,
                        result=result,
                    ),
                }
            )
            updates.update(
                {
                    "phase": ReadinessPhaseV1.COMPLETED,
                    "terminal_status": "COMPLETED",
                    "safety_review_fingerprint": safety.safety_review_fingerprint,
                    "requirement_matrix_fingerprint": requirement.matrix_fingerprint,
                    "gap_matrix_fingerprint": gap.matrix_fingerprint,
                    "result_fingerprint": result.result_fingerprint,
                }
            )
        else:
            updates["phase"] = phase
            pending = _pending_call(next_request)
            files[pending.request_artifact_path] = canonical_json_bytes(
                next_request.model_dump(mode="json")
            )
            updates["pending_call"] = pending
        if next_request is None:
            updates["pending_call"] = None
        successor = manifest.model_copy(update={"accepted_calls": accepted_calls, **updates})
        manifest = commit_readiness_transition_v1(
            run_dir,
            expected_manifest_fingerprint=manifest.manifest_fingerprint,
            files=files,
            successor=successor,
        )

    context = load_verified_readiness_context_v1(run_dir)
    assert context.result is not None
    assert context.verification is not None
    assert context.verification.valid is True
    assert len(context.responses) == len(context.manifest.accepted_calls)
    assert context.grader_lanes is not None
    assert context.strict_equivalent is not None
    assert context.candidates is not None
    assert len(context.safety_lanes) == 2
    assert context.disputes
    assert len(context.referee_decisions) == len(context.disputes)
    assert context.safety_review is not None
    assert context.requirement_matrix is not None
    assert context.gap_matrix is not None
    assert context.handoff == (run_dir / ATTORNEY_HANDOFF_PATH).read_bytes()
    assert all(type(item) is int for item in context.root_identity)
    assert verify_readiness_run_v1(run_dir) == context.verification
    assert {
        path: _tree_bytes(path)
        for path in (
            source.baseline_run_dir,
            source.qualification_run_dir,
            source.generation_run_dir,
        )
    } == source_before
    handoff = run_dir / ATTORNEY_HANDOFF_PATH
    original_handoff = handoff.read_bytes()
    handoff.write_bytes(original_handoff + b"tamper")
    assert verify_readiness_run_v1(run_dir).valid is False
    handoff.write_bytes(original_handoff)
    assert verify_readiness_run_v1(run_dir).valid is True
    orphan = run_dir / "orphan.json"
    orphan.write_bytes(b"{}")
    assert verify_readiness_run_v1(run_dir).valid is False
    orphan.unlink()
    assert verify_readiness_run_v1(run_dir).valid is True

    terminal_snapshot = _tree_bytes(run_dir)
    terminal_manifest = _manifest_from_bytes(terminal_snapshot[READINESS_MANIFEST_PATH])
    terminal_files = {
        path: data for path, data in terminal_snapshot.items() if path != READINESS_MANIFEST_PATH
    }
    reordered_calls = list(terminal_manifest.accepted_calls)
    reordered_calls[0], reordered_calls[1] = reordered_calls[1], reordered_calls[0]
    reordered = _with_inventory(
        terminal_manifest.model_copy(update={"accepted_calls": tuple(reordered_calls)}),
        terminal_files,
    )
    (run_dir / READINESS_MANIFEST_PATH).write_bytes(_manifest_bytes(reordered))
    assert verify_readiness_run_v1(run_dir).valid is False
    (run_dir / READINESS_MANIFEST_PATH).write_bytes(terminal_snapshot[READINESS_MANIFEST_PATH])

    swapped_files = dict(terminal_files)
    swapped_files[GRADER_LANE_1_PATH], swapped_files[GRADER_LANE_2_PATH] = (
        swapped_files[GRADER_LANE_2_PATH],
        swapped_files[GRADER_LANE_1_PATH],
    )
    (run_dir / GRADER_LANE_1_PATH).write_bytes(swapped_files[GRADER_LANE_1_PATH])
    (run_dir / GRADER_LANE_2_PATH).write_bytes(swapped_files[GRADER_LANE_2_PATH])
    swapped_manifest = _with_inventory(terminal_manifest, swapped_files)
    (run_dir / READINESS_MANIFEST_PATH).write_bytes(_manifest_bytes(swapped_manifest))
    assert verify_readiness_run_v1(run_dir).valid is False
    for relative, original in terminal_snapshot.items():
        (run_dir / relative).write_bytes(original)

    for relative, original in terminal_snapshot.items():
        if relative == READINESS_MANIFEST_PATH:
            continue
        target = run_dir / relative
        target.write_bytes(original + b"tamper")
        assert verify_readiness_run_v1(run_dir).valid is False, relative
        target.write_bytes(original)
    assert verify_readiness_run_v1(run_dir).valid is True

    from regulatory_harvest.storage import sha256_digest

    result_wire = json.loads((run_dir / READINESS_RESULT_PATH).read_bytes())
    result_wire["attorney_review_warning"] += " Altered."
    result_descriptor = {
        key: value for key, value in result_wire.items() if key != "result_fingerprint"
    }
    result_wire["result_fingerprint"] = sha256_digest(canonical_json_bytes(result_descriptor))
    (run_dir / READINESS_RESULT_PATH).write_bytes(canonical_json_bytes(result_wire))
    files = {
        path: data
        for path, data in _tree_bytes(run_dir).items()
        if path not in {READINESS_MANIFEST_PATH, "readiness-verification.json"}
    }
    rebuilt_verification = readiness_artifacts._runtime_verification(files)
    files["readiness-verification.json"] = canonical_json_bytes(
        rebuilt_verification.model_dump(mode="json")
    )
    (run_dir / "readiness-verification.json").write_bytes(files["readiness-verification.json"])
    old_manifest = terminal_manifest
    forged_manifest = _with_inventory(
        old_manifest.model_copy(update={"result_fingerprint": result_wire["result_fingerprint"]}),
        files,
    )
    (run_dir / READINESS_MANIFEST_PATH).write_bytes(_manifest_bytes(forged_manifest))
    assert verify_readiness_run_v1(run_dir).valid is False
    for relative, original in terminal_snapshot.items():
        (run_dir / relative).write_bytes(original)
    assert verify_readiness_run_v1(run_dir).valid is True
