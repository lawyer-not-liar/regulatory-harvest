"""Run-level safety-response contract selection and replay compatibility."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from test_attorney_readiness_inputs import _make_verified_inputs
from test_attorney_readiness_workflow import _draft

from regulatory_harvest.evaluation.attorney_artifacts import EvaluationIntegrityError
from regulatory_harvest.evaluation.attorney_readiness_artifacts import (
    READINESS_MANIFEST_PATH,
    _inputs_from_file,
    _manifest_bytes,
    _manifest_from_bytes,
    _with_inventory,
    initialize_readiness_run_storage_v1,
    load_verified_readiness_context_v1,
    verify_readiness_run_v1,
)
from regulatory_harvest.evaluation.attorney_readiness_drafts import (
    CompiledReadinessDraftV1,
    ReadinessEvaluatorProvenanceV1,
    compile_readiness_draft_v1,
)
from regulatory_harvest.evaluation.attorney_readiness_requests import (
    build_baseline_locked_grade_batches_v1,
    build_baseline_locked_grade_request_v1,
    build_gap_candidate_inventory_v1,
    build_safety_lane_request_v1,
)
from regulatory_harvest.evaluation.attorney_readiness_response_contract import (
    READINESS_SAFETY_RESPONSE_CONTRACT_VERSION_V3,
    build_readiness_safety_response_contract_v1,
)
from regulatory_harvest.evaluation.attorney_readiness_workflow import (
    guarded_submit_readiness_response_v1,
    initialize_readiness_v1,
    next_readiness_request_v1,
)
from regulatory_harvest.storage import canonical_json_bytes


def _portable(monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "scripts"))
    from test_attorney_eval_portable import _load_protocol_22_portable

    return _load_protocol_22_portable()


def _provenance() -> ReadinessEvaluatorProvenanceV1:
    return ReadinessEvaluatorProvenanceV1(
        provider_name="public-fixture-provider",
        model_name="public-fixture-model",
        judge_isolation="scripted_fixture",
    )


def _tree_bytes(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def test_portable_contract_factory_exactly_matches_full_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    portable = _portable(monkeypatch)
    assert portable._readiness_safety_response_contract_v1() == (
        build_readiness_safety_response_contract_v1()
    )


def test_new_admission_selects_current_contract_and_legacy_none_is_omitted(
    tmp_path: Path,
) -> None:
    source = _make_verified_inputs(tmp_path, limitations=None)
    run = tmp_path / "readiness"
    initialize_readiness_v1(run, **source.without_history())

    context = load_verified_readiness_context_v1(run)
    readiness_input = context.inputs.readiness_input
    assert (
        readiness_input.safety_response_contract_version
        == READINESS_SAFETY_RESPONSE_CONTRACT_VERSION_V3
    )
    assert json.loads((run / "readiness-input.json").read_bytes())["readiness_input"][
        "safety_response_contract_version"
    ] == READINESS_SAFETY_RESPONSE_CONTRACT_VERSION_V3

    legacy = readiness_input.model_copy(update={"safety_response_contract_version": None})
    assert "safety_response_contract_version" not in legacy.model_dump(mode="json")


def test_persisted_input_accepts_absent_legacy_selector_but_rejects_null_or_unknown(
    tmp_path: Path,
) -> None:
    source = _make_verified_inputs(tmp_path, limitations=None)
    run = tmp_path / "readiness"
    initialize_readiness_v1(run, **source.without_history())
    payload = json.loads((run / "readiness-input.json").read_bytes())
    rubric_bytes = (run / "readiness-rubric.json").read_bytes()

    del payload["readiness_input"]["safety_response_contract_version"]
    legacy = _inputs_from_file(canonical_json_bytes(payload), rubric_bytes)
    assert legacy.readiness_input.safety_response_contract_version is None

    for invalid in (None, "readiness-safety-response-unknown"):
        payload["readiness_input"]["safety_response_contract_version"] = invalid
        with pytest.raises(ValueError):
            _inputs_from_file(canonical_json_bytes(payload), rubric_bytes)


def test_v3_filters_ambiguous_grade_quotes_without_changing_other_grade_content(
    tmp_path: Path,
) -> None:
    source = _make_verified_inputs(tmp_path, limitations=None)
    from regulatory_harvest.evaluation.attorney_readiness_inputs import (
        build_verified_readiness_input_v1,
    )

    current = build_verified_readiness_input_v1(**source.without_history())
    legacy = replace(
        current,
        readiness_input=current.readiness_input.model_copy(
            update={"safety_response_contract_version": None}
        ),
    )
    batch = build_baseline_locked_grade_batches_v1(current.gradeable_baseline, lane=1)[0]
    current_request = build_baseline_locked_grade_request_v1(current, batch)
    legacy_request = build_baseline_locked_grade_request_v1(legacy, batch)

    ambiguous = (
        "Section 1. A covered operator must file a notice. "
        "Section 2. The notice must identify the operator. [S1]"
    )
    current_allowlist = list(current_request.payload["report_passage_allowlist"])
    legacy_allowlist = list(legacy_request.payload["report_passage_allowlist"])
    assert ambiguous in legacy_allowlist
    assert ambiguous not in current_allowlist
    assert current_allowlist == [passage for passage in legacy_allowlist if passage != ambiguous]
    assert all(current.report_text.count(passage) == 1 for passage in current_allowlist)

    current_wire = current_request.model_dump(mode="json")
    legacy_wire = legacy_request.model_dump(mode="json")
    assert current_wire.pop("request_fingerprint") != legacy_wire.pop("request_fingerprint")
    for wire in (current_wire, legacy_wire):
        wire["payload"].pop("report_passage_allowlist")
        for grade in wire["json_schema"]["properties"]["requirement_grades"]["prefixItems"]:
            grade["properties"]["report_passages"]["items"].pop("enum")
    assert canonical_json_bytes(current_wire) == canonical_json_bytes(legacy_wire)


def test_current_contract_full_and_portable_complete_graphs_match(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    portable = _portable(monkeypatch)
    source = _make_verified_inputs(tmp_path, limitations=None)
    full_run = tmp_path / "full"
    portable_run = tmp_path / "portable"
    report = tmp_path / "synthetic-report.md"
    report.write_text(source.report_text, encoding="utf-8")
    init = {
        "baseline_run_dir": source.baseline_run_dir,
        "qualification_run_dir": source.qualification_run_dir,
        "external_report_path": report,
    }
    initialize_readiness_v1(full_run, **init)
    portable.initialize_readiness_v1(portable_run, **init)

    while (request := next_readiness_request_v1(full_run)) is not None:
        portable_request = portable.next_readiness_request_v1(portable_run)
        assert portable_request == request.model_dump(mode="json")
        draft = _draft(request, grade_mode="partial", disputes=True)
        compiled = compile_readiness_draft_v1(request, draft, _provenance())
        assert isinstance(compiled, CompiledReadinessDraftV1), request.operation
        portable_response = portable.compile_readiness_draft_v1(
            portable_request,
            draft,
            {
                "provider_name": "public-fixture-provider",
                "model_name": "public-fixture-model",
                "judge_isolation": "scripted_fixture",
            },
        )
        assert portable_response == compiled.response.model_dump(mode="json")
        assert guarded_submit_readiness_response_v1(full_run, compiled.response).accepted
        assert portable.guarded_submit_readiness_response_v1(
            portable_run, portable_response
        )["accepted"]

    assert verify_readiness_run_v1(full_run).valid is True
    assert portable.verify_readiness_run_v1(portable_run) == verify_readiness_run_v1(
        full_run
    ).model_dump(mode="json")


def test_legacy_absent_selector_replays_at_every_phase_in_full_and_portable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    portable = _portable(monkeypatch)
    source = _make_verified_inputs(tmp_path, limitations=None)
    from regulatory_harvest.evaluation.attorney_readiness_inputs import (
        build_verified_readiness_input_v1,
    )

    current_inputs = build_verified_readiness_input_v1(**source.without_history())
    inputs = replace(
        current_inputs,
        readiness_input=current_inputs.readiness_input.model_copy(
            update={"safety_response_contract_version": None}
        ),
    )
    assert inputs.readiness_input.safety_response_contract_version is None
    first_batch = build_baseline_locked_grade_batches_v1(inputs.gradeable_baseline, lane=1)[0]
    first_request = build_baseline_locked_grade_request_v1(inputs, first_batch)
    run = tmp_path / "legacy"
    initialize_readiness_run_storage_v1(run, inputs, first_request)
    observed_operations: set[str] = set()

    while (request := next_readiness_request_v1(run)) is not None:
        assert verify_readiness_run_v1(run).valid is True
        assert portable.verify_readiness_run_v1(run)["valid"] is True
        observed_operations.add(request.operation.value)
        draft = _draft(request, grade_mode="partial", disputes=True)
        compiled = compile_readiness_draft_v1(request, draft, _provenance())
        assert isinstance(compiled, CompiledReadinessDraftV1), request.operation
        assert guarded_submit_readiness_response_v1(run, compiled.response).accepted

    assert observed_operations >= {
        "baseline_locked_grade",
        "safety_review",
        "safety_referee",
    }
    assert verify_readiness_run_v1(run).valid is True
    assert portable.verify_readiness_run_v1(run)["valid"] is True


def test_current_run_rejects_resealed_coherent_legacy_safety_request_downgrade(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    portable = _portable(monkeypatch)
    source = _make_verified_inputs(tmp_path, limitations=None)
    run = tmp_path / "current"
    initialize_readiness_v1(run, **source.without_history())

    while True:
        request = next_readiness_request_v1(run)
        assert request is not None
        if request.operation.value == "safety_review":
            break
        compiled = compile_readiness_draft_v1(
            request,
            _draft(request, grade_mode="partial", disputes=True),
            _provenance(),
        )
        assert isinstance(compiled, CompiledReadinessDraftV1)
        assert guarded_submit_readiness_response_v1(run, compiled.response).accepted

    context = load_verified_readiness_context_v1(run)
    assert context.grader_lanes is not None
    legacy_inputs = replace(
        context.inputs,
        readiness_input=context.inputs.readiness_input.model_copy(
            update={"safety_response_contract_version": None}
        ),
    )
    legacy_candidates = build_gap_candidate_inventory_v1(
        legacy_inputs, context.grader_lanes
    )
    legacy_request = build_safety_lane_request_v1(
        legacy_inputs,
        context.grader_lanes,
        legacy_candidates,
        lane=request.payload["lane"],
    )
    assert "safety_response_contract" not in legacy_request.payload
    assert legacy_request.request_fingerprint != request.request_fingerprint

    manifest = _manifest_from_bytes((run / READINESS_MANIFEST_PATH).read_bytes())
    pending = manifest.pending_call
    assert pending is not None
    request_path = run / pending.request_artifact_path
    request_wire = legacy_request.model_dump(mode="json")
    request_bytes = canonical_json_bytes(request_wire)
    files = {
        path: data
        for path, data in _tree_bytes(run).items()
        if path != READINESS_MANIFEST_PATH
    }
    files[pending.request_artifact_path] = request_bytes
    resealed = _with_inventory(
        manifest.model_copy(
            update={
                "pending_call": pending.model_copy(
                    update={"request_fingerprint": request_wire["request_fingerprint"]}
                )
            }
        ),
        files,
    )
    request_path.write_bytes(request_bytes)
    (run / READINESS_MANIFEST_PATH).write_bytes(_manifest_bytes(resealed))

    # A standalone compiler lacks the persisted run selector and must retain legacy replay.
    downgraded_request = type(request).model_validate(request_wire)
    downgraded = compile_readiness_draft_v1(
        downgraded_request,
        _draft(downgraded_request, grade_mode="partial", disputes=True),
        _provenance(),
    )
    assert isinstance(downgraded, CompiledReadinessDraftV1)

    with pytest.raises(EvaluationIntegrityError, match="READINESS_ARTIFACT_CALL_HISTORY"):
        guarded_submit_readiness_response_v1(run, downgraded.response)
    portable_submission = portable.guarded_submit_readiness_response_v1(
        run, downgraded.response.model_dump(mode="json")
    )
    assert portable_submission["accepted"] is False
    assert verify_readiness_run_v1(run).issues == ("READINESS_SEMANTIC_REPLAY_INVALID",)
    assert portable.verify_readiness_run_v1(run)["issues"] == [
        "READINESS_SEMANTIC_REPLAY_INVALID"
    ]
