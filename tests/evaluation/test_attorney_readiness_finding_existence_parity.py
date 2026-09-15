"""A referee's finding-presence marker is not a finding payload field."""

import shutil
from dataclasses import replace
from pathlib import Path

import pytest
from test_attorney_readiness_inputs import _make_verified_inputs
from test_attorney_readiness_response_contract_workflow import _portable, _provenance
from test_attorney_readiness_workflow import _draft

from regulatory_harvest.evaluation.attorney_readiness_artifacts import (
    initialize_readiness_run_storage_v1,
    verify_readiness_run_v1,
)
from regulatory_harvest.evaluation.attorney_readiness_drafts import (
    CompiledReadinessDraftV1,
    compile_readiness_draft_v1,
)
from regulatory_harvest.evaluation.attorney_readiness_inputs import (
    build_verified_readiness_input_v1,
)
from regulatory_harvest.evaluation.attorney_readiness_requests import (
    build_baseline_locked_grade_batches_v1,
    build_baseline_locked_grade_request_v1,
)
from regulatory_harvest.evaluation.attorney_readiness_workflow import (
    guarded_submit_readiness_response_v1,
    next_readiness_request_v1,
)


def _initialize_retained_pair(full_run: Path, portable_run: Path, admission: dict) -> None:
    """Retain the V1 bugs' exact protocol; separate scoped tests cover new V2 graphs."""
    inputs = build_verified_readiness_input_v1(**admission)
    inputs = replace(inputs, readiness_input=inputs.readiness_input.model_copy(
        update={"safety_response_contract_version": "readiness-safety-response-v1"}
    ))
    batch = build_baseline_locked_grade_batches_v1(inputs.gradeable_baseline, lane=1)[0]
    initialize_readiness_run_storage_v1(
        full_run, inputs, build_baseline_locked_grade_request_v1(inputs, batch)
    )
    shutil.copytree(full_run, portable_run)


@pytest.mark.parametrize("present_lane", [1, 2])
@pytest.mark.parametrize("selected_lane", [1, 2])
def test_finding_existence_referee_preserves_exact_full_portable_terminal_graph(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, present_lane: int, selected_lane: int
) -> None:
    portable = _portable(monkeypatch)
    inputs = _make_verified_inputs(tmp_path, limitations=None)
    full_run = tmp_path / "full"
    portable_run = tmp_path / "portable"
    report = tmp_path / "synthetic-report.md"
    report.write_text(inputs.report_text, encoding="utf-8")
    admission = {
        "baseline_run_dir": inputs.baseline_run_dir,
        "qualification_run_dir": inputs.qualification_run_dir,
        "external_report_path": report,
    }
    _initialize_retained_pair(full_run, portable_run, admission)
    seen_referees = 0
    while (request := next_readiness_request_v1(full_run)) is not None:
        assert portable.next_readiness_request_v1(portable_run) == request.model_dump(mode="json")
        draft = _draft(
            request,
            grade_mode="met",
            blocking_safety=request.payload.get("lane") == present_lane,
        )
        if request.operation.value == "safety_referee":
            assert request.payload["dispute_kind"] == "finding_existence"
            draft["disposition"] = f"lane_{selected_lane}"
            seen_referees += 1
        compiled = compile_readiness_draft_v1(request, draft, _provenance())
        assert isinstance(compiled, CompiledReadinessDraftV1)
        assert guarded_submit_readiness_response_v1(full_run, compiled.response).accepted
        assert portable.guarded_submit_readiness_response_v1(
            portable_run, compiled.response.model_dump(mode="json")
        )["accepted"]
    assert seen_referees == 1
    assert verify_readiness_run_v1(full_run).valid
    assert portable.verify_readiness_run_v1(full_run)["valid"]
    assert portable.verify_readiness_run_v1(portable_run)["valid"]
    assert (full_run / "aggregates/safety-review.json").read_bytes() == (
        portable_run / "aggregates/safety-review.json"
    ).read_bytes()


@pytest.mark.parametrize("referee_disposition", ["blocking", "unresolved"])
def test_referee_adds_blocker_even_when_candidate_already_has_a_different_blocker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, referee_disposition: str
) -> None:
    portable = _portable(monkeypatch)
    inputs = _make_verified_inputs(tmp_path, limitations=None)
    full_run, portable_run = tmp_path / "full", tmp_path / "portable"
    report = tmp_path / "synthetic-report.md"
    report.write_text(inputs.report_text, encoding="utf-8")
    admission = {
        "baseline_run_dir": inputs.baseline_run_dir,
        "qualification_run_dir": inputs.qualification_run_dir,
        "external_report_path": report,
    }
    _initialize_retained_pair(full_run, portable_run, admission)
    seen_referees = 0
    while (request := next_readiness_request_v1(full_run)) is not None:
        assert portable.next_readiness_request_v1(portable_run) == request.model_dump(mode="json")
        draft = _draft(request, grade_mode="partial")
        if request.operation.value == "safety_review":
            first = draft["candidate_assessments"][0]
            first.update(blocking_code="HIDDEN_MATERIAL_GAP", visibility="prominent",
                         owner_role="reviewing_attorney")
            if request.payload["lane"] == 2:
                first["why_unresolved"] += " Further source evidence remains unresolved."
        elif request.operation.value == "safety_referee":
            assert request.payload["dispute_kind"] == "rationale"
            draft["disposition"] = referee_disposition
            seen_referees += 1
        compiled = compile_readiness_draft_v1(request, draft, _provenance())
        assert isinstance(compiled, CompiledReadinessDraftV1)
        assert guarded_submit_readiness_response_v1(full_run, compiled.response).accepted
        assert portable.guarded_submit_readiness_response_v1(
            portable_run, compiled.response.model_dump(mode="json")
        )["accepted"]
    assert seen_referees == 1
    assert verify_readiness_run_v1(full_run).valid
    assert portable.verify_readiness_run_v1(full_run)["valid"]
    assert portable.verify_readiness_run_v1(portable_run)["valid"]
    for name in ("aggregates/safety-review.json", "delivery-readiness.json"):
        assert (full_run / name).read_bytes() == (portable_run / name).read_bytes()
