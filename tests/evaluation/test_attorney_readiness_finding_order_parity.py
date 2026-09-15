"""Portable safety reconciliation must retain the full engine's finding order."""

from __future__ import annotations

import copy
from pathlib import Path

import pytest
from test_attorney_readiness_inputs import _make_verified_inputs
from test_attorney_readiness_response_contract_workflow import _portable, _provenance
from test_attorney_readiness_workflow import _draft

from regulatory_harvest.evaluation.attorney_readiness_artifacts import verify_readiness_run_v1
from regulatory_harvest.evaluation.attorney_readiness_drafts import (
    CompiledReadinessDraftV1,
    compile_readiness_draft_v1,
)
from regulatory_harvest.evaluation.attorney_readiness_workflow import (
    guarded_submit_readiness_response_v1,
    initialize_readiness_v1,
    next_readiness_request_v1,
)


def _finding_pair(request: object) -> tuple[dict[str, object], dict[str, object]]:
    draft = _draft(request, grade_mode="met", blocking_safety=True)
    original = draft["finding_proposals"][0]
    earlier = copy.deepcopy(original)
    later = copy.deepcopy(original)
    earlier["subject_id"] = "a-report-assertion"
    later["subject_id"] = "z-report-assertion"
    return earlier, later


def _run_order_case(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    lane_2_only_earlier: bool,
) -> tuple[Path, Path, int]:
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
    initialize_readiness_v1(full_run, **admission)
    portable.initialize_readiness_v1(portable_run, **admission)
    referees = 0
    while (request := next_readiness_request_v1(full_run)) is not None:
        assert portable.next_readiness_request_v1(portable_run) == request.model_dump(mode="json")
        draft = _draft(request, grade_mode="met")
        if request.operation.value == "safety_review":
            earlier, later = _finding_pair(request)
            draft["finding_proposals"] = (
                [later, earlier]
                if not lane_2_only_earlier or request.payload["lane"] == 2
                else [later]
            )
        elif request.operation.value == "safety_referee":
            assert lane_2_only_earlier
            assert request.payload["dispute_kind"] == "assessment"
            assert request.payload["subject_identity"].endswith(":a-report-assertion")
            draft["disposition"] = "lane_2"
            referees += 1
        compiled = compile_readiness_draft_v1(request, draft, _provenance())
        assert isinstance(compiled, CompiledReadinessDraftV1)
        assert guarded_submit_readiness_response_v1(full_run, compiled.response).accepted
        assert portable.guarded_submit_readiness_response_v1(
            portable_run, compiled.response.model_dump(mode="json")
        )["accepted"]
    assert verify_readiness_run_v1(full_run).valid
    assert portable.verify_readiness_run_v1(portable_run)["valid"]
    return full_run, portable_run, referees


def test_matching_lanes_sort_two_findings_by_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    full_run, portable_run, referees = _run_order_case(
        tmp_path, monkeypatch, lane_2_only_earlier=False
    )
    assert referees == 0
    assert (full_run / "aggregates/safety-review.json").read_bytes() == (
        portable_run / "aggregates/safety-review.json"
    ).read_bytes()


def test_selected_lane_2_only_finding_is_sorted_before_existing_later_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    full_run, portable_run, referees = _run_order_case(
        tmp_path, monkeypatch, lane_2_only_earlier=True
    )
    assert referees == 1
    assert (full_run / "aggregates/safety-review.json").read_bytes() == (
        portable_run / "aggregates/safety-review.json"
    ).read_bytes()
