"""Scoped-review admission, refusal, and full/portable graph parity."""

from __future__ import annotations

import copy
import json
import shutil
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any

import pytest


def _helpers(monkeypatch: pytest.MonkeyPatch) -> tuple[Any, Any, Any, Any]:
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "evaluation"))
    from test_attorney_eval_portable import _load_protocol_22_portable
    from test_attorney_readiness_inputs import _make_verified_inputs
    from test_attorney_readiness_response_contract_workflow import _provenance
    from test_attorney_readiness_workflow import _draft

    return _load_protocol_22_portable(), _make_verified_inputs, _draft, _provenance


def test_portable_new_admission_uses_scoped_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    portable, make_inputs, _, _ = _helpers(monkeypatch)
    source = make_inputs(tmp_path)
    report = tmp_path / "report.md"
    report.write_text(source.report_text, encoding="utf-8")
    run = tmp_path / "portable"
    portable.initialize_readiness_v1(
        run,
        baseline_run_dir=source.baseline_run_dir,
        qualification_run_dir=source.qualification_run_dir,
        external_report_path=report,
    )
    assert (
        json.loads((run / "readiness-input.json").read_bytes())["readiness_input"][
            "safety_response_contract_version"
        ]
        == "readiness-safety-response-v3"
    )


@pytest.mark.parametrize(
    "version", [None, "readiness-safety-response-v1", "readiness-safety-response-v2"]
)
@pytest.mark.parametrize("selected", ["lane_1", "lane_2", "unresolved"])
def test_scoped_and_legacy_graphs_match(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    version: str | None,
    selected: str,
    finding_lane: int | None = None,
) -> None:
    portable, make_inputs, draft_for, provenance = _helpers(monkeypatch)
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

    source = make_inputs(tmp_path)
    inputs = build_verified_readiness_input_v1(**source.without_history())
    inputs = replace(
        inputs,
        readiness_input=inputs.readiness_input.model_copy(
            update={"safety_response_contract_version": version},
        ),
    )
    batch = build_baseline_locked_grade_batches_v1(inputs.gradeable_baseline, lane=1)[0]
    first = build_baseline_locked_grade_request_v1(inputs, batch)
    full, other = tmp_path / "full", tmp_path / "portable"
    initialize_readiness_run_storage_v1(full, inputs, first)
    shutil.copytree(full, other)
    scoped = version == "readiness-safety-response-v2"
    seen = 0
    while (request := next_readiness_request_v1(full)) is not None:
        raw_request = request.model_dump(mode="json")
        assert portable.next_readiness_request_v1(other) == raw_request
        draft = draft_for(
            request,
            grade_mode="met",
            disputes=not scoped,
            blocking_safety=finding_lane is not None
            and request.payload.get("lane") == finding_lane,
        )
        if request.operation.value == "safety_review":
            candidates = request.payload["gap_candidates"]
            for candidate, assessment in zip(
                candidates, draft["candidate_assessments"], strict=True
            ):
                if scoped:
                    assessment["scope_status"] = "open_gap"
                    if candidate["origin"] == "prerequisite" and request.payload["lane"] == 1:
                        assessment.update(
                            scope_status="not_required_for_scope",
                            visibility="hidden",
                            report_passages=[],
                            disclosure_location=None,
                            owner_role="reviewing_attorney",
                        )
                else:
                    assessment.pop("scope_status", None)
        elif request.operation.value == "safety_referee":
            seen += 1
            if scoped:
                assert request.payload["dispute_kind"] == "assessment"
                if request.payload["subject_identity"].startswith("candidate:"):
                    assert "scope_status" in request.payload["lane_1_choice"]
                else:
                    assert request.payload[f"lane_{3 - finding_lane}_choice"] is None
                assert request.payload["safety_response_contract"]["version"] == version
            draft["disposition"] = selected
        compiled = compile_readiness_draft_v1(request, draft, provenance())
        assert isinstance(compiled, CompiledReadinessDraftV1), compiled
        other_response = portable.compile_readiness_draft_v1(
            raw_request, draft, asdict(provenance())
        )
        assert other_response == compiled.response.model_dump(mode="json")
        assert guarded_submit_readiness_response_v1(full, compiled.response).accepted
        assert portable.guarded_submit_readiness_response_v1(other, other_response)["accepted"]
    assert verify_readiness_run_v1(full).valid
    assert portable.verify_readiness_run_v1(other)["valid"]
    for path in full.rglob("*"):
        if path.is_file() and path.name != ".readiness.lock":
            assert path.read_bytes() == (other / path.relative_to(full)).read_bytes(), path
    if scoped:
        assert seen > 0
        matrix = json.loads((full / "gap-follow-up-matrix.json").read_bytes())
        prerequisite_rows = [row for row in matrix["rows"] if row["origin"] == "prerequisite"]
        assert prerequisite_rows
        expected = "open" if selected == "lane_2" else "not_required_for_scope"
        assert {row["status"] for row in prerequisite_rows} == {expected}
        if selected == "unresolved":
            safety = json.loads((full / "aggregates/safety-review.json").read_bytes())
            assert "GAP_RATIONALE_INVALID" in safety["blocking_codes"]
            assert all(row["blocking_code"] is None for row in safety["candidate_assessments"])
        if finding_lane is not None:
            safety = json.loads((full / "aggregates/safety-review.json").read_bytes())
            present = selected == "unresolved" or selected == f"lane_{finding_lane}"
            assert len(safety["finding_proposals"]) == int(present)
            assert ("MATERIAL_UNSUPPORTED_ASSERTION" in safety["blocking_codes"]) == present


@pytest.mark.parametrize("finding_lane", [1, 2])
@pytest.mark.parametrize("selected", ["lane_1", "lane_2", "unresolved"])
def test_whole_finding_presence_graph_parity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    finding_lane: int,
    selected: str,
) -> None:
    test_scoped_and_legacy_graphs_match(
        tmp_path,
        monkeypatch,
        "readiness-safety-response-v2",
        selected,
        finding_lane,
    )


@pytest.mark.parametrize(
    "mutation", ["missing", "unknown", "blocking", "baseline", "unbound", "finding"]
)
def test_scoped_invalid_drafts_refused_by_both_runtimes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    portable, make_inputs, draft_for, provenance = _helpers(monkeypatch)
    from regulatory_harvest.evaluation.attorney_readiness_drafts import (
        CompiledReadinessDraftV1,
        NeedsReadinessClarificationV1,
        compile_readiness_draft_v1,
    )
    from regulatory_harvest.evaluation.attorney_readiness_workflow import (
        guarded_submit_readiness_response_v1,
        initialize_readiness_v1,
        next_readiness_request_v1,
    )

    source = make_inputs(tmp_path)
    run = tmp_path / "full"
    initialize_readiness_v1(run, **source.without_history())
    while (request := next_readiness_request_v1(run)) is not None:
        draft = draft_for(request, grade_mode="partial", blocking_safety=True)
        if request.operation.value == "safety_review":
            break
        compiled = compile_readiness_draft_v1(request, draft, provenance())
        assert isinstance(compiled, CompiledReadinessDraftV1)
        assert guarded_submit_readiness_response_v1(run, compiled.response).accepted
    assert request is not None
    for assessment in draft["candidate_assessments"]:
        assessment["scope_status"] = "open_gap"
    index = next(
        index
        for index, candidate in enumerate(request.payload["gap_candidates"])
        if (
            candidate["origin"] != "prerequisite"
            if mutation == "baseline"
            else candidate["origin"] == "prerequisite"
        )
    )
    item = draft["candidate_assessments"][index]
    item["scope_status"] = "not_required_for_scope"
    if mutation == "missing":
        item.pop("scope_status")
    elif mutation == "unknown":
        item["scope_status"] = "resolved"
    elif mutation == "blocking":
        item["blocking_code"] = "HIDDEN_MATERIAL_GAP"
    elif mutation == "unbound":
        item["evidence_refs"] = []
    elif mutation == "finding":
        draft["finding_proposals"][0]["scope_status"] = "not_required_for_scope"
    before = {str(path): path.read_bytes() for path in run.rglob("*") if path.is_file()}
    full = compile_readiness_draft_v1(request, copy.deepcopy(draft), provenance())
    assert isinstance(full, NeedsReadinessClarificationV1), full
    with pytest.raises(portable.PortableEvaluationInputError):
        portable.compile_readiness_draft_v1(
            request.model_dump(mode="json"), draft, asdict(provenance())
        )
    assert before == {str(path): path.read_bytes() for path in run.rglob("*") if path.is_file()}


@pytest.mark.parametrize(
    "mutation",
    [
        "identity",
        "evidence_union",
        "passage_union",
        "missing_choice_scope",
        "report",
        "question",
        "unbound_passage",
    ],
)
def test_scoped_referee_rejects_resealed_choice_tamper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    portable, make_inputs, draft_for, provenance = _helpers(monkeypatch)
    from regulatory_harvest.evaluation.attorney_readiness_drafts import (
        CompiledReadinessDraftV1,
        ReadinessEngineDefectV1,
        compile_readiness_draft_v1,
    )
    from regulatory_harvest.evaluation.attorney_readiness_models import ReadinessEvaluatorRequestV1
    from regulatory_harvest.evaluation.attorney_readiness_workflow import (
        guarded_submit_readiness_response_v1,
        initialize_readiness_v1,
        next_readiness_request_v1,
    )
    from regulatory_harvest.storage import canonical_json_bytes, sha256_digest

    source = make_inputs(tmp_path)
    run = tmp_path / "full"
    initialize_readiness_v1(run, **source.without_history())
    while (request := next_readiness_request_v1(run)) is not None:
        draft = draft_for(request, grade_mode="met", disputes=True)
        if request.operation.value == "safety_referee":
            break
        if request.operation.value == "safety_review":
            for assessment in draft["candidate_assessments"]:
                assessment["scope_status"] = "open_gap"
        compiled = compile_readiness_draft_v1(request, draft, provenance())
        assert isinstance(compiled, CompiledReadinessDraftV1)
        assert guarded_submit_readiness_response_v1(run, compiled.response).accepted
    assert request is not None and request.operation.value == "safety_referee"
    raw = request.model_dump(mode="json")
    payload = raw["payload"]
    if mutation == "identity":
        payload["lane_1_choice"]["candidate_id"] = "GC-9999"
    elif mutation == "evidence_union":
        payload["lane_1_choice"]["evidence_refs"] = []
        payload["lane_2_choice"]["evidence_refs"] = []
    elif mutation == "passage_union":
        payload["disputed_report_passages"] = []
    elif mutation == "missing_choice_scope":
        payload["lane_1_choice"].pop("scope_status")
    elif mutation == "report":
        payload["report_text"] += " Altered context."
    elif mutation == "question":
        payload["research_question"] = ""
    else:
        for choice in (payload["lane_1_choice"], payload["lane_2_choice"]):
            choice["report_passages"] = ["Invented passage outside the report."]
        payload["disputed_report_passages"] = ["Invented passage outside the report."]
    raw["request_fingerprint"] = sha256_digest(
        canonical_json_bytes(
            {key: value for key, value in raw.items() if key != "request_fingerprint"}
        )
    )
    with pytest.raises(portable.PortableEvaluationInputError):
        portable.compile_readiness_draft_v1(raw, draft, asdict(provenance()))
    assert isinstance(
        compile_readiness_draft_v1(
            ReadinessEvaluatorRequestV1.model_validate(raw),
            draft,
            provenance(),
        ),
        ReadinessEngineDefectV1,
    )
