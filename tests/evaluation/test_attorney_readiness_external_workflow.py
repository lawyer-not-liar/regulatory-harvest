"""Exact external-report admission, immutable replay, and portable parity."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from test_attorney_readiness_inputs import _make_verified_inputs
from test_attorney_readiness_workflow import ScriptedEvaluator, _tree_bytes

from regulatory_harvest.evaluation.attorney_readiness_artifacts import (
    load_verified_readiness_context_v1,
    verify_readiness_run_v1,
)
from regulatory_harvest.evaluation.attorney_readiness_workflow import (
    continue_readiness_v1,
    initialize_readiness_v1,
)


def test_external_report_completes_without_generation_claims(tmp_path: Path) -> None:
    source = _make_verified_inputs(tmp_path, limitations=None)
    report = tmp_path / "external.md"
    report.write_bytes(source.report_text.encode("utf-8"))
    before = report.read_bytes()
    run = tmp_path / "external-readiness"
    initialize_readiness_v1(
        run,
        baseline_run_dir=source.baseline_run_dir,
        qualification_run_dir=source.qualification_run_dir,
        external_report_path=report,
    )
    context = load_verified_readiness_context_v1(run)
    assert context.inputs.generation_binding is None
    assert context.inputs.generation_validation is None
    assert context.manifest.generation_capsule_root is None
    assert context.inputs.report_text.encode("utf-8") == before
    outcome = asyncio.run(continue_readiness_v1(run, ScriptedEvaluator(grade_mode="met")))
    assert outcome.result is not None
    assert outcome.result.delivery_readiness.value == "REVIEW_READY_WITH_GAPS"
    assert "external" in outcome.result.attorney_review_warning.lower()
    verification = verify_readiness_run_v1(run)
    assert verification.valid
    assert verification.checks["external_report_valid"] is True
    assert "generation_valid" not in verification.checks
    assert report.read_bytes() == before
    frozen = _tree_bytes(run)
    assert load_verified_readiness_context_v1(run).result == outcome.result
    assert _tree_bytes(run) == frozen


@pytest.mark.parametrize("mutation", ["report_hash", "grade_target_fingerprint", "strip_binding"])
def test_external_persisted_binding_tampering_fails_closed(tmp_path: Path, mutation: str) -> None:
    source = _make_verified_inputs(tmp_path, limitations=None)
    report = tmp_path / "external.md"
    report.write_text(source.report_text, encoding="utf-8")
    run = tmp_path / "external-readiness"
    initialize_readiness_v1(
        run,
        baseline_run_dir=source.baseline_run_dir,
        qualification_run_dir=source.qualification_run_dir,
        external_report_path=report,
    )
    # Exercise the semantic receiving boundary independently of inventory hashes.
    from regulatory_harvest.evaluation.attorney_readiness_artifacts import _inputs_from_file
    from regulatory_harvest.storage import canonical_json_bytes

    payload = json.loads((run / "readiness-input.json").read_bytes())
    if mutation == "strip_binding":
        del payload["readiness_input"]["external_report_binding"]
    else:
        payload["readiness_input"]["external_report_binding"][mutation] = "0" * 64
    with pytest.raises(ValueError):
        _inputs_from_file(
            canonical_json_bytes(payload), (run / "readiness-rubric.json").read_bytes()
        )


@pytest.mark.parametrize("mutation", ["report_hash", "strip_binding", "missing_validation"])
def test_portable_external_request_origin_tampering_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    from regulatory_harvest.evaluation.attorney_readiness_workflow import next_readiness_request_v1
    from regulatory_harvest.storage import canonical_json_bytes, sha256_digest

    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "scripts"))
    from test_attorney_eval_portable import _load_protocol_22_portable

    portable = _load_protocol_22_portable()
    source = _make_verified_inputs(tmp_path, limitations=None)
    report = tmp_path / "external.md"
    report.write_text(source.report_text, encoding="utf-8")
    run = tmp_path / "readiness"
    initialize_readiness_v1(
        run,
        baseline_run_dir=source.baseline_run_dir,
        qualification_run_dir=source.qualification_run_dir,
        external_report_path=report,
    )
    request = next_readiness_request_v1(run)
    assert request is not None
    raw = request.model_dump(mode="json")
    if mutation == "strip_binding":
        del raw["payload"]["external_report_binding"]
    elif mutation == "missing_validation":
        del raw["payload"]["generation_validation"]
    else:
        raw["payload"]["external_report_binding"]["report_hash"] = "0" * 64
    del raw["request_fingerprint"]
    raw["request_fingerprint"] = sha256_digest(canonical_json_bytes(raw))
    with pytest.raises(portable.PortableEvaluationInputError):
        portable._readiness_checked_request(raw)


def test_external_output_cannot_overlap_report_file(tmp_path: Path) -> None:
    source = _make_verified_inputs(tmp_path, limitations=None)
    report = tmp_path / "external.md"
    report.write_text(source.report_text, encoding="utf-8")
    before = report.read_bytes()
    with pytest.raises(ValueError, match="READINESS_OUTPUT_OVERLAPS_INPUT"):
        initialize_readiness_v1(
            report,
            baseline_run_dir=source.baseline_run_dir,
            qualification_run_dir=source.qualification_run_dir,
            external_report_path=report,
        )
    assert report.read_bytes() == before


def test_generated_persisted_input_rejects_explicit_null_external_binding(tmp_path: Path) -> None:
    from regulatory_harvest.evaluation.attorney_readiness_artifacts import _inputs_from_file
    from regulatory_harvest.storage import canonical_json_bytes

    source = _make_verified_inputs(tmp_path, limitations=None)
    run = tmp_path / "generated"
    initialize_readiness_v1(run, **source.without_history())
    payload = json.loads((run / "readiness-input.json").read_bytes())
    assert "external_report_binding" not in payload["readiness_input"]
    payload["readiness_input"]["external_report_binding"] = None
    with pytest.raises(ValueError):
        _inputs_from_file(
            canonical_json_bytes(payload), (run / "readiness-rubric.json").read_bytes()
        )


@pytest.mark.parametrize("blocking_safety", [False, True])
@pytest.mark.parametrize("omit_qualification_metadata", [False, True])
def test_external_complete_tree_full_portable_parity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    blocking_safety: bool,
    omit_qualification_metadata: bool,
) -> None:
    from test_attorney_readiness_workflow import _draft

    from regulatory_harvest.evaluation.attorney_readiness_drafts import (
        CompiledReadinessDraftV1,
        ReadinessEvaluatorProvenanceV1,
        compile_readiness_draft_v1,
    )
    from regulatory_harvest.evaluation.attorney_readiness_workflow import (
        guarded_submit_readiness_response_v1,
        next_readiness_request_v1,
    )

    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "scripts"))
    from test_attorney_eval_portable import _load_protocol_22_portable

    portable = _load_protocol_22_portable()
    source = _make_verified_inputs(
        tmp_path,
        limitations=None,
        omitted_response_metadata=("response_id", "usage") if omit_qualification_metadata else (),
    )
    report = tmp_path / "external.md"
    report.write_text(source.report_text, encoding="utf-8")
    full_run = tmp_path / "full"
    portable_run = tmp_path / "portable"
    init = {
        "baseline_run_dir": source.baseline_run_dir,
        "qualification_run_dir": source.qualification_run_dir,
        "external_report_path": report,
    }
    initialize_readiness_v1(full_run, **init)
    portable.initialize_readiness_v1(portable_run, **init)
    assert _tree_bytes(full_run) == _tree_bytes(portable_run)
    provenance = ReadinessEvaluatorProvenanceV1(
        provider_name="public-fixture-provider",
        model_name="public-fixture-model",
        judge_isolation="scripted_fixture",
    )
    while (request := next_readiness_request_v1(full_run)) is not None:
        portable_request = portable.next_readiness_request_v1(portable_run)
        assert portable_request == request.model_dump(mode="json")
        draft = _draft(request, grade_mode="met", blocking_safety=blocking_safety)
        compiled = compile_readiness_draft_v1(request, draft, provenance)
        assert isinstance(compiled, CompiledReadinessDraftV1)
        portable_response = portable.compile_readiness_draft_v1(
            portable_request,
            draft,
            {
                "provider_name": provenance.provider_name,
                "model_name": provenance.model_name,
                "judge_isolation": provenance.judge_isolation,
            },
        )
        assert portable_response == compiled.response.model_dump(mode="json")
        assert guarded_submit_readiness_response_v1(full_run, compiled.response).accepted
        assert portable.guarded_submit_readiness_response_v1(portable_run, portable_response)[
            "accepted"
        ]
        assert _tree_bytes(full_run) == _tree_bytes(portable_run)
    assert portable.verify_readiness_run_v1(portable_run) == (
        verify_readiness_run_v1(full_run).model_dump(mode="json")
    )
    result = json.loads((full_run / "delivery-readiness.json").read_bytes())
    assert result["delivery_readiness"] == (
        "NOT_DELIVERABLE" if blocking_safety else "REVIEW_READY_WITH_GAPS"
    )
