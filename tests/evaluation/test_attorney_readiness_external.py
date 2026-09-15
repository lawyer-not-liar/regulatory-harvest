"""External admission preserves bytes and never fabricates generation evidence."""

from dataclasses import replace
from pathlib import Path

import pytest
from test_attorney_readiness_inputs import _make_verified_inputs

from regulatory_harvest.evaluation.attorney_readiness_inputs import (
    ReadinessInputError,
    build_verified_readiness_input_v1,
)
from regulatory_harvest.evaluation.attorney_readiness_models import ReadinessInputV1
from regulatory_harvest.evaluation.attorney_readiness_requests import (
    build_baseline_locked_grade_batches_v1,
    build_baseline_locked_grade_request_v1,
)
from regulatory_harvest.storage import sha256_digest


@pytest.fixture
def setup_external(tmp_path):
    fixture = _make_verified_inputs(tmp_path)
    report = tmp_path / "external.md"
    report.write_bytes(b"# External report\r\n\r\nExact text.  \r\n")
    return fixture, report


def admit(fixture, report):
    return build_verified_readiness_input_v1(
        baseline_run_dir=fixture.baseline_run_dir,
        qualification_run_dir=fixture.qualification_run_dir,
        external_report_path=report,
    )


def test_external_admission_preserves_bytes_and_discloses_missing_generation(setup_external):
    fixture, report = setup_external
    inputs = admit(fixture, report)
    assert inputs.report_text.encode("utf-8") == report.read_bytes()
    assert inputs.report_hash == sha256_digest(report.read_bytes())
    assert inputs.generation_binding is None
    assert inputs.generation_validation is None
    wire = inputs.readiness_input.model_dump(mode="json")
    assert wire["generation_capsule_root"] is None
    assert wire["generation_validation"] is None
    assert wire["external_report_binding"] == {
        "origin": "external",
        "report_hash": inputs.report_hash,
        "grade_target_fingerprint": inputs.readiness_input.grade_target_fingerprint,
        "generation_validation_status": "not_performed",
    }
    batch = build_baseline_locked_grade_batches_v1(inputs.gradeable_baseline, lane=1)[0]
    request = build_baseline_locked_grade_request_v1(inputs, batch)
    assert request.payload["generation_validation"] is None
    assert request.payload["external_report_binding"]["origin"] == "external"


@pytest.mark.parametrize(
    "include_generation,include_receipt", [(True, False), (False, True), (True, True)]
)
def test_external_cannot_mix_with_generation(setup_external, include_generation, include_receipt):
    fixture, report = setup_external
    with pytest.raises(ReadinessInputError, match="READINESS_REPORT_ARGUMENTS_INVALID"):
        build_verified_readiness_input_v1(
            baseline_run_dir=fixture.baseline_run_dir,
            qualification_run_dir=fixture.qualification_run_dir,
            external_report_path=report,
            generation_run_dir=fixture.generation_run_dir if include_generation else None,
            validation_receipt_path=fixture.validation_receipt_path if include_receipt else None,
        )


@pytest.mark.parametrize("content", [b"", b" \r\n", b"\xff"])
def test_external_rejects_empty_or_non_utf8_report(setup_external, content):
    fixture, report = setup_external
    report.write_bytes(content)
    with pytest.raises(ReadinessInputError, match="READINESS_EXTERNAL_REPORT_INVALID"):
        admit(fixture, report)


def test_external_rejects_symlink(setup_external, tmp_path: Path):
    fixture, report = setup_external
    link = tmp_path / "link.md"
    link.symlink_to(report)
    with pytest.raises(ReadinessInputError, match="READINESS_EXTERNAL_REPORT_INVALID"):
        admit(fixture, link)


@pytest.mark.parametrize("field", ["report_hash", "grade_target_fingerprint"])
def test_external_binding_cannot_be_retargeted(setup_external, field):
    fixture, report = setup_external
    inputs = admit(fixture, report)
    wire = inputs.readiness_input.model_dump(mode="json")
    wire["gradeable_baseline"] = inputs.gradeable_baseline
    wire["external_report_binding"][field] = "0" * 64
    with pytest.raises(ValueError):
        ReadinessInputV1.model_validate(wire)


def test_external_detached_generation_claim_is_rejected(setup_external):
    fixture, report = setup_external
    inputs = admit(fixture, report)
    generated = build_verified_readiness_input_v1(**fixture.without_history())
    forged = replace(inputs, generation_binding=generated.generation_binding)
    batch = build_baseline_locked_grade_batches_v1(inputs.gradeable_baseline, lane=1)[0]
    with pytest.raises(ValueError, match="verified readiness inputs are invalid"):
        build_baseline_locked_grade_request_v1(forged, batch)


@pytest.mark.parametrize(
    "mutation", ["null_binding", "retarget", "missing_origin", "fake_validation"]
)
def test_resealed_external_request_cannot_change_its_evidence_branch(setup_external, mutation):
    from test_attorney_readiness_drafts import _ordinary_draft, _provenance, _reseal_request

    from regulatory_harvest.evaluation.attorney_readiness_drafts import (
        ReadinessEngineDefectV1,
        compile_readiness_draft_v1,
    )

    fixture, report = setup_external
    inputs = admit(fixture, report)
    batch = build_baseline_locked_grade_batches_v1(inputs.gradeable_baseline, lane=1)[0]
    request = build_baseline_locked_grade_request_v1(inputs, batch)
    raw = request.model_dump(mode="json")
    payload = raw["payload"]
    if mutation == "null_binding":
        payload["external_report_binding"] = None
    elif mutation == "retarget":
        payload["external_report_binding"]["grade_target_fingerprint"] = "0" * 64
    elif mutation == "missing_origin":
        del payload["external_report_binding"]
    else:
        payload["generation_validation"] = {"status": "completed"}
    forged = _reseal_request(raw)
    result = compile_readiness_draft_v1(forged, _ordinary_draft(request), _provenance())
    assert isinstance(result, ReadinessEngineDefectV1)
