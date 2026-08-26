"""Deterministic public-synthetic stress coverage for portable readiness parity."""

from __future__ import annotations

import importlib.util
import json
import sys
from copy import deepcopy
from pathlib import Path
from types import ModuleType

import pytest

from regulatory_harvest.evaluation.attorney_readiness_drafts import (
    CompiledReadinessDraftV1,
    ReadinessEvaluatorProvenanceV1,
    compile_readiness_draft_v1,
)
from regulatory_harvest.evaluation.attorney_readiness_models import (
    load_readiness_rubric_v1,
)
from regulatory_harvest.evaluation.attorney_readiness_workflow import (
    guarded_submit_readiness_response_v1,
    initialize_readiness_v1,
    next_readiness_request_v1,
)

ROOT = Path(__file__).parents[2]
PORTABLE = ROOT / "scripts" / "attorney_eval_portable.py"


def _portable() -> ModuleType:
    spec = importlib.util.spec_from_file_location("attorney_readiness_portable_stress", PORTABLE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("seed", range(96))
def test_readiness_seeded_scoring_boundary_matrix(
    seed: int, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every seed completes independent full and portable readiness transcripts."""
    portable = _portable()
    rubric_bytes, rubric, rubric_fingerprint = portable._readiness_rubric_v1()
    vector = portable._readiness_stress_vector_v1(seed, rubric)
    full_rubric = load_readiness_rubric_v1().model_dump(mode="json")

    assert rubric == full_rubric
    assert vector["seed"] == seed
    assert vector["rubric_fingerprint"] == rubric_fingerprint
    assert rubric_bytes == (
        ROOT
        / "src"
        / "regulatory_harvest"
        / "evaluation"
        / "readiness-rubric-v1.json"
    ).read_bytes()
    assert vector["grade_mode"] in {"met", "review", "inconclusive"}
    assert vector["rationale_kind"] in full_rubric["rationale_kinds"]
    assert vector["follow_up_code"] in full_rubric["follow_up_codes"]
    assert vector["owner_role"] in full_rubric["owner_roles"]
    assert vector["blocking_code"] in full_rubric["blocking_codes"]

    monkeypatch.syspath_prepend(str(ROOT / "tests" / "evaluation"))
    inputs = __import__("test_attorney_readiness_inputs")
    workflow = __import__("test_attorney_readiness_workflow")
    generation = __import__(
        "regulatory_harvest.evaluation.attorney_generation", fromlist=["*"]
    )
    source = inputs._make_verified_inputs(
        tmp_path / "inputs",
        limitations=(
            "Machine translated." if vector["declared_limitation"] else None
        ),
    )
    full_run = tmp_path / "full"
    portable_run = tmp_path / "portable"
    init = {
        "baseline_run_dir": source.baseline_run_dir,
        "qualification_run_dir": source.qualification_run_dir,
        "generation_run_dir": source.generation_run_dir,
        "validation_receipt_path": source.validation_receipt_path,
    }
    initialize_readiness_v1(full_run, **init)
    portable.initialize_readiness_v1(
        portable_run, **init, generation_substrate=generation
    )
    provenance = ReadinessEvaluatorProvenanceV1(
        provider_name="public-stress-provider",
        model_name="public-stress-model",
        judge_isolation="scripted_fixture",
    )
    grade_mode = vector["grade_mode"]
    blocking = vector["blocking_safety"]
    disputes = vector["lane_dispute"]
    transcript: list[tuple[bytes, bytes]] = []
    while (full_request := next_readiness_request_v1(full_run)) is not None:
        portable_request = portable.next_readiness_request_v1(portable_run)
        full_request_bytes = json.dumps(
            full_request.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        portable_request_bytes = portable.canonical_json_bytes(portable_request)
        assert portable_request_bytes == full_request_bytes
        if vector["interrupt_resume"]:
            assert portable.next_readiness_request_v1(portable_run) == portable_request
            assert portable.readiness_status_payload_v1(portable_run)[
                "pending_operation"
            ]["operation"] == full_request.operation.value
        draft = workflow._draft(
            full_request,
            grade_mode=grade_mode,
            blocking_safety=blocking,
            disputes=disputes,
        )
        if full_request.operation.value == "safety_review":
            probe = workflow._draft(
                full_request,
                grade_mode=grade_mode,
                blocking_safety=True,
                disputes=disputes,
            )
            target = probe["finding_proposals"][0]
            target["rationale_kind"] = vector["rationale_kind"]
            target["follow_up_code"] = vector["follow_up_code"]
            target["owner_role"] = vector["owner_role"]
            target["visibility"] = vector["visibility"]
            target["blocking_code"] = vector["blocking_code"]
            dispute_field = {
                "finding_existence": "subject_id",
                "rationale": "shortfall_description",
                "evidence_binding": "evidence_refs",
                "visibility": "visibility",
                "blocker": "blocking_code",
                "follow_up": "follow_up_code",
                "owner": "owner_role",
                "resolution_test": "resolution_test",
            }[vector["dispute_kind"]]
            assert dispute_field in target
            if vector["normalization"] or vector["one_repair_success"] or vector[
                "second_refusal_pause"
            ]:
                target["why_unresolved"] = "more research is needed"
            attempts = 2 if vector["second_refusal_pause"] else 1
            before_probe = {
                path.relative_to(full_run).as_posix(): path.read_bytes()
                for path in sorted(full_run.rglob("*"))
                if path.is_file()
            }
            for _ in range(attempts):
                full_probe = compile_readiness_draft_v1(
                    full_request, deepcopy(probe), provenance
                )
                try:
                    portable_probe = portable.compile_readiness_draft_v1(
                        portable_request,
                        deepcopy(probe),
                        {
                            "provider_name": provenance.provider_name,
                            "model_name": provenance.model_name,
                            "judge_isolation": provenance.judge_isolation,
                        },
                    )
                except portable.PortableEvaluationInputError:
                    assert not isinstance(full_probe, CompiledReadinessDraftV1)
                else:
                    assert isinstance(full_probe, CompiledReadinessDraftV1)
                    assert portable_probe == full_probe.response.model_dump(mode="json")
            assert {
                path.relative_to(full_run).as_posix(): path.read_bytes()
                for path in sorted(full_run.rglob("*"))
                if path.is_file()
            } == before_probe
            if vector["second_refusal_pause"]:
                assert portable.readiness_status_payload_v1(portable_run)[
                    "engine_paused"
                ] is False
        full_response = compile_readiness_draft_v1(
            full_request, draft, provenance
        ).response
        portable_response = portable.compile_readiness_draft_v1(
            portable_request,
            deepcopy(draft),
            {
                "provider_name": provenance.provider_name,
                "model_name": provenance.model_name,
                "judge_isolation": provenance.judge_isolation,
            },
        )
        full_response_bytes = json.dumps(
            full_response.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        portable_response_bytes = portable.canonical_json_bytes(portable_response)
        assert portable_response_bytes == full_response_bytes
        transcript.append((full_request_bytes, full_response_bytes))
        assert guarded_submit_readiness_response_v1(full_run, full_response).accepted
        assert portable.guarded_submit_readiness_response_v1(
            portable_run, portable_response
        )["accepted"]
        assert {
            path.relative_to(portable_run).as_posix(): path.read_bytes()
            for path in sorted(portable_run.rglob("*"))
            if path.is_file()
        } == {
            path.relative_to(full_run).as_posix(): path.read_bytes()
            for path in sorted(full_run.rglob("*"))
            if path.is_file()
        }
    assert transcript
    result = json.loads((portable_run / "delivery-readiness.json").read_bytes())
    assert result["protocol_version"] == "delivery-readiness-v1"
    assert result["delivery_readiness"] in {
        "HIGH_ASSURANCE",
        "REVIEW_READY_WITH_GAPS",
        "NOT_DELIVERABLE",
    }


def test_readiness_stress_matrix_covers_every_declared_dimension() -> None:
    portable = _portable()
    _, rubric, _ = portable._readiness_rubric_v1()
    vectors = [portable._readiness_stress_vector_v1(seed, rubric) for seed in range(96)]

    for field, expected in (
        ("grade_mode", {"met", "review", "inconclusive"}),
        ("declared_limitation", {False, True}),
        ("blocking_safety", {False, True}),
        ("lane_dispute", {False, True}),
        ("rationale_kind", set(rubric["rationale_kinds"])),
        ("follow_up_code", set(rubric["follow_up_codes"])),
        ("owner_role", set(rubric["owner_roles"])),
        ("blocking_code", set(rubric["blocking_codes"])),
        ("visibility", {"hidden", "visible", "prominent"}),
        (
            "dispute_kind",
            {
                "finding_existence",
                "rationale",
                "evidence_binding",
                "visibility",
                "blocker",
                "follow_up",
                "owner",
                "resolution_test",
            },
        ),
    ):
        assert {vector[field] for vector in vectors} == expected
    for field in (
        "normalization",
        "one_repair_success",
        "second_refusal_pause",
        "interrupt_resume",
    ):
        assert {vector[field] for vector in vectors} == {False, True}
