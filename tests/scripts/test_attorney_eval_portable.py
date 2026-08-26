from __future__ import annotations

import base64
import concurrent.futures
import copy
import hashlib
import importlib.util
import io
import json
import math
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import time
from pathlib import Path
from types import ModuleType
from typing import Any, cast

import pytest
from pydantic import ValidationError

from regulatory_harvest.evaluation import attorney_artifacts
from regulatory_harvest.evaluation import attorney_workflow as core_workflow
from regulatory_harvest.evaluation.attorney_admission import (
    adjudicate_admission as adjudicate_core,
)
from regulatory_harvest.evaluation.attorney_admission import build_admission_packet as packet_core
from regulatory_harvest.evaluation.attorney_admission import freeze_case as freeze_core
from regulatory_harvest.evaluation.attorney_baseline_input import (
    baseline_reuse_decision_v1 as baseline_reuse_decision_core,
)
from regulatory_harvest.evaluation.attorney_baseline_models import BaselineInputV1
from regulatory_harvest.evaluation.attorney_cli import _case_from_fixture
from regulatory_harvest.evaluation.attorney_contract import (
    PREFLIGHT_ISSUE_MESSAGES,
    ResponseContractCode,
)
from regulatory_harvest.evaluation.attorney_grading import GradeInconclusiveError
from regulatory_harvest.evaluation.attorney_grading import resolve_grades as resolve_core
from regulatory_harvest.evaluation.attorney_grading import validate_grade as validate_grade_core
from regulatory_harvest.evaluation.attorney_ledger import (
    LedgerInconclusiveError as LedgerInconclusiveErrorCore,
)
from regulatory_harvest.evaluation.attorney_ledger import (
    _ledger_invariant_contract_v1_0,
    ledger_invariant_contract,
)
from regulatory_harvest.evaluation.attorney_ledger import (
    ledger_disputes as ledger_disputes_core,
)
from regulatory_harvest.evaluation.attorney_ledger import ledger_findings as ledger_findings_core
from regulatory_harvest.evaluation.attorney_ledger import seal_ledger as seal_core
from regulatory_harvest.evaluation.attorney_models import (
    AttorneyEvaluationResult,
    CandidateGrade,
    CaseAdmissionJudgment,
    DeterministicChecks,
    EvaluationPreflightIssue,
    GradeDispute,
    JudgeResponse,
    LedgerAudit,
    LedgerDispute,
    LegalLedger,
    QualificationCase,
    SealedLedger,
)
from regulatory_harvest.evaluation.attorney_qualification import (
    _preflight_result as qualification_preflight_result_core,
)
from regulatory_harvest.evaluation.attorney_qualification import (
    guarded_submit_case_qualification as guarded_submit_qualification_core,
)
from regulatory_harvest.evaluation.attorney_qualification import (
    initialize_case_qualification as initialize_qualification_core,
)
from regulatory_harvest.evaluation.attorney_qualification import (
    next_qualification_request as next_qualification_core,
)
from regulatory_harvest.evaluation.attorney_qualification import (
    preflight_case_qualification as preflight_qualification_core,
)
from regulatory_harvest.evaluation.attorney_qualification import (
    resume_case_qualification as resume_qualification_core,
)
from regulatory_harvest.evaluation.attorney_qualification import (
    submit_case_qualification as submit_qualification_core,
)
from regulatory_harvest.evaluation.attorney_qualification import (
    verify_case_qualification as verify_qualification_core,
)
from regulatory_harvest.evaluation.attorney_readiness_drafts import (
    CompiledReadinessDraftV1,
    ReadinessEvaluatorProvenanceV1,
    compile_readiness_draft_v1,
)
from regulatory_harvest.evaluation.attorney_readiness_models import (
    ReadinessEvaluatorRequestV1,
)
from regulatory_harvest.evaluation.attorney_readiness_workflow import (
    guarded_submit_readiness_response_v1 as submit_readiness_core,
)
from regulatory_harvest.evaluation.attorney_readiness_workflow import (
    initialize_readiness_v1 as initialize_readiness_core,
)
from regulatory_harvest.evaluation.attorney_readiness_workflow import (
    next_readiness_request_v1 as next_readiness_core,
)
from regulatory_harvest.evaluation.attorney_scoring import (
    ReportScoreInputs,
)
from regulatory_harvest.evaluation.attorney_scoring import (
    compare_reports as compare_core,
)
from regulatory_harvest.evaluation.attorney_scoring import score_report as score_core
from regulatory_harvest.evaluation.attorney_v22_drafts import (
    CompiledDraftV22,
    EvaluatorProvenanceV22,
    compile_evaluator_draft_v22,
)
from regulatory_harvest.evaluation.attorney_v22_models import EvaluatorRequestV22
from regulatory_harvest.evaluation.attorney_v22_requests import (
    COMPILER_CONTRACT_FINGERPRINT_V22,
)
from regulatory_harvest.evaluation.attorney_v22_workflow import (
    guarded_submit_evaluator_response_v22 as guarded_submit_v22_core,
)
from regulatory_harvest.evaluation.attorney_v22_workflow import (
    initialize_evaluation_v22 as initialize_v22_core,
)
from regulatory_harvest.evaluation.attorney_v22_workflow import (
    next_evaluator_request_v22 as next_v22_core,
)
from regulatory_harvest.evaluation.attorney_v22_workflow import (
    preflight_evaluator_response_v22 as preflight_v22_core,
)
from regulatory_harvest.evaluation.attorney_workflow import (
    _audit_ledger_request as audit_ledger_request_core,
)
from regulatory_harvest.evaluation.attorney_workflow import (
    _build_ledger_request as build_ledger_request_core,
)
from regulatory_harvest.evaluation.attorney_workflow import (
    _ledger_referee_request as ledger_referee_request_core,
)
from regulatory_harvest.evaluation.attorney_workflow import (
    _repair_ledger_request as repair_ledger_request_core,
)
from regulatory_harvest.evaluation.attorney_workflow import (
    guarded_submit_judge_response as guarded_submit_core,
)
from regulatory_harvest.evaluation.attorney_workflow import (
    initialize_evaluation as initialize_core,
)
from regulatory_harvest.evaluation.attorney_workflow import (
    next_judge_request as next_core,
)
from regulatory_harvest.evaluation.attorney_workflow import (
    submit_judge_response as submit_core,
)
from regulatory_harvest.storage.serialization import canonical_json_bytes

ROOT = Path(__file__).parents[2]
SCRIPT = ROOT / "scripts" / "attorney_eval_portable.py"
FIXTURE = ROOT / "tests" / "fixtures" / "attorney-eval"
V2_FIXTURE = ROOT / "tests" / "fixtures" / "attorney-eval-v2"
READINESS_RUBRIC = (
    ROOT
    / "src"
    / "regulatory_harvest"
    / "evaluation"
    / "readiness-rubric-v1.json"
)
GOLDEN_ARTIFACTS = (
    "case-readiness.json",
    "legal-ledger.json",
    "evaluation-result.json",
    "evaluation-report.md",
)


def _load_portable() -> ModuleType:
    """Load the retained 1.3 internals for their isolated algorithm suite.

    New public runs are exercised through the portable CLI differential tests.
    The established ledger fixtures deliberately retain their internal v1
    constructor so they never create a fresh legacy run via the public surface.
    """
    spec = importlib.util.spec_from_file_location("attorney_eval_portable", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    module.initialize_evaluation = module._initialize_evaluation_v1
    module.verify_evaluation_run = module._verify_evaluation_run_v1
    module.resume_evaluation = module._resume_evaluation_v1
    module.next_judge_request = module._next_judge_request_v1
    module.preflight_judge_response = module._preflight_judge_response_v1
    module.guarded_submit_judge_response = module._guarded_submit_judge_response_v1
    module.submit_judge_response = module._submit_judge_response_v1
    return module


def _load_protocol_21_portable() -> ModuleType:
    """Load the current public portable surface without the retained-1.3 aliases."""
    spec = importlib.util.spec_from_file_location("attorney_eval_portable_v21", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load_protocol_22_portable() -> ModuleType:
    """Load the current public portable surface for Protocol 2.2 conformance."""
    spec = importlib.util.spec_from_file_location("attorney_eval_portable_v22", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_readiness_portable_rubric_asset_is_shared_exact_and_strict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Portable readiness consumes the one packaged policy asset without redeclaration."""
    portable = _load_protocol_22_portable()
    expected = READINESS_RUBRIC.read_bytes()
    rubric_bytes, rubric, fingerprint = portable._readiness_rubric_v1()

    assert rubric_bytes == expected
    assert rubric == json.loads(expected)
    assert fingerprint == hashlib.sha256(expected).hexdigest()

    for name, mutated in (
        ("duplicate", expected[:-1] + b',"version":"delivery-readiness-v1"}'),
        (
            "unknown-key",
            canonical_json_bytes({**json.loads(expected), "unknown_policy_key": True}),
        ),
        (
            "unchanged-version-floor-drift",
            canonical_json_bytes(
                {
                    **json.loads(expected),
                    "review_ready_weighted_coverage_floor": 0.1,
                }
            ),
        ),
    ):
        changed = tmp_path / f"readiness-rubric-{name}.json"
        changed.write_bytes(mutated)
        monkeypatch.setattr(portable, "_READINESS_RUBRIC_PATH", changed)
        with pytest.raises(
            portable.PortableEvaluationInputError,
            match="READINESS_RUBRIC_INVALID",
        ):
            portable._readiness_rubric_v1()

    in_place = tmp_path / "readiness-rubric-in-place-drift.json"
    in_place.write_bytes(
        canonical_json_bytes(
            {
                **json.loads(expected),
                "review_ready_weighted_coverage_floor": 0.1,
            }
        )
    )
    monkeypatch.setattr(portable, "_READINESS_CANONICAL_RUBRIC_PATH", in_place)
    monkeypatch.setattr(portable, "_READINESS_RUBRIC_PATH", in_place)
    with pytest.raises(
        portable.PortableEvaluationInputError,
        match="READINESS_RUBRIC_INVALID",
    ):
        portable._readiness_rubric_v1()


@pytest.mark.parametrize(
    ("command", "flags"),
    [
        (
            "eval-readiness-init",
            (
                "--baseline-run",
                "--qualification-run",
                "--generation-run",
                "--validation-receipt",
                "--historical-v22-run",
                "--historical-report-label",
                "--run",
            ),
        ),
        ("eval-readiness-next", ("--run",)),
        (
            "eval-readiness-submit-safe",
            (
                "--run",
                "--response",
                "--provider-name",
                "--model-name",
                "--judge-isolation",
            ),
        ),
        ("eval-readiness-status", ("--run",)),
        ("eval-readiness-verify", ("--run",)),
    ],
)
def test_readiness_portable_help_isolated(
    command: str, flags: tuple[str, ...]
) -> None:
    completed = subprocess.run(
        [
            "python3",
            "-I",
            "-S",
            str(ROOT / "scripts" / "harvest_portable.py"),
            command,
            "--help",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert (completed.returncode, completed.stderr) == (0, "")
    assert f"harvest-skill {command}" in completed.stdout
    for flag in flags:
        assert flag in completed.stdout


def test_readiness_initial_tree_full_portable_parity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Admission, projection, first request, manifest, and rubric bytes match exactly."""
    monkeypatch.syspath_prepend(str(ROOT / "tests" / "evaluation"))
    inputs = __import__("test_attorney_readiness_inputs")
    generation = __import__(
        "regulatory_harvest.evaluation.attorney_generation", fromlist=["*"]
    )
    source = inputs._make_verified_inputs(tmp_path, limitations=None)
    full_run = tmp_path / "readiness-full"
    portable_run = tmp_path / "readiness-portable"

    initialize_readiness_core(
        full_run,
        baseline_run_dir=source.baseline_run_dir,
        qualification_run_dir=source.qualification_run_dir,
        generation_run_dir=source.generation_run_dir,
        validation_receipt_path=source.validation_receipt_path,
    )
    portable = _load_protocol_22_portable()
    portable.initialize_readiness_v1(
        portable_run,
        baseline_run_dir=source.baseline_run_dir,
        qualification_run_dir=source.qualification_run_dir,
        generation_run_dir=source.generation_run_dir,
        validation_receipt_path=source.validation_receipt_path,
        generation_substrate=generation,
    )

    assert _tree_bytes(portable_run) == _tree_bytes(full_run)
    assert portable.next_readiness_request_v1(portable_run) == json.loads(
        (full_run / "requests" / "grade-lane-1-GB-1-0001.json").read_text()
    )


def test_readiness_portable_rejects_nested_output_and_tampered_next(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Portable admission and next fail closed at the same physical/hash boundaries."""
    monkeypatch.syspath_prepend(str(ROOT / "tests" / "evaluation"))
    inputs = __import__("test_attorney_readiness_inputs")
    generation = __import__(
        "regulatory_harvest.evaluation.attorney_generation", fromlist=["*"]
    )
    source = inputs._make_verified_inputs(tmp_path, limitations=None)
    init = {
        "baseline_run_dir": source.baseline_run_dir,
        "qualification_run_dir": source.qualification_run_dir,
        "generation_run_dir": source.generation_run_dir,
        "validation_receipt_path": source.validation_receipt_path,
    }
    portable = _load_protocol_22_portable()
    with pytest.raises(ValueError, match="READINESS_OUTPUT_OVERLAPS_INPUT"):
        initialize_readiness_core(source.baseline_run_dir / "nested-full", **init)
    with pytest.raises(
        portable.PortableEvaluationInputError,
        match="READINESS_OUTPUT_OVERLAPS_INPUT",
    ):
        portable.initialize_readiness_v1(
            source.baseline_run_dir / "nested-portable",
            **init,
            generation_substrate=generation,
        )
    assert not (source.baseline_run_dir / "nested-full").exists()
    assert not (source.baseline_run_dir / "nested-portable").exists()

    full_run = tmp_path / "tampered-next-full"
    portable_run = tmp_path / "tampered-next-portable"
    initialize_readiness_core(full_run, **init)
    portable.initialize_readiness_v1(
        portable_run, **init, generation_substrate=generation
    )
    for run in (full_run, portable_run):
        manifest = json.loads((run / "readiness-manifest.json").read_bytes())
        request_path = manifest["pending_call"]["request_artifact_path"]
        request = json.loads((run / request_path).read_bytes())
        request["system_instructions"] += " tampered"
        (run / request_path).write_bytes(canonical_json_bytes(request))
    with pytest.raises(Exception, match="READINESS_ARTIFACT_ARTIFACT_HASH"):
        next_readiness_core(full_run)
    with pytest.raises(
        portable.EvaluationIntegrityError, match="READINESS_ARTIFACT_HASH"
    ):
        portable.next_readiness_request_v1(portable_run)

    full_run = tmp_path / "resealed-next-full"
    portable_run = tmp_path / "resealed-next-portable"
    initialize_readiness_core(full_run, **init)
    portable.initialize_readiness_v1(
        portable_run, **init, generation_substrate=generation
    )
    for run in (full_run, portable_run):
        manifest_path = run / "readiness-manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        request_path = manifest["pending_call"]["request_artifact_path"]
        request_artifact = run / request_path
        request = json.loads(request_artifact.read_bytes())
        request["system_instructions"] += " TAMPERED"
        request["request_fingerprint"] = hashlib.sha256(
            canonical_json_bytes(
                {
                    key: value
                    for key, value in request.items()
                    if key != "request_fingerprint"
                }
            )
        ).hexdigest()
        request_bytes = canonical_json_bytes(request)
        request_artifact.write_bytes(request_bytes)
        manifest["pending_call"]["request_fingerprint"] = request[
            "request_fingerprint"
        ]
        for record in manifest["artifacts"]:
            if record["artifact_path"] == request_path:
                record["artifact_hash"] = hashlib.sha256(request_bytes).hexdigest()
        body = {
            key: value
            for key, value in manifest.items()
            if key not in {"manifest_fingerprint", "root_hash"}
        }
        manifest["manifest_fingerprint"] = hashlib.sha256(
            canonical_json_bytes(body)
        ).hexdigest()
        manifest["root_hash"] = hashlib.sha256(
            canonical_json_bytes(
                {key: value for key, value in manifest.items() if key != "root_hash"}
            )
        ).hexdigest()
        manifest_path.write_bytes(canonical_json_bytes(manifest))
    with pytest.raises(Exception, match="READINESS_ARTIFACT_CALL_HISTORY"):
        next_readiness_core(full_run)
    with pytest.raises(
        portable.EvaluationIntegrityError,
        match="READINESS_ARTIFACT_CALL_HISTORY",
    ):
        portable.next_readiness_request_v1(portable_run)


def test_readiness_portable_rejects_private_qualification_projection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Qualification text containing a private absolute path is never persisted."""
    monkeypatch.syspath_prepend(str(ROOT / "tests" / "evaluation"))
    inputs = __import__("test_attorney_readiness_inputs")
    generation = __import__(
        "regulatory_harvest.evaluation.attorney_generation", fromlist=["*"]
    )
    source = inputs._make_verified_inputs(
        tmp_path,
        limitations="See /private/client-matter/source.txt before delivery.",
    )
    init = {
        "baseline_run_dir": source.baseline_run_dir,
        "qualification_run_dir": source.qualification_run_dir,
        "generation_run_dir": source.generation_run_dir,
        "validation_receipt_path": source.validation_receipt_path,
    }
    portable = _load_protocol_22_portable()
    full_run = tmp_path / "private-full"
    portable_run = tmp_path / "private-portable"
    with pytest.raises(Exception, match="READINESS_QUALIFICATION_INVALID"):
        initialize_readiness_core(full_run, **init)
    with pytest.raises(
        portable.PortableEvaluationInputError,
        match="READINESS_QUALIFICATION_INVALID",
    ):
        portable.initialize_readiness_v1(
            portable_run, **init, generation_substrate=generation
        )
    assert not full_run.exists()
    assert not portable_run.exists()


def test_readiness_portable_rejects_resealed_private_persisted_projection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Authenticated replay cannot turn a private qualification path into a prompt."""
    monkeypatch.syspath_prepend(str(ROOT / "tests" / "evaluation"))
    inputs = __import__("test_attorney_readiness_inputs")
    artifacts = __import__(
        "regulatory_harvest.evaluation.attorney_readiness_artifacts",
        fromlist=["*"],
    )
    generation = __import__(
        "regulatory_harvest.evaluation.attorney_generation", fromlist=["*"]
    )
    source = inputs._make_verified_inputs(tmp_path, limitations=None)
    init = {
        "baseline_run_dir": source.baseline_run_dir,
        "qualification_run_dir": source.qualification_run_dir,
        "generation_run_dir": source.generation_run_dir,
        "validation_receipt_path": source.validation_receipt_path,
    }
    runs = (tmp_path / "persisted-private-full", tmp_path / "persisted-private-portable")
    initialize_readiness_core(runs[0], **init)
    portable = _load_protocol_22_portable()
    portable.initialize_readiness_v1(runs[1], **init, generation_substrate=generation)
    private_text = "See /private/client-secret.txt before delivery."
    for run in runs:
        input_path = run / "readiness-input.json"
        persisted = json.loads(input_path.read_bytes())
        persisted["qualification_limits"]["receipt_readiness"]["rationale"] = (
            private_text
        )
        input_bytes = canonical_json_bytes(persisted)
        input_path.write_bytes(input_bytes)
        manifest_path = run / "readiness-manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        next(
            row
            for row in manifest["artifacts"]
            if row["artifact_path"] == "readiness-input.json"
        )["artifact_hash"] = hashlib.sha256(input_bytes).hexdigest()
        body = {
            key: value
            for key, value in manifest.items()
            if key not in {"manifest_fingerprint", "root_hash"}
        }
        manifest["manifest_fingerprint"] = hashlib.sha256(
            canonical_json_bytes(body)
        ).hexdigest()
        manifest["root_hash"] = hashlib.sha256(
            canonical_json_bytes(
                {key: value for key, value in manifest.items() if key != "root_hash"}
            )
        ).hexdigest()
        manifest_path.write_bytes(canonical_json_bytes(manifest))
    full_verification = artifacts.verify_readiness_run_v1(runs[0]).model_dump(
        mode="json"
    )
    portable_verification = portable.verify_readiness_run_v1(runs[1])
    assert portable_verification == full_verification
    assert portable_verification["valid"] is False
    assert portable_verification["issues"] == ["READINESS_STORAGE_UNSAFE"]
    before = _tree_bytes(runs[1])
    with pytest.raises(portable.EvaluationIntegrityError):
        portable.next_readiness_request_v1(runs[1])
    assert _tree_bytes(runs[1]) == before
    assert private_text.encode() not in b"".join(
        data for path, data in before.items() if path.startswith("requests/")
    )


def test_readiness_portable_rejects_forged_validation_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A canonical but non-replayable bundle cannot satisfy readiness admission."""
    monkeypatch.syspath_prepend(str(ROOT / "tests" / "evaluation"))
    inputs = __import__("test_attorney_readiness_inputs")
    generation = __import__(
        "regulatory_harvest.evaluation.attorney_generation", fromlist=["*"]
    )
    source = inputs._make_verified_inputs(tmp_path, limitations=None)
    receipt = json.loads(source.validation_receipt_path.read_bytes())
    Path(receipt["bundle"]).write_bytes(b"{}")
    init = {
        "baseline_run_dir": source.baseline_run_dir,
        "qualification_run_dir": source.qualification_run_dir,
        "generation_run_dir": source.generation_run_dir,
        "validation_receipt_path": source.validation_receipt_path,
    }
    full_run = tmp_path / "forged-validation-full"
    portable_run = tmp_path / "forged-validation-portable"
    with pytest.raises(Exception, match="READINESS_VALIDATION_RECEIPT_INVALID"):
        initialize_readiness_core(full_run, **init)
    portable = _load_protocol_22_portable()
    with pytest.raises(
        portable.PortableEvaluationInputError,
        match="READINESS_VALIDATION_RECEIPT_INVALID",
    ):
        portable.initialize_readiness_v1(
            portable_run, **init, generation_substrate=generation
        )
    assert not full_run.exists()
    assert not portable_run.exists()


def test_readiness_portable_rejects_boolean_validation_receipt_count(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Boolean values cannot impersonate native integer validation counts."""
    monkeypatch.syspath_prepend(str(ROOT / "tests" / "evaluation"))
    inputs = __import__("test_attorney_readiness_inputs")
    generation = __import__(
        "regulatory_harvest.evaluation.attorney_generation", fromlist=["*"]
    )
    source = inputs._make_verified_inputs(tmp_path, limitations=None)
    receipt = json.loads(source.validation_receipt_path.read_bytes())
    receipt["blocking_review_count"] = False
    source.validation_receipt_path.write_bytes(canonical_json_bytes(receipt) + b"\n")
    init = {
        "baseline_run_dir": source.baseline_run_dir,
        "qualification_run_dir": source.qualification_run_dir,
        "generation_run_dir": source.generation_run_dir,
        "validation_receipt_path": source.validation_receipt_path,
    }
    full_run = tmp_path / "boolean-count-full"
    portable_run = tmp_path / "boolean-count-portable"
    with pytest.raises(Exception, match="READINESS_VALIDATION_RECEIPT_INVALID"):
        initialize_readiness_core(full_run, **init)
    portable = _load_protocol_22_portable()
    with pytest.raises(
        portable.PortableEvaluationInputError,
        match="READINESS_VALIDATION_RECEIPT_INVALID",
    ):
        portable.initialize_readiness_v1(
            portable_run, **init, generation_substrate=generation
        )
    assert not full_run.exists()
    assert not portable_run.exists()


@pytest.mark.parametrize(
    "mutation",
    [
        "manifest-unknown",
        "updated-at-type",
        "configuration-fingerprint-type",
        "created-at-date-only",
        "validated-at-invalid",
        "generator-mismatch",
        "source-input-title-type",
        "source-input-language-normalization",
        "multi-running-stages",
        "nonterminal-before-terminal",
    ],
)
def test_readiness_portable_rejects_nested_validation_bundle_mutations(
    mutation: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Strict generation bundle metadata cannot be canonically resealed around replay."""
    monkeypatch.syspath_prepend(str(ROOT / "tests" / "evaluation"))
    inputs = __import__("test_attorney_readiness_inputs")
    generation = __import__(
        "regulatory_harvest.evaluation.attorney_generation", fromlist=["*"]
    )
    source = inputs._make_verified_inputs(tmp_path, limitations=None)
    receipt = json.loads(source.validation_receipt_path.read_bytes())
    bundle_path = Path(receipt["bundle"])
    bundle = json.loads(bundle_path.read_bytes())
    dossier_path = source.validation_receipt_path.parent / "agent-dossier.json"
    dossier = json.loads(dossier_path.read_bytes())
    if mutation == "manifest-unknown":
        bundle["manifest"]["unknown"] = True
    elif mutation == "updated-at-type":
        bundle["manifest"]["updated_at"] = 7
    elif mutation == "configuration-fingerprint-type":
        bundle["manifest"]["configuration_fingerprint"] = 7
    elif mutation == "created-at-date-only":
        bundle["manifest"]["created_at"] = "2026-08-25"
    elif mutation == "validated-at-invalid":
        bundle["validation"]["validated_at"] = "banana"
    elif mutation == "generator-mismatch":
        bundle["generator_version"] = "regulatory-harvest/999"
    elif mutation == "source-input-title-type":
        bundle["request"]["source_inputs"][0]["title"] = 7
        dossier["request"]["source_inputs"][0]["title"] = 7
        dossier_path.write_bytes(canonical_json_bytes(dossier) + b"\n")
    elif mutation == "source-input-language-normalization":
        bundle["request"]["source_inputs"][0]["language"] = " en "
        dossier["request"]["source_inputs"][0]["language"] = " en "
        dossier_path.write_bytes(canonical_json_bytes(dossier) + b"\n")
    elif mutation == "multi-running-stages":
        bundle["manifest"]["stages"][0]["status"] = "running"
        bundle["manifest"]["stages"][1]["status"] = "running"
    else:
        bundle["manifest"]["stages"][1]["status"] = "completed"
    bundle["bundle_hash"] = hashlib.sha256(
        canonical_json_bytes(
            {key: value for key, value in bundle.items() if key != "bundle_hash"}
        )
    ).hexdigest()
    bundle_path.write_bytes(canonical_json_bytes(bundle))
    init = {
        "baseline_run_dir": source.baseline_run_dir,
        "qualification_run_dir": source.qualification_run_dir,
        "generation_run_dir": source.generation_run_dir,
        "validation_receipt_path": source.validation_receipt_path,
    }
    full_run = tmp_path / f"{mutation}-full"
    portable_run = tmp_path / f"{mutation}-portable"
    with pytest.raises(Exception, match="READINESS_VALIDATION_RECEIPT_INVALID"):
        initialize_readiness_core(full_run, **init)
    portable = _load_protocol_22_portable()
    with pytest.raises(
        portable.PortableEvaluationInputError,
        match="READINESS_VALIDATION_RECEIPT_INVALID",
    ):
        portable.initialize_readiness_v1(
            portable_run, **init, generation_substrate=generation
        )
    assert not full_run.exists()
    assert not portable_run.exists()


@pytest.mark.parametrize("field", ["context", "output_instructions"])
def test_readiness_portable_accepts_empty_optional_generation_request_text(
    field: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Strict optional request strings retain the full model's empty-string semantics."""
    monkeypatch.syspath_prepend(str(ROOT / "tests" / "evaluation"))
    inputs = __import__("test_attorney_readiness_inputs")
    generation = __import__(
        "regulatory_harvest.evaluation.attorney_generation", fromlist=["*"]
    )
    source = inputs._make_verified_inputs(tmp_path, limitations=None)
    receipt = json.loads(source.validation_receipt_path.read_bytes())
    bundle_path = Path(receipt["bundle"])
    dossier_path = source.validation_receipt_path.parent / "agent-dossier.json"
    bundle = json.loads(bundle_path.read_bytes())
    dossier = json.loads(dossier_path.read_bytes())
    bundle["request"][field] = ""
    dossier["request"][field] = ""
    dossier_path.write_bytes(canonical_json_bytes(dossier) + b"\n")
    bundle["bundle_hash"] = hashlib.sha256(
        canonical_json_bytes(
            {key: value for key, value in bundle.items() if key != "bundle_hash"}
        )
    ).hexdigest()
    bundle_path.write_bytes(canonical_json_bytes(bundle))
    init = {
        "baseline_run_dir": source.baseline_run_dir,
        "qualification_run_dir": source.qualification_run_dir,
        "generation_run_dir": source.generation_run_dir,
        "validation_receipt_path": source.validation_receipt_path,
    }
    full_run = tmp_path / f"empty-{field}-full"
    portable_run = tmp_path / f"empty-{field}-portable"
    initialize_readiness_core(full_run, **init)
    portable = _load_protocol_22_portable()
    portable.initialize_readiness_v1(
        portable_run, **init, generation_substrate=generation
    )
    assert _tree_bytes(portable_run) == _tree_bytes(full_run)


def test_readiness_portable_accepts_full_valid_failed_generation_stage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A strict failed final generation stage retains full readiness admission parity."""
    monkeypatch.syspath_prepend(str(ROOT / "tests" / "evaluation"))
    inputs = __import__("test_attorney_readiness_inputs")
    generation = __import__(
        "regulatory_harvest.evaluation.attorney_generation", fromlist=["*"]
    )
    source = inputs._make_verified_inputs(tmp_path, limitations=None)
    receipt = json.loads(source.validation_receipt_path.read_bytes())
    bundle_path = Path(receipt["bundle"])
    bundle = json.loads(bundle_path.read_bytes())
    final_stage = bundle["manifest"]["stages"][-1]
    final_stage["status"] = "failed"
    final_stage["completed_at"] = None
    final_stage["error"] = {
        "stage": final_stage["name"],
        "category": "public-fixture",
        "retryable": False,
        "message": "The public synthetic stage failed.",
        "provider_status_code": None,
    }
    bundle["bundle_hash"] = hashlib.sha256(
        canonical_json_bytes(
            {key: value for key, value in bundle.items() if key != "bundle_hash"}
        )
    ).hexdigest()
    bundle_path.write_bytes(canonical_json_bytes(bundle))
    init = {
        "baseline_run_dir": source.baseline_run_dir,
        "qualification_run_dir": source.qualification_run_dir,
        "generation_run_dir": source.generation_run_dir,
        "validation_receipt_path": source.validation_receipt_path,
    }
    full_run = tmp_path / "failed-stage-full"
    portable_run = tmp_path / "failed-stage-portable"
    initialize_readiness_core(full_run, **init)
    portable = _load_protocol_22_portable()
    portable.initialize_readiness_v1(
        portable_run, **init, generation_substrate=generation
    )
    assert _tree_bytes(portable_run) == _tree_bytes(full_run)


def test_readiness_portable_initialization_rolls_back_manifest_write_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed initial manifest write leaves no partially authenticated graph."""
    monkeypatch.syspath_prepend(str(ROOT / "tests" / "evaluation"))
    inputs = __import__("test_attorney_readiness_inputs")
    generation = __import__(
        "regulatory_harvest.evaluation.attorney_generation", fromlist=["*"]
    )
    source = inputs._make_verified_inputs(tmp_path, limitations=None)
    portable = _load_protocol_22_portable()
    original = portable._PosixRunStorage.atomic_write

    def fail_manifest(
        storage: object, path: str, data: bytes, *, mutable: bool
    ) -> object:
        if path == "readiness-manifest.json":
            raise OSError("injected readiness manifest failure")
        return original(storage, path, data, mutable=mutable)

    monkeypatch.setattr(portable._PosixRunStorage, "atomic_write", fail_manifest)
    output = tmp_path / "portable-init-rollback"
    with pytest.raises(portable.EvaluationIntegrityError):
        portable.initialize_readiness_v1(
            output,
            baseline_run_dir=source.baseline_run_dir,
            qualification_run_dir=source.qualification_run_dir,
            generation_run_dir=source.generation_run_dir,
            validation_receipt_path=source.validation_receipt_path,
            generation_substrate=generation,
        )
    assert _tree_bytes(output) == {}


@pytest.mark.parametrize("concurrent_callers", [False, True])
def test_readiness_portable_transition_is_atomic_and_serialized(
    concurrent_callers: bool, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A transition rolls back on failure and admits one cooperating caller only."""
    monkeypatch.syspath_prepend(str(ROOT / "tests" / "evaluation"))
    inputs = __import__("test_attorney_readiness_inputs")
    workflow = __import__("test_attorney_readiness_workflow")
    generation = __import__(
        "regulatory_harvest.evaluation.attorney_generation", fromlist=["*"]
    )
    source = inputs._make_verified_inputs(tmp_path, limitations=None)
    init = {
        "baseline_run_dir": source.baseline_run_dir,
        "qualification_run_dir": source.qualification_run_dir,
        "generation_run_dir": source.generation_run_dir,
        "validation_receipt_path": source.validation_receipt_path,
    }
    full_run = tmp_path / "transaction-full"
    portable_run = tmp_path / "transaction-portable"
    initialize_readiness_core(full_run, **init)
    portable = _load_protocol_22_portable()
    portable.initialize_readiness_v1(
        portable_run, **init, generation_substrate=generation
    )
    request = next_readiness_core(full_run)
    portable_request = portable.next_readiness_request_v1(portable_run)
    assert request is not None and portable_request is not None
    response = portable.compile_readiness_draft_v1(
        portable_request,
        workflow._draft(request, grade_mode="met"),
        {
            "provider_name": "portable-parity-provider",
            "model_name": "portable-parity-model",
            "judge_isolation": "scripted_fixture",
        },
    )
    if concurrent_callers:
        barrier = __import__("threading").Barrier(2)

        def submit(_: int) -> dict[str, object]:
            barrier.wait()
            return portable.guarded_submit_readiness_response_v1(
                portable_run, response
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(submit, range(2)))
        assert sorted(outcome["accepted"] for outcome in outcomes) == [False, True]
        loser = next(outcome for outcome in outcomes if not outcome["accepted"])
        assert loser["reason_code"] == "READINESS_EXTERNAL_RESPONSE_INVALID"
        assert portable.verify_readiness_run_v1(portable_run)["valid"] is True
        return

    before = _tree_bytes(portable_run)
    original = portable._PosixRunStorage.atomic_write

    def fail_manifest(
        storage: object, path: str, data: bytes, *, mutable: bool
    ) -> object:
        if path == "readiness-manifest.json" and mutable:
            raise OSError("injected readiness transition failure")
        return original(storage, path, data, mutable=mutable)

    monkeypatch.setattr(portable._PosixRunStorage, "atomic_write", fail_manifest)
    with pytest.raises(portable.EvaluationIntegrityError):
        portable.guarded_submit_readiness_response_v1(portable_run, response)
    assert _tree_bytes(portable_run) == before
    assert portable.verify_readiness_run_v1(portable_run)["valid"] is True


def test_readiness_portable_isolated_processes_serialize_same_response(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Descriptor locking gives two isolated submitters one exact winner."""
    monkeypatch.syspath_prepend(str(ROOT / "tests" / "evaluation"))
    inputs = __import__("test_attorney_readiness_inputs")
    workflow = __import__("test_attorney_readiness_workflow")
    generation = __import__(
        "regulatory_harvest.evaluation.attorney_generation", fromlist=["*"]
    )
    source = inputs._make_verified_inputs(tmp_path, limitations=None)
    init = {
        "baseline_run_dir": source.baseline_run_dir,
        "qualification_run_dir": source.qualification_run_dir,
        "generation_run_dir": source.generation_run_dir,
        "validation_receipt_path": source.validation_receipt_path,
    }
    full_run = tmp_path / "process-lock-full"
    portable_run = tmp_path / "process-lock-portable"
    initialize_readiness_core(full_run, **init)
    portable = _load_protocol_22_portable()
    portable.initialize_readiness_v1(portable_run, **init, generation_substrate=generation)
    request = next_readiness_core(full_run)
    portable_request = portable.next_readiness_request_v1(portable_run)
    assert request is not None and portable_request is not None
    response = portable.compile_readiness_draft_v1(
        portable_request,
        workflow._draft(request, grade_mode="met"),
        {
            "provider_name": "portable-parity-provider",
            "model_name": "portable-parity-model",
            "judge_isolation": "scripted_fixture",
        },
    )
    response_path = tmp_path / "process-response.json"
    response_path.write_bytes(canonical_json_bytes(response))
    barrier = tmp_path / "process-barrier"
    barrier.mkdir()
    script = """
import importlib.util, json, sys, time
from pathlib import Path
spec = importlib.util.spec_from_file_location("portable_process", sys.argv[1])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
run = Path(sys.argv[2])
response = json.loads(Path(sys.argv[3]).read_bytes())
barrier = Path(sys.argv[4])
identity = sys.argv[5]
original = module._readiness_snapshot_unlocked
def synchronized_snapshot(path):
    result = original(path)
    (barrier / identity).write_text("ready", encoding="utf-8")
    deadline = time.monotonic() + 1.0
    while len(tuple(barrier.iterdir())) < 2 and time.monotonic() < deadline:
        time.sleep(0.01)
    return result
module._readiness_snapshot_unlocked = synchronized_snapshot
print(json.dumps(module.guarded_submit_readiness_response_v1(run, response), sort_keys=True))
"""
    processes = [
        subprocess.Popen(
            [
                "python3",
                "-I",
                "-S",
                "-c",
                script,
                str(SCRIPT),
                str(portable_run),
                str(response_path),
                str(barrier),
                str(index),
            ],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        for index in range(2)
    ]
    completed = [process.communicate(timeout=20) for process in processes]
    assert [process.returncode for process in processes] == [0, 0]
    assert [stderr for _stdout, stderr in completed] == [b"", b""]
    outcomes = [json.loads(stdout) for stdout, _stderr in completed]
    assert sorted(outcome["accepted"] for outcome in outcomes) == [False, True]
    assert portable.verify_readiness_run_v1(portable_run)["valid"] is True


@pytest.mark.parametrize("reader", ["status", "verify"])
def test_readiness_portable_isolated_readers_wait_for_transition(
    reader: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Shared descriptor locks keep readers outside an active transition."""
    monkeypatch.syspath_prepend(str(ROOT / "tests" / "evaluation"))
    inputs = __import__("test_attorney_readiness_inputs")
    workflow = __import__("test_attorney_readiness_workflow")
    generation = __import__(
        "regulatory_harvest.evaluation.attorney_generation", fromlist=["*"]
    )
    source = inputs._make_verified_inputs(tmp_path, limitations=None)
    portable = _load_protocol_22_portable()
    run = tmp_path / f"process-reader-{reader}"
    portable.initialize_readiness_v1(
        run,
        baseline_run_dir=source.baseline_run_dir,
        qualification_run_dir=source.qualification_run_dir,
        generation_run_dir=source.generation_run_dir,
        validation_receipt_path=source.validation_receipt_path,
        generation_substrate=generation,
    )
    request = portable.next_readiness_request_v1(run)
    assert request is not None
    response = portable.compile_readiness_draft_v1(
        request,
        workflow._draft(ReadinessEvaluatorRequestV1.model_validate(request), grade_mode="met"),
        {
            "provider_name": "portable-parity-provider",
            "model_name": "portable-parity-model",
            "judge_isolation": "scripted_fixture",
        },
    )
    response_path = tmp_path / f"reader-{reader}-response.json"
    response_path.write_bytes(canonical_json_bytes(response))
    entered = tmp_path / f"reader-{reader}-entered"
    release = tmp_path / f"reader-{reader}-release"
    transition_script = """
import importlib.util, json, sys, time
from pathlib import Path
spec = importlib.util.spec_from_file_location("portable_transition", sys.argv[1])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
run, response_path, entered, release = map(Path, sys.argv[2:])
response = json.loads(response_path.read_bytes())
original = module._readiness_commit
def paused_commit(*args, **kwargs):
    entered.write_text("entered", encoding="utf-8")
    deadline = time.monotonic() + 10.0
    while not release.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    return original(*args, **kwargs)
module._readiness_commit = paused_commit
print(json.dumps(module.guarded_submit_readiness_response_v1(run, response), sort_keys=True))
"""
    reader_script = """
import importlib.util, json, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("portable_reader", sys.argv[1])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
run = Path(sys.argv[2])
value = (module.readiness_status_payload_v1(run) if sys.argv[3] == "status"
         else module.verify_readiness_run_v1(run))
print(json.dumps(value, sort_keys=True))
"""
    transition = subprocess.Popen(
        [
            "python3",
            "-I",
            "-S",
            "-c",
            transition_script,
            str(SCRIPT),
            str(run),
            str(response_path),
            str(entered),
            str(release),
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    deadline = time.monotonic() + 10.0
    while not entered.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert entered.exists()
    reading = subprocess.Popen(
        ["python3", "-I", "-S", "-c", reader_script, str(SCRIPT), str(run), reader],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(0.2)
    assert reading.poll() is None
    release.write_bytes(b"release")
    transition_stdout, transition_stderr = transition.communicate(timeout=20)
    reader_stdout, reader_stderr = reading.communicate(timeout=20)
    assert transition.returncode == reading.returncode == 0
    assert transition_stderr == reader_stderr == b""
    assert json.loads(transition_stdout)["accepted"] is True
    payload = json.loads(reader_stdout)
    if reader == "verify":
        assert payload["valid"] is True
    else:
        assert payload["protocol_version"] == "delivery-readiness-v1"
        assert payload["pending_operation"]["operation"] == "baseline_locked_grade"


@pytest.mark.parametrize("shape", ["cycle", "deep"])
def test_readiness_portable_bounds_native_response_and_draft_graphs(
    shape: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cyclic and over-depth native objects are refused without recursion or writes."""
    monkeypatch.syspath_prepend(str(ROOT / "tests" / "evaluation"))
    inputs = __import__("test_attorney_readiness_inputs")
    generation = __import__(
        "regulatory_harvest.evaluation.attorney_generation", fromlist=["*"]
    )
    source = inputs._make_verified_inputs(tmp_path, limitations=None)
    init = {
        "baseline_run_dir": source.baseline_run_dir,
        "qualification_run_dir": source.qualification_run_dir,
        "generation_run_dir": source.generation_run_dir,
        "validation_receipt_path": source.validation_receipt_path,
    }
    full_run = tmp_path / f"native-{shape}-full"
    portable_run = tmp_path / f"native-{shape}-portable"
    initialize_readiness_core(full_run, **init)
    portable = _load_protocol_22_portable()
    portable.initialize_readiness_v1(portable_run, **init, generation_substrate=generation)
    full_request = next_readiness_core(full_run)
    portable_request = portable.next_readiness_request_v1(portable_run)
    assert full_request is not None and portable_request is not None
    if shape == "cycle":
        hostile: dict[str, object] = {}
        hostile["x"] = hostile
    else:
        hostile = {}
        cursor = hostile
        for _ in range(70):
            child: dict[str, object] = {}
            cursor["x"] = child
            cursor = child
    provenance = ReadinessEvaluatorProvenanceV1(
        provider_name="portable-parity-provider",
        model_name="portable-parity-model",
        judge_isolation="scripted_fixture",
    )
    full_compile = compile_readiness_draft_v1(full_request, hostile, provenance)
    expected_reason = "DRAFT_INVALID" if shape == "cycle" else "DRAFT_DEPTH_EXCEEDED"
    assert tuple(code.value for code in full_compile.reason_codes) == (expected_reason,)
    with pytest.raises(
        portable.PortableEvaluationInputError, match="READINESS_DRAFT_INVALID"
    ):
        portable.compile_readiness_draft_v1(
            portable_request,
            hostile,
            {
                "provider_name": provenance.provider_name,
                "model_name": provenance.model_name,
                "judge_isolation": provenance.judge_isolation,
            },
        )
    before_full, before_portable = _tree_bytes(full_run), _tree_bytes(portable_run)
    full_submit = submit_readiness_core(full_run, hostile)
    portable_submit = portable.guarded_submit_readiness_response_v1(
        portable_run, hostile
    )
    assert full_submit.accepted is False
    assert portable_submit == {
        "accepted": False,
        "reason_code": "READINESS_EXTERNAL_RESPONSE_INVALID",
    }
    assert (_tree_bytes(full_run), _tree_bytes(portable_run)) == (
        before_full,
        before_portable,
    )


def test_readiness_portable_rejects_generic_safety_rationale(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Generic safety rationale is refused before either controller can persist it."""
    monkeypatch.syspath_prepend(str(ROOT / "tests" / "evaluation"))
    inputs = __import__("test_attorney_readiness_inputs")
    workflow = __import__("test_attorney_readiness_workflow")
    generation = __import__(
        "regulatory_harvest.evaluation.attorney_generation", fromlist=["*"]
    )
    source = inputs._make_verified_inputs(tmp_path, limitations="Machine translated.")
    init = {
        "baseline_run_dir": source.baseline_run_dir,
        "qualification_run_dir": source.qualification_run_dir,
        "generation_run_dir": source.generation_run_dir,
        "validation_receipt_path": source.validation_receipt_path,
    }
    full_run = tmp_path / "generic-rationale-full"
    portable_run = tmp_path / "generic-rationale-portable"
    initialize_readiness_core(full_run, **init)
    portable = _load_protocol_22_portable()
    portable.initialize_readiness_v1(
        portable_run, **init, generation_substrate=generation
    )
    provenance = ReadinessEvaluatorProvenanceV1(
        provider_name="portable-parity-provider",
        model_name="portable-parity-model",
        judge_isolation="scripted_fixture",
    )
    while True:
        request = next_readiness_core(full_run)
        portable_request = portable.next_readiness_request_v1(portable_run)
        assert request is not None
        assert portable_request == request.model_dump(mode="json")
        draft = workflow._draft(request, grade_mode="met")
        if request.operation.value == "safety_review":
            break
        if request.operation.value == "baseline_locked_grade":
            ordinary_generic = copy.deepcopy(draft)
            ordinary_generic["requirement_grades"][0]["rationale"] = "met"
            ordinary_generic["rationale"] = "met"
            full_generic = compile_readiness_draft_v1(
                request, ordinary_generic, provenance
            )
            assert isinstance(full_generic, CompiledReadinessDraftV1)
            assert portable.compile_readiness_draft_v1(
                portable_request,
                copy.deepcopy(ordinary_generic),
                {
                    "provider_name": provenance.provider_name,
                    "model_name": provenance.model_name,
                    "judge_isolation": provenance.judge_isolation,
                },
            ) == full_generic.response.model_dump(mode="json")
        full_response = compile_readiness_draft_v1(
            request, draft, provenance
        ).response
        portable_response = portable.compile_readiness_draft_v1(
            portable_request,
            copy.deepcopy(draft),
            {
                "provider_name": provenance.provider_name,
                "model_name": provenance.model_name,
                "judge_isolation": provenance.judge_isolation,
            },
        )
        assert submit_readiness_core(full_run, full_response).accepted
        assert portable.guarded_submit_readiness_response_v1(
            portable_run, portable_response
        )["accepted"]
    normalized_drafts: list[dict[str, object]] = []
    duplicate_ref = copy.deepcopy(draft)
    duplicate_ref["candidate_assessments"][0]["evidence_refs"].append(
        duplicate_ref["candidate_assessments"][0]["evidence_refs"][0]
    )
    normalized_drafts.append(duplicate_ref)
    duplicate_assessment = copy.deepcopy(draft)
    duplicate_assessment["candidate_assessments"].append(
        copy.deepcopy(duplicate_assessment["candidate_assessments"][0])
    )
    normalized_drafts.append(duplicate_assessment)
    duplicate_finding = workflow._draft(
        request, grade_mode="met", blocking_safety=True
    )
    duplicate_finding["finding_proposals"].append(
        copy.deepcopy(duplicate_finding["finding_proposals"][0])
    )
    normalized_drafts.append(duplicate_finding)
    for normalized in normalized_drafts:
        full_normalized = compile_readiness_draft_v1(
            request, normalized, provenance
        )
        assert isinstance(full_normalized, CompiledReadinessDraftV1)
        assert full_normalized.normalization_codes == (
            "DRAFT_NORMALIZED_DUPLICATES",
        )
        assert portable.compile_readiness_draft_v1(
            portable_request,
            copy.deepcopy(normalized),
            {
                "provider_name": provenance.provider_name,
                "model_name": provenance.model_name,
                "judge_isolation": provenance.judge_isolation,
            },
        ) == full_normalized.response.model_dump(mode="json")
    conflicting = copy.deepcopy(duplicate_finding)
    conflicting["finding_proposals"][1]["why_unresolved"] = (
        "The cited source still lacks exact support for this report assertion."
    )
    full_conflict = compile_readiness_draft_v1(request, conflicting, provenance)
    assert tuple(item.value for item in full_conflict.reason_codes) == (
        "CONFLICTING_ITEMS",
    )
    with pytest.raises(
        portable.PortableEvaluationInputError,
        match="READINESS_DRAFT_CONFLICTING_ITEMS",
    ):
        portable.compile_readiness_draft_v1(
            portable_request,
            conflicting,
            {
                "provider_name": provenance.provider_name,
                "model_name": provenance.model_name,
                "judge_isolation": provenance.judge_isolation,
            },
        )
    oversized = copy.deepcopy(draft)
    evidence_refs = oversized["candidate_assessments"][0]["evidence_refs"]
    assert evidence_refs
    oversized["candidate_assessments"][0]["evidence_refs"] = [
        evidence_refs[0]
    ] * 641
    full_oversized = compile_readiness_draft_v1(request, oversized, provenance)
    assert tuple(item.value for item in full_oversized.reason_codes) == (
        "ITEM_LIMIT_EXCEEDED",
    )
    with pytest.raises(
        portable.PortableEvaluationInputError, match="READINESS_DRAFT_INVALID"
    ):
        portable.compile_readiness_draft_v1(
            portable_request,
            oversized,
            {
                "provider_name": provenance.provider_name,
                "model_name": provenance.model_name,
                "judge_isolation": provenance.judge_isolation,
            },
        )
    cast(dict[str, object], cast(list[object], draft["candidate_assessments"])[0])[
        "why_unresolved"
    ] = "more research needed"
    full_outcome = compile_readiness_draft_v1(request, draft, provenance)
    assert tuple(item.value for item in full_outcome.reason_codes) == (
        "RATIONALE_GENERIC",
    )
    with pytest.raises(
        portable.PortableEvaluationInputError, match="READINESS_DRAFT_INVALID"
    ):
        portable.compile_readiness_draft_v1(
            portable_request,
            copy.deepcopy(draft),
            {
                "provider_name": provenance.provider_name,
                "model_name": provenance.model_name,
                "judge_isolation": provenance.judge_isolation,
            },
        )
    assert _tree_bytes(portable_run) == _tree_bytes(full_run)


def test_readiness_portable_rejects_resealed_unknown_manifest_field(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Canonical resealing cannot smuggle an unknown manifest field past verification."""
    monkeypatch.syspath_prepend(str(ROOT / "tests" / "evaluation"))
    inputs = __import__("test_attorney_readiness_inputs")
    generation = __import__(
        "regulatory_harvest.evaluation.attorney_generation", fromlist=["*"]
    )
    artifacts = __import__(
        "regulatory_harvest.evaluation.attorney_readiness_artifacts",
        fromlist=["*"],
    )
    source = inputs._make_verified_inputs(tmp_path, limitations=None)
    init = {
        "baseline_run_dir": source.baseline_run_dir,
        "qualification_run_dir": source.qualification_run_dir,
        "generation_run_dir": source.generation_run_dir,
        "validation_receipt_path": source.validation_receipt_path,
    }
    full_run = tmp_path / "unknown-manifest-full"
    portable_run = tmp_path / "unknown-manifest-portable"
    initialize_readiness_core(full_run, **init)
    portable = _load_protocol_22_portable()
    portable.initialize_readiness_v1(
        portable_run, **init, generation_substrate=generation
    )
    for run in (full_run, portable_run):
        path = run / "readiness-manifest.json"
        manifest = json.loads(path.read_bytes())
        manifest["unknown"] = True
        body = {
            key: value
            for key, value in manifest.items()
            if key not in {"manifest_fingerprint", "root_hash"}
        }
        manifest["manifest_fingerprint"] = hashlib.sha256(
            canonical_json_bytes(body)
        ).hexdigest()
        manifest["root_hash"] = hashlib.sha256(
            canonical_json_bytes(
                {key: value for key, value in manifest.items() if key != "root_hash"}
            )
        ).hexdigest()
        path.write_bytes(canonical_json_bytes(manifest))
    full_verification = artifacts.verify_readiness_run_v1(full_run)
    portable_verification = portable.verify_readiness_run_v1(portable_run)
    assert full_verification.valid is False
    assert full_verification.issues == ("READINESS_ARTIFACT_INVALID",)
    assert portable_verification["valid"] is False, full_verification.issues
    assert portable_verification["issues"] == ["READINESS_ARTIFACT_INVALID"]


def test_readiness_portable_rejects_resealed_unknown_persisted_input_field(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Semantic replay rejects unknown fields inside the persisted readiness model."""
    monkeypatch.syspath_prepend(str(ROOT / "tests" / "evaluation"))
    inputs = __import__("test_attorney_readiness_inputs")
    generation = __import__(
        "regulatory_harvest.evaluation.attorney_generation", fromlist=["*"]
    )
    artifacts = __import__(
        "regulatory_harvest.evaluation.attorney_readiness_artifacts",
        fromlist=["*"],
    )
    source = inputs._make_verified_inputs(tmp_path, limitations=None)
    init = {
        "baseline_run_dir": source.baseline_run_dir,
        "qualification_run_dir": source.qualification_run_dir,
        "generation_run_dir": source.generation_run_dir,
        "validation_receipt_path": source.validation_receipt_path,
    }
    full_run = tmp_path / "unknown-input-full"
    portable_run = tmp_path / "unknown-input-portable"
    initialize_readiness_core(full_run, **init)
    portable = _load_protocol_22_portable()
    portable.initialize_readiness_v1(
        portable_run, **init, generation_substrate=generation
    )
    for run in (full_run, portable_run):
        input_path = run / "readiness-input.json"
        persisted = json.loads(input_path.read_bytes())
        persisted["readiness_input"]["unknown"] = True
        input_bytes = canonical_json_bytes(persisted)
        input_path.write_bytes(input_bytes)
        manifest_path = run / "readiness-manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        for record in manifest["artifacts"]:
            if record["artifact_path"] == "readiness-input.json":
                record["artifact_hash"] = hashlib.sha256(input_bytes).hexdigest()
        body = {
            key: value
            for key, value in manifest.items()
            if key not in {"manifest_fingerprint", "root_hash"}
        }
        manifest["manifest_fingerprint"] = hashlib.sha256(
            canonical_json_bytes(body)
        ).hexdigest()
        manifest["root_hash"] = hashlib.sha256(
            canonical_json_bytes(
                {key: value for key, value in manifest.items() if key != "root_hash"}
            )
        ).hexdigest()
        manifest_path.write_bytes(canonical_json_bytes(manifest))
    full_verification = artifacts.verify_readiness_run_v1(full_run)
    portable_verification = portable.verify_readiness_run_v1(portable_run)
    assert full_verification.valid is False
    assert full_verification.issues == ("READINESS_SEMANTIC_REPLAY_INVALID",)
    assert portable_verification["valid"] is False
    assert portable_verification["issues"] == ["READINESS_SEMANTIC_REPLAY_INVALID"]


@pytest.mark.parametrize(
    ("mutation", "expected_issue"),
    [
        ("pending-call-unknown", "READINESS_ARTIFACT_INVALID"),
        ("protocol-version", "READINESS_ARTIFACT_INVALID"),
        ("phase", "READINESS_ARTIFACT_INVALID"),
        ("terminal-completed-with-pending", "READINESS_ARTIFACT_INVALID"),
        ("terminal-inconclusive-with-pending", "READINESS_ARTIFACT_INVALID"),
        ("pending-state", "READINESS_ARTIFACT_INVALID"),
        ("pending-request-fingerprint-binding", "READINESS_SEMANTIC_REPLAY_INVALID"),
        ("baseline-derived-fingerprint", "READINESS_ARTIFACT_INVALID"),
        ("safety-derived-fingerprint", "READINESS_ARTIFACT_INVALID"),
        ("requirement-derived-fingerprint", "READINESS_ARTIFACT_INVALID"),
        ("gap-derived-fingerprint", "READINESS_ARTIFACT_INVALID"),
        ("result-derived-fingerprint", "READINESS_ARTIFACT_INVALID"),
        ("grade-target-binding", "READINESS_SEMANTIC_REPLAY_INVALID"),
        ("report-hash-binding", "READINESS_SEMANTIC_REPLAY_INVALID"),
        ("generation-root-binding", "READINESS_SEMANTIC_REPLAY_INVALID"),
        ("scoring-contract-binding", "READINESS_SEMANTIC_REPLAY_INVALID"),
        ("qualification-check-bool", "READINESS_STORAGE_UNSAFE"),
    ],
)
def test_readiness_portable_rejects_nested_manifest_and_input_model_mutations(
    mutation: str,
    expected_issue: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Nested call and qualification models remain exact under canonical resealing."""
    monkeypatch.syspath_prepend(str(ROOT / "tests" / "evaluation"))
    inputs = __import__("test_attorney_readiness_inputs")
    generation = __import__(
        "regulatory_harvest.evaluation.attorney_generation", fromlist=["*"]
    )
    artifacts = __import__(
        "regulatory_harvest.evaluation.attorney_readiness_artifacts",
        fromlist=["*"],
    )
    source = inputs._make_verified_inputs(tmp_path, limitations=None)
    init = {
        "baseline_run_dir": source.baseline_run_dir,
        "qualification_run_dir": source.qualification_run_dir,
        "generation_run_dir": source.generation_run_dir,
        "validation_receipt_path": source.validation_receipt_path,
    }
    portable = _load_protocol_22_portable()
    runs = (tmp_path / f"{mutation}-full", tmp_path / f"{mutation}-portable")
    initialize_readiness_core(runs[0], **init)
    portable.initialize_readiness_v1(runs[1], **init, generation_substrate=generation)
    for run in runs:
        manifest_path = run / "readiness-manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        if mutation == "pending-call-unknown":
            manifest["pending_call"]["unknown"] = True
        elif mutation == "protocol-version":
            manifest["protocol_version"] = "evil"
        elif mutation == "phase":
            manifest["phase"] = "evil"
        elif mutation == "terminal-completed-with-pending":
            manifest["phase"] = "completed"
            manifest["terminal_status"] = "COMPLETED"
        elif mutation == "terminal-inconclusive-with-pending":
            manifest["phase"] = "inconclusive"
            manifest["terminal_status"] = "INCONCLUSIVE"
        elif mutation == "pending-state":
            manifest["pending_call"]["state"] = "accepted"
        elif mutation == "pending-request-fingerprint-binding":
            manifest["pending_call"]["request_fingerprint"] = "1" * 64
        elif mutation.endswith("-derived-fingerprint"):
            derived_field = {
                "baseline-derived-fingerprint": (
                    "baseline_locked_strict_equivalent_fingerprint"
                ),
                "safety-derived-fingerprint": "safety_review_fingerprint",
                "requirement-derived-fingerprint": "requirement_matrix_fingerprint",
                "gap-derived-fingerprint": "gap_matrix_fingerprint",
                "result-derived-fingerprint": "result_fingerprint",
            }[mutation]
            manifest[derived_field] = 7
        elif mutation.endswith("-binding"):
            binding_field = {
                "grade-target-binding": "grade_target_fingerprint",
                "report-hash-binding": "report_hash",
                "generation-root-binding": "generation_capsule_root",
                "scoring-contract-binding": (
                    "strict_equivalent_scoring_contract_fingerprint"
                ),
            }[mutation]
            manifest[binding_field] = "1" * 64
        else:
            input_path = run / "readiness-input.json"
            persisted = json.loads(input_path.read_bytes())
            persisted["qualification_limits"]["admission_checks"][0]["satisfied"] = (
                "yes"
            )
            input_bytes = canonical_json_bytes(persisted)
            input_path.write_bytes(input_bytes)
            for record in manifest["artifacts"]:
                if record["artifact_path"] == "readiness-input.json":
                    record["artifact_hash"] = hashlib.sha256(input_bytes).hexdigest()
        body = {
            key: value
            for key, value in manifest.items()
            if key not in {"manifest_fingerprint", "root_hash"}
        }
        manifest["manifest_fingerprint"] = hashlib.sha256(
            canonical_json_bytes(body)
        ).hexdigest()
        manifest["root_hash"] = hashlib.sha256(
            canonical_json_bytes(
                {key: value for key, value in manifest.items() if key != "root_hash"}
            )
        ).hexdigest()
        manifest_path.write_bytes(canonical_json_bytes(manifest))
    full_verification = artifacts.verify_readiness_run_v1(runs[0])
    portable_verification = portable.verify_readiness_run_v1(runs[1])
    assert full_verification.valid is False
    assert full_verification.issues == (expected_issue,)
    assert portable_verification["valid"] is False, full_verification.issues
    assert portable_verification["issues"] == [expected_issue]


@pytest.mark.parametrize(
    "mutation",
    [
        "schema-version",
        "readiness-protocol-version",
        "binding-readiness",
        "limits-schema-version",
        "limits-admission-status",
        "limits-readiness",
        "receipt-readiness-status",
        "language-limitation-status",
        "client-facts-hash-type",
        "inner-rubric-fingerprint-binding",
        "baseline-manifest-unknown",
        "baseline-input-unknown",
        "baseline-unknown",
        "baseline-verification-unknown",
        "baseline-manifest-root-binding",
        "qualification-root-binding",
        "generation-source-hash-binding",
        "historical-disposition",
    ],
)
def test_readiness_portable_rejects_persisted_closed_value_and_type_mutations(
    mutation: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Persisted closed-v1 values and nullable hashes retain full verification parity."""
    monkeypatch.syspath_prepend(str(ROOT / "tests" / "evaluation"))
    inputs = __import__("test_attorney_readiness_inputs")
    generation = __import__(
        "regulatory_harvest.evaluation.attorney_generation", fromlist=["*"]
    )
    artifacts = __import__(
        "regulatory_harvest.evaluation.attorney_readiness_artifacts",
        fromlist=["*"],
    )
    source = inputs._make_verified_inputs(tmp_path, limitations=None)
    init = {
        "baseline_run_dir": source.baseline_run_dir,
        "qualification_run_dir": source.qualification_run_dir,
        "generation_run_dir": source.generation_run_dir,
        "validation_receipt_path": source.validation_receipt_path,
    }
    portable = _load_protocol_22_portable()
    runs = (tmp_path / f"{mutation}-full", tmp_path / f"{mutation}-portable")
    initialize_readiness_core(runs[0], **init)
    portable.initialize_readiness_v1(runs[1], **init, generation_substrate=generation)
    for run in runs:
        input_path = run / "readiness-input.json"
        persisted = json.loads(input_path.read_bytes())
        if mutation == "schema-version":
            persisted["schema_version"] = "evil"
        elif mutation == "readiness-protocol-version":
            persisted["readiness_input"]["protocol_version"] = "evil"
        elif mutation == "binding-readiness":
            persisted["qualification_binding"]["qualification_readiness"] = "evil"
        elif mutation == "limits-schema-version":
            persisted["qualification_limits"]["case_schema_version"] = "evil"
        elif mutation == "limits-admission-status":
            persisted["qualification_limits"]["admission_status"] = "evil"
        elif mutation == "limits-readiness":
            persisted["qualification_limits"]["qualification_readiness"] = "evil"
        elif mutation == "receipt-readiness-status":
            persisted["qualification_limits"]["receipt_readiness"]["status"] = "evil"
        elif mutation == "language-limitation-status":
            persisted["qualification_limits"]["language_treatments"][0][
                "limitation_status"
            ] = "evil"
        elif mutation == "inner-rubric-fingerprint-binding":
            persisted["readiness_input"]["readiness_rubric_fingerprint"] = "1" * 64
        elif mutation == "qualification-root-binding":
            persisted["qualification_binding"]["qualification_root"] = "1" * 64
            persisted["qualification_limits"]["qualification_root"] = "1" * 64
        elif mutation == "generation-source-hash-binding":
            persisted["generation_binding"]["source_hashes"][0][1] = "1" * 64
        elif mutation == "historical-disposition":
            baseline = persisted["readiness_input"]
            baseline["historical_v22_cross_check"] = {
                "report_hash": baseline["report_hash"],
                "strict_disposition": "EVIL",
                "result_fingerprint": "1" * 64,
                "manifest_fingerprint": "2" * 64,
                "baseline_fingerprint": "3" * 64,
                "grader_aggregate_fingerprints": ["4" * 64, "5" * 64],
                "reason_codes": [],
                "baseline_comparable": True,
                "report_comparable": True,
            }
        elif mutation.startswith("baseline-"):
            context_field = {
                "baseline-manifest-unknown": "manifest",
                "baseline-input-unknown": "baseline_input",
                "baseline-unknown": "baseline",
                "baseline-verification-unknown": "verification",
                "baseline-manifest-root-binding": "manifest",
            }[mutation]
            if mutation == "baseline-manifest-root-binding":
                persisted["baseline_context"][context_field]["root_hash"] = "1" * 64
            else:
                persisted["baseline_context"][context_field]["unknown_nested"] = True
        else:
            persisted["generation_binding"]["client_facts_hash"] = 7
        input_bytes = canonical_json_bytes(persisted)
        input_path.write_bytes(input_bytes)
        manifest_path = run / "readiness-manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        for record in manifest["artifacts"]:
            if record["artifact_path"] == "readiness-input.json":
                record["artifact_hash"] = hashlib.sha256(input_bytes).hexdigest()
        body = {
            key: value
            for key, value in manifest.items()
            if key not in {"manifest_fingerprint", "root_hash"}
        }
        manifest["manifest_fingerprint"] = hashlib.sha256(
            canonical_json_bytes(body)
        ).hexdigest()
        manifest["root_hash"] = hashlib.sha256(
            canonical_json_bytes(
                {key: value for key, value in manifest.items() if key != "root_hash"}
            )
        ).hexdigest()
        manifest_path.write_bytes(canonical_json_bytes(manifest))
    full_verification = artifacts.verify_readiness_run_v1(runs[0])
    portable_verification = portable.verify_readiness_run_v1(runs[1])
    assert full_verification.valid is False
    assert portable_verification["valid"] is False, full_verification.issues
    assert portable_verification["issues"] == list(full_verification.issues)
@pytest.mark.parametrize("mutation", ["reorder", "omit-first", "phase-created"])
def test_readiness_portable_rejects_authenticated_call_history_mutations(
    mutation: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Accepted call order, completeness, and phase remain semantically authenticated."""
    monkeypatch.syspath_prepend(str(ROOT / "tests" / "evaluation"))
    inputs = __import__("test_attorney_readiness_inputs")
    workflow = __import__("test_attorney_readiness_workflow")
    generation = __import__(
        "regulatory_harvest.evaluation.attorney_generation", fromlist=["*"]
    )
    artifacts = __import__(
        "regulatory_harvest.evaluation.attorney_readiness_artifacts",
        fromlist=["*"],
    )
    source = inputs._make_verified_inputs(tmp_path, limitations=None)
    init = {
        "baseline_run_dir": source.baseline_run_dir,
        "qualification_run_dir": source.qualification_run_dir,
        "generation_run_dir": source.generation_run_dir,
        "validation_receipt_path": source.validation_receipt_path,
    }
    portable = _load_protocol_22_portable()
    runs = (tmp_path / f"{mutation}-full", tmp_path / f"{mutation}-portable")
    initialize_readiness_core(runs[0], **init)
    portable.initialize_readiness_v1(runs[1], **init, generation_substrate=generation)
    provenance = ReadinessEvaluatorProvenanceV1(
        provider_name="portable-parity-provider",
        model_name="portable-parity-model",
        judge_isolation="scripted_fixture",
    )
    portable_provenance = {
        "provider_name": provenance.provider_name,
        "model_name": provenance.model_name,
        "judge_isolation": provenance.judge_isolation,
    }
    for _ in range(2):
        full_request = next_readiness_core(runs[0])
        portable_request = portable.next_readiness_request_v1(runs[1])
        assert full_request is not None
        assert portable_request == full_request.model_dump(mode="json")
        draft = workflow._draft(full_request, grade_mode="met")
        full_compiled = compile_readiness_draft_v1(full_request, draft, provenance)
        assert isinstance(full_compiled, CompiledReadinessDraftV1)
        portable_response = portable.compile_readiness_draft_v1(
            portable_request, copy.deepcopy(draft), portable_provenance
        )
        assert submit_readiness_core(runs[0], full_compiled.response).accepted
        assert portable.guarded_submit_readiness_response_v1(
            runs[1], portable_response
        )["accepted"]
    for run in runs:
        manifest_path = run / "readiness-manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        if mutation == "reorder":
            manifest["accepted_calls"][:2] = reversed(manifest["accepted_calls"][:2])
        elif mutation == "omit-first":
            del manifest["accepted_calls"][0]
        else:
            manifest["phase"] = "created"
        body = {
            key: value
            for key, value in manifest.items()
            if key not in {"manifest_fingerprint", "root_hash"}
        }
        manifest["manifest_fingerprint"] = hashlib.sha256(
            canonical_json_bytes(body)
        ).hexdigest()
        manifest["root_hash"] = hashlib.sha256(
            canonical_json_bytes(
                {key: value for key, value in manifest.items() if key != "root_hash"}
            )
        ).hexdigest()
        manifest_path.write_bytes(canonical_json_bytes(manifest))
    full_verification = artifacts.verify_readiness_run_v1(runs[0])
    portable_verification = portable.verify_readiness_run_v1(runs[1])
    assert full_verification.valid is False
    assert portable_verification["valid"] is False, full_verification.issues
    assert portable_verification["issues"] == list(full_verification.issues)
    for command in ("eval-readiness-next", "eval-readiness-status"):
        full_command = subprocess.run(
            [
                str(ROOT / ".venv" / "bin" / "python"),
                str(ROOT / "scripts" / "attorney_eval_full.py"),
                command,
                "--run",
                str(runs[0]),
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
        )
        portable_command = subprocess.run(
            [
                "python3",
                "-I",
                "-S",
                str(ROOT / "scripts" / "harvest_portable.py"),
                command,
                "--run",
                str(runs[1]),
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
        )
        assert (
            portable_command.returncode,
            portable_command.stdout,
            portable_command.stderr,
        ) == (
            full_command.returncode,
            full_command.stdout,
            full_command.stderr,
        )
        assert full_command.returncode == 5


@pytest.mark.parametrize(
    "artifact_name",
    ["readiness-verification.json", "unexpected.json", "unexpected-directory/"],
)
def test_readiness_portable_rejects_declared_unbound_artifacts(
    artifact_name: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A nonterminal run cannot inject a self-declared valid verification artifact."""
    monkeypatch.syspath_prepend(str(ROOT / "tests" / "evaluation"))
    inputs = __import__("test_attorney_readiness_inputs")
    generation = __import__(
        "regulatory_harvest.evaluation.attorney_generation", fromlist=["*"]
    )
    artifacts = __import__(
        "regulatory_harvest.evaluation.attorney_readiness_artifacts",
        fromlist=["*"],
    )
    source = inputs._make_verified_inputs(tmp_path, limitations=None)
    init = {
        "baseline_run_dir": source.baseline_run_dir,
        "qualification_run_dir": source.qualification_run_dir,
        "generation_run_dir": source.generation_run_dir,
        "validation_receipt_path": source.validation_receipt_path,
    }
    portable = _load_protocol_22_portable()
    runs = (tmp_path / "forged-full", tmp_path / "forged-portable")
    initialize_readiness_core(runs[0], **init)
    portable.initialize_readiness_v1(runs[1], **init, generation_substrate=generation)
    forged_bytes = (
        canonical_json_bytes(
            {
                "protocol_version": "delivery-readiness-v1",
                "valid": True,
                "checks": {},
                "issues": [],
                "graph_fingerprint": "0" * 64,
                "verification_fingerprint": "0" * 64,
            }
        )
        if artifact_name == "readiness-verification.json"
        else canonical_json_bytes({"unexpected": True})
    )
    for run in runs:
        if artifact_name.endswith("/"):
            (run / artifact_name).mkdir()
            continue
        (run / artifact_name).write_bytes(forged_bytes)
        manifest_path = run / "readiness-manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        manifest["artifacts"].append(
            {
                "artifact_path": artifact_name,
                "artifact_hash": hashlib.sha256(forged_bytes).hexdigest(),
            }
        )
        manifest["artifacts"].sort(key=lambda item: item["artifact_path"])
        body = {
            key: value
            for key, value in manifest.items()
            if key not in {"manifest_fingerprint", "root_hash"}
        }
        manifest["manifest_fingerprint"] = hashlib.sha256(
            canonical_json_bytes(body)
        ).hexdigest()
        manifest["root_hash"] = hashlib.sha256(
            canonical_json_bytes(
                {key: value for key, value in manifest.items() if key != "root_hash"}
            )
        ).hexdigest()
        manifest_path.write_bytes(canonical_json_bytes(manifest))
    full_verification = artifacts.verify_readiness_run_v1(runs[0])
    portable_verification = portable.verify_readiness_run_v1(runs[1])
    assert full_verification.valid is False
    assert full_verification.issues == ("READINESS_INVENTORY_INVALID",)
    assert portable_verification["valid"] is False
    assert portable_verification["issues"] == list(full_verification.issues)
    for command in ("eval-readiness-next", "eval-readiness-status"):
        full_command = subprocess.run(
            [
                str(ROOT / ".venv" / "bin" / "python"),
                str(ROOT / "scripts" / "attorney_eval_full.py"),
                command,
                "--run",
                str(runs[0]),
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
        )
        portable_command = subprocess.run(
            [
                "python3",
                "-I",
                "-S",
                str(ROOT / "scripts" / "harvest_portable.py"),
                command,
                "--run",
                str(runs[1]),
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
        )
        assert (
            portable_command.returncode,
            portable_command.stdout,
            portable_command.stderr,
        ) == (
            full_command.returncode,
            full_command.stdout,
            full_command.stderr,
        )
        assert full_command.returncode == 5


def test_readiness_portable_bounds_oversized_manifest_without_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both verifiers reject an oversized manifest before parsing or rewriting it."""
    monkeypatch.syspath_prepend(str(ROOT / "tests" / "evaluation"))
    inputs = __import__("test_attorney_readiness_inputs")
    generation = __import__(
        "regulatory_harvest.evaluation.attorney_generation", fromlist=["*"]
    )
    artifacts = __import__(
        "regulatory_harvest.evaluation.attorney_readiness_artifacts",
        fromlist=["*"],
    )
    source = inputs._make_verified_inputs(tmp_path, limitations=None)
    init = {
        "baseline_run_dir": source.baseline_run_dir,
        "qualification_run_dir": source.qualification_run_dir,
        "generation_run_dir": source.generation_run_dir,
        "validation_receipt_path": source.validation_receipt_path,
    }
    portable = _load_protocol_22_portable()
    runs = (tmp_path / "oversized-full", tmp_path / "oversized-portable")
    initialize_readiness_core(runs[0], **init)
    portable.initialize_readiness_v1(runs[1], **init, generation_substrate=generation)
    oversized = b" " * (16 * 1024 * 1024 + 1)
    for run in runs:
        (run / "readiness-manifest.json").write_bytes(oversized)
    full_verification = artifacts.verify_readiness_run_v1(runs[0])
    portable_verification = portable.verify_readiness_run_v1(runs[1])
    assert full_verification.valid is False
    assert portable_verification["valid"] is False
    assert portable_verification["issues"] == list(full_verification.issues)
    assert (runs[0] / "readiness-manifest.json").read_bytes() == oversized
    assert (runs[1] / "readiness-manifest.json").read_bytes() == oversized


def test_readiness_portable_bounds_deep_manifest_with_cli_parity(
    tmp_path: Path,
) -> None:
    """Deep attacker JSON returns one bounded verification result and CLI error."""
    artifacts = __import__(
        "regulatory_harvest.evaluation.attorney_readiness_artifacts",
        fromlist=["*"],
    )
    portable = _load_protocol_22_portable()
    runs = (tmp_path / "deep-full", tmp_path / "deep-portable")
    deep = b"[" * 1100 + b"0" + b"]" * 1100
    for run in runs:
        run.mkdir()
        (run / "readiness-manifest.json").write_bytes(deep)
    full_verification = artifacts.verify_readiness_run_v1(runs[0])
    portable_verification = portable.verify_readiness_run_v1(runs[1])
    assert full_verification.valid is False
    assert full_verification.issues == ("READINESS_ARTIFACT_INVALID",)
    assert portable_verification["valid"] is False
    assert portable_verification["issues"] == list(full_verification.issues)
    full_command = subprocess.run(
        [
            str(ROOT / ".venv" / "bin" / "python"),
            str(ROOT / "scripts" / "attorney_eval_full.py"),
            "eval-readiness-verify",
            "--run",
            str(runs[0]),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
    )
    portable_command = subprocess.run(
        [
            "python3",
            "-I",
            "-S",
            str(ROOT / "scripts" / "harvest_portable.py"),
            "eval-readiness-verify",
            "--run",
            str(runs[1]),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
    )
    assert (
        portable_command.returncode,
        portable_command.stdout,
        portable_command.stderr,
    ) == (
        full_command.returncode,
        full_command.stdout,
        full_command.stderr,
    )
    assert full_command.returncode == 5


@pytest.mark.parametrize(
    "target", ["readiness-manifest.json", "readiness-input.json"]
)
def test_readiness_portable_rejects_snapshot_replacement_race(
    target: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A leaf replaced after the initial identity scan cannot verify from stale bytes."""
    monkeypatch.syspath_prepend(str(ROOT / "tests" / "evaluation"))
    inputs = __import__("test_attorney_readiness_inputs")
    generation = __import__(
        "regulatory_harvest.evaluation.attorney_generation", fromlist=["*"]
    )
    source = inputs._make_verified_inputs(tmp_path, limitations=None)
    run = tmp_path / f"snapshot-race-{Path(target).stem}"
    portable = _load_protocol_22_portable()
    portable.initialize_readiness_v1(
        run,
        baseline_run_dir=source.baseline_run_dir,
        qualification_run_dir=source.qualification_run_dir,
        generation_run_dir=source.generation_run_dir,
        validation_receipt_path=source.validation_receipt_path,
        generation_substrate=generation,
    )
    original_scan = portable._PosixRunStorage.scan_inventory
    replaced = False

    def replace_after_scan(storage: object) -> object:
        nonlocal replaced
        inventory = original_scan(storage)
        if not replaced:
            (run / target).write_bytes(b"{}")
            replaced = True
        return inventory

    monkeypatch.setattr(
        portable._PosixRunStorage, "scan_inventory", replace_after_scan
    )
    verification = portable.verify_readiness_run_v1(run)
    assert replaced
    assert verification["valid"] is False
    assert verification["graph_fingerprint"] is None
    assert verification["verification_fingerprint"] is None


def test_readiness_contested_request_and_compiler_full_portable_parity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Contested alternatives retain the exact full request and response contract."""
    monkeypatch.syspath_prepend(str(ROOT / "tests" / "evaluation"))
    request_tests = __import__("test_attorney_readiness_requests")
    draft_tests = __import__("test_attorney_readiness_drafts")
    request_builders = __import__(
        "regulatory_harvest.evaluation.attorney_readiness_requests",
        fromlist=["*"],
    )
    inputs = request_tests.inputs.__wrapped__(tmp_path)
    full_request = request_builders.build_baseline_locked_contested_grade_request_v1(
        inputs,
        lane=1,
        contested_requirement_id="CONT-0001",
    )
    portable = _load_protocol_22_portable()
    _, rubric, _ = portable._readiness_rubric_v1()
    readiness_input = inputs.readiness_input.model_dump(mode="json")
    contest = inputs.gradeable_baseline.contested_requirements[0].model_dump(mode="json")
    portable_request = portable._readiness_contested_request(
        readiness_input,
        rubric,
        lane=1,
        contest=contest,
    )
    assert portable_request == full_request.model_dump(mode="json")

    draft = draft_tests._contested_draft(full_request)
    provenance = ReadinessEvaluatorProvenanceV1(
        provider_name="portable-parity-provider",
        model_name="portable-parity-model",
        judge_isolation="scripted_fixture",
    )
    full_response = compile_readiness_draft_v1(full_request, draft, provenance)
    assert isinstance(full_response, CompiledReadinessDraftV1)
    portable_response = portable.compile_readiness_draft_v1(
        portable_request,
        copy.deepcopy(draft),
        {
            "provider_name": provenance.provider_name,
            "model_name": provenance.model_name,
            "judge_isolation": provenance.judge_isolation,
        },
    )
    assert portable_response == full_response.response.model_dump(mode="json")


@pytest.mark.parametrize(
    (
        "grade_mode",
        "blocking_safety",
        "disputes",
        "referee_disposition",
        "limitations",
        "expected_delivery",
    ),
    [
        ("met", False, False, None, None, "HIGH_ASSURANCE"),
        ("met", True, False, None, None, "NOT_DELIVERABLE"),
        ("review", False, False, None, None, "NOT_DELIVERABLE"),
        ("review", False, True, None, None, "NOT_DELIVERABLE"),
        ("review", False, True, "unresolved", None, "NOT_DELIVERABLE"),
        ("met", False, False, None, "Machine translated.", "REVIEW_READY_WITH_GAPS"),
    ],
)
def test_readiness_complete_terminal_tree_full_portable_parity(
    grade_mode: str,
    blocking_safety: bool,
    disputes: bool,
    referee_disposition: str | None,
    limitations: str | None,
    expected_delivery: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every accepted transition produces the same high or blocked complete tree."""
    monkeypatch.syspath_prepend(str(ROOT / "tests" / "evaluation"))
    inputs = __import__("test_attorney_readiness_inputs")
    workflow = __import__("test_attorney_readiness_workflow")
    generation = __import__(
        "regulatory_harvest.evaluation.attorney_generation", fromlist=["*"]
    )
    source = inputs._make_verified_inputs(tmp_path, limitations=limitations)
    full_run = tmp_path / "readiness-full"
    portable_run = tmp_path / "readiness-portable"
    init = {
        "baseline_run_dir": source.baseline_run_dir,
        "qualification_run_dir": source.qualification_run_dir,
        "generation_run_dir": source.generation_run_dir,
        "validation_receipt_path": source.validation_receipt_path,
    }
    initialize_readiness_core(full_run, **init)
    portable = _load_protocol_22_portable()
    portable.initialize_readiness_v1(
        portable_run, **init, generation_substrate=generation
    )
    provenance = ReadinessEvaluatorProvenanceV1(
        provider_name="portable-parity-provider",
        model_name="portable-parity-model",
        judge_isolation="scripted_fixture",
    )

    while True:
        full_request = next_readiness_core(full_run)
        portable_request = portable.next_readiness_request_v1(portable_run)
        assert portable_request == (
            None if full_request is None else full_request.model_dump(mode="json")
        )
        if full_request is None:
            break
        draft = workflow._draft(
            full_request,
            grade_mode=grade_mode,
            blocking_safety=blocking_safety,
            disputes=disputes,
        )
        if referee_disposition is not None and full_request.operation.value == "safety_referee":
            draft["disposition"] = referee_disposition
        full_compiled = compile_readiness_draft_v1(full_request, draft, provenance)
        assert isinstance(full_compiled, CompiledReadinessDraftV1)
        portable_response = portable.compile_readiness_draft_v1(
            portable_request,
            copy.deepcopy(draft),
            {
                "provider_name": provenance.provider_name,
                "model_name": provenance.model_name,
                "judge_isolation": provenance.judge_isolation,
            },
        )
        assert portable_response == full_compiled.response.model_dump(mode="json")
        full_result = submit_readiness_core(full_run, full_compiled.response)
        portable_result = portable.guarded_submit_readiness_response_v1(
            portable_run, portable_response
        )
        assert portable_result["accepted"] is full_result.accepted
        assert _tree_bytes(portable_run) == _tree_bytes(full_run)

    assert "delivery-readiness.json" in _tree_bytes(full_run)
    assert portable.readiness_status_payload_v1(portable_run) == {
        "baseline_locked_strict_equivalent_disposition": (
            "FAIL" if grade_mode == "review" else "PASS"
        ),
        "delivery_readiness": expected_delivery,
        "engine_paused": False,
        "manifest_fingerprint": json.loads(
            (full_run / "readiness-manifest.json").read_text()
        )["manifest_fingerprint"],
        "pending_operation": None,
        "protocol_version": "delivery-readiness-v1",
    }
    expected_exit = 4 if expected_delivery == "NOT_DELIVERABLE" else 0
    for command in (
        "eval-readiness-next",
        "eval-readiness-status",
        "eval-readiness-verify",
    ):
        full_command = subprocess.run(
            [
                str(ROOT / ".venv" / "bin" / "python"),
                str(ROOT / "scripts" / "attorney_eval_full.py"),
                command,
                "--run",
                str(full_run),
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
        )
        portable_command = subprocess.run(
            [
                "python3",
                "-I",
                "-S",
                str(ROOT / "scripts" / "harvest_portable.py"),
                command,
                "--run",
                str(portable_run),
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
        )
        assert (
            portable_command.returncode,
            portable_command.stdout,
            portable_command.stderr,
        ) == (
            full_command.returncode,
            full_command.stdout,
            full_command.stderr,
        ) == (expected_exit, full_command.stdout, b"")


def test_readiness_historical_v22_noncomparable_complete_tree_parity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verified history remains separately labeled and cannot alter the fresh tier."""
    monkeypatch.syspath_prepend(str(ROOT / "tests" / "evaluation"))
    inputs = __import__("test_attorney_readiness_inputs")
    workflow = __import__("test_attorney_readiness_workflow")
    generation = __import__(
        "regulatory_harvest.evaluation.attorney_generation", fromlist=["*"]
    )
    portable = _load_protocol_22_portable()
    history = tmp_path / "historical-v22"
    portable.initialize_evaluation_v22(_case_payload(), history, seed_hex="5" * 64)
    for _ in range(32):
        historical_request = portable.next_evaluator_request_v22(history)
        if historical_request is None:
            break
        portable.submit_evaluator_response_v22(
            history,
            _protocol_22_storage_response(
                portable, historical_request, disputed=False
            ),
        )
    else:
        pytest.fail("historical Protocol 2.2 run did not terminate")

    source = inputs._make_verified_inputs(tmp_path / "current", limitations=None)
    full_run = tmp_path / "readiness-history-full"
    portable_run = tmp_path / "readiness-history-portable"
    init = {
        "baseline_run_dir": source.baseline_run_dir,
        "qualification_run_dir": source.qualification_run_dir,
        "generation_run_dir": source.generation_run_dir,
        "validation_receipt_path": source.validation_receipt_path,
        "historical_v22_run_dir": history,
        "historical_anonymous_label": "A",
    }
    initialize_readiness_core(full_run, **init)
    portable.initialize_readiness_v1(
        portable_run, **init, generation_substrate=generation
    )
    assert _tree_bytes(portable_run) == _tree_bytes(full_run)
    provenance = ReadinessEvaluatorProvenanceV1(
        provider_name="portable-parity-provider",
        model_name="portable-parity-model",
        judge_isolation="scripted_fixture",
    )
    while (full_request := next_readiness_core(full_run)) is not None:
        portable_request = portable.next_readiness_request_v1(portable_run)
        assert portable_request == full_request.model_dump(mode="json")
        draft = workflow._draft(full_request, grade_mode="met")
        full_response = compile_readiness_draft_v1(
            full_request, draft, provenance
        ).response
        portable_response = portable.compile_readiness_draft_v1(
            portable_request,
            copy.deepcopy(draft),
            {
                "provider_name": provenance.provider_name,
                "model_name": provenance.model_name,
                "judge_isolation": provenance.judge_isolation,
            },
        )
        assert portable_response == full_response.model_dump(mode="json")
        assert submit_readiness_core(full_run, full_response).accepted
        assert portable.guarded_submit_readiness_response_v1(
            portable_run, portable_response
        )["accepted"]
        assert _tree_bytes(portable_run) == _tree_bytes(full_run)
    result = json.loads((portable_run / "delivery-readiness.json").read_bytes())
    assert result["delivery_readiness"] == "HIGH_ASSURANCE"
    assert result["historical_v22_cross_check_status"] == "BASELINE_NOT_COMPARABLE"


@pytest.mark.parametrize(
    ("historical_grade", "expected_status"),
    [
        ("met", "BASELINE_NOT_COMPARABLE"),
        ("not_met", "BASELINE_NOT_COMPARABLE"),
    ],
)
def test_readiness_historical_v22_seed_orientation_tree_parity(
    historical_grade: str,
    expected_status: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both historical grade orientations stay noncomparable and tier-neutral."""
    monkeypatch.syspath_prepend(str(ROOT / "tests" / "evaluation"))
    inputs = __import__("test_attorney_readiness_inputs")
    workflow = __import__("test_attorney_readiness_workflow")
    generation = __import__(
        "regulatory_harvest.evaluation.attorney_generation", fromlist=["*"]
    )
    source = inputs._make_verified_inputs(tmp_path / "current", limitations=None)
    portable = _load_protocol_22_portable()
    baseline_input = source.baseline_context.baseline_input.model_dump(mode="json")
    stable = source.baseline_context.baseline.model_dump(mode="json")
    case = {
        "schema_version": "1.1",
        "case_id": "public-synthetic-history",
        "mode": "closed-universe",
        "question": baseline_input["question"],
        "jurisdiction": baseline_input["jurisdiction"],
        "as_of": baseline_input["as_of"],
        "requested_authorities": copy.deepcopy(baseline_input["requested_authorities"]),
        "sources": copy.deepcopy(baseline_input["sources"]),
        "candidates": [
            {
                "candidate_id": "historical-report",
                "role": "candidate",
                "report_text": source.report_text,
                "report_hash": hashlib.sha256(source.report_text.encode()).hexdigest(),
                "validation_receipt": {"kind": "external"},
            }
        ],
        "client_facts": baseline_input["client_facts"],
    }
    history = tmp_path / f"historical-{historical_grade}"
    portable.initialize_evaluation_v22(case, history, seed_hex="6" * 64)
    provenance = {
        "provider_name": "portable-parity-provider",
        "model_name": "portable-parity-model",
        "judge_isolation": "scripted_fixture",
    }
    for _ in range(32):
        request = portable.next_evaluator_request_v22(history)
        if request is None:
            break
        payload = request["payload"]
        if request["operation"] == "source_review_fragment":
            draft = {
                "proposals": [
                    {
                        "statement": requirement["statement"],
                        "kind": requirement["kind"],
                        "importance": requirement["importance"],
                        "passages": [
                            {
                                "source_id": passage["source_id"],
                                "quote": passage["quote"],
                            }
                            for passage in requirement["passages"]
                        ],
                        "dependency": requirement["dependency"],
                        "confidence": requirement["confidence"],
                        "rationale": requirement["substantive_rationale"],
                    }
                    for requirement in stable["requirements"]
                ],
                "review_complete": True,
            }
        elif request["operation"] == "source_audit_fragment":
            draft = {"concerns": [], "audit_complete": True}
        else:
            assert request["operation"] == "ordinary_grade_fragment"
            draft = {
                "requirement_grades": [
                    {
                        "requirement_ordinal": ordinal,
                        "disposition": historical_grade,
                        "report_passages": [payload["report_text"]]
                        if historical_grade == "met"
                        else [],
                        "rationale": "The historical report was independently graded.",
                        "omission": None
                        if historical_grade == "met"
                        else "The historical report does not state the requirement.",
                    }
                    for ordinal, _ in enumerate(payload["requirements"], 1)
                ],
                "rationale": "The historical batch is complete.",
            }
        response, reasons = portable._v22_compile_draft(request, draft, provenance)
        assert response is not None, reasons
        portable.submit_evaluator_response_v22(history, response)
    else:
        pytest.fail("comparable historical Protocol 2.2 run did not terminate")

    full_run = tmp_path / f"readiness-{historical_grade}-full"
    portable_run = tmp_path / f"readiness-{historical_grade}-portable"
    init = {
        "baseline_run_dir": source.baseline_run_dir,
        "qualification_run_dir": source.qualification_run_dir,
        "generation_run_dir": source.generation_run_dir,
        "validation_receipt_path": source.validation_receipt_path,
        "historical_v22_run_dir": history,
        "historical_anonymous_label": "A",
    }
    initialize_readiness_core(full_run, **init)
    portable.initialize_readiness_v1(
        portable_run, **init, generation_substrate=generation
    )
    while (full_request := next_readiness_core(full_run)) is not None:
        portable_request = portable.next_readiness_request_v1(portable_run)
        assert portable_request == full_request.model_dump(mode="json")
        draft = workflow._draft(full_request, grade_mode="met")
        full_response = compile_readiness_draft_v1(
            full_request,
            draft,
            ReadinessEvaluatorProvenanceV1(**provenance),
        ).response
        portable_response = portable.compile_readiness_draft_v1(
            portable_request, copy.deepcopy(draft), provenance
        )
        assert submit_readiness_core(full_run, full_response).accepted
        assert portable.guarded_submit_readiness_response_v1(
            portable_run, portable_response
        )["accepted"]
        assert _tree_bytes(portable_run) == _tree_bytes(full_run)
    result = json.loads((portable_run / "delivery-readiness.json").read_bytes())
    assert result["delivery_readiness"] == "HIGH_ASSURANCE"
    assert result["historical_v22_cross_check_status"] == expected_status


def test_readiness_multi_batch_request_inventory_parity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Six-plus requirements preserve exact lane and batch request order."""
    monkeypatch.syspath_prepend(str(ROOT / "tests" / "evaluation"))
    workflow = __import__("test_attorney_readiness_workflow")
    readiness_workflow = __import__(
        "regulatory_harvest.evaluation.attorney_readiness_workflow",
        fromlist=["*"],
    )
    full_run, verified = workflow._initialize_verified_multi(monkeypatch, tmp_path)
    portable = _load_protocol_22_portable()
    persisted = json.loads((full_run / "readiness-input.json").read_bytes())
    rubric = verified.readiness_rubric.model_dump(mode="json")
    portable_requests = portable._readiness_grade_requests(
        persisted["readiness_input"], rubric
    )
    full_requests = [
        request.model_dump(mode="json")
        for request in readiness_workflow._grade_requests(verified)
    ]
    assert portable_requests == full_requests
    assert [request["payload"]["batch_ref"] for request in portable_requests[:2]] == [
        "GB-1-0001",
        "GB-1-0002",
    ]


def test_readiness_isolated_cli_init_next_submit_complete_parity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The isolated command family matches full stdout, stderr, exits, and every byte."""
    monkeypatch.syspath_prepend(str(ROOT / "tests" / "evaluation"))
    inputs = __import__("test_attorney_readiness_inputs")
    workflow = __import__("test_attorney_readiness_workflow")
    source = inputs._make_verified_inputs(tmp_path, limitations=None)
    full_run = tmp_path / "readiness-full-cli"
    portable_run = tmp_path / "readiness-portable-cli"

    def command(
        script: Path, name: str, *arguments: str, isolated: bool = False
    ) -> subprocess.CompletedProcess[bytes]:
        prefix = ["python3", "-I", "-S"] if isolated else [
            str(ROOT / ".venv" / "bin" / "python")
        ]
        return subprocess.run(
            [*prefix, str(script), name, *arguments],
            cwd=ROOT,
            check=False,
            capture_output=True,
        )

    common = (
        "--baseline-run",
        str(source.baseline_run_dir),
        "--qualification-run",
        str(source.qualification_run_dir),
        "--generation-run",
        str(source.generation_run_dir),
        "--validation-receipt",
        str(source.validation_receipt_path),
    )
    full_init = command(
        ROOT / "scripts" / "attorney_eval_full.py",
        "eval-readiness-init",
        *common,
        "--run",
        str(full_run),
    )
    portable_init = command(
        ROOT / "scripts" / "harvest_portable.py",
        "eval-readiness-init",
        *common,
        "--run",
        str(portable_run),
        isolated=True,
    )
    assert (
        portable_init.returncode,
        portable_init.stdout,
        portable_init.stderr,
    ) == (full_init.returncode, full_init.stdout, full_init.stderr) == (
        0,
        full_init.stdout,
        b"",
    )
    assert _tree_bytes(portable_run) == _tree_bytes(full_run)

    invalid = tmp_path / "invalid-readiness-draft.json"
    invalid.write_bytes(b"{}")
    before_full = _tree_bytes(full_run)
    before_portable = _tree_bytes(portable_run)
    invalid_metadata = (
        "--provider-name",
        "portable-parity-provider",
        "--model-name",
        "portable-parity-model",
        "--judge-isolation",
        "scripted_fixture",
    )
    full_invalid = command(
        ROOT / "scripts" / "attorney_eval_full.py",
        "eval-readiness-submit-safe",
        "--run",
        str(full_run),
        "--response",
        str(invalid),
        *invalid_metadata,
    )
    portable_invalid = command(
        ROOT / "scripts" / "harvest_portable.py",
        "eval-readiness-submit-safe",
        "--run",
        str(portable_run),
        "--response",
        str(invalid),
        *invalid_metadata,
        isolated=True,
    )
    assert (
        portable_invalid.returncode,
        portable_invalid.stdout,
        portable_invalid.stderr,
    ) == (
        full_invalid.returncode,
        full_invalid.stdout,
        full_invalid.stderr,
    ) == (2, full_invalid.stdout, b"")
    assert _tree_bytes(full_run) == before_full
    assert _tree_bytes(portable_run) == before_portable
    full_second_invalid = command(
        ROOT / "scripts" / "attorney_eval_full.py",
        "eval-readiness-submit-safe",
        "--run",
        str(full_run),
        "--response",
        str(invalid),
        *invalid_metadata,
    )
    portable_second_invalid = command(
        ROOT / "scripts" / "harvest_portable.py",
        "eval-readiness-submit-safe",
        "--run",
        str(portable_run),
        "--response",
        str(invalid),
        *invalid_metadata,
        isolated=True,
    )
    assert (
        portable_second_invalid.returncode,
        portable_second_invalid.stdout,
        portable_second_invalid.stderr,
    ) == (
        full_second_invalid.returncode,
        full_second_invalid.stdout,
        full_second_invalid.stderr,
    ) == (2, full_second_invalid.stdout, b"")
    for script, current_run, isolated in (
        (ROOT / "scripts" / "attorney_eval_full.py", full_run, False),
        (ROOT / "scripts" / "harvest_portable.py", portable_run, True),
    ):
        status = command(
            script,
            "eval-readiness-status",
            "--run",
            str(current_run),
            isolated=isolated,
        )
        assert status.returncode == 0
        assert json.loads(status.stdout)["engine_paused"] is False

    ordinal = 0
    while (request := next_readiness_core(full_run)) is not None:
        ordinal += 1
        draft = workflow._draft(request, grade_mode="met")
        full_draft = tmp_path / f"full-draft-{ordinal}.json"
        portable_draft = tmp_path / f"portable-draft-{ordinal}.json"
        draft_bytes = canonical_json_bytes(draft)
        full_draft.write_bytes(draft_bytes)
        portable_draft.write_bytes(draft_bytes)
        metadata = (
            "--provider-name",
            "portable-parity-provider",
            "--model-name",
            "portable-parity-model",
            "--judge-isolation",
            "scripted_fixture",
        )
        full_submit = command(
            ROOT / "scripts" / "attorney_eval_full.py",
            "eval-readiness-submit-safe",
            "--run",
            str(full_run),
            "--response",
            str(full_draft),
            *metadata,
        )
        portable_submit = command(
            ROOT / "scripts" / "harvest_portable.py",
            "eval-readiness-submit-safe",
            "--run",
            str(portable_run),
            "--response",
            str(portable_draft),
            *metadata,
            isolated=True,
        )
        assert (
            portable_submit.returncode,
            portable_submit.stdout,
            portable_submit.stderr,
        ) == (
            full_submit.returncode,
            full_submit.stdout,
            full_submit.stderr,
        ) == (0, full_submit.stdout, b"")
        assert _tree_bytes(portable_run) == _tree_bytes(full_run)

    for run in (full_run, portable_run):
        response_path = run / "responses" / "safety-lane-2.json"
        response = json.loads(response_path.read_bytes())
        response["provider_name"] = "tampered-provider"
        response_path.write_bytes(canonical_json_bytes(response))
    full_verify = command(
        ROOT / "scripts" / "attorney_eval_full.py",
        "eval-readiness-verify",
        "--run",
        str(full_run),
    )
    portable_verify = command(
        ROOT / "scripts" / "harvest_portable.py",
        "eval-readiness-verify",
        "--run",
        str(portable_run),
        isolated=True,
    )
    assert (
        portable_verify.returncode,
        portable_verify.stdout,
        portable_verify.stderr,
    ) == (
        full_verify.returncode,
        full_verify.stdout,
        full_verify.stderr,
    ) == (5, full_verify.stdout, b"")


def test_baseline_parity_policy_asset_is_exact_and_strict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The mirror loads the packaged policy and refuses byte or shape drift."""
    portable = _load_protocol_21_portable()
    policy_path = ROOT / "assets" / "evaluation-baseline-policy-v1.json"
    expected = policy_path.read_bytes()
    policy_bytes, policy, fingerprint = portable._baseline_policy()
    assert policy_bytes == expected
    assert fingerprint == hashlib.sha256(expected).hexdigest()
    assert policy == json.loads(expected)

    for name, mutated in (
        ("one-byte", expected[:-1] + bytes((expected[-1] ^ 1,))),
        (
            "unknown-key",
            canonical_json_bytes({**json.loads(expected), "unknown_policy_key": True}),
        ),
    ):
        changed = tmp_path / f"policy-{name}.json"
        changed.write_bytes(mutated)
        monkeypatch.setattr(portable, "_BASELINE_POLICY_PATH", changed)
        with pytest.raises(portable.BaselineInputError, match="BASELINE_IMPORTANCE_POLICY_INVALID"):
            portable._baseline_policy()


def test_baseline_parity_projection_adapter_remains_test_only() -> None:
    """Projection is exposed to differential tests, never as report-grading API."""
    portable = _load_protocol_21_portable()
    assert callable(portable._baseline_gradeable_projection_bytes_for_test)
    assert not hasattr(portable, "project_gradeable_baseline_v1")


@pytest.mark.parametrize(
    ("mutation", "reason"),
    (
        ("source-bytes", "SOURCE_BYTES_CHANGED"),
        ("source-id", "SOURCE_ID_CHANGED"),
        ("question", "QUESTION_CHANGED"),
        ("jurisdiction", "JURISDICTION_CHANGED"),
        ("as-of", "AS_OF_CHANGED"),
        ("authority", "AUTHORITY_SCOPE_CHANGED"),
        ("client-facts", "CLIENT_FACTS_CHANGED"),
        ("qualification", "QUALIFICATION_CHANGED"),
        ("compiler", "COMPILER_CHANGED"),
        ("rubric", "RUBRIC_CHANGED"),
        ("policy", "IMPORTANCE_POLICY_CHANGED"),
        ("fingerprint", "LEGAL_INPUT_FINGERPRINT_CHANGED"),
    ),
)
def test_baseline_parity_reuse_refuses_every_legal_identity_change(
    mutation: str, reason: str
) -> None:
    """Every named Task 2 refusal stays exact in the standard-library mirror."""
    portable = _load_protocol_21_portable()
    policy_bytes, policy, policy_fingerprint = portable._baseline_policy()
    contract = portable._baseline_contract(policy_fingerprint)
    source_text = "A covered operator must file notice."
    sealed: dict[str, Any] = {
        "schema_version": "baseline-input-v1",
        "sources": [
            {
                "source_id": "source-1",
                "title": "Synthetic Rule",
                "normalized_text": source_text,
                "content_hash": hashlib.sha256(source_text.encode()).hexdigest(),
                "jurisdiction": "Example State",
                "authority_type": "regulation",
                "source_role": "official_primary",
                "source_quality": "primary",
                "completeness": "complete",
                "language": "en",
            }
        ],
        "source_record_fingerprint": "a" * 64,
        "question": "What notice is required?",
        "jurisdiction": "Example State",
        "as_of": "2026-08-24",
        "requested_authorities": [
            {
                "authority_id": "rule-1",
                "title": "Synthetic Rule",
                "jurisdiction": "Example State",
                "authority_type": "regulation",
                "source_ids": ["source-1"],
            }
        ],
        "client_facts": None,
        "client_facts_binding": "explicit-null",
        "qualification_root": "b" * 64,
        "qualification_receipt_fingerprint": "c" * 64,
        "qualification_readiness": "ADMITTED",
        "compiler_contract": contract,
        "compiler_contract_fingerprint": hashlib.sha256(
            canonical_json_bytes(contract)
        ).hexdigest(),
        "evaluation_rubric_version": portable._BASELINE_RUBRIC["version"],
        "evaluation_rubric_bytes": portable._BASELINE_RUBRIC_BYTES.decode(),
        "evaluation_rubric_fingerprint": portable._BASELINE_RUBRIC_FINGERPRINT,
        "importance_policy_version": policy["importance_policy_version"],
        "importance_policy_bytes": policy_bytes.decode(),
        "importance_policy_fingerprint": policy_fingerprint,
        "legal_input_fingerprint": "0" * 64,
    }
    sealed["legal_input_fingerprint"] = hashlib.sha256(
        canonical_json_bytes(portable._baseline_legal_projection(sealed))
    ).hexdigest()
    proposed = copy.deepcopy(sealed)
    if mutation == "source-bytes":
        proposed["sources"][0]["normalized_text"] += " Changed."
        proposed["sources"][0]["content_hash"] = hashlib.sha256(
            proposed["sources"][0]["normalized_text"].encode()
        ).hexdigest()
        proposed["source_record_fingerprint"] = "1" * 64
    elif mutation == "source-id":
        proposed["sources"][0]["source_id"] = "source-2"
        proposed["requested_authorities"][0]["source_ids"] = ["source-2"]
        proposed["source_record_fingerprint"] = "2" * 64
    elif mutation == "question":
        proposed["question"] += " Changed?"
        proposed["source_record_fingerprint"] = "3" * 64
    elif mutation == "jurisdiction":
        proposed["jurisdiction"] = "Other State"
        proposed["source_record_fingerprint"] = "3" * 64
    elif mutation == "as-of":
        proposed["as_of"] = "2026-08-25"
        proposed["source_record_fingerprint"] = "3" * 64
    elif mutation == "authority":
        proposed["requested_authorities"][0]["title"] = "Other Rule"
        proposed["source_record_fingerprint"] = "3" * 64
    elif mutation == "client-facts":
        proposed["client_facts"] = "The operator is covered."
        proposed["client_facts_binding"] = "sha256:" + hashlib.sha256(
            proposed["client_facts"].encode()
        ).hexdigest()
    elif mutation == "qualification":
        proposed["qualification_root"] = "d" * 64
    elif mutation == "compiler":
        proposed["compiler_contract"] = {**contract, "contract_version": "changed"}
        proposed["compiler_contract_fingerprint"] = hashlib.sha256(
            canonical_json_bytes(proposed["compiler_contract"])
        ).hexdigest()
    elif mutation == "rubric":
        proposed["evaluation_rubric_bytes"] = '{"version":"attorney-eval-v2.2","changed":true}'
        proposed["evaluation_rubric_fingerprint"] = hashlib.sha256(
            proposed["evaluation_rubric_bytes"].encode()
        ).hexdigest()
    elif mutation == "policy":
        proposed["importance_policy_bytes"] = (
            '{"importance_policy_version":"importance-policy-v1","changed":true}'
        )
        proposed["importance_policy_fingerprint"] = hashlib.sha256(
            proposed["importance_policy_bytes"].encode()
        ).hexdigest()
    else:
        proposed["legal_input_fingerprint"] = "f" * 64

    if mutation != "fingerprint":
        proposed["legal_input_fingerprint"] = hashlib.sha256(
            canonical_json_bytes(portable._baseline_legal_projection(proposed))
        ).hexdigest()

    portable_decision = portable.baseline_reuse_decision_v1(sealed, proposed)

    def full_input(value: dict[str, Any]) -> BaselineInputV1:
        payload = copy.deepcopy(value)
        payload["evaluation_rubric_bytes"] = payload["evaluation_rubric_bytes"].encode()
        payload["importance_policy_bytes"] = payload["importance_policy_bytes"].encode()
        return BaselineInputV1.model_validate(payload)

    core = baseline_reuse_decision_core(full_input(sealed), full_input(proposed))
    assert portable_decision == {
        "reusable": core.reusable,
        "reason_codes": list(core.reason_codes),
    }
    assert portable_decision == {"reusable": False, "reason_codes": [reason]}


def _protocol_21_test_response(request: dict[str, Any]) -> dict[str, Any]:
    """Build one valid scripted response for the source/no-dispute grade path."""
    payload = request["payload"]
    operation = request["operation"]
    if operation == "source_review":
        source = payload["source_record"]["sources"][0]
        response_payload: dict[str, Any] = {
            "schema_version": "2.1",
            "proposals": [
                {
                    "statement": "A covered operator must file notice.",
                    "kind": "obligation",
                    "importance": "critical",
                    "passages": [
                        {"source_id": source["source_id"], "quote": source["normalized_text"]}
                    ],
                    "dependency": None,
                    "confidence": "clear",
                    "rationale": "The supplied source states the filing duty.",
                }
            ],
        }
    elif operation == "source_audit":
        response_payload = {"schema_version": "2.1", "concerns": []}
    else:
        assert operation == "ordinary_grade_fragment"
        response_payload = {
            "schema_version": "2.1",
            "anonymous_label": payload["anonymous_label"],
            "grader_lane": payload["grader_lane"],
            "batch_ref": payload["batch_ref"],
            "baseline_fingerprint": payload["baseline_fingerprint"],
            "report_fingerprint": payload["report_fingerprint"],
            "requirement_grades": [
                {
                    "requirement_id": requirement["requirement_id"],
                    "disposition": "met",
                    "report_passages": [payload["report_text"]],
                    "rationale": "The report was assessed against this requirement.",
                    "omission": None,
                }
                for requirement in payload["requirements"]
            ],
            "rationale": "The bounded grade batch is complete.",
        }
    return {
        "schema_version": "2.1",
        "operation": operation,
        "request_fingerprint": request["request_fingerprint"],
        "provider_name": "local-scripted-fixture",
        "model_name": "no-provider",
        "judge_isolation": "scripted_fixture",
        "payload": response_payload,
    }


def _case_payload() -> dict[str, Any]:
    case = _case_from_fixture(FIXTURE / "case.json", root=FIXTURE)
    return case.model_dump(mode="json")


def _scripted_payloads() -> list[dict[str, Any]]:
    value = json.loads(
        (FIXTURE / "responses" / "scripted-responses.json").read_text(encoding="utf-8")
    )
    return cast(list[dict[str, Any]], value["responses"])


def _response(request: dict[str, Any], scripted: dict[str, Any], index: int) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "operation": request["operation"],
        "request_fingerprint": request["request_fingerprint"],
        "provider_name": "local-scripted-fixture",
        "model_name": "no-provider",
        "judge_isolation": "scripted_fixture",
        "payload": scripted["payload"],
        "response_id": f"fixture-response-{index}",
        "usage": {},
    }


def _core_case_from_payload(payload: dict[str, Any]) -> Any:
    case_type = type(_case_from_fixture(FIXTURE / "case.json", root=FIXTURE))
    return case_type.model_validate(payload)


def _case_payload_with_report(report_text: str) -> dict[str, Any]:
    """Return the public fixture with one exact replacement report."""
    payload = _case_payload()
    candidate = payload["candidates"][0]
    candidate["report_text"] = report_text
    candidate["report_hash"] = hashlib.sha256(report_text.encode("utf-8")).hexdigest()
    return payload


def _narrative_dispute(
    sealed: dict[str, Any],
    *,
    dimension: str,
    first_passage: str,
    second_passage: str | None = None,
) -> dict[str, Any]:
    """Build one valid synthetic narrative dispute from literal grader passages."""
    first = {
        "request_fingerprint": "1" * 64,
        "entry_grade": None,
        "out_of_ledger_claim": None,
        "narrative_score": {
            "dimension": dimension,
            "score": 4,
            "rationale": "The first grader found this narrative treatment complete.",
            "report_passage": first_passage,
            "finding_codes": [],
        },
        "absent_claim": False,
    }
    second = copy.deepcopy(first)
    second["request_fingerprint"] = "2" * 64
    second["narrative_score"]["score"] = 2
    second["narrative_score"]["rationale"] = (
        "The second grader found this narrative treatment incomplete."
    )
    second["narrative_score"]["report_passage"] = second_passage or first_passage
    return {
        "dispute_id": f"grade-narrative-{dimension.replace('_', '-')}",
        "anonymous_label": "A",
        "ledger_fingerprint": sealed["ledger_fingerprint"],
        "kind": "narrative_score",
        "subject_id": dimension,
        "materiality": None,
        "grader_1": first,
        "grader_2": second,
        "rationale": "The blind graders assign different narrative scores.",
    }


def _referee_requests_for_report(
    report_text: str,
    *,
    dimension: str,
    first_passage: str,
    second_passage: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build byte-comparable portable and full referee requests."""
    portable = _load_portable()
    case_payload = _case_payload_with_report(report_text)
    portable_envelope = portable.freeze_case(case_payload, seed_hex="0" * 64)
    scripted = _scripted_payloads()
    portable_sealed = portable.seal_ledger(
        portable_envelope,
        scripted[1]["payload"],
        scripted[2]["payload"],
        None,
    )
    dispute_payload = _narrative_dispute(
        portable_sealed,
        dimension=dimension,
        first_passage=first_passage,
        second_passage=second_passage,
    )
    legal_hash = hashlib.sha256(portable.canonical_json_bytes(portable_sealed)).hexdigest()
    portable_request = portable._report_referee_request(
        portable_envelope,
        portable_sealed,
        dispute_payload,
        legal_hash,
    )

    core_envelope = freeze_core(_core_case_from_payload(case_payload), seed_hex="0" * 64)
    core_request = core_workflow._report_referee_request(
        core_envelope,
        SealedLedger.model_validate(portable_sealed),
        GradeDispute.model_validate(dispute_payload),
        legal_ledger_hash=legal_hash,
    ).model_dump(mode="json")
    assert portable.canonical_json_bytes(portable_request) == canonical_json_bytes(core_request)
    return portable_request, core_request


def _run_portable(module: ModuleType, run: Path) -> None:
    module.initialize_evaluation(_case_payload(), run, seed_hex="0" * 64)
    scripted = _scripted_payloads()
    for index, item in enumerate(scripted, start=1):
        request = module.next_judge_request(run)
        assert request is not None
        assert request["operation"] == item["operation"]
        assert request["request_fingerprint"] == item["expect"]["request_fingerprint"]
        module.submit_judge_response(run, _response(request, item, index))
    assert module.next_judge_request(run) is None


def _tree_bytes(run: Path) -> dict[str, bytes]:
    return {
        path.relative_to(run).as_posix(): path.read_bytes()
        for path in sorted(run.rglob("*"))
        if path.is_file()
    }


def _extract_retained_run_fixture(archive_bytes: bytes, destination: Path) -> None:
    """Extract one hash-pinned run fixture after rejecting unsafe members."""
    root = destination.resolve()
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as archive:
        members = archive.getmembers()
        for member in members:
            target = (root / member.name).resolve()
            if (
                not target.is_relative_to(root)
                or member.issym()
                or member.islnk()
                or not (member.isdir() or member.isfile())
            ):
                raise ValueError("unsafe retained run fixture member")
        try:
            archive.extractall(destination, filter="data")
        except TypeError:
            archive.extractall(destination)


def _qualification_payload() -> dict[str, Any]:
    case = _case_payload()
    return {
        "schema_version": "1.0",
        "case_id": case["case_id"],
        "mode": case["mode"],
        "question": case["question"],
        "jurisdiction": case["jurisdiction"],
        "as_of": case["as_of"],
        "requested_authorities": copy.deepcopy(case["requested_authorities"]),
        "sources": copy.deepcopy(case["sources"]),
    }


def _qualification_schema_1_1_payload() -> dict[str, Any]:
    """Return one Unicode, CRLF-preserving schema-1.1 qualification case."""
    payload = _qualification_payload()
    source = payload["sources"][0]
    source_text = (
        "Artículo 1. A covered operator must file notice.\r\n"
        "Estado: vigente al 2026-08-12.\r\n"
    )
    source["normalized_text"] = source_text
    source["content_hash"] = hashlib.sha256(source_text.encode("utf-8")).hexdigest()
    source["language"] = "es"
    payload.update(
        {
            "schema_version": "1.1",
            "build_binding": {
                "commit": "a" * 40,
                "archive_sha256": "b" * 64,
            },
            "language_treatments": [
                {
                    "source_ids": [source["source_id"]],
                    "method": "Revisión bilingüe del texto oficial.",
                    "rationale": "La traducción conserva la obligación jurídica.",
                    "limitations": "La terminología técnica sigue en español.",
                }
            ],
        }
    )
    return payload


def _qualification_judgment_payload(
    request_fingerprint: str,
    *,
    failed_currentness: bool = False,
) -> dict[str, Any]:
    payload = copy.deepcopy(_scripted_payloads()[0]["payload"])
    payload["request_fingerprint"] = request_fingerprint
    if failed_currentness:
        check = next(
            item for item in payload["checks"] if item["code"] == "CURRENTNESS_EVIDENCE"
        )
        check["satisfied"] = False
        check["source_ids"] = []
        check["rationale"] = "No retained status source supports the declared date."
    return cast(dict[str, Any], payload)


def _qualification_response_payload(
    request_fingerprint: str,
    *,
    judge_isolation: str = "fresh_context",
    include_optional_fields: bool = True,
) -> dict[str, Any]:
    response: dict[str, Any] = {
        "schema_version": "1.0",
        "operation": "admit_case",
        "request_fingerprint": request_fingerprint,
        "provider_name": "fictional-provider",
        "model_name": "fictional-model",
        "judge_isolation": judge_isolation,
        "payload": _qualification_judgment_payload(request_fingerprint),
    }
    if include_optional_fields:
        response.update(
            {
                "response_id": "fictional-response-1",
                "usage": {"input_tokens": 101, "output_tokens": 202},
            }
        )
    return response


def _initialize_qualification_pair_from_payload(
    tmp_path: Path,
    payload: dict[str, Any],
) -> tuple[ModuleType, Path, Path, Any, dict[str, Any]]:
    portable = _load_portable()
    core_run = tmp_path / "core-qualification"
    portable_run = tmp_path / "portable-qualification"
    core_state = initialize_qualification_core(
        QualificationCase.model_validate(payload),
        core_run,
        nonce_hex="7" * 64,
    )
    portable_state = portable.initialize_case_qualification(
        payload,
        portable_run,
        nonce_hex="7" * 64,
    )
    assert portable_state == core_state.model_dump(mode="json")
    core_request = next_qualification_core(core_run)
    portable_request = portable.next_qualification_request(portable_run)
    assert core_request is not None and portable_request is not None
    assert portable_request == core_request.model_dump(mode="json")
    assert _tree_bytes(portable_run) == _tree_bytes(core_run)
    return portable, core_run, portable_run, core_request, portable_request


def _initialize_qualification_pair(
    tmp_path: Path,
) -> tuple[ModuleType, Path, Path, Any, dict[str, Any]]:
    portable = _load_portable()
    payload = _qualification_payload()
    core_run = tmp_path / "core-qualification"
    portable_run = tmp_path / "portable-qualification"
    core_state = initialize_qualification_core(
        QualificationCase.model_validate(payload),
        core_run,
        nonce_hex="7" * 64,
    )
    portable_state = portable.initialize_case_qualification(
        payload,
        portable_run,
        nonce_hex="7" * 64,
    )
    assert portable_state == core_state.model_dump(mode="json")
    core_request = next_qualification_core(core_run)
    portable_request = portable.next_qualification_request(portable_run)
    assert core_request is not None and portable_request is not None
    assert portable_request == core_request.model_dump(mode="json")
    assert _tree_bytes(portable_run) == _tree_bytes(core_run)
    return portable, core_run, portable_run, core_request, portable_request


def test_portable_candidate_free_qualification_matches_full_bytes_and_roots(
    tmp_path: Path,
) -> None:
    portable = _load_portable()
    payload = _qualification_payload()
    core_run = tmp_path / "core-qualification"
    portable_run = tmp_path / "portable-qualification"
    core_case = QualificationCase.model_validate(payload)

    core_state = initialize_qualification_core(
        core_case,
        core_run,
        nonce_hex="7" * 64,
    )
    portable_state = portable.initialize_case_qualification(
        payload,
        portable_run,
        nonce_hex="7" * 64,
    )
    assert portable_state == core_state.model_dump(mode="json")
    assert _tree_bytes(portable_run) == _tree_bytes(core_run)

    core_request = next_qualification_core(core_run)
    portable_request = portable.next_qualification_request(portable_run)
    assert core_request is not None and portable_request is not None
    assert portable_request == core_request.model_dump(mode="json")
    assert "candidates" not in portable_request["payload"]
    assert "client_facts" not in portable_request["payload"]

    malformed = {"request_fingerprint": "not-a-hash", "checks": []}
    before = _tree_bytes(core_run)
    core_preflight = preflight_qualification_core(core_run, malformed)
    portable_preflight = portable.preflight_case_qualification(portable_run, malformed)
    assert portable_preflight == core_preflight.model_dump(mode="json")
    core_guarded = guarded_submit_qualification_core(core_run, malformed)
    portable_guarded = portable.guarded_submit_case_qualification(
        portable_run,
        malformed,
    )
    assert portable_guarded == core_guarded.model_dump(mode="json")
    assert _tree_bytes(core_run) == before
    assert _tree_bytes(portable_run) == before

    judgment_payload = copy.deepcopy(_scripted_payloads()[0]["payload"])
    judgment_payload["request_fingerprint"] = core_request.request_fingerprint
    core_receipt = submit_qualification_core(
        core_run,
        CaseAdmissionJudgment.model_validate(judgment_payload),
    )
    portable_receipt = portable.submit_case_qualification(
        portable_run,
        judgment_payload,
    )
    assert portable_receipt == core_receipt.model_dump(mode="json")
    assert _tree_bytes(portable_run) == _tree_bytes(core_run)
    assert portable.resume_case_qualification(portable_run) == (
        resume_qualification_core(core_run).model_dump(mode="json")
    )
    portable_verification = portable.verify_case_qualification(portable_run)
    core_verification = verify_qualification_core(core_run)
    assert portable_verification == core_verification.model_dump(mode="json")


def test_portable_qualification_case_invalid_matches_full_artifacts_and_root(
    tmp_path: Path,
) -> None:
    portable, core_run, portable_run, core_request, portable_request = (
        _initialize_qualification_pair(tmp_path)
    )
    core_payload = _qualification_judgment_payload(
        core_request.request_fingerprint,
        failed_currentness=True,
    )
    portable_payload = _qualification_judgment_payload(
        cast(str, portable_request["request_fingerprint"]),
        failed_currentness=True,
    )

    core_receipt = submit_qualification_core(
        core_run,
        CaseAdmissionJudgment.model_validate(core_payload),
    )
    portable_receipt = portable.submit_case_qualification(
        portable_run,
        portable_payload,
    )

    assert core_receipt.readiness.status.value == "CASE_INVALID"
    assert portable_receipt == core_receipt.model_dump(mode="json")
    assert _tree_bytes(portable_run) == _tree_bytes(core_run)
    assert portable.resume_case_qualification(portable_run) == (
        resume_qualification_core(core_run).model_dump(mode="json")
    )
    assert portable.verify_case_qualification(portable_run) == (
        verify_qualification_core(core_run).model_dump(mode="json")
    )


def test_portable_current_law_qualification_requires_objective_currentness_metadata(
    tmp_path: Path,
) -> None:
    portable = _load_portable()
    payload = _qualification_payload()
    payload["mode"] = "current-law"
    for source in payload["sources"]:
        source["version"] = None
        source["effective_date"] = None
        source["supersession"] = None
    payload["sources"][-1]["source_role"] = "commentary_analysis"
    payload["sources"][-1]["version"] = "2026 commentary edition"
    core_run = tmp_path / "core-currentness-minimum"
    portable_run = tmp_path / "portable-currentness-minimum"
    initialize_qualification_core(
        QualificationCase.model_validate(payload),
        core_run,
        nonce_hex="7" * 64,
    )
    portable.initialize_case_qualification(
        payload,
        portable_run,
        nonce_hex="7" * 64,
    )
    core_request = next_qualification_core(core_run)
    portable_request = portable.next_qualification_request(portable_run)
    assert core_request is not None and portable_request is not None
    core_payload = _qualification_judgment_payload(core_request.request_fingerprint)
    portable_payload = _qualification_judgment_payload(
        cast(str, portable_request["request_fingerprint"])
    )

    core_receipt = submit_qualification_core(
        core_run,
        CaseAdmissionJudgment.model_validate(core_payload),
    )
    portable_receipt = portable.submit_case_qualification(
        portable_run,
        portable_payload,
    )

    assert core_receipt.readiness.status.value == "CASE_INVALID"
    assert core_receipt.readiness.issue_codes == ["CURRENTNESS_EVIDENCE_INSUFFICIENT"]
    assert portable_receipt == core_receipt.model_dump(mode="json")
    assert _tree_bytes(portable_run) == _tree_bytes(core_run)
    assert portable.resume_case_qualification(portable_run) == (
        resume_qualification_core(core_run).model_dump(mode="json")
    )
    assert portable.verify_case_qualification(portable_run) == (
        verify_qualification_core(core_run).model_dump(mode="json")
    )


@pytest.mark.parametrize(
    ("vector", "expected_code"),
    [
        ("request-mismatch", "EVALUATION_RESPONSE_REQUEST_MISMATCH"),
        ("semantic-rejection", "EVALUATION_RESPONSE_SEMANTIC_INVALID"),
    ],
)
def test_portable_qualification_refusal_vectors_match_full_without_mutation(
    tmp_path: Path,
    vector: str,
    expected_code: str,
) -> None:
    portable, core_run, portable_run, core_request, _ = _initialize_qualification_pair(
        tmp_path
    )
    payload = _qualification_judgment_payload(core_request.request_fingerprint)
    if vector == "request-mismatch":
        payload["request_fingerprint"] = "8" * 64
    else:
        payload["checks"] = payload["checks"][:-1]
    before = _tree_bytes(core_run)

    core_preflight = preflight_qualification_core(core_run, payload)
    portable_preflight = portable.preflight_case_qualification(portable_run, payload)
    core_guarded = guarded_submit_qualification_core(core_run, payload)
    portable_guarded = portable.guarded_submit_case_qualification(
        portable_run,
        payload,
    )

    assert [issue.code for issue in core_preflight.issues] == [expected_code]
    assert portable_preflight == core_preflight.model_dump(mode="json")
    assert portable_guarded == core_guarded.model_dump(mode="json")
    assert _tree_bytes(core_run) == before
    assert _tree_bytes(portable_run) == before
    assert portable.resume_case_qualification(portable_run) == (
        resume_qualification_core(core_run).model_dump(mode="json")
    )
    assert portable.verify_case_qualification(portable_run) == (
        verify_qualification_core(core_run).model_dump(mode="json")
    )


def test_portable_qualification_terminal_refusal_matches_full_without_mutation(
    tmp_path: Path,
) -> None:
    portable, core_run, portable_run, core_request, _ = _initialize_qualification_pair(
        tmp_path
    )
    payload = _qualification_judgment_payload(core_request.request_fingerprint)
    submit_qualification_core(
        core_run,
        CaseAdmissionJudgment.model_validate(payload),
    )
    portable.submit_case_qualification(portable_run, payload)
    sealed = _tree_bytes(core_run)

    core_preflight = preflight_qualification_core(core_run, payload)
    portable_preflight = portable.preflight_case_qualification(portable_run, payload)
    core_guarded = guarded_submit_qualification_core(core_run, payload)
    portable_guarded = portable.guarded_submit_case_qualification(portable_run, payload)

    assert [issue.code for issue in core_preflight.issues] == [
        "EVALUATION_NO_PENDING_REQUEST"
    ]
    assert portable_preflight == core_preflight.model_dump(mode="json")
    assert portable_guarded == core_guarded.model_dump(mode="json")
    with pytest.raises(attorney_artifacts.EvaluationIntegrityError):
        submit_qualification_core(
            core_run,
            CaseAdmissionJudgment.model_validate(payload),
        )
    with pytest.raises(portable.EvaluationIntegrityError):
        portable.submit_case_qualification(portable_run, payload)
    assert _tree_bytes(core_run) == sealed
    assert _tree_bytes(portable_run) == sealed
    assert portable.resume_case_qualification(portable_run) == (
        resume_qualification_core(core_run).model_dump(mode="json")
    )
    assert portable.verify_case_qualification(portable_run) == (
        verify_qualification_core(core_run).model_dump(mode="json")
    )


@pytest.mark.parametrize("tamper", ["artifact", "empty-directory", "symlink"])
def test_portable_qualification_tamper_verification_matches_full(
    tmp_path: Path,
    tamper: str,
) -> None:
    portable, core_run, portable_run, _, _ = _initialize_qualification_pair(tmp_path)
    if tamper == "artifact":
        for run in (core_run, portable_run):
            case_path = run / "qualification-case.json"
            case_value = json.loads(case_path.read_text(encoding="utf-8"))
            case_value["question"] = "Tampered question?"
            case_path.write_bytes(canonical_json_bytes(case_value))
    elif tamper == "empty-directory":
        (core_run / "unexpected-empty-directory").mkdir()
        (portable_run / "unexpected-empty-directory").mkdir()
    else:
        core_target = tmp_path / "core-symlink-target"
        portable_target = tmp_path / "portable-symlink-target"
        core_target.mkdir()
        portable_target.mkdir()
        (core_run / "unexpected-link").symlink_to(
            core_target,
            target_is_directory=True,
        )
        (portable_run / "unexpected-link").symlink_to(
            portable_target,
            target_is_directory=True,
        )

    core_verification = verify_qualification_core(core_run)
    portable_verification = portable.verify_case_qualification(portable_run)

    assert core_verification.valid is False
    assert portable_verification == core_verification.model_dump(mode="json")


def test_portable_nonempty_qualification_refusal_preserves_mode_and_stat(
    tmp_path: Path,
) -> None:
    portable = _load_portable()
    payload = _qualification_payload()
    runs = [tmp_path / "core-nonempty", tmp_path / "portable-nonempty"]
    before: dict[Path, tuple[int, int, int, int, int, int]] = {}
    for run in runs:
        run.mkdir(mode=0o755)
        run.chmod(0o755)
        (run / "owned.txt").write_text("owned\n", encoding="utf-8")
        metadata = run.stat()
        before[run] = (
            stat.S_IMODE(metadata.st_mode),
            metadata.st_uid,
            metadata.st_gid,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )

    with pytest.raises(attorney_artifacts.EvaluationIntegrityError, match="must be empty"):
        initialize_qualification_core(
            QualificationCase.model_validate(payload),
            runs[0],
            nonce_hex="9" * 64,
        )
    with pytest.raises(portable.EvaluationIntegrityError, match="must be empty"):
        portable.initialize_case_qualification(
            payload,
            runs[1],
            nonce_hex="9" * 64,
        )

    for run in runs:
        metadata = run.stat()
        assert (
            stat.S_IMODE(metadata.st_mode),
            metadata.st_uid,
            metadata.st_gid,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        ) == before[run]
        assert _tree_bytes(run) == {"owned.txt": b"owned\n"}


def test_portable_qualification_receipt_builder_rejects_inconclusive_readiness() -> None:
    portable = _load_portable()
    readiness = {
        "status": "INCONCLUSIVE",
        "case_fingerprint": "1" * 64,
        "judgment_fingerprint": "2" * 64,
        "issue_codes": ["JUDGE_UNAVAILABLE"],
        "rationale": "No terminal source qualification was reached.",
    }

    with pytest.raises(portable.EvaluationIntegrityError, match="status is invalid"):
        portable._qualification_receipt(
            case_fingerprint="1" * 64,
            source_record_fingerprint="3" * 64,
            request_fingerprint="4" * 64,
            judgment_fingerprint="2" * 64,
            readiness=readiness,
        )


@pytest.mark.parametrize(
    "code",
    [
        "EVALUATION_NO_PENDING_REQUEST",
        "EVALUATION_RESPONSE_REQUEST_MISMATCH",
        "EVALUATION_RESPONSE_SCHEMA_INVALID",
        *(item.value for item in ResponseContractCode),
    ],
)
def test_portable_safe_diagnostic_fixture_covers_every_core_code(
    code: str,
    tmp_path: Path,
) -> None:
    """A wrong code, message, ID normalization, or fingerprint must break byte parity."""
    portable, core_run, _portable_run, core_request, portable_request = (
        _initialize_qualification_pair(tmp_path)
    )
    related_ids = [] if code == "EVALUATION_NO_PENDING_REQUEST" else [
        "z-safe",
        "a-safe",
        "z-safe",
    ]
    issue = EvaluationPreflightIssue(
        code=code,
        message=PREFLIGHT_ISSUE_MESSAGES[code],
        related_ids=related_ids,
    )
    request = None if code == "EVALUATION_NO_PENDING_REQUEST" else core_request
    portable_pending = None if request is None else portable_request

    core_result = qualification_preflight_result_core(request, issue)
    portable_result = portable._preflight_result(
        portable_pending,
        code=code,
        related_ids=tuple(related_ids),
    )

    assert portable.canonical_json_bytes(portable_result) == canonical_json_bytes(
        core_result.model_dump(mode="json")
    )
    assert portable_result["issues"][0]["related_ids"] == (
        [] if request is None else ["a-safe", "z-safe"]
    )
    assert _tree_bytes(core_run)


def test_portable_qualification_safe_diagnostic_rejects_raw_and_validation_bypass(
    tmp_path: Path,
) -> None:
    """Malformed dictionaries and model-construct bypasses must share one safe refusal."""
    portable, core_run, portable_run, core_request, _ = _initialize_qualification_pair(
        tmp_path
    )
    malformed = {
        "request_fingerprint": core_request.request_fingerprint,
        "checks": [{"code": "AUTHORITY_ALIGNMENT", "satisfied": 1, "material": True}],
    }
    bypass = CaseAdmissionJudgment.model_construct(**malformed)
    before = _tree_bytes(core_run)

    core_result = guarded_submit_qualification_core(core_run, bypass)
    portable_result = portable.guarded_submit_case_qualification(portable_run, malformed)

    assert portable_result == core_result.model_dump(mode="json")
    assert portable_result["preflight"]["issues"][0]["code"] == (
        "EVALUATION_RESPONSE_SCHEMA_INVALID"
    )
    assert _tree_bytes(core_run) == before
    assert _tree_bytes(portable_run) == before


@pytest.mark.parametrize(
    ("judge_isolation", "include_optional_fields"),
    [
        ("fresh_context", False),
        ("sequential_same_context", True),
        ("scripted_fixture", True),
    ],
)
def test_portable_qualification_schema_1_1_case_request_and_envelope_parity(
    judge_isolation: str,
    include_optional_fields: bool,
    tmp_path: Path,
) -> None:
    """Any portable projection or envelope-byte drift must fail against the full oracle."""
    payload = _qualification_schema_1_1_payload()
    before_case = copy.deepcopy(payload)
    portable, core_run, portable_run, core_request, portable_request = (
        _initialize_qualification_pair_from_payload(tmp_path, payload)
    )

    assert payload == before_case
    assert portable.validate_qualification_case(payload) == (
        QualificationCase.model_validate(payload).model_dump(mode="json")
    )
    assert "\r\n" in portable_request["payload"]["sources"][0]["normalized_text"]
    assert portable_request["payload"]["language_treatments"] == payload[
        "language_treatments"
    ]
    assert portable_request["payload"]["build_binding"] == payload["build_binding"]
    assert "supplied language treatment and its limitations" in portable_request[
        "system_instructions"
    ]
    assert portable.canonical_json_bytes(portable_request) == canonical_json_bytes(
        core_request.model_dump(mode="json")
    )

    response = _qualification_response_payload(
        core_request.request_fingerprint,
        judge_isolation=judge_isolation,
        include_optional_fields=include_optional_fields,
    )
    before_response = copy.deepcopy(response)
    core_receipt = submit_qualification_core(core_run, response)  # type: ignore[arg-type]
    portable_receipt = portable.submit_case_qualification(portable_run, response)
    expected_response_bytes = canonical_json_bytes(response)

    assert response == before_response
    assert portable_receipt == core_receipt.model_dump(mode="json")
    assert (core_run / "admission-response.json").read_bytes() == expected_response_bytes
    assert (portable_run / "admission-response.json").read_bytes() == expected_response_bytes
    assert portable_receipt["judgment_fingerprint"] == hashlib.sha256(
        canonical_json_bytes(response["payload"])
    ).hexdigest()
    assert _tree_bytes(portable_run) == _tree_bytes(core_run)
    assert portable.resume_case_qualification(portable_run) == (
        resume_qualification_core(core_run).model_dump(mode="json")
    )
    assert portable.verify_case_qualification(portable_run) == (
        verify_qualification_core(core_run).model_dump(mode="json")
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "missing-build-binding",
        "missing-language-treatments",
        "duplicate-treatment",
        "duplicate-after-normalization",
        "unknown-treatment",
        "malformed-commit",
        "malformed-archive",
        "non-string-commit",
        "blank-method",
        "blank-rationale",
        "blank-limitations",
        "legacy-explicit-empty-treatment",
    ],
)
def test_portable_qualification_schema_1_1_invalid_case_vectors_match_full(
    mutation: str,
) -> None:
    """Every schema-directed case refusal must be strict, bounded, and non-mutating."""
    portable = _load_portable()
    payload = _qualification_schema_1_1_payload()
    treatment = payload["language_treatments"][0]
    if mutation == "missing-build-binding":
        payload.pop("build_binding")
    elif mutation == "missing-language-treatments":
        payload.pop("language_treatments")
    elif mutation == "duplicate-treatment":
        payload["language_treatments"].append(copy.deepcopy(treatment))
    elif mutation == "duplicate-after-normalization":
        treatment["source_ids"].append(f"  {treatment['source_ids'][0]}\t")
    elif mutation == "unknown-treatment":
        treatment["source_ids"].append("unknown-source")
    elif mutation == "malformed-commit":
        payload["build_binding"]["commit"] = "A" * 40
    elif mutation == "malformed-archive":
        payload["build_binding"]["archive_sha256"] = "b" * 63
    elif mutation == "non-string-commit":
        payload["build_binding"]["commit"] = True
    elif mutation == "blank-method":
        treatment["method"] = "   "
    elif mutation == "blank-rationale":
        treatment["rationale"] = "\t"
    elif mutation == "blank-limitations":
        treatment["limitations"] = "\n"
    else:
        payload["schema_version"] = "1.0"
        payload.pop("build_binding")
        payload["language_treatments"] = []
    before = copy.deepcopy(payload)

    with pytest.raises((ValidationError, TypeError, ValueError)):
        QualificationCase.model_validate(payload)
    with pytest.raises((portable.PortableEvaluationInputError, TypeError, ValueError)):
        portable.validate_qualification_case(payload)

    assert payload == before


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        ("raw-inner", "EVALUATION_RESPONSE_SCHEMA_INVALID"),
        ("operation", "EVALUATION_RESPONSE_REQUEST_MISMATCH"),
        ("outer-fingerprint", "EVALUATION_RESPONSE_REQUEST_MISMATCH"),
        ("inner-fingerprint", "EVALUATION_RESPONSE_REQUEST_MISMATCH"),
        ("blank-provider", "EVALUATION_RESPONSE_SCHEMA_INVALID"),
        ("blank-model", "EVALUATION_RESPONSE_SCHEMA_INVALID"),
        ("invalid-isolation", "EVALUATION_RESPONSE_SCHEMA_INVALID"),
        ("extra-key", "EVALUATION_RESPONSE_SCHEMA_INVALID"),
        ("usage-string", "EVALUATION_RESPONSE_SCHEMA_INVALID"),
        ("usage-boolean", "EVALUATION_RESPONSE_SCHEMA_INVALID"),
        ("nonfinite-payload", "EVALUATION_RESPONSE_SCHEMA_INVALID"),
        ("response-id-boolean", "EVALUATION_RESPONSE_SCHEMA_INVALID"),
        ("payload-array", "EVALUATION_RESPONSE_SCHEMA_INVALID"),
    ],
)
def test_portable_qualification_schema_1_1_response_refusal_parity_is_write_free(
    mutation: str,
    expected_code: str,
    tmp_path: Path,
) -> None:
    portable, core_run, portable_run, core_request, _ = (
        _initialize_qualification_pair_from_payload(
            tmp_path,
            _qualification_schema_1_1_payload(),
        )
    )
    response: object = _qualification_response_payload(core_request.request_fingerprint)
    assert isinstance(response, dict)
    if mutation == "raw-inner":
        response = response["payload"]
    elif mutation == "operation":
        response["operation"] = "grade_report"
    elif mutation == "outer-fingerprint":
        response["request_fingerprint"] = "0" * 64
    elif mutation == "inner-fingerprint":
        response["payload"]["request_fingerprint"] = "0" * 64
    elif mutation == "blank-provider":
        response["provider_name"] = "   "
    elif mutation == "blank-model":
        response["model_name"] = "\t"
    elif mutation == "invalid-isolation":
        response["judge_isolation"] = "not-isolated"
    elif mutation == "extra-key":
        response["unexpected"] = "forbidden"
    elif mutation == "usage-string":
        response["usage"] = {"input_tokens": "101"}
    elif mutation == "usage-boolean":
        response["usage"] = {"input_tokens": True}
    elif mutation == "nonfinite-payload":
        response["payload"]["checks"][0]["source_ids"] = [float("nan")]
    elif mutation == "response-id-boolean":
        response["response_id"] = False
    else:
        response["payload"] = []
    before_response = copy.deepcopy(response)
    before = _tree_bytes(core_run)

    core_preflight = preflight_qualification_core(core_run, response)
    portable_preflight = portable.preflight_case_qualification(portable_run, response)
    core_guarded = guarded_submit_qualification_core(core_run, response)
    portable_guarded = portable.guarded_submit_case_qualification(portable_run, response)

    assert [issue.code for issue in core_preflight.issues] == [expected_code]
    assert portable_preflight == core_preflight.model_dump(mode="json")
    assert portable_guarded == core_guarded.model_dump(mode="json")
    if mutation == "nonfinite-payload":
        assert math.isnan(response["payload"]["checks"][0]["source_ids"][0])
    else:
        assert response == before_response
    assert _tree_bytes(core_run) == before
    assert _tree_bytes(portable_run) == before


@pytest.mark.parametrize("mutation", ["blank-provider", "unhashable-payload"])
def test_portable_qualification_schema_1_1_model_construct_bypass_matches_raw_mapping(
    mutation: str,
    tmp_path: Path,
) -> None:
    portable, core_run, portable_run, core_request, _ = (
        _initialize_qualification_pair_from_payload(
            tmp_path,
            _qualification_schema_1_1_payload(),
        )
    )
    raw = _qualification_response_payload(core_request.request_fingerprint)
    if mutation == "blank-provider":
        raw["provider_name"] = "   "
    else:
        raw["payload"]["checks"][0]["source_ids"] = [["not-an-identifier"]]
    bypass = JudgeResponse.model_construct(**raw)
    before = _tree_bytes(core_run)

    core_guarded = guarded_submit_qualification_core(core_run, bypass)
    portable_guarded = portable.guarded_submit_case_qualification(portable_run, raw)

    assert portable_guarded == core_guarded.model_dump(mode="json")
    assert portable_guarded["preflight"]["issues"][0]["code"] == (
        "EVALUATION_RESPONSE_SCHEMA_INVALID"
    )
    assert _tree_bytes(core_run) == before
    assert _tree_bytes(portable_run) == before


@pytest.mark.parametrize("shape", ["too-deep", "list-cycle", "dict-cycle"])
def test_portable_qualification_schema_1_1_depth_and_cycle_diagnostics_are_bounded(
    shape: str,
    tmp_path: Path,
) -> None:
    portable, core_run, portable_run, core_request, _ = (
        _initialize_qualification_pair_from_payload(
            tmp_path,
            _qualification_schema_1_1_payload(),
        )
    )
    raw = _qualification_response_payload(core_request.request_fingerprint)
    if shape == "too-deep":
        nested: object = []
        for _ in range(2048):
            nested = [nested]
    elif shape == "list-cycle":
        nested = []
        nested.append(nested)
    else:
        nested = {}
        nested["self"] = nested
    raw["payload"]["checks"][0]["source_ids"] = nested
    bypass = JudgeResponse.model_construct(**raw)
    before = _tree_bytes(core_run)

    core_preflight = preflight_qualification_core(core_run, bypass)
    portable_preflight = portable.preflight_case_qualification(portable_run, raw)

    assert portable_preflight == core_preflight.model_dump(mode="json")
    assert portable_preflight["issues"][0]["code"] == (
        "EVALUATION_RESPONSE_SCHEMA_INVALID"
    )
    assert _tree_bytes(core_run) == before
    assert _tree_bytes(portable_run) == before


@pytest.mark.parametrize(
    ("artifact", "path", "replacement"),
    [
        ("admission-response.json", ("provider_name",), "tampered-provider"),
        ("admission-response.json", ("model_name",), "tampered-model"),
        ("admission-response.json", ("judge_isolation",), "scripted_fixture"),
        ("admission-response.json", ("usage", "input_tokens"), 999),
        ("admission-response.json", ("payload", "request_fingerprint"), "0" * 64),
        ("qualification-case.json", ("build_binding", "commit"), "c" * 40),
        (
            "qualification-case.json",
            ("language_treatments", 0, "limitations"),
            "Tampered limitation.",
        ),
    ],
)
def test_portable_qualification_schema_1_1_tamper_verification_matches_full(
    artifact: str,
    path: tuple[str | int, ...],
    replacement: object,
    tmp_path: Path,
) -> None:
    portable, core_run, portable_run, core_request, _ = (
        _initialize_qualification_pair_from_payload(
            tmp_path,
            _qualification_schema_1_1_payload(),
        )
    )
    response = _qualification_response_payload(core_request.request_fingerprint)
    submit_qualification_core(core_run, response)  # type: ignore[arg-type]
    portable.submit_case_qualification(portable_run, response)
    for run in (core_run, portable_run):
        artifact_path = run / artifact
        value = json.loads(artifact_path.read_bytes())
        target = value
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = replacement
        artifact_path.write_bytes(canonical_json_bytes(value))

    assert portable.verify_case_qualification(portable_run) == (
        verify_qualification_core(core_run).model_dump(mode="json")
    ) == {
        "valid": False,
        "issues": ["QUALIFICATION_INTEGRITY_INVALID"],
        "root_hash": None,
    }


def test_portable_qualification_legacy_1_0_frozen_replay_bytes_are_unchanged(
    tmp_path: Path,
) -> None:
    portable, core_run, portable_run, core_request, _ = _initialize_qualification_pair(
        tmp_path
    )
    judgment = _qualification_judgment_payload(core_request.request_fingerprint)
    core_receipt = submit_qualification_core(
        core_run,
        CaseAdmissionJudgment.model_validate(judgment),
    )
    portable_receipt = portable.submit_case_qualification(portable_run, judgment)

    expected_hashes = {
        "qualification-case.json": (
            "939722d649e99c104e54ac1fd5da339b3fbbfd51c1c142963f61927123e715b4"
        ),
        "admission-request.json": (
            "d27f773b799bfc0197254e375cc7c0ed1c99dc575f00f538d80339114e80a792"
        ),
        "admission-response.json": (
            "e265b2ef3a0a5917aa739f130a11527a87e871bd48a3229ed7f0a030ab7830c7"
        ),
        "qualification-receipt.json": (
            "86036d485f3700b0cc92a15d8e149c5b6986761d42917a9d870c8bbf8c813be0"
        ),
        "manifest.json": "b5f27fbb7513e7297bc60839752aeda99639a14ce48b293c9080b7db8b1e7728",
    }
    assert portable_receipt == core_receipt.model_dump(mode="json")
    assert {
        name: hashlib.sha256((portable_run / name).read_bytes()).hexdigest()
        for name in expected_hashes
    } == expected_hashes
    assert _tree_bytes(portable_run) == _tree_bytes(core_run)
    assert portable.resume_case_qualification(portable_run)["root_hash"] == (
        "3c8d8ec61ac301e8921dd16fe9ea2817f098306b6b79a271662cde8e8ff27ce3"
    )
    assert portable.verify_case_qualification(portable_run) == (
        verify_qualification_core(core_run).model_dump(mode="json")
    )


def _advance_portable_to_first_grade(module: ModuleType, run: Path) -> dict[str, Any]:
    module.initialize_evaluation(_case_payload(), run, seed_hex="0" * 64)
    for index, item in enumerate(_scripted_payloads()[:3], start=1):
        request = module.next_judge_request(run)
        assert request is not None
        module.submit_judge_response(run, _response(request, item, index))
    request = module.next_judge_request(run)
    assert request is not None and request["operation"] == "grade_report"
    return cast(dict[str, Any], request)


def _grade_with_evidence(
    portable: ModuleType,
    envelope: dict[str, Any],
    sealed: dict[str, Any],
    *,
    response_index: int = 3,
) -> dict[str, Any]:
    grade = copy.deepcopy(_scripted_payloads()[response_index]["payload"])
    grade["schema_version"] = "1.3"
    report = portable._candidate_for_label(envelope, grade["anonymous_label"])[
        "report_text"
    ].strip()
    for entry in grade["entry_grades"]:
        entry["report_passage"] = None if entry["disposition"] == "MISSING" else report
    for narrative in grade["narrative_scores"]:
        narrative["report_passage"] = report
    source_record = portable.build_admission_packet(envelope)["payload"]
    source = source_record["sources"][0]
    evidence_quote = "civil penalty of $500"
    start = source["normalized_text"].index(evidence_quote)
    grade["out_of_ledger_claims"] = [
        {
            "claim_id": "civil-penalty-claim",
            "claim_text": "civil penalty of $500",
            "report_location": "paragraph 1",
            "disposition": "COMPLETE",
            "category": "penalty",
            "materiality": "material",
            "related_ledger_ids": ["civil-penalty"],
            "rationale": "The report states the penalty and the source record supports it.",
            "source_record_fingerprint": source_record["source_record_fingerprint"],
            "evidence_basis": "source_spans",
            "evidence_spans": [
                {
                    "source_id": source["source_id"],
                    "start_char": start,
                    "end_char": start + len(evidence_quote),
                    "quote": evidence_quote,
                }
            ],
        }
    ]
    grade["ledger_fingerprint"] = sealed["ledger_fingerprint"]
    return cast(dict[str, Any], grade)


def _portable_comparison_fixture(portable: ModuleType) -> dict[str, Any]:
    """Build two real source-bearing portable scores and their immutable inputs."""
    envelope = portable.freeze_case(_case_payload(), seed_hex="0" * 64)
    responses = _scripted_payloads()
    sealed = portable.seal_ledger(
        envelope,
        responses[1]["payload"],
        responses[2]["payload"],
        None,
    )
    first_a = _grade_with_evidence(portable, envelope, sealed)
    second_a = copy.deepcopy(first_a)
    second_a["request_fingerprint"] = "f" * 64
    first_b = copy.deepcopy(first_a)
    first_b["anonymous_label"] = "B"
    first_b["request_fingerprint"] = "b" * 64
    first_b["narrative_scores"][0]["score"] = 3
    second_b = copy.deepcopy(first_b)
    second_b["request_fingerprint"] = "c" * 64
    resolved_a = portable.resolve_grades(sealed, first_a, second_a)
    resolved_b = portable.resolve_grades(sealed, first_b, second_b)
    checks_a = portable._derive_deterministic_checks(
        portable._candidate_for_label(envelope, "A"), "A"
    )
    checks_b = copy.deepcopy(checks_a)
    checks_b["anonymous_label"] = "B"
    source_record = portable.build_admission_packet(envelope)["payload"]

    def inputs(label: str, resolved: dict[str, Any], checks: dict[str, Any]) -> dict[str, Any]:
        return {
            "schema_version": "1.4",
            "anonymous_label": label,
            "sealed_ledger": copy.deepcopy(sealed),
            "resolved_grade": {"schema_version": "1.3", **copy.deepcopy(resolved)},
            "deterministic_checks": copy.deepcopy(checks),
            "rubric": copy.deepcopy(portable.RUBRIC_V1),
            "source_record": copy.deepcopy(source_record),
        }

    candidate_inputs = inputs("A", resolved_a, checks_a)
    comparator_inputs = inputs("B", resolved_b, checks_b)
    return {
        "envelope": envelope,
        "candidate": portable.score_report(
            sealed,
            resolved_a,
            checks_a,
            source_record=source_record,
        ),
        "comparator": portable.score_report(
            sealed,
            resolved_b,
            checks_b,
            source_record=source_record,
        ),
        "candidate_inputs": candidate_inputs,
        "comparator_inputs": comparator_inputs,
    }


def _rebind_portable_resolution_fingerprint(
    portable: ModuleType,
    score_inputs: dict[str, Any],
) -> None:
    resolved = score_inputs["resolved_grade"]
    payload = {
        key: resolved[key]
        for key in (
            "grade",
            "audit",
            "original_grader_1",
            "original_grader_2",
            "referee_decisions",
        )
    }
    resolved["resolution_fingerprint"] = hashlib.sha256(
        portable.canonical_json_bytes(payload)
    ).hexdigest()


def _run_core(run: Path) -> None:
    case = _case_from_fixture(FIXTURE / "case.json", root=FIXTURE)
    initialize_core(case, run, seed_hex="0" * 64)
    scripted = _scripted_payloads()
    for index, item in enumerate(scripted, start=1):
        request = next_core(run)
        assert request is not None
        response = JudgeResponse.model_validate(
            _response(request.model_dump(mode="json"), item, index)
        )
        submit_core(run, response)


def _differential_payload(
    request: dict[str, Any], grade_counts: dict[str, int], *, hostile: bool = False
) -> dict[str, Any]:
    scripted = _scripted_payloads()
    operation = request["operation"]
    if operation == "admit_case":
        payload = cast(dict[str, Any], copy.deepcopy(scripted[0]["payload"]))
        payload["request_fingerprint"] = request["request_fingerprint"]
        return payload
    if operation == "build_ledger":
        payload = cast(dict[str, Any], copy.deepcopy(scripted[1]["payload"]))
        payload["case_fingerprint"] = request["safe_metadata"]["source_record_fingerprint"]
        if hostile:
            entry = payload["entries"][0]
            source_text = request["payload"]["source_record"]["sources"][0]["normalized_text"]
            entry["proposition"] = (
                "<img src=x onerror=alert(1)> | slash \\ cr\r lf\n tab\t "
                "bell\x07 c1\x85 entity &lt; source <br>"
            )
            entry["citations"] = [
                {
                    "source_id": "synthetic-rule-1-source",
                    "start_char": 0,
                    "end_char": 4,
                    "quote": source_text[0:4],
                },
                {
                    "source_id": "synthetic-rule-1-source",
                    "start_char": 5,
                    "end_char": 7,
                    "quote": source_text[5:7],
                },
            ]
        return payload
    if operation == "audit_ledger":
        payload = cast(dict[str, Any], copy.deepcopy(scripted[2]["payload"]))
        payload["request_fingerprint"] = request["request_fingerprint"]
        return payload
    if operation == "grade_report":
        label = request["safe_metadata"]["anonymous_label"]
        grade_counts[label] = grade_counts.get(label, 0) + 1
        payload = cast(
            dict[str, Any],
            copy.deepcopy(scripted[3 if grade_counts[label] == 1 else 4]["payload"]),
        )
        payload["request_fingerprint"] = request["request_fingerprint"]
        payload["anonymous_label"] = label
        payload["ledger_fingerprint"] = request["safe_metadata"]["legal_ledger_fingerprint"]
        if hostile:
            finding = payload["entry_grades"][0]
            finding.update(
                {
                    "disposition": "MISSING",
                    "report_location": None,
                    "finding_codes": ["CRITICAL_LEDGER_ENTRY_MISSING"],
                    "rationale": "why | because\\yes\r\nthen\tend\x7f &amp; <br>",
                }
            )
        return payload
    raise AssertionError(f"unexpected operation in differential fixture: {operation}")


def _run_differential(
    portable: ModuleType,
    case_payload: dict[str, Any],
    portable_run: Path,
    core_run: Path,
    *,
    hostile: bool = False,
) -> None:
    portable.initialize_evaluation(case_payload, portable_run, seed_hex="0" * 64)
    initialize_core(_core_case_from_payload(case_payload), core_run, seed_hex="0" * 64)
    grade_counts: dict[str, int] = {}
    response_number = 0
    while True:
        portable_request = portable.next_judge_request(portable_run)
        core_request = next_core(core_run)
        if portable_request is None or core_request is None:
            assert portable_request is None and core_request is None
            break
        assert portable.canonical_json_bytes(portable_request) == portable.canonical_json_bytes(
            core_request.model_dump(mode="json")
        )
        payload = _differential_payload(portable_request, grade_counts, hostile=hostile)
        response_number += 1
        response = _response(portable_request, {"payload": payload}, response_number)
        assert response["schema_version"] == "1.0"
        portable.submit_judge_response(portable_run, response)
        submit_core(core_run, JudgeResponse.model_validate(response))


def _rehash_manifest_artifact(portable: ModuleType, run: Path, artifact: str) -> None:
    manifest_path = run / "run-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    record = next(item for item in manifest["artifacts"] if item["artifact_path"] == artifact)
    record["artifact_hash"] = hashlib.sha256((run / artifact).read_bytes()).hexdigest()
    manifest["artifact_inventory_fingerprint"] = hashlib.sha256(
        portable.canonical_json_bytes(manifest["artifacts"])
    ).hexdigest()
    manifest["manifest_fingerprint"] = "0" * 64
    manifest["manifest_fingerprint"] = portable._model_fingerprint(
        manifest, exclude={"manifest_fingerprint"}
    )
    manifest_path.write_bytes(portable.canonical_json_bytes(manifest))


def _rehash_completed_response(portable: ModuleType, run: Path, artifact: str) -> None:
    manifest_path = run / "run-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    digest = hashlib.sha256((run / artifact).read_bytes()).hexdigest()
    call = next(
        item
        for item in manifest["judge_calls"]
        if item["response_artifact_path"] == artifact
    )
    call["response_fingerprint"] = digest
    record = next(item for item in manifest["artifacts"] if item["artifact_path"] == artifact)
    record["artifact_hash"] = digest
    manifest["artifact_inventory_fingerprint"] = hashlib.sha256(
        portable.canonical_json_bytes(manifest["artifacts"])
    ).hexdigest()
    manifest["manifest_fingerprint"] = "0" * 64
    manifest["manifest_fingerprint"] = portable._model_fingerprint(
        manifest, exclude={"manifest_fingerprint"}
    )
    manifest_path.write_bytes(portable.canonical_json_bytes(manifest))


def _rewrite_portable_history_artifacts(
    portable: ModuleType,
    run: Path,
    replacements: dict[str, bytes],
) -> None:
    """Rebind hashes so semantic replay evaluates self-consistent mutations."""
    for artifact_path, artifact_bytes in replacements.items():
        (run / artifact_path).write_bytes(artifact_bytes)
    manifest_path = run / "run-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for record in manifest["artifacts"]:
        artifact_path = record["artifact_path"]
        if artifact_path in replacements:
            record["artifact_hash"] = hashlib.sha256(replacements[artifact_path]).hexdigest()
    for call in manifest["judge_calls"]:
        response_path = call["response_artifact_path"]
        if response_path in replacements:
            call["response_fingerprint"] = hashlib.sha256(
                replacements[response_path]
            ).hexdigest()
        request_path = call["request_artifact_path"]
        if request_path in replacements:
            request = json.loads(replacements[request_path])
            call["request_fingerprint"] = request["request_fingerprint"]
            call["prompt_fingerprint"] = portable._prompt_fingerprint(request)
    manifest["artifact_inventory_fingerprint"] = hashlib.sha256(
        portable.canonical_json_bytes(manifest["artifacts"])
    ).hexdigest()
    manifest["manifest_fingerprint"] = "0" * 64
    manifest["manifest_fingerprint"] = portable._model_fingerprint(
        manifest,
        exclude={"manifest_fingerprint"},
    )
    manifest_path.write_bytes(portable.canonical_json_bytes(manifest))


def _refingerprint_result(portable: ModuleType, result: dict[str, Any]) -> None:
    for report in result["reports"]:
        report["score_fingerprint"] = "0" * 64
        report["score_fingerprint"] = portable._model_fingerprint(
            report, exclude={"score_fingerprint"}
        )
    result["result_fingerprint"] = "0" * 64
    result["result_fingerprint"] = portable._model_fingerprint(
        result, exclude={"result_fingerprint"}
    )


def _render_core_result_payload(payload: dict[str, Any]) -> str:
    result = attorney_artifacts._load_model_bytes(
        canonical_json_bytes(payload),
        AttorneyEvaluationResult,
        location="evaluation-result.json",
    )
    return attorney_artifacts.render_evaluation_report(result)


def test_import_is_standard_library_only_under_isolated_python() -> None:
    code = f"""
import importlib.util
import sys
spec = importlib.util.spec_from_file_location('portable', {str(SCRIPT)!r})
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
assert not (set(sys.modules) & {{'pydantic', 'regulatory_harvest'}})
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", code],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_canonical_json_rejects_nonordinary_and_noncanonical_values() -> None:
    portable = _load_portable()
    assert portable.canonical_json_bytes({"z": 1, "a": "é"}) == b'{"a":"\xc3\xa9","z":1}'
    with pytest.raises(portable.EvaluationIntegrityError, match="non-finite"):
        portable.canonical_json_bytes({"value": float("nan")})
    with pytest.raises(portable.EvaluationIntegrityError, match="non-string key"):
        portable.canonical_json_bytes({1: "not ordinary"})
    with pytest.raises(portable.EvaluationIntegrityError, match="not canonical JSON"):
        portable.parse_canonical_json_bytes(b'{"z":1, "a":2}', location="fixture")


def test_case_validation_is_strict_typed_and_does_not_coerce() -> None:
    portable = _load_portable()
    case = _case_payload()
    assert portable.validate_case(case) == case
    malformed = copy.deepcopy(case)
    malformed["sources"][0]["relationship_ids"] = [1]
    with pytest.raises(portable.PortableEvaluationInputError):
        portable.validate_case(malformed)
    extra = copy.deepcopy(case)
    extra["private_answer_key"] = {"A": "candidate"}
    with pytest.raises(portable.PortableEvaluationInputError):
        portable.validate_case(extra)


@pytest.mark.parametrize(
    "exact_text",
    ["  Exact text  ", "Exact text\n", "Exact text\r\n", "\ufeffExact text"],
)
def test_portable_case_validation_preserves_exact_content_like_core(exact_text: str) -> None:
    """Portable validation must not normalize a byte-equivalent content field."""
    portable = _load_portable()
    case = _case_payload()
    content_hash = hashlib.sha256(exact_text.encode("utf-8")).hexdigest()
    case["sources"][0].update(normalized_text=exact_text, content_hash=content_hash)
    case["candidates"][0].update(report_text=exact_text, report_hash=content_hash)
    case["client_facts"] = exact_text

    portable_case = portable.validate_case(case)
    core_case = _core_case_from_payload(case).model_dump(mode="json")

    assert portable_case == core_case
    assert portable_case["sources"][0]["normalized_text"] == exact_text
    assert portable_case["candidates"][0]["report_text"] == exact_text
    assert portable_case["client_facts"] == exact_text


@pytest.mark.parametrize("blank_text", ["", " \r\n\t", "\ufeff", "\ufeff \r\n"])
def test_portable_case_validation_rejects_semantically_blank_content_like_core(
    blank_text: str,
) -> None:
    """Exact-byte handling must keep the full and portable nonblank boundary identical."""
    portable = _load_portable()
    case = _case_payload()
    content_hash = hashlib.sha256(blank_text.encode("utf-8")).hexdigest()
    case["sources"][0].update(normalized_text=blank_text, content_hash=content_hash)

    with pytest.raises(portable.PortableEvaluationInputError):
        portable.validate_case(case)
    with pytest.raises(ValidationError):
        _core_case_from_payload(case)


def test_role_packets_preserve_source_and_report_noninterference(tmp_path: Path) -> None:
    portable = _load_portable()
    run = tmp_path / "run"
    portable.initialize_evaluation(_case_payload(), run, seed_hex="0" * 64)
    admission = portable.next_judge_request(run)
    assert admission is not None
    serialized = json.dumps(admission, sort_keys=True).casefold()
    assert "report_text" not in serialized
    assert "synthetic-harvest" not in serialized
    assert "assignments" not in serialized

    scripted = _scripted_payloads()
    for index, item in enumerate(scripted[:3], start=1):
        request = portable.next_judge_request(run)
        assert request is not None
        assert request["operation"] == item["operation"]
        source_packet = json.dumps(request, sort_keys=True).casefold()
        assert "report_text" not in source_packet
        assert "synthetic-harvest" not in source_packet
        portable.submit_judge_response(run, _response(request, item, index))

    grade = portable.next_judge_request(run)
    assert grade is not None and grade["operation"] == "grade_report"
    assert grade["payload"]["anonymous_report"]["anonymous_label"] == "A"
    assert "candidate_id" not in json.dumps(grade, sort_keys=True)


def test_grade_packet_exposes_the_complete_source_record_and_evidence_contract(
    tmp_path: Path,
) -> None:
    """Removing closed-universe evidence from a grader packet must break this contract."""
    portable = _load_portable()
    run = tmp_path / "run"
    grade = _advance_portable_to_first_grade(portable, run)
    envelope = json.loads((run / "case-envelope.json").read_text(encoding="utf-8"))

    assert grade["payload"]["source_record"] == portable.build_admission_packet(envelope)[
        "payload"
    ]
    assert grade["payload"]["source_spans"]
    definitions = grade["json_schema"]["$defs"]
    assert "report_passage" in definitions["EntryGrade"]["required"]
    assert "report_passage" in definitions["NarrativeScore"]["required"]
    assert {
        "source_record_fingerprint",
        "evidence_basis",
        "evidence_spans",
    } <= set(definitions["OutOfLedgerClaim"]["required"])
    assert grade["payload"]["finding_code_contract"] == {
        "entry_finding_codes": {
            "CONSEQUENCE_TRIGGER_DETACHED": {
                "allowed_dispositions": ["PARTIAL", "OVERSTATED", "CONTRADICTED"],
                "ledger_categories": ["enforcement", "penalty", "remedy"],
                "ledger_fields": {
                    "consequence": "required",
                    "trigger_or_relationship_ids": "at_least_one_required",
                },
            },
            "CRITICAL_LEDGER_ENTRY_MISSING": {
                "allowed_dispositions": ["MISSING"],
                "ledger_materialities": ["critical"],
            },
            "MATERIAL_EXCEPTION_MISSING": {
                "allowed_dispositions": ["MISSING", "PARTIAL"],
                "ledger_categories": ["exception"],
                "ledger_materialities": ["critical", "material"],
            },
        },
        "narrative_finding_codes": {
            "KEY_REQUIREMENTS_ACTION_PLAN": {
                "allowed_dimensions": [
                    "key_requirements",
                    "requirements_workplan_boundary",
                ],
                "maximum_score": 2,
            }
        },
    }


def test_grade_evidence_requires_exact_report_and_source_slices() -> None:
    """Fabricated passages or evidence offsets must fail before a grade is persisted."""
    portable = _load_portable()
    envelope = portable.freeze_case(_case_payload(), seed_hex="0" * 64)
    responses = _scripted_payloads()
    sealed = portable.seal_ledger(
        envelope,
        responses[1]["payload"],
        responses[2]["payload"],
        None,
    )
    grade = _grade_with_evidence(portable, envelope, sealed)
    validated, issues = portable.validate_grade(sealed, grade)

    assert issues == []
    portable._validate_grade_evidence(envelope, validated, "A")

    fabricated_passage = copy.deepcopy(validated)
    fabricated_passage["narrative_scores"][0]["report_passage"] = "invented passage"
    with pytest.raises(portable.PortableEvaluationInputError, match="report passage"):
        portable._validate_grade_evidence(envelope, fabricated_passage, "A")

    fabricated_source = copy.deepcopy(validated)
    fabricated_source["out_of_ledger_claims"][0]["evidence_spans"][0]["quote"] = (
        "invented source text"
    )
    with pytest.raises(portable.PortableEvaluationInputError, match="evidence span"):
        portable._validate_grade_evidence(envelope, fabricated_source, "A")


@pytest.mark.parametrize(
    "disposition",
    sorted(portable_disposition for portable_disposition in (
        "COMPLETE",
        "PARTIAL",
        "MISSING",
        "OVERSTATED",
        "CONTRADICTED",
        "NOT_APPLICABLE",
    )),
)
def test_portable_only_unsupported_claim_may_use_absence_basis(disposition: str) -> None:
    portable = _load_portable()
    claim = {
        "claim_id": "claim-1",
        "claim_text": "The report states an additional penalty.",
        "report_location": "paragraph 1",
        "disposition": disposition,
        "category": "penalty",
        "materiality": "material",
        "related_ledger_ids": [],
        "source_record_fingerprint": "1" * 64,
        "evidence_basis": "closed_universe_absence",
        "evidence_spans": [],
        "rationale": "The complete source record lacks support.",
    }

    with pytest.raises(
        portable.PortableEvaluationInputError,
        match="valid only for the UNSUPPORTED",
    ):
        portable._validate_claim(claim, location="test claim")


@pytest.mark.parametrize("disposition", ["COMPLETE", "PARTIAL"])
def test_positive_credit_absence_grade_retries_with_full_portable_parity(
    tmp_path: Path,
    disposition: str,
) -> None:
    portable = _load_portable()
    portable_run = tmp_path / "portable"
    core_run = tmp_path / "core"
    request = _advance_portable_to_first_grade(portable, portable_run)
    initialize_core(_core_case_from_payload(_case_payload()), core_run, seed_hex="0" * 64)
    for index, item in enumerate(_scripted_payloads()[:3], start=1):
        core_request = next_core(core_run)
        assert core_request is not None
        submit_core(
            core_run,
            JudgeResponse.model_validate(
                _response(core_request.model_dump(mode="json"), item, index)
            ),
        )
    core_request = next_core(core_run)
    assert core_request is not None
    assert request == core_request.model_dump(mode="json")
    envelope = json.loads((portable_run / "case-envelope.json").read_text(encoding="utf-8"))
    sealed = json.loads((portable_run / "legal-ledger.json").read_text(encoding="utf-8"))
    grade = _grade_with_evidence(portable, envelope, sealed)
    grade["out_of_ledger_claims"][0]["disposition"] = disposition
    grade["out_of_ledger_claims"][0]["evidence_basis"] = "closed_universe_absence"
    grade["out_of_ledger_claims"][0]["evidence_spans"] = []
    response = _response(request, {"payload": grade}, 4)

    portable_state = portable.submit_judge_response(portable_run, response)
    core_state = submit_core(core_run, JudgeResponse.model_validate(response))

    portable_state_without_manifest = {
        key: value for key, value in portable_state.items() if key != "manifest_fingerprint"
    }
    core_state_without_manifest = {
        key: value
        for key, value in core_state.model_dump(mode="json").items()
        if key != "manifest_fingerprint"
    }
    assert portable_state_without_manifest == core_state_without_manifest
    assert portable_state["state"] == "grade-a"
    assert portable_state["attempt"] == 2
    assert portable_state["retry_count"] == 1
    assert not (portable_run / "grader-1-report-A.json").exists()
    assert not (core_run / "grader-1-report-A.json").exists()


@pytest.mark.parametrize(
    ("disposition", "evidence_basis", "expected_precision"),
    [
        ("COMPLETE", "source_spans", 1.0),
        ("UNSUPPORTED", "closed_universe_absence", 0.0),
    ],
)
def test_portable_claim_evidence_binding_retains_expected_precision_credit(
    disposition: str,
    evidence_basis: str,
    expected_precision: float,
) -> None:
    portable = _load_portable()
    envelope = portable.freeze_case(_case_payload(), seed_hex="0" * 64)
    responses = _scripted_payloads()
    sealed = portable.seal_ledger(
        envelope,
        responses[1]["payload"],
        responses[2]["payload"],
        None,
    )
    first = _grade_with_evidence(portable, envelope, sealed)
    claim = first["out_of_ledger_claims"][0]
    claim["disposition"] = disposition
    claim["evidence_basis"] = evidence_basis
    if evidence_basis == "closed_universe_absence":
        claim["evidence_spans"] = []
    first, issues = portable.validate_grade(sealed, first)
    assert issues == []
    portable._validate_grade_evidence(envelope, first, "A")
    second = copy.deepcopy(first)
    second["request_fingerprint"] = "f" * 64
    resolved = portable.resolve_grades(sealed, first, second)
    checks = portable._derive_deterministic_checks(
        portable._candidate_for_label(envelope, "A"), "A"
    )

    scored = portable.score_report(
        sealed,
        resolved,
        checks,
        source_record=portable.build_admission_packet(envelope)["payload"],
    )

    assert scored["claim_precision"] == expected_precision


def test_portable_score_report_requires_the_common_source_record() -> None:
    portable = _load_portable()
    envelope = portable.freeze_case(_case_payload(), seed_hex="0" * 64)
    responses = _scripted_payloads()
    sealed = portable.seal_ledger(
        envelope,
        responses[1]["payload"],
        responses[2]["payload"],
        None,
    )
    first = _grade_with_evidence(portable, envelope, sealed)
    second = copy.deepcopy(first)
    second["request_fingerprint"] = "f" * 64
    resolved = portable.resolve_grades(sealed, first, second)
    checks = portable._derive_deterministic_checks(
        portable._candidate_for_label(envelope, "A"), "A"
    )

    with pytest.raises(TypeError, match="source_record"):
        portable.score_report(sealed, resolved, checks)


@pytest.mark.parametrize(
    "mutation",
    ["fingerprint", "source_id", "bounds", "quote"],
)
def test_portable_score_report_rejects_fabricated_or_unbound_exact_evidence(
    mutation: str,
) -> None:
    portable = _load_portable()
    envelope = portable.freeze_case(_case_payload(), seed_hex="0" * 64)
    responses = _scripted_payloads()
    sealed = portable.seal_ledger(
        envelope,
        responses[1]["payload"],
        responses[2]["payload"],
        None,
    )
    first = _grade_with_evidence(portable, envelope, sealed)
    claim = first["out_of_ledger_claims"][0]
    span = claim["evidence_spans"][0]
    source_record = portable.build_admission_packet(envelope)["payload"]
    if mutation == "fingerprint":
        claim["source_record_fingerprint"] = "f" * 64
    elif mutation == "source_id":
        span["source_id"] = "unknown-source"
    elif mutation == "bounds":
        span["end_char"] = len(source_record["sources"][0]["normalized_text"]) + 1
    else:
        span["quote"] = "fabricated exact quote"
    second = copy.deepcopy(first)
    second["request_fingerprint"] = "f" * 64
    resolved = portable.resolve_grades(sealed, first, second)
    checks = portable._derive_deterministic_checks(
        portable._candidate_for_label(envelope, "A"), "A"
    )

    with pytest.raises(
        portable.EvaluationInconclusiveError,
        match=r"source record|exact source span",
    ):
        portable.score_report(
            sealed,
            resolved,
            checks,
            source_record=source_record,
        )


def test_portable_score_report_rejects_invalid_referee_replacement_source_evidence() -> None:
    portable = _load_portable()
    envelope = portable.freeze_case(_case_payload(), seed_hex="0" * 64)
    responses = _scripted_payloads()
    sealed = portable.seal_ledger(
        envelope,
        responses[1]["payload"],
        responses[2]["payload"],
        None,
    )
    first = _grade_with_evidence(portable, envelope, sealed)
    second = copy.deepcopy(first)
    second["request_fingerprint"] = "f" * 64
    second["out_of_ledger_claims"][0]["disposition"] = "PARTIAL"
    records = portable._comparison_records(sealed, first, second)
    dispute = next(
        record["dispute"]
        for record in records
        if record["kind"] == "out_of_ledger_claim"
    )
    assert dispute is not None
    replacement_claim = copy.deepcopy(first["out_of_ledger_claims"][0])
    replacement_claim["claim_id"] = dispute["subject_id"]
    replacement_claim["evidence_spans"][0]["quote"] = "fabricated exact quote"
    decision = {
        "dispute_id": dispute["dispute_id"],
        "selected_grade_resolution": "replace",
        "grade_dispute_fingerprint": portable._model_fingerprint(dispute),
        "replacement_grade_alternative": {
            "request_fingerprint": "c" * 64,
            "out_of_ledger_claim": replacement_claim,
        },
        "rationale": "The referee supplied a replacement claim.",
    }
    resolved = portable.resolve_grades(sealed, first, second, [decision])
    checks = portable._derive_deterministic_checks(
        portable._candidate_for_label(envelope, "A"), "A"
    )

    with pytest.raises(portable.EvaluationInconclusiveError, match="exact source span"):
        portable.score_report(
            sealed,
            resolved,
            checks,
            source_record=portable.build_admission_packet(envelope)["payload"],
        )


def test_portable_referee_replacement_cannot_introduce_positive_credit_absence() -> None:
    portable = _load_portable()
    envelope = portable.freeze_case(_case_payload(), seed_hex="0" * 64)
    responses = _scripted_payloads()
    sealed = portable.seal_ledger(
        envelope,
        responses[1]["payload"],
        responses[2]["payload"],
        None,
    )
    grade = _grade_with_evidence(portable, envelope, sealed)
    replacement_claim = copy.deepcopy(grade["out_of_ledger_claims"][0])
    replacement_claim["evidence_basis"] = "closed_universe_absence"
    replacement_claim["evidence_spans"] = []
    decision = {
        "dispute_id": "grade-claim-matched-claim-0001",
        "selected_grade_resolution": "replace",
        "grade_dispute_fingerprint": "a" * 64,
        "replacement_grade_alternative": {
            "request_fingerprint": "b" * 64,
            "out_of_ledger_claim": replacement_claim,
        },
        "rationale": "The referee supplied a replacement claim.",
    }

    with pytest.raises(
        portable.PortableEvaluationInputError,
        match="valid only for the UNSUPPORTED",
    ):
        portable.validate_referee_decision(decision)


@pytest.mark.parametrize(
    ("legacy_kind", "message"),
    [
        ("selected_disposition", "legacy resolution domain"),
        ("selected_ledger_resolution", "legacy resolution domain"),
        ("replacement_entries", "legacy resolution domain"),
        ("source_ids", "only the supplied dispute"),
    ],
)
def test_portable_grade_referee_rejects_legacy_domain_and_external_sources(
    legacy_kind: str,
    message: str,
) -> None:
    portable = _load_portable()
    envelope = portable.freeze_case(_case_payload(), seed_hex="0" * 64)
    responses = _scripted_payloads()
    sealed = portable.seal_ledger(
        envelope,
        responses[1]["payload"],
        responses[2]["payload"],
        None,
    )
    first = _grade_with_evidence(portable, envelope, sealed)
    second = copy.deepcopy(first)
    second["request_fingerprint"] = "f" * 64
    second["entry_grades"][0]["disposition"] = "PARTIAL"
    second["entry_grades"][0]["rationale"] = "The report covers only part of the duty."
    dispute = portable.material_disputes(sealed, first, second)[0]
    legacy_fields: dict[str, Any] = {
        "selected_disposition": {"selected_disposition": "PARTIAL"},
        "selected_ledger_resolution": {"selected_ledger_resolution": "accept_a"},
        "replacement_entries": {
            "replacement_entries": [sealed["ledger"]["entries"][0]]
        },
        "source_ids": {"source_ids": ["synthetic-rule-1-source"]},
    }[legacy_kind]
    decision = {
        "dispute_id": dispute["dispute_id"],
        "selected_grade_resolution": "accept_grader_1",
        "grade_dispute_fingerprint": portable._model_fingerprint(dispute),
        "rationale": "The first grade is better supported by the supplied packet.",
        **legacy_fields,
    }

    with pytest.raises(portable.EvaluationInconclusiveError, match=message):
        portable.resolve_grades(sealed, first, second, [decision])


def test_portable_grade_referee_replacement_matches_dispute_invariants() -> None:
    """Portable referees must not rewrite the kind, subject, or weight of a dispute."""
    portable = _load_portable()
    envelope = portable.freeze_case(_case_payload(), seed_hex="0" * 64)
    responses = _scripted_payloads()
    sealed = portable.seal_ledger(
        envelope,
        responses[1]["payload"],
        responses[2]["payload"],
        None,
    )
    first = _grade_with_evidence(portable, envelope, sealed)
    second = copy.deepcopy(first)
    second["request_fingerprint"] = "f" * 64
    second["out_of_ledger_claims"] = []
    claim_dispute = next(
        dispute
        for dispute in portable.material_disputes(sealed, first, second)
        if dispute["kind"] == "out_of_ledger_claim"
    )

    def decision(replacement: dict[str, Any]) -> dict[str, Any]:
        return {
            "dispute_id": claim_dispute["dispute_id"],
            "selected_grade_resolution": "replace",
            "grade_dispute_fingerprint": portable._model_fingerprint(claim_dispute),
            "replacement_grade_alternative": replacement,
            "rationale": "The referee supplied a replacement for the exact dispute.",
        }

    wrong_kind = {
        "request_fingerprint": "c" * 64,
        "entry_grade": copy.deepcopy(first["entry_grades"][0]),
    }
    wrong_identity = copy.deepcopy(claim_dispute["grader_1"])
    wrong_identity["request_fingerprint"] = "c" * 64
    wrong_identity["out_of_ledger_claim"]["claim_text"] = (
        "An unrelated status proposition that would change the scored evidence."
    )
    understated = copy.deepcopy(claim_dispute["grader_1"])
    understated["request_fingerprint"] = "d" * 64
    understated["out_of_ledger_claim"]["materiality"] = "supporting"

    for replacement, message in (
        (wrong_kind, "replacement kind"),
        (wrong_identity, "claim identity"),
        (understated, "understate materiality"),
    ):
        with pytest.raises(portable.EvaluationInconclusiveError, match=message):
            portable.resolve_grades(sealed, first, second, [decision(replacement)])

    absence = {
        "request_fingerprint": "e" * 64,
        "absent_claim": True,
    }
    resolved = portable.resolve_grades(sealed, first, second, [decision(absence)])
    assert resolved["grade"]["out_of_ledger_claims"] == []


def test_portable_grade_referee_replacement_matches_entry_and_narrative_subjects() -> None:
    portable = _load_portable()
    envelope = portable.freeze_case(_case_payload(), seed_hex="0" * 64)
    responses = _scripted_payloads()
    sealed = portable.seal_ledger(
        envelope,
        responses[1]["payload"],
        responses[2]["payload"],
        None,
    )
    first = _grade_with_evidence(portable, envelope, sealed)

    entry_second = copy.deepcopy(first)
    entry_second["request_fingerprint"] = "f" * 64
    entry_second["entry_grades"][0]["disposition"] = "PARTIAL"
    entry_dispute = next(
        dispute
        for dispute in portable.material_disputes(sealed, first, entry_second)
        if dispute["kind"] == "entry_grade"
    )
    wrong_entry = copy.deepcopy(entry_dispute["grader_1"])
    wrong_entry["request_fingerprint"] = "c" * 64
    wrong_entry["entry_grade"]["ledger_id"] = "different-ledger-entry"
    entry_decision = {
        "dispute_id": entry_dispute["dispute_id"],
        "selected_grade_resolution": "replace",
        "grade_dispute_fingerprint": portable._model_fingerprint(entry_dispute),
        "replacement_grade_alternative": wrong_entry,
        "rationale": "The referee supplied an entry replacement.",
    }
    with pytest.raises(portable.EvaluationInconclusiveError, match="entry subject"):
        portable.resolve_grades(sealed, first, entry_second, [entry_decision])

    narrative_second = copy.deepcopy(first)
    narrative_second["request_fingerprint"] = "e" * 64
    narrative_second["narrative_scores"][0]["score"] = 3
    narrative_dispute = next(
        dispute
        for dispute in portable.material_disputes(sealed, first, narrative_second)
        if dispute["kind"] == "narrative_score"
    )
    wrong_narrative = copy.deepcopy(narrative_dispute["grader_1"])
    wrong_narrative["request_fingerprint"] = "d" * 64
    wrong_narrative["narrative_score"]["dimension"] = "scanability"
    narrative_decision = {
        "dispute_id": narrative_dispute["dispute_id"],
        "selected_grade_resolution": "replace",
        "grade_dispute_fingerprint": portable._model_fingerprint(narrative_dispute),
        "replacement_grade_alternative": wrong_narrative,
        "rationale": "The referee supplied a narrative replacement.",
    }
    with pytest.raises(portable.EvaluationInconclusiveError, match="narrative subject"):
        portable.resolve_grades(sealed, first, narrative_second, [narrative_decision])


@pytest.mark.parametrize(
    "disposition",
    ["COMPLETE", "PARTIAL", "MISSING", "OVERSTATED", "CONTRADICTED", "NOT_APPLICABLE"],
)
def test_portable_rebound_resolved_grade_rejects_nonunsupported_absence(
    disposition: str,
) -> None:
    portable = _load_portable()
    envelope = portable.freeze_case(_case_payload(), seed_hex="0" * 64)
    responses = _scripted_payloads()
    sealed = portable.seal_ledger(
        envelope,
        responses[1]["payload"],
        responses[2]["payload"],
        None,
    )
    first = _grade_with_evidence(portable, envelope, sealed)
    second = copy.deepcopy(first)
    second["request_fingerprint"] = "f" * 64
    resolved = portable.resolve_grades(sealed, first, second)

    def rebound(value: object) -> None:
        if isinstance(value, dict):
            if value.get("disposition") == "COMPLETE" and "evidence_basis" in value:
                value["disposition"] = disposition
                value["evidence_basis"] = "closed_universe_absence"
                value["evidence_spans"] = []
            for child in value.values():
                rebound(child)
        elif isinstance(value, list):
            for child in value:
                rebound(child)

    rebound(resolved)
    resolution_payload = {
        key: resolved[key]
        for key in (
            "grade",
            "audit",
            "original_grader_1",
            "original_grader_2",
            "referee_decisions",
        )
    }
    resolved["resolution_fingerprint"] = hashlib.sha256(
        portable.canonical_json_bytes(resolution_payload)
    ).hexdigest()
    checks = portable._derive_deterministic_checks(
        portable._candidate_for_label(envelope, "A"), "A"
    )

    with pytest.raises(
        portable.PortableEvaluationInputError,
        match="valid only for the UNSUPPORTED",
    ):
        portable.score_report(
            sealed,
            resolved,
            checks,
            source_record=portable.build_admission_packet(envelope)["payload"],
        )


def test_report_referee_packet_is_dispute_scoped_label_free_and_self_contained() -> None:
    """A fresh report referee must receive one complete dispute and no report label."""
    portable = _load_portable()
    envelope = portable.freeze_case(_case_payload(), seed_hex="0" * 64)
    responses = _scripted_payloads()
    sealed = portable.seal_ledger(
        envelope,
        responses[1]["payload"],
        responses[2]["payload"],
        None,
    )
    report_passage = "A covered operator must file a registry notice within 10 days"
    first = {
        "request_fingerprint": "1" * 64,
        "entry_grade": {
            "ledger_id": "file-notice",
            "disposition": "COMPLETE",
            "report_location": "paragraph 1",
            "report_passage": report_passage,
            "finding_codes": [],
            "rationale": "The complete filing duty appears in the passage.",
        },
        "out_of_ledger_claim": None,
        "narrative_score": None,
        "absent_claim": False,
    }
    second = copy.deepcopy(first)
    second["request_fingerprint"] = "2" * 64
    second["entry_grade"]["disposition"] = "PARTIAL"
    second["entry_grade"]["rationale"] = "The passage omits part of the filing duty."
    dispute = {
        "dispute_id": "grade-entry-file-notice",
        "anonymous_label": "A",
        "ledger_fingerprint": sealed["ledger_fingerprint"],
        "kind": "entry_grade",
        "subject_id": "file-notice",
        "materiality": "critical",
        "grader_1": first,
        "grader_2": second,
        "rationale": "The blind graders disagree on the entry disposition.",
    }
    legal_hash = hashlib.sha256(portable.canonical_json_bytes(sealed)).hexdigest()

    request = portable._report_referee_request(envelope, sealed, dispute, legal_hash)
    core_envelope = freeze_core(_core_case_from_payload(_case_payload()), seed_hex="0" * 64)
    core_request = core_workflow._report_referee_request(
        core_envelope,
        SealedLedger.model_validate(sealed),
        GradeDispute.model_validate(dispute),
        legal_ledger_hash=legal_hash,
    ).model_dump(mode="json")
    serialized = json.dumps(request, sort_keys=True)

    assert portable.canonical_json_bytes(request) == canonical_json_bytes(core_request)
    assert "anonymous_label" not in serialized
    assert "candidate_id" not in serialized
    assert request["payload"]["anonymous_passages"] == [report_passage]
    assert request["payload"]["relevant_context"]["ledger_entries"][0][
        "ledger_id"
    ] == "file-notice"
    assert request["payload"]["source_spans"]
    assert request["payload"]["dispute"]["grader_1"]["entry_grade"]["rationale"]
    assert request["payload"]["dispute"]["grader_2"]["entry_grade"]["rationale"]
    assert set(request["payload"]["alternative_meanings"]) == {
        "accept_grader_1",
        "accept_grader_2",
        "replace",
    }
    assert "Do not set selected_disposition" in request["system_instructions"]
    assert "source_ids" in request["system_instructions"]
    assert "closed-record limitation" in request["system_instructions"]
    assert "not an affirmative out-of-ledger claim" in request["system_instructions"]
    assert request["safe_metadata"]["grade_dispute_fingerprint"] == portable._model_fingerprint(
        dispute
    )
    assert request["request_fingerprint"] == (
        "96b4f9159549996b1488bb10132da4905a18c0b47b16989fd70993e854b39612"
    )
    assert hashlib.sha256(portable.canonical_json_bytes(request)).hexdigest() == (
        "dcacec8e3117c79ca5db1b66420ceed9518c3de0b694d6f8c9115d7542b2cc61"
    )
    portable._verify_request_noninterference(request, envelope["case"])


@pytest.mark.parametrize(
    "passage",
    [
        "## Key Requirements",
        "| Duty | Timing |\n| --- | --- |",
    ],
)
def test_narrative_referee_expands_heading_and_table_snippets_to_complete_h2_section(
    passage: str,
) -> None:
    """Removing H2 expansion would again leave the referee with a fragment."""
    expected_section = (
        "## Key Requirements\n\n"
        "| Duty | Timing |\n"
        "| --- | --- |\n"
        "| File notice | 10 days |\n\n"
        "The exception applies during an emergency.\n\n"
    )
    report = (
        "# Compliance Brief\n\n"
        "## Executive Summary\n\nSummary.\n\n"
        f"{expected_section}"
        "## Penalties and Enforcement\n\nA violation carries a penalty.\n"
    )

    request, _ = _referee_requests_for_report(
        report,
        dimension="key_requirements",
        first_passage=passage,
    )

    assert request["payload"]["anonymous_passages"] == [expected_section]
    assert request["payload"]["dispute"]["grader_1"]["narrative_score"][
        "report_passage"
    ] == passage


def test_narrative_referee_unions_sections_in_report_order_and_deduplicates_repeats() -> None:
    """Changing union ordering or retaining duplicate sections would bloat the packet."""
    requirements = "## Key Requirements\n\nRepeated duty.\nAnother duty.\n\n"
    penalties = "## Penalties and Enforcement\n\nPenalty consequence.\n\n"
    report = f"# Brief\n\n{requirements}{penalties}## Implementation Workplan\n\nAct.\n"

    request, _ = _referee_requests_for_report(
        report,
        dimension="key_requirements",
        first_passage="Penalty consequence.",
        second_passage="Repeated duty.",
    )
    assert request["payload"]["anonymous_passages"] == [requirements, penalties]

    repeated, _ = _referee_requests_for_report(
        report,
        dimension="key_requirements",
        first_passage="Repeated duty.",
        second_passage="Repeated duty.",
    )
    assert repeated["payload"]["anonymous_passages"] == [requirements]


@pytest.mark.parametrize(
    "dimension",
    [
        "regulatory_walk",
        "qualification_placement",
        "requirements_workplan_boundary",
        "scanability",
    ],
)
def test_workflow_narrative_dimensions_receive_complete_anonymous_report(
    dimension: str,
) -> None:
    """Report-wide rubric dimensions must not be decided from one grader snippet."""
    report = (
        "# Brief\n\n## Scope\n\nCovered operators.\n\n"
        "## Key Requirements\n\nFile notice.\n\n"
        "## Implementation Workplan\n\nAssign an owner.\n"
    )

    request, _ = _referee_requests_for_report(
        report,
        dimension=dimension,
        first_passage="File notice.",
    )

    assert request["payload"]["anonymous_passages"] == [report]
    assert "complete anonymous report" in request["system_instructions"]


def test_narrative_referee_preserves_crlf_section_bytes() -> None:
    """Normalizing CRLF would break the exact report-byte evidence contract."""
    expected_section = "## Key Requirements\r\n\r\nFile notice.\r\n\r\n"
    report = (
        "# Brief\r\n\r\n"
        f"{expected_section}"
        "## Penalties and Enforcement\r\n\r\nPenalty.\r\n"
    )

    request, _ = _referee_requests_for_report(
        report,
        dimension="key_requirements",
        first_passage="File notice.",
    )

    assert request["payload"]["anonymous_passages"] == [expected_section]
    assert request["payload"]["anonymous_passages"][0].encode() == expected_section.encode()


def test_narrative_referee_ignores_h2_like_lines_inside_fenced_code() -> None:
    """Treating a fenced pseudo-heading as H2 would truncate the enclosing section."""
    expected_section = (
        "## Key Requirements\n\n"
        "Before fence.\n\n"
        "```text\n"
        "## Not A Section\n"
        "example only\n"
        "```\n\n"
        "After fence.\n\n"
    )
    report = f"# Brief\n\n{expected_section}## Penalties\n\nPenalty.\n"

    request, _ = _referee_requests_for_report(
        report,
        dimension="key_requirements",
        first_passage="After fence.",
    )

    assert request["payload"]["anonymous_passages"] == [expected_section]


@pytest.mark.parametrize(
    ("report", "passage"),
    [
        (
            "# Brief\n\n## First\n\nRepeated rule.\n\n## Second\n\nRepeated rule.\n",
            "Repeated rule.",
        ),
        (
            "# Brief\n\nUnsectioned summary.\n\n## Requirements\n\nDuty.\n",
            "Unsectioned summary.",
        ),
        (
            "# Brief\n\n## Requirements\n\nDuty.\n\n## Penalties\n\nPenalty.\n",
            "Duty.\n\n## Penalties\n\nPenalty.",
        ),
    ],
)
def test_narrative_referee_falls_back_to_full_report_when_section_is_not_unique(
    report: str,
    passage: str,
) -> None:
    """Guessing at absent, boundary-spanning, or ambiguous sections is unsafe."""
    request, _ = _referee_requests_for_report(
        report,
        dimension="key_requirements",
        first_passage=passage,
    )

    assert request["payload"]["anonymous_passages"] == [report]


def test_portable_admission_packet_exposes_exact_codes_and_rejects_aliases() -> None:
    portable = _load_portable()
    envelope = portable.freeze_case(_case_payload(), seed_hex="0" * 64)
    packet = portable.build_admission_packet(envelope)
    required_codes = {
        "AUTHORITY_ALIGNMENT",
        "OPERATIVE_TEXT",
        "CURRENTNESS_EVIDENCE",
        "LANGUAGE_RESOLUTION",
        "SOURCE_PARITY",
    }

    assert set(
        packet["json_schema"]["$defs"]["AdmissionCheck"]["properties"]["code"][
            "enum"
        ]
    ) == required_codes
    assert all(code in packet["system_instructions"] for code in required_codes)
    judgment = copy.deepcopy(_scripted_payloads()[0]["payload"])
    judgment["checks"][0]["code"] = "REQUESTED_AUTHORITY_COVERAGE"
    with pytest.raises(portable.PortableEvaluationInputError, match="code"):
        portable._validate_admission_judgment(judgment)


@pytest.mark.parametrize("source_ids", [[], ["invented-source"]])
def test_portable_admission_rejects_satisfied_checks_without_known_source_support(
    source_ids: list[str],
) -> None:
    """Portable admission must enforce the same source-support boundary as core."""
    portable = _load_portable()
    envelope = portable.freeze_case(_case_payload(), seed_hex="0" * 64)
    judgment = copy.deepcopy(_scripted_payloads()[0]["payload"])
    judgment["request_fingerprint"] = portable.build_admission_packet(envelope)[
        "request_fingerprint"
    ]
    judgment["checks"][0]["source_ids"] = source_ids

    with pytest.raises(portable.PortableEvaluationInputError, match="supporting source_ids"):
        portable.adjudicate_admission(envelope, judgment)


def test_ledger_referee_helper_rejects_structural_candidate_contamination() -> None:
    portable = _load_portable()
    contaminated = {
        "operation": "referee",
        "safe_metadata": {
            "record_scope": "source-only-dispute",
            "referee_scope": "ledger",
        },
        "payload": {
            "dispute": {"candidate_id": "leaked-candidate"},
            "relevant_entries": [],
        },
    }
    with pytest.raises(portable.EvaluationIntegrityError, match="source-only"):
        portable._verify_request_noninterference(contaminated, _case_payload())


def test_ledger_referee_packet_is_self_contained_and_matches_portable() -> None:
    """Fresh full and portable referees need identical evidence and choice semantics."""
    portable = _load_portable()
    case_payload = _case_payload()
    core_envelope = freeze_core(_core_case_from_payload(case_payload), seed_hex="0" * 64)
    portable_envelope = portable.freeze_case(case_payload, seed_hex="0" * 64)
    ledger_payload = copy.deepcopy(_scripted_payloads()[1]["payload"])
    dispute_payload = {
        "dispute_id": "file-notice-materiality",
        "action": "materiality",
        "target_ledger_ids": ["file-notice"],
        "proposed_entries": [],
        "materiality": "critical",
        "rationale": "Materiality needs an independent source-grounded decision.",
    }

    core_request = ledger_referee_request_core(
        core_envelope,
        LegalLedger.model_validate(ledger_payload),
        LedgerDispute.model_validate(dispute_payload),
    ).model_dump(mode="json")
    portable_request = portable._ledger_referee_request(
        portable_envelope,
        ledger_payload,
        dispute_payload,
    )

    assert core_request == portable_request
    assert core_request["payload"]["resolution_contract"] == {
        "accept_a": "keep the repaired ledger unchanged for this dispute",
        "accept_b": "apply the supplied audit dispute to the repaired ledger",
    }
    assert core_request["payload"]["source_record"]["sources"]
    assert core_request["payload"]["source_spans"]


def test_audit_and_repair_ledger_invariant_contract_packets_match_portable() -> None:
    """Full and portable source-only roles must receive byte-equivalent audit contracts."""
    portable = _load_portable()
    case_payload = _case_payload()
    core_envelope = freeze_core(_core_case_from_payload(case_payload), seed_hex="0" * 64)
    portable_envelope = portable.freeze_case(case_payload, seed_hex="0" * 64)
    ledger_payload = copy.deepcopy(_scripted_payloads()[1]["payload"])
    core_ledger = LegalLedger.model_validate(ledger_payload)
    audit_payload = {
        "request_fingerprint": "a" * 64,
        "complete": True,
        "disputes": [
            {
                "dispute_id": "missing-duty",
                "action": "add",
                "target_ledger_ids": [],
                "proposed_entries": [],
                "materiality": "supporting",
                "rationale": (
                    "synthetic-rule-1-source is missing covered operator registry notice "
                    "requirement."
                ),
            }
        ],
    }
    core_audit = LedgerAudit.model_validate(audit_payload)

    full_audit_request = audit_ledger_request_core(core_envelope, core_ledger).model_dump(
        mode="json"
    )
    portable_audit_request = portable._audit_ledger_request(portable_envelope, ledger_payload)
    full_repair_request = repair_ledger_request_core(
        core_envelope, core_ledger, core_audit
    ).model_dump(mode="json")
    portable_repair_request = portable._repair_ledger_request(
        portable_envelope, ledger_payload, audit_payload
    )

    assert full_audit_request == portable_audit_request
    assert full_repair_request == portable_repair_request
    assert full_audit_request["payload"]["ledger_invariant_contract"] == (
        ledger_invariant_contract()
    )
    assert full_repair_request["payload"]["ledger_invariant_contract"] == (
        ledger_invariant_contract()
    )
    assert (
        full_audit_request["payload"]["audit_action_contract"]
        == full_repair_request["payload"]["audit_action_contract"]
    )
    assert full_audit_request["payload"]["audit_action_contract"][
        "initial_audit_findings"
    ]["action_payloads"]["add"]["ledger_id_rule"] == (
        "new_relative_to_proposed_ledger"
    )
    portable_findings = portable.validate_ledger_audit_findings(
        audit_payload, envelope=portable_envelope, proposed_ledger=ledger_payload
    )
    assert portable_findings["disputes"] == [
        finding.model_dump(mode="json")
        for finding in ledger_findings_core(core_envelope, core_ledger, core_audit)
    ]
    with pytest.raises(portable.PortableEvaluationInputError, match="action payload"):
        portable.validate_ledger_audit(audit_payload)
    with pytest.raises(LedgerInconclusiveErrorCore, match="add"):
        ledger_disputes_core(core_audit)


def test_build_ledger_invariant_contract_packet_matches_portable() -> None:
    """Fresh full and portable ledger builders must receive identical invariants."""
    portable = _load_portable()
    case_payload = _case_payload()
    core_envelope = freeze_core(_core_case_from_payload(case_payload), seed_hex="0" * 64)
    portable_envelope = portable.freeze_case(case_payload, seed_hex="0" * 64)

    full_request = build_ledger_request_core(core_envelope).model_dump(mode="json")
    portable_request = portable._build_ledger_request(portable_envelope)

    assert full_request == portable_request
    assert full_request["payload"]["ledger_invariant_contract"] == (
        ledger_invariant_contract()
    )


def test_portable_ledger_invariant_contract_returns_fresh_json() -> None:
    """Portable callers must not share mutable nested invariant state."""
    portable = _load_portable()

    mutated = portable._ledger_invariant_contract()
    mutated["relationships"]["trigger_link_categories"].append("remedy")

    assert portable._ledger_invariant_contract() == ledger_invariant_contract()


@pytest.mark.parametrize(
    ("action", "targets", "proposed_count", "valid"),
    [
        ("add", [], 0, True),
        ("add", [], 1, True),
        ("add", ["file-notice"], 0, False),
        ("edit", ["file-notice"], 0, True),
        ("edit", ["file-notice"], 1, True),
        ("edit", [], 0, False),
        ("delete", ["file-notice"], 0, True),
        ("delete", ["file-notice"], 1, False),
        ("split", ["file-notice"], 0, True),
        ("split", ["unknown-ledger-id"], 0, False),
        ("split", ["file-notice"], 2, True),
        ("split", ["file-notice"], 1, False),
        ("merge", ["file-notice", "retain-proof"], 0, True),
        ("merge", ["file-notice", "retain-proof"], 1, True),
        ("merge", ["file-notice"], 0, False),
        ("materiality", ["file-notice"], 0, True),
        ("materiality", [], 0, False),
        ("materiality", ["file-notice"], 1, False),
    ],
)
def test_initial_finding_action_validation_matches_core_and_portable(
    action: str,
    targets: list[str],
    proposed_count: int,
    valid: bool,
) -> None:
    portable = _load_portable()
    envelope_payload = portable.freeze_case(_case_payload(), seed_hex="0" * 64)
    ledger_payload = copy.deepcopy(_scripted_payloads()[1]["payload"])
    core_envelope = freeze_core(_core_case_from_payload(_case_payload()), seed_hex="0" * 64)
    core_ledger = LegalLedger.model_validate(ledger_payload)
    proposed = copy.deepcopy(ledger_payload["entries"][:proposed_count])
    if action == "add" and proposed:
        proposed[0]["ledger_id"] = "added-entry"
    if action == "edit" and proposed:
        proposed[0]["ledger_id"] = targets[0]
    payload = {
        "request_fingerprint": "a" * 64,
        "complete": True,
        "disputes": [
            {
                "dispute_id": "finding",
                "action": action,
                "target_ledger_ids": targets,
                "proposed_entries": proposed,
                "materiality": "supporting",
                "rationale": (
                    "synthetic-rule-1-source is missing covered operator registry notice "
                    "requirement."
                ),
            }
        ],
    }
    core_audit = LedgerAudit.model_validate(payload)

    if valid:
        assert portable.validate_ledger_audit_findings(
            payload, envelope=envelope_payload, proposed_ledger=ledger_payload
        )["disputes"] == [
            finding.model_dump(mode="json")
            for finding in ledger_findings_core(core_envelope, core_ledger, core_audit)
        ]
    else:
        with pytest.raises(portable.PortableEvaluationInputError):
            portable.validate_ledger_audit_findings(
                payload, envelope=envelope_payload, proposed_ledger=ledger_payload
            )
        with pytest.raises(LedgerInconclusiveErrorCore):
            ledger_findings_core(core_envelope, core_ledger, core_audit)


def test_initial_add_reused_id_rejection_matches_core_and_portable() -> None:
    portable = _load_portable()
    case_payload = _case_payload()
    portable_envelope = portable.freeze_case(case_payload, seed_hex="0" * 64)
    core_envelope = freeze_core(_core_case_from_payload(case_payload), seed_hex="0" * 64)
    ledger_payload = copy.deepcopy(_scripted_payloads()[1]["payload"])
    payload = {
        "request_fingerprint": "a" * 64,
        "complete": True,
        "disputes": [
            {
                "dispute_id": "reused-add-id",
                "action": "add",
                "target_ledger_ids": [],
                "proposed_entries": [copy.deepcopy(ledger_payload["entries"][0])],
                "materiality": "supporting",
                "rationale": "The source record needs a ledger correction.",
            }
        ],
    }

    with pytest.raises(
        portable.PortableEvaluationInputError,
        match="add initial ledger finding must use new ledger IDs",
    ) as portable_error:
        portable.validate_ledger_audit_findings(
            payload,
            envelope=portable_envelope,
            proposed_ledger=ledger_payload,
        )
    with pytest.raises(
        LedgerInconclusiveErrorCore,
        match="add initial ledger finding must use new ledger IDs",
    ) as core_error:
        ledger_findings_core(
            core_envelope,
            LegalLedger.model_validate(ledger_payload),
            LedgerAudit.model_validate(payload),
        )
    assert str(portable_error.value) == str(core_error.value)


@pytest.mark.parametrize(
    ("rationale", "valid"),
    [
        ("This finding is very important indeed.", False),
        ("The source record needs a ledger correction.", True),
        ("The notice duty combines distinct filing and timing propositions.", True),
    ],
)
def test_initial_finding_rationale_validation_matches_core_and_portable(
    rationale: str, valid: bool
) -> None:
    portable = _load_portable()
    envelope_payload = portable.freeze_case(_case_payload(), seed_hex="0" * 64)
    ledger_payload = copy.deepcopy(_scripted_payloads()[1]["payload"])
    core_envelope = freeze_core(_core_case_from_payload(_case_payload()), seed_hex="0" * 64)
    core_ledger = LegalLedger.model_validate(ledger_payload)
    proposed = copy.deepcopy(ledger_payload["entries"][:1])
    proposed[0]["ledger_id"] = "added-entry"
    payload = {
        "request_fingerprint": "a" * 64,
        "complete": True,
        "disputes": [
            {
                "dispute_id": "generic",
                "action": "add",
                "target_ledger_ids": [],
                "proposed_entries": proposed,
                "materiality": "supporting",
                "rationale": rationale,
            }
        ],
    }

    if valid:
        assert portable.validate_ledger_audit_findings(
            payload, envelope=envelope_payload, proposed_ledger=ledger_payload
        )["disputes"] == [
            finding.model_dump(mode="json")
            for finding in ledger_findings_core(
                core_envelope,
                core_ledger,
                LedgerAudit.model_validate(payload),
            )
        ]
    else:
        with pytest.raises(portable.PortableEvaluationInputError, match="concrete rationale"):
            portable.validate_ledger_audit_findings(
                payload, envelope=envelope_payload, proposed_ledger=ledger_payload
            )
        with pytest.raises(LedgerInconclusiveErrorCore, match="concrete rationale"):
            ledger_findings_core(
                core_envelope,
                core_ledger,
                LedgerAudit.model_validate(payload),
            )


@pytest.mark.parametrize(
    ("rationale", "valid"),
    [
        ("The case metadata needs a ledger correction.", False),
        ("The request fingerprint needs a ledger correction.", False),
        ("The response schema needs a ledger correction.", False),
        ("unknown-source is missing covered operator registry notice requirement.", False),
        (
            "synthetic-rule-1-source is missing covered operator registry notice requirement.",
            True,
        ),
        (
            "synthetic-rule-1-source is missing the requirement at Rule 1.",
            True,
        ),
        (
            "synthetic-rule-1-source is missing the requirement at rUlE 1.",
            True,
        ),
        (
            "synthetic-rule-1-source is missing the requirement at Rule 404.",
            False,
        ),
        (
            "synthetic-rule-1-source is missing covered operator registry notice "
            "requirement at Rule 404.",
            False,
        ),
    ],
)
def test_proposal_free_add_source_grounding_matches_core_and_portable(
    rationale: str, valid: bool
) -> None:
    portable = _load_portable()
    envelope_payload = portable.freeze_case(_case_payload(), seed_hex="0" * 64)
    ledger_payload = copy.deepcopy(_scripted_payloads()[1]["payload"])
    core_envelope = freeze_core(_core_case_from_payload(_case_payload()), seed_hex="0" * 64)
    core_ledger = LegalLedger.model_validate(ledger_payload)
    payload = {
        "request_fingerprint": "a" * 64,
        "complete": True,
        "disputes": [
            {
                "dispute_id": "source-grounding",
                "action": "add",
                "target_ledger_ids": [],
                "proposed_entries": [],
                "materiality": "supporting",
                "rationale": rationale,
            }
        ],
    }
    core_audit = LedgerAudit.model_validate(payload)

    if valid:
        assert portable.validate_ledger_audit_findings(
            payload, envelope=envelope_payload, proposed_ledger=ledger_payload
        )["disputes"] == [
            finding.model_dump(mode="json")
            for finding in ledger_findings_core(core_envelope, core_ledger, core_audit)
        ]
    else:
        with pytest.raises(portable.PortableEvaluationInputError, match="source-grounded"):
            portable.validate_ledger_audit_findings(
                payload, envelope=envelope_payload, proposed_ledger=ledger_payload
            )
        with pytest.raises(LedgerInconclusiveErrorCore, match="source-grounded"):
            ledger_findings_core(core_envelope, core_ledger, core_audit)


@pytest.mark.parametrize(
    ("rationale", "valid"),
    [
        (
            "synthetic-rule-1-source is missing covered operator registry notice "
            "requirement at Rule 1 and Section 2.",
            True,
        ),
        (
            "synthetic-rule-1-source is missing covered operator registry notice "
            "requirement at Rule 1 and Section 999.",
            False,
        ),
    ],
)
def test_multiple_locator_grounding_fails_closed_with_full_portable_parity(
    rationale: str, valid: bool
) -> None:
    portable = _load_portable()
    case_payload = _case_payload()
    case_payload["sources"][0]["title"] = "Synthetic Rule 1 Section 2"
    envelope_payload = portable.freeze_case(case_payload, seed_hex="0" * 64)
    ledger_payload = copy.deepcopy(_scripted_payloads()[1]["payload"])
    ledger_payload["case_fingerprint"] = portable.build_admission_packet(envelope_payload)[
        "safe_metadata"
    ]["source_record_fingerprint"]
    payload = {
        "request_fingerprint": "a" * 64,
        "complete": True,
        "disputes": [
            {
                "dispute_id": "multiple-locators",
                "action": "add",
                "target_ledger_ids": [],
                "proposed_entries": [],
                "materiality": "supporting",
                "rationale": rationale,
            }
        ],
    }
    core_envelope = freeze_core(_core_case_from_payload(case_payload), seed_hex="0" * 64)
    core_ledger = LegalLedger.model_validate(ledger_payload)
    core_audit = LedgerAudit.model_validate(payload)

    if valid:
        assert portable.validate_ledger_audit_findings(
            payload, envelope=envelope_payload, proposed_ledger=ledger_payload
        )["disputes"] == [
            finding.model_dump(mode="json")
            for finding in ledger_findings_core(core_envelope, core_ledger, core_audit)
        ]
    else:
        with pytest.raises(portable.PortableEvaluationInputError, match="source-grounded"):
            portable.validate_ledger_audit_findings(
                payload, envelope=envelope_payload, proposed_ledger=ledger_payload
            )
        with pytest.raises(LedgerInconclusiveErrorCore, match="source-grounded"):
            ledger_findings_core(core_envelope, core_ledger, core_audit)


@pytest.mark.parametrize(
    ("defect", "issue_code"),
    [
        ("unknown-source", "LEDGER_CITATION_SOURCE_UNKNOWN"),
        ("wrong-quote", "LEDGER_QUOTE_MISMATCH"),
        ("out-of-range", "LEDGER_QUOTE_MISMATCH"),
        ("commentary-only", "LEDGER_COMMENTARY_ONLY_SUPPORT"),
    ],
)
def test_initial_proposed_entry_exact_source_validation_matches_core_and_portable(
    defect: str, issue_code: str
) -> None:
    portable = _load_portable()
    case_payload = _case_payload()
    if defect == "commentary-only":
        commentary = copy.deepcopy(case_payload["sources"][0])
        commentary.update(
            {
                "source_id": "commentary-source",
                "source_role": "commentary_analysis",
                "source_quality": "secondary",
            }
        )
        case_payload["sources"].append(commentary)
        case_payload["requested_authorities"][0]["source_ids"].append(
            commentary["source_id"]
        )
    envelope_payload = portable.freeze_case(case_payload, seed_hex="0" * 64)
    ledger_payload = copy.deepcopy(_scripted_payloads()[1]["payload"])
    ledger_payload["case_fingerprint"] = portable.build_admission_packet(envelope_payload)[
        "safe_metadata"
    ]["source_record_fingerprint"]
    proposed = copy.deepcopy(ledger_payload["entries"][0])
    proposed["ledger_id"] = "invalid-proposed"
    citation = proposed["citations"][0]
    if defect == "unknown-source":
        citation["source_id"] = "unknown-source"
    elif defect == "wrong-quote":
        citation["quote"] = "covered operator notice language"
    elif defect == "out-of-range":
        source_text = envelope_payload["case"]["sources"][0]["normalized_text"]
        citation.update(
            {
                "start_char": len(source_text) + 1,
                "end_char": len(source_text) + 2,
                "quote": "x",
            }
        )
    else:
        citation["source_id"] = "commentary-source"
    payload = {
        "request_fingerprint": "a" * 64,
        "complete": True,
        "disputes": [
            {
                "dispute_id": "invalid-proposed-finding",
                "action": "add",
                "target_ledger_ids": [],
                "proposed_entries": [proposed],
                "materiality": "supporting",
                "rationale": "The source record needs a ledger correction.",
            }
        ],
    }
    core_envelope = freeze_core(_core_case_from_payload(case_payload), seed_hex="0" * 64)
    core_ledger = LegalLedger.model_validate(ledger_payload)
    core_audit = LedgerAudit.model_validate(payload)

    with pytest.raises(
        portable.PortableEvaluationInputError,
        match=rf"invalid-proposed-finding.*{issue_code}",
    ) as portable_error:
        portable.validate_ledger_audit_findings(
            payload, envelope=envelope_payload, proposed_ledger=ledger_payload
        )
    with pytest.raises(
        LedgerInconclusiveErrorCore,
        match=rf"invalid-proposed-finding.*{issue_code}",
    ) as core_error:
        ledger_findings_core(core_envelope, core_ledger, core_audit)
    assert str(portable_error.value) == str(core_error.value)


@pytest.mark.parametrize("candidate_id", ["a", "operator"])
def test_candidate_ids_inside_ordinary_source_values_match_core_packets(
    tmp_path: Path, candidate_id: str
) -> None:
    portable = _load_portable()
    case_payload = _case_payload()
    case_payload["candidates"][0]["candidate_id"] = candidate_id
    assert candidate_id.casefold() in case_payload["sources"][0]["normalized_text"].casefold()
    portable_run = tmp_path / "portable"
    core_run = tmp_path / "core"
    portable.initialize_evaluation(case_payload, portable_run, seed_hex="0" * 64)
    initialize_core(_core_case_from_payload(case_payload), core_run, seed_hex="0" * 64)

    for index, scripted in enumerate(_scripted_payloads(), start=1):
        portable_request = portable.next_judge_request(portable_run)
        core_request = next_core(core_run)
        assert portable_request is not None and core_request is not None
        assert portable.canonical_json_bytes(portable_request) == portable.canonical_json_bytes(
            core_request.model_dump(mode="json")
        )
        response = _response(portable_request, scripted, index)
        portable.submit_judge_response(portable_run, response)
        submit_core(core_run, JudgeResponse.model_validate(response))
    assert portable.next_judge_request(portable_run) is None
    assert next_core(core_run) is None
    for artifact in GOLDEN_ARTIFACTS:
        assert (portable_run / artifact).read_bytes() == (core_run / artifact).read_bytes()
    assert portable.verify_evaluation_run(portable_run).valid


def test_cc0_golden_artifacts_are_byte_identical_to_core(tmp_path: Path) -> None:
    portable = _load_portable()
    core_run = tmp_path / "core"
    portable_run = tmp_path / "portable"
    _run_core(core_run)
    _run_portable(portable, portable_run)
    for artifact in GOLDEN_ARTIFACTS:
        assert (portable_run / artifact).read_bytes() == (core_run / artifact).read_bytes()


def test_renderer_rejects_incoherent_report_matrix_shapes(tmp_path: Path) -> None:
    portable = _load_portable()
    one_run = tmp_path / "one"
    _run_portable(portable, one_run)
    one = json.loads((one_run / "evaluation-result.json").read_text(encoding="utf-8"))

    a_with_b = copy.deepcopy(one)
    a_with_b["requirement_matrix"]["rows"][0]["report_b"] = {
        **copy.deepcopy(a_with_b["requirement_matrix"]["rows"][0]["report_a"]),
        "anonymous_label": "B",
    }
    b_only = copy.deepcopy(one)
    b_only["reports"][0]["anonymous_label"] = "B"
    non_admitted = copy.deepcopy(one)
    non_admitted["readiness"]["status"] = "INCONCLUSIVE"
    noncontiguous = copy.deepcopy(one)
    noncontiguous["requirement_matrix"]["rows"][0]["walk_order"] = 1

    for malformed in (a_with_b, b_only, non_admitted, noncontiguous):
        malformed["result_fingerprint"] = "0" * 64
        malformed["result_fingerprint"] = portable._model_fingerprint(
            malformed, exclude={"result_fingerprint"}
        )
        with pytest.raises(portable.EvaluationIntegrityError, match="malformed"):
            portable.render_evaluation_report(malformed)


@pytest.mark.parametrize(
    ("path", "value", "delete"),
    [
        (("rubric", "unexpected"), "value", False),
        (("rubric", "comparison_margin"), None, True),
        (("readiness", "issue_codes"), ["bad code"], False),
        (("reports", 0, "issue_codes"), ["bad code"], False),
        (("reports", 0, "blocking_codes"), ["bad code"], False),
        (("reports", 0, "critical_recall"), 1, False),
        (("reports", 0, "normalized_score"), True, False),
        (("reports", 0, "walk_minimum"), 4.0, False),
        (("rubric", "comparison_margin"), 5, False),
        (("requirement_matrix", "rows", 0, "citations", 0, "start_char"), False, False),
    ],
    ids=[
        "rubric-extra",
        "rubric-missing",
        "readiness-code",
        "report-issue-code",
        "report-blocking-code",
        "report-float-is-int",
        "report-float-is-bool",
        "walk-minimum-is-float",
        "rubric-float-is-int",
        "citation-int-is-bool",
    ],
)
def test_direct_result_validation_rejects_every_value_core_rejects(
    tmp_path: Path,
    path: tuple[str | int, ...],
    value: object,
    delete: bool,
) -> None:
    portable = _load_portable()
    portable_run = tmp_path / "portable"
    _run_differential(portable, _case_payload(), portable_run, tmp_path / "core-fixture")
    malformed = json.loads(
        (portable_run / "evaluation-result.json").read_text(encoding="utf-8")
    )
    target: Any = malformed
    for segment in path[:-1]:
        target = target[segment]
    final = path[-1]
    if delete:
        target.pop(final)
    else:
        target[final] = value
    _refingerprint_result(portable, malformed)

    with pytest.raises(attorney_artifacts.EvaluationIntegrityError):
        _render_core_result_payload(malformed)
    with pytest.raises(portable.EvaluationIntegrityError):
        portable.render_evaluation_report(malformed)


def test_portable_direct_renderer_requires_the_canonical_terminal_rubric(
    tmp_path: Path,
) -> None:
    portable = _load_portable()
    run = tmp_path / "run"
    _run_portable(portable, run)
    malformed = json.loads((run / "evaluation-result.json").read_text(encoding="utf-8"))
    malformed["rubric"]["comparison_margin"] = 6.0
    _refingerprint_result(portable, malformed)

    with pytest.raises(portable.EvaluationIntegrityError, match="malformed"):
        portable.render_evaluation_report(malformed)


def test_core_differential_vectors_cover_admission_ledger_resolution_and_score() -> None:
    portable = _load_portable()
    case_payload = _case_payload()
    core_case = _case_from_fixture(FIXTURE / "case.json", root=FIXTURE)
    portable_envelope = portable.freeze_case(case_payload, seed_hex="0" * 64)
    core_envelope = freeze_core(core_case, seed_hex="0" * 64)
    assert portable_envelope == core_envelope.model_dump(mode="json")
    assert portable.build_admission_packet(portable_envelope) == packet_core(
        core_envelope
    ).model_dump(mode="json")

    responses = _scripted_payloads()
    portable_readiness = portable.adjudicate_admission(portable_envelope, responses[0]["payload"])
    core_readiness = adjudicate_core(
        core_envelope,
        CaseAdmissionJudgment.model_validate(responses[0]["payload"], strict=True),
    )
    assert portable_readiness == core_readiness.model_dump(mode="json")

    portable_sealed = portable.seal_ledger(
        portable_envelope, responses[1]["payload"], responses[2]["payload"], None
    )
    core_sealed = seal_core(
        core_envelope,
        LegalLedger.model_validate(responses[1]["payload"]),
        LedgerAudit.model_validate(responses[2]["payload"]),
        None,
    )
    assert portable_sealed == core_sealed.model_dump(mode="json")

    portable_resolved = portable.resolve_grades(
        portable_sealed, responses[3]["payload"], responses[4]["payload"]
    )
    core_resolved = resolve_core(
        core_sealed,
        CandidateGrade.model_validate(responses[3]["payload"]),
        CandidateGrade.model_validate(responses[4]["payload"]),
        [],
    )
    checks = portable._derive_deterministic_checks(
        portable._candidate_for_label(portable_envelope, "A"), "A"
    )
    source_record = portable.build_admission_packet(portable_envelope)["payload"]
    assert portable.score_report(
        portable_sealed,
        portable_resolved,
        checks,
        source_record=source_record,
    ) == score_core(
        core_sealed,
        core_resolved,
        DeterministicChecks.model_validate(checks),
        source_record=source_record,
    ).model_dump(mode="json")


@pytest.mark.parametrize(
    "issue_code",
    [
        "AUTHORITY_MISMATCH",
        "OPERATIVE_TEXT_MISSING",
        "CURRENTNESS_EVIDENCE_INSUFFICIENT",
        "LANGUAGE_UNRESOLVED",
        "SOURCE_PARITY_UNPROVEN",
    ],
)
def test_material_admission_issue_codes_fail_closed(issue_code: str) -> None:
    portable = _load_portable()
    envelope = portable.freeze_case(_case_payload(), seed_hex="0" * 64)
    judgment = copy.deepcopy(_scripted_payloads()[0]["payload"])
    judgment["issues"] = [
        {
            "code": issue_code,
            "severity": "error",
            "message": "A material admission defect was found.",
            "related_ids": [],
        }
    ]
    readiness = portable.adjudicate_admission(envelope, judgment)
    assert readiness["status"] == "CASE_INVALID"
    assert readiness["issue_codes"] == [issue_code]


def test_portable_resolved_non_english_source_can_be_admitted() -> None:
    """Portable admission must defer language capability to the fresh judge check."""
    portable = _load_portable()
    case_payload = _case_payload()
    case_payload["sources"][0]["language"] = "fr"
    envelope = portable.freeze_case(case_payload, seed_hex="0" * 64)
    judgment = copy.deepcopy(_scripted_payloads()[0]["payload"])
    request = portable.build_admission_packet(envelope)
    judgment["request_fingerprint"] = request["request_fingerprint"]

    readiness = portable.adjudicate_admission(envelope, judgment)

    assert readiness["status"] == "ADMITTED"
    assert "LANGUAGE_UNRESOLVED" not in readiness["issue_codes"]


def test_portable_non_english_source_with_failed_language_resolution_is_invalid() -> None:
    portable = _load_portable()
    case_payload = _case_payload()
    case_payload["sources"][0]["language"] = "fr"
    envelope = portable.freeze_case(case_payload, seed_hex="0" * 64)
    judgment = copy.deepcopy(_scripted_payloads()[0]["payload"])
    request = portable.build_admission_packet(envelope)
    judgment["request_fingerprint"] = request["request_fingerprint"]
    language_check = next(
        check for check in judgment["checks"] if check["code"] == "LANGUAGE_RESOLUTION"
    )
    language_check["satisfied"] = False

    readiness = portable.adjudicate_admission(envelope, judgment)

    assert readiness["status"] == "CASE_INVALID"
    assert readiness["issue_codes"] == ["LANGUAGE_UNRESOLVED"]


@pytest.mark.parametrize(
    "disposition",
    [
        "COMPLETE",
        "PARTIAL",
        "MISSING",
        "OVERSTATED",
        "CONTRADICTED",
        "UNSUPPORTED",
        "NOT_APPLICABLE",
    ],
)
def test_scoring_disposition_vectors_match_core(disposition: str) -> None:
    portable = _load_portable()
    responses = _scripted_payloads()
    envelope = portable.freeze_case(_case_payload(), seed_hex="0" * 64)
    sealed = portable.seal_ledger(envelope, responses[1]["payload"], responses[2]["payload"], None)
    first = copy.deepcopy(responses[3]["payload"])
    second = copy.deepcopy(responses[4]["payload"])
    for grade in (first, second):
        grade["entry_grades"][0]["disposition"] = disposition
        grade["entry_grades"][0]["report_location"] = (
            None if disposition in {"MISSING", "NOT_APPLICABLE"} else "paragraph 1"
        )
        if disposition == "MISSING":
            grade["entry_grades"][0]["report_passage"] = None
    if disposition == "NOT_APPLICABLE":
        with pytest.raises(portable.EvaluationInconclusiveError):
            portable.resolve_grades(sealed, first, second)
        with pytest.raises(GradeInconclusiveError):
            resolve_core(
                SealedLedger.model_validate(sealed),
                CandidateGrade.model_validate(first),
                CandidateGrade.model_validate(second),
                [],
            )
        return
    resolved = portable.resolve_grades(sealed, first, second)
    checks = portable._derive_deterministic_checks(
        portable._candidate_for_label(envelope, "A"), "A"
    )
    source_record = portable.build_admission_packet(envelope)["payload"]
    portable_score = portable.score_report(
        sealed,
        resolved,
        checks,
        source_record=source_record,
    )

    core_sealed = SealedLedger.model_validate(sealed)
    core_resolved = resolve_core(
        core_sealed,
        CandidateGrade.model_validate(first),
        CandidateGrade.model_validate(second),
        [],
    )
    assert portable_score == score_core(
        core_sealed,
        core_resolved,
        DeterministicChecks.model_validate(checks),
        source_record=source_record,
    ).model_dump(mode="json")


def test_multi_code_finding_diagnostics_match_core_and_portable() -> None:
    portable = _load_portable()
    responses = _scripted_payloads()
    envelope = portable.freeze_case(_case_payload(), seed_hex="0" * 64)
    sealed = portable.seal_ledger(
        envelope,
        responses[1]["payload"],
        responses[2]["payload"],
        None,
    )
    grade = copy.deepcopy(responses[3]["payload"])
    finding = next(
        item for item in grade["entry_grades"] if item["ledger_id"] == "file-notice"
    )
    finding["disposition"] = "COMPLETE"
    finding["finding_codes"] = [
        "CRITICAL_LEDGER_ENTRY_MISSING",
        "MATERIAL_EXCEPTION_MISSING",
        "CONSEQUENCE_TRIGGER_DETACHED",
    ]

    portable_grade, portable_issues = portable.validate_grade(sealed, grade)
    portable_diagnostics = portable._grade_issue_diagnostics(
        sealed,
        portable_grade,
        portable_issues,
    )
    core_issues = validate_grade_core(
        SealedLedger.model_validate(sealed),
        CandidateGrade.model_validate(grade),
    )
    core_diagnostics = [f"{issue.code}: {issue.message}" for issue in core_issues]

    assert core_diagnostics == portable_diagnostics
    assert [
        message.split(" finding_code=", maxsplit=1)[1].split(" ", maxsplit=1)[0]
        for message in portable_diagnostics
    ] == finding["finding_codes"]
    assert all("ledger_id=file-notice" in message for message in portable_diagnostics)


def test_portable_invalid_finding_diagnostic_is_specific_and_anonymous_safe(
    tmp_path: Path,
) -> None:
    portable = _load_portable()
    run = tmp_path / "run"
    request = _advance_portable_to_first_grade(portable, run)
    payload = copy.deepcopy(_scripted_payloads()[3]["payload"])
    payload["request_fingerprint"] = request["request_fingerprint"]
    payload["anonymous_label"] = request["safe_metadata"]["anonymous_label"]
    payload["ledger_fingerprint"] = request["safe_metadata"][
        "legal_ledger_fingerprint"
    ]
    finding = next(
        item for item in payload["entry_grades"] if item["ledger_id"] == "file-notice"
    )
    finding["disposition"] = "PARTIAL"
    finding["finding_codes"] = ["MATERIAL_EXCEPTION_MISSING"]

    state = portable.submit_judge_response(
        run,
        _response(request, {"payload": payload}, 4),
    )
    diagnostics = json.loads(
        (run / "judge-diagnostics/grade-A-1-attempt-1.json").read_text(
            encoding="utf-8"
        )
    )
    message = diagnostics["issues"][0]["message"]

    assert state["attempt"] == 2
    assert "ledger_id=file-notice" in message
    assert "finding_code=MATERIAL_EXCEPTION_MISSING" in message
    assert (
        "allowed_context=disposition in [MISSING, PARTIAL]; category=exception; "
        "materiality in [critical, material]" in message
    )
    for forbidden in (
        "synthetic-harvest",
        "candidate_id",
        "mapping",
        payload["entry_grades"][0]["report_passage"],
    ):
        assert forbidden not in message


def test_portable_unknown_ledger_id_is_not_echoed_in_diagnostics(tmp_path: Path) -> None:
    portable = _load_portable()
    run = tmp_path / "run"
    request = _advance_portable_to_first_grade(portable, run)
    payload = copy.deepcopy(_scripted_payloads()[3]["payload"])
    payload["request_fingerprint"] = request["request_fingerprint"]
    payload["anonymous_label"] = request["safe_metadata"]["anonymous_label"]
    payload["ledger_fingerprint"] = request["safe_metadata"][
        "legal_ledger_fingerprint"
    ]
    payload["entry_grades"][0]["ledger_id"] = "synthetic-harvest"
    payload["entry_grades"][0]["finding_codes"] = ["MATERIAL_EXCEPTION_MISSING"]

    portable.submit_judge_response(
        run,
        _response(request, {"payload": payload}, 4),
    )
    diagnostics = json.loads(
        (run / "judge-diagnostics/grade-A-1-attempt-1.json").read_text(
            encoding="utf-8"
        )
    )

    assert "synthetic-harvest" not in diagnostics["issues"][0]["message"]


def test_multi_code_retry_diagnostics_and_hash_match_core_and_portable(
    tmp_path: Path,
) -> None:
    portable = _load_portable()
    case_payload = _case_payload()
    portable_run = tmp_path / "portable"
    core_run = tmp_path / "core"
    portable.initialize_evaluation(case_payload, portable_run, seed_hex="0" * 64)
    initialize_core(_core_case_from_payload(case_payload), core_run, seed_hex="0" * 64)
    for index, item in enumerate(_scripted_payloads()[:3], start=1):
        portable_request = portable.next_judge_request(portable_run)
        core_request = next_core(core_run)
        assert portable_request is not None and core_request is not None
        assert portable_request == core_request.model_dump(mode="json")
        payload = copy.deepcopy(item["payload"])
        if "request_fingerprint" in payload:
            payload["request_fingerprint"] = portable_request["request_fingerprint"]
        response = _response(portable_request, {"payload": payload}, index)
        portable.submit_judge_response(portable_run, response)
        submit_core(core_run, JudgeResponse.model_validate(response))
    portable_request = portable.next_judge_request(portable_run)
    core_request = next_core(core_run)
    assert portable_request is not None and core_request is not None
    assert portable_request == core_request.model_dump(mode="json")
    grade = copy.deepcopy(_scripted_payloads()[3]["payload"])
    grade["request_fingerprint"] = portable_request["request_fingerprint"]
    grade["anonymous_label"] = portable_request["safe_metadata"]["anonymous_label"]
    grade["ledger_fingerprint"] = portable_request["safe_metadata"][
        "legal_ledger_fingerprint"
    ]
    finding = next(
        item for item in grade["entry_grades"] if item["ledger_id"] == "file-notice"
    )
    finding["disposition"] = "COMPLETE"
    finding["finding_codes"] = [
        "CRITICAL_LEDGER_ENTRY_MISSING",
        "MATERIAL_EXCEPTION_MISSING",
        "CONSEQUENCE_TRIGGER_DETACHED",
    ]
    response = _response(portable_request, {"payload": grade}, 4)

    portable_state = portable.submit_judge_response(portable_run, response)
    core_state = submit_core(core_run, JudgeResponse.model_validate(response))
    diagnostic_path = "judge-diagnostics/grade-A-1-attempt-1.json"
    portable_diagnostics = (portable_run / diagnostic_path).read_bytes()
    core_diagnostics = (core_run / diagnostic_path).read_bytes()
    diagnostic_hash = hashlib.sha256(portable_diagnostics).hexdigest()
    portable_manifest = json.loads(
        (portable_run / "run-manifest.json").read_text(encoding="utf-8")
    )
    core_manifest = json.loads(
        (core_run / "run-manifest.json").read_text(encoding="utf-8")
    )

    assert portable_state["attempt"] == core_state.attempt == 2
    assert portable_diagnostics == core_diagnostics
    for manifest in (portable_manifest, core_manifest):
        diagnostic_record = next(
            item for item in manifest["artifacts"] if item["artifact_path"] == diagnostic_path
        )
        assert diagnostic_record["artifact_hash"] == diagnostic_hash
    message = json.loads(portable_diagnostics)["issues"][0]["message"]
    assert [message.count(f"finding_code={code}") for code in finding["finding_codes"]] == [
        1,
        1,
        1,
    ]
    for forbidden in (
        "synthetic-harvest",
        "candidate_id",
        "mapping",
        finding["report_passage"],
    ):
        assert forbidden not in message
    portable_retry = portable.next_judge_request(portable_run)
    core_retry = next_core(core_run)
    assert portable_retry is not None and core_retry is not None
    assert portable_retry == core_retry.model_dump(mode="json")
    assert portable.verify_evaluation_run(portable_run).valid
    assert attorney_artifacts.verify_evaluation_run(core_run).valid


def test_portable_compare_reports_requires_keyword_only_score_inputs() -> None:
    portable = _load_portable()
    fixture = _portable_comparison_fixture(portable)

    with pytest.raises(TypeError, match="candidate_inputs"):
        portable.compare_reports(fixture["candidate"], fixture["comparator"])


def test_portable_comparison_rejects_fabricated_rehashed_report() -> None:
    portable = _load_portable()
    fixture = _portable_comparison_fixture(portable)
    fabricated = copy.deepcopy(fixture["candidate"])
    fabricated["absolute_disposition"] = "FAIL"
    fabricated["blocking_codes"] = ["FABRICATED_BLOCKER"]
    fabricated["score_fingerprint"] = portable._model_fingerprint(
        fabricated,
        exclude={"score_fingerprint"},
    )

    with pytest.raises(
        portable.EvaluationInconclusiveError,
        match="replayed score inputs",
    ):
        portable.compare_reports(
            fabricated,
            fixture["comparator"],
            candidate_inputs=fixture["candidate_inputs"],
            comparator_inputs=fixture["comparator_inputs"],
        )


@pytest.mark.parametrize("side", ["candidate_inputs", "comparator_inputs"])
@pytest.mark.parametrize(
    "mutation",
    ["fingerprint", "source_id", "bounds", "quote"],
)
def test_portable_comparison_rejects_mutated_exact_evidence_in_either_input(
    side: str,
    mutation: str,
) -> None:
    portable = _load_portable()
    fixture = _portable_comparison_fixture(portable)
    score_inputs = copy.deepcopy(fixture[side])

    def mutate_exact_evidence(value: object) -> None:
        if isinstance(value, dict):
            if value.get("evidence_basis") == "source_spans":
                span = value["evidence_spans"][0]
                if mutation == "fingerprint":
                    value["source_record_fingerprint"] = "f" * 64
                elif mutation == "source_id":
                    span["source_id"] = "unknown-source"
                elif mutation == "bounds":
                    span["end_char"] = (
                        len(
                            score_inputs["source_record"]["sources"][0][
                                "normalized_text"
                            ]
                        )
                        + 1
                    )
                else:
                    span["quote"] = "fabricated exact quote"
            for child in value.values():
                mutate_exact_evidence(child)
        elif isinstance(value, list):
            for child in value:
                mutate_exact_evidence(child)

    mutate_exact_evidence(score_inputs["resolved_grade"])
    _rebind_portable_resolution_fingerprint(portable, score_inputs)

    with pytest.raises(
        portable.EvaluationInconclusiveError,
        match=r"source record|exact source span",
    ):
        portable.compare_reports(
            fixture["candidate"],
            fixture["comparator"],
            candidate_inputs=(
                score_inputs if side == "candidate_inputs" else fixture["candidate_inputs"]
            ),
            comparator_inputs=(
                score_inputs if side == "comparator_inputs" else fixture["comparator_inputs"]
            ),
        )


@pytest.mark.parametrize("mutation", ["sealed_ledger", "source_record"])
def test_portable_comparison_requires_same_ledger_and_common_source_record(
    mutation: str,
) -> None:
    portable = _load_portable()
    fixture = _portable_comparison_fixture(portable)
    comparator_inputs = copy.deepcopy(fixture["comparator_inputs"])
    if mutation == "sealed_ledger":
        comparator_inputs["sealed_ledger"]["audit_fingerprint"] = "f" * 64
    else:
        source_record = comparator_inputs["source_record"]
        source_record["question"] = "A different closed-universe question?"
        projection = {
            key: value
            for key, value in source_record.items()
            if key != "source_record_fingerprint"
        }
        source_record["source_record_fingerprint"] = hashlib.sha256(
            portable.canonical_json_bytes(projection)
        ).hexdigest()

    with pytest.raises(
        portable.EvaluationInconclusiveError,
        match=r"same strict sealed ledger|same common source record|bind the scoring source record",
    ):
        portable.compare_reports(
            fixture["candidate"],
            fixture["comparator"],
            candidate_inputs=fixture["candidate_inputs"],
            comparator_inputs=comparator_inputs,
        )


def test_comparison_and_score_threshold_vectors_match_core() -> None:
    portable = _load_portable()
    responses = _scripted_payloads()
    envelope = portable.freeze_case(_case_payload(), seed_hex="0" * 64)
    sealed = portable.seal_ledger(envelope, responses[1]["payload"], responses[2]["payload"], None)
    checks_a = portable._derive_deterministic_checks(
        portable._candidate_for_label(envelope, "A"), "A"
    )
    grade_a_1 = copy.deepcopy(responses[3]["payload"])
    grade_a_2 = copy.deepcopy(responses[4]["payload"])
    grade_b_1 = copy.deepcopy(grade_a_1)
    grade_b_2 = copy.deepcopy(grade_a_2)
    for grade in (grade_b_1, grade_b_2):
        grade["anonymous_label"] = "B"
        grade["request_fingerprint"] = "b" * 64
        grade["narrative_scores"][0]["score"] = 3
    resolved_a = portable.resolve_grades(sealed, grade_a_1, grade_a_2)
    resolved_b = portable.resolve_grades(sealed, grade_b_1, grade_b_2)
    checks_b = copy.deepcopy(checks_a)
    checks_b["anonymous_label"] = "B"
    source_record = portable.build_admission_packet(envelope)["payload"]
    score_a = portable.score_report(
        sealed,
        resolved_a,
        checks_a,
        source_record=source_record,
    )
    score_b = portable.score_report(
        sealed,
        resolved_b,
        checks_b,
        source_record=source_record,
    )
    candidate_input_payload = {
        "schema_version": "1.4",
        "anonymous_label": "A",
        "sealed_ledger": sealed,
        "resolved_grade": {"schema_version": "1.3", **resolved_a},
        "deterministic_checks": checks_a,
        "rubric": copy.deepcopy(portable.RUBRIC_V1),
        "source_record": source_record,
    }
    comparator_input_payload = {
        "schema_version": "1.4",
        "anonymous_label": "B",
        "sealed_ledger": sealed,
        "resolved_grade": {"schema_version": "1.3", **resolved_b},
        "deterministic_checks": checks_b,
        "rubric": copy.deepcopy(portable.RUBRIC_V1),
        "source_record": source_record,
    }
    portable_comparison = portable.compare_reports(
        score_a,
        score_b,
        candidate_inputs=candidate_input_payload,
        comparator_inputs=comparator_input_payload,
    )

    core_sealed = SealedLedger.model_validate(sealed)
    core_resolved_a = resolve_core(
        core_sealed,
        CandidateGrade.model_validate(grade_a_1),
        CandidateGrade.model_validate(grade_a_2),
        [],
    )
    core_resolved_b = resolve_core(
        core_sealed,
        CandidateGrade.model_validate(grade_b_1),
        CandidateGrade.model_validate(grade_b_2),
        [],
    )
    core_checks_a = DeterministicChecks.model_validate(checks_a)
    core_checks_b = DeterministicChecks.model_validate(checks_b)
    core_score_a = score_core(
        core_sealed,
        core_resolved_a,
        core_checks_a,
        source_record=source_record,
    )
    core_score_b = score_core(
        core_sealed,
        core_resolved_b,
        core_checks_b,
        source_record=source_record,
    )
    expected = compare_core(
        core_score_a,
        core_score_b,
        candidate_inputs=ReportScoreInputs(
            sealed_ledger=core_sealed,
            resolved_grade=core_resolved_a,
            deterministic_checks=core_checks_a,
            source_record=portable.canonical_json_bytes(source_record),
        ),
        comparator_inputs=ReportScoreInputs(
            sealed_ledger=core_sealed,
            resolved_grade=core_resolved_b,
            deterministic_checks=core_checks_b,
            source_record=portable.canonical_json_bytes(source_record),
        ),
    )
    assert portable_comparison == expected.model_dump(mode="json")


@pytest.mark.parametrize(
    ("ledger_id", "disposition", "finding_code"),
    [
        ("file-notice", "MISSING", "CRITICAL_LEDGER_ENTRY_MISSING"),
        ("emergency-exception", "MISSING", "MATERIAL_EXCEPTION_MISSING"),
        ("emergency-exception", "PARTIAL", "MATERIAL_EXCEPTION_MISSING"),
        ("bureau-order", "PARTIAL", "CONSEQUENCE_TRIGGER_DETACHED"),
    ],
)
def test_entry_finding_code_vectors_match_core(
    ledger_id: str, disposition: str, finding_code: str
) -> None:
    portable = _load_portable()
    responses = _scripted_payloads()
    envelope = portable.freeze_case(_case_payload(), seed_hex="0" * 64)
    sealed = portable.seal_ledger(envelope, responses[1]["payload"], responses[2]["payload"], None)
    first = copy.deepcopy(responses[3]["payload"])
    second = copy.deepcopy(responses[4]["payload"])
    for grade in (first, second):
        entry = next(item for item in grade["entry_grades"] if item["ledger_id"] == ledger_id)
        entry["disposition"] = disposition
        entry["report_location"] = None if disposition == "MISSING" else "paragraph 1"
        entry["report_passage"] = (
            None if disposition == "MISSING" else entry["report_passage"]
        )
        entry["finding_codes"] = [finding_code]
    resolved = portable.resolve_grades(sealed, first, second)
    checks = portable._derive_deterministic_checks(
        portable._candidate_for_label(envelope, "A"), "A"
    )
    source_record = portable.build_admission_packet(envelope)["payload"]
    portable_score = portable.score_report(
        sealed,
        resolved,
        checks,
        source_record=source_record,
    )
    core_sealed = SealedLedger.model_validate(sealed)
    core_resolved = resolve_core(
        core_sealed,
        CandidateGrade.model_validate(first),
        CandidateGrade.model_validate(second),
        [],
    )
    assert portable_score == score_core(
        core_sealed,
        core_resolved,
        DeterministicChecks.model_validate(checks),
        source_record=source_record,
    ).model_dump(mode="json")


@pytest.mark.parametrize("dimension", ["key_requirements", "requirements_workplan_boundary"])
def test_narrative_finding_code_vectors_match_core(dimension: str) -> None:
    portable = _load_portable()
    responses = _scripted_payloads()
    envelope = portable.freeze_case(_case_payload(), seed_hex="0" * 64)
    sealed = portable.seal_ledger(envelope, responses[1]["payload"], responses[2]["payload"], None)
    first = copy.deepcopy(responses[3]["payload"])
    second = copy.deepcopy(responses[4]["payload"])
    for grade in (first, second):
        narrative = next(
            item for item in grade["narrative_scores"] if item["dimension"] == dimension
        )
        narrative["score"] = 2
        narrative["finding_codes"] = ["KEY_REQUIREMENTS_ACTION_PLAN"]
    resolved = portable.resolve_grades(sealed, first, second)
    checks = portable._derive_deterministic_checks(
        portable._candidate_for_label(envelope, "A"), "A"
    )
    source_record = portable.build_admission_packet(envelope)["payload"]
    portable_score = portable.score_report(
        sealed,
        resolved,
        checks,
        source_record=source_record,
    )
    core_sealed = SealedLedger.model_validate(sealed)
    core_resolved = resolve_core(
        core_sealed,
        CandidateGrade.model_validate(first),
        CandidateGrade.model_validate(second),
        [],
    )
    assert portable_score == score_core(
        core_sealed,
        core_resolved,
        DeterministicChecks.model_validate(checks),
        source_record=source_record,
    ).model_dump(mode="json")


def test_exact_scoring_floor_boundaries_match_core() -> None:
    portable = _load_portable()
    responses = _scripted_payloads()
    envelope = portable.freeze_case(_case_payload(), seed_hex="0" * 64)
    ledger = copy.deepcopy(responses[1]["payload"])
    ledger["entries"] = ledger["entries"][:4]
    ledger["entries"][2]["materiality"] = "supporting"
    ledger["entries"][3]["materiality"] = "supporting"
    for index, entry in enumerate(ledger["entries"]):
        entry["walk_order"] = index
    audit = copy.deepcopy(responses[2]["payload"])
    sealed = portable.seal_ledger(envelope, ledger, audit, None)

    first = copy.deepcopy(responses[3]["payload"])
    second = copy.deepcopy(responses[4]["payload"])
    retained_ids = {entry["ledger_id"] for entry in ledger["entries"]}
    source_record = portable.build_admission_packet(envelope)["payload"]
    source_record_fingerprint = source_record["source_record_fingerprint"]
    source = source_record["sources"][0]
    evidence_quote = source["normalized_text"][0:1]
    narrative_values = (2, 3, 3, 3, 3, 3, 3, 4)
    for grade in (first, second):
        grade["ledger_fingerprint"] = sealed["ledger_fingerprint"]
        grade["entry_grades"] = [
            item for item in grade["entry_grades"] if item["ledger_id"] in retained_ids
        ]
        missing = next(
            item for item in grade["entry_grades"] if item["ledger_id"] == "notice-deadline"
        )
        missing["disposition"] = "MISSING"
        missing["report_location"] = None
        missing["report_passage"] = None
        for narrative, value in zip(grade["narrative_scores"], narrative_values, strict=True):
            narrative["score"] = value
        grade["out_of_ledger_claims"] = [
            {
                "claim_id": f"claim-{index}",
                "claim_text": f"Supported ancillary statement {index}.",
                "report_location": f"paragraph {index + 1}",
                "disposition": "PARTIAL" if index == 9 else "COMPLETE",
                "category": "definition",
                "materiality": "supporting",
                "source_record_fingerprint": source_record_fingerprint,
                "evidence_basis": "source_spans",
                "evidence_spans": [
                    {
                        "source_id": source["source_id"],
                        "start_char": 0,
                        "end_char": 1,
                        "quote": evidence_quote,
                    }
                ],
                "rationale": "The claim is evaluated against the source record.",
                "related_ledger_ids": [],
            }
            for index in range(10)
        ]
    resolved = portable.resolve_grades(sealed, first, second)
    checks = portable._derive_deterministic_checks(
        portable._candidate_for_label(envelope, "A"), "A"
    )
    portable_score = portable.score_report(
        sealed,
        resolved,
        checks,
        source_record=source_record,
    )
    assert portable_score["critical_recall"] == 1.0
    assert portable_score["weighted_recall"] == 0.9
    assert portable_score["claim_precision"] == 0.95
    assert portable_score["walk_average"] == 3.0
    assert portable_score["walk_minimum"] == 2
    assert portable_score["absolute_disposition"] == "PASS"

    core_sealed = SealedLedger.model_validate(sealed)
    core_resolved = resolve_core(
        core_sealed,
        CandidateGrade.model_validate(first),
        CandidateGrade.model_validate(second),
        [],
    )
    assert portable_score == score_core(
        core_sealed,
        core_resolved,
        DeterministicChecks.model_validate(checks),
        source_record=source_record,
    ).model_dump(mode="json")


def test_portable_valid_source_bearing_inputs_reproduce_full_exact_comparison() -> None:
    portable = _load_portable()
    fixture = _portable_comparison_fixture(portable)

    actual = portable.compare_reports(
        fixture["candidate"],
        fixture["comparator"],
        candidate_inputs=fixture["candidate_inputs"],
        comparator_inputs=fixture["comparator_inputs"],
    )

    candidate_inputs = fixture["candidate_inputs"]
    comparator_inputs = fixture["comparator_inputs"]
    core_sealed = SealedLedger.model_validate(candidate_inputs["sealed_ledger"])
    core_candidate_resolved = resolve_core(
        core_sealed,
        CandidateGrade.model_validate(
            candidate_inputs["resolved_grade"]["original_grader_1"]
        ),
        CandidateGrade.model_validate(
            candidate_inputs["resolved_grade"]["original_grader_2"]
        ),
        [],
    )
    core_comparator_resolved = resolve_core(
        core_sealed,
        CandidateGrade.model_validate(
            comparator_inputs["resolved_grade"]["original_grader_1"]
        ),
        CandidateGrade.model_validate(
            comparator_inputs["resolved_grade"]["original_grader_2"]
        ),
        [],
    )
    core_candidate_checks = DeterministicChecks.model_validate(
        candidate_inputs["deterministic_checks"]
    )
    core_comparator_checks = DeterministicChecks.model_validate(
        comparator_inputs["deterministic_checks"]
    )
    source_record_bytes = portable.canonical_json_bytes(
        candidate_inputs["source_record"]
    )
    expected = compare_core(
        score_core(
            core_sealed,
            core_candidate_resolved,
            core_candidate_checks,
            source_record=candidate_inputs["source_record"],
        ),
        score_core(
            core_sealed,
            core_comparator_resolved,
            core_comparator_checks,
            source_record=candidate_inputs["source_record"],
        ),
        candidate_inputs=ReportScoreInputs(
            sealed_ledger=core_sealed,
            resolved_grade=core_candidate_resolved,
            deterministic_checks=core_candidate_checks,
            source_record=source_record_bytes,
        ),
        comparator_inputs=ReportScoreInputs(
            sealed_ledger=core_sealed,
            resolved_grade=core_comparator_resolved,
            deterministic_checks=core_comparator_checks,
            source_record=source_record_bytes,
        ),
    )

    assert actual == expected.model_dump(mode="json")


def test_duplicate_and_out_of_order_responses_do_not_advance(tmp_path: Path) -> None:
    portable = _load_portable()
    run = tmp_path / "run"
    portable.initialize_evaluation(_case_payload(), run, seed_hex="0" * 64)
    request = portable.next_judge_request(run)
    assert request is not None
    item = _scripted_payloads()[0]
    response = _response(request, item, 1)
    portable.submit_judge_response(run, response)
    state_before = portable.resume_evaluation(run)
    with pytest.raises(portable.PortableEvaluationInputError):
        portable.submit_judge_response(run, response)
    assert portable.resume_evaluation(run) == state_before
    wrong = copy.deepcopy(response)
    wrong["operation"] = "grade_report"
    with pytest.raises(portable.PortableEvaluationInputError):
        portable.submit_judge_response(run, wrong)
    assert portable.resume_evaluation(run) == state_before


@pytest.mark.parametrize(
    ("overridden_isolation", "expected"),
    [
        (None, "fresh_context"),
        ("sequential_same_context", "sequential_same_context"),
    ],
)
def test_terminal_result_aggregates_judge_isolation_conservatively(
    tmp_path: Path,
    overridden_isolation: str | None,
    expected: str,
) -> None:
    """One sequential call must downgrade the terminal isolation declaration."""
    portable = _load_portable()
    run = tmp_path / "run"
    portable.initialize_evaluation(_case_payload(), run, seed_hex="0" * 64)
    for index, item in enumerate(_scripted_payloads(), start=1):
        request = portable.next_judge_request(run)
        assert request is not None
        response = _response(request, item, index)
        if overridden_isolation is not None and index == 2:
            response["judge_isolation"] = overridden_isolation
        portable.submit_judge_response(run, response)

    result = json.loads((run / "evaluation-result.json").read_text(encoding="utf-8"))
    report = (run / "evaluation-report.md").read_text(encoding="utf-8")
    assert result["schema_version"] == "1.3"
    assert result["judge_isolation"] == expected
    assert f"- Aggregate judge isolation: {expected}." in report
    assert portable.verify_evaluation_run(run).valid


def test_verifier_recomputes_aggregate_judge_isolation(tmp_path: Path) -> None:
    """Rehashing a stronger isolation claim must not make the run verify."""
    portable = _load_portable()
    run = tmp_path / "run"
    portable.initialize_evaluation(_case_payload(), run, seed_hex="0" * 64)
    for index, item in enumerate(_scripted_payloads(), start=1):
        request = portable.next_judge_request(run)
        assert request is not None
        response = _response(request, item, index)
        if index == 2:
            response["judge_isolation"] = "sequential_same_context"
        portable.submit_judge_response(run, response)

    result_path = run / "evaluation-result.json"
    result = json.loads(result_path.read_text(encoding="utf-8"))
    assert result["judge_isolation"] == "sequential_same_context"
    result["judge_isolation"] = "fresh_context"
    result["result_fingerprint"] = "0" * 64
    result["result_fingerprint"] = portable._model_fingerprint(
        result, exclude={"result_fingerprint"}
    )
    result_path.write_bytes(portable.canonical_json_bytes(result))
    (run / "evaluation-report.md").write_text(
        portable.render_evaluation_report(result), encoding="utf-8"
    )
    manifest_path = run / "run-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["result_hash"] = hashlib.sha256(result_path.read_bytes()).hexdigest()
    manifest_path.write_bytes(portable.canonical_json_bytes(manifest))
    _rehash_manifest_artifact(portable, run, "evaluation-result.json")
    _rehash_manifest_artifact(portable, run, "evaluation-report.md")

    assert portable.verify_evaluation_run(run).issues == ("EVALUATION_INTEGRITY_INVALID",)


def test_invalid_response_retries_once_then_becomes_inconclusive(tmp_path: Path) -> None:
    portable = _load_portable()
    run = tmp_path / "run"
    portable.initialize_evaluation(_case_payload(), run, seed_hex="0" * 64)
    first = portable.next_judge_request(run)
    assert first is not None
    invalid = _response(first, {"payload": {"malformed": True}}, 1)
    retry = portable.submit_judge_response(run, invalid)
    assert retry["attempt"] == 2
    second = portable.next_judge_request(run)
    assert second == first
    terminal = portable.submit_judge_response(
        run, _response(second, {"payload": {"still": "malformed"}}, 2)
    )
    assert terminal["state"] == "inconclusive"
    assert terminal["terminal_status"] == "inconclusive"
    result = json.loads((run / "evaluation-result.json").read_text(encoding="utf-8"))
    assert result["schema_version"] == "1.3"
    assert result["readiness"]["status"] == "INCONCLUSIVE"
    assert "JUDGE_RESPONSE_INVALID" in result["readiness"]["issue_codes"]
    assert result["requirement_matrix"] == {
        "available": False,
        "rows": [],
        "unavailable_reason": "INCONCLUSIVE",
    }


def test_case_invalid_terminal_phase_stops_after_admission(tmp_path: Path) -> None:
    portable = _load_portable()
    portable_run = tmp_path / "portable"
    core_run = tmp_path / "core"
    case_payload = _case_payload()
    portable.initialize_evaluation(case_payload, portable_run, seed_hex="0" * 64)
    initialize_core(_core_case_from_payload(case_payload), core_run, seed_hex="0" * 64)
    request = portable.next_judge_request(portable_run)
    core_request = next_core(core_run)
    assert request is not None and core_request is not None
    assert portable.canonical_json_bytes(request) == portable.canonical_json_bytes(
        core_request.model_dump(mode="json")
    )
    payload = copy.deepcopy(_scripted_payloads()[0]["payload"])
    payload["request_fingerprint"] = request["request_fingerprint"]
    check = next(item for item in payload["checks"] if item["code"] == "OPERATIVE_TEXT")
    check["satisfied"] = False
    response = _response(request, {"payload": payload}, 1)
    terminal = portable.submit_judge_response(portable_run, response)
    core_terminal = submit_core(core_run, JudgeResponse.model_validate(response))
    assert terminal == core_terminal.model_dump(mode="json")
    assert terminal["state"] == "case-invalid"
    assert terminal["terminal_status"] == "case-invalid"
    assert portable.next_judge_request(portable_run) is None
    assert next_core(core_run) is None
    for artifact in ("case-readiness.json", "evaluation-result.json", "evaluation-report.md"):
        assert (portable_run / artifact).read_bytes() == (core_run / artifact).read_bytes()
    result = json.loads((portable_run / "evaluation-result.json").read_text(encoding="utf-8"))
    assert result["requirement_matrix"] == {
        "available": False,
        "rows": [],
        "unavailable_reason": "CASE_INVALID",
    }
    assert portable.verify_evaluation_run(portable_run).valid


@pytest.mark.parametrize(
    "invalid_grade_schema",
    [pytest.param("1.2", id="old-version"), pytest.param(None, id="omitted")],
)
def test_invalid_grade_schema_retries_but_completed_grade_requires_explicit_13(
    tmp_path: Path, invalid_grade_schema: str | None
) -> None:
    portable = _load_portable()
    portable_run = tmp_path / "portable"
    core_run = tmp_path / "core"
    case_payload = _case_payload()
    portable.initialize_evaluation(case_payload, portable_run, seed_hex="0" * 64)
    initialize_core(_core_case_from_payload(case_payload), core_run, seed_hex="0" * 64)
    grade_counts: dict[str, int] = {}
    response_number = 0
    rejected_old_grade = False

    while True:
        request = portable.next_judge_request(portable_run)
        core_request = next_core(core_run)
        if request is None or core_request is None:
            assert request is None and core_request is None
            break
        assert portable.canonical_json_bytes(request) == portable.canonical_json_bytes(
            core_request.model_dump(mode="json")
        )
        payload = _differential_payload(request, grade_counts)
        if request["operation"] == "grade_report" and not rejected_old_grade:
            if invalid_grade_schema is None:
                payload.pop("schema_version")
            else:
                payload["schema_version"] = invalid_grade_schema
            rejected_old_grade = True
            grade_counts[request["safe_metadata"]["anonymous_label"]] -= 1
        response_number += 1
        response = _response(request, {"payload": payload}, response_number)
        portable_state = portable.submit_judge_response(portable_run, response)
        core_state = submit_core(core_run, JudgeResponse.model_validate(response))
        assert portable_state == core_state.model_dump(mode="json")

    assert rejected_old_grade
    assert portable.verify_evaluation_run(portable_run).valid
    failed_response = json.loads(
        (portable_run / "judge-responses" / "grade-A-1-attempt-1.json").read_text(
            encoding="utf-8"
        )
    )
    assert failed_response["schema_version"] == "1.0"
    if invalid_grade_schema is None:
        assert "schema_version" not in failed_response["payload"]
    else:
        assert failed_response["payload"]["schema_version"] == invalid_grade_schema
    completed_response = json.loads(
        (portable_run / "judge-responses" / "grade-A-1-attempt-2.json").read_text(
            encoding="utf-8"
        )
    )
    assert completed_response["schema_version"] == "1.0"
    assert completed_response["payload"]["schema_version"] == "1.3"


def _repair_and_referee_payload(
    request: dict[str, Any],
    scripted: list[dict[str, Any]],
    grade_count: list[int],
    *,
    omit_defaults: bool = False,
) -> dict[str, Any]:
    operation = request["operation"]
    if operation == "admit_case":
        payload = copy.deepcopy(scripted[0]["payload"])
        if omit_defaults:
            payload.pop("issues")
    elif operation == "build_ledger":
        payload = copy.deepcopy(scripted[1]["payload"])
        if omit_defaults:
            payload.pop("gaps")
    elif operation == "audit_ledger":
        dispute = {
            "dispute_id": "file-notice-materiality",
            "action": "materiality",
            "target_ledger_ids": ["file-notice"],
            "proposed_entries": [],
            "materiality": "critical",
            "rationale": "Materiality needs an independent source-grounded decision.",
        }
        if omit_defaults:
            dispute.pop("proposed_entries")
        payload = {
            "request_fingerprint": request["request_fingerprint"],
            "complete": True,
            "disputes": [dispute],
        }
    elif operation == "repair_ledger":
        repaired = copy.deepcopy(request["payload"]["proposed_ledger"])
        dispute = {
            "dispute_id": "file-notice-materiality",
            "action": "materiality",
            "target_ledger_ids": ["file-notice"],
            "proposed_entries": [],
            "materiality": "critical",
            "rationale": "Materiality still needs an independent decision.",
        }
        if omit_defaults:
            repaired.pop("gaps")
            dispute.pop("proposed_entries")
        payload = {
            "repaired_ledger": repaired,
            "remaining_audit": {
                "request_fingerprint": request["request_fingerprint"],
                "complete": True,
                "disputes": [dispute],
            },
        }
    elif operation == "referee" and request["safe_metadata"]["referee_scope"] == "ledger":
        payload = {
            "dispute_id": "file-notice-materiality",
            "selected_ledger_resolution": "accept_a",
            "selected_grade_resolution": None,
            "replacement_entries": [],
            "replacement_grade_alternative": None,
            "selected_disposition": None,
            "grade_dispute_fingerprint": None,
            "rationale": "The original ledger treatment is source supported.",
            "source_ids": ["synthetic-rule-1-source"],
        }
        if omit_defaults:
            for key in (
                "selected_grade_resolution",
                "replacement_entries",
                "replacement_grade_alternative",
                "selected_disposition",
                "grade_dispute_fingerprint",
            ):
                payload.pop(key)
    elif operation == "grade_report":
        grade_count[0] += 1
        payload = copy.deepcopy(scripted[3 if grade_count[0] == 1 else 4]["payload"])
        payload["request_fingerprint"] = request["request_fingerprint"]
        payload["anonymous_label"] = request["safe_metadata"]["anonymous_label"]
        payload["ledger_fingerprint"] = request["safe_metadata"]["legal_ledger_fingerprint"]
        if grade_count[0] == 2:
            payload["entry_grades"][0]["disposition"] = "PARTIAL"
            payload["entry_grades"][0]["rationale"] = "The duty is only partly covered."
        if omit_defaults:
            payload.pop("out_of_ledger_claims")
            for entry_grade in payload["entry_grades"]:
                entry_grade.pop("finding_codes")
            for narrative_score in payload["narrative_scores"]:
                narrative_score.pop("finding_codes")
    else:
        dispute = request["payload"]["dispute"]
        payload = {
            "dispute_id": dispute["dispute_id"],
            "selected_ledger_resolution": None,
            "selected_grade_resolution": "accept_grader_1",
            "replacement_entries": [],
            "replacement_grade_alternative": None,
            "selected_disposition": None,
            "grade_dispute_fingerprint": request["safe_metadata"]["grade_dispute_fingerprint"],
            "rationale": "The first grade is better supported.",
            "source_ids": [],
        }
        if omit_defaults:
            for key in (
                "selected_ledger_resolution",
                "replacement_entries",
                "replacement_grade_alternative",
                "selected_disposition",
                "source_ids",
            ):
                payload.pop(key)
    return cast(dict[str, Any], payload)


@pytest.mark.parametrize(
    ("fixture_name", "archive_hash", "contract_mode"),
    [
        (
            "legacy-ledger-repair-919eb5f.tgz.b64",
            "0a13f0fbeb9c6c5841a198a811efcf1f567c91ebfbeade3f9d4214b87ee7729d",
            "pre-contract",
        ),
        (
            "ledger-invariant-contract-v1-445f4d9.tgz.b64",
            "3446c3904939653460c52ba54334b89739b012107a6e17bc3ee2c041e4d10952",
            "1.0",
        ),
    ],
)
def test_portable_replay_accepts_retained_ledger_contract_generations(
    fixture_name: str,
    archive_hash: str,
    contract_mode: str,
    tmp_path: Path,
) -> None:
    """Genuine pre-contract and schema-1.0 repair runs must replay on both heads."""
    portable = _load_portable()
    fixture = FIXTURE / fixture_name
    archive_bytes = base64.b64decode(fixture.read_bytes())
    assert hashlib.sha256(archive_bytes).hexdigest() == archive_hash
    _extract_retained_run_fixture(archive_bytes, tmp_path)
    run = tmp_path / "completed-repair"
    before = _tree_bytes(run)
    ledger_requests = [
        json.loads(path.read_bytes())
        for path in sorted((run / "judge-requests").glob("ledger-*-attempt-1.json"))
        if path.name
        in {
            "ledger-build-attempt-1.json",
            "ledger-audit-attempt-1.json",
            "ledger-repair-attempt-1.json",
        }
    ]

    assert len(ledger_requests) == 3
    if contract_mode == "pre-contract":
        assert all(
            "ledger_invariant_contract" not in request["payload"]
            and "ledger_invariant_contract" not in request["system_instructions"]
            for request in ledger_requests
        )
    else:
        assert all(
            request["payload"]["ledger_invariant_contract"]
            == _ledger_invariant_contract_v1_0()
            for request in ledger_requests
        )
    full_verification = attorney_artifacts.verify_evaluation_run(run)
    portable_verification = portable.verify_evaluation_run(run)
    assert portable_verification.valid == full_verification.valid is True
    assert portable_verification.issues == tuple(full_verification.issues) == ()
    assert portable_verification.root_hash == full_verification.root_hash
    assert _tree_bytes(run) == before


def test_portable_replay_accepts_current_ledger_contract_generation(
    tmp_path: Path,
) -> None:
    """A current build/audit/repair run remains the schema-1.1 control."""
    portable = _load_portable()
    run = tmp_path / "current-contract"
    portable.initialize_evaluation(_case_payload(), run, seed_hex="0" * 64)
    scripted = _scripted_payloads()
    grade_count = [0]
    for response_number in range(1, 5):
        request = portable.next_judge_request(run)
        assert request is not None
        payload = _repair_and_referee_payload(request, scripted, grade_count)
        portable.submit_judge_response(
            run, _response(request, {"payload": payload}, response_number)
        )
    ledger_requests = [
        json.loads(path.read_bytes())
        for path in sorted((run / "judge-requests").glob("ledger-*-attempt-1.json"))
        if path.name
        in {
            "ledger-build-attempt-1.json",
            "ledger-audit-attempt-1.json",
            "ledger-repair-attempt-1.json",
        }
    ]

    assert all(
        request["payload"]["ledger_invariant_contract"] == ledger_invariant_contract()
        for request in ledger_requests
    )
    full_verification = attorney_artifacts.verify_evaluation_run(run)
    portable_verification = portable.verify_evaluation_run(run)
    assert portable_verification.valid == full_verification.valid is True
    assert portable_verification.issues == tuple(full_verification.issues) == ()
    assert portable_verification.root_hash == full_verification.root_hash


def test_portable_historical_ledger_contract_generation_is_fresh_json() -> None:
    """Historical schema-1.0 replay data must be exact and independently mutable."""
    portable = _load_portable()

    mutated = portable._ledger_invariant_contract_v1_0()
    mutated["relationships"]["trigger_link_categories"].append("remedy")

    assert portable._ledger_invariant_contract_v1_0() == (
        _ledger_invariant_contract_v1_0()
    )


@pytest.mark.parametrize("mutation", ["mixed", "modified", "unknown"])
def test_portable_replay_rejects_mixed_or_modified_ledger_contract_generation(
    mutation: str,
    tmp_path: Path,
) -> None:
    """Self-consistent history cannot mix modes or alter a recognized contract."""
    portable = _load_portable()
    run = tmp_path / mutation
    portable.initialize_evaluation(_case_payload(), run, seed_hex="0" * 64)
    scripted = _scripted_payloads()
    grade_count = [0]
    for response_number in range(1, 3):
        request = portable.next_judge_request(run)
        assert request is not None
        payload = _repair_and_referee_payload(request, scripted, grade_count)
        portable.submit_judge_response(
            run, _response(request, {"payload": payload}, response_number)
        )
    audit_path = "judge-requests/ledger-audit-attempt-1.json"
    request = json.loads((run / audit_path).read_bytes())
    if mutation == "mixed":
        request["payload"]["ledger_invariant_contract"] = (
            _ledger_invariant_contract_v1_0()
        )
    elif mutation == "modified":
        request["payload"]["ledger_invariant_contract"]["binding"][
            "case_fingerprint"
        ] = "modified"
    else:
        request["payload"]["ledger_invariant_contract"]["schema_version"] = "9.9"
    request["request_fingerprint"] = "0" * 64
    request["request_fingerprint"] = portable._model_fingerprint(
        request, exclude={"request_fingerprint"}
    )
    _rewrite_portable_history_artifacts(
        portable,
        run,
        {audit_path: portable.canonical_json_bytes(request)},
    )

    full_verification = attorney_artifacts.verify_evaluation_run(run)
    portable_verification = portable.verify_evaluation_run(run)
    assert portable_verification.valid == full_verification.valid is False
    assert portable_verification.issues == (
        "EVALUATION_INTEGRITY_INVALID",
    )
    assert full_verification.issues
    assert portable_verification.root_hash == full_verification.root_hash is None


def test_repair_and_both_referee_paths_complete_and_replay(tmp_path: Path) -> None:
    portable = _load_portable()
    run = tmp_path / "run"
    portable.initialize_evaluation(_case_payload(), run, seed_hex="0" * 64)
    scripted = _scripted_payloads()
    operations: list[str] = []
    grade_count = [0]
    response_number = 0
    while (request := portable.next_judge_request(run)) is not None:
        before = {
            path.relative_to(run).as_posix(): path.read_bytes()
            for path in run.rglob("*")
            if path.is_file()
        }
        portable.resume_evaluation(run)
        assert portable.next_judge_request(run) == request
        after = {
            path.relative_to(run).as_posix(): path.read_bytes()
            for path in run.rglob("*")
            if path.is_file()
        }
        assert after == before
        response_number += 1
        operation = request["operation"]
        operations.append(operation)
        payload = _repair_and_referee_payload(request, scripted, grade_count)
        portable.submit_judge_response(
            run, _response(request, {"payload": payload}, response_number)
        )
    assert operations == [
        "admit_case",
        "build_ledger",
        "audit_ledger",
        "repair_ledger",
        "referee",
        "grade_report",
        "grade_report",
        "referee",
    ]
    assert portable.verify_evaluation_run(run).valid


@pytest.mark.parametrize("audit_kind", ["initial", "remaining"])
def test_portable_replay_rejects_rebound_inner_audit_request_fingerprint(
    tmp_path: Path,
    audit_kind: str,
) -> None:
    portable = _load_portable()
    run = tmp_path / "run"
    portable.initialize_evaluation(_case_payload(), run, seed_hex="0" * 64)
    scripted = _scripted_payloads()
    grade_count = [0]
    for response_number in range(1, (3 if audit_kind == "initial" else 4) + 1):
        request = portable.next_judge_request(run)
        assert request is not None
        payload = _repair_and_referee_payload(request, scripted, grade_count)
        portable.submit_judge_response(
            run, _response(request, {"payload": payload}, response_number)
        )
    assert portable.verify_evaluation_run(run).valid

    if audit_kind == "initial":
        response_path = "judge-responses/ledger-audit-attempt-1.json"
        response = json.loads((run / response_path).read_text(encoding="utf-8"))
        wrong = "f" * 64 if response["request_fingerprint"] != "f" * 64 else "e" * 64
        response["payload"]["request_fingerprint"] = wrong
        audit = response["payload"]
        envelope = json.loads((run / "case-envelope.json").read_text(encoding="utf-8"))
        proposed = json.loads(
            (run / "legal-ledger.proposed.json").read_text(encoding="utf-8")
        )
        repair_request = portable._repair_ledger_request(envelope, proposed, audit)
        replacements = {
            response_path: portable.canonical_json_bytes(response),
            "legal-ledger-audit.json": portable.canonical_json_bytes(audit),
            "judge-requests/ledger-repair-attempt-1.json": portable.canonical_json_bytes(
                repair_request
            ),
        }
    else:
        response_path = "judge-responses/ledger-repair-attempt-1.json"
        response = json.loads((run / response_path).read_text(encoding="utf-8"))
        wrong = "f" * 64 if response["request_fingerprint"] != "f" * 64 else "e" * 64
        response["payload"]["remaining_audit"]["request_fingerprint"] = wrong
        remaining = response["payload"]["remaining_audit"]
        replacements = {
            response_path: portable.canonical_json_bytes(response),
            "legal-ledger.remaining-audit.json": portable.canonical_json_bytes(remaining),
        }
    _rewrite_portable_history_artifacts(portable, run, replacements)

    assert portable.verify_evaluation_run(run).issues == ("EVALUATION_INTEGRITY_INVALID",)


def test_omitted_defaults_across_repair_and_referees_match_core(tmp_path: Path) -> None:
    portable = _load_portable()
    portable_run = tmp_path / "portable"
    core_run = tmp_path / "core"
    case_payload = _case_payload()
    portable.initialize_evaluation(case_payload, portable_run, seed_hex="1" * 64)
    initialize_core(_core_case_from_payload(case_payload), core_run, seed_hex="1" * 64)
    scripted = _scripted_payloads()
    grade_count = [0]
    response_number = 0

    while True:
        portable_request = portable.next_judge_request(portable_run)
        core_request = next_core(core_run)
        if portable_request is None or core_request is None:
            assert portable_request is None and core_request is None
            break
        assert portable.canonical_json_bytes(portable_request) == portable.canonical_json_bytes(
            core_request.model_dump(mode="json")
        )
        payload = _repair_and_referee_payload(
            portable_request,
            scripted,
            grade_count,
            omit_defaults=True,
        )
        response_number += 1
        response = _response(portable_request, {"payload": payload}, response_number)
        portable_state = portable.submit_judge_response(portable_run, response)
        core_state = submit_core(core_run, JudgeResponse.model_validate(response))

        assert portable_state == core_state.model_dump(mode="json")
        assert portable.verify_evaluation_run(portable_run).valid
        assert attorney_artifacts.verify_evaluation_run(core_run).valid

    assert (portable_run / "evaluation-result.json").read_bytes() == (
        core_run / "evaluation-result.json"
    ).read_bytes()
    assert (portable_run / "evaluation-report.md").read_bytes() == (
        core_run / "evaluation-report.md"
    ).read_bytes()


def test_multiple_remaining_ledger_disputes_terminal_matches_core(tmp_path: Path) -> None:
    portable = _load_portable()
    portable_run = tmp_path / "portable"
    core_run = tmp_path / "core"
    case_payload = _case_payload()
    portable.initialize_evaluation(case_payload, portable_run, seed_hex="0" * 64)
    initialize_core(_core_case_from_payload(case_payload), core_run, seed_hex="0" * 64)
    scripted = _scripted_payloads()
    portable_state: dict[str, Any] | None = None
    core_state: Any = None

    for index in range(4):
        portable_request = portable.next_judge_request(portable_run)
        core_request = next_core(core_run)
        assert portable_request is not None and core_request is not None
        assert portable.canonical_json_bytes(portable_request) == portable.canonical_json_bytes(
            core_request.model_dump(mode="json")
        )
        if index == 0:
            payload = copy.deepcopy(scripted[0]["payload"])
            payload["request_fingerprint"] = portable_request["request_fingerprint"]
        elif index == 1:
            payload = copy.deepcopy(scripted[1]["payload"])
            payload["case_fingerprint"] = portable_request["safe_metadata"][
                "source_record_fingerprint"
            ]
        elif index == 2:
            payload = {
                "request_fingerprint": portable_request["request_fingerprint"],
                "complete": True,
                "disputes": [
                    {
                        "dispute_id": "file-notice-materiality",
                        "action": "materiality",
                        "target_ledger_ids": ["file-notice"],
                        "proposed_entries": [],
                        "materiality": "critical",
                        "rationale": "The duty needs independent materiality review.",
                    }
                ],
            }
        else:
            dispute_template = {
                "action": "materiality",
                "proposed_entries": [],
                "rationale": "The duty still needs independent materiality review.",
            }
            payload = {
                "repaired_ledger": portable_request["payload"]["proposed_ledger"],
                "remaining_audit": {
                    "request_fingerprint": portable_request["request_fingerprint"],
                    "complete": True,
                    "disputes": [
                        {
                            **dispute_template,
                            "dispute_id": "file-notice-materiality",
                            "target_ledger_ids": ["file-notice"],
                            "materiality": "critical",
                        },
                        {
                            **dispute_template,
                            "dispute_id": "retain-proof-materiality",
                            "target_ledger_ids": ["retain-proof"],
                            "materiality": "material",
                        },
                    ],
                },
            }
        response = _response(portable_request, {"payload": payload}, index + 1)
        portable_state = portable.submit_judge_response(portable_run, response)
        core_state = submit_core(core_run, JudgeResponse.model_validate(response))

    assert portable_state is not None
    assert portable_state == core_state.model_dump(mode="json")
    assert portable_state["state"] == "inconclusive"
    assert portable_state["terminal_status"] == "inconclusive"
    assert portable.next_judge_request(portable_run) is None
    assert next_core(core_run) is None
    for artifact in (
        "legal-ledger.repaired.json",
        "legal-ledger.remaining-audit.json",
        "terminal-readiness.json",
        "evaluation-result.json",
        "evaluation-report.md",
    ):
        assert (portable_run / artifact).read_bytes() == (core_run / artifact).read_bytes()
    result = json.loads((portable_run / "evaluation-result.json").read_text(encoding="utf-8"))
    assert result["readiness"]["issue_codes"][-1] == ("MULTIPLE_LEDGER_DISPUTES_UNRESOLVED")
    assert portable.verify_evaluation_run(portable_run).valid


def test_portable_initial_nontransaction_audit_advances_to_repair(tmp_path: Path) -> None:
    portable = _load_portable()
    run = tmp_path / "run"
    portable.initialize_evaluation(_case_payload(), run, seed_hex="9" * 64)
    scripted = _scripted_payloads()
    for index, item in enumerate(scripted[:2], start=1):
        request = portable.next_judge_request(run)
        assert request is not None
        portable.submit_judge_response(run, _response(request, item, index))

    audit_request = portable.next_judge_request(run)
    assert audit_request is not None
    assert audit_request["operation"] == "audit_ledger"
    audit_response = _response(
        audit_request,
        {
            "payload": {
                "request_fingerprint": audit_request["request_fingerprint"],
                "complete": True,
                "disputes": [
                    {
                        "dispute_id": "add-omitted-record",
                        "action": "add",
                        "target_ledger_ids": [],
                        "proposed_entries": [],
                        "materiality": "supporting",
                        "rationale": (
                            "synthetic-rule-1-source is missing covered operator registry "
                            "notice requirement."
                        ),
                    },
                    {
                        "dispute_id": "add-located-record",
                        "action": "add",
                        "target_ledger_ids": [],
                        "proposed_entries": [],
                        "materiality": "supporting",
                        "rationale": (
                            "synthetic-rule-1-source is missing the notice requirement "
                            "at Rule 1."
                        ),
                    },
                    {
                        "dispute_id": "add-proposed-record",
                        "action": "add",
                        "target_ledger_ids": [],
                        "proposed_entries": [
                            {
                                **copy.deepcopy(
                                    audit_request["payload"]["proposed_ledger"]["entries"][0]
                                ),
                                "ledger_id": "proposed-notice",
                            }
                        ],
                        "materiality": "supporting",
                        "rationale": "The source record needs a ledger correction.",
                    },
                    {
                        "dispute_id": "split-notice-duty",
                        "action": "split",
                        "target_ledger_ids": ["file-notice"],
                        "proposed_entries": [],
                        "materiality": "supporting",
                        "rationale": (
                            "The notice duty combines distinct filing and timing propositions."
                        ),
                    },
                ],
            }
        },
        3,
    )

    state = portable.submit_judge_response(run, audit_response)
    repair_request = portable.next_judge_request(run)

    assert state["state"] == "ledger-repair"
    assert repair_request is not None
    assert repair_request["operation"] == "repair_ledger"
    assert portable.verify_evaluation_run(run).valid

    remaining = copy.deepcopy(audit_response["payload"])
    remaining["request_fingerprint"] = repair_request["request_fingerprint"]
    retry_state = portable.submit_judge_response(
        run,
        _response(
            repair_request,
            {
                "payload": {
                    "repaired_ledger": repair_request["payload"]["proposed_ledger"],
                    "remaining_audit": remaining,
                }
            },
            4,
        ),
    )
    retry_request = portable.next_judge_request(run)

    assert retry_state["state"] == "ledger-repair"
    assert retry_state["attempt"] == 2
    assert retry_request is not None
    assert retry_request["operation"] == "repair_ledger"
    assert portable.verify_evaluation_run(run).valid


def test_portable_initial_add_reusing_existing_ledger_id_retries_and_replays(
    tmp_path: Path,
) -> None:
    portable = _load_portable()
    run = tmp_path / "run"
    portable.initialize_evaluation(_case_payload(), run, seed_hex="5" * 64)
    for index, item in enumerate(_scripted_payloads()[:2], start=1):
        request = portable.next_judge_request(run)
        assert request is not None
        payload = copy.deepcopy(item["payload"])
        if "request_fingerprint" in payload:
            payload["request_fingerprint"] = request["request_fingerprint"]
        if request["operation"] == "build_ledger":
            payload["case_fingerprint"] = request["safe_metadata"][
                "source_record_fingerprint"
            ]
        portable.submit_judge_response(
            run,
            _response(request, {"payload": payload}, index),
        )
    audit_request = portable.next_judge_request(run)
    assert audit_request is not None
    existing_entry = copy.deepcopy(
        audit_request["payload"]["proposed_ledger"]["entries"][0]
    )

    state = portable.submit_judge_response(
        run,
        _response(
            audit_request,
            {
                "payload": {
                    "request_fingerprint": audit_request["request_fingerprint"],
                    "complete": True,
                    "disputes": [
                        {
                            "dispute_id": "reused-add-id",
                            "action": "add",
                            "target_ledger_ids": [],
                            "proposed_entries": [existing_entry],
                            "materiality": "supporting",
                            "rationale": "The source record needs a ledger correction.",
                        }
                    ],
                }
            },
            3,
        ),
    )
    retry = portable.next_judge_request(run)

    assert state["state"] == "ledger-audit"
    assert state["attempt"] == 2
    assert retry is not None and retry["operation"] == "audit_ledger"
    diagnostics = json.loads(
        (run / "judge-diagnostics/ledger-audit-attempt-1.json").read_text(
            encoding="utf-8"
        )
    )
    assert "add initial ledger finding must use new ledger IDs" in diagnostics["issues"][0][
        "message"
    ]
    assert portable.verify_evaluation_run(run).valid


def test_portable_replay_rejects_rebound_initial_add_with_existing_ledger_id(
    tmp_path: Path,
) -> None:
    portable = _load_portable()
    run = tmp_path / "run"
    portable.initialize_evaluation(_case_payload(), run, seed_hex="6" * 64)
    for index, item in enumerate(_scripted_payloads()[:2], start=1):
        request = portable.next_judge_request(run)
        assert request is not None
        payload = copy.deepcopy(item["payload"])
        if "request_fingerprint" in payload:
            payload["request_fingerprint"] = request["request_fingerprint"]
        if request["operation"] == "build_ledger":
            payload["case_fingerprint"] = request["safe_metadata"][
                "source_record_fingerprint"
            ]
        portable.submit_judge_response(
            run,
            _response(request, {"payload": payload}, index),
        )
    audit_request = portable.next_judge_request(run)
    assert audit_request is not None
    proposed = copy.deepcopy(
        audit_request["payload"]["proposed_ledger"]["entries"][0]
    )
    proposed["ledger_id"] = "proposed-notice"
    response = _response(
        audit_request,
        {
            "payload": {
                "request_fingerprint": audit_request["request_fingerprint"],
                "complete": True,
                "disputes": [
                    {
                        "dispute_id": "add-proposed-record",
                        "action": "add",
                        "target_ledger_ids": [],
                        "proposed_entries": [proposed],
                        "materiality": "supporting",
                        "rationale": "The source record needs a ledger correction.",
                    }
                ],
            }
        },
        3,
    )
    portable.submit_judge_response(run, response)
    assert portable.verify_evaluation_run(run).valid

    response_path = "judge-responses/ledger-audit-attempt-1.json"
    rebound_response = json.loads((run / response_path).read_text(encoding="utf-8"))
    rebound_response["payload"]["disputes"][0]["proposed_entries"][0][
        "ledger_id"
    ] = "file-notice"
    rebound_audit = rebound_response["payload"]
    envelope = json.loads((run / "case-envelope.json").read_text(encoding="utf-8"))
    proposed_ledger = json.loads(
        (run / "legal-ledger.proposed.json").read_text(encoding="utf-8")
    )
    repair_request = portable._repair_ledger_request(
        envelope,
        proposed_ledger,
        rebound_audit,
    )
    _rewrite_portable_history_artifacts(
        portable,
        run,
        {
            response_path: portable.canonical_json_bytes(rebound_response),
            "legal-ledger-audit.json": portable.canonical_json_bytes(rebound_audit),
            "judge-requests/ledger-repair-attempt-1.json": portable.canonical_json_bytes(
                repair_request
            ),
        },
    )

    assert portable.verify_evaluation_run(run).issues == ("EVALUATION_INTEGRITY_INVALID",)


def test_portable_initial_contradictory_generic_finding_retries_and_replays(
    tmp_path: Path,
) -> None:
    portable = _load_portable()
    run = tmp_path / "run"
    portable.initialize_evaluation(_case_payload(), run, seed_hex="8" * 64)
    scripted = _scripted_payloads()
    for index, item in enumerate(scripted[:2], start=1):
        request = portable.next_judge_request(run)
        assert request is not None
        portable.submit_judge_response(run, _response(request, item, index))
    audit_request = portable.next_judge_request(run)
    assert audit_request is not None

    state = portable.submit_judge_response(
        run,
        _response(
            audit_request,
            {
                "payload": {
                    "request_fingerprint": audit_request["request_fingerprint"],
                    "complete": True,
                    "disputes": [
                        {
                            "dispute_id": "contradictory-add",
                            "action": "add",
                            "target_ledger_ids": ["file-notice"],
                            "proposed_entries": [],
                            "materiality": "supporting",
                            "rationale": "This finding is very important indeed.",
                        }
                    ],
                }
            },
            3,
        ),
    )
    retry = portable.next_judge_request(run)

    assert state["state"] == "ledger-audit"
    assert state["attempt"] == 2
    assert retry is not None
    assert retry["operation"] == "audit_ledger"
    assert portable.verify_evaluation_run(run).valid


@pytest.mark.parametrize(
    ("action", "targets", "rationale"),
    [
        ("add", [], "The source record needs a ledger correction."),
        ("add", [], "The source record requires this concrete ledger correction."),
        ("add", [], "The case metadata needs a ledger correction."),
        ("add", [], "The request fingerprint needs a ledger correction."),
        ("add", [], "The response schema needs a ledger correction."),
        (
            "add",
            [],
            "unknown-source is missing covered operator registry notice requirement.",
        ),
        (
            "split",
            ["unknown-ledger-id"],
            "The notice duty combines distinct filing and timing propositions.",
        ),
        (
            "add",
            [],
            "synthetic-rule-1-source is missing the requirement at Rule 404.",
        ),
        (
            "add",
            [],
            (
                "synthetic-rule-1-source is missing covered operator registry notice "
                "requirement at Rule 404."
            ),
        ),
    ],
)
def test_portable_initial_content_free_finding_retries_and_replays(
    tmp_path: Path, action: str, targets: list[str], rationale: str
) -> None:
    portable = _load_portable()
    run = tmp_path / "run"
    portable.initialize_evaluation(_case_payload(), run, seed_hex="7" * 64)
    scripted = _scripted_payloads()
    for index, item in enumerate(scripted[:2], start=1):
        request = portable.next_judge_request(run)
        assert request is not None
        portable.submit_judge_response(run, _response(request, item, index))
    audit_request = portable.next_judge_request(run)
    assert audit_request is not None

    state = portable.submit_judge_response(
        run,
        _response(
            audit_request,
            {
                "payload": {
                    "request_fingerprint": audit_request["request_fingerprint"],
                    "complete": True,
                    "disputes": [
                        {
                            "dispute_id": "ungrounded-finding",
                            "action": action,
                            "target_ledger_ids": targets,
                            "proposed_entries": [],
                            "materiality": "supporting",
                            "rationale": rationale,
                        }
                    ],
                }
            },
            3,
        ),
    )
    retry = portable.next_judge_request(run)

    assert state["state"] == "ledger-audit"
    assert state["attempt"] == 2
    assert retry is not None
    assert retry["operation"] == "audit_ledger"
    assert portable.verify_evaluation_run(run).valid


@pytest.mark.parametrize(
    ("defect", "issue_code"),
    [
        ("unknown-source", "LEDGER_CITATION_SOURCE_UNKNOWN"),
        ("wrong-quote", "LEDGER_QUOTE_MISMATCH"),
        ("out-of-range", "LEDGER_QUOTE_MISMATCH"),
        ("commentary-only", "LEDGER_COMMENTARY_ONLY_SUPPORT"),
    ],
)
def test_portable_initial_invalid_proposed_entry_retries_and_replays(
    tmp_path: Path, defect: str, issue_code: str
) -> None:
    portable = _load_portable()
    case_payload = _case_payload()
    if defect == "commentary-only":
        commentary = copy.deepcopy(case_payload["sources"][0])
        commentary.update(
            {
                "source_id": "commentary-source",
                "source_role": "commentary_analysis",
                "source_quality": "secondary",
            }
        )
        case_payload["sources"].append(commentary)
        case_payload["requested_authorities"][0]["source_ids"].append(
            commentary["source_id"]
        )
    run = tmp_path / "run"
    portable.initialize_evaluation(case_payload, run, seed_hex="6" * 64)
    scripted = _scripted_payloads()
    for index, item in enumerate(scripted[:2], start=1):
        request = portable.next_judge_request(run)
        assert request is not None
        payload = copy.deepcopy(item["payload"])
        if "request_fingerprint" in payload:
            payload["request_fingerprint"] = request["request_fingerprint"]
        if request["operation"] == "build_ledger":
            payload["case_fingerprint"] = request["safe_metadata"][
                "source_record_fingerprint"
            ]
        portable.submit_judge_response(
            run, _response(request, {"payload": payload}, index)
        )
    audit_request = portable.next_judge_request(run)
    assert audit_request is not None
    proposed = copy.deepcopy(audit_request["payload"]["proposed_ledger"]["entries"][0])
    proposed["ledger_id"] = "invalid-proposed"
    citation = proposed["citations"][0]
    if defect == "unknown-source":
        citation["source_id"] = "unknown-source"
    elif defect == "wrong-quote":
        citation["quote"] = "covered operator notice language"
    elif defect == "out-of-range":
        source_text = audit_request["payload"]["source_record"]["sources"][0][
            "normalized_text"
        ]
        citation.update(
            {
                "start_char": len(source_text) + 1,
                "end_char": len(source_text) + 2,
                "quote": "x",
            }
        )
    else:
        citation["source_id"] = "commentary-source"

    state = portable.submit_judge_response(
        run,
        _response(
            audit_request,
            {
                "payload": {
                    "request_fingerprint": audit_request["request_fingerprint"],
                    "complete": True,
                    "disputes": [
                        {
                            "dispute_id": "invalid-proposed-finding",
                            "action": "add",
                            "target_ledger_ids": [],
                            "proposed_entries": [proposed],
                            "materiality": "supporting",
                            "rationale": "The source record needs a ledger correction.",
                        }
                    ],
                }
            },
            3,
        ),
    )
    retry = portable.next_judge_request(run)

    assert state["state"] == "ledger-audit"
    assert state["attempt"] == 2
    assert retry is not None
    assert retry["operation"] == "audit_ledger"
    attempt = json.loads(
        (run / "judge-diagnostics" / "ledger-audit-attempt-1.json").read_text()
    )
    message = attempt["issues"][0]["message"]
    assert "invalid-proposed-finding" in message
    assert issue_code in message
    assert portable.verify_evaluation_run(run).valid


@pytest.mark.parametrize("phase_count", range(6))
def test_resume_is_read_only_at_each_golden_phase(tmp_path: Path, phase_count: int) -> None:
    portable = _load_portable()
    run = tmp_path / f"run-{phase_count}"
    portable.initialize_evaluation(_case_payload(), run, seed_hex="0" * 64)
    for index, item in enumerate(_scripted_payloads()[:phase_count], start=1):
        request = portable.next_judge_request(run)
        assert request is not None
        portable.submit_judge_response(run, _response(request, item, index))
    before = {
        path.relative_to(run).as_posix(): path.read_bytes()
        for path in run.rglob("*")
        if path.is_file()
    }
    state = portable.resume_evaluation(run)
    request = portable.next_judge_request(run)
    after = {
        path.relative_to(run).as_posix(): path.read_bytes()
        for path in run.rglob("*")
        if path.is_file()
    }
    assert state["terminal_status"] is None or request is None
    assert after == before


def test_verification_rejects_added_tampered_and_mixed_version_artifacts(tmp_path: Path) -> None:
    portable = _load_portable()
    run = tmp_path / "run"
    _run_portable(portable, run)
    before = {
        path.relative_to(run).as_posix(): path.read_bytes()
        for path in run.rglob("*")
        if path.is_file()
    }
    verification = portable.verify_evaluation_run(run)
    assert verification.valid is True
    assert verification.root_hash
    after = {
        path.relative_to(run).as_posix(): path.read_bytes()
        for path in run.rglob("*")
        if path.is_file()
    }
    assert after == before

    (run / "unexpected.json").write_text("{}", encoding="utf-8")
    assert portable.verify_evaluation_run(run).issues == ("EVALUATION_INTEGRITY_INVALID",)
    (run / "unexpected.json").unlink()

    manifest = json.loads((run / "run-manifest.json").read_text(encoding="utf-8"))
    manifest["schema_version"] = "1.0"
    (run / "run-manifest.json").write_bytes(portable.canonical_json_bytes(manifest))
    assert portable.verify_evaluation_run(run).issues == ("EVALUATION_ARTIFACT_SCHEMA_UNSUPPORTED",)


@pytest.mark.parametrize(
    ("artifact", "nested_path"),
    [
        ("evaluation-result.json", ("schema_version",)),
        ("report-evaluation-A.json", ("schema_version",)),
        ("report-disputes.json", ("schema_version",)),
        ("grader-1-report-A.json", ("schema_version",)),
        ("resolved-grade-A.json", ("schema_version",)),
        ("resolved-grade-A.json", ("grade", "schema_version")),
        ("report-score-inputs-A.json", ("resolved_grade", "grade", "schema_version")),
    ],
)
def test_mixed_12_and_13_artifact_families_fail_with_stable_schema_code(
    tmp_path: Path, artifact: str, nested_path: tuple[str, ...]
) -> None:
    portable = _load_portable()
    run = tmp_path / "run"
    _run_portable(portable, run)
    value = json.loads((run / artifact).read_text(encoding="utf-8"))
    target = value
    for key in nested_path[:-1]:
        target = target[key]
    target[nested_path[-1]] = "1.2"
    (run / artifact).write_bytes(portable.canonical_json_bytes(value))
    _rehash_manifest_artifact(portable, run, artifact)

    assert portable.verify_evaluation_run(run).issues == (
        "EVALUATION_ARTIFACT_SCHEMA_UNSUPPORTED",
    )


@pytest.mark.parametrize("legacy_schema", ["1.3", "1.2"])
def test_portable_legacy_score_input_schema_fails_closed(
    tmp_path: Path,
    legacy_schema: str,
) -> None:
    portable = _load_portable()
    run = tmp_path / "run"
    _run_portable(portable, run)
    artifact = "report-score-inputs-A.json"
    path = run / artifact
    value = json.loads(path.read_text(encoding="utf-8"))
    value["schema_version"] = legacy_schema
    path.write_bytes(portable.canonical_json_bytes(value))
    _rehash_manifest_artifact(portable, run, artifact)

    assert portable.verify_evaluation_run(run).issues == (
        "EVALUATION_SCORE_INPUT_SCHEMA_UNSUPPORTED",
    )


def test_portable_score_input_source_record_tamper_fails_exact_replay(
    tmp_path: Path,
) -> None:
    portable = _load_portable()
    run = tmp_path / "run"
    _run_portable(portable, run)
    artifact = "report-score-inputs-A.json"
    path = run / artifact
    value = json.loads(path.read_text(encoding="utf-8"))
    source_record = value["source_record"]
    source = source_record["sources"][0]
    source["normalized_text"] += " Tampered."
    source["content_hash"] = hashlib.sha256(
        source["normalized_text"].encode("utf-8")
    ).hexdigest()
    projection = {
        key: item
        for key, item in source_record.items()
        if key != "source_record_fingerprint"
    }
    source_record["source_record_fingerprint"] = hashlib.sha256(
        portable.canonical_json_bytes(projection)
    ).hexdigest()
    path.write_bytes(portable.canonical_json_bytes(value))
    _rehash_manifest_artifact(portable, run, artifact)

    assert portable.verify_evaluation_run(run).issues == (
        "EVALUATION_SCORE_INPUT_SOURCE_RECORD_MISMATCH",
    )


def test_completed_grade_response_with_pre_matrix_payload_fails_stable_schema_check(
    tmp_path: Path,
) -> None:
    portable = _load_portable()
    run = tmp_path / "run"
    _run_portable(portable, run)
    artifact = "judge-responses/grade-A-1-attempt-1.json"
    response = json.loads((run / artifact).read_text(encoding="utf-8"))
    assert response["schema_version"] == "1.0"
    response["payload"]["schema_version"] = "1.2"
    (run / artifact).write_bytes(portable.canonical_json_bytes(response))
    _rehash_completed_response(portable, run, artifact)

    assert portable.verify_evaluation_run(run).issues == (
        "EVALUATION_ARTIFACT_SCHEMA_UNSUPPORTED",
    )


def test_verification_replays_requirement_matrix_from_immutable_evidence(
    tmp_path: Path,
) -> None:
    portable = _load_portable()
    run = tmp_path / "run"
    _run_portable(portable, run)
    result_path = run / "evaluation-result.json"
    result = json.loads(result_path.read_text(encoding="utf-8"))
    result["requirement_matrix"]["rows"][0]["proposition"] = "Altered proposition."
    result["result_fingerprint"] = "0" * 64
    result["result_fingerprint"] = portable._model_fingerprint(
        result, exclude={"result_fingerprint"}
    )
    result_path.write_bytes(portable.canonical_json_bytes(result))
    (run / "evaluation-report.md").write_text(
        portable.render_evaluation_report(result), encoding="utf-8"
    )
    manifest_path = run / "run-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["result_hash"] = hashlib.sha256(result_path.read_bytes()).hexdigest()
    manifest_path.write_bytes(portable.canonical_json_bytes(manifest))
    _rehash_manifest_artifact(portable, run, "evaluation-result.json")
    _rehash_manifest_artifact(portable, run, "evaluation-report.md")

    assert portable.verify_evaluation_run(run).issues == ("EVALUATION_INTEGRITY_INVALID",)


def test_verification_rejects_self_consistent_semantic_artifact_rewrite(tmp_path: Path) -> None:
    portable = _load_portable()
    run = tmp_path / "run"
    portable.initialize_evaluation(_case_payload(), run, seed_hex="0" * 64)
    request = portable.next_judge_request(run)
    assert request is not None
    portable.submit_judge_response(run, _response(request, _scripted_payloads()[0], 1))

    readiness_path = run / "case-readiness.json"
    readiness = json.loads(readiness_path.read_text(encoding="utf-8"))
    readiness["status"] = "CASE_INVALID"
    readiness_path.write_bytes(portable.canonical_json_bytes(readiness))
    _rehash_manifest_artifact(portable, run, "case-readiness.json")

    assert portable.verify_evaluation_run(run).issues == ("EVALUATION_INTEGRITY_INVALID",)


def test_verification_rejects_self_consistent_request_expansion(tmp_path: Path) -> None:
    portable = _load_portable()
    run = tmp_path / "run"
    portable.initialize_evaluation(_case_payload(), run, seed_hex="0" * 64)
    request_path = run / "judge-requests" / "admission-attempt-1.json"
    request = json.loads(request_path.read_text(encoding="utf-8"))
    request["safe_metadata"]["unexpected_scope"] = "expanded"
    request["request_fingerprint"] = "0" * 64
    request["request_fingerprint"] = portable._model_fingerprint(
        request, exclude={"request_fingerprint"}
    )
    request_path.write_bytes(portable.canonical_json_bytes(request))

    manifest_path = run / "run-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    call = manifest["judge_calls"][0]
    call["request_fingerprint"] = request["request_fingerprint"]
    call["prompt_fingerprint"] = portable._prompt_fingerprint(request)
    manifest_path.write_bytes(portable.canonical_json_bytes(manifest))
    _rehash_manifest_artifact(portable, run, "judge-requests/admission-attempt-1.json")

    assert portable.verify_evaluation_run(run).issues == ("EVALUATION_INTEGRITY_INVALID",)


def test_storage_rejects_symlink_components_and_nonregular_leaves(tmp_path: Path) -> None:
    portable = _load_portable()
    outside = tmp_path / "outside"
    outside.mkdir()
    link = tmp_path / "linked-run"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"symlinks unavailable: {error}")
    with pytest.raises(portable.EvaluationIntegrityError):
        portable.initialize_evaluation(_case_payload(), link, seed_hex="0" * 64)

    run = tmp_path / "run"
    _run_portable(portable, run)
    (run / "evaluation-report.md").unlink()
    os.mkfifo(run / "evaluation-report.md")
    try:
        assert portable.verify_evaluation_run(run).issues == ("EVALUATION_INTEGRITY_INVALID",)
    finally:
        (run / "evaluation-report.md").unlink()


def test_storage_rejects_hardlinked_artifacts(tmp_path: Path) -> None:
    portable = _load_portable()
    run = tmp_path / "run"
    _run_portable(portable, run)
    try:
        os.link(run / "evaluation-report.md", tmp_path / "report-hardlink.md")
    except OSError as error:
        pytest.skip(f"hardlinks unavailable: {error}")
    assert portable.verify_evaluation_run(run).issues == ("EVALUATION_INTEGRITY_INVALID",)


def test_storage_detects_root_replacement_after_descriptor_open(tmp_path: Path) -> None:
    portable = _load_portable()
    run = tmp_path / "run"
    _run_portable(portable, run)
    displaced = tmp_path / "displaced"
    with portable._open_run_storage(run) as storage:
        run.rename(displaced)
        run.mkdir()
        with pytest.raises(portable.EvaluationIntegrityError, match="path identity changed"):
            storage.assert_root_identity()


def test_storage_detects_leaf_replacement_during_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    portable = _load_portable()
    run = tmp_path / "run"
    _run_portable(portable, run)
    report = run / "evaluation-report.md"
    displaced = tmp_path / "displaced-report.md"
    original_read = portable._read_all
    raced = False

    def replace_after_read(descriptor: int) -> bytes:
        nonlocal raced
        data = original_read(descriptor)
        if not raced:
            raced = True
            report.rename(displaced)
            report.write_bytes(data)
        return cast(bytes, data)

    with portable._open_run_storage(run) as storage:
        monkeypatch.setattr(portable, "_read_all", replace_after_read)
        with pytest.raises(portable.EvaluationIntegrityError, match="changed while reading"):
            storage.read_artifact("evaluation-report.md")


def test_storage_detects_late_inventory_addition(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    portable = _load_portable()
    run = tmp_path / "run"
    _run_portable(portable, run)
    original_scan = portable._PosixRunStorage.scan_inventory
    calls = 0

    def racing_scan(storage: Any) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        if calls == 2:
            (run / "late-addition.json").write_text("{}", encoding="utf-8")
        return cast(dict[str, Any], original_scan(storage))

    monkeypatch.setattr(portable._PosixRunStorage, "scan_inventory", racing_scan)
    assert portable.verify_evaluation_run(run).issues == ("EVALUATION_INTEGRITY_INVALID",)


def test_failed_atomic_write_cleans_exclusive_temporary_leaf(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    portable = _load_portable()
    run = tmp_path / "run"

    def fail_link(*args: Any, **kwargs: Any) -> None:
        raise OSError("race")

    with portable._open_run_storage(run, initialize=True) as storage:
        monkeypatch.setattr(portable.os, "link", fail_link)
        with pytest.raises(OSError, match="race"):
            storage.atomic_write("artifact.json", b"{}", mutable=False)
        assert [path.name for path in run.iterdir()] == []


def test_windows_storage_fails_closed_without_a_pathname_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    portable = _load_portable()
    monkeypatch.setattr(portable, "_storage_platform", lambda: "nt")
    with pytest.raises(
        portable.EvaluationIntegrityError,
        match="EVALUATION_STORAGE_PLATFORM_UNSUPPORTED",
    ):
        portable.initialize_evaluation(_case_payload(), tmp_path / "run", seed_hex="0" * 64)
    verification = portable.verify_evaluation_run(tmp_path / "run")
    assert verification.valid is False
    assert verification.issues == ("EVALUATION_STORAGE_PLATFORM_UNSUPPORTED",)
    with pytest.raises(
        portable.EvaluationIntegrityError,
        match="EVALUATION_STORAGE_PLATFORM_UNSUPPORTED",
    ):
        portable.resume_evaluation(tmp_path / "run")
    assert not (tmp_path / "run").exists()


def test_portable_preflight_matches_core_and_never_changes_run_bytes(tmp_path: Path) -> None:
    """Portable preflight must calculate the same transition without committing either run."""
    portable = _load_portable()
    portable_run = tmp_path / "portable"
    core_run = tmp_path / "core"
    case_payload = _case_payload()
    portable.initialize_evaluation(case_payload, portable_run, seed_hex="0" * 64)
    initialize_core(_core_case_from_payload(case_payload), core_run, seed_hex="0" * 64)
    for index, item in enumerate(_scripted_payloads()[:3], start=1):
        portable_request = portable.next_judge_request(portable_run)
        core_request = next_core(core_run)
        assert portable_request is not None and core_request is not None
        assert portable_request == core_request.model_dump(mode="json")
        accepted = _response(portable_request, item, index)
        portable.submit_judge_response(portable_run, accepted)
        submit_core(core_run, JudgeResponse.model_validate(accepted))
    request = portable.next_judge_request(portable_run)
    assert request is not None and request["operation"] == "grade_report"
    response = _response(request, _scripted_payloads()[3], 4)
    invalid = copy.deepcopy(response)
    invalid["payload"] = {"malformed": True}
    portable_before = _tree_bytes(portable_run)
    core_before = _tree_bytes(core_run)

    portable_valid = portable.preflight_judge_response(portable_run, response)
    core_valid = core_workflow.preflight_judge_response(
        core_run, JudgeResponse.model_validate(response)
    )
    portable_invalid = portable.preflight_judge_response(portable_run, invalid)
    core_invalid = core_workflow.preflight_judge_response(
        core_run, JudgeResponse.model_validate(invalid)
    )

    assert portable_valid == core_valid.model_dump(mode="json")
    assert portable_invalid == core_invalid.model_dump(mode="json")
    assert _tree_bytes(portable_run) == portable_before
    assert _tree_bytes(core_run) == core_before

    portable_state = portable.submit_judge_response(portable_run, response)
    core_state = submit_core(core_run, JudgeResponse.model_validate(response))
    assert portable_state == core_state.model_dump(mode="json")


def test_portable_preflight_refuses_terminal_run_without_changing_bytes(
    tmp_path: Path,
) -> None:
    """A terminal run has no transition to validate and must remain byte-identical."""
    portable = _load_portable()
    run = tmp_path / "terminal"
    portable.initialize_evaluation(_case_payload(), run, seed_hex="0" * 64)
    request = portable.next_judge_request(run)
    assert request is not None
    payload = copy.deepcopy(_scripted_payloads()[0]["payload"])
    payload["request_fingerprint"] = request["request_fingerprint"]
    payload["checks"][0]["satisfied"] = False
    response = _response(request, {"payload": payload}, 1)
    portable.submit_judge_response(run, response)
    before = _tree_bytes(run)

    refused = portable.preflight_judge_response(run, response)

    assert refused == {
        "schema_version": "1.0",
        "ok": False,
        "operation": None,
        "request_fingerprint": None,
        "diagnostic_fingerprint": None,
        "issues": [
            {
                "code": "EVALUATION_NO_PENDING_REQUEST",
                "message": "The evaluation run has no pending request.",
                "related_ids": [],
            }
        ],
    }
    assert _tree_bytes(run) == before


def test_portable_preflight_propagates_transition_integrity_failure_without_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Portable integrity faults must remain distinct from semantic rejection."""
    portable = _load_portable()
    run = tmp_path / "run"
    portable.initialize_evaluation(_case_payload(), run, seed_hex="0" * 64)
    request = portable.next_judge_request(run)
    assert request is not None
    response = _response(request, _scripted_payloads()[0], 1)
    before = _tree_bytes(run)

    def fail_integrity(*args: object, **kwargs: object) -> None:
        raise portable.EvaluationIntegrityError("injected transition failure")

    monkeypatch.setattr(portable, "_accepted_transition", fail_integrity)

    with pytest.raises(
        portable.EvaluationIntegrityError,
        match="injected transition failure",
    ):
        portable.preflight_judge_response(run, response)

    assert _tree_bytes(run) == before


def test_portable_guarded_submit_matches_core_for_valid_and_refused_responses(
    tmp_path: Path,
) -> None:
    """Guarded portable submission must share the core result and artifact contracts."""
    portable = _load_portable()
    case_payload = _case_payload()
    portable_run = tmp_path / "portable"
    core_run = tmp_path / "core"
    portable.initialize_evaluation(case_payload, portable_run, seed_hex="d" * 64)
    initialize_core(_core_case_from_payload(case_payload), core_run, seed_hex="d" * 64)
    request = portable.next_judge_request(portable_run)
    core_request = next_core(core_run)
    assert request is not None and core_request is not None
    assert request == core_request.model_dump(mode="json")
    valid = _response(request, _scripted_payloads()[0], 1)
    refused = copy.deepcopy(valid)
    refused["payload"] = {"malformed": True}
    portable_before = _tree_bytes(portable_run)
    core_before = _tree_bytes(core_run)

    portable_refused = portable.guarded_submit_judge_response(portable_run, refused)
    core_refused = guarded_submit_core(core_run, JudgeResponse.model_validate(refused))

    assert portable_refused == core_refused.model_dump(mode="json")
    assert _tree_bytes(portable_run) == portable_before
    assert _tree_bytes(core_run) == core_before

    portable_accepted = portable.guarded_submit_judge_response(portable_run, valid)
    core_accepted = guarded_submit_core(core_run, JudgeResponse.model_validate(valid))

    assert portable_accepted == core_accepted.model_dump(mode="json")
    assert _tree_bytes(portable_run) == _tree_bytes(core_run)


def test_portable_guarded_submit_propagates_transition_integrity_write_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Injected transition integrity faults are exit-class 5, not retryable responses."""
    portable = _load_portable()
    case_payload = _case_payload()
    portable_run = tmp_path / "portable"
    core_run = tmp_path / "core"
    portable.initialize_evaluation(case_payload, portable_run, seed_hex="e" * 64)
    initialize_core(_core_case_from_payload(case_payload), core_run, seed_hex="e" * 64)
    request = portable.next_judge_request(portable_run)
    assert request is not None
    response = _response(request, _scripted_payloads()[0], 1)
    portable_before = _tree_bytes(portable_run)
    core_before = _tree_bytes(core_run)

    def fail_portable(*args: object, **kwargs: object) -> None:
        raise portable.EvaluationIntegrityError("injected transition fault")

    def fail_core(*args: object, **kwargs: object) -> None:
        raise attorney_artifacts.EvaluationIntegrityError("injected transition fault")

    monkeypatch.setattr(portable, "_accepted_transition", fail_portable)
    monkeypatch.setattr(core_workflow, "_accepted_transition", fail_core)

    with pytest.raises(portable.EvaluationIntegrityError, match="injected transition fault"):
        portable.guarded_submit_judge_response(portable_run, response)
    with pytest.raises(
        attorney_artifacts.EvaluationIntegrityError, match="injected transition fault"
    ):
        guarded_submit_core(core_run, JudgeResponse.model_validate(response))
    with pytest.raises(portable.EvaluationIntegrityError, match="injected transition fault"):
        portable.submit_judge_response(portable_run, response)
    with pytest.raises(
        attorney_artifacts.EvaluationIntegrityError, match="injected transition fault"
    ):
        submit_core(core_run, JudgeResponse.model_validate(response))

    assert portable.EVAL_EXIT_INTEGRITY == 5
    assert _tree_bytes(portable_run) == portable_before
    assert _tree_bytes(core_run) == core_before


def test_protocol_2_fictional_fixture_has_exact_full_portable_command_parity(
    tmp_path: Path,
) -> None:
    """Exercise the public fictional protocol-2 lifecycle through both CLIs."""
    fixture = tmp_path / "attorney-eval-v2"
    shutil.copytree(V2_FIXTURE, fixture)
    full_run = tmp_path / "full"
    portable_run = tmp_path / "portable"
    seed = "0" * 64
    full_runner = ROOT / "scripts" / "harvest_skill.py"
    portable_runner = ROOT / "scripts" / "harvest_portable.py"

    def invoke(runner: Path, *args: str) -> subprocess.CompletedProcess[str]:
        command = (
            [sys.executable, str(runner), *args]
            if runner == full_runner
            else ["python3", "-I", "-S", str(runner), *args]
        )
        return subprocess.run(
            command,
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )

    def paired(command: str, *args: str) -> tuple[subprocess.CompletedProcess[str], object | None]:
        full = invoke(full_runner, command, *args, "--run", str(full_run))
        portable = invoke(portable_runner, command, *args, "--run", str(portable_run))
        assert (full.returncode, full.stdout, full.stderr) == (
            portable.returncode,
            portable.stdout,
            portable.stderr,
        ), (full.stdout, full.stderr, portable.stdout, portable.stderr)
        payload = None if not full.stdout else json.loads(full.stdout)
        return full, payload

    init_full, _ = paired(
        "eval-init", "--case", str(fixture / "case.json"), "--seed-hex", seed
    )
    assert init_full.returncode == 0
    responses = json.loads((fixture / "scripted-responses.json").read_text(encoding="utf-8"))
    entries = responses["responses"]
    assert isinstance(entries, list) and len(entries) == 7
    observed_operations: list[str] = []
    for index, entry in enumerate(entries, start=1):
        assert isinstance(entry, dict)
        next_full, request = paired("eval-next")
        assert next_full.returncode == 0
        assert isinstance(request, dict)
        observed_operations.append(request["operation"])
        request_payload = request["payload"]
        assert isinstance(request_payload, dict)
        if request["operation"] == "source_review":
            response_payload = copy.deepcopy(entries[0]["payload"])
            response_payload["schema_version"] = "2.1"
        elif request["operation"] == "source_audit":
            response_payload = copy.deepcopy(entries[1]["payload"])
            response_payload["schema_version"] = "2.1"
        elif request["operation"] == "source_referee_fragment":
            dispute = request_payload["material_disputes"][0]
            response_payload = {
                "schema_version": "2.1",
                "decision": "accept_auditor",
                "unresolved_reason": None,
                "evidence_refs": [dispute["evidence"][0]["evidence_ref"]],
                "rationale": "The explicit fictional date supports the corrected requirement.",
            }
        else:
            assert request["operation"] == "ordinary_grade_fragment"
            label = request_payload["anonymous_label"]
            disposition = "met" if label == "A" else "not_met"
            response_payload = {
                "schema_version": "2.1",
                "anonymous_label": label,
                "grader_lane": request_payload["grader_lane"],
                "batch_ref": request_payload["batch_ref"],
                "baseline_fingerprint": request_payload["baseline_fingerprint"],
                "report_fingerprint": request_payload["report_fingerprint"],
                "requirement_grades": [
                    {
                        "requirement_id": requirement["requirement_id"],
                        "disposition": disposition,
                        "report_passages": [request_payload["report_text"]]
                        if disposition == "met" else [],
                        "rationale": "The fictional report was assessed against this requirement.",
                        "omission": None,
                    }
                    for requirement in request_payload["requirements"]
                ],
                "rationale": "The bounded fictional batch is complete.",
            }
        response_path = tmp_path / f"response-{index}.json"
        response_path.write_bytes(canonical_json_bytes(response_payload))
        submitted, submitted_payload = paired(
            "eval-submit-safe",
            "--response",
            str(response_path),
            "--provider-name",
            "local-scripted-fixture",
            "--model-name",
            "no-provider",
            "--judge-isolation",
            "scripted_fixture",
        )
        assert submitted.returncode == 0
        assert isinstance(submitted_payload, dict)
        assert submitted_payload["accepted"] is True

    assert observed_operations == [
        "source_review",
        "source_audit",
        "source_referee_fragment",
        "ordinary_grade_fragment",
        "ordinary_grade_fragment",
        "ordinary_grade_fragment",
        "ordinary_grade_fragment",
    ]
    terminal_next, terminal_request = paired("eval-next")
    assert terminal_next.returncode == 4
    assert terminal_request is None
    status, status_payload = paired("eval-status")
    verify, verify_payload = paired("eval-verify")
    assert status.returncode == verify.returncode == 4
    assert isinstance(status_payload, dict) and status_payload["terminal_status"] == "COMPLETED"
    assert isinstance(verify_payload, dict) and verify_payload["ok"] is True
    assert _tree_bytes(full_run) == _tree_bytes(portable_run)
    assert (full_run / "result.json").read_bytes() == (portable_run / "result.json").read_bytes()
    assert (full_run / "run-manifest.json").read_bytes() == (
        portable_run / "run-manifest.json"
    ).read_bytes()

    for run in (full_run, portable_run):
        result_path = run / "result.json"
        result = json.loads(result_path.read_text(encoding="utf-8"))
        result["result_fingerprint"] = "0" * 64
        result_path.write_bytes(canonical_json_bytes(result))
    tampered_full = _tree_bytes(full_run)
    tampered_portable = _tree_bytes(portable_run)
    invalid_status, invalid_status_payload = paired("eval-status")
    invalid_verify, invalid_verify_payload = paired("eval-verify")
    assert invalid_status.returncode == invalid_verify.returncode == 5
    assert invalid_status_payload is None
    assert invalid_verify_payload == {
        "issues": ["EVALUATION_INTEGRITY_INVALID"],
        "ok": False,
    }
    assert _tree_bytes(full_run) == tampered_full
    assert _tree_bytes(portable_run) == tampered_portable


def test_protocol_21_public_mirror_loads_with_only_the_standard_library() -> None:
    """The 2.1 mirror remains importable when site packages are disabled."""
    probe = (
        "import runpy,sys;"
        f"m=runpy.run_path({str(SCRIPT)!r});"
        "assert m['_V21_PROTOCOL']=='2.1';"
        "assert 'pydantic' not in sys.modules"
    )
    completed = subprocess.run(
        [sys.executable, "-I", "-S", "-c", probe],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr


def _portable_v22_review_request() -> dict[str, object]:
    return {
        "schema_version": "2.2",
        "operation": "source_review_fragment",
        "request_fingerprint": "a" * 64,
        "system_instructions": "Review the frozen source record.",
        "json_schema": {"type": "object"},
        "payload": {
            "source_record": {
                "sources": [
                    {
                        "source_id": "rule-1",
                        "normalized_text": "The controller shall act.",
                    }
                ]
            },
            "max_new_proposals": 5,
        },
        "safe_metadata": {},
    }


def test_protocol_22_portable_source_requests_expose_compiler_constraints() -> None:
    portable = _load_protocol_22_portable()
    assert (
        portable._V22_COMPILER_CONTRACT_FINGERPRINT
        == COMPILER_CONTRACT_FINGERPRINT_V22
    )
    envelope = portable.freeze_case(_case_payload(), seed_hex="0" * 64)
    review_request = portable._v22_review_request(envelope, [])
    review_definitions = review_request["json_schema"]["$defs"]
    assert review_definitions["_EvidenceHandleDraftV22"]["properties"][
        "evidence_handle"
    ]["enum"] == ["SOURCE-000001"]
    assert review_definitions["_ProposalDraftV22"]["properties"]["dependency"] == {
        "default": None,
        "type": "null",
    }
    assert "controller-issued evidence_handle" in review_request["system_instructions"]

    proposal = copy.deepcopy(_portable_v22_review_draft()["proposals"][0])
    audit_request = portable._v22_audit_request(
        envelope,
        {
            "proposals": [{"proposal_ref": "P0001", "proposal": proposal}],
            "aggregate_fingerprint": "a" * 64,
        },
        [],
    )
    audit_definitions = audit_request["json_schema"]["$defs"]
    assert audit_definitions["_AuditConcernDraftV22"]["properties"][
        "target_proposal_ordinal"
    ]["anyOf"][0]["maximum"] == 1
    assert audit_definitions["_DependencyDraftV22"]["properties"][
        "target_ordinal"
    ]["maximum"] == 1
    assert "omission requires no target and a correction" in audit_request[
        "system_instructions"
    ]

    empty_audit = portable._v22_audit_request(
        envelope,
        {"proposals": [], "aggregate_fingerprint": "b" * 64},
        [],
    )
    empty_definitions = empty_audit["json_schema"]["$defs"]
    assert empty_definitions["_AuditConcernDraftV22"]["properties"][
        "target_proposal_ordinal"
    ] == {"default": None, "type": "null"}
    assert empty_definitions["_ProposalDraftV22"]["properties"]["dependency"] == {
        "default": None,
        "type": "null",
    }


def test_protocol_22_portable_ordinary_request_exposes_exact_ordinal_allowlist() -> None:
    portable = _load_protocol_22_portable()
    requirements = [
        {"requirement_id": f"REQ-{ordinal:04d}"} for ordinal in range(1, 5)
    ]
    request = portable._v22_new_request(
        "ordinary_grade_fragment",
        {
            "anonymous_label": "A",
            "grader_lane": 1,
            "batch_ref": "GB-A-1-0001",
            "baseline_fingerprint": "a" * 64,
            "report_text": "The report addresses the issued requirements.",
            "report_fingerprint": "b" * 64,
            "report_passage_allowlist": [
                "The report addresses the issued requirements."
            ],
            "source_context": {"rule-1": "The frozen source context."},
            "rubric": copy.deepcopy(portable._V22_RUBRIC),
            "requirements": requirements,
        },
        {
            "record_scope": "one-ordinary-grade-batch",
            "baseline_fingerprint": "a" * 64,
            "batch_ref": "GB-A-1-0001",
        },
    )
    definitions = request["json_schema"]["$defs"]
    ordinal = definitions["_RequirementGradeDraftV22"]["properties"][
        "requirement_ordinal"
    ]
    grades = request["json_schema"]["properties"]["requirement_grades"]

    assert ordinal["enum"] == [1, 2, 3, 4]
    assert grades["minItems"] == grades["maxItems"] == 4
    assert "Allowed requirement_ordinal values: [1,2,3,4]" in request[
        "system_instructions"
    ]

    tampered = copy.deepcopy(request)
    tampered["json_schema"]["$defs"]["_RequirementGradeDraftV22"][
        "properties"
    ]["requirement_ordinal"]["enum"] = [1, 2, 3]
    tampered["request_fingerprint"] = portable._v22_request_fingerprint(tampered)
    with pytest.raises(
        portable.PortableEvaluationInputError,
        match="request schema is invalid",
    ):
        portable._v22_validate_request(tampered)


def test_protocol_22_portable_grade_requests_issue_exact_report_passages() -> None:
    portable = _load_protocol_22_portable()
    report = "Repeated support.\nRepeated support.\nUnique controlling passage."
    payload = {
        "anonymous_label": "A",
        "grader_lane": 1,
        "batch_ref": "GB-A-1-0001",
        "baseline_fingerprint": "a" * 64,
        "report_text": report,
        "report_fingerprint": hashlib.sha256(report.encode()).hexdigest(),
        "source_context": {"rule-1": "The frozen source context."},
        "rubric": copy.deepcopy(portable._V22_RUBRIC),
        "requirements": [{"requirement_id": "REQ-0001"}],
        "report_passage_allowlist": ["Unique controlling passage.", report],
    }
    request = portable._v22_new_request(
        "ordinary_grade_fragment",
        payload,
        {
            "record_scope": "one-ordinary-grade-batch",
            "baseline_fingerprint": "a" * 64,
            "batch_ref": "GB-A-1-0001",
        },
    )

    items = request["json_schema"]["$defs"]["_RequirementGradeDraftV22"][
        "properties"
    ]["report_passages"]["items"]
    assert items["enum"] == ["Unique controlling passage.", report]
    assert "controller-issued report_passage_allowlist" in request[
        "system_instructions"
    ]

    missing_inventory = copy.deepcopy(payload)
    missing_inventory.pop("report_passage_allowlist")
    with pytest.raises(
        portable.PortableEvaluationInputError,
        match="report passage allowlist is invalid",
    ):
        portable._v22_new_request(
            "ordinary_grade_fragment",
            missing_inventory,
            {
                "record_scope": "one-ordinary-grade-batch",
                "baseline_fingerprint": "a" * 64,
                "batch_ref": "GB-A-1-0001",
            },
        )


def test_protocol_22_source_evidence_handles_have_full_portable_byte_parity() -> None:
    """Dropping portable handle resolution must diverge from the full compiler bytes."""
    portable = _load_protocol_22_portable()
    envelope = portable.freeze_case(_case_payload(), seed_hex="0" * 64)
    request = portable._v22_review_request(envelope, [])
    draft = {
        "proposals": [
            {
                "statement": "A controller must act.",
                "kind": "obligation",
                "importance": "critical",
                "passages": [{"evidence_handle": "SOURCE-000001"}],
                "dependency": None,
                "confidence": "clear",
                "rationale": "The controller-issued evidence supports the duty.",
            }
        ],
        "review_complete": True,
    }
    provenance = {
        "provider_name": "scripted",
        "model_name": "fixture",
        "judge_isolation": "scripted_fixture",
    }
    full = compile_evaluator_draft_v22(
        EvaluatorRequestV22.model_validate(request),
        draft,
        EvaluatorProvenanceV22(**provenance),
    )

    assert isinstance(full, CompiledDraftV22)
    assert request["payload"]["evidence_handles"] == [
        {
            "evidence_handle": "SOURCE-000001",
            "source_id": "synthetic-rule-1-source",
        }
    ]
    assert portable._compile_evaluator_draft_v22_for_test(
        canonical_json_bytes(request), canonical_json_bytes(draft), provenance
    ) == canonical_json_bytes(full.response.model_dump(mode="json"))

    cast(list[dict[str, object]], draft["proposals"])[0]["passages"] = [
        {"evidence_handle": "SOURCE-999999"}
    ]
    refused = compile_evaluator_draft_v22(
        EvaluatorRequestV22.model_validate(request),
        draft,
        EvaluatorProvenanceV22(**provenance),
    )
    assert type(refused).__name__ == "NeedsClarificationV22"
    assert tuple(code.value for code in refused.reason_codes) == ("REFERENCE_UNKNOWN",)
    assert portable._compile_evaluator_draft_v22_for_test(
        canonical_json_bytes(request), canonical_json_bytes(draft), provenance
    ) == ("REFERENCE_UNKNOWN",)


def _portable_v22_review_draft() -> dict[str, object]:
    return {
        "proposals": [
            {
                "statement": "A controller must act.",
                "kind": "obligation",
                "importance": "critical",
                "passages": [
                    {"source_id": "rule-1", "quote": "The controller shall act."}
                ],
                "dependency": None,
                "confidence": "clear",
                "rationale": "The source uses mandatory language.",
            }
        ],
        "review_complete": True,
    }


def _portable_v22_audit_request() -> dict[str, object]:
    proposal = copy.deepcopy(_portable_v22_review_draft()["proposals"][0])
    return {
        **_portable_v22_review_request(),
        "operation": "source_audit_fragment",
        "request_fingerprint": "b" * 64,
        "payload": {
            "source_record": _portable_v22_review_request()["payload"]["source_record"],
            "indexed_proposals": [{"proposal_ref": "P0001", "proposal": proposal}],
            "accepted_concerns": [],
            "fragment_ordinal": 1,
            "max_new_concerns": 5,
        },
    }


def _portable_v22_contested_request() -> dict[str, object]:
    return {
        **_portable_v22_review_request(),
        "operation": "contested_grade_fragment",
        "request_fingerprint": "c" * 64,
        "payload": {
            "anonymous_label": "A",
            "grader_lane": 1,
            "baseline_fingerprint": "d" * 64,
            "report_fingerprint": "e" * 64,
            "report_text": "The report satisfies the issued duty.",
            "contested_requirement": {"contested_requirement_id": "CR0001"},
        },
    }


def _portable_v22_referee_request() -> dict[str, object]:
    return {
        **_portable_v22_review_request(),
        "operation": "source_referee_fragment",
        "request_fingerprint": "c" * 64,
        "payload": {
            "material_disputes": [
                {
                    "evidence": [
                        {
                            "evidence_ref": "EVID-0001",
                            "passage": {
                                "source_id": "rule-1",
                                "quote": "The controller shall act.",
                                "start_char": 0,
                                "end_char": 25,
                            },
                        }
                    ]
                }
            ]
        },
    }


def _portable_v22_referee_draft() -> dict[str, object]:
    return {
        "decision": "accept_reviewer",
        "unresolved_reason": None,
        "evidence_ordinals": [1],
        "rationale": "The sole passage supports the reviewer.",
    }


def _portable_v22_ordinary_request() -> dict[str, object]:
    return {
        **_portable_v22_review_request(),
        "operation": "ordinary_grade_fragment",
        "request_fingerprint": "d" * 64,
        "payload": {
            "anonymous_label": "A",
            "grader_lane": 1,
            "batch_ref": "GB-A-1-0001",
            "baseline_fingerprint": "e" * 64,
            "report_fingerprint": "f" * 64,
            "report_text": "The report addresses the requirement.",
            "requirements": [{"requirement_id": "REQ-0001"}],
        },
    }


def _portable_v22_ordinary_draft() -> dict[str, object]:
    return {
        "requirement_grades": [
            {
                "requirement_ordinal": 1,
                "disposition": "met",
                "report_passages": ["The report addresses the requirement."],
                "rationale": "The report addresses the requirement.",
                "omission": None,
            }
        ],
        "rationale": "The bounded requirement is met.",
    }


def _portable_v22_contested_draft() -> dict[str, object]:
    alternative = {
        "disposition": "met",
        "report_passages": ["The report satisfies the issued duty."],
        "rationale": "The issued alternative is satisfied.",
    }
    return {
        "reviewer_alternative_grade": copy.deepcopy(alternative),
        "auditor_alternative_grade": copy.deepcopy(alternative),
        "ambiguity_disposition": "acknowledged",
        "rationale": "Both alternatives were evaluated.",
    }


def _portable_v22_audit_draft() -> dict[str, object]:
    return {
        "concerns": [
            {
                "target_proposal_ordinal": 1,
                "concern_type": "incorrect_statement",
                "passages": [
                    {
                        "source_id": "rule-1",
                        "quote": "The controller shall act.",
                    }
                ],
                "explanation": "The formulation requires correction.",
                "correction": copy.deepcopy(
                    _portable_v22_review_draft()["proposals"][0]
                ),
            }
        ],
        "audit_complete": True,
    }


_V22TextCase = tuple[
    str, dict[str, object], dict[str, object], tuple[str | int, ...]
]


def _portable_v22_required_text_cases() -> list[_V22TextCase]:
    review = _portable_v22_review_draft
    audit = _portable_v22_audit_draft
    referee = _portable_v22_referee_draft
    ordinary = _portable_v22_ordinary_draft
    contested = _portable_v22_contested_draft
    review_request = _portable_v22_review_request
    audit_request = _portable_v22_audit_request
    return [
        ("review-statement", review_request(), review(), ("proposals", 0, "statement")),
        (
            "review-source-id",
            review_request(),
            review(),
            ("proposals", 0, "passages", 0, "source_id"),
        ),
        (
            "review-quote",
            review_request(),
            review(),
            ("proposals", 0, "passages", 0, "quote"),
        ),
        ("review-rationale", review_request(), review(), ("proposals", 0, "rationale")),
        (
            "audit-source-id",
            audit_request(),
            audit(),
            ("concerns", 0, "passages", 0, "source_id"),
        ),
        (
            "audit-quote",
            audit_request(),
            audit(),
            ("concerns", 0, "passages", 0, "quote"),
        ),
        ("audit-explanation", audit_request(), audit(), ("concerns", 0, "explanation")),
        (
            "audit-correction-statement",
            audit_request(),
            audit(),
            ("concerns", 0, "correction", "statement"),
        ),
        (
            "audit-correction-source-id",
            audit_request(),
            audit(),
            ("concerns", 0, "correction", "passages", 0, "source_id"),
        ),
        (
            "audit-correction-quote",
            audit_request(),
            audit(),
            ("concerns", 0, "correction", "passages", 0, "quote"),
        ),
        (
            "audit-correction-rationale",
            audit_request(),
            audit(),
            ("concerns", 0, "correction", "rationale"),
        ),
        (
            "referee-rationale",
            _portable_v22_referee_request(),
            referee(),
            ("rationale",),
        ),
        (
            "ordinary-grade-rationale",
            _portable_v22_ordinary_request(),
            ordinary(),
            ("requirement_grades", 0, "rationale"),
        ),
        (
            "ordinary-rationale",
            _portable_v22_ordinary_request(),
            ordinary(),
            ("rationale",),
        ),
        (
            "contested-reviewer-rationale",
            _portable_v22_contested_request(),
            contested(),
            ("reviewer_alternative_grade", "rationale"),
        ),
        (
            "contested-auditor-rationale",
            _portable_v22_contested_request(),
            contested(),
            ("auditor_alternative_grade", "rationale"),
        ),
        (
            "contested-rationale",
            _portable_v22_contested_request(),
            contested(),
            ("rationale",),
        ),
    ]


def _portable_v22_mutate_path(
    value: dict[str, object], path: tuple[str | int, ...], mode: str
) -> None:
    target: Any = value
    for part in path[:-1]:
        target = target[part]
    if mode == "absent":
        del target[path[-1]]
    elif mode == "blank":
        target[path[-1]] = "   "
    else:
        assert mode == "non-string"
        target[path[-1]] = 7


@pytest.mark.parametrize("mode", ["absent", "blank", "non-string"])
@pytest.mark.parametrize(
    ("case_name", "request_value", "draft", "path"),
    _portable_v22_required_text_cases(),
)
def test_protocol_22_internal_draft_compiler_distinguishes_every_required_text_field(
    case_name: str,
    request_value: dict[str, object],
    draft: dict[str, object],
    path: tuple[str | int, ...],
    mode: str,
) -> None:
    """All operation text fields distinguish absence from an invalid supplied value."""
    del case_name
    portable = _load_protocol_22_portable()
    provenance = {
        "provider_name": "scripted",
        "model_name": "fixture",
        "judge_isolation": "scripted_fixture",
    }
    _portable_v22_mutate_path(draft, path, mode)
    full = compile_evaluator_draft_v22(
        EvaluatorRequestV22.model_validate(request_value),
        draft,
        EvaluatorProvenanceV22(**provenance),
    )
    expected = "SUBSTANCE_MISSING" if mode == "absent" else "DRAFT_INVALID"

    assert type(full).__name__ == "NeedsClarificationV22"
    assert tuple(code.value for code in full.reason_codes) == (expected,)
    assert portable._compile_evaluator_draft_v22_for_test(
        canonical_json_bytes(request_value), canonical_json_bytes(draft), provenance
    ) == (expected,)


@pytest.mark.parametrize("replacement", ["   ", 7])
def test_protocol_22_internal_draft_compiler_treats_present_invalid_optional_text_as_shape(
    replacement: object,
) -> None:
    """Optional omission may be absent or null, but not malformed when present."""
    portable = _load_protocol_22_portable()
    request = _portable_v22_ordinary_request()
    draft = _portable_v22_ordinary_draft()
    cast(dict[str, object], cast(list[object], draft["requirement_grades"])[0])[
        "omission"
    ] = replacement
    provenance = {
        "provider_name": "scripted",
        "model_name": "fixture",
        "judge_isolation": "scripted_fixture",
    }
    full = compile_evaluator_draft_v22(
        EvaluatorRequestV22.model_validate(request),
        draft,
        EvaluatorProvenanceV22(**provenance),
    )

    assert type(full).__name__ == "NeedsClarificationV22"
    assert tuple(code.value for code in full.reason_codes) == ("DRAFT_INVALID",)
    assert portable._compile_evaluator_draft_v22_for_test(
        canonical_json_bytes(request), canonical_json_bytes(draft), provenance
    ) == ("DRAFT_INVALID",)


@pytest.mark.parametrize("field", ["provider_name", "model_name"])
@pytest.mark.parametrize("mode", ["absent", "blank", "non-string"])
def test_protocol_22_internal_draft_compiler_treats_provenance_as_controller_owned(
    field: str, mode: str
) -> None:
    """Missing or malformed controller provenance is never a draft clarification."""
    portable = _load_protocol_22_portable()
    provenance: dict[str, object] = {
        "provider_name": "scripted",
        "model_name": "fixture",
        "judge_isolation": "scripted_fixture",
    }
    if mode == "absent":
        del provenance[field]
    elif mode == "blank":
        provenance[field] = "   "
    else:
        provenance[field] = 7

    with pytest.raises(
        portable.EvaluationIntegrityError, match="EVALUATOR_V22_PROVENANCE"
    ):
        portable._v22_compile_draft(
            _portable_v22_review_request(),
            _portable_v22_review_draft(),
            provenance,
        )


def _portable_v22_response_text_cases() -> list[_V22TextCase]:
    ordinary = _portable_v22_ordinary_draft()
    cast(
        dict[str, object], cast(list[object], ordinary["requirement_grades"])[0]
    )["omission"] = "A required item is omitted."
    review_request = _portable_v22_review_request
    review = _portable_v22_review_draft
    audit_request = _portable_v22_audit_request
    audit = _portable_v22_audit_draft
    contested_request = _portable_v22_contested_request
    contested = _portable_v22_contested_draft
    return [
        ("provider", review_request(), review(), ("provider_name",)),
        ("model", review_request(), review(), ("model_name",)),
        (
            "audit-explanation",
            audit_request(),
            audit(),
            ("payload", "concerns", 0, "explanation"),
        ),
        (
            "audit-source-id",
            audit_request(),
            audit(),
            ("payload", "concerns", 0, "passages", 0, "source_id"),
        ),
        (
            "audit-quote",
            audit_request(),
            audit(),
            ("payload", "concerns", 0, "passages", 0, "quote"),
        ),
        (
            "referee-rationale",
            _portable_v22_referee_request(),
            _portable_v22_referee_draft(),
            ("payload", "rationale"),
        ),
        (
            "ordinary-rationale",
            _portable_v22_ordinary_request(),
            ordinary,
            ("payload", "rationale"),
        ),
        (
            "ordinary-grade-rationale",
            _portable_v22_ordinary_request(),
            ordinary,
            ("payload", "requirement_grades", 0, "rationale"),
        ),
        (
            "ordinary-omission",
            _portable_v22_ordinary_request(),
            ordinary,
            ("payload", "requirement_grades", 0, "omission"),
        ),
        (
            "contested-rationale",
            contested_request(),
            contested(),
            ("payload", "rationale"),
        ),
        (
            "contested-reviewer-rationale",
            contested_request(),
            contested(),
            ("payload", "reviewer_alternative_grade", "rationale"),
        ),
        (
            "contested-auditor-rationale",
            contested_request(),
            contested(),
            ("payload", "auditor_alternative_grade", "rationale"),
        ),
    ]


@pytest.mark.parametrize(
    ("case_name", "request_value", "draft", "path"),
    _portable_v22_response_text_cases(),
)
def test_protocol_22_strict_response_text_validation_uses_only_input_errors(
    case_name: str,
    request_value: dict[str, object],
    draft: dict[str, object],
    path: tuple[str | int, ...],
) -> None:
    """Invalid response text never enters the semantic-draft clarification channel."""
    del case_name
    portable = _load_protocol_22_portable()
    provenance = EvaluatorProvenanceV22(
        provider_name="scripted",
        model_name="fixture",
        judge_isolation="scripted_fixture",
    )
    full = compile_evaluator_draft_v22(
        EvaluatorRequestV22.model_validate(request_value), draft, provenance
    )
    assert isinstance(full, CompiledDraftV22)
    response = full.response.model_dump(mode="json")
    _portable_v22_mutate_path(response, path, "blank")

    with pytest.raises(portable.PortableEvaluationInputError):
        portable._v22_validate_response(request_value, response)


_V22LookupCase = tuple[str, str, tuple[str | int, ...]]


def _portable_v22_lookup_cases() -> list[_V22LookupCase]:
    envelope = ("judge-isolation", ("judge_isolation",))
    return [
        (f"review-{envelope[0]}", "source_review_fragment", envelope[1]),
        ("review-kind", "source_review_fragment", ("payload", "proposals", 0, "kind")),
        (
            "review-importance",
            "source_review_fragment",
            ("payload", "proposals", 0, "importance"),
        ),
        (
            "review-confidence",
            "source_review_fragment",
            ("payload", "proposals", 0, "confidence"),
        ),
        (
            "review-dependency-relationship",
            "source_review_fragment",
            ("payload", "proposals", 0, "dependency", "relationship"),
        ),
        (f"audit-{envelope[0]}", "source_audit_fragment", envelope[1]),
        (
            "audit-target-proposal-ref",
            "source_audit_fragment",
            ("payload", "concerns", 0, "target_proposal_ref"),
        ),
        (
            "audit-concern-type",
            "source_audit_fragment",
            ("payload", "concerns", 0, "concern_type"),
        ),
        (
            "audit-correction-kind",
            "source_audit_fragment",
            ("payload", "concerns", 0, "correction", "kind"),
        ),
        (
            "audit-correction-importance",
            "source_audit_fragment",
            ("payload", "concerns", 0, "correction", "importance"),
        ),
        (
            "audit-correction-confidence",
            "source_audit_fragment",
            ("payload", "concerns", 0, "correction", "confidence"),
        ),
        (
            "audit-correction-dependency-relationship",
            "source_audit_fragment",
            ("payload", "concerns", 0, "correction", "dependency", "relationship"),
        ),
        (f"referee-{envelope[0]}", "source_referee_fragment", envelope[1]),
        (
            "referee-decision",
            "source_referee_fragment",
            ("payload", "decision"),
        ),
        (
            "referee-unresolved-reason",
            "source_referee_fragment",
            ("payload", "unresolved_reason"),
        ),
        (
            "referee-evidence-ref",
            "source_referee_fragment",
            ("payload", "evidence_refs", 0),
        ),
        (f"ordinary-{envelope[0]}", "ordinary_grade_fragment", envelope[1]),
        (
            "ordinary-requirement-id",
            "ordinary_grade_fragment",
            ("payload", "requirement_grades", 0, "requirement_id"),
        ),
        (
            "ordinary-disposition",
            "ordinary_grade_fragment",
            ("payload", "requirement_grades", 0, "disposition"),
        ),
        (f"contested-{envelope[0]}", "contested_grade_fragment", envelope[1]),
        (
            "contested-requirement-id",
            "contested_grade_fragment",
            ("payload", "contested_requirement_id"),
        ),
        (
            "contested-ambiguity-disposition",
            "contested_grade_fragment",
            ("payload", "ambiguity_disposition"),
        ),
        (
            "contested-reviewer-disposition",
            "contested_grade_fragment",
            ("payload", "reviewer_alternative_grade", "disposition"),
        ),
        (
            "contested-auditor-disposition",
            "contested_grade_fragment",
            ("payload", "auditor_alternative_grade", "disposition"),
        ),
    ]


def _portable_v22_request_and_draft(
    operation: str,
) -> tuple[dict[str, object], dict[str, object]]:
    return {
        "source_review_fragment": (
            _portable_v22_review_request(),
            _portable_v22_review_draft(),
        ),
        "source_audit_fragment": (
            _portable_v22_audit_request(),
            _portable_v22_audit_draft(),
        ),
        "source_referee_fragment": (
            _portable_v22_referee_request(),
            _portable_v22_referee_draft(),
        ),
        "ordinary_grade_fragment": (
            _portable_v22_ordinary_request(),
            _portable_v22_ordinary_draft(),
        ),
        "contested_grade_fragment": (
            _portable_v22_contested_request(),
            _portable_v22_contested_draft(),
        ),
    }[operation]


def _portable_v22_lookup_value(kind: str) -> object:
    return {
        "list": ["invalid"],
        "dict": {"invalid": True},
        "non-string": 7,
        "unhashable": [{"nested": []}],
    }[kind]


def _portable_v22_set_path(
    value: dict[str, object], path: tuple[str | int, ...], replacement: object
) -> None:
    target: Any = value
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = replacement


def _portable_v22_invalid_lookup_response(
    valid: dict[str, object],
    case_name: str,
    path: tuple[str | int, ...],
    replacement: object,
) -> dict[str, object]:
    response = copy.deepcopy(valid)
    payload = cast(dict[str, Any], response["payload"])
    if case_name == "review-dependency-relationship":
        payload["proposals"][0]["dependency"] = {
            "relationship": "depends_on",
            "target_statement": "An issued proposal.",
        }
    elif case_name == "audit-correction-dependency-relationship":
        payload["concerns"][0]["correction"]["dependency"] = {
            "relationship": "depends_on",
            "target_statement": "An issued proposal.",
        }
    elif case_name == "referee-unresolved-reason":
        payload["decision"] = "unresolved"
        payload["unresolved_reason"] = "SOURCE_AMBIGUITY"
    _portable_v22_set_path(response, path, replacement)
    return response


@pytest.mark.parametrize("value_kind", ["list", "dict", "non-string", "unhashable"])
@pytest.mark.parametrize(
    ("case_name", "operation", "path"), _portable_v22_lookup_cases()
)
def test_protocol_22_portable_response_lookup_corpus_is_controlled_input(
    case_name: str,
    operation: str,
    path: tuple[str | int, ...],
    value_kind: str,
) -> None:
    """Every untrusted enum/reference lookup rejects malformed JSON values safely."""
    portable = _load_protocol_22_portable()
    request, draft = _portable_v22_request_and_draft(operation)
    compiled = compile_evaluator_draft_v22(
        EvaluatorRequestV22.model_validate(request),
        draft,
        EvaluatorProvenanceV22(
            provider_name="scripted",
            model_name="fixture",
            judge_isolation="scripted_fixture",
        ),
    )
    assert isinstance(compiled, CompiledDraftV22)
    invalid = _portable_v22_invalid_lookup_response(
        compiled.response.model_dump(mode="json"),
        case_name,
        path,
        _portable_v22_lookup_value(value_kind),
    )

    with pytest.raises(portable.PortableEvaluationInputError):
        portable._v22_validate_response(request, invalid)


@pytest.mark.parametrize(
    ("request_value", "draft", "reason"),
    [
        (
            _portable_v22_review_request(),
            {
                **_portable_v22_review_draft(),
                "proposals": [
                    {
                        **_portable_v22_review_draft()["proposals"][0],
                        "passages": [{"source_id": "rule-1"}],
                    }
                ],
            },
            "SUBSTANCE_MISSING",
        ),
        (
            _portable_v22_review_request(),
            {
                **_portable_v22_review_draft(),
                "proposals": [
                    {
                        **_portable_v22_review_draft()["proposals"][0],
                        "dependency": {"relationship": "depends_on"},
                    }
                ],
            },
            "SUBSTANCE_MISSING",
        ),
        (
            _portable_v22_review_request(),
            {
                **_portable_v22_review_draft(),
                "proposals": [
                    {
                        **_portable_v22_review_draft()["proposals"][0],
                        "dependency": {
                            "relationship": "depends_on",
                            "target_ordinal": "1",
                        },
                    }
                ],
            },
            "DRAFT_INVALID",
        ),
        (
            _portable_v22_audit_request(),
            {
                "concerns": [
                    {
                        "target_proposal_ordinal": 1,
                        "concern_type": "incorrect_statement",
                        "passages": [
                            {
                                "source_id": "rule-1",
                                "quote": "The controller shall act.",
                            }
                        ],
                        "explanation": "The formulation requires correction.",
                        "correction": {
                            **_portable_v22_review_draft()["proposals"][0],
                            "dependency": {"relationship": "depends_on"},
                        },
                    }
                ],
                "audit_complete": True,
            },
            "SUBSTANCE_MISSING",
        ),
        (
            _portable_v22_audit_request(),
            {
                "concerns": [
                    {
                        "target_proposal_ordinal": 1,
                        "concern_type": "incorrect_statement",
                        "passages": [
                            {
                                "source_id": "rule-1",
                                "quote": "The controller shall act.",
                            }
                        ],
                        "explanation": "The formulation requires correction.",
                        "correction": [],
                    }
                ],
                "audit_complete": True,
            },
            "DRAFT_INVALID",
        ),
        (
            _portable_v22_contested_request(),
            {
                "reviewer_alternative_grade": {
                    "disposition": "met",
                    "report_passages": ["The report satisfies the issued duty."],
                },
                "auditor_alternative_grade": {
                    "disposition": "met",
                    "report_passages": ["The report satisfies the issued duty."],
                    "rationale": "The issued alternative is satisfied.",
                },
                "ambiguity_disposition": "acknowledged",
                "rationale": "Both alternatives were evaluated.",
            },
            "SUBSTANCE_MISSING",
        ),
    ],
)
def test_protocol_22_internal_draft_compiler_matches_nested_substance_and_shape(
    request_value: dict[str, object], draft: dict[str, object], reason: str
) -> None:
    """Nested missing fields and malformed shapes use the full reason taxonomy."""
    portable = _load_protocol_22_portable()
    provenance = {
        "provider_name": "scripted",
        "model_name": "fixture",
        "judge_isolation": "scripted_fixture",
    }
    full = compile_evaluator_draft_v22(
        EvaluatorRequestV22.model_validate(request_value),
        draft,
        EvaluatorProvenanceV22(**provenance),
    )

    assert type(full).__name__ == "NeedsClarificationV22"
    assert tuple(code.value for code in full.reason_codes) == (reason,)
    assert portable._compile_evaluator_draft_v22_for_test(
        canonical_json_bytes(request_value), canonical_json_bytes(draft), provenance
    ) == (reason,)


def test_protocol_22_internal_draft_compiler_returns_exact_full_bytes_or_reasons() -> None:
    """The internal conformance hook mirrors the full compiler without a CLI bypass."""
    portable = _load_protocol_22_portable()
    request = _portable_v22_review_request()
    draft = _portable_v22_review_draft()
    provenance = {
        "provider_name": "scripted",
        "model_name": "fixture",
        "judge_isolation": "scripted_fixture",
    }
    full = compile_evaluator_draft_v22(
        EvaluatorRequestV22.model_validate(request),
        draft,
        EvaluatorProvenanceV22(**provenance),
    )
    assert isinstance(full, CompiledDraftV22)

    compiled = portable._compile_evaluator_draft_v22_for_test(
        canonical_json_bytes(request), canonical_json_bytes(draft), provenance
    )
    missing = portable._compile_evaluator_draft_v22_for_test(
        canonical_json_bytes(request), b'{"review_complete":true}', provenance
    )

    assert compiled == canonical_json_bytes(full.response.model_dump(mode="json"))
    assert missing == ("SUBSTANCE_MISSING",)


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        (("proposals", 0), []),
        (("proposals", 0, "passages"), {}),
        (("proposals", 0, "passages", 0), []),
        (("proposals", 0, "dependency"), []),
    ],
)
def test_protocol_22_internal_draft_compiler_recovers_nested_structural_drafts(
    path: tuple[str | int, ...], replacement: object
) -> None:
    """Nested draft shape failures mirror full clarification, not input termination."""
    portable = _load_protocol_22_portable()
    request = _portable_v22_review_request()
    draft = copy.deepcopy(_portable_v22_review_draft())
    target: Any = draft
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = replacement
    provenance = {
        "provider_name": "scripted",
        "model_name": "fixture",
        "judge_isolation": "scripted_fixture",
    }
    full = compile_evaluator_draft_v22(
        EvaluatorRequestV22.model_validate(request),
        draft,
        EvaluatorProvenanceV22(**provenance),
    )

    assert type(full).__name__ == "NeedsClarificationV22"
    assert tuple(code.value for code in full.reason_codes) == ("DRAFT_INVALID",)
    assert portable._compile_evaluator_draft_v22_for_test(
        canonical_json_bytes(request), canonical_json_bytes(draft), provenance
    ) == ("DRAFT_INVALID",)


def test_protocol_22_internal_draft_compiler_does_not_swallow_engine_defects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only controlled draft-structure failures enter the clarification channel."""
    portable = _load_protocol_22_portable()

    def fail_engine(_request: object) -> dict[str, str]:
        raise RuntimeError("simulated compiler defect")

    monkeypatch.setattr(portable, "_v22_request_sources", fail_engine)
    with pytest.raises(RuntimeError, match="simulated compiler defect"):
        portable._v22_compile_draft(
            _portable_v22_review_request(),
            _portable_v22_review_draft(),
            {
                "provider_name": "scripted",
                "model_name": "fixture",
                "judge_isolation": "scripted_fixture",
            },
        )


def _portable_v22_aggregate_proposal(*, statement: str = "Duty one.") -> dict[str, object]:
    return {
        "statement": statement,
        "kind": "obligation",
        "importance": "critical",
        "passages": [{"source_id": "rule-1", "quote": "The controller shall act."}],
        "dependency": None,
        "confidence": "clear",
        "rationale": "The frozen source states the duty.",
    }


def _portable_v22_review_fragments(second: dict[str, object]) -> list[dict[str, object]]:
    return [
        {
            "fragment_ordinal": 1,
            "request_fingerprint": "1" * 64,
            "response_fingerprint": "2" * 64,
            "payload": {
                "schema_version": "2.2",
                "proposals": [_portable_v22_aggregate_proposal()],
                "review_complete": False,
            },
        },
        {
            "fragment_ordinal": 2,
            "request_fingerprint": "3" * 64,
            "response_fingerprint": "4" * 64,
            "payload": {
                "schema_version": "2.2",
                "proposals": [second],
                "review_complete": True,
            },
        },
    ]


@pytest.mark.parametrize(
    ("conflict", "message"),
    [
        (False, "duplicate accepted source-review proposal"),
        (True, "conflicting accepted source-review proposal"),
    ],
)
def test_protocol_22_review_aggregate_rejects_global_semantic_identity_reuse(
    conflict: bool, message: str
) -> None:
    """Review identities are unique across the complete fragment sequence."""
    portable = _load_protocol_22_portable()
    second = _portable_v22_aggregate_proposal(
        statement="Duty  one." if conflict else "Duty one."
    )
    with pytest.raises(ValueError, match=message):
        portable._v22_review_aggregate(_portable_v22_review_fragments(second))


def _portable_v22_audit_concern(*, explanation: str) -> dict[str, object]:
    return {
        "target_proposal_ref": "P0001",
        "concern_type": "ambiguity",
        "passages": [{"source_id": "rule-1", "quote": "The controller shall act."}],
        "explanation": explanation,
        "correction": None,
    }


@pytest.mark.parametrize(
    ("conflict", "message"),
    [
        (False, "duplicate accepted source-audit concern"),
        (True, "conflicting accepted source-audit concern"),
    ],
)
def test_protocol_22_audit_aggregate_rejects_global_semantic_identity_reuse(
    conflict: bool, message: str
) -> None:
    """Audit identities are unique across the complete fragment sequence."""
    portable = _load_protocol_22_portable()
    review = portable._v22_review_aggregate(
        _portable_v22_review_fragments(_portable_v22_aggregate_proposal(statement="Duty two."))
    )
    first = _portable_v22_audit_concern(explanation="The meaning is ambiguous.")
    second = _portable_v22_audit_concern(
        explanation="A different explanation." if conflict else "The meaning is ambiguous."
    )
    fragments = [
        {
            "fragment_ordinal": 1,
            "request_fingerprint": "5" * 64,
            "response_fingerprint": "6" * 64,
            "payload": {
                "schema_version": "2.2",
                "concerns": [first],
                "audit_complete": False,
            },
        },
        {
            "fragment_ordinal": 2,
            "request_fingerprint": "7" * 64,
            "response_fingerprint": "8" * 64,
            "payload": {
                "schema_version": "2.2",
                "concerns": [second],
                "audit_complete": True,
            },
        },
    ]
    with pytest.raises(ValueError, match=message):
        portable._v22_audit_aggregate(review, fragments)


@pytest.mark.parametrize(
    ("draft_bytes", "reason"),
    [
        (b'{"proposals":[],"proposals":[],"review_complete":true}', "DRAFT_INVALID"),
        (b" " * 262_145, "DRAFT_TOO_LARGE"),
        (
            canonical_json_bytes(
                {
                    "proposals": [
                        _portable_v22_review_draft()["proposals"][0]
                        for _ in range(6)
                    ],
                    "review_complete": True,
                }
            ),
            "ITEM_LIMIT_EXCEEDED",
        ),
    ],
)
def test_protocol_22_internal_draft_compiler_is_strict_on_raw_bytes_and_bounds(
    draft_bytes: bytes, reason: str
) -> None:
    portable = _load_protocol_22_portable()
    outcome = portable._compile_evaluator_draft_v22_for_test(
        canonical_json_bytes(_portable_v22_review_request()),
        draft_bytes,
        {
            "provider_name": "scripted",
            "model_name": "fixture",
            "judge_isolation": "scripted_fixture",
        },
    )

    assert outcome == (reason,)


def test_protocol_22_public_mirror_loads_with_only_the_standard_library() -> None:
    probe = (
        "import runpy,sys;"
        f"m=runpy.run_path({str(SCRIPT)!r});"
        "assert m['_V22_PROTOCOL']=='2.2';"
        "assert callable(m['_compile_evaluator_draft_v22_for_test']);"
        "assert 'pydantic' not in sys.modules"
    )
    completed = subprocess.run(
        [sys.executable, "-I", "-S", "-c", probe],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr


def _protocol_22_storage_response(
    portable: ModuleType, request: dict[str, Any], *, disputed: bool = True
) -> dict[str, Any]:
    """Compile one complete, disputed-world response for storage transition tests."""
    operation = request["operation"]
    payload = request["payload"]
    if operation == "source_review_fragment":
        source = payload["source_record"]["sources"][0]
        draft: dict[str, Any] = {
            "proposals": [
                {
                    "statement": statement,
                    "kind": "obligation",
                    "importance": "critical",
                    "passages": [
                        {
                            "source_id": source["source_id"],
                            "quote": source["normalized_text"],
                        }
                    ],
                    "dependency": None,
                    "confidence": "clear",
                    "rationale": "The frozen source states the filing duty.",
                }
                for statement in (
                    "A covered operator must file notice.",
                    "A covered operator must retain the public filing.",
                )
            ],
            "review_complete": True,
        }
    elif operation == "source_audit_fragment":
        concerns: list[dict[str, Any]] = []
        if disputed:
            proposal = copy.deepcopy(payload["indexed_proposals"][0]["proposal"])
            proposal["statement"] = "A covered operator must file corrected notice."
            concerns.append(
                {
                    "target_proposal_ordinal": 1,
                    "concern_type": "incorrect_statement",
                    "passages": proposal["passages"],
                    "explanation": "The exact formulation is disputed.",
                    "correction": proposal,
                }
            )
        draft = {"concerns": concerns, "audit_complete": True}
    elif operation == "source_referee_fragment":
        draft = {
            "decision": "unresolved",
            "unresolved_reason": "SOURCE_AMBIGUITY",
            "evidence_ordinals": [1],
            "rationale": "The issued evidence supports the reviewer formulation.",
        }
    elif operation == "ordinary_grade_fragment":
        report = payload["report_text"]
        draft = {
            "requirement_grades": [
                {
                    "requirement_ordinal": index,
                    "disposition": "met",
                    "report_passages": [report],
                    "rationale": "The supplied report states the requirement.",
                    "omission": None,
                }
                for index, _ in enumerate(payload["requirements"], 1)
            ],
            "rationale": "Every issued requirement was graded.",
        }
    else:
        assert operation == "contested_grade_fragment"
        report = payload["report_text"]
        alternative = {
            "disposition": "met",
            "report_passages": [report],
            "rationale": "The issued alternative is satisfied.",
        }
        draft = {
            "reviewer_alternative_grade": alternative,
            "auditor_alternative_grade": alternative,
            "ambiguity_disposition": "acknowledged",
            "rationale": "Both issued alternatives were evaluated.",
        }
    response, reasons = portable._v22_compile_draft(
        request,
        draft,
        {
            "provider_name": "local-scripted-fixture",
            "model_name": "no-provider",
            "judge_isolation": "scripted_fixture",
        },
    )
    assert response is not None, reasons
    return cast(dict[str, Any], response)


def _protocol_22_outcome_stable_variance_response(
    portable: ModuleType, request: dict[str, Any]
) -> dict[str, Any]:
    if request["operation"] != "ordinary_grade_fragment":
        return _protocol_22_storage_response(portable, request, disputed=False)
    payload = request["payload"]
    lane = payload["grader_lane"]
    dispositions = (
        ("partially_met", "met")
        if lane == 1
        else ("partially_met", "partially_met")
    )
    passages = ("First grading passage.", "Second grading passage.")
    draft = {
        "requirement_grades": [
            {
                "requirement_ordinal": ordinal,
                "disposition": disposition,
                "report_passages": [passages[ordinal - 1]],
                "rationale": "The requirement was independently graded.",
                "omission": None
                if disposition == "met"
                else "The report does not fully state the requirement.",
            }
            for ordinal, disposition in enumerate(dispositions, 1)
        ],
        "rationale": "The issued ordinary batch was independently graded.",
    }
    response, reasons = portable._v22_compile_draft(
        request,
        draft,
        {
            "provider_name": "local-scripted-fixture",
            "model_name": "no-provider",
            "judge_isolation": "scripted_fixture",
        },
    )
    assert response is not None, reasons
    return cast(dict[str, Any], response)


def test_protocol_22_outcome_stable_grader_variance_has_full_portable_parity(
    tmp_path: Path,
) -> None:
    portable = _load_protocol_22_portable()
    case_payload = _case_payload_with_report(
        "First grading passage. Second grading passage."
    )
    full_run = tmp_path / "full-outcome-stable-variance"
    portable_run = tmp_path / "portable-outcome-stable-variance"
    initialize_v22_core(
        _core_case_from_payload(case_payload), full_run, seed_hex="8" * 64
    )
    portable.initialize_evaluation_v22(
        case_payload, portable_run, seed_hex="8" * 64
    )

    for _ in range(20):
        full_request = next_v22_core(full_run)
        portable_request = portable.next_evaluator_request_v22(portable_run)
        assert (full_request is None) == (portable_request is None)
        if full_request is None:
            break
        assert portable_request is not None
        assert canonical_json_bytes(full_request.model_dump(mode="json")) == (
            portable.canonical_json_bytes(portable_request)
        )
        response = _protocol_22_outcome_stable_variance_response(
            portable, portable_request
        )
        full_submitted = guarded_submit_v22_core(full_run, response)
        portable_submitted = portable.guarded_submit_evaluator_response_v22(
            portable_run, response
        )
        assert full_submitted.accepted and portable_submitted["accepted"]
        assert _tree_bytes(full_run) == _tree_bytes(portable_run)
    else:
        pytest.fail("Protocol 2.2 variance lifecycle did not terminate")

    result = json.loads((full_run / "result.json").read_text(encoding="utf-8"))
    assert result["terminal_status"] == "COMPLETED"
    assert result["reports"][0]["reconciliation"]["absolute_disposition"] == "FAIL"
    assert result["reports"][0]["sensitivity"]["absolute_disposition"] == "FAIL"
    assert result["reports"][0]["reconciliation"]["reason_codes"] == [
        "CRITICAL_RECALL_BELOW_FLOOR",
        "WEIGHTED_COVERAGE_BELOW_FLOOR",
    ]


def _protocol_22_prepare_response_pair(
    portable: ModuleType,
    tmp_path: Path,
    operation: str,
) -> tuple[Path, Path, dict[str, Any], dict[str, Any]]:
    full_run = tmp_path / f"full-{operation}"
    portable_run = tmp_path / f"portable-{operation}"
    case_payload = _case_payload()
    initialize_v22_core(
        _core_case_from_payload(case_payload), full_run, seed_hex="1" * 64
    )
    portable.initialize_evaluation_v22(
        case_payload, portable_run, seed_hex="1" * 64
    )
    while True:
        full_request = next_v22_core(full_run)
        portable_request = portable.next_evaluator_request_v22(portable_run)
        assert full_request is not None and portable_request is not None
        full_request_json = full_request.model_dump(mode="json")
        assert canonical_json_bytes(full_request_json) == portable.canonical_json_bytes(
            portable_request
        )
        response = _protocol_22_storage_response(portable, portable_request)
        if portable_request["operation"] == operation:
            return full_run, portable_run, portable_request, response
        full_submitted = guarded_submit_v22_core(full_run, response)
        portable_submitted = portable.guarded_submit_evaluator_response_v22(
            portable_run, response
        )
        assert full_submitted.accepted and portable_submitted["accepted"]
        assert _tree_bytes(full_run) == _tree_bytes(portable_run)


def _protocol_22_core_preflight_payload(value: object) -> dict[str, object]:
    return {
        "valid": value.valid,
        "diagnostics": list(value.diagnostics),
    }


@pytest.mark.parametrize(
    "operation",
    [
        "source_review_fragment",
        "source_audit_fragment",
        "source_referee_fragment",
        "ordinary_grade_fragment",
        "contested_grade_fragment",
    ],
)
def test_protocol_22_response_lookup_corpus_has_public_full_portable_parity(
    operation: str, tmp_path: Path
) -> None:
    """Every malformed lookup is write-free, recoverable, and byte-exact publicly."""
    portable = _load_protocol_22_portable()
    full_run, portable_run, pending, valid = _protocol_22_prepare_response_pair(
        portable, tmp_path, operation
    )
    initial_tree = _tree_bytes(full_run)
    assert initial_tree == _tree_bytes(portable_run)
    failures: list[str] = []
    cases = [case for case in _portable_v22_lookup_cases() if case[1] == operation]

    for case_name, _operation, path in cases:
        for value_kind in ("list", "dict", "non-string", "unhashable"):
            invalid = _portable_v22_invalid_lookup_response(
                valid,
                case_name,
                path,
                _portable_v22_lookup_value(value_kind),
            )
            try:
                full_preflight = preflight_v22_core(full_run, invalid)
                portable_preflight = portable.preflight_evaluator_response_v22(
                    portable_run, invalid
                )
                assert portable_preflight == _protocol_22_core_preflight_payload(
                    full_preflight
                ) == {
                    "valid": False,
                    "diagnostics": ["EXTERNAL_RESPONSE_INVALID"],
                }
            except Exception as error:
                failures.append(
                    f"{case_name}/{value_kind}/preflight:{type(error).__name__}"
                )
            try:
                full_submitted = guarded_submit_v22_core(full_run, invalid)
                portable_submitted = portable.guarded_submit_evaluator_response_v22(
                    portable_run, invalid
                )
                expected = {
                    "accepted": full_submitted.accepted,
                    "preflight": _protocol_22_core_preflight_payload(
                        full_submitted.preflight
                    ),
                }
                assert portable_submitted == expected == {
                    "accepted": False,
                    "preflight": {
                        "valid": False,
                        "diagnostics": ["EXTERNAL_RESPONSE_INVALID"],
                    },
                }
            except Exception as error:
                failures.append(
                    f"{case_name}/{value_kind}/safe-submit:{type(error).__name__}"
                )
            assert _tree_bytes(full_run) == initial_tree
            assert _tree_bytes(portable_run) == initial_tree
            assert next_v22_core(full_run).model_dump(mode="json") == pending
            assert portable.next_evaluator_request_v22(portable_run) == pending

    full_valid = guarded_submit_v22_core(full_run, valid)
    portable_valid = portable.guarded_submit_evaluator_response_v22(
        portable_run, valid
    )
    assert full_valid.accepted and portable_valid["accepted"]
    assert _tree_bytes(full_run) == _tree_bytes(portable_run)
    assert not failures, failures


@pytest.mark.parametrize("blank", ["envelope", "payload"])
def test_protocol_22_portable_blank_external_response_is_refused_write_free(
    blank: str, tmp_path: Path
) -> None:
    """Blank external text receives the safe refusal payload without losing the request."""
    portable = _load_protocol_22_portable()
    run = tmp_path / f"v22-blank-{blank}"
    portable.initialize_evaluation_v22(_case_payload(), run, seed_hex="1" * 64)
    request = portable.next_evaluator_request_v22(run)
    assert request is not None
    response = _protocol_22_storage_response(portable, request)
    if blank == "envelope":
        response["provider_name"] = "   "
    else:
        cast(dict[str, Any], response["payload"])["proposals"][0]["rationale"] = "   "
    before = _tree_bytes(run)
    pending = copy.deepcopy(request)

    preflight = portable.preflight_evaluator_response_v22(run, response)
    submitted = portable.guarded_submit_evaluator_response_v22(run, response)

    assert preflight == {
        "valid": False,
        "diagnostics": ["EXTERNAL_RESPONSE_INVALID"],
    }
    assert submitted == {"accepted": False, "preflight": preflight}
    assert _tree_bytes(run) == before
    assert portable.next_evaluator_request_v22(run) == pending


@pytest.mark.parametrize(
    "fault",
    ("integrity", "input", "type", "value", "storage"),
)
def test_protocol_22_portable_preflight_propagates_verified_run_faults(
    fault: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verified-run faults are never relabeled as an invalid external response."""
    portable = _load_protocol_22_portable()
    run = tmp_path / f"v22-preflight-{fault}"
    portable.initialize_evaluation_v22(_case_payload(), run, seed_hex="1" * 64)
    request = portable.next_evaluator_request_v22(run)
    assert request is not None
    response = _protocol_22_storage_response(portable, request)
    before = _tree_bytes(run)
    pending = copy.deepcopy(request)
    error = {
        "integrity": portable.EvaluationIntegrityError("injected verification fault"),
        "input": portable.PortableEvaluationInputError("injected verifier input fault"),
        "type": TypeError("injected verifier type fault"),
        "value": ValueError("injected verifier value fault"),
        "storage": OSError("injected storage fault"),
    }[fault]

    def fail_verified(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise error

    with monkeypatch.context() as patch:
        patch.setattr(portable, "_v22_verified", fail_verified)
        with pytest.raises(type(error), match=str(error)):
            portable.preflight_evaluator_response_v22(run, response)

    assert _tree_bytes(run) == before
    assert portable.next_evaluator_request_v22(run) == pending


def _protocol_22_is_result_transition(
    portable: ModuleType,
    run: Path,
    response: dict[str, Any],
) -> bool:
    manifest, files = portable._v22_verified(run)
    envelope = portable._object(
        portable.parse_canonical_json_bytes(
            files["inputs/case.json"], location="inputs/case.json"
        ),
        location="inputs/case.json",
    )
    prior = [
        portable._object(
            portable.parse_canonical_json_bytes(
                files[call["response_artifact_path"]], location="response"
            ),
            location="response",
        )
        for call in manifest["calls"]
        if call["state"] == "accepted"
    ]
    successor, _ = portable._v22_snapshot(envelope, [*prior, response])
    return successor["terminal_status"] is not None


@pytest.mark.parametrize(
    "transition",
    (
        "source_review",
        "source_audit",
        "referee",
        "ordinary_grade",
        "contested_grade",
        "result",
    ),
)
@pytest.mark.parametrize(
    "failure_stage", ("before_manifest", "post_manifest_fsync", "post_commit_replay")
)
def test_protocol_22_transition_failure_restores_exact_prior_tree(
    transition: str,
    failure_stage: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every lifecycle transition preserves the prior verified tree on commit failure."""
    portable = _load_protocol_22_portable()
    run = tmp_path / f"v22-{transition}-{failure_stage}"
    portable.initialize_evaluation_v22(_case_payload(), run, seed_hex="6" * 64)
    disputed = transition in {"referee", "contested_grade", "result"}

    while True:
        request = portable.next_evaluator_request_v22(run)
        assert request is not None
        response = _protocol_22_storage_response(portable, request, disputed=disputed)
        operation = request["operation"]
        is_result = _protocol_22_is_result_transition(portable, run, response)
        current = {
            "source_review_fragment": "source_review",
            "source_audit_fragment": "source_audit",
            "source_referee_fragment": "referee",
            "ordinary_grade_fragment": "ordinary_grade",
            "contested_grade_fragment": "result" if is_result else "contested_grade",
        }[operation]
        if current == transition:
            break
        portable.submit_evaluator_response_v22(run, response)

    before = _tree_bytes(run)
    original_atomic = portable._PosixRunStorage.atomic_write
    original_replace = portable.os.replace
    original_fsync = portable.os.fsync
    original_verified = portable._v22_verified_storage
    manifest_replaced = False
    failed = False

    def fail_before_manifest(
        storage: object, path: str, data: bytes, *, mutable: bool
    ) -> object:
        nonlocal failed
        if path == "run-manifest.json" and not failed:
            failed = True
            raise OSError("injected pre-manifest failure")
        return original_atomic(storage, path, data, mutable=mutable)

    def record_manifest_replace(
        source: object, destination: object, *args: object, **kwargs: object
    ) -> None:
        nonlocal manifest_replaced
        original_replace(source, destination, *args, **kwargs)
        if destination == "run-manifest.json":
            manifest_replaced = True

    def fail_manifest_fsync(descriptor: int) -> None:
        nonlocal failed
        if manifest_replaced and not failed and stat.S_ISDIR(os.fstat(descriptor).st_mode):
            failed = True
            raise OSError("injected post-manifest fsync failure")
        original_fsync(descriptor)

    verified_calls = 0

    def fail_successor_replay(storage: object) -> object:
        nonlocal failed, verified_calls
        verified_calls += 1
        if verified_calls == 2:
            failed = True
            raise OSError("injected post-commit replay failure")
        return original_verified(storage)

    if failure_stage == "before_manifest":
        monkeypatch.setattr(portable._PosixRunStorage, "atomic_write", fail_before_manifest)
    elif failure_stage == "post_manifest_fsync":
        monkeypatch.setattr(portable.os, "replace", record_manifest_replace)
        monkeypatch.setattr(portable.os, "fsync", fail_manifest_fsync)
    else:
        monkeypatch.setattr(portable, "_v22_verified_storage", fail_successor_replay)

    with pytest.raises((OSError, portable.EvaluationIntegrityError)):
        portable.submit_evaluator_response_v22(run, response)

    assert failed
    assert _tree_bytes(run) == before
    assert portable.verify_evaluation_run(run).valid


def test_protocol_22_cooperative_callers_serialize_same_response(
    tmp_path: Path,
) -> None:
    """The portable physical-root lock serializes cooperating in-process callers."""
    portable = _load_protocol_22_portable()
    assert (
        portable._V22_STORAGE_CONCURRENCY_CONTRACT
        == "cooperative-exclusive-directory-namespace-per-operation-v1"
    )
    run = tmp_path / "v22-cooperative-callers"
    portable.initialize_evaluation_v22(_case_payload(), run, seed_hex="5" * 64)
    request = portable.next_evaluator_request_v22(run)
    assert request is not None
    response = _protocol_22_storage_response(portable, request)

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(
            executor.map(
                lambda _: portable.guarded_submit_evaluator_response_v22(run, response),
                range(2),
            )
        )

    assert sorted(outcome["accepted"] for outcome in outcomes) == [False, True]
    assert portable.verify_evaluation_run(run).valid


def test_protocol_22_rollback_preserves_same_byte_competing_addition(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A same-byte collision remains external state when the transition rolls back."""
    portable = _load_protocol_22_portable()
    run = tmp_path / "v22-same-byte-competitor"
    portable.initialize_evaluation_v22(_case_payload(), run, seed_hex="4" * 64)
    request = portable.next_evaluator_request_v22(run)
    assert request is not None
    response = _protocol_22_storage_response(portable, request)
    manifest = json.loads((run / "run-manifest.json").read_bytes())
    pending = [call for call in manifest["calls"] if call["state"] == "pending"]
    assert len(pending) == 1
    target = f"responses/{pending[0]['call_id']}.json"
    response_bytes = portable.canonical_json_bytes(response)
    before = _tree_bytes(run)
    original_atomic = portable._PosixRunStorage.atomic_write
    collided = False

    def collide_then_fail(
        storage: object, path: str, data: bytes, *, mutable: bool
    ) -> object:
        nonlocal collided
        if path == target and not collided:
            assert original_atomic(storage, path, data, mutable=False)
            collided = True
        if path == "run-manifest.json":
            raise OSError("injected manifest failure after same-byte collision")
        return original_atomic(storage, path, data, mutable=mutable)

    monkeypatch.setattr(portable._PosixRunStorage, "atomic_write", collide_then_fail)
    with pytest.raises(portable.EvaluationIntegrityError):
        portable.submit_evaluator_response_v22(run, response)

    assert collided
    assert _tree_bytes(run) == {**before, target: response_bytes}


@pytest.mark.skipif(os.name != "posix", reason="inode ownership is POSIX-specific")
def test_protocol_22_rollback_preserves_identical_manifest_inode_swap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Rollback never overwrites an identical-byte manifest installed by another owner."""
    portable = _load_protocol_22_portable()
    run = tmp_path / "v22-manifest-inode-competitor"
    portable.initialize_evaluation_v22(_case_payload(), run, seed_hex="3" * 64)
    request = portable.next_evaluator_request_v22(run)
    assert request is not None
    response = _protocol_22_storage_response(portable, request)
    before = _tree_bytes(run)
    original_replace = portable.os.replace
    original_fsync = portable.os.fsync
    competitor_bytes: bytes | None = None
    competitor_identity: tuple[int, int] | None = None
    swapped = False
    failed = False

    def replace_then_swap(
        source: object, destination: object, *args: object, **kwargs: object
    ) -> None:
        nonlocal competitor_bytes, competitor_identity, swapped
        original_replace(source, destination, *args, **kwargs)
        if destination != "run-manifest.json" or swapped:
            return
        manifest_path = run / "run-manifest.json"
        competitor_bytes = manifest_path.read_bytes()
        competitor_path = run / "external-manifest.json"
        competitor_path.write_bytes(competitor_bytes)
        identity = os.stat(competitor_path, follow_symlinks=False)
        competitor_identity = (identity.st_dev, identity.st_ino)
        original_replace(competitor_path, manifest_path)
        swapped = True

    def fail_after_swap(descriptor: int) -> None:
        nonlocal failed
        if swapped and not failed and stat.S_ISDIR(os.fstat(descriptor).st_mode):
            failed = True
            raise OSError("injected post-swap directory fsync failure")
        original_fsync(descriptor)

    monkeypatch.setattr(portable.os, "replace", replace_then_swap)
    monkeypatch.setattr(portable.os, "fsync", fail_after_swap)
    with pytest.raises(portable.EvaluationIntegrityError, match="ROLLBACK_FAILED"):
        portable.submit_evaluator_response_v22(run, response)

    current = os.stat(run / "run-manifest.json", follow_symlinks=False)
    assert swapped and failed and competitor_bytes is not None
    assert competitor_identity == (current.st_dev, current.st_ino)
    assert _tree_bytes(run) == {**before, "run-manifest.json": competitor_bytes}


def test_protocol_22_portable_refuses_unsupported_storage_without_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The portable mirror keeps non-POSIX ownership outside its public contract."""
    portable = _load_protocol_22_portable()
    run = tmp_path / "v22-unsupported-storage"
    monkeypatch.setattr(portable, "_storage_platform", lambda: "simulated")

    with pytest.raises(
        portable.EvaluationIntegrityError,
        match="EVALUATION_STORAGE_PLATFORM_UNSUPPORTED",
    ):
        portable.initialize_evaluation_v22(_case_payload(), run, seed_hex="2" * 64)

    assert not run.exists()


@pytest.mark.parametrize(
    "failure_stage",
    (
        "post_immutable_signal",
        "before_replace",
        "after_replace",
        "post_commit_verify",
    ),
)
def test_protocol_21_manifest_failure_rolls_back_additions_and_preserves_valid_run(
    failure_stage: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Manifest failures before or after replacement restore the exact prior tree."""
    run = tmp_path / "portable-v21-rollback"
    initialized = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "harvest_portable.py"),
            "eval-init",
            "--case",
            str(FIXTURE / "case.json"),
            "--run",
            str(run),
            "--seed-hex",
            "9" * 64,
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert initialized.returncode == 0, initialized.stderr
    portable = _load_protocol_21_portable()
    request = portable.next_judge_request(run)
    assert request is not None and request["operation"] == "source_review"
    source = request["payload"]["source_record"]["sources"][0]
    response = {
        "schema_version": "2.1",
        "operation": "source_review",
        "request_fingerprint": request["request_fingerprint"],
        "provider_name": "local-scripted-fixture",
        "model_name": "no-provider",
        "judge_isolation": "scripted_fixture",
        "payload": {
            "schema_version": "2.1",
            "proposals": [
                {
                    "statement": "A covered operator must file notice.",
                    "kind": "obligation",
                    "importance": "critical",
                    "passages": [
                        {"source_id": source["source_id"], "quote": source["normalized_text"]}
                    ],
                    "dependency": None,
                    "confidence": "clear",
                    "rationale": "The synthetic source states the filing duty.",
                }
            ],
        },
    }
    before = _tree_bytes(run)
    original = portable._PosixRunStorage.atomic_write
    original_replace = portable.os.replace
    original_fsync = portable.os.fsync
    failed = False
    manifest_replaced = False

    def fail_manifest_once(
        storage: object, path: str, data: bytes, *, mutable: bool
    ) -> object:
        nonlocal failed
        if path == "run-manifest.json" and mutable and not failed:
            failed = True
            raise OSError("injected manifest failure")
        return original(storage, path, data, mutable=mutable)

    def record_manifest_replace(
        source: object,
        destination: object,
        *args: object,
        **kwargs: object,
    ) -> None:
        nonlocal manifest_replaced
        original_replace(source, destination, *args, **kwargs)
        if destination == "run-manifest.json":
            manifest_replaced = True

    def fail_post_replace_directory_fsync(descriptor: int) -> None:
        nonlocal failed
        if (
            manifest_replaced
            and not failed
            and stat.S_ISDIR(os.fstat(descriptor).st_mode)
        ):
            failed = True
            raise OSError("injected post-replacement directory fsync failure")
        original_fsync(descriptor)

    def fail_after_reporting_owned_immutable(
        storage: object, path: str, data: bytes, *, mutable: bool
    ) -> bool:
        nonlocal failed
        created = original(storage, path, data, mutable=mutable)
        if path != "run-manifest.json" and created and not failed:
            failed = True
            failure = OSError("injected post-immutable failure")
            raise portable._AtomicWriteOwnershipError(path, failure) from failure
        return created

    if failure_stage == "post_commit_verify":
        original_scan = portable._PosixRunStorage.scan_inventory

        def fail_successor_verification(storage: object) -> object:
            nonlocal failed
            inventory = original_scan(storage)
            current = json.loads((run / "run-manifest.json").read_bytes())
            if not failed and current["phase"] == "source_audit":
                failed = True
                raise OSError("injected post-commit verification failure")
            return inventory

        monkeypatch.setattr(
            portable._PosixRunStorage, "scan_inventory", fail_successor_verification
        )
    elif failure_stage == "post_immutable_signal":
        monkeypatch.setattr(
            portable._PosixRunStorage,
            "atomic_write",
            fail_after_reporting_owned_immutable,
        )
    elif failure_stage == "after_replace":
        monkeypatch.setattr(portable.os, "replace", record_manifest_replace)
        monkeypatch.setattr(portable.os, "fsync", fail_post_replace_directory_fsync)
    else:
        monkeypatch.setattr(portable._PosixRunStorage, "atomic_write", fail_manifest_once)
    refused = portable.guarded_submit_judge_response(run, response)

    assert failed
    assert refused == {
        "accepted": False,
        "preflight": {"valid": False, "diagnostics": ["MECHANICAL_RESPONSE_INVALID"]},
    }
    assert _tree_bytes(run) == before
    assert portable.verify_evaluation_run(run).valid


@pytest.mark.parametrize("stage", ("source_review", "ordinary_grade"))
def test_protocol_21_rollback_preserves_same_byte_competing_addition(
    stage: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A same-byte collision is external state and is never rollback-owned."""
    run = tmp_path / f"portable-v21-collision-{stage}"
    initialized = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "harvest_portable.py"),
            "eval-init",
            "--case",
            str(FIXTURE / "case.json"),
            "--run",
            str(run),
            "--seed-hex",
            "8" * 64,
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert initialized.returncode == 0, initialized.stderr
    portable = _load_protocol_21_portable()
    if stage == "ordinary_grade":
        for expected in ("source_review", "source_audit"):
            request = portable.next_judge_request(run)
            assert request is not None and request["operation"] == expected
            portable.submit_judge_response(run, _protocol_21_test_response(request))
    request = portable.next_judge_request(run)
    assert request is not None
    response = _protocol_21_test_response(request)
    manifest = json.loads((run / "run-manifest.json").read_bytes())
    pending = [call for call in manifest["calls"] if call["state"] == "pending"]
    assert len(pending) == 1
    target_path = f"responses/{pending[0]['call_id']}.json"
    response_bytes = portable.canonical_json_bytes(response)
    before = _tree_bytes(run)
    original = portable._PosixRunStorage.atomic_write
    collided = False

    def same_byte_competitor_then_manifest_failure(
        storage: object, path: str, data: bytes, *, mutable: bool
    ) -> bool:
        nonlocal collided
        if path == target_path and not collided:
            assert original(storage, path, data, mutable=False)
            collided = True
        if path == "run-manifest.json":
            raise OSError("injected manifest failure after same-byte collision")
        return original(storage, path, data, mutable=mutable)

    monkeypatch.setattr(
        portable._PosixRunStorage,
        "atomic_write",
        same_byte_competitor_then_manifest_failure,
    )
    refused = portable.guarded_submit_judge_response(run, response)

    assert collided
    assert refused == {
        "accepted": False,
        "preflight": {"valid": False, "diagnostics": ["MECHANICAL_RESPONSE_INVALID"]},
    }
    assert _tree_bytes(run) == {**before, target_path: response_bytes}


@pytest.mark.skipif(os.name != "posix", reason="link ownership is POSIX-specific")
def test_portable_posix_immutable_write_never_leaves_unreported_path_after_link_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    portable = _load_protocol_21_portable()
    run = tmp_path / "portable-post-link-failure"
    storage = portable._PosixRunStorage.open(run, initialize=True)
    original_fsync = portable.os.fsync
    original_link = portable.os.link
    linked = False

    def record_link(*args: object, **kwargs: object) -> None:
        nonlocal linked
        original_link(*args, **kwargs)
        linked = True

    def fail_post_link_directory_fsync(descriptor: int) -> None:
        if linked and stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise OSError("injected post-link directory fsync failure")
        original_fsync(descriptor)

    monkeypatch.setattr(portable.os, "link", record_link)
    monkeypatch.setattr(portable.os, "fsync", fail_post_link_directory_fsync)
    try:
        with pytest.raises(portable._AtomicWriteOwnershipError) as raised:
            storage.atomic_write("owned.json", b"{}", mutable=False)
    finally:
        storage.close()

    assert linked
    assert raised.value.created is True
    assert raised.value.identity is not None
    current = os.stat(run / "owned.json", follow_symlinks=False)
    assert (raised.value.identity.device, raised.value.identity.inode) == (
        current.st_dev,
        current.st_ino,
    )
    assert (run / "owned.json").read_bytes() == b"{}"


@pytest.mark.skipif(os.name != "posix", reason="write identity is POSIX-specific")
def test_portable_posix_successful_write_reports_installed_leaf_identity(
    tmp_path: Path,
) -> None:
    portable = _load_protocol_21_portable()
    run = tmp_path / "portable-successful-write-identity"
    storage = portable._PosixRunStorage.open(run, initialize=True)
    try:
        assert storage.atomic_write("manifest.json", b"new", mutable=False)
        receipt = storage.atomic_write_receipt("manifest.json")
    finally:
        storage.close()

    current = os.stat(run / "manifest.json", follow_symlinks=False)
    assert receipt is not None and receipt.identity is not None
    assert receipt.created is True
    assert receipt.replaced is False
    assert (receipt.identity.device, receipt.identity.inode) == (
        current.st_dev,
        current.st_ino,
    )


@pytest.mark.skipif(os.name != "posix", reason="replace ownership is POSIX-specific")
def test_portable_posix_mutable_write_reports_replaced_path_after_directory_fsync_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    portable = _load_protocol_21_portable()
    run = tmp_path / "portable-post-replace-failure"
    storage = portable._PosixRunStorage.open(run, initialize=True)
    assert storage.atomic_write("manifest.json", b"old", mutable=False)
    original_replace = portable.os.replace
    original_fsync = portable.os.fsync
    replaced = False

    def record_replace(*args: object, **kwargs: object) -> None:
        nonlocal replaced
        original_replace(*args, **kwargs)
        replaced = True

    def fail_post_replace_directory_fsync(descriptor: int) -> None:
        if replaced and stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise OSError("injected post-replace directory fsync failure")
        original_fsync(descriptor)

    monkeypatch.setattr(portable.os, "replace", record_replace)
    monkeypatch.setattr(portable.os, "fsync", fail_post_replace_directory_fsync)
    try:
        with pytest.raises(portable._AtomicWriteOwnershipError) as raised:
            storage.atomic_write("manifest.json", b"new", mutable=True)
    finally:
        storage.close()

    assert replaced
    assert raised.value.created is False
    assert raised.value.replaced is True
    assert raised.value.identity is not None
    current = os.stat(run / "manifest.json", follow_symlinks=False)
    assert (raised.value.identity.device, raised.value.identity.inode) == (
        current.st_dev,
        current.st_ino,
    )
    assert (run / "manifest.json").read_bytes() == b"new"


@pytest.mark.skipif(os.name != "posix", reason="inode ownership is POSIX-specific")
def test_protocol_21_init_preserves_identical_byte_manifest_inode_swap_before_fsync_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    portable = _load_protocol_21_portable()
    run = tmp_path / "portable-v21-init-manifest-inode-swap"
    original_link = portable.os.link
    original_replace = portable.os.replace
    original_fsync = portable.os.fsync
    installed_identity: tuple[int, int] | None = None
    competitor_identity: tuple[int, int] | None = None
    competitor_bytes: bytes | None = None
    swapped = False
    failed = False

    def install_then_swap(
        source: object,
        destination: object,
        *args: object,
        **kwargs: object,
    ) -> None:
        nonlocal installed_identity, competitor_identity, competitor_bytes, swapped
        original_link(source, destination, *args, **kwargs)
        if destination != "run-manifest.json":
            return
        manifest_path = run / "run-manifest.json"
        installed = os.stat(manifest_path, follow_symlinks=False)
        installed_identity = (installed.st_dev, installed.st_ino)
        competitor_bytes = manifest_path.read_bytes()
        competitor_path = run / "external-manifest.json"
        competitor_path.write_bytes(competitor_bytes)
        competitor = os.stat(competitor_path, follow_symlinks=False)
        competitor_identity = (competitor.st_dev, competitor.st_ino)
        original_replace(competitor_path, manifest_path)
        swapped = True

    def fail_post_swap_directory_fsync(descriptor: int) -> None:
        nonlocal failed
        if swapped and not failed and stat.S_ISDIR(os.fstat(descriptor).st_mode):
            failed = True
            raise OSError("injected post-swap directory fsync failure")
        original_fsync(descriptor)

    monkeypatch.setattr(portable.os, "link", install_then_swap)
    monkeypatch.setattr(portable.os, "fsync", fail_post_swap_directory_fsync)

    with pytest.raises(
        portable.EvaluationIntegrityError, match="EVALUATOR_V21_ROLLBACK_FAILED"
    ):
        portable.initialize_evaluation(_case_payload(), run, seed_hex="3" * 64)

    current = os.stat(run / "run-manifest.json", follow_symlinks=False)
    assert swapped and failed and competitor_bytes is not None
    assert installed_identity is not None and competitor_identity is not None
    assert installed_identity != competitor_identity
    assert (current.st_dev, current.st_ino) == competitor_identity
    assert (run / "run-manifest.json").read_bytes() == competitor_bytes


def test_protocol_21_init_preserves_same_byte_competing_manifest_after_verify_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    portable = _load_protocol_21_portable()
    run = tmp_path / "portable-v21-init-manifest-competitor"
    original_atomic = portable._PosixRunStorage.atomic_write
    original_scan = portable._PosixRunStorage.scan_inventory
    competitor_bytes: bytes | None = None
    collided = False
    failed = False

    def competing_manifest(
        storage: object, path: str, data: bytes, *, mutable: bool
    ) -> bool:
        nonlocal collided, competitor_bytes
        if path == "run-manifest.json" and not collided:
            assert original_atomic(storage, path, data, mutable=False)
            competitor_bytes = data
            collided = True
        created = original_atomic(storage, path, data, mutable=mutable)
        if path == "run-manifest.json":
            assert created is False
        return created

    def fail_post_commit_verification(storage: object) -> object:
        nonlocal failed
        inventory = original_scan(storage)
        if collided and not failed and "run-manifest.json" in inventory:
            failed = True
            raise OSError("injected post-commit verification failure")
        return inventory

    monkeypatch.setattr(portable._PosixRunStorage, "atomic_write", competing_manifest)
    monkeypatch.setattr(
        portable._PosixRunStorage, "scan_inventory", fail_post_commit_verification
    )
    with pytest.raises(portable.EvaluationIntegrityError):
        portable.initialize_evaluation(_case_payload(), run, seed_hex="7" * 64)

    assert collided and failed and competitor_bytes is not None
    assert _tree_bytes(run) == {"run-manifest.json": competitor_bytes}


@pytest.mark.parametrize(
    "failure_stage",
    ("before_manifest", "post_manifest_signal", "post_manifest_fsync", "post_verify"),
)
def test_protocol_21_init_owned_manifest_failure_restores_empty_tree(
    failure_stage: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    portable = _load_protocol_21_portable()
    run = tmp_path / f"portable-v21-init-owned-{failure_stage}"
    original_atomic = portable._PosixRunStorage.atomic_write
    original_scan = portable._PosixRunStorage.scan_inventory
    original_link = portable.os.link
    original_fsync = portable.os.fsync
    manifest_written = False
    manifest_linked = False
    failed = False

    def fail_manifest(
        storage: object, path: str, data: bytes, *, mutable: bool
    ) -> bool:
        nonlocal failed, manifest_written
        if path != "run-manifest.json":
            return original_atomic(storage, path, data, mutable=mutable)
        if failure_stage == "before_manifest":
            failed = True
            raise OSError("injected pre-manifest failure")
        created = original_atomic(storage, path, data, mutable=mutable)
        manifest_written = created
        if failure_stage == "post_manifest_signal":
            failed = True
            cause = OSError("injected post-manifest failure")
            raise portable._AtomicWriteOwnershipError(path, cause) from cause
        return created

    def record_manifest_link(
        source: object,
        destination: object,
        *args: object,
        **kwargs: object,
    ) -> None:
        nonlocal manifest_linked
        original_link(source, destination, *args, **kwargs)
        if destination == "run-manifest.json":
            manifest_linked = True

    def fail_post_manifest_link_fsync(descriptor: int) -> None:
        nonlocal failed
        if (
            manifest_linked
            and not failed
            and stat.S_ISDIR(os.fstat(descriptor).st_mode)
        ):
            failed = True
            raise OSError("injected post-manifest directory fsync failure")
        original_fsync(descriptor)

    def fail_verification(storage: object) -> object:
        nonlocal failed
        inventory = original_scan(storage)
        if manifest_written and not failed:
            failed = True
            raise OSError("injected post-commit verification failure")
        return inventory

    monkeypatch.setattr(portable._PosixRunStorage, "atomic_write", fail_manifest)
    if failure_stage == "post_manifest_fsync":
        monkeypatch.setattr(portable.os, "link", record_manifest_link)
        monkeypatch.setattr(portable.os, "fsync", fail_post_manifest_link_fsync)
    elif failure_stage == "post_verify":
        monkeypatch.setattr(portable._PosixRunStorage, "scan_inventory", fail_verification)
    with pytest.raises(portable.EvaluationIntegrityError):
        portable.initialize_evaluation(_case_payload(), run, seed_hex="5" * 64)

    assert failed
    assert _tree_bytes(run) == {}


def test_protocol_21_transition_preserves_same_byte_competing_manifest(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    portable = _load_protocol_21_portable()
    run = tmp_path / "portable-v21-transition-manifest-competitor"
    portable.initialize_evaluation(_case_payload(), run, seed_hex="6" * 64)
    request = portable.next_judge_request(run)
    assert request is not None
    response = _protocol_21_test_response(request)
    before = _tree_bytes(run)
    original_atomic = portable._PosixRunStorage.atomic_write
    original_scan = portable._PosixRunStorage.scan_inventory
    competitor_bytes: bytes | None = None
    collided = False
    failed = False

    def competing_manifest(
        storage: object, path: str, data: bytes, *, mutable: bool
    ) -> bool:
        nonlocal collided, competitor_bytes
        if path == "run-manifest.json" and mutable and not collided:
            assert original_atomic(storage, path, data, mutable=True)
            competitor_bytes = data
            collided = True
        created = original_atomic(storage, path, data, mutable=mutable)
        if path == "run-manifest.json":
            assert created is False
        return created

    def fail_post_commit_verification(storage: object) -> object:
        nonlocal failed
        inventory = original_scan(storage)
        if collided and not failed:
            failed = True
            raise OSError("injected post-commit verification failure")
        return inventory

    monkeypatch.setattr(portable._PosixRunStorage, "atomic_write", competing_manifest)
    monkeypatch.setattr(
        portable._PosixRunStorage, "scan_inventory", fail_post_commit_verification
    )
    refused = portable.guarded_submit_judge_response(run, response)

    assert collided and failed and competitor_bytes is not None
    assert refused == {
        "accepted": False,
        "preflight": {"valid": False, "diagnostics": ["MECHANICAL_RESPONSE_INVALID"]},
    }
    assert _tree_bytes(run) == {**before, "run-manifest.json": competitor_bytes}
    assert not portable.verify_evaluation_run(run).valid
    after = _tree_bytes(run)
    assert portable.guarded_submit_judge_response(run, response)["accepted"] is False
    assert _tree_bytes(run) == after


@pytest.mark.skipif(os.name != "posix", reason="inode ownership is POSIX-specific")
def test_protocol_21_transition_preserves_identical_byte_manifest_inode_swap_before_fsync_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    portable = _load_protocol_21_portable()
    run = tmp_path / "portable-v21-transition-manifest-inode-swap"
    portable.initialize_evaluation(_case_payload(), run, seed_hex="2" * 64)
    request = portable.next_judge_request(run)
    assert request is not None
    response = _protocol_21_test_response(request)
    before = _tree_bytes(run)
    original_replace = portable.os.replace
    original_fsync = portable.os.fsync
    installed_identity: tuple[int, int] | None = None
    competitor_identity: tuple[int, int] | None = None
    competitor_bytes: bytes | None = None
    swapped = False
    failed = False

    def install_then_swap(
        source: object,
        destination: object,
        *args: object,
        **kwargs: object,
    ) -> None:
        nonlocal installed_identity, competitor_identity, competitor_bytes, swapped
        original_replace(source, destination, *args, **kwargs)
        if destination != "run-manifest.json" or swapped:
            return
        manifest_path = run / "run-manifest.json"
        installed = os.stat(manifest_path, follow_symlinks=False)
        installed_identity = (installed.st_dev, installed.st_ino)
        competitor_bytes = manifest_path.read_bytes()
        competitor_path = run / "external-manifest.json"
        competitor_path.write_bytes(competitor_bytes)
        competitor = os.stat(competitor_path, follow_symlinks=False)
        competitor_identity = (competitor.st_dev, competitor.st_ino)
        original_replace(competitor_path, manifest_path)
        swapped = True

    def fail_post_swap_directory_fsync(descriptor: int) -> None:
        nonlocal failed
        if swapped and not failed and stat.S_ISDIR(os.fstat(descriptor).st_mode):
            failed = True
            raise OSError("injected post-swap directory fsync failure")
        original_fsync(descriptor)

    monkeypatch.setattr(portable.os, "replace", install_then_swap)
    monkeypatch.setattr(portable.os, "fsync", fail_post_swap_directory_fsync)
    refused = portable.guarded_submit_judge_response(run, response)

    current = os.stat(run / "run-manifest.json", follow_symlinks=False)
    assert swapped and failed and competitor_bytes is not None
    assert installed_identity is not None and competitor_identity is not None
    assert installed_identity != competitor_identity
    assert refused == {
        "accepted": False,
        "preflight": {"valid": False, "diagnostics": ["MECHANICAL_RESPONSE_INVALID"]},
    }
    assert (current.st_dev, current.st_ino) == competitor_identity
    assert _tree_bytes(run) == {**before, "run-manifest.json": competitor_bytes}
    assert not portable.verify_evaluation_run(run).valid


@pytest.mark.skipif(os.name != "posix", reason="inode ownership is POSIX-specific")
def test_protocol_21_transition_preserves_different_byte_manifest_inode_swap_before_fsync_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    portable = _load_protocol_21_portable()
    run = tmp_path / "portable-v21-transition-different-manifest-inode-swap"
    portable.initialize_evaluation(_case_payload(), run, seed_hex="1" * 64)
    request = portable.next_judge_request(run)
    assert request is not None
    response = _protocol_21_test_response(request)
    before = _tree_bytes(run)
    original_replace = portable.os.replace
    original_fsync = portable.os.fsync
    competitor_bytes = b'{"external":"different"}\n'
    competitor_identity: tuple[int, int] | None = None
    swapped = False
    failed = False

    def install_then_swap(
        source: object,
        destination: object,
        *args: object,
        **kwargs: object,
    ) -> None:
        nonlocal competitor_identity, swapped
        original_replace(source, destination, *args, **kwargs)
        if destination != "run-manifest.json" or swapped:
            return
        competitor_path = run / "external-manifest.json"
        competitor_path.write_bytes(competitor_bytes)
        competitor = os.stat(competitor_path, follow_symlinks=False)
        competitor_identity = (competitor.st_dev, competitor.st_ino)
        original_replace(competitor_path, run / "run-manifest.json")
        swapped = True

    def fail_post_swap_directory_fsync(descriptor: int) -> None:
        nonlocal failed
        if swapped and not failed and stat.S_ISDIR(os.fstat(descriptor).st_mode):
            failed = True
            raise OSError("injected post-swap directory fsync failure")
        original_fsync(descriptor)

    monkeypatch.setattr(portable.os, "replace", install_then_swap)
    monkeypatch.setattr(portable.os, "fsync", fail_post_swap_directory_fsync)
    refused = portable.guarded_submit_judge_response(run, response)

    current = os.stat(run / "run-manifest.json", follow_symlinks=False)
    assert swapped and failed and competitor_identity is not None
    assert refused == {
        "accepted": False,
        "preflight": {"valid": False, "diagnostics": ["MECHANICAL_RESPONSE_INVALID"]},
    }
    assert (current.st_dev, current.st_ino) == competitor_identity
    assert _tree_bytes(run) == {**before, "run-manifest.json": competitor_bytes}


@pytest.mark.skipif(os.name != "posix", reason="inode ownership is POSIX-specific")
def test_protocol_21_transition_preserves_owned_manifest_when_rollback_identity_read_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    portable = _load_protocol_21_portable()
    run = tmp_path / "portable-v21-transition-manifest-identity-read-failure"
    portable.initialize_evaluation(_case_payload(), run, seed_hex="0" * 64)
    request = portable.next_judge_request(run)
    assert request is not None
    response = _protocol_21_test_response(request)
    before = _tree_bytes(run)
    original_replace = portable.os.replace
    original_fsync = portable.os.fsync
    original_stat = portable.os.stat
    installed_identity: tuple[int, int] | None = None
    replaced = False
    failed = False
    identity_failed = False

    def record_manifest_replace(
        source: object,
        destination: object,
        *args: object,
        **kwargs: object,
    ) -> None:
        nonlocal installed_identity, replaced
        original_replace(source, destination, *args, **kwargs)
        if destination == "run-manifest.json" and not replaced:
            current = original_stat(
                run / "run-manifest.json", follow_symlinks=False
            )
            installed_identity = (current.st_dev, current.st_ino)
            replaced = True

    def fail_post_replace_directory_fsync(descriptor: int) -> None:
        nonlocal failed
        if replaced and not failed and stat.S_ISDIR(os.fstat(descriptor).st_mode):
            failed = True
            raise OSError("injected post-replace directory fsync failure")
        original_fsync(descriptor)

    def fail_rollback_identity_read(
        path: object, *args: object, **kwargs: object
    ) -> os.stat_result:
        nonlocal identity_failed
        if failed and path == "run-manifest.json" and not identity_failed:
            identity_failed = True
            raise OSError("injected rollback identity read failure")
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(portable.os, "replace", record_manifest_replace)
    monkeypatch.setattr(portable.os, "fsync", fail_post_replace_directory_fsync)
    monkeypatch.setattr(portable.os, "stat", fail_rollback_identity_read)
    refused = portable.guarded_submit_judge_response(run, response)

    current = original_stat(run / "run-manifest.json", follow_symlinks=False)
    assert replaced and failed and identity_failed and installed_identity is not None
    assert refused == {
        "accepted": False,
        "preflight": {"valid": False, "diagnostics": ["MECHANICAL_RESPONSE_INVALID"]},
    }
    assert (current.st_dev, current.st_ino) == installed_identity
    assert _tree_bytes(run)["run-manifest.json"] != before["run-manifest.json"]


def test_protocol_21_post_replace_fsync_and_restore_failure_is_controlled(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    portable = _load_protocol_21_portable()
    run = tmp_path / "portable-v21-post-replace-cleanup-failure"
    portable.initialize_evaluation(_case_payload(), run, seed_hex="4" * 64)
    request = portable.next_judge_request(run)
    assert request is not None
    response = _protocol_21_test_response(request)
    before = _tree_bytes(run)
    original_replace = portable.os.replace
    original_fsync = portable.os.fsync
    manifest_replacements = 0
    failures = 0

    def record_manifest_replace(
        source: object,
        destination: object,
        *args: object,
        **kwargs: object,
    ) -> None:
        nonlocal manifest_replacements
        original_replace(source, destination, *args, **kwargs)
        if destination == "run-manifest.json":
            manifest_replacements += 1

    def fail_two_manifest_directory_fsyncs(descriptor: int) -> None:
        nonlocal failures
        if (
            manifest_replacements > failures
            and failures < 2
            and stat.S_ISDIR(os.fstat(descriptor).st_mode)
        ):
            failures += 1
            raise OSError(f"injected manifest directory fsync failure {failures}")
        original_fsync(descriptor)

    monkeypatch.setattr(portable.os, "replace", record_manifest_replace)
    monkeypatch.setattr(portable.os, "fsync", fail_two_manifest_directory_fsyncs)

    accepted_response = portable._v21_response(response, request)
    with pytest.raises(
        portable.EvaluationIntegrityError, match="EVALUATOR_V21_ROLLBACK_FAILED"
    ):
        portable._v21_commit_source_review(run, accepted_response)

    assert manifest_replacements == 2
    assert failures == 2
    assert _tree_bytes(run) == before
